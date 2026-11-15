package graphqlapp

import (
	context "context"
	"database/sql"

	"github.com/google/uuid"
	"github.com/target/goalert/assignment"
	"github.com/target/goalert/graphql2"
	"github.com/target/goalert/organization"
	"github.com/target/goalert/permission"
	sraudit "github.com/target/goalert/schedule/deleteaudit"
	"github.com/target/goalert/schedule/rule"
	"github.com/target/goalert/validation"

	"github.com/pkg/errors"
)

type ScheduleRule App

func (a *App) ScheduleRule() graphql2.ScheduleRuleResolver { return (*ScheduleRule)(a) }
func (r *ScheduleRule) Target(ctx context.Context, raw *rule.Rule) (*assignment.RawTarget, error) {
	tgt := assignment.NewRawTarget(raw.Target)
	return &tgt, nil
}

func (r *ScheduleRule) WeekdayFilter(ctx context.Context, raw *rule.Rule) ([]bool, error) {
	var f [7]bool
	for i, v := range raw.WeekdayFilter {
		f[i] = v == 1
	}
	return f[:], nil
}

func (m *Mutation) UpdateScheduleTarget(ctx context.Context, input graphql2.ScheduleTargetInput) (bool, error) {
	event := scheduleTargetUpdateAuditEvent(ctx)
	return m.configureScheduleTarget(ctx, input, &event)
}

// Creation explicitly uses this configuration helper without an Update event.
// An inherited authorized Update still stages its witness on the outer Tx.
func (m *Mutation) configureScheduleTarget(ctx context.Context, input graphql2.ScheduleTargetInput, event *sraudit.Event) (bool, error) {
	var schedID string
	if input.ScheduleID != nil {
		schedID = *input.ScheduleID
	}
	if input.Target.Type == assignment.TargetTypeUser && input.Target.ID == "__current_user" {
		input.Target.ID = permission.UserID(ctx)
	}
	organizationID, err := scheduleRotationManagementAuthority(ctx, scheduleRotationManagementUpdate)
	if err != nil {
		if event != nil && !hasInheritedContextTx(ctx) {
			err = finishScheduleTargetUpdateAudit(ctx, m.DB, nil, nil, false, false, *event, err)
		}
		return false, err
	}
	runTx := func(ctx context.Context, update func(context.Context, *sql.Tx) error) error {
		if event == nil {
			return withContextTx(ctx, m.DB, update)
		}
		return withScheduleTargetUpdateAuditTx(ctx, m.DB, event, update)
	}
	err = runTx(ctx, func(ctx context.Context, tx *sql.Tx) error {
		organizationID, err = existingRootTargetOrganization(ctx, tx, assignment.TargetTypeSchedule, schedID)
		if err != nil {
			return err
		}
		sched, err := m.ScheduleStore.FindOneForUpdate(ctx, tx, schedID, organizationID) // lock schedule
		if errors.Is(err, sql.ErrNoRows) {
			return validation.NewFieldError("scheduleID", "schedule not found")
		}
		if err != nil {
			return errors.Wrap(err, "lock schedule")
		}

		if event != nil {
			event.RootID, event.TargetOrganizationID, event.TargetOrgResolution = uuid.MustParse(sched.ID), sched.OrganizationID, "known_normal"
		}
		if err := m.RuleStore.LockScheduleRulesTx(ctx, tx, schedID); err != nil {
			return err
		}
		// Separate post-wait statement preserves the existing created_at,id order.
		rules, err := m.RuleStore.FindByTargetTx(ctx, tx, schedID, input.Target)
		if err != nil {
			return errors.Wrap(err, "fetch existing rules")
		}
		if organizationID != nil && input.Target.Type == assignment.TargetTypeUser && len(input.Rules) > 0 {
			// Target syntax was checked above. Empty rules only remove a
			// relationship, including an unavailable historical affiliation.
			err := organization.NewStore(m.DB).ValidateUserOrganizationTx(ctx, tx, uuid.MustParse(input.Target.ID), sched.OrganizationID)
			if errors.Is(err, organization.ErrNotFound) {
				return validation.NewFieldError("TargetID", "does not exist")
			}
			if err != nil {
				return err
			}
		}
		if organizationID != nil && input.Target.Type == assignment.TargetTypeRotation && len(input.Rules) > 0 {
			// FindByTargetTx validates the target before resolving the reference.
			// Empty rules only remove a relationship and need no target authority.
			_, err := m.RotationStore.FindRotationTx(ctx, tx, input.Target.ID, &sched.OrganizationID)
			if errors.Is(err, sql.ErrNoRows) {
				return validation.NewFieldError("TargetID", "does not exist")
			}
			if err != nil {
				return err
			}
		}
		for ruleIndex, inputRule := range input.Rules {
			r := rule.NewAlwaysActive(schedID, input.Target)
			if inputRule.Start != nil {
				r.Start = *inputRule.Start
			}
			if inputRule.End != nil {
				r.End = *inputRule.End
			}
			if inputRule.WeekdayFilter != nil {
				r.WeekdayFilter = *inputRule.WeekdayFilter
			}
			if ruleIndex < len(rules) {
				r.ID = rules[ruleIndex].ID
				err = errors.Wrap(m.RuleStore.UpdateTx(ctx, tx, r), "update rule")
			} else {
				_, err = m.RuleStore.CreateRuleTx(ctx, tx, r)
				err = errors.Wrap(err, "create rule")
			}
			if err != nil {
				return err
			}
		}

		if len(rules) > len(input.Rules) {
			toDelete := make([]string, len(rules)-len(input.Rules))
			for i, r := range rules[len(input.Rules):] {
				toDelete[i] = r.ID
			}
			if event == nil {
				return errors.Wrap(m.RuleStore.DeleteManyTx(ctx, tx, toDelete), "delete old rules")
			}
			receipts, err := m.RuleStore.DeleteManyReceiptTx(ctx, tx, schedID, input.Target, toDelete)
			if err != nil {
				return errors.Wrap(err, "delete old rules")
			}
			for _, receipt := range receipts {
				effect, err := scheduleTargetRuleEffect(*event, receipt)
				if err != nil {
					return err
				}
				event.Effects = append(event.Effects, effect)
			}
		}
		return nil
	})
	return err == nil, err
}
