package graphqlapp

import (
	context "context"
	"database/sql"

	"github.com/target/goalert/assignment"
	"github.com/target/goalert/graphql2"
	"github.com/target/goalert/permission"
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
	var schedID string
	if input.ScheduleID != nil {
		schedID = *input.ScheduleID
	}
	if input.Target.Type == assignment.TargetTypeUser && input.Target.ID == "__current_user" {
		input.Target.ID = permission.UserID(ctx)
	}
	organizationID, err := rootStoreOrganizationID(ctx)
	if err != nil {
		return false, err
	}
	err = withContextTx(ctx, m.DB, func(ctx context.Context, tx *sql.Tx) error {
		sched, err := m.ScheduleStore.FindOneForUpdate(ctx, tx, schedID, organizationID) // lock schedule
		if errors.Is(err, sql.ErrNoRows) {
			return validation.NewFieldError("scheduleID", "schedule not found")
		}
		if err != nil {
			return errors.Wrap(err, "lock schedule")
		}

		rules, err := m.RuleStore.FindByTargetTx(ctx, tx, schedID, input.Target)
		if err != nil {
			return errors.Wrap(err, "fetch existing rules")
		}
		if organizationID != nil && input.Target.Type == assignment.TargetTypeRotation && len(input.Rules) > 0 {
			// FindByTargetTx validates the target before resolving the reference.
			// Empty rules only remove a relationship and need no target authority.
			_, err := m.RotationStore.FindRotationForUpdateTx(ctx, tx, input.Target.ID, &sched.OrganizationID)
			if errors.Is(err, sql.ErrNoRows) {
				return validation.NewFieldError("TargetID", "does not exist")
			}
			if err != nil {
				return err
			}
		}
		rulesByID := make(map[string]*rule.Rule, len(rules))
		for i := range rules {
			rulesByID[rules[i].ID] = &rules[i]
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
			err := errors.Wrap(m.RuleStore.DeleteManyTx(ctx, tx, toDelete), "delete old rules")
			if err != nil {
				return err
			}
		}
		return nil
	})
	return err == nil, err
}
