package graphqlapp

import (
	"context"
	"database/sql"
	"reflect"

	"github.com/google/uuid"
	ds "github.com/target/goalert/deletionsafety"
	collector "github.com/target/goalert/deletionsafety/postgres"
	epaudit "github.com/target/goalert/escalation/deleteaudit"
	"github.com/target/goalert/gadb"
	"github.com/target/goalert/internal/updateguard"
	sraudit "github.com/target/goalert/schedule/deleteaudit"
	"github.com/target/goalert/schedule/rule"
)

// Only consent-relevant identity, ownership, retained target and provenance.
// SD10 remains the sole audit producer and validates the entire real receipt.
// A Step's receipt number can change due to the frozen renumbering trigger as
// earlier, approved Steps are removed; the complete original order is versioned.
type updateConsent struct{ Root, Organization, Parent, Target, Source string }

func updateEPConsent(effects []epaudit.Effect) (map[string]updateConsent, error) {
	result := map[string]updateConsent{}
	for _, f := range effects {
		if f.ResourceUUID == nil {
			return nil, previewUnavailable()
		}
		key := f.ResourceType + ":" + f.ResourceUUID.String()
		if _, ok := result[key]; ok {
			return nil, previewUnavailable()
		}
		c := updateConsent{Root: f.RootID.String(), Organization: f.TargetOrganizationID.String(), Source: f.Provenance}
		if f.ParentStepID != nil {
			c.Parent = f.ParentStepID.String()
		}
		if f.TargetID != nil {
			c.Target = f.TargetKind + ":" + f.TargetID.String()
		}
		result[key] = c
	}
	return result, nil
}
func updateRuleConsent(effects []sraudit.Effect) (map[string]updateConsent, error) {
	result := map[string]updateConsent{}
	for _, f := range effects {
		if f.ResourceUUID == nil || f.RuleDeletion == nil {
			return nil, previewUnavailable()
		}
		key := f.ResourceType + ":" + f.ResourceUUID.String()
		if _, ok := result[key]; ok {
			return nil, previewUnavailable()
		}
		result[key] = updateConsent{Root: f.RootID.String(), Organization: f.TargetOrganizationID.String(), Parent: f.RuleDeletion.ScheduleID.String(), Target: f.RuleDeletion.TargetKind + ":" + f.RuleDeletion.TargetID.String(), Source: f.Provenance}
	}
	return result, nil
}

// Validate the exact existing SD10 closed effect shape and capacity BEFORE
// promising execution. This creates no durable event and invokes no appender.
// The event constructors/effect adapters/validators are the accepted SD10 ones.
func (s updateAssessment) auditFeasibility(ctx context.Context, tx *sql.Tx) (map[string]updateConsent, error) {
	if s.operation == ds.OperationUpdateScheduleTarget {
		e := scheduleTargetUpdateAuditEvent(ctx)
		if err := tx.QueryRowContext(ctx, `SELECT organization_id FROM schedules WHERE id=$1`, s.root.ID).Scan(&e.TargetOrganizationID); err != nil {
			return nil, previewUnavailable()
		}
		e.RootID = uuid.MustParse(s.root.ID)
		e.TargetOrgResolution = "known_normal"
		e.RecordKind, e.Outcome, e.Reason = "success_witness", "committed", "children_deleted"
		e.Provenance, e.DeletionMechanism, e.Cause = "EXPLICIT", "explicit_sql", "update_induced"
		for _, c := range s.plan.Changes() {
			var r rule.DeleteReceipt
			var u, rot uuid.NullUUID
			if err := tx.QueryRowContext(ctx, `SELECT id,schedule_id,tgt_user_id,tgt_rotation_id FROM schedule_rules WHERE id=$1`, c.Resource.ID).Scan(&r.ID, &r.ScheduleID, &u, &rot); err != nil {
				return nil, previewUnavailable()
			}
			if u.Valid == rot.Valid {
				return nil, previewUnavailable()
			}
			r.TargetKind, r.TargetID = "rotation", rot.UUID
			if u.Valid {
				r.TargetKind, r.TargetID = "user", u.UUID
			}
			effect, err := scheduleTargetRuleEffect(e, r)
			if err != nil {
				return nil, previewUnavailable()
			}
			e.Effects = append(e.Effects, effect)
		}
		if err := e.Validate(); err != nil {
			return nil, previewUnavailable()
		}
		return updateRuleConsent(e.Effects)
	}
	operation := epaudit.PolicyUpdate
	if s.operation == ds.OperationUpdateEscalationPolicyStep {
		operation = epaudit.StepUpdate
	}
	e := epUpdateAuditEvent(ctx, operation)
	e.RootID = uuid.MustParse(s.root.ID)
	e.TargetOrgResolution = "known_normal"
	query := `SELECT organization_id FROM escalation_policies WHERE id=$1`
	if operation == epaudit.StepUpdate {
		query = `SELECT p.organization_id FROM escalation_policy_steps s JOIN escalation_policies p ON p.id=s.escalation_policy_id WHERE s.id=$1`
		if err := tx.QueryRowContext(ctx, `SELECT escalation_policy_id FROM escalation_policy_steps WHERE id=$1`, s.root.ID).Scan(&e.ParentPolicyID); err != nil {
			return nil, previewUnavailable()
		}
	}
	if err := tx.QueryRowContext(ctx, query, s.root.ID).Scan(&e.TargetOrganizationID); err != nil {
		return nil, previewUnavailable()
	}
	e.RecordKind, e.Outcome, e.Reason = "success_witness", "committed", "children_deleted"
	e.Provenance, e.DeletionMechanism, e.Cause = "EXPLICIT", "explicit_sql", "update_induced"
	for _, c := range s.plan.Changes() {
		if c.Resource.Kind == ds.ResourceEscalationPolicyStep {
			var r gadb.EPStepDeleteReceiptRow
			if err := tx.QueryRowContext(ctx, `SELECT id,escalation_policy_id,step_number FROM escalation_policy_steps WHERE id=$1`, c.Resource.ID).Scan(&r.ID, &r.EscalationPolicyID, &r.StepNumber); err != nil {
				return nil, previewUnavailable()
			}
			e.Effects = append(e.Effects, epUpdateStepEffect(e, r))
		} else {
			var r gadb.EPStepActionsDeleteReceiptRow
			if err := tx.QueryRowContext(ctx, `SELECT id,escalation_policy_step_id,user_id,schedule_id,rotation_id,channel_id FROM escalation_policy_actions WHERE id=$1`, c.Resource.ID).Scan(&r.ID, &r.EscalationPolicyStepID, &r.UserID, &r.ScheduleID, &r.RotationID, &r.ChannelID); err != nil {
				return nil, previewUnavailable()
			}
			f, err := epUpdateActionEffect(e, r, operation == epaudit.PolicyUpdate)
			if err != nil {
				return nil, previewUnavailable()
			}
			e.Effects = append(e.Effects, f)
		}
	}
	if err := e.Validate(); err != nil {
		return nil, previewUnavailable()
	}
	return updateEPConsent(e.Effects)
}

func epUpdateStepEffect(e epaudit.Event, r gadb.EPStepDeleteReceiptRow) epaudit.Effect {
	n := int(r.StepNumber)
	return epaudit.Effect{EffectID: uuid.New(), ResourceType: epaudit.Step, RootID: e.RootID, TargetOrganizationID: e.TargetOrganizationID, ResourceUUID: &r.ID, StepNumber: &n, Relation: "escalation_policy.step", Change: "deleted", Provenance: "EXPLICIT", DeletionMechanism: "explicit_sql", Cause: "update_induced"}
}

func (s updateAssessment) recheck(ctx context.Context, tx *sql.Tx) error {
	result, err := collector.CollectUpdate(ctx, tx, s.root, s.selected, collector.Recheck, func(_ context.Context, _ *sql.Tx, t collector.Target) error {
		if t.Resource() != s.root {
			return previewUnavailable()
		}
		return nil
	})
	if err != nil {
		return err
	}
	intents := make([]ds.DestructiveChange, len(s.selected))
	for n, r := range s.selected {
		intents[n] = ds.DestructiveChange{Resource: r, Kind: ds.ChangeDeleted}
	}
	p, err := ds.BuildPlan(ds.PlanInput{Operation: s.operation, Targets: s.selected, Intent: intents, Collection: result.Collection, ScopeFingerprint: result.ScopeFingerprint}, ds.Budget{})
	if err != nil {
		return err
	}
	return p.Check(s.plan.ImpactVersion(), true)
}

func (s updateAssessment) finish(ctx context.Context, tx *sql.Tx, effects any) error {
	var actual map[string]updateConsent
	var err error
	switch e := effects.(type) {
	case []epaudit.Effect:
		actual, err = updateEPConsent(e)
	case []sraudit.Effect:
		actual, err = updateRuleConsent(e)
	default:
		return previewUnavailable()
	}
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(s.expected, actual) {
		return &ds.DeletionSafetyError{Code: ds.DeletionDependencyChanged}
	}
	return updateguard.Complete(ctx, tx)
}
