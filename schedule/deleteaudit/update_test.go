package deleteaudit

import (
	"encoding/json"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func targetUpdateEvent() Event {
	e := testEvent(Schedule)
	e.SchemaVersion, e.EffectsVersion, e.Operation = 2, 2, ScheduleTargetUpdate
	e.Reason, e.Cause = "children_deleted", "update_induced"
	id := uuid.New()
	e.Effects = []Effect{{EffectID: uuid.New(), ResourceType: Rule, RootID: e.RootID, TargetOrganizationID: e.TargetOrganizationID,
		Relation: "schedule.schedule_rule", Change: "deleted", Provenance: "EXPLICIT", DeletionMechanism: "explicit_sql", Cause: "update_induced", ResourceUUID: &id,
		RuleDeletion: &RuleDeleteDetail{ScheduleID: e.RootID, TargetKind: "user", TargetID: uuid.New()}}}
	return e
}

func TestScheduleTargetUpdateClosedContract(t *testing.T) {
	for _, kind := range []string{"user", "rotation"} {
		e := targetUpdateEvent()
		e.Effects[0].RuleDeletion.TargetKind = kind
		require.NoError(t, e.Validate())
		require.ErrorIs(t, Append(t.Context(), nil, e), ErrUnavailable)
		b, err := json.Marshal(e.Canonical().Effects)
		require.NoError(t, err)
		var fs []map[string]any
		require.NoError(t, json.Unmarshal(b, &fs))
		require.Len(t, fs[0], 11)
		require.Len(t, fs[0]["rule_deletion"], 3)
		require.NotContains(t, string(b), "start")
		require.NotContains(t, string(b), "destination")
	}
	for name, change := range map[string]func(*Event){
		"wrong_operation":    func(e *Event) { e.Operation = "schedule.delete" },
		"wrong_root":         func(e *Event) { e.RootType = Rotation },
		"mixed_version":      func(e *Event) { e.EffectsVersion = 1 },
		"empty_success":      func(e *Event) { e.Effects = nil },
		"wrong_root_cause":   func(e *Event) { e.Cause = "schedule_delete" },
		"wrong_effect_cause": func(e *Event) { e.Effects[0].Cause = "rotation_delete" },
		"cascade":            func(e *Event) { e.Effects[0].Provenance = "CASCADE" },
		"wrong_org":          func(e *Event) { e.Effects[0].TargetOrganizationID = uuid.New() },
		"wrong_parent":       func(e *Event) { e.Effects[0].RuleDeletion.ScheduleID = uuid.New() },
		"deleted_target":     func(e *Event) { e.Effects[0].ResourceType = "user" },
		"nil_target":         func(e *Event) { e.Effects[0].RuleDeletion.TargetID = uuid.Nil },
		"wrong_target_kind":  func(e *Event) { e.Effects[0].RuleDeletion.TargetKind = "scheduleTarget" },
		"full_rule":          func(e *Event) { e.Effects[0].Rule = &RuleDetail{} },
		"extra_numeric_id":   func(e *Event) { n := int64(1); e.Effects[0].ResourceNumericID = &n },
		"state":              func(e *Event) { e.BeforeState = &RotationState{} },
		"duplicate_rule":     func(e *Event) { f := e.Effects[0]; f.EffectID = uuid.New(); e.Effects = append(e.Effects, f) },
		"duplicate_effect": func(e *Event) {
			f := e.Effects[0]
			id := uuid.New()
			f.ResourceUUID = &id
			e.Effects = append(e.Effects, f)
		},
		"mixed_targets": func(e *Event) {
			f := e.Effects[0]
			id := uuid.New()
			f.ResourceUUID, f.EffectID = &id, uuid.New()
			d := *f.RuleDeletion
			d.TargetID = uuid.New()
			f.RuleDeletion = &d
			e.Effects = append(e.Effects, f)
		},
		"failed_with_effects": func(e *Event) {
			e.RecordKind, e.Outcome, e.Reason, e.Provenance, e.DeletionMechanism, e.Cause = "attempt_observation", "commit_unknown", "commit_unconfirmed", "", "", ""
		},
	} {
		t.Run(name, func(t *testing.T) { e := targetUpdateEvent(); change(&e); require.ErrorIs(t, e.Validate(), ErrInvalid) })
	}
	for _, outcome := range [][2]string{{"denied", "authority_denied"}, {"validation_failed", "invalid_fields"}, {"tx_failed", "audit_write_failed"}, {"commit_unknown", "commit_unconfirmed"}, {"rollback_unconfirmed", "rollback_unconfirmed"}} {
		e := targetUpdateEvent()
		e.RecordKind, e.Outcome, e.Reason, e.Provenance, e.DeletionMechanism, e.Cause = "attempt_observation", outcome[0], outcome[1], "", "", ""
		e.Effects = nil
		require.NoError(t, e.Validate())
	}
}

func TestScheduleTargetUpdateV1SeparationAndCapacity(t *testing.T) {
	e := targetUpdateEvent()
	e.SchemaVersion, e.EffectsVersion, e.Operation, e.Reason, e.Cause = 1, 1, "schedule.delete", "deleted", "explicit_target"
	// The new detail is never accepted by the historical Root Delete validator.
	require.ErrorIs(t, e.Validate(), ErrInvalid)
	for _, typ := range []string{Schedule, Rotation} {
		require.NoError(t, testEvent(typ).Validate())
	}
	e = targetUpdateEvent()
	template := e.Effects[0]
	e.Effects = make([]Effect, MaxEffects)
	for i := range e.Effects {
		id := uuid.New()
		f := template
		f.ResourceUUID, f.EffectID = &id, uuid.New()
		e.Effects[i] = f
	}
	require.ErrorIs(t, e.Validate(), ErrCapacity, "the byte budget can bind before the count budget")
	require.NoError(t, func() error { small := e; small.Effects = e.Effects[:210]; return small.Validate() }())
	e.Effects = append(e.Effects, template)
	require.ErrorIs(t, e.Validate(), ErrCapacity)
}
