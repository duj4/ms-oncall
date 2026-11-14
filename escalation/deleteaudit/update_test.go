package deleteaudit

import (
	"encoding/json"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func updateEvent(operation string) Event {
	e := testEvent()
	e.SchemaVersion, e.EffectsVersion, e.Operation = 2, 2, operation
	e.Reason, e.Cause = "children_deleted", "update_induced"
	if operation == StepUpdate {
		e.ParentPolicyID = uuid.New()
	}
	return e
}

func updateAction(e Event, step uuid.UUID, kind string) Effect {
	id, target := uuid.New(), uuid.New()
	f := Effect{EffectID: uuid.New(), ResourceType: Action, RootID: e.RootID, TargetOrganizationID: e.TargetOrganizationID,
		ResourceUUID: &id, ParentStepID: &step, TargetKind: kind, TargetID: &target, Relation: "escalation_policy.step.action",
		Change: "deleted", Provenance: "EXPLICIT", DeletionMechanism: "explicit_sql", Cause: "update_induced"}
	if e.Operation == PolicyUpdate {
		f.Provenance, f.DeletionMechanism, f.Cause = "CASCADE", "fk_cascade", "step_delete"
	}
	return f
}

func TestEPUpdateContractRealSurvivingStep(t *testing.T) {
	for _, kind := range []string{"user", "schedule", "rotation", "notification_channel"} {
		t.Run(kind, func(t *testing.T) {
			e := updateEvent(StepUpdate)
			e.Effects = []Effect{updateAction(e, e.RootID, kind)}
			require.NoError(t, e.Validate())
			require.Equal(t, Step, e.RootType())
			// This exact Action-only shape remains invalid for accepted Root Delete.
			old := testEvent()
			f := e.Effects[0]
			f.RootID, f.TargetOrganizationID = old.RootID, old.TargetOrganizationID
			f.Provenance, f.DeletionMechanism, f.Cause = "CASCADE", "fk_cascade", "escalation_policy_delete"
			old.Effects = []Effect{f}
			require.ErrorIs(t, old.Validate(), ErrInvalid)
		})
	}
}

func TestEPUpdateContractStepCascadeAndClosedProjection(t *testing.T) {
	e := updateEvent(PolicyUpdate)
	step := testStep(e)
	step.Provenance, step.DeletionMechanism, step.Cause = "EXPLICIT", "explicit_sql", "update_induced"
	action := updateAction(e, *step.ResourceUUID, "notification_channel")
	e.Effects = []Effect{action, step}
	require.NoError(t, e.Validate())
	require.Equal(t, "escalation_policy", e.RootType())
	for name, change := range map[string]func(*Event){
		"missing_deleted_parent":           func(e *Event) { e.Effects = e.Effects[:1] },
		"duplicate_object":                 func(e *Event) { f := e.Effects[0]; f.EffectID = uuid.New(); e.Effects = append(e.Effects, f) },
		"duplicate_effect_id":              func(e *Event) { e.Effects[1].EffectID = e.Effects[0].EffectID },
		"wrong_cascade_cause":              func(e *Event) { e.Effects[0].Cause = "escalation_policy_delete" },
		"explicit_action_in_policy_update": func(e *Event) { e.Effects[0].Provenance = "EXPLICIT" },
		"derived_on_call":                  func(e *Event) { e.Effects[0].ResourceType = "ep_step_on_call_users" },
		"state_set_null":                   func(e *Event) { e.Effects[0].ResourceType = "escalation_policy_state" },
		"favorite":                         func(e *Event) { e.Effects[0].ResourceType = Favorite },
		"mixed_owner":                      func(e *Event) { id := uuid.New(); e.Effects[0].OwnerUserID = &id },
		"unsafe_target_kind":               func(e *Event) { e.Effects[0].TargetKind = "SYNTHETIC_DESTINATION" },
		"wrong_root":                       func(e *Event) { e.Effects[0].RootID = uuid.New() },
		"wrong_org":                        func(e *Event) { e.Effects[0].TargetOrganizationID = uuid.New() },
		"zero_receipt":                     func(e *Event) { id := uuid.Nil; e.Effects[0].ResourceUUID = &id },
		"zero_target":                      func(e *Event) { id := uuid.Nil; e.Effects[0].TargetID = &id },
		"unknown_operation":                func(e *Event) { e.Operation = "updateScheduleTarget" },
		"empty_success":                    func(e *Event) { e.Effects = nil },
		"fabricated_policy_parent":         func(e *Event) { e.ParentPolicyID = uuid.New() },
	} {
		t.Run(name, func(t *testing.T) {
			copy := e
			copy.Effects = append([]Effect{}, e.Effects...)
			change(&copy)
			require.ErrorIs(t, copy.Validate(), ErrInvalid)
		})
	}
}

func TestEPUpdateContractFailuresAndVersionSeparation(t *testing.T) {
	for _, operation := range []string{PolicyUpdate, StepUpdate} {
		e := updateEvent(operation)
		e.RecordKind, e.Outcome, e.Reason = "attempt_observation", "commit_unknown", "commit_unconfirmed"
		e.Provenance, e.DeletionMechanism, e.Cause = "", "", ""
		require.NoError(t, e.Validate())
		e.Effects = []Effect{updateAction(e, e.RootID, "user")}
		require.ErrorIs(t, e.Validate(), ErrInvalid, "uncertainty never asserts committed deletions")
	}
	e := updateEvent(StepUpdate)
	e.Effects = []Effect{updateAction(e, e.RootID, "user")}
	e.ParentPolicyID = uuid.Nil
	require.ErrorIs(t, e.Validate(), ErrInvalid)
	e = updateEvent(StepUpdate)
	e.Effects = []Effect{updateAction(e, uuid.New(), "user")}
	require.ErrorIs(t, e.Validate(), ErrInvalid)
	e = updateEvent(StepUpdate)
	e.Effects = []Effect{testStep(e)}
	require.ErrorIs(t, e.Validate(), ErrInvalid, "surviving Step must not be fabricated as deleted")
	e = testEvent()
	e.Operation = PolicyUpdate
	require.ErrorIs(t, e.Validate(), ErrInvalid, "v1 operation remains closed")
}

func TestEPUpdateContractCanonicalAndCapacity(t *testing.T) {
	e := updateEvent(StepUpdate)
	a, b := updateAction(e, e.RootID, "user"), updateAction(e, e.RootID, "schedule")
	e.Effects = []Effect{a, b}
	first, err := json.Marshal(e.Canonical())
	require.NoError(t, err)
	e.Effects = []Effect{b, a}
	second, err := json.Marshal(e.Canonical())
	require.NoError(t, err)
	require.Equal(t, string(first), string(second))
	e.Effects = make([]Effect, MaxEffects+1)
	require.ErrorIs(t, e.Validate(), ErrCapacity)
}

func TestEPUpdateSourceDefaultCapacity(t *testing.T) {
	// Source defaults are 10 Steps and 20 Actions/Step, not a claim about a
	// deployed configuration. Configurable/no-limit installations still use
	// both count and byte guards and must roll back rather than truncate.
	e := updateEvent(PolicyUpdate)
	for n := range 10 {
		step := testStep(e)
		step.StepNumber = &n
		step.Provenance, step.DeletionMechanism, step.Cause = "EXPLICIT", "explicit_sql", "update_induced"
		e.Effects = append(e.Effects, step)
		for range 20 {
			e.Effects = append(e.Effects, updateAction(e, *step.ResourceUUID, "notification_channel"))
		}
	}
	require.Len(t, e.Effects, 210)
	require.NoError(t, e.Validate())
	raw, err := json.Marshal(e.Canonical().Effects)
	require.NoError(t, err)
	require.Less(t, len(raw), MaxJSONBytes)
	t.Logf("source-default U01 effects=%d compact JSON bytes=%d count limit=%d byte limit=%d", len(e.Effects), len(raw), MaxEffects, MaxJSONBytes)
}
