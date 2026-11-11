package deleteaudit

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/organization"
)

func testEvent() Event {
	return Event{SchemaVersion: 1, EffectsVersion: 1, EventID: uuid.New(), RequestID: uuid.New(), ExecutionID: uuid.New(), AttemptID: uuid.New(), RecordKind: "success_witness", RootID: uuid.New(), TargetOrganizationID: uuid.New(), TargetOrgResolution: "known_normal", Provenance: "EXPLICIT", DeletionMechanism: "explicit_sql", Cause: "explicit_target", ActorKind: "internal_system", AuthoritySource: "trusted_internal_system", AuthorityRole: "internal_system", OrganizationRole: "unknown", Outcome: "committed", Reason: "deleted", OccurredAt: time.Now()}
}
func testStep(e Event) Effect {
	id, n := uuid.New(), 0
	return Effect{EffectID: uuid.New(), ResourceType: Step, RootID: e.RootID, TargetOrganizationID: e.TargetOrganizationID, Relation: "escalation_policy.step", Change: "deleted", Provenance: "CASCADE", DeletionMechanism: "fk_cascade", Cause: "escalation_policy_delete", ResourceUUID: &id, StepNumber: &n}
}
func TestEscalationPolicyDeleteClosedEvent(t *testing.T) {
	e := testEvent()
	require.NoError(t, e.Validate())
	raw, err := json.Marshal(e.Canonical().Effects)
	require.NoError(t, err)
	require.Equal(t, "[]", string(raw))
	for name, change := range map[string]func(*Event){
		"unknown_success": func(e *Event) { e.ActorKind, e.AuthoritySource, e.AuthorityRole = "unknown", "unknown", "unknown" },
		"missing_root":    func(e *Event) { e.RootID = uuid.Nil },
		"default_target":  func(e *Event) { e.TargetOrganizationID = uuid.MustParse(organization.DefaultOrganizationID) },
		"wrong_version":   func(e *Event) { e.EffectsVersion = 2 },
		"wrong_reason":    func(e *Event) { e.Reason = "SYNTHETIC_SECRET" },
		"system_human":    func(e *Event) { e.ActorID = uuid.New() },
		"nil_request":     func(e *Event) { e.RequestID = uuid.Nil },
		"org_admin_foreign": func(e *Event) {
			e.ActorKind, e.ActorID, e.HomeOrganizationID, e.AuthoritySource, e.AuthorityRole, e.OrganizationRole = "human", uuid.New(), uuid.New(), "current_local_user_organization_at_admission", "org_admin", "ORG_ADMIN"
		},
	} {
		t.Run(name, func(t *testing.T) { e := testEvent(); change(&e); require.ErrorIs(t, e.Validate(), ErrInvalid) })
	}
	e.ActorKind, e.ActorID, e.HomeOrganizationID, e.AuthoritySource, e.AuthorityRole, e.OrganizationRole = "human", uuid.New(), uuid.MustParse(organization.DefaultOrganizationID), "current_local_user_organization_at_admission", "platform_admin", "NONE"
	require.NoError(t, e.Validate())
	for _, reason := range []string{"invalid_fields", "target_unavailable", "target_in_use"} {
		e := testEvent()
		e.RecordKind, e.Outcome, e.Reason, e.Provenance, e.DeletionMechanism, e.Cause = "attempt_observation", "validation_failed", reason, "", "", ""
		e.RootID, e.TargetOrganizationID, e.TargetOrgResolution = uuid.Nil, uuid.Nil, "unknown"
		require.NoError(t, e.Validate())
	}
}
func TestEscalationPolicyDeleteClosedEffects(t *testing.T) {
	for name, change := range map[string]func(*Effect){
		"unknown": func(f *Effect) { f.ResourceType = "unknown" }, "wrong_root": func(f *Effect) { f.RootID = uuid.New() }, "wrong_org": func(f *Effect) { f.TargetOrganizationID = uuid.New() }, "bad_provenance": func(f *Effect) { f.Provenance = "EXPLICIT" }, "step_target": func(f *Effect) { f.TargetKind = "user" }, "negative_step": func(f *Effect) { n := -1; f.StepNumber = &n }, "missing_identity": func(f *Effect) { f.ResourceUUID = nil }, "zero_identity": func(f *Effect) { id := uuid.Nil; f.ResourceUUID = &id }, "mixed_identity": func(f *Effect) { n := int64(1); f.ResourceNumericID = &n }, "wrong_change": func(f *Effect) { f.Change = "relationship_removed" },
	} {
		t.Run(name, func(t *testing.T) {
			e := testEvent()
			f := testStep(e)
			change(&f)
			e.Effects = []Effect{f}
			require.ErrorIs(t, e.Validate(), ErrInvalid)
		})
	}
	e := testEvent()
	step := testStep(e)
	id, target := uuid.New(), uuid.New()
	action := step
	action.EffectID, action.ResourceType, action.ResourceUUID, action.StepNumber, action.ParentStepID, action.TargetKind, action.TargetID, action.Relation = uuid.New(), Action, &id, nil, step.ResourceUUID, "notification_channel", &target, "escalation_policy.step.action"
	e.Effects = []Effect{action, step}
	require.NoError(t, e.Validate())
	e.Effects = []Effect{action}
	require.ErrorIs(t, e.Validate(), ErrInvalid)
	e.Effects = []Effect{step, step}
	require.ErrorIs(t, e.Validate(), ErrInvalid)
	other := e
	other.EventID, other.RootID = uuid.New(), uuid.New()
	other.Effects = []Effect{step}
	other.Effects[0].RootID = other.RootID
	e.Effects = []Effect{step}
	require.ErrorIs(t, ValidateBatch([]Event{e, other}), ErrInvalid)
}
func TestEscalationPolicyDeleteGroupBudget(t *testing.T) {
	e := testEvent()
	for i := 0; i < MaxEffects; i++ {
		e.Effects = append(e.Effects, testStep(e))
	}
	require.NoError(t, e.Validate())
	require.NoError(t, ValidateBatch([]Event{e}))
	e.Effects = append(e.Effects, testStep(e))
	require.ErrorIs(t, e.Validate(), ErrCapacity)
	e.Effects = e.Effects[:MaxEffects]
	other := testEvent()
	other.Effects = []Effect{testStep(other)}
	require.ErrorIs(t, ValidateBatch([]Event{e, other}), ErrCapacity)
	// Favorites have a larger closed projection. Each root fits, but their shared
	// encoded byte budget fails; no arbitrary padding/free-text field is needed.
	a, b := testEvent(), testEvent()
	for _, root := range []*Event{&a, &b} {
		for i := int64(1); i <= 8000; i++ {
			owner, org := uuid.New(), uuid.New()
			id := i
			if root == &b {
				id += 8000
			}
			f := testStep(*root)
			f.ResourceType, f.ResourceUUID, f.StepNumber, f.ResourceNumericID, f.OwnerUserID, f.OwnerOrganizationID, f.OwnerOrgResolution, f.Relation, f.Change = Favorite, nil, nil, &id, &owner, &org, "known_normal", "escalation_policy.favorite", "relationship_removed"
			root.Effects = append(root.Effects, f)
		}
	}
	require.NoError(t, a.Validate())
	require.NoError(t, b.Validate())
	require.ErrorIs(t, ValidateBatch([]Event{a, b}), ErrCapacity)
}
