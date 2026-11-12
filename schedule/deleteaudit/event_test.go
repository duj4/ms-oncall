package deleteaudit

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func testEvent(typ string) Event {
	return Event{SchemaVersion: 1, EffectsVersion: 1, RootType: typ, Operation: typ + ".delete", EventID: uuid.New(), RequestID: uuid.New(), ExecutionID: uuid.New(), AttemptID: uuid.New(), RootID: uuid.New(), TargetOrganizationID: uuid.New(), TargetOrgResolution: "known_normal", RecordKind: "success_witness", Outcome: "committed", Reason: "deleted", Provenance: "EXPLICIT", DeletionMechanism: "explicit_sql", Cause: "explicit_target", ActorKind: "internal_system", AuthoritySource: "trusted_internal_system", AuthorityRole: "internal_system", OrganizationRole: "unknown", OccurredAt: time.Now()}
}
func testParticipant(e Event) Effect {
	id := uuid.New()
	return Effect{EffectID: uuid.New(), ResourceType: Participant, RootID: e.RootID, TargetOrganizationID: e.TargetOrganizationID, ResourceUUID: &id, Relation: "rotation.participant", Change: "relationship_removed", Provenance: "CASCADE", DeletionMechanism: "fk_cascade", Cause: "rotation_delete", Participant: &ParticipantDetail{UserID: uuid.New()}}
}
func TestSRClosedEventsAndAttribution(t *testing.T) {
	for _, typ := range []string{Schedule, Rotation} {
		e := testEvent(typ)
		require.NoError(t, e.Validate())
		require.ErrorIs(t, Append(t.Context(), nil, e), ErrUnavailable)
		for _, change := range []func(*Event){func(e *Event) { e.Operation = "other.delete" }, func(e *Event) { e.RootType = "user" }, func(e *Event) { e.ActorKind = "unknown" }, func(e *Event) { e.TargetOrganizationID = uuid.Nil }, func(e *Event) { e.ActorKind = "human"; e.ActorID = uuid.New() }, func(e *Event) { e.RecordKind = "attempt_observation" }, func(e *Event) { e.Cause = "cascade" }} {
			bad := e
			change(&bad)
			require.Error(t, bad.Validate())
		}
		e.RecordKind, e.Outcome, e.Reason, e.Provenance, e.DeletionMechanism, e.Cause = "attempt_observation", "commit_unknown", "commit_unconfirmed", "", "", ""
		require.NoError(t, e.Validate())
	}
	e := testEvent(Rotation)
	f := testParticipant(e)
	e.Effects = []Effect{f}
	require.NoError(t, e.Validate())
	s := &RotationState{ID: 1, ParticipantID: *f.ResourceUUID, Version: 2, ShiftStart: time.Now()}
	e.BeforeState = s
	require.NoError(t, e.Validate())
	s.Position = 1
	require.Error(t, e.Validate())
	s.Position = 0
	f.Action = &ActionDetail{PolicyID: uuid.New(), PolicyOrganizationID: e.TargetOrganizationID, StepID: uuid.New()}
	e.Effects = []Effect{f}
	require.ErrorIs(t, e.Validate(), ErrInvalid)
}

func TestSRProjectionIdentitiesAndSafety(t *testing.T) {
	e := testEvent(Schedule)
	start := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	end := start.Add(time.Hour)
	user, channel := uuid.New(), uuid.New()
	raw := fmt.Sprintf(`{"TemporarySchedules":[{"Start":%q,"End":%q,"Shifts":[{"Start":%q,"End":%q,"UserID":%q},{"Start":%q,"End":%q,"UserID":%q}],"future":"SYNTHETIC_PRIVATE"}],"OnCallNotificationRules":[{"ID":%q,"ChannelID":%q,"Time":"12:30","WeekdayFilter":"1010101","NextNotification":"SYNTHETIC_PRIVATE"}],"future":"SYNTHETIC_PRIVATE"}`, start.Format(time.RFC3339), end.Format(time.RFC3339), start.Format(time.RFC3339), end.Format(time.RFC3339), user, start.Format(time.RFC3339), end.Format(time.RFC3339), user, e.RootID.String()+":1", channel)
	effects, err := ProjectData(e, 42, []byte(raw), 4)
	require.NoError(t, err)
	require.Len(t, effects, 4)
	require.NotEqual(t, effects[1].Identity(), effects[2].Identity())
	e.Effects = effects
	require.NoError(t, e.Validate())
	encoded, _ := json.Marshal(effects)
	require.NotContains(t, string(encoded), "SYNTHETIC_")
	require.NotContains(t, string(encoded), "NextNotification")
	require.NotContains(t, string(encoded), "resource_uuid")
	_, err = ProjectData(e, 42, []byte(raw), 3)
	require.ErrorIs(t, err, ErrCapacity)
	for _, bad := range []string{strings.Replace(raw, user.String(), "SYNTHETIC_PRIVATE", 1), strings.Replace(raw, ":1", ":-1", 1), strings.Replace(raw, `"12:30"`, `"SYNTHETIC_PRIVATE"`, 1), strings.Replace(raw, `"1010101"`, `"2222222"`, 1)} {
		_, err := ProjectData(testEvent(Schedule), 42, []byte(bad), 100)
		require.Error(t, err)
	}
	e.Effects[2].Fragment.Ordinal = 0
	require.Error(t, e.Validate())
}

func TestSRSharedUnitAndByteBoundaries(t *testing.T) {
	e := testEvent(Rotation)
	for i := 0; i < MaxEffects; i++ {
		e.Effects = append(e.Effects, testParticipant(e))
	}
	require.NoError(t, e.Validate())
	require.NoError(t, ValidateBatch([]Event{e}))
	e.Effects = append(e.Effects, testParticipant(e))
	require.ErrorIs(t, e.Validate(), ErrCapacity)
	e.Effects = e.Effects[:MaxEffects]
	e.BeforeState = &RotationState{ID: 1, ParticipantID: *e.Effects[0].ResourceUUID, Version: 2, ShiftStart: time.Now()}
	require.ErrorIs(t, e.Validate(), ErrCapacity)
	e.BeforeState = nil
	other := testEvent(Schedule)
	n := int64(1)
	owner, org := uuid.New(), uuid.New()
	other.Effects = []Effect{{EffectID: uuid.New(), ResourceType: Favorite, RootID: other.RootID, TargetOrganizationID: other.TargetOrganizationID, ResourceNumericID: &n, Relation: "schedule.favorite", Change: "relationship_removed", Provenance: "CASCADE", DeletionMechanism: "fk_cascade", Cause: "schedule_delete", Favorite: &FavoriteDetail{OwnerUserID: owner, OwnerOrganizationID: &org, OwnerOrgResolution: "known_normal"}}}
	require.ErrorIs(t, ValidateBatch([]Event{e, other}), ErrCapacity)
	// Reach the nearest valid byte boundary with closed, real-sized identities;
	// no arbitrary strings, padding fields or weakened whitelist are involved.
	f := other.Effects[0]
	other.Effects = nil
	for i := 0; i < MaxEffects; i++ {
		x := f
		id := int64(10000 + i)
		x.ResourceNumericID = &id
		x.EffectID = uuid.New()
		other.Effects = append(other.Effects, x)
	}
	lo, hi := 0, len(other.Effects)
	all := other.Effects
	for lo < hi {
		mid := (lo + hi + 1) / 2
		other.Effects = all[:mid]
		if other.JSONBytes() <= MaxJSONBytes {
			lo = mid
		} else {
			hi = mid - 1
		}
	}
	require.Less(t, lo, len(all))
	other.Effects = all[:lo]
	require.NoError(t, other.Validate())
	other.Effects = all[:lo+1]
	require.ErrorIs(t, other.Validate(), ErrCapacity)
}
