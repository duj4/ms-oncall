package sessionaudit

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func testEvent() Event {
	now := time.Now().UTC().Truncate(time.Microsecond)
	actor, home := uuid.New(), uuid.New()
	return Event{SchemaVersion: 1, EventID: uuid.New(), RequestID: uuid.New(), ExecutionID: uuid.New(), AttemptID: uuid.New(), RecordKind: "success_witness", Operation: "user_session.revoke", SelectionMode: "selected_sessions", ActorKind: "human", ActorID: &actor, InitiatorKind: "human", InitiatorUserID: &actor, HomeOrganizationID: &home, AuthoritySource: "current_local_user_organization_at_admission", AuthorityRole: "org_member", OrganizationRole: "ORG_MEMBER", AffectedCount: 1, Outcome: "committed", Reason: "revoked", OccurredAt: now, RecordedAt: now}
}
func TestClosedEventAndDetail(t *testing.T) {
	e := testEvent()
	require.NoError(t, e.Validate())
	raw, err := json.Marshal(e)
	require.NoError(t, err)
	decoded, err := DecodeEvent(raw)
	require.NoError(t, err)
	require.Equal(t, e, decoded)
	var original map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(raw, &original))
	for key := range original {
		t.Run(key, func(t *testing.T) {
			for _, mode := range []string{"missing", "null"} {
				var obj map[string]json.RawMessage
				require.NoError(t, json.Unmarshal(raw, &obj))
				if mode == "missing" {
					delete(obj, key)
				} else {
					obj[key] = json.RawMessage(`null`)
				}
				bad, err := json.Marshal(obj)
				require.NoError(t, err)
				_, err = DecodeEvent(bad)
				require.Error(t, err)
			}
		})
	}
	for _, bad := range []string{string(raw) + `{}`, strings.Replace(string(raw), `"schema_version":1`, `"schema_version":1,"schema_version":1`, 1), strings.Replace(string(raw), `"schema_version":1`, `"schema_version":1,"session_id":"SYNTHETIC_FORBIDDEN"`, 1), strings.Replace(string(raw), `"affected_count":"1"`, `"affected_count":1`, 1)} {
		_, err = DecodeEvent([]byte(bad))
		require.Error(t, err)
	}
	d := Detail{EventID: e.EventID, Ordinal: 0, SessionAuditID: uuid.New(), TargetUserID: &uuid.Nil, TargetOrgResolution: "unknown", Provenance: "EXPLICIT", DeletionMechanism: "explicit_sql", Cause: "explicit_target"}
	require.NoError(t, d.Validate(e))
	raw, err = json.Marshal(d)
	require.NoError(t, err)
	_, err = DecodeDetail(raw, e)
	require.NoError(t, err)
	d.Ordinal = 1
	require.Error(t, d.Validate(e))
	d.Ordinal = 0
	d.SessionAuditID = uuid.Nil
	require.Error(t, d.Validate(e))
}
func TestObservationAndBindingRules(t *testing.T) {
	e := testEvent()
	e.RecordKind = "attempt_observation"
	e.AffectedCount = 0
	e.Outcome = "commit_unknown"
	e.Reason = "commit_unconfirmed"
	require.NoError(t, e.Validate())
	e.AffectedCount = 1
	require.Error(t, e.Validate())
	e.AffectedCount = 0
	e.InitiatorUserID = ID(uuid.New())
	require.Error(t, e.Validate())
	e = testEvent()
	e.SelectionMode = "other_sessions_of_current_user"
	d := Detail{EventID: e.EventID, SessionAuditID: uuid.New(), TargetUserID: e.ActorID, TargetOrgResolution: "unknown", Provenance: "EXPLICIT", DeletionMechanism: "explicit_sql", Cause: "end_other_self_sessions"}
	require.NoError(t, d.Validate(e))
	d.TargetUserID = ID(uuid.New())
	require.Error(t, d.Validate(e))
}
