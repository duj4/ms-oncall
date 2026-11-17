package usersessioncompat

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/assignment"
	ds "github.com/target/goalert/deletionsafety"
	"github.com/target/goalert/graphql2/graphqlapp"
	"github.com/target/goalert/permission"
)

// This is the existing UserSessionList mutation, including its variable and
// one-element input array. Authority comes from the signed HTTP Session.
const sessionCompatUIMutation = `mutation ($id: ID!) {
  deleteAll(input: [{ id: $id, type: userSession }])
}`

func sessionCompatSucceeded(t *testing.T, response map[string]json.RawMessage) {
	t.Helper()
	require.Empty(t, response["errors"], "Session response withheld")
	var data struct{ DeleteAll bool }
	require.NoError(t, json.Unmarshal(response["data"], &data))
	require.True(t, data.DeleteAll)
}

func TestUserSessionCompatUIContract(t *testing.T) {
	f := newFixture(t)
	h := f.h
	var version string
	require.NoError(t, h.App().DB().QueryRow(`SHOW server_version`).Scan(&version))
	require.Equal(t, "17.11", version)
	require.EqualValues(t, 307, countSQL(t, h, `SELECT max(canonical_position) FROM ms_oncall_migration_provenance`))
	require.EqualValues(t, 307, countSQL(t, h, `SELECT count(*) FROM gorp_migrations`))
	t.Log("PostgreSQL 17.11; fresh migration 0 -> 307; provenance tail 307")
	id, safe := createSession(t, h, h.UUID("om"))
	profile := request(t, h, f.tokens["om"], `{user{sessions{id current}}}`, nil)
	require.Empty(t, profile["errors"])
	var data struct {
		User struct{ Sessions []struct{ ID string } }
	}
	require.NoError(t, json.Unmarshal(profile["data"], &data))
	found := false
	for _, session := range data.User.Sessions {
		found = found || session.ID == id
	}
	require.True(t, found, "UI selector must come from the existing Session query")
	before := successCount(t, h)
	response := request(t, h, f.tokens["om"], sessionCompatUIMutation, map[string]any{"id": id})
	sessionCompatSucceeded(t, response)
	require.Zero(t, countSQL(t, h, `SELECT count(*) FROM auth_user_sessions WHERE id=$1`, id))
	require.Equal(t, before+1, successCount(t, h))
	var bound bool
	require.NoError(t, h.App().DB().QueryRow(`SELECT
 e.selection_mode='selected_sessions' AND e.operation='user_session.revoke'
 AND e.outcome='committed' AND e.reason_code='revoked' AND e.affected_count=1
 AND e.actor_id=$2 AND e.initiator_user_id=$2 AND e.home_organization_id=$3
 AND d.session_audit_id=$1 AND d.target_user_id=$2 AND d.target_organization_id=$3
 AND d.target_org_resolution='known_normal' AND d.provenance='EXPLICIT'
 AND d.deletion_mechanism='explicit_sql' AND d.cause='explicit_target'
 FROM user_session_revoke_audit_events e JOIN user_session_revoke_audit_details d USING(event_id)
 WHERE d.session_audit_id=$1`, safe, h.UUID("om"), h.UUID("s2-org-a")).Scan(&bound))
	require.True(t, bound, "committed SD9 attribution and safe persistent identity")
	var stored []byte
	require.NoError(t, h.App().DB().QueryRow(`SELECT (to_jsonb(e)||jsonb_build_object('detail',to_jsonb(d)))::text FROM user_session_revoke_audit_events e JOIN user_session_revoke_audit_details d USING(event_id) WHERE d.session_audit_id=$1`, safe).Scan(&stored))
	require.False(t, id == safe.String(), "audit identity must differ from locator")
	for _, raw := range [][]byte{stored, response["data"], response["extensions"]} {
		sessionIdentityAbsent(t, raw, id, f.sessions["om"], f.tokens["om"])
	}
	// A fresh transaction replay is a Missing no-op, with no second success.
	sessionCompatSucceeded(t, request(t, h, f.tokens["om"], sessionCompatUIMutation, map[string]any{"id": id}))
	require.Equal(t, before+1, successCount(t, h))
}

func sessionIdentityAbsent(t *testing.T, raw []byte, private ...string) {
	t.Helper()
	for _, value := range private {
		// Boolean assertions deliberately withhold credentials and locators.
		require.False(t, value != "" && bytes.Contains(raw, []byte(value)), "private Session material leaked")
	}
}

func TestUserSessionCompatMixedAndMalformed(t *testing.T) {
	f := newFixture(t)
	h := f.h
	h.IgnoreErrorsWith("GraphQL operation failed") // Deliberate invalid inputs below.
	id, safe := createSession(t, h, h.UUID("om"))
	before, successes := businessSnapshot(t, f), successCount(t, h)
	for _, root := range []struct{ typ, id string }{
		{"user", h.UUID("om")}, {"service", h.UUID("svc-a")},
		{"escalationPolicy", h.UUID("ep-a")}, {"schedule", h.UUID("sched-a")},
		{"rotation", h.UUID("rot-a")}, {"contactMethod", h.UUID("cm-om")},
		{"notificationRule", h.UUID("nr-om")}, {"integrationKey", uuid.NewString()},
		{"userOverride", uuid.NewString()}, {"calendarSubscription", uuid.NewString()},
		{"heartbeatMonitor", uuid.NewString()},
	} {
		t.Run(root.typ, func(t *testing.T) {
			for _, sessionFirst := range []bool{true, false} {
				one := map[string]any{"type": "userSession", "id": id}
				two := map[string]any{"type": root.typ, "id": root.id}
				input := []any{one, two}
				if !sessionFirst {
					input = []any{two, one}
				}
				r := request(t, h, f.tokens["pam"], `mutation($input:[TargetInput!]){deleteAll(input:$input,confirmation:{expectedImpactVersion:"guessed",acknowledgeImpacts:true})}`, map[string]any{"input": input})
				require.NotEmpty(t, r["errors"])
				require.Contains(t, string(r["errors"]), string(ds.DeletionUnavailable))
				sessionIdentityAbsent(t, r["errors"], id, f.tokens["pam"])
			}
		})
	}
	for _, tc := range []struct {
		name, query string
		variables   map[string]any
		status      int
	}{
		{"malformed-id", sessionCompatUIMutation, map[string]any{"id": "invalid-session-id"}, 200},
		{"empty-id", sessionCompatUIMutation, map[string]any{"id": ""}, 200},
		{"null-id", sessionCompatUIMutation, map[string]any{"id": nil}, 422},
		{"missing-variable", sessionCompatUIMutation, nil, 422},
		{"null-selector", `mutation{deleteAll(input:[null])}`, nil, 422},
		{"missing-type", `mutation{deleteAll(input:[{id:"invalid"}])}`, nil, 422},
		{"unsupported", `mutation{deleteAll(input:[{type:calendarSubscription,id:"invalid"}])}`, nil, 200},
		{"unknown-mixed", `mutation($id:ID!){deleteAll(input:[{type:userSession,id:$id},{type:unknown,id:"invalid"}])}`, map[string]any{"id": id}, 422},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := request(t, h, f.tokens["pam"], tc.query, tc.variables, tc.status)
			require.NotEmpty(t, r["errors"])
			sessionIdentityAbsent(t, r["errors"], id, f.tokens["pam"])
		})
	}
	// Null/omitted/empty input keeps the original harmless no-op contract.
	for _, query := range []string{`mutation{deleteAll(input:[])}`, `mutation{deleteAll(input:null)}`, `mutation{deleteAll}`} {
		sessionCompatSucceeded(t, request(t, h, f.tokens["pam"], query, nil))
	}
	require.Equal(t, before, businessSnapshot(t, f))
	require.Equal(t, successes, successCount(t, h))
	require.EqualValues(t, 1, countSQL(t, h, `SELECT count(*) FROM auth_user_sessions WHERE id=$1`, id))
	require.Zero(t, countSQL(t, h, `SELECT count(*) FROM user_session_revoke_audit_details WHERE session_audit_id=$1`, safe))
}

func TestUserSessionCompatAuthorityFailClosed(t *testing.T) {
	f := newFixture(t)
	h := f.h
	id, safe := createSession(t, h, h.UUID("aowner"))
	before := successCount(t, h)
	// Neither ordinary membership nor Org Admin grants other-user revocation,
	// including a target in the caller's own Organization.
	for _, actor := range []string{"om", "oa", "ba"} {
		sessionCompatSucceeded(t, request(t, h, f.tokens[actor], sessionCompatUIMutation, map[string]any{"id": id}))
	}
	// Existing signed credentials do not preserve a revoked platform role.
	execSQL(t, h, `UPDATE users SET role='user' WHERE id=$1`, h.UUID("pam"))
	sessionCompatSucceeded(t, request(t, h, f.tokens["pam"], sessionCompatUIMutation, map[string]any{"id": id}))
	a := &graphqlapp.App{DB: h.App().DB(), AuthHandler: h.App().AuthHandler}
	for _, ctx := range []context.Context{
		t.Context(), permission.UserContext(t.Context(), h.UUID("pam"), permission.RoleAdmin),
		permission.UserSourceContext(t.Context(), h.UUID("pam"), permission.RoleAdmin, &permission.SourceInfo{Type: permission.SourceTypeAuthProvider, ID: id}),
	} {
		ok, err := a.Mutation().DeleteAll(ctx, []assignment.RawTarget{{Type: assignment.TargetTypeUserSession, ID: id}}, nil)
		require.False(t, ok)
		require.Error(t, err)
		sessionIdentityAbsent(t, []byte(err.Error()), id)
	}
	// A signed Session whose live server-side organization assignment vanished
	// cannot recover authority from the selector or the cookie.
	execSQL(t, h, `DELETE FROM user_organization_assignments WHERE user_id=$1`, h.UUID("paa"))
	status, r := requestRaw(t, h, f.tokens["paa"], selectedQuery(id), nil)
	require.True(t, status == http.StatusUnauthorized || status == http.StatusForbidden || len(r["errors"]) > 0)
	require.Equal(t, before, successCount(t, h))
	require.EqualValues(t, 1, countSQL(t, h, `SELECT count(*) FROM auth_user_sessions WHERE id=$1`, id))
	require.Zero(t, countSQL(t, h, `SELECT count(*) FROM user_session_revoke_audit_details WHERE session_audit_id=$1`, safe))
}

func TestUserSessionCompatAuditFailureAtomicity(t *testing.T) {
	f := newFixture(t)
	h := f.h
	h.IgnoreErrorsWith("GraphQL operation failed") // Injected append/commit failures.
	for _, mode := range []string{"header", "detail", "commit", "end_other"} {
		t.Run(mode, func(t *testing.T) {
			id, safe := createSession(t, h, h.UUID("om"))
			before := countSQL(t, h, `SELECT count(*) FROM auth_user_sessions`)
			successes := successCount(t, h)
			table, timing := "user_session_revoke_audit_events", "BEFORE"
			if mode == "detail" {
				table = "user_session_revoke_audit_details"
			}
			if mode == "commit" {
				timing = "AFTER"
			}
			execSQL(t, h, fmt.Sprintf(`CREATE SEQUENCE compat_append_seen;
 CREATE FUNCTION compat_append_failure() RETURNS trigger LANGUAGE plpgsql AS $$
 BEGIN
 IF TG_TABLE_NAME='user_session_revoke_audit_details' OR to_jsonb(NEW)->>'record_kind'='success_witness' THEN
  IF EXISTS(SELECT FROM auth_user_sessions WHERE audit_resource_id='%s'::uuid) THEN RAISE EXCEPTION 'revocation not reached'; END IF;
  PERFORM nextval('compat_append_seen'); RAISE EXCEPTION 'SYNTHETIC_PRIVATE_APPEND';
 END IF; RETURN NEW; END $$;`, safe))
			if mode == "commit" {
				execSQL(t, h, `CREATE CONSTRAINT TRIGGER compat_append_failure AFTER INSERT ON user_session_revoke_audit_events DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION compat_append_failure()`)
			} else {
				execSQL(t, h, fmt.Sprintf(`CREATE TRIGGER compat_append_failure %s INSERT ON %s FOR EACH ROW EXECUTE FUNCTION compat_append_failure()`, timing, table))
			}
			query, actor := sessionCompatUIMutation, "pam"
			if mode == "end_other" {
				query, actor = `mutation{endAllAuthSessionsByCurrentUser}`, "om"
			}
			r := request(t, h, f.tokens[actor], query, map[string]any{"id": id})
			require.NotEmpty(t, r["errors"])
			sessionIdentityAbsent(t, r["errors"], id, "SYNTHETIC_PRIVATE_APPEND")
			require.EqualValues(t, 1, countSQL(t, h, `SELECT count(*) FROM compat_append_seen WHERE is_called AND last_value=1`), "real append failure after DELETE must be reached once")
			require.Equal(t, before, countSQL(t, h, `SELECT count(*) FROM auth_user_sessions`))
			require.EqualValues(t, 1, countSQL(t, h, `SELECT count(*) FROM auth_user_sessions WHERE id=$1`, id))
			require.Equal(t, successes, successCount(t, h))
			require.Zero(t, countSQL(t, h, `SELECT count(*) FROM user_session_revoke_audit_details WHERE session_audit_id=$1`, safe))
			execSQL(t, h, fmt.Sprintf(`DROP TRIGGER compat_append_failure ON %s; DROP FUNCTION compat_append_failure(); DROP SEQUENCE compat_append_seen`, table))
		})
	}
	// End-other still keeps the current and foreign Sessions and audits actual
	// self revocations on its unchanged entry point.
	foreign := f.sessions["b"]
	r := request(t, h, f.tokens["om"], `mutation{endAllAuthSessionsByCurrentUser}`, nil)
	require.Empty(t, r["errors"])
	require.EqualValues(t, 2, countSQL(t, h, `SELECT count(*) FROM auth_user_sessions WHERE id=ANY($1)`, []string{foreign, f.sessions["om"]}))
	require.EqualValues(t, 1, countSQL(t, h, `SELECT count(*) FROM user_session_revoke_audit_events WHERE selection_mode='other_sessions_of_current_user' AND record_kind='success_witness'`))
}
