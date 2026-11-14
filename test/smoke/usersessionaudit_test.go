package smoke

import (
	"bytes"
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/assignment"
	"github.com/target/goalert/organization"
	"github.com/target/goalert/permission"
	"github.com/target/goalert/test/smoke/harness"
	"github.com/target/goalert/util/log"
)

func usSession(t *testing.T, h *harness.Harness, owner any) (string, uuid.UUID) {
	t.Helper()
	id := uuid.NewString()
	var safe uuid.UUID
	err := h.App().DB().QueryRow(`INSERT INTO auth_user_sessions(id,user_agent,user_id) VALUES($1,'SYNTHETIC_PRIVATE_UA',$2) RETURNING audit_resource_id`, id, owner).Scan(&safe)
	require.True(t, err == nil, "create synthetic Session (details withheld)")
	return id, safe
}
func usQuery(ids ...string) string {
	var targets []string
	for _, id := range ids {
		targets = append(targets, fmt.Sprintf(`{type:userSession,id:%q}`, id))
	}
	return `mutation{deleteAll(input:[` + strings.Join(targets, ",") + `])}`
}
func usSuccesses(t *testing.T, h *harness.Harness) int64 {
	return sd8Scalar(t, h, `SELECT count(*) FROM user_session_revoke_audit_events WHERE record_kind='success_witness'`)
}
func usHTTP(t *testing.T, f *s2Fixture, actor, query string, denied bool) map[string]json.RawMessage {
	t.Helper()
	r := asHTTP(t, f.h, f.tokens[actor], query, nil, true)
	require.Equal(t, denied, len(r["errors"]) > 0 && string(r["errors"]) != "null", "HTTP error classification (response withheld)")
	return r
}
func TestUserSessionAuditSignedReceiptAndAuthorization(t *testing.T) {
	f := globalOrganizationFixture(t)
	h := f.h
	for _, tc := range []struct {
		actor, owner    string
		denied, deleted bool
	}{
		{"pam", "b", false, true}, {"paa", "om", false, true}, {"om", "om", false, true}, {"oa", "oa", false, true},
		{"om", "b", false, false}, {"oa", "b", false, false}, {"pd0", "b", false, true}, {"pd0", "pd0", true, false}, {"od", "b", true, false},
	} {
		t.Run(tc.actor+"_"+tc.owner, func(t *testing.T) {
			id, safe := usSession(t, h, h.UUID(tc.owner))
			before := usSuccesses(t, h)
			usHTTP(t, f, tc.actor, usQuery(id), tc.denied)
			remaining := sd8Scalar(t, h, `SELECT count(*) FROM auth_user_sessions WHERE id=$1`, id)
			expected := int64(1)
			if tc.deleted {
				expected = 0
			}
			require.Equal(t, expected, remaining)
			count := sd8Scalar(t, h, `SELECT count(*) FROM user_session_revoke_audit_details WHERE session_audit_id=$1`, safe)
			if tc.deleted {
				require.EqualValues(t, 1, count)
				require.Equal(t, before+1, usSuccesses(t, h))
			} else {
				require.Zero(t, count)
				require.Equal(t, before, usSuccesses(t, h))
				return
			}
			home := h.UUID("s2-org-a")
			if tc.actor == "pd0" {
				home = organization.DefaultOrganizationID
			}
			var bound bool
			require.NoError(t, h.App().DB().QueryRow(`SELECT e.actor_id=$2 AND e.initiator_user_id=$2 AND e.home_organization_id=$3 AND d.target_user_id=$4 AND d.target_organization_id=$5 AND e.affected_count=1 AND d.effect_ordinal=0 AND d.cause='explicit_target' FROM user_session_revoke_audit_events e JOIN user_session_revoke_audit_details d USING(event_id) WHERE d.session_audit_id=$1`, safe, h.UUID(tc.actor), home, h.UUID(tc.owner), h.UUID("s2-org-"+map[bool]string{true: "b", false: "a"}[tc.owner == "b"])).Scan(&bound))
			require.True(t, bound, "Actor/Home/Target snapshots must be independent")
			usHTTP(t, f, tc.actor, usQuery(id), false)
			require.Equal(t, before+1, usSuccesses(t, h))
		})
	}
	// Duplicate input and multi-Organization receipts produce one complete root.
	one, s1 := usSession(t, h, h.UUID("om"))
	two, s2 := usSession(t, h, h.UUID("b"))
	before := usSuccesses(t, h)
	usHTTP(t, f, "pam", usQuery(one, two, one, uuid.NewString()), false)
	require.Equal(t, before+1, usSuccesses(t, h))
	require.EqualValues(t, 2, sd8Scalar(t, h, `SELECT count(*) FROM user_session_revoke_audit_details WHERE session_audit_id=ANY($1)`, []uuid.UUID{s1, s2}))
	// Normal-user batch and duplicate selectors use actual deleted rows too.
	for _, duplicate := range []bool{false, true} {
		one, s1 = usSession(t, h, h.UUID("om"))
		two, s2 = usSession(t, h, h.UUID("om"))
		before = usSuccesses(t, h)
		ids := []string{one, two}
		if duplicate {
			ids = append(ids, one, two)
		}
		usHTTP(t, f, "om", usQuery(ids...), false)
		require.Equal(t, before+1, usSuccesses(t, h))
		require.Zero(t, sd8Scalar(t, h, `SELECT count(*) FROM auth_user_sessions WHERE id=ANY($1)`, []string{one, two}))
		require.EqualValues(t, 2, sd8Scalar(t, h, `SELECT count(*) FROM user_session_revoke_audit_details WHERE session_audit_id=ANY($1)`, []uuid.UUID{s1, s2}))
	}
}
func TestUserSessionAuditEndAllAndAtomicRollback(t *testing.T) {
	f := globalOrganizationFixture(t)
	h := f.h
	owner := h.UUID("om")
	current := f.sessions["om"]
	one, s1 := usSession(t, h, owner)
	_, s2 := usSession(t, h, owner)
	foreign, _ := usSession(t, h, h.UUID("b"))
	usHTTP(t, f, "om", `mutation{endAllAuthSessionsByCurrentUser}`, false)
	require.EqualValues(t, 0, sd8Scalar(t, h, `SELECT count(*) FROM auth_user_sessions WHERE id=$1`, one))
	require.EqualValues(t, 2, sd8Scalar(t, h, `SELECT count(*) FROM auth_user_sessions WHERE id=ANY($1)`, []string{current, foreign}))
	require.EqualValues(t, 2, sd8Scalar(t, h, `SELECT count(*) FROM user_session_revoke_audit_details WHERE session_audit_id=ANY($1) AND cause='end_other_self_sessions'`, []uuid.UUID{s1, s2}))
	before := usSuccesses(t, h)
	usHTTP(t, f, "om", `mutation{endAllAuthSessionsByCurrentUser}`, false)
	require.Equal(t, before, usSuccesses(t, h))
	usHTTP(t, f, "pd0", `mutation{endAllAuthSessionsByCurrentUser}`, true)
	for _, mode := range []string{"end_all", "selected", "mixed"} {
		t.Run(mode, func(t *testing.T) {
			id, safe := usSession(t, h, owner)
			sd8Exec(t, h, `CREATE FUNCTION us_fail_detail() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'SYNTHETIC_PRIVATE_SQL';END;$$; CREATE TRIGGER us_fail_detail BEFORE INSERT ON user_session_revoke_audit_details FOR EACH ROW EXECUTE FUNCTION us_fail_detail()`)
			query := usQuery(id)
			actor := "pam"
			var contact string
			if mode == "end_all" {
				query = `mutation{endAllAuthSessionsByCurrentUser}`
				actor = "om"
			}
			if mode == "mixed" {
				contact, _ = sd8CMNR(t, h, owner)
				query = fmt.Sprintf(`mutation{deleteAll(input:[{type:contactMethod,id:%q},{type:userSession,id:%q}])}`, contact, id)
			}
			expected := h.ExpectBackendError("GraphQL operation failed")
			usHTTP(t, f, actor, query, true)
			expected()
			require.EqualValues(t, 1, sd8Scalar(t, h, `SELECT count(*) FROM auth_user_sessions WHERE id=$1`, id))
			require.Zero(t, sd8Scalar(t, h, `SELECT count(*) FROM user_session_revoke_audit_details WHERE session_audit_id=$1`, safe))
			if contact != "" {
				require.EqualValues(t, 1, sd8Scalar(t, h, `SELECT count(*) FROM user_contact_methods WHERE id=$1`, contact))
			}
			sd8Exec(t, h, `DROP TRIGGER us_fail_detail ON user_session_revoke_audit_details; DROP FUNCTION us_fail_detail()`)
		})
	}
	contact, _ := sd8CMNR(t, h, owner)
	id, safe := usSession(t, h, owner)
	usHTTP(t, f, "pam", fmt.Sprintf(`mutation{deleteAll(input:[{type:contactMethod,id:%q},{type:userSession,id:%q}])}`, contact, id), false)
	require.Zero(t, sd8Scalar(t, h, `SELECT count(*) FROM user_contact_methods WHERE id=$1`, contact))
	require.EqualValues(t, 1, sd8Scalar(t, h, `SELECT count(*) FROM user_session_revoke_audit_details d JOIN user_session_revoke_audit_events e USING(event_id) JOIN user_cmnr_delete_audit_events c ON c.request_id=e.request_id AND c.execution_id=e.execution_id AND c.attempt_id=e.attempt_id WHERE d.session_audit_id=$1 AND c.root_id=$2 AND c.record_kind='success_witness'`, safe, contact))

}
func TestUserSessionAuditSystemCascadeAndPaging(t *testing.T) {
	h := sd1Harness(t)
	a := sd7App(h)
	ctx := permission.SystemContext(t.Context(), "Engine")
	owner := sd7User(t, h)
	id, safe := usSession(t, h, owner)
	ok, err := a.Mutation().DeleteAll(ctx, []assignment.RawTarget{{Type: assignment.TargetTypeUser, ID: owner}, {Type: assignment.TargetTypeUserSession, ID: id}})
	require.NoError(t, err)
	require.True(t, ok)
	require.Zero(t, sd8Scalar(t, h, `SELECT count(*) FROM user_session_revoke_audit_details WHERE session_audit_id=$1`, safe))
	require.EqualValues(t, 1, sd8Scalar(t, h, `SELECT count(*) FROM user_delete_audit_effects WHERE resource_type='user_session' AND payload->>'provenance'='IMPLICIT_FK_CASCADE'`))
	// More than two pages, nullable historical owner, no artificial business cap.
	var ids []assignment.RawTarget
	for range 520 {
		id, _ := usSession(t, h, nil)
		ids = append(ids, assignment.RawTarget{Type: assignment.TargetTypeUserSession, ID: id})
	}
	before := usSuccesses(t, h)
	ok, err = a.Mutation().DeleteAll(ctx, ids)
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, before+1, usSuccesses(t, h))
	require.EqualValues(t, 520, sd8Scalar(t, h, `SELECT count(*) FROM user_session_revoke_audit_details WHERE target_user_id IS NULL AND target_org_resolution='unknown'`))
}
func TestUserSessionAuditDiagnostics(t *testing.T) {
	f := globalOrganizationFixture(t)
	h := f.h
	id, safe := usSession(t, h, h.UUID("om"))
	logger := log.FromContext(h.App().Context(context.Background()))
	logger.EnableDebug()
	canary := &asLogCanary{next: logger.Logrus().Out, private: []string{f.tokens["pam"], f.sessions["pam"], "SYNTHETIC_SESSION_ALIAS", "SYNTHETIC_AUTH_REFERER", "SYNTHETIC_PRIVATE_UA", "SYNTHETIC_PRIVATE_SQL", id}}
	logger.SetOutput(canary)

	usHTTP(t, f, "pam", strings.Replace(usQuery(id), "deleteAll", "SYNTHETIC_SESSION_ALIAS:deleteAll", 1), false)
	// Validation failure is selected before a resolver can run, aliases and traces
	// cannot bypass the request-completion projection.
	r := asHTTP(t, h, f.tokens["pam"], `mutation{SYNTHETIC_SESSION_ALIAS:endAllAuthSessionsByCurrentUser(bad:"SYNTHETIC_PRIVATE_SQL")}`, nil, true, 422)
	require.NotEmpty(t, r["errors"])
	var stored string
	require.NoError(t, h.App().DB().QueryRow(`SELECT to_jsonb(e)::text||to_jsonb(d)::text FROM user_session_revoke_audit_events e JOIN user_session_revoke_audit_details d USING(event_id) WHERE d.session_audit_id=$1`, safe).Scan(&stored))
	for _, value := range canary.private {
		require.False(t, bytes.Contains([]byte(stored), []byte(value)), "persistent projection leaked (sample withheld)")
	}
	require.Eventually(t, func() bool { return canary.mutation.Load() && canary.complete.Load() }, time.Second, 10*time.Millisecond)
	require.False(t, canary.leaked.Load(), "diagnostic projection leaked (sample withheld)")
}
func TestUserSessionAuditRealConcurrentCause(t *testing.T) {
	h := sd1Harness(t)
	db := h.App().DB()
	var name string
	require.NoError(t, db.QueryRow(`SELECT current_database()`).Scan(&name))
	for _, mode := range []string{"session_session", "session_user", "user_session", "rollback_session"} {
		t.Run(mode, func(t *testing.T) {
			owner := sd7User(t, h)
			id, safe := usSession(t, h, owner)
			ctx, cancel := context.WithTimeout(permission.SystemContext(context.Background(), "Engine"), 15*time.Second)
			defer cancel()
			c1, err := sd8PGConnector(harness.DBURL(name))
			require.NoError(t, err)
			c2, err := sd8PGConnector(harness.DBURL(name))
			require.NoError(t, err)
			d1, d2 := sql.OpenDB(c1), sql.OpenDB(c2)
			defer d1.Close()
			defer d2.Close()
			a1, a2 := sd7App(h), sd7App(h)
			a1.DB, a2.DB = d1, d2
			entered, release := make(chan struct{}), make(chan struct{})
			var once sync.Once
			unblock := func() { once.Do(func() { close(release) }) }
			defer unblock()
			c1.afterEntry = func(context.Context, driver.Conn) error { close(entered); <-release; return nil }
			if mode == "rollback_session" {
				var once atomic.Bool
				c1.beforeCommit = func(ctx context.Context, c driver.Conn) error {
					if once.CompareAndSwap(false, true) {
						_, _ = c.(driver.ExecerContext).ExecContext(ctx, `SELECT 1/0`, nil)
					}
					return nil
				}
			}
			targets := func(user bool) []assignment.RawTarget {
				if user {
					return []assignment.RawTarget{{Type: assignment.TargetTypeUser, ID: owner}}
				}
				return []assignment.RawTarget{{Type: assignment.TargetTypeUserSession, ID: id}}
			}
			done1, done2 := make(chan error, 1), make(chan error, 1)
			go func() { _, err := a1.Mutation().DeleteAll(ctx, targets(mode == "user_session")); done1 <- err }()
			<-entered
			go func() { _, err := a2.Mutation().DeleteAll(ctx, targets(mode == "session_user")); done2 <- err }()
			// Waiting is observed in PostgreSQL, rather than assumed from a sleep.
			require.Eventually(t, func() bool {
				return sd8Scalar(t, h, `SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND wait_event='advisory'`) > 0
			}, time.Second, 10*time.Millisecond)
			unblock()
			err1, err2 := <-done1, <-done2
			require.NoError(t, err2)
			if mode == "rollback_session" {
				require.Error(t, err1)
			} else {
				require.NoError(t, err1)
			}
			explicit := sd8Scalar(t, h, `SELECT count(*) FROM user_session_revoke_audit_details WHERE session_audit_id=$1`, safe)
			cascade := sd8Scalar(t, h, `SELECT count(*) FROM user_delete_audit_effects WHERE resource_type='user_session' AND payload->'before'->>'id'=$1`, id)
			require.EqualValues(t, 1, explicit+cascade)
			if mode == "user_session" {
				require.Zero(t, explicit)
			} else {
				require.EqualValues(t, 1, explicit)
			}
		})
	}
}

func TestUserSessionAuditSiblingDiagnostics(t *testing.T) {
	f := globalOrganizationFixture(t)
	h := f.h
	l := log.FromContext(h.App().Context(context.Background()))
	l.EnableDebug()
	original := l.Logrus().Out
	capture := &asDiagnosticLogs{next: original}
	l.SetOutput(capture)
	defer l.SetOutput(original)
	h.IgnoreErrorsWith("GraphQL operation failed")
	id, _ := usSession(t, h, h.UUID("om"))
	sensitive := strings.Replace(usQuery(id), "mutation{", "", 1)
	sensitive = strings.TrimSuffix(sensitive, "}")
	sibling := `SYNTHETIC_SESSION_SIBLING:sendSignal(input:{serviceID:"22222222-2222-4222-8222-222222222222",dest:{type:"synthetic-review",args:{}}})`
	for _, first := range []bool{true, false} {
		fields := sensitive + " " + sibling
		if !first {
			fields = sibling + " " + sensitive
		}
		r := asMixedRequest(t, h, f.tokens["pam"], "mutation SYNTHETIC_SESSION_OPERATION{"+fields+"}", "SYNTHETIC_SESSION_OPERATION")
		require.NotEmpty(t, r["errors"])
		require.NotContains(t, string(r["extensions"]), "tracing")
	}
	// Variables and two aliases create independent executions and complete roots.
	one, safe1 := usSession(t, h, h.UUID("om"))
	two, safe2 := usSession(t, h, h.UUID("om"))
	variables := map[string]any{"one": []any{map[string]any{"type": "userSession", "id": one}}, "two": []any{map[string]any{"type": "userSession", "id": two}}}
	r := asHTTP(t, h, f.tokens["pam"], `mutation($one:[TargetInput!]!,$two:[TargetInput!]!){SYNTHETIC_SESSION_ONE:deleteAll(input:$one) SYNTHETIC_SESSION_TWO:deleteAll(input:$two)}`, variables, true)
	require.Empty(t, r["errors"])
	require.NotContains(t, string(r["extensions"]), "tracing")
	require.EqualValues(t, 2, sd8Scalar(t, h, `SELECT count(DISTINCT e.execution_id) FROM user_session_revoke_audit_events e JOIN user_session_revoke_audit_details d USING(event_id) WHERE d.session_audit_id=ANY($1)`, []uuid.UUID{safe1, safe2}))
	require.Eventually(t, func() bool {
		n := 0
		for _, record := range capture.snapshot() {
			if record["msg"] == "request complete" {
				n++
			}
		}
		return n >= 3
	}, time.Second, 10*time.Millisecond)
	for _, record := range capture.snapshot() {
		raw, _ := json.Marshal(record)
		for _, private := range []string{"SYNTHETIC_SESSION", id, one, two, f.sessions["pam"], f.tokens["pam"]} {
			require.False(t, bytes.Contains(raw, []byte(private)), "sibling diagnostic projection leaked (sample withheld)")
		}
	}
}
