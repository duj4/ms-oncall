package smoke

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/assignment"
	"github.com/target/goalert/test/smoke/harness"
)

// Exercise both the original prepared statement and the audited HTTP entry.
// Assertions use persisted rows and safe identities, never selector cardinality.
func TestUserSessionAuditU1UserMatrix(t *testing.T) {
	f := globalOrganizationFixture(t)
	h := f.h
	for _, path := range []string{"original_handler", "signed_http"} {
		t.Run(path, func(t *testing.T) {
			for _, tc := range []struct {
				name      string
				selectors []string
				deleted   int
				invalid   bool
			}{
				{"U1-01_single", []string{"one"}, 1, false},
				{"U1-02_batch", []string{"one", "two"}, 2, false},
				{"U1-03_duplicate", []string{"one", "two", "one", "two"}, 2, false},
				{"U1-04_own_foreign", []string{"one", "foreign", "two", "foreign"}, 2, false},
				{"U1-05_all_foreign", []string{"foreign", "foreign"}, 0, false},
				{"U1-06_missing", []string{"missing", "missing"}, 0, false},
				{"U1-06_own_missing", []string{"one", "missing", "two"}, 2, false},
				{"U1-07_empty", nil, 0, false},
				{"U1-08_malformed", []string{"one", "invalid", "two"}, 0, true},
			} {
				t.Run(tc.name, func(t *testing.T) {
					one, s1 := usSession(t, h, h.UUID("om"))
					two, s2 := usSession(t, h, h.UUID("om"))
					foreign, sf := usSession(t, h, h.UUID("b"))
					values := map[string]string{"one": one, "two": two, "foreign": foreign, "missing": uuid.NewString(), "invalid": "SYNTHETIC_INVALID_SESSION"}
					var ids []string
					for _, key := range tc.selectors {
						ids = append(ids, values[key])
					}
					before := usSuccesses(t, h)
					if path == "original_handler" {
						tx, err := h.App().DB().BeginTx(t.Context(), nil)
						require.NoError(t, err)
						defer tx.Rollback()
						err = h.App().AuthHandler.EndUserSessionTx(a12HumanContext(t, f, "om"), tx, ids...)
						require.Equal(t, tc.invalid, err != nil, "prepared statement error contract (details withheld)")
						if err == nil {
							require.NoError(t, tx.Commit())
						} else {
							require.NoError(t, tx.Rollback())
						}
					} else {
						if tc.invalid {
							expected := h.ExpectBackendError("GraphQL operation failed")
							usHTTP(t, f, "om", usQuery(ids...), true)
							expected()
						} else {
							usHTTP(t, f, "om", usQuery(ids...), false)
						}
					}
					require.EqualValues(t, 2-tc.deleted, sd8Scalar(t, h, `SELECT count(*) FROM auth_user_sessions WHERE id=ANY($1)`, []string{one, two}))
					for i, id := range []string{one, two} {
						wantRow, wantDetail := int64(1), int64(0)
						if i < tc.deleted {
							wantRow = 0
							if path == "signed_http" {
								wantDetail = 1
							}
						}
						require.Equal(t, wantRow, sd8Scalar(t, h, `SELECT count(*) FROM auth_user_sessions WHERE id=$1`, id))
						require.Equal(t, wantDetail, sd8Scalar(t, h, `SELECT count(*) FROM user_session_revoke_audit_details WHERE session_audit_id=$1`, []uuid.UUID{s1, s2}[i]))
					}
					require.EqualValues(t, 1, sd8Scalar(t, h, `SELECT count(*) FROM auth_user_sessions WHERE id=$1 AND user_id=$2`, foreign, h.UUID("b")))
					require.EqualValues(t, 1, sd8Scalar(t, h, `SELECT count(*) FROM auth_user_sessions WHERE id=$1`, f.sessions["om"]))
					actualDetails := int64(0)
					if path == "signed_http" {
						actualDetails = int64(tc.deleted)
					}
					require.Equal(t, actualDetails, sd8Scalar(t, h, `SELECT count(*) FROM user_session_revoke_audit_details WHERE session_audit_id=ANY($1)`, []uuid.UUID{s1, s2, sf}))
					require.Zero(t, sd8Scalar(t, h, `SELECT count(*) FROM user_session_revoke_audit_details WHERE session_audit_id=$1`, sf))
					if actualDetails == 0 {
						require.Equal(t, before, usSuccesses(t, h))
						return
					}
					require.Equal(t, before+1, usSuccesses(t, h))
					require.EqualValues(t, 1, sd8Scalar(t, h, `SELECT count(DISTINCT event_id) FROM user_session_revoke_audit_details WHERE session_audit_id=ANY($1)`, []uuid.UUID{s1, s2}))
					require.Equal(t, actualDetails, sd8Scalar(t, h, `SELECT count(*) FROM user_session_revoke_audit_events e JOIN user_session_revoke_audit_details d USING(event_id) WHERE d.session_audit_id=ANY($1) AND e.affected_count=$2 AND e.actor_id=$3 AND e.initiator_user_id=$3 AND d.target_user_id=$3 AND e.home_organization_id=$4 AND d.target_organization_id=$4 AND d.cause='explicit_target' AND e.record_kind='success_witness' AND e.outcome='committed'`, []uuid.UUID{s1, s2}, actualDetails, h.UUID("om"), h.UUID("s2-org-a")))
					// A new HTTP request for the same complete set adds no fact.
					usHTTP(t, f, "om", usQuery(ids...), false)
					require.Equal(t, before+1, usSuccesses(t, h))
					require.Equal(t, actualDetails, sd8Scalar(t, h, `SELECT count(*) FROM user_session_revoke_audit_details WHERE session_audit_id=ANY($1)`, []uuid.UUID{s1, s2}))
				})
			}
		})
	}
}

func TestUserSessionAuditU1BatchAtomicity(t *testing.T) {
	f := globalOrganizationFixture(t)
	h := f.h
	for _, mode := range []string{"U1-09_audit_failure", "U1-11_mixed_failure", "U1-11_mixed_success"} {
		t.Run(mode, func(t *testing.T) {
			one, s1 := usSession(t, h, h.UUID("om"))
			two, s2 := usSession(t, h, h.UUID("om"))
			foreign, sf := usSession(t, h, h.UUID("b"))
			query := usQuery(one, two, one, foreign)
			contact := ""
			if mode != "U1-09_audit_failure" {
				contact, _ = sd8CMNR(t, h, h.UUID("om"))
				query = fmt.Sprintf(`mutation{deleteAll(input:[{type:contactMethod,id:%q},{type:userSession,id:%q},{type:userSession,id:%q},{type:userSession,id:%q},{type:userSession,id:%q}])}`, contact, one, two, one, foreign)
			}
			before := usSuccesses(t, h)
			failed := mode != "U1-11_mixed_success"
			if failed {
				sd8Exec(t, h, `CREATE FUNCTION us_u1_fail() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'SYNTHETIC_PRIVATE_SQL';END;$$; CREATE TRIGGER us_u1_fail BEFORE INSERT ON user_session_revoke_audit_details FOR EACH ROW EXECUTE FUNCTION us_u1_fail()`)
				expected := h.ExpectBackendError("GraphQL operation failed")
				usHTTP(t, f, "om", query, true)
				expected()
				sd8Exec(t, h, `DROP TRIGGER us_u1_fail ON user_session_revoke_audit_details; DROP FUNCTION us_u1_fail()`)
			} else {
				usHTTP(t, f, "om", query, false)
			}
			remaining, details, roots := int64(0), int64(2), int64(1)
			if failed {
				remaining, details, roots = 2, 0, 0
			}
			require.Equal(t, remaining, sd8Scalar(t, h, `SELECT count(*) FROM auth_user_sessions WHERE id=ANY($1)`, []string{one, two}))
			require.EqualValues(t, 1, sd8Scalar(t, h, `SELECT count(*) FROM auth_user_sessions WHERE id=$1`, foreign))
			require.Equal(t, details, sd8Scalar(t, h, `SELECT count(*) FROM user_session_revoke_audit_details WHERE session_audit_id=ANY($1)`, []uuid.UUID{s1, s2, sf}))
			require.Equal(t, before+roots, usSuccesses(t, h))
			if contact != "" {
				wantContact := int64(0)
				if failed {
					wantContact = 1
				}
				require.Equal(t, wantContact, sd8Scalar(t, h, `SELECT count(*) FROM user_contact_methods WHERE id=$1`, contact))
				require.Equal(t, roots, sd8Scalar(t, h, `SELECT count(*) FROM user_cmnr_delete_audit_events WHERE root_id=$1 AND record_kind='success_witness'`, contact))
				if !failed {
					require.EqualValues(t, 2, sd8Scalar(t, h, `SELECT count(*) FROM user_session_revoke_audit_events e JOIN user_session_revoke_audit_details d USING(event_id) JOIN user_cmnr_delete_audit_events c ON c.request_id=e.request_id AND c.execution_id=e.execution_id AND c.attempt_id=e.attempt_id WHERE d.session_audit_id=ANY($1) AND c.root_id=$2 AND c.record_kind='success_witness'`, []uuid.UUID{s1, s2}, contact))
				}
			}
		})
	}
}

func TestUserSessionAuditU1ConcurrentUserBatch(t *testing.T) {
	f := globalOrganizationFixture(t)
	h := f.h
	var database string
	require.NoError(t, h.App().DB().QueryRow(`SELECT current_database()`).Scan(&database))
	one, s1 := usSession(t, h, h.UUID("om"))
	two, s2 := usSession(t, h, h.UUID("om"))
	foreign, sf := usSession(t, h, h.UUID("b"))
	c1, err := sd8PGConnector(harness.DBURL(database))
	require.NoError(t, err)
	c2, err := sd8PGConnector(harness.DBURL(database))
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
	ctx, cancel := context.WithTimeout(a12HumanContext(t, f, "om"), 15*time.Second)
	defer cancel()
	var targets []assignment.RawTarget
	for _, id := range []string{one, two, one, foreign} {
		targets = append(targets, assignment.RawTarget{Type: assignment.TargetTypeUserSession, ID: id})
	}
	before := usSuccesses(t, h)
	done1, done2 := make(chan error, 1), make(chan error, 1)
	go func() { _, err := a1.Mutation().DeleteAll(ctx, targets); done1 <- err }()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("first transaction did not acquire shared entry lock")
	}
	go func() { _, err := a2.Mutation().DeleteAll(ctx, targets); done2 <- err }()
	require.Eventually(t, func() bool {
		return sd8Scalar(t, h, `SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND wait_event='advisory'`) > 0
	}, time.Second, 10*time.Millisecond)
	unblock()
	require.NoError(t, <-done1)
	require.NoError(t, <-done2)
	require.Zero(t, sd8Scalar(t, h, `SELECT count(*) FROM auth_user_sessions WHERE id=ANY($1)`, []string{one, two}))
	require.EqualValues(t, 1, sd8Scalar(t, h, `SELECT count(*) FROM auth_user_sessions WHERE id=$1`, foreign))
	require.Equal(t, before+1, usSuccesses(t, h))
	require.EqualValues(t, 2, sd8Scalar(t, h, `SELECT count(*) FROM user_session_revoke_audit_details WHERE session_audit_id=ANY($1)`, []uuid.UUID{s1, s2, sf}))
	require.EqualValues(t, 1, sd8Scalar(t, h, `SELECT count(DISTINCT event_id) FROM user_session_revoke_audit_details WHERE session_audit_id=ANY($1)`, []uuid.UUID{s1, s2}))
}
