package graphqlapp_test

import (
	"context"
	"github.com/google/uuid"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/target/goalert/graphql2/graphqlapp"
	"github.com/target/goalert/test/smoke/harness"
)

func TestPostgresUserDeleteFailure500(t *testing.T) {
	if os.Getenv("MS_ONCALL_CORE_MIGRATION_TEST_POSTGRES_ENABLE") != "1" {
		t.Skip("explicit PostgreSQL opt-in required")
	}
	for _, mode := range []string{"400", "500", "501", "user101", "last_append_failure", "commit_failure"} {
		t.Run(mode, func(t *testing.T) {
			h := harness.NewHarness(t, "", "")
			t.Cleanup(h.Close)
			db := h.App().DB()
			users := 100
			if mode == "400" {
				users = 0
			}
			if mode == "501" || mode == "user101" {
				users = 101
			}
			if mode == "last_append_failure" {
				_, err := db.Exec(`CREATE FUNCTION sd8_failure_inject() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'SYNTHETIC_PRIVATE';END;$$;CREATE TRIGGER sd8_failure_inject BEFORE INSERT ON user_delete_audit_events FOR EACH ROW EXECUTE FUNCTION sd8_failure_inject()`)
				require.NoError(t, err)
			}
			if mode == "commit_failure" {
				_, err := db.Exec(`CREATE FUNCTION sd8_failure_inject() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'SYNTHETIC_PRIVATE';END;$$;CREATE CONSTRAINT TRIGGER sd8_failure_inject AFTER INSERT ON user_delete_audit_events DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION sd8_failure_inject()`)
				require.NoError(t, err)
			}
			start := time.Now()
			persisted, released := graphqlapp.SD8FailureBatchForTest(db, 50, 50, 50, users)
			elapsed := time.Since(start)
			allowed := mode == "400" || mode == "500"
			require.Equal(t, allowed, persisted)
			require.True(t, released)
			require.Less(t, elapsed, 2*time.Second)
			total := int64(0)
			for _, table := range []string{"service_delete_audit_events", "user_cmnr_delete_audit_events", "integration_key_delete_audit_events", "escalation_policy_delete_audit_events", "schedule_rotation_delete_audit_events", "user_override_delete_audit_events", "user_delete_audit_events"} {
				var n int64
				require.NoError(t, db.QueryRow(`SELECT count(*) FROM `+table).Scan(&n))
				total += n
			}
			expected := int64(0)
			if allowed {
				expected = int64(400 + users)
			}
			require.Equal(t, expected, total)
			t.Logf("batch=%d persisted=%t released=%t elapsed=%s durable=%d", 400+users, persisted, released, elapsed, total)
		})
	}
}

func TestPostgresUserDeleteFailureDeadline(t *testing.T) {
	if os.Getenv("MS_ONCALL_CORE_MIGRATION_TEST_POSTGRES_ENABLE") != "1" {
		t.Skip("explicit PostgreSQL opt-in required")
	}
	h := harness.NewHarness(t, "", "")
	t.Cleanup(h.Close)
	db := h.App().DB()
	for _, mode := range []string{"release_before_deadline", "release_after_deadline"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			blocker, err := db.Conn(ctx)
			require.NoError(t, err)
			defer blocker.Close()
			tx, err := blocker.BeginTx(ctx, nil)
			require.NoError(t, err)
			defer func() { _ = tx.Rollback() }()
			_, err = tx.ExecContext(ctx, `LOCK TABLE user_delete_audit_events IN SHARE MODE`)
			require.NoError(t, err)
			_, err = tx.ExecContext(ctx, `INSERT INTO user_delete_audit_events(event_id,request_id,execution_id,attempt_id,record_kind,actor_kind,authority_source,authority_role,organization_role,target_org_resolution,outcome,reason_code,occurred_at) VALUES($1,$2,$3,$4,'attempt_observation','internal_system','trusted_internal_system','internal_system','unknown','unknown','tx_failed','write_failed',now())`, uuid.New(), uuid.New(), uuid.New(), uuid.New())
			require.NoError(t, err)
			var blockerPID int
			require.NoError(t, tx.QueryRowContext(ctx, `SELECT pg_backend_pid()`).Scan(&blockerPID))
			type result struct {
				persisted, released bool
				elapsed             time.Duration
			}
			done := make(chan result, 1)
			start := time.Now()
			go func() {
				p, r := graphqlapp.SD8FailureBatchForTest(db, 50, 50, 50, 100)
				done <- result{p, r, time.Since(start)}
			}()
			var writerPID int
			require.Eventually(t, func() bool {
				return db.QueryRowContext(ctx, `SELECT pid FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND $1=ANY(pg_blocking_pids(pid)) AND query LIKE 'INSERT INTO user_delete_audit_events%' LIMIT 1`, blockerPID).Scan(&writerPID) == nil
			}, 1500*time.Millisecond, 5*time.Millisecond)
			var waitType string
			require.NoError(t, db.QueryRowContext(ctx, `SELECT wait_event_type FROM pg_stat_activity WHERE pid=$1`, writerPID).Scan(&waitType))
			require.Equal(t, "Lock", waitType)
			var observed result
			if mode == "release_before_deadline" {
				timer := time.NewTimer(100 * time.Millisecond)
				<-timer.C
				require.NoError(t, tx.Rollback())
				observed = <-done
				require.True(t, observed.persisted)
				require.True(t, observed.released)
				require.Less(t, observed.elapsed, 2*time.Second)
			} else {
				observed = <-done
				require.GreaterOrEqual(t, observed.elapsed, 1900*time.Millisecond)
				require.Less(t, observed.elapsed, 3*time.Second)
				require.False(t, observed.persisted)
				require.NoError(t, tx.Rollback())
				require.Eventually(t, func() bool {
					var n int
					return db.QueryRowContext(ctx, `SELECT count(*) FROM pg_stat_activity WHERE pid=$1 AND (state LIKE '%transaction%' OR wait_event_type='Lock')`, writerPID).Scan(&n) == nil && n == 0
				}, 3*time.Second, 10*time.Millisecond)
			}
			var users int
			require.NoError(t, db.QueryRow(`SELECT count(*) FROM user_delete_audit_events`).Scan(&users))
			require.Equal(t, 100, users, "first batch remains; timed-out batch must not partially commit")
			total := 0
			for _, table := range []string{"service_delete_audit_events", "user_cmnr_delete_audit_events", "integration_key_delete_audit_events", "escalation_policy_delete_audit_events", "schedule_rotation_delete_audit_events", "user_override_delete_audit_events", "user_delete_audit_events"} {
				var n int
				require.NoError(t, db.QueryRow(`SELECT count(*) FROM `+table).Scan(&n))
				total += n
			}
			require.Equal(t, 500, total)
			t.Logf("mode=%s blocker_pid=%d writer_pid=%d native_wait=%s persisted=%t released_at_return=%t elapsed=%s final_user_observations=%d", mode, blockerPID, writerPID, waitType, observed.persisted, observed.released, observed.elapsed, users)
		})
	}
}
