package smoke

import (
	"context"
	"database/sql"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/graphql2"
	"github.com/target/goalert/graphql2/graphqlapp"
	"github.com/target/goalert/schedule"
	"github.com/target/goalert/schedule/rule"
	"github.com/target/goalert/test/smoke/harness"
)

func u03FaultApp(t *testing.T, db *sql.DB) *graphqlapp.App {
	t.Helper()
	rs, err := rule.NewStore(context.Background(), db)
	require.NoError(t, err)
	ss, err := schedule.NewStore(context.Background(), db, nil)
	require.NoError(t, err)
	return &graphqlapp.App{DB: db, RuleStore: rs, ScheduleStore: ss}
}

// Native PG changes/commit with controlled driver acknowledgements. This is
// deliberately not described as a real network disconnect or lost-packet test.
func TestScheduleTargetUpdateNativeControlledCommit(t *testing.T) {
	for _, mode := range []string{"commit_then_error", "completion_unknown", "rollback_then_error"} {
		t.Run(mode, func(t *testing.T) {
			h := u03Harness(t)
			root, target := h.UUID("schedule-a"), u03Target(t, h, "user")
			id := u03Rule(t, h, root, target, 0)
			var name string
			require.NoError(t, h.App().DB().QueryRow(`SELECT current_database()`).Scan(&name))
			cfg, err := pgx.ParseConfig(harness.DBURL(name))
			require.NoError(t, err)
			c := &serviceAuditFaultConnector{base: stdlib.GetConnector(*cfg), mode: mode}
			db := sql.OpenDB(c)
			db.SetMaxOpenConns(1)
			defer db.Close()
			a := u03FaultApp(t, db)
			ok, err := a.Mutation().UpdateScheduleTarget(sd3System(), graphql2.ScheduleTargetInput{ScheduleID: &root, Target: &target, Rules: []graphql2.ScheduleRuleInput{}})
			require.Error(t, err)
			require.False(t, ok)
			var success, unknown, badEffects, requests, executions, attempts int
			require.NoError(t, h.App().DB().QueryRow(`SELECT count(*) FILTER(WHERE record_kind='success_witness'),count(*) FILTER(WHERE outcome='commit_unknown'),count(*) FILTER(WHERE record_kind='attempt_observation' AND effects<>'[]'::jsonb),count(DISTINCT request_id),count(DISTINCT execution_id),count(DISTINCT attempt_id) FROM schedule_rotation_delete_audit_events WHERE schema_version=2`).Scan(&success, &unknown, &badEffects, &requests, &executions, &attempts))
			require.Equal(t, 1, unknown)
			require.Zero(t, badEffects)
			require.Equal(t, 1, requests)
			require.Equal(t, 1, executions)
			require.Equal(t, 1, attempts)
			require.EqualValues(t, 2, c.begins.Load(), "one business transaction and one observation, no replay")
			if mode == "rollback_then_error" {
				require.Zero(t, success)
				require.Contains(t, u03IDs(t, h, "schedule_rules"), id)
				require.Empty(t, u03IDs(t, h, "u03_actual_deleted"))
			} else {
				require.Equal(t, 1, success)
				u03AssertEffects(t, h, root, target, []string{id})
			}
		})
	}
}

func TestScheduleTargetUpdateNativeReleaseBarrier(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(fmt.Sprint("audit_failure=", fail), func(t *testing.T) {
			h := u03Harness(t)
			root, target := h.UUID("schedule-a"), u03Target(t, h, "user")
			id := u03Rule(t, h, root, target, 0)
			if fail {
				_, err := h.App().DB().Exec(`CREATE FUNCTION u03_reject_witness() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'SYNTHETIC_AUDIT_FAILURE'; END$$; CREATE TRIGGER u03_reject_witness BEFORE INSERT ON schedule_rotation_delete_audit_events FOR EACH ROW WHEN(NEW.record_kind='success_witness') EXECUTE FUNCTION u03_reject_witness()`)
				require.NoError(t, err)
			}
			var name string
			require.NoError(t, h.App().DB().QueryRow(`SELECT current_database()`).Scan(&name))
			cfg, err := pgx.ParseConfig(harness.DBURL(name))
			require.NoError(t, err)
			c := &serviceAuditCloseConnector{base: stdlib.GetConnector(*cfg), started: make(chan struct{}), release: make(chan struct{}), finished: make(chan struct{})}
			db := sql.OpenDB(c)
			db.SetMaxOpenConns(1)
			t.Cleanup(func() { c.unblock(); require.NoError(t, db.Close()) })
			a := u03FaultApp(t, db)
			db.SetMaxIdleConns(0)
			c.armed.Store(true)
			ok, err := a.Mutation().UpdateScheduleTarget(sd3System(), graphql2.ScheduleTargetInput{ScheduleID: &root, Target: &target, Rules: []graphql2.ScheduleRuleInput{}})
			require.EqualValues(t, 1, c.begins.Load(), "unconfirmed release must not start another writer")
			select {
			case <-c.started:
			default:
				t.Fatal("Close barrier was not entered")
			}
			select {
			case <-c.finished:
				t.Fatal("Close should remain gated at bounded return")
			default:
			}
			c.unblock()
			require.Eventually(t, func() bool { return db.Stats().OpenConnections == 0 && db.Stats().InUse == 0 }, 5*time.Second, time.Millisecond)
			if fail {
				require.Error(t, err)
				require.False(t, ok)
				require.Zero(t, u03Count(t, h))
				require.Contains(t, u03IDs(t, h, "schedule_rules"), id)
			} else {
				require.NoError(t, err, "confirmed commit remains success despite cleanup timeout")
				require.True(t, ok)
				require.EqualValues(t, 1, c.commitOK.Load())
				u03AssertEffects(t, h, root, target, []string{id})
			}
		})
	}
}

func TestScheduleTargetUpdateNativeMixedHTTP(t *testing.T) {
	h := u03Harness(t)
	ikSetAuthority(t, h, "ORG_ADMIN", false)
	root, other := h.UUID("schedule-a"), h.UUID("schedule-c")
	target := u03Target(t, h, "user")
	id := u03Rule(t, h, root, target, 0)
	keep := u03Rule(t, h, other, target, 0)
	ep := sd5EP(t, h, harness.SmokeOrganizationID)
	sd5Step(t, h, ep)
	query := fmt.Sprintf(`mutation U03Mixed{...F} fragment F on Mutation{
 a:updateScheduleTarget(input:{scheduleID:%q,target:{type:user,id:%q},rules:[]})
 ep:updateEscalationPolicy(input:{id:%q,stepIDs:[]})
 b:updateScheduleTarget(input:{scheduleID:%q,target:{type:user,id:%q},rules:[{}]})}`, root, target.ID, ep, other, uuid.NewString())
	r := stepOrganizationQuery(t, h, query)
	require.NotEmpty(t, r.Errors)
	u03AssertEffects(t, h, root, target, []string{id})
	require.Contains(t, u03IDs(t, h, "schedule_rules"), keep)
	require.Equal(t, 1, euSuccessCount(t, h))
	var requests, executions, attempts, failures, bad int
	require.NoError(t, h.App().DB().QueryRow(`SELECT count(DISTINCT request_id),count(DISTINCT execution_id),count(DISTINCT attempt_id),count(*) FILTER(WHERE record_kind='attempt_observation'),count(*) FILTER(WHERE record_kind='attempt_observation' AND effects<>'[]'::jsonb) FROM schedule_rotation_delete_audit_events WHERE operation='updateScheduleTarget'`).Scan(&requests, &executions, &attempts, &failures, &bad))
	require.Equal(t, 1, requests)
	require.Equal(t, 2, executions)
	require.Equal(t, 2, attempts)
	require.Equal(t, 1, failures)
	require.Zero(t, bad)
}
