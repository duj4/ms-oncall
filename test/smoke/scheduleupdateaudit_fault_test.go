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
	"github.com/target/goalert/schedule/updateaudit"
	"github.com/target/goalert/test/smoke/harness"
)

func TestScheduleUpdateAuditSimulatedCommitAcknowledgements(t *testing.T) {
	for _, mode := range []string{"commit_then_error", "rollback_then_error", "begin_failed", "rollback_unconfirmed", "completion_unknown"} {
		t.Run(mode, func(t *testing.T) {
			h := scheduleAuditHarness(t)
			ikSetAuthority(t, h, "ORG_MEMBER", true)
			var name string
			require.NoError(t, h.App().DB().QueryRow(`SELECT current_database()`).Scan(&name))
			cfg, err := pgx.ParseConfig(harness.DBURL(name))
			require.NoError(t, err)
			c := &serviceAuditFaultConnector{base: stdlib.GetConnector(*cfg), mode: mode}
			db := sql.OpenDB(c)
			defer db.Close()
			store, err := schedule.NewStore(context.Background(), db, nil)
			require.NoError(t, err)
			a := graphqlapp.App{DB: db, ScheduleStore: store}
			description := "synthetic fault update"
			input := graphql2.UpdateScheduleInput{ID: h.UUID("schedule-a"), Description: &description}
			if mode == "rollback_unconfirmed" {
				bad := ""
				input.Name = &bad
			}
			ok, err := a.Mutation().UpdateSchedule(servicePlatformAdminContext(t, h), input)
			require.Error(t, err)
			require.False(t, ok, "Commit error never reports resolver success")
			require.NotContains(t, err.Error(), "SYNTHETIC_")
			var committed, unknown, failed, rollback int
			require.NoError(t, h.App().DB().QueryRow(`SELECT count(*) FILTER(WHERE outcome='committed'),count(*) FILTER(WHERE outcome='commit_unknown'),count(*) FILTER(WHERE outcome='tx_failed'),count(*) FILTER(WHERE outcome='rollback_unconfirmed') FROM schedule_rotation_update_audit_events`).Scan(&committed, &unknown, &failed, &rollback))
			var actual string
			require.NoError(t, h.App().DB().QueryRow(`SELECT description FROM schedules WHERE id=$1`, h.UUID("schedule-a")).Scan(&actual))
			switch mode {
			case "commit_then_error", "completion_unknown":
				require.Equal(t, description, actual)
				require.Equal(t, 1, committed)
				require.Equal(t, 1, unknown)
			case "rollback_then_error":
				require.Empty(t, actual)
				require.Zero(t, committed)
				require.Equal(t, 1, unknown)
			case "begin_failed":
				require.Empty(t, actual)
				require.Equal(t, 1, failed)
			case "rollback_unconfirmed":
				require.Empty(t, actual)
				require.Equal(t, 1, rollback)
			}
			require.EqualValues(t, 2, c.begins.Load(), "one business attempt and one failure transaction; no mutation replay")
			rows := scheduleAuditRows(t, h)
			require.NotContains(t, rows, "SYNTHETIC_")
			if mode == "commit_then_error" || mode == "completion_unknown" {
				var attempts int
				require.NoError(t, h.App().DB().QueryRow(`SELECT count(DISTINCT attempt_id) FROM schedule_rotation_update_audit_events`).Scan(&attempts))
				require.Equal(t, 1, attempts, "success witness and uncertainty observation correlate without overwriting")
			}
		})
	}
}

func TestScheduleUpdateAuditRealCommitRejection(t *testing.T) {
	h := scheduleAuditHarness(t)
	ikSetAuthority(t, h, "ORG_MEMBER", true)
	_, err := h.App().DB().Exec(`CREATE FUNCTION audit_test_commit_reject() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='SYNTHETIC_DEFERRED_SECRET'; END $$;
CREATE CONSTRAINT TRIGGER audit_test_commit_reject AFTER UPDATE ON schedules DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION audit_test_commit_reject()`)
	require.NoError(t, err)
	before := serviceManagementSnapshot(t, h)
	wait := h.ExpectBackendError("schedule.update transaction failed")
	r := stepOrganizationQuery(t, h, fmt.Sprintf(`mutation{updateSchedule(input:{id:%q,description:"deferred failure"})}`, h.UUID("schedule-a")))
	wait()
	require.NotEmpty(t, r.Errors)
	require.Equal(t, before, serviceManagementSnapshot(t, h))
	var outcome, reason string
	require.NoError(t, h.App().DB().QueryRow(`SELECT outcome,reason_code FROM schedule_rotation_update_audit_events`).Scan(&outcome, &reason))
	require.Equal(t, "tx_failed", outcome)
	require.Equal(t, "commit_rejected", reason)
	require.NotContains(t, scheduleAuditRows(t, h), "SYNTHETIC_DEFERRED_SECRET")
}

func TestScheduleUpdateAuditFailurePersistenceLimits(t *testing.T) {
	h := scheduleAuditHarness(t)
	ikSetAuthority(t, h, "ORG_MEMBER", false)
	_, err := h.App().DB().Exec(`CREATE FUNCTION audit_test_sink_fail() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'SYNTHETIC_SINK_SECRET'; END $$;
CREATE TRIGGER audit_test_sink_fail BEFORE INSERT ON schedule_rotation_update_audit_events FOR EACH ROW EXECUTE FUNCTION audit_test_sink_fail()`)
	require.NoError(t, err)
	wait := h.ExpectBackendError("schedule/rotation update audit persistence unavailable")
	r := stepOrganizationQuery(t, h, fmt.Sprintf(`mutation{updateSchedule(input:{id:%q,description:"denied during outage"})}`, h.UUID("schedule-a")))
	wait()
	require.NotEmpty(t, r.Errors)
	require.Contains(t, fmt.Sprint(r.Errors), "audit persistence unavailable")
	require.Zero(t, scheduleAuditCount(t, h), "a failed independent append must not claim durable denial")
	_, err = h.App().DB().Exec(`DROP TRIGGER audit_test_sink_fail ON schedule_rotation_update_audit_events`)
	require.NoError(t, err)
	e := updateaudit.Event{Operation: updateaudit.ScheduleUpdate, EventID: uuid.New(), AttemptID: uuid.New(), RequestID: uuid.New(), ActorKind: "unknown", AuthoritySource: "unknown", AuthorityRole: "unknown", OrganizationRole: "unknown", Outcome: "denied", Reason: "authority_denied", OccurredAt: time.Now()}
	tx, err := h.App().DB().Begin()
	require.NoError(t, err)
	_, err = tx.Exec(`LOCK TABLE schedule_rotation_update_audit_events IN SHARE MODE`)
	require.NoError(t, err)
	start := time.Now()
	err = updateaudit.RecordFailure(h.App().DB(), e)
	require.ErrorIs(t, err, updateaudit.ErrUnavailable)
	require.Less(t, time.Since(start), 4*time.Second, "independent append has a finite budget")
	require.NoError(t, tx.Rollback())
	require.Zero(t, scheduleAuditCount(t, h))
	require.NoError(t, updateaudit.RecordFailure(h.App().DB(), e))
	require.Equal(t, 1, scheduleAuditCount(t, h))
	var name string
	require.NoError(t, h.App().DB().QueryRow(`SELECT current_database()`).Scan(&name))
	cfg, err := pgx.ParseConfig(harness.DBURL(name))
	require.NoError(t, err)
	closed := sql.OpenDB(stdlib.GetConnector(*cfg))
	require.NoError(t, closed.Close())
	require.ErrorIs(t, updateaudit.RecordFailure(closed, e), updateaudit.ErrUnavailable)
	scheduleAuditRows(t, h)
	t.Log("closed-pool unavailable control; no production/whole-server disconnect experiment claimed")
}
