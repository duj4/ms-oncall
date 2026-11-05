package smoke

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/config"
	"github.com/target/goalert/engine/escalationmanager"
	"github.com/target/goalert/engine/npcyclemanager"
	"github.com/target/goalert/engine/schedulemanager"
	"github.com/target/goalert/organization"
	"github.com/target/goalert/permission"
	"github.com/target/goalert/test/smoke/harness"
)

func staffingCount(t *testing.T, db *sql.DB, query string, args ...any) int {
	t.Helper()
	var count int
	require.NoError(t, db.QueryRow(query, args...).Scan(&count))
	return count
}

func staffingContained(t *testing.T, h *harness.Harness, db *sql.DB, schedule bool) {
	t.Helper()
	require.Zero(t, staffingCount(t, db, `SELECT count(*) FROM ep_step_on_call_users WHERE ep_step_id=$1 AND user_id=$2 AND end_time IS NULL`, h.UUID("step-a"), h.UUID("target")))
	require.Equal(t, 1, staffingCount(t, db, `SELECT count(*) FROM ep_step_on_call_users WHERE ep_step_id=$1 AND user_id=$2 AND end_time IS NULL`, h.UUID("step-a"), h.UUID("control")))
	if schedule {
		require.Zero(t, staffingCount(t, db, `SELECT count(*) FROM schedule_on_call_users WHERE schedule_id=$1 AND user_id=$2 AND end_time IS NULL`, h.UUID("sched-a"), h.UUID("target")))
		require.Equal(t, 1, staffingCount(t, db, `SELECT count(*) FROM schedule_on_call_users WHERE schedule_id=$1 AND user_id=$2 AND end_time IS NULL`, h.UUID("sched-a"), h.UUID("control")))
	}
}

func staffingNoIntent(t *testing.T, h *harness.Harness, db *sql.DB, alertID int) {
	t.Helper()
	require.Zero(t, staffingCount(t, db, `SELECT count(*) FROM notification_policy_cycles WHERE alert_id=$1 AND user_id=$2`, alertID, h.UUID("target")))
	require.Zero(t, staffingCount(t, db, `SELECT count(*) FROM outgoing_messages WHERE alert_id=$1 AND user_id=$2`, alertID, h.UUID("target")))
}

func staffingContext(t *testing.T) context.Context {
	t.Helper()
	return permission.SystemContext(t.Context(), "StaffingCycleIntegrity")
}

// T2-04 and T2-06 exercise real source records and stale materialization. Apply
// overrides before the affiliation filter: replacement matching must not change.
func TestStaffingAlternateScheduleSources(t *testing.T) {
	for _, source := range []string{"rule", "override-add", "override-remove", "replace-foreign", "replace-from-foreign", "replace-nonmatch", "temporary"} {
		t.Run(source, func(t *testing.T) {
			h, db := t1New(t, true, false)
			pauseStepOrganizationEngine(t, h)
			ctx := staffingContext(t)
			mgr, err := schedulemanager.NewDB(ctx, db)
			require.NoError(t, err)
			recipientExec(t, db, `DELETE FROM schedule_rules WHERE schedule_id=$1`, h.UUID("sched-a"))
			wantControl := 1
			rule := func(user string) {
				recipientExec(t, db, `INSERT INTO schedule_rules(schedule_id,tgt_user_id) VALUES($1,$2)`, h.UUID("sched-a"), h.UUID(user))
			}
			override := func(remove, add any) {
				recipientExec(t, db, `INSERT INTO user_overrides(id,tgt_schedule_id,remove_user_id,add_user_id,start_time,end_time) VALUES(gen_random_uuid(),$1,$2,$3,now()-interval '1 hour',now()+interval '1 hour')`, h.UUID("sched-a"), remove, add)
			}
			switch source {
			case "rule":
				rule("target")
				rule("control")
			case "override-add":
				rule("control")
				override(nil, h.UUID("target"))
			case "override-remove":
				rule("target")
				rule("control")
				override(h.UUID("control"), nil)
				wantControl = 0
			case "replace-foreign":
				rule("control")
				override(h.UUID("control"), h.UUID("target"))
				wantControl = 0
			case "replace-from-foreign":
				rule("target")
				override(h.UUID("target"), h.UUID("control"))
			case "replace-nonmatch":
				rule("target")
				override(h.UUID("control"), h.UUID("target"))
				wantControl = 0
			case "temporary":
				data := fmt.Sprintf(`{"V1":{"TemporarySchedules":[{"Start":"2000-01-01T00:00:00Z","End":"9999-01-01T00:00:00Z","Shifts":[{"Start":"2000-01-01T00:00:00Z","End":"9999-01-01T00:00:00Z","UserID":%q},{"Start":"2000-01-01T00:00:00Z","End":"9999-01-01T00:00:00Z","UserID":%q}]}]}}`, h.UUID("target"), h.UUID("control"))
				recipientExec(t, db, `INSERT INTO schedule_data(schedule_id,data) VALUES($1,$2) ON CONFLICT(schedule_id) DO UPDATE SET data=$2`, h.UUID("sched-a"), data)
			}
			// Historical rows satisfy the native constraints. No source repair.
			recipientExec(t, db, `INSERT INTO schedule_on_call_users(schedule_id,user_id) VALUES($1,$2) ON CONFLICT DO NOTHING`, h.UUID("sched-a"), h.UUID("target"))
			recipientExec(t, db, `INSERT INTO ep_step_on_call_users(ep_step_id,user_id) VALUES($1,$2) ON CONFLICT DO NOTHING`, h.UUID("step-a"), h.UUID("target"))
			before := t1Snapshot(t, db, "before-reconciliation")
			require.NoError(t, mgr.UpdateAll(ctx))
			require.Zero(t, staffingCount(t, db, `SELECT count(*) FROM schedule_on_call_users WHERE schedule_id=$1 AND user_id=$2 AND end_time IS NULL`, h.UUID("sched-a"), h.UUID("target")))
			require.Equal(t, wantControl, staffingCount(t, db, `SELECT count(*) FROM schedule_on_call_users WHERE schedule_id=$1 AND user_id=$2 AND end_time IS NULL`, h.UUID("sched-a"), h.UUID("control")))
			ep, err := escalationmanager.NewDB(ctx, db, h.App().AlertLogStore)
			require.NoError(t, err)
			require.NoError(t, ep.UpdateAll(ctx))
			require.Zero(t, staffingCount(t, db, `SELECT count(*) FROM ep_step_on_call_users WHERE user_id=$1 AND end_time IS NULL`, h.UUID("target")))
			require.Positive(t, staffingCount(t, db, `SELECT count(*) FROM schedule_on_call_users WHERE user_id=$1 AND end_time IS NOT NULL`, h.UUID("target")))
			after := t1Snapshot(t, db, "after-reconciliation")
			for _, table := range []string{"rotation_participants", "schedule_rules", "user_overrides", "schedule_data", "escalation_policy_actions"} {
				require.JSONEq(t, string(before[table]), string(after[table]), table)
			}
		})
	}
}

func TestStaffingDirectRotation(t *testing.T) {
	h, db := t1New(t, true, false)
	pauseStepOrganizationEngine(t, h)
	recipientExec(t, db, `DELETE FROM escalation_policy_actions WHERE escalation_policy_step_id=$1`, h.UUID("step-a"))
	recipientExec(t, db, `INSERT INTO escalation_policy_actions(escalation_policy_step_id,rotation_id) VALUES($1,$2)`, h.UUID("step-a"), h.UUID("rot-a"))
	recipientExec(t, db, `INSERT INTO escalation_policy_actions(escalation_policy_step_id,user_id) VALUES($1,$2)`, h.UUID("step-a"), h.UUID("control"))
	ep, err := escalationmanager.NewDB(staffingContext(t), db, h.App().AlertLogStore)
	require.NoError(t, err)
	require.NoError(t, ep.UpdateAll(staffingContext(t)))
	staffingContained(t, h, db, false)
	t1Snapshot(t, db, "direct-rotation-final")
}

// Hold the existing maintenance statement after on-call commits. The committed
// assignment change then precedes each separate cycle statement, leaving stale
// EP materialization on purpose. This is a DATA-PLANE SIMULATION, not transfer API.
func TestStaffingCycleCreationBranches(t *testing.T) {
	for _, branch := range []string{"initial", "normal", "deleted"} {
		t.Run(branch, func(t *testing.T) {
			h, db := t1New(t, false, true)
			pauseStepOrganizationEngine(t, h)
			ctx, cancel := context.WithTimeout(staffingContext(t), 15*time.Second)
			defer cancel()
			ep, err := escalationmanager.NewDB(ctx, db, h.App().AlertLogStore)
			require.NoError(t, err)
			id := recipientAlert(t, h, db, "svc-a")
			if branch != "initial" {
				recipientExec(t, db, `UPDATE escalation_policy_state SET last_escalation=now()-interval '2 hours',next_escalation=now()-interval '1 hour',escalation_policy_step_id=$1,escalation_policy_step_number=0 WHERE alert_id=$2`, h.UUID("step-a"), id)
				if branch == "normal" {
					recipientExec(t, db, `UPDATE escalation_policy_state SET force_escalation=true WHERE alert_id=$1`, id)
				} else {
					recipientExec(t, db, `UPDATE escalation_policy_state SET escalation_policy_step_id=NULL WHERE alert_id=$1`, id)
				}
			}
			gate, err := db.BeginTx(ctx, nil)
			require.NoError(t, err)
			defer func() { _ = gate.Rollback() }()
			var pid int
			require.NoError(t, gate.QueryRowContext(ctx, `SELECT pg_backend_pid()`).Scan(&pid))
			_, err = gate.ExecContext(ctx, `LOCK services IN SHARE MODE`)
			require.NoError(t, err)
			done := make(chan error, 1)
			go func() { done <- ep.UpdateAll(ctx) }()
			defer func() { _ = gate.Rollback(); cancel(); <-done }()
			require.Eventually(t, func() bool {
				return staffingCount(t, db, `SELECT count(*) FROM pg_stat_activity WHERE $1=ANY(pg_blocking_pids(pid)) AND query LIKE '%maintenance_expires_at%'`, pid) == 1
			}, 5*time.Second, 10*time.Millisecond)
			recipientAssign(t, h, db, true)
			t1Snapshot(t, db, "committed-assignment-with-stale-ep")
			require.NoError(t, gate.Commit())
			// The deferred receive also joins the manager on assertion failures.
			require.NoError(t, <-done)
			done <- nil
			require.Equal(t, 1, staffingCount(t, db, `SELECT count(*) FROM ep_step_on_call_users WHERE user_id=$1 AND end_time IS NULL`, h.UUID("target")))
			staffingNoIntent(t, h, db, id)
			require.Equal(t, 1, staffingCount(t, db, `SELECT count(*) FROM notification_policy_cycles WHERE alert_id=$1 AND user_id=$2`, id, h.UUID("control")))
			t1Snapshot(t, db, "cycle-branch-final")
		})
	}
}

func TestStaffingInvalidAssignments(t *testing.T) {
	for _, kind := range []string{"absent", "default", "multiple", "unknown-role", "foreign-admin"} {
		t.Run(kind, func(t *testing.T) {
			h, db := t1New(t, false, false)
			pauseStepOrganizationEngine(t, h)
			switch kind {
			case "absent":
				recipientExec(t, db, `DELETE FROM user_organization_assignments WHERE user_id=$1`, h.UUID("target"))
			case "default", "multiple":
				outcome, count := "ZERO", 0
				if kind == "multiple" {
					outcome, count = "MULTIPLE", 2
				}
				recipientExec(t, db, `UPDATE user_organization_assignments SET effective_organization_id=$1,effective_normal_organization_id=NULL,effective_organization_classification='DEFAULT',organization_role='NONE',mapping_outcome=$2,matched_count=$3 WHERE user_id=$4`, organization.DefaultOrganizationID, outcome, count, h.UUID("target"))
			case "unknown-role":
				recipientExec(t, db, `UPDATE users SET role='unknown' WHERE id=$1`, h.UUID("target"))
			case "foreign-admin":
				recipientAssign(t, h, db, true)
				recipientExec(t, db, `UPDATE users SET role='admin' WHERE id=$1`, h.UUID("target"))
			}
			sm, err := schedulemanager.NewDB(staffingContext(t), db)
			require.NoError(t, err)
			ep, err := escalationmanager.NewDB(staffingContext(t), db, h.App().AlertLogStore)
			require.NoError(t, err)
			require.NoError(t, sm.UpdateAll(staffingContext(t)))
			require.NoError(t, ep.UpdateAll(staffingContext(t)))
			staffingContained(t, h, db, true)
			t1Snapshot(t, db, "invalid-authority-final")
		})
	}
}

func TestStaffingAuthorityReadFailureAtomicity(t *testing.T) {
	h, db := t1New(t, false, false)
	h.Trigger()
	pauseStepOrganizationEngine(t, h)
	ctx := staffingContext(t)
	sm, err := schedulemanager.NewDB(ctx, db)
	require.NoError(t, err)
	ep, err := escalationmanager.NewDB(ctx, db, h.App().AlertLogStore)
	require.NoError(t, err)
	np, err := npcyclemanager.NewDB(ctx, db, h.App().AlertLogStore)
	require.NoError(t, err)
	id := recipientAlert(t, h, db, "svc-a")
	recipientExec(t, db, `INSERT INTO notification_policy_cycles(alert_id,user_id) VALUES($1,$2)`, id, h.UUID("target"))
	before := t1Snapshot(t, db, "before-authority-timeout")
	gate, err := db.BeginTx(ctx, nil)
	require.NoError(t, err)
	defer func() { _ = gate.Rollback() }()
	_, err = gate.ExecContext(ctx, `LOCK user_organization_assignments IN ACCESS EXCLUSIVE MODE`)
	require.NoError(t, err)
	for _, mgr := range []interface{ UpdateAll(context.Context) error }{sm, ep, np} {
		bounded, cancel := context.WithTimeout(ctx, 200*time.Millisecond)
		err := mgr.UpdateAll(bounded)
		cancel()
		require.Error(t, err, "unavailable authority must fail the transaction")
	}
	require.NoError(t, gate.Rollback())
	after := t1Snapshot(t, db, "after-authority-timeout")
	for _, table := range []string{"schedule_on_call_users", "ep_step_on_call_users", "notification_policy_cycles", "outgoing_messages", "escalation_policy_state", "alert_logs"} {
		require.JSONEq(t, string(before[table]), string(after[table]), table)
	}
}

func TestStaffingNoRecipientAndChannel(t *testing.T) {
	for _, channel := range []bool{false, true} {
		t.Run(fmt.Sprint(channel), func(t *testing.T) {
			h, db := t1New(t, true, true)
			pauseStepOrganizationEngine(t, h)
			recipientExec(t, db, `DELETE FROM escalation_policy_actions WHERE user_id=$1`, h.UUID("control"))
			if channel {
				ch := uuid.NewString()
				recipientExec(t, db, `INSERT INTO notification_channels(id,name,dest) SELECT $1,'Synthetic independent channel',dest FROM user_contact_methods WHERE id=$2`, ch, h.UUID("cm-control"))
				recipientExec(t, db, `INSERT INTO escalation_policy_actions(escalation_policy_step_id,channel_id) VALUES($1,$2)`, h.UUID("step-a"), ch)
			}
			id := recipientAlert(t, h, db, "svc-a")
			ep, err := escalationmanager.NewDB(staffingContext(t), db, h.App().AlertLogStore)
			require.NoError(t, err)
			require.NoError(t, ep.UpdateAll(staffingContext(t)))
			staffingNoIntent(t, h, db, id)
			var meta struct{ NoOneOnCall bool }
			var data []byte
			require.NoError(t, db.QueryRow(`SELECT meta FROM alert_logs WHERE alert_id=$1 AND event='escalated'`, id).Scan(&data))
			require.NoError(t, json.Unmarshal(data, &meta))
			require.Equal(t, !channel, meta.NoOneOnCall)
			require.Equal(t, 1, staffingCount(t, db, `SELECT count(*) FROM escalation_policy_state WHERE alert_id=$1 AND last_escalation IS NOT NULL AND next_escalation=last_escalation+interval '60 minutes'`, id))
			require.NoError(t, h.App().Engine.Resume(t.Context()))
			h.Trigger()
			if channel {
				require.NoError(t, h.D08T1Consume(h.Email("control"), "Outbound isolation control", ""))
			}
			t1Snapshot(t, db, "no-recipient-final")
			t1Sink(t, h, "sink-final")
		})
	}
}

func TestStaffingHistoricalCycleAndPending(t *testing.T) {
	h, db := t1New(t, false, true)
	pauseStepOrganizationEngine(t, h)
	ctx := staffingContext(t)
	ep, err := escalationmanager.NewDB(ctx, db, h.App().AlertLogStore)
	require.NoError(t, err)
	np, err := npcyclemanager.NewDB(ctx, db, h.App().AlertLogStore)
	require.NoError(t, err)
	id := recipientAlert(t, h, db, "svc-a")
	require.NoError(t, ep.UpdateAll(ctx))
	require.NoError(t, np.UpdateAll(ctx))
	var pending, cycle string
	require.NoError(t, db.QueryRow(`SELECT id,cycle_id FROM outgoing_messages WHERE alert_id=$1 AND user_id=$2`, id, h.UUID("target")).Scan(&pending, &cycle))
	recipientAssign(t, h, db, true)
	// Commit assignment before the next normal due batch. Preserve the old
	// outbox FK and verify that suppression does not cascade-delete it.
	recipientExec(t, db, `UPDATE notification_policy_cycles SET last_tick=now()-interval '2 minutes' WHERE alert_id=$1`, id)
	t1Snapshot(t, db, "before-old-cycle-reconciliation")
	require.NoError(t, np.UpdateAll(ctx))
	require.Equal(t, 1, staffingCount(t, db, `SELECT count(*) FROM outgoing_messages WHERE id=$1 AND cycle_id=$2`, pending, cycle))
	require.Equal(t, 1, staffingCount(t, db, `SELECT count(*) FROM notification_policy_cycles WHERE id=$1`, cycle))
	require.Equal(t, 1, staffingCount(t, db, `SELECT count(*) FROM alert_logs WHERE alert_id=$1 AND event='no_notification_sent' AND meta->>'Reason'='notification_cycle_recipient_org_denied' AND meta->>'UserID'=$2`, id, h.UUID("target")))
	require.Equal(t, 1, staffingCount(t, db, `SELECT count(*) FROM outgoing_messages WHERE alert_id=$1 AND user_id=$2`, id, h.UUID("target")))
	t1Snapshot(t, db, "after-old-cycle-suppression")
	require.NoError(t, h.App().Engine.Resume(t.Context()))
	h.Trigger()
	t1Rejected(t, h, db, id, "cm-target", 1)
	require.NoError(t, h.D08T1Consume(h.Email("control"), "Outbound isolation control", ""))
	recipientNoUnread(t, h)
	t1Snapshot(t, db, "old-pending-final-guard")
	t1Sink(t, h, "sink-final")
}

func TestStaffingDelayedAndAckClose(t *testing.T) {
	for _, multi := range []bool{false, true} {
		t.Run(fmt.Sprint(multi), func(t *testing.T) {
			h, db := t1New(t, false, true)
			pauseStepOrganizationEngine(t, h)
			ctx := staffingContext(t)
			recipientExec(t, db, `UPDATE escalation_policy_steps SET multi_ack=$1 WHERE id=$2`, multi, h.UUID("step-a"))
			recipientExec(t, db, `UPDATE user_notification_rules SET delay_minutes=2`)
			ep, err := escalationmanager.NewDB(ctx, db, h.App().AlertLogStore)
			require.NoError(t, err)
			np, err := npcyclemanager.NewDB(ctx, db, h.App().AlertLogStore)
			require.NoError(t, err)
			id := recipientAlert(t, h, db, "svc-a")
			require.NoError(t, ep.UpdateAll(ctx))
			require.NoError(t, np.UpdateAll(ctx))
			require.Zero(t, staffingCount(t, db, `SELECT count(*) FROM outgoing_messages WHERE alert_id=$1`, id))
			recipientExec(t, db, `UPDATE notification_policy_cycles SET started_at=now()-interval '3 minutes',last_tick=now()-interval '2 minutes' WHERE alert_id=$1`, id)
			require.NoError(t, np.UpdateAll(ctx))
			require.Equal(t, 2, staffingCount(t, db, `SELECT count(*) FROM outgoing_messages WHERE alert_id=$1`, id))
			require.NoError(t, h.App().Engine.Resume(t.Context()))
			h.Trigger()
			require.NoError(t, h.D08T1Consume(h.Email("target"), "Outbound isolation control", ""))
			require.NoError(t, h.D08T1Consume(h.Email("control"), "Outbound isolation control", ""))
			pauseStepOrganizationEngine(t, h)
			recipientExec(t, db, `UPDATE alerts SET status='active' WHERE id=$1`, id)
			recipientExec(t, db, `INSERT INTO alert_logs(alert_id,event,sub_user_id,message) VALUES($1,'acknowledged',$2,'Synthetic acknowledgement')`, id, h.UUID("target"))
			recipientExec(t, db, `UPDATE notification_policy_cycles SET last_tick=now()-interval '2 minutes' WHERE alert_id=$1`, id)
			require.NoError(t, np.UpdateAll(ctx))
			want := 0
			if multi {
				want = 1
			}
			require.Equal(t, want, staffingCount(t, db, `SELECT count(*) FROM notification_policy_cycles WHERE alert_id=$1`, id))
			require.Zero(t, staffingCount(t, db, `SELECT count(*) FROM notification_policy_cycles WHERE alert_id=$1 AND user_id=$2`, id, h.UUID("target")))
			recipientExec(t, db, `UPDATE alerts SET status='closed' WHERE id=$1`, id)
			recipientExec(t, db, `UPDATE notification_policy_cycles SET last_tick=now()-interval '2 minutes' WHERE alert_id=$1`, id)
			require.NoError(t, np.UpdateAll(ctx))
			require.Zero(t, staffingCount(t, db, `SELECT count(*) FROM notification_policy_cycles WHERE alert_id=$1`, id))
			t1Snapshot(t, db, "delayed-ack-close-final")
			t1Sink(t, h, "sink-final")
		})
	}
}

func TestStaffingPersistedParentOrganizations(t *testing.T) {
	h, db := t1New(t, false, false)
	pauseStepOrganizationEngine(t, h)
	ctx := staffingContext(t)
	// The same User is valid for Schedule A but invalid for Schedule B. An
	// EP B reference to A's materialized schedule must also be rejected.
	recipientExec(t, db, `INSERT INTO schedules(id,name,time_zone,organization_id) VALUES($1,'Synthetic B schedule','Asia/Shanghai',$2)`, h.UUID("sched-b"), h.UUID("org-b"))
	recipientExec(t, db, `INSERT INTO schedule_rules(schedule_id,tgt_user_id) VALUES($1,$2)`, h.UUID("sched-b"), h.UUID("target"))
	recipientExec(t, db, `INSERT INTO escalation_policy_steps(id,escalation_policy_id,delay) VALUES($1,$2,60)`, h.UUID("step-b"), h.UUID("ep-b"))
	recipientExec(t, db, `INSERT INTO escalation_policy_actions(escalation_policy_step_id,schedule_id) VALUES($1,$2)`, h.UUID("step-b"), h.UUID("sched-a"))
	sm, err := schedulemanager.NewDB(ctx, db)
	require.NoError(t, err)
	ep, err := escalationmanager.NewDB(ctx, db, h.App().AlertLogStore)
	require.NoError(t, err)
	require.NoError(t, sm.UpdateAll(ctx))
	require.NoError(t, ep.UpdateAll(ctx))
	require.Equal(t, 1, staffingCount(t, db, `SELECT count(*) FROM schedule_on_call_users WHERE schedule_id=$1 AND user_id=$2 AND end_time IS NULL`, h.UUID("sched-a"), h.UUID("target")))
	require.Zero(t, staffingCount(t, db, `SELECT count(*) FROM schedule_on_call_users WHERE schedule_id=$1 AND end_time IS NULL`, h.UUID("sched-b")))
	require.Zero(t, staffingCount(t, db, `SELECT count(*) FROM ep_step_on_call_users WHERE ep_step_id=$1 AND end_time IS NULL`, h.UUID("step-b")))
	// A historical Service/EP mismatch cannot create user-directed cycles even
	// if both roots and the on-call User independently exist.
	recipientExec(t, db, `UPDATE services SET organization_id=$1 WHERE id=$2`, h.UUID("org-b"), h.UUID("svc-a"))
	id := recipientAlert(t, h, db, "svc-a")
	require.NoError(t, ep.UpdateAll(ctx))
	require.Zero(t, staffingCount(t, db, `SELECT count(*) FROM notification_policy_cycles WHERE alert_id=$1`, id))
	t1Snapshot(t, db, "persisted-parents-final")
}

func TestStaffingScheduleNotificationChannel(t *testing.T) {
	deliveries := make(chan POSTDataOnCallNotification, 1)
	sink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload POSTDataOnCallNotification
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		select {
		case deliveries <- payload:
		default:
		}
	}))
	defer sink.Close()
	h, db := t1New(t, true, false)
	pauseStepOrganizationEngine(t, h)
	require.NoError(t, h.App().ConfigStore.UpdateConfig(staffingContext(t), func(c config.Config) (config.Config, error) {
		c.Webhook.Enable = true
		return c, nil
	}))
	ch := uuid.NewString()
	recipientExec(t, db, `INSERT INTO notification_channels(id,name,type,value) VALUES($1,'Synthetic schedule channel','WEBHOOK',$2)`, ch, sink.URL)
	data := fmt.Sprintf(`{"V1":{"OnCallNotificationRules":[{"ChannelID":%q}]}}`, ch)
	recipientExec(t, db, `INSERT INTO schedule_data(schedule_id,data) VALUES($1,$2) ON CONFLICT(schedule_id) DO UPDATE SET data=$2`, h.UUID("sched-a"), data)
	recipientExec(t, db, `INSERT INTO schedule_on_call_users(schedule_id,user_id) VALUES($1,$2) ON CONFLICT DO NOTHING`, h.UUID("sched-a"), h.UUID("target"))
	sm, err := schedulemanager.NewDB(staffingContext(t), db)
	require.NoError(t, err)
	require.NoError(t, sm.UpdateAll(staffingContext(t)))
	require.Equal(t, 1, staffingCount(t, db, `SELECT count(*) FROM outgoing_messages WHERE schedule_id=$1 AND channel_id=$2 AND message_type='schedule_on_call_notification'`, h.UUID("sched-a"), ch))
	require.NoError(t, h.App().Engine.Resume(t.Context()))
	h.Trigger()
	select {
	case payload := <-deliveries:
		require.Equal(t, "ScheduleOnCallUsers", payload.Type)
		require.Len(t, payload.Users, 1)
		require.Equal(t, h.UUID("control"), payload.Users[0].ID)
		t1Write(t, "channel-payload", payload)
	case <-time.After(5 * time.Second):
		t.Fatal("synthetic schedule channel did not receive notification")
	}
	require.Equal(t, 1, staffingCount(t, db, `SELECT count(*) FROM outgoing_messages WHERE schedule_id=$1 AND channel_id=$2 AND last_status='sent'`, h.UUID("sched-a"), ch))
	t1Snapshot(t, db, "schedule-channel-final")
}
