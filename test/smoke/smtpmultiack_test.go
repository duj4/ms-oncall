package smoke

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/devtools/pgmocktime"
	"github.com/target/goalert/test/smoke/harness"
)

const smtpMultiAckSQL = `
	INSERT INTO users(id,name,email,role) VALUES
		({{uuid "u1"}},'First','first@example.invalid','user'),
		({{uuid "u2"}},'Second','second@example.invalid','user');
	INSERT INTO user_contact_methods(id,user_id,name,type,value,enable_status_updates) VALUES
		({{uuid "c1"}},{{uuid "u1"}},'Email','EMAIL',{{email "first"}},true),
		({{uuid "c2"}},{{uuid "u2"}},'Email','EMAIL',{{email "second"}},true);
	INSERT INTO user_notification_rules(user_id,contact_method_id,delay_minutes) VALUES
		({{uuid "u1"}},{{uuid "c1"}},0),({{uuid "u1"}},{{uuid "c1"}},30),({{uuid "u1"}},{{uuid "c1"}},60),
		({{uuid "u2"}},{{uuid "c2"}},0),({{uuid "u2"}},{{uuid "c2"}},30),({{uuid "u2"}},{{uuid "c2"}},60);
	INSERT INTO escalation_policies(id,name,organization_id) VALUES
		({{uuid "eid"}},'SMTP retained MultiAck',{{smokeOrganizationID}});
	INSERT INTO escalation_policy_steps(id,escalation_policy_id,multi_ack) VALUES
		({{uuid "esid"}},{{uuid "eid"}},true);
	INSERT INTO escalation_policy_actions(escalation_policy_step_id,user_id) VALUES
		({{uuid "esid"}},{{uuid "u1"}}),({{uuid "esid"}},{{uuid "u2"}});
	INSERT INTO services(id,name,escalation_policy_id,organization_id) VALUES
		({{uuid "sid"}},'SMTP retained MultiAck',{{uuid "eid"}},{{smokeOrganizationID}});
	INSERT INTO alerts(id,service_id,summary,dedup_key) VALUES
		(198,{{uuid "sid"}},'SMTP retained MultiAck alert','auto:1:smtp-retained-multiack');
`

func newSMTPMultiAck(t *testing.T) (*harness.Harness, *pgmocktime.Mocker, map[string]multiAckCycle) {
	t.Helper()
	h := harness.NewHarness(t, smtpMultiAckSQL, "")
	t.Cleanup(h.Close)
	var database string
	require.NoError(t, h.App().DB().QueryRowContext(t.Context(), `SELECT current_database()`).Scan(&database))
	clock, err := pgmocktime.New(t.Context(), harness.DBURL(database))
	require.NoError(t, err)
	t.Cleanup(clock.Close)
	require.NoError(t, clock.SetSpeed(t.Context(), 0))
	// Startup is asynchronous. Actual initial delivery is the readiness barrier
	// before inspecting Engine-created Step state and notification cycles.
	h.SMTP().ExpectMessage(h.Email("first"), "SMTP retained MultiAck alert", "198")
	h.SMTP().ExpectMessage(h.Email("second"), "SMTP retained MultiAck alert", "198")
	smtpMultiAckOutbox(t, h, 0, false)
	h.SMTP().WaitAndAssert()
	smtpLifecycleSubscriptions(t, h, "triggered")

	// Inspect the live Step selected by the Engine, rather than only the SQL fixture.
	var valid bool
	require.NoError(t, h.App().DB().QueryRowContext(t.Context(), `SELECT
		s.id=$1 AND s.organization_id=$2 AND ep.id=$3 AND ep.organization_id=$2
		AND state.escalation_policy_id=ep.id AND step.id=$4
		AND step.escalation_policy_id=ep.id AND step.multi_ack
		FROM alerts a JOIN services s ON s.id=a.service_id
		JOIN escalation_policies ep ON ep.id=s.escalation_policy_id
		JOIN escalation_policy_state state ON state.alert_id=a.id
		JOIN escalation_policy_steps step ON step.id=state.escalation_policy_step_id
		WHERE a.id=198`, h.UUID("sid"), harness.SmokeOrganizationID, h.UUID("eid"), h.UUID("esid")).Scan(&valid))
	require.True(t, valid, "Organization-owned live Step explicitly enables MultiAck")
	for _, user := range []string{"u1", "u2"} {
		require.NoError(t, h.App().DB().QueryRowContext(t.Context(), `SELECT
			u.role='user' AND ua.effective_organization_id=$2 AND ua.effective_normal_organization_id=$2
			AND ua.effective_organization_classification='NORMAL' AND ua.organization_role='ORG_MEMBER'
			AND ua.mapping_outcome='EXACTLY_ONE'
			AND EXISTS(SELECT FROM escalation_policy_actions WHERE escalation_policy_step_id=$3 AND user_id=u.id)
			AND (SELECT array_agg(delay_minutes ORDER BY delay_minutes) FROM user_notification_rules WHERE user_id=u.id)=ARRAY[0,30,60]
			FROM users u JOIN user_organization_assignments ua ON ua.user_id=u.id WHERE u.id=$1`,
			h.UUID(user), harness.SmokeOrganizationID, h.UUID("esid")).Scan(&valid))
		require.True(t, valid, "ordinary User, valid Organization assignment, Step action and three rules")
	}
	require.NotEqual(t, h.Email("first"), h.Email("second"))
	cycles := multiAckCycles(t, h, 198)
	require.Len(t, cycles, 2)
	for _, user := range []string{"u1", "u2"} {
		cycle, ok := cycles[h.UUID(user)]
		require.True(t, ok, "cycle belongs to the expected User and Alert")
		id, err := uuid.Parse(cycle.ID)
		require.NoError(t, err)
		require.NotEqual(t, uuid.Nil, id)
		require.True(t, cycle.MultiAck)
		require.False(t, cycle.StartedAt.IsZero())
		require.False(t, cycle.StartedAt.After(h.Now()))
		t.Logf("alert=198 live-step=%s user=%s original-cycle=%s multi_ack=true started=%s",
			h.UUID("esid"), h.UUID(user), cycle.ID, cycle.StartedAt.Format(time.RFC3339Nano))
	}
	require.NotEqual(t, cycles[h.UUID("u1")].ID, cycles[h.UUID("u2")].ID)
	multiAckStatus(t, h, 198, "triggered")
	t.Logf("Mailpit initial receipts: First=%s Second=%s alert=198, one page each", h.Email("first"), h.Email("second"))
	return h, clock, cycles
}

// Exact whole-outbox accounting supplements physical Mailpit receipts. Future
// rules live in cycles, not pending outgoing_messages. Sent messages clear
// cycle_id; the original cycle identities are checked separately at each tick.
func smtpMultiAckOutbox(t *testing.T, h *harness.Harness, logID int64, delayed bool) string {
	t.Helper()
	want := []smtpLifecycleMessage{
		{Type: "alert_notification", User: h.UUID("u1"), Contact: h.UUID("c1"), Alert: 198, Status: "sent", Sent: true},
		{Type: "alert_notification", User: h.UUID("u2"), Contact: h.UUID("c2"), Alert: 198, Status: "sent", Sent: true},
	}
	if logID != 0 {
		want = append(want, smtpLifecycleMessage{Type: "alert_status_update", User: h.UUID("u2"),
			Contact: h.UUID("c2"), Alert: 198, Status: "sent", Sent: true, LogID: logID})
	}
	if delayed {
		want = append(want, want[1])
	}
	var got []smtpLifecycleMessage
	require.Eventually(t, func() bool {
		got = smtpLifecycleMessages(t, h)
		if len(got) < len(want) {
			return false
		}
		for _, m := range got {
			if m.Status != "sent" {
				return false
			}
		}
		return true
	}, 15*time.Second, 10*time.Millisecond, "SMTP sends must settle durably")
	for i := range got {
		require.NotEmpty(t, got[i].ID)
		got[i].ID = ""
	}
	require.ElementsMatch(t, want, got, "exact recipients/types/log references; sent, no retry, pending cycle or in-flight send")

	var count int
	require.NoError(t, h.App().DB().QueryRowContext(t.Context(), `SELECT count(*) FROM outgoing_messages m
		JOIN user_contact_methods cm ON cm.id=m.contact_method_id AND cm.user_id=m.user_id
		WHERE m.alert_id=198 AND cm.type='EMAIL' AND cm.enable_status_updates
		AND ((m.user_id=$1 AND cm.id=$2 AND cm.value=$3) OR (m.user_id=$4 AND cm.id=$5 AND cm.value=$6))
		AND (m.message_type!='alert_notification' OR (m.service_id=$7 AND m.escalation_policy_id=$8))
		AND m.channel_id IS NULL`, h.UUID("u1"), h.UUID("c1"), h.Email("first"),
		h.UUID("u2"), h.UUID("c2"), h.Email("second"), h.UUID("sid"), h.UUID("eid")).Scan(&count))
	require.Equal(t, len(want), count, "durable recipient, contact ownership and paging resource identity")
	if logID != 0 {
		var actor, event string
		require.NoError(t, h.App().DB().QueryRowContext(t.Context(), `SELECT sub_user_id,event FROM alert_logs
			WHERE id=$1 AND alert_id=198`, logID).Scan(&actor, &event))
		require.Equal(t, h.UUID("u1"), actor)
		require.Contains(t, []string{"acknowledged", "closed"}, event)
	}

	// Preserve actual timestamps and row identities, so later checks also detect
	// replacement, deletion or another send of an existing settled message.
	snapshot := smtpMultiAckSnapshot(t, h)
	t.Logf("durable SMTP outbox: %s", snapshot)
	return snapshot
}

func smtpMultiAckSnapshot(t *testing.T, h *harness.Harness) string {
	t.Helper()
	var snapshot string
	require.NoError(t, h.App().DB().QueryRowContext(t.Context(), `SELECT jsonb_agg(to_jsonb(m) ORDER BY id)::text FROM (
		SELECT id,message_type,user_id,contact_method_id,alert_id,alert_log_id,service_id,escalation_policy_id,
		sent_at,last_status,retry_count,cycle_id,next_retry_at,sending_deadline FROM outgoing_messages
		) m`).Scan(&snapshot))
	return snapshot
}

func smtpMultiAckEvent(t *testing.T, h *harness.Harness, event string, actors ...string) int64 {
	t.Helper()
	rows, err := h.App().DB().QueryContext(t.Context(), `SELECT id,sub_user_id,timestamp FROM alert_logs
		WHERE alert_id=198 AND event=$1 ORDER BY id`, event)
	require.NoError(t, err)
	defer rows.Close()
	var firstID int64
	var got []string
	for rows.Next() {
		var id int64
		var actor string
		var at time.Time
		require.NoError(t, rows.Scan(&id, &actor, &at))
		if firstID == 0 {
			firstID = id
		}
		got = append(got, actor)
		t.Logf("authenticated lifecycle: alert=198 log=%d event=%s actor=%s timestamp=%s", id, event, actor, at.Format(time.RFC3339Nano))
	}
	require.NoError(t, rows.Err())
	require.Equal(t, actors, got, "exact persisted human lifecycle events in order")
	return firstID
}

func smtpMultiAckQuiet(t *testing.T, h *harness.Harness, snapshot string) {
	t.Helper()
	// Bound the asynchronous observation after settled delivery and Engine
	// checkpoints. This does not claim cancellation of retries or in-flight SMTP.
	// Keep observations on the test goroutine. Never can leave its final
	// condition running after its timer fires and test cleanup cancels Context.
	for start := time.Now(); time.Since(start) < time.Second; time.Sleep(100 * time.Millisecond) {
		h.SMTP().WaitAndAssert() // Unread physical receipts expose duplicates even of the same outbox row.
		require.Equal(t, snapshot, smtpMultiAckSnapshot(t, h), "no late durable outbox changes")
	}
	h.SMTP().WaitAndAssert()
}

func TestSMTPRetainedMultiAckLifecycle(t *testing.T) {
	t.Parallel()
	h, clock, original := newSMTPMultiAck(t)
	b := original[h.UUID("u2")]
	require.NoError(t, clock.AdvanceTime(t.Context(), 2*time.Minute))
	for _, c := range original {
		require.True(t, h.Now().After(c.StartedAt))
		require.True(t, h.Now().Before(c.StartedAt.Add(30*time.Minute)))
	}
	supportedRetainedMultiAckStatus(t, h, "u1", "StatusAcknowledged")
	logID := smtpMultiAckEvent(t, h, "acknowledged", h.UUID("u1"))
	// GraphQL can tick the Engine. Cross the strict last_tick < now()-1 minute
	// boundary after the ACK before asserting consumption of First's cycle.
	require.NoError(t, clock.AdvanceTime(t.Context(), 2*time.Minute))
	supportedRetainedMultiAckTick(t, h)
	require.Equal(t, map[string]multiAckCycle{h.UUID("u2"): b}, multiAckCycles(t, h, 198))
	h.SMTP().ExpectMessage(h.Email("second"), "Acknowledged by First", "198", "status updates enabled")
	smtpLifecycleSubscriptions(t, h, "active")
	before := smtpMultiAckOutbox(t, h, logID, false)
	h.SMTP().WaitAndAssert()
	t.Log("Mailpit ACK status: Second received Acknowledged by First; First received no self-update")

	require.NoError(t, clock.SetTime(t.Context(), b.StartedAt.Add(29*time.Minute)))
	supportedRetainedMultiAckTick(t, h)
	require.Equal(t, map[string]multiAckCycle{h.UUID("u2"): b}, multiAckCycles(t, h, 198))
	require.Equal(t, before, smtpMultiAckOutbox(t, h, logID, false))
	smtpMultiAckQuiet(t, h, before)
	require.NoError(t, clock.SetTime(t.Context(), b.StartedAt.Add(31*time.Minute)))
	supportedRetainedMultiAckTick(t, h)
	h.SMTP().ExpectMessage(h.Email("second"), "SMTP retained MultiAck alert", "198")
	before = smtpMultiAckOutbox(t, h, logID, true)
	h.SMTP().WaitAndAssert()
	require.Equal(t, map[string]multiAckCycle{h.UUID("u2"): b}, multiAckCycles(t, h, 198))
	t.Log("Mailpit delayed paging: Second received one 30-minute page; First received none; total=4")

	require.NoError(t, clock.AdvanceTime(t.Context(), 2*time.Minute))
	supportedRetainedMultiAckStatus(t, h, "u2", "StatusAcknowledged")
	smtpMultiAckEvent(t, h, "acknowledged", h.UUID("u1"), h.UUID("u2"))
	require.NoError(t, clock.AdvanceTime(t.Context(), 2*time.Minute))
	supportedRetainedMultiAckTick(t, h)
	require.Empty(t, multiAckCycles(t, h, 198))
	smtpLifecycleSubscriptions(t, h, "active")
	require.Equal(t, before, smtpMultiAckOutbox(t, h, logID, true), "second ACK is an event, without another status transition")
	smtpMultiAckQuiet(t, h, before)

	require.NoError(t, clock.SetTime(t.Context(), b.StartedAt.Add(61*time.Minute)))
	supportedRetainedMultiAckTick(t, h)
	require.Empty(t, multiAckCycles(t, h, 198))
	multiAckStatus(t, h, 198, "active")
	smtpMultiAckEvent(t, h, "acknowledged", h.UUID("u1"), h.UUID("u2"))
	require.Equal(t, before, smtpMultiAckOutbox(t, h, logID, true))
	smtpMultiAckQuiet(t, h, before)
}

func TestSMTPRetainedMultiAckDirectClose(t *testing.T) {
	t.Parallel()
	h, clock, original := newSMTPMultiAck(t)
	require.NoError(t, clock.AdvanceTime(t.Context(), 2*time.Minute))
	var latest time.Time
	for _, c := range original {
		require.True(t, h.Now().Before(c.StartedAt.Add(30*time.Minute)))
		if c.StartedAt.After(latest) {
			latest = c.StartedAt
		}
	}
	supportedRetainedMultiAckStatus(t, h, "u1", "StatusClosed")
	logID := smtpMultiAckEvent(t, h, "closed", h.UUID("u1"))
	multiAckLogUsers(t, h, 198)
	require.NoError(t, clock.AdvanceTime(t.Context(), 2*time.Minute))
	supportedRetainedMultiAckTick(t, h)
	require.Empty(t, multiAckCycles(t, h, 198), "Close cancels both original true-MultiAck cycles")
	h.SMTP().ExpectMessage(h.Email("second"), "Closed by First", "198", "status updates enabled")
	smtpLifecycleSubscriptions(t, h, "closed")
	before := smtpMultiAckOutbox(t, h, logID, false)
	h.SMTP().WaitAndAssert()
	t.Log("Mailpit Close status: Second received Closed by First; First received no self-update; total=3")
	for _, offset := range []time.Duration{31 * time.Minute, 61 * time.Minute} {
		require.NoError(t, clock.SetTime(t.Context(), latest.Add(offset)))
		supportedRetainedMultiAckTick(t, h)
		require.Empty(t, multiAckCycles(t, h, 198))
		multiAckStatus(t, h, 198, "closed")
		smtpLifecycleSubscriptions(t, h, "closed")
		smtpMultiAckEvent(t, h, "closed", h.UUID("u1"))
		multiAckLogUsers(t, h, 198)
		require.Equal(t, before, smtpMultiAckOutbox(t, h, logID, false))
		smtpMultiAckQuiet(t, h, before)
	}
}
