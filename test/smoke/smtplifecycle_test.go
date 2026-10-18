package smoke

import (
	"encoding/json"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/target/goalert/devtools/pgmocktime"
	"github.com/target/goalert/test/smoke/harness"
)

const smtpLifecycleSQL = `
	INSERT INTO users(id,name,email,role) VALUES
		({{uuid "u1"}},'First','first@example.invalid','user'),
		({{uuid "u2"}},'Second','second@example.invalid','user');
	INSERT INTO user_contact_methods(id,user_id,name,type,value,enable_status_updates) VALUES
		({{uuid "c1"}},{{uuid "u1"}},'Email','EMAIL',{{email "first"}},true),
		({{uuid "c2"}},{{uuid "u2"}},'Email','EMAIL',{{email "second"}},true);
	INSERT INTO user_notification_rules(user_id,contact_method_id,delay_minutes) VALUES
		({{uuid "u1"}},{{uuid "c1"}},0),({{uuid "u1"}},{{uuid "c1"}},30),
		({{uuid "u2"}},{{uuid "c2"}},0),({{uuid "u2"}},{{uuid "c2"}},30);
	INSERT INTO escalation_policies(id,name,organization_id) VALUES
		({{uuid "eid"}},'SMTP lifecycle',{{smokeOrganizationID}});
	-- Omit multi_ack to exercise the ordinary default-false Step.
	INSERT INTO escalation_policy_steps(id,escalation_policy_id,delay) VALUES
		({{uuid "step"}},{{uuid "eid"}},60);
	INSERT INTO escalation_policy_actions(escalation_policy_step_id,user_id) VALUES
		({{uuid "step"}},{{uuid "u1"}}),({{uuid "step"}},{{uuid "u2"}});
	INSERT INTO services(id,name,escalation_policy_id,organization_id) VALUES
		({{uuid "sid"}},'SMTP lifecycle',{{uuid "eid"}},{{smokeOrganizationID}});
	INSERT INTO alerts(id,service_id,summary,dedup_key) VALUES
		(198,{{uuid "sid"}},'SMTP lifecycle alert','auto:1:smtp-lifecycle');
`

type smtpLifecycleMessage struct {
	ID, Type, User, Contact, Status string
	Alert, Retries                  int
	LogID                           int64
	Sent, Cycle, Retry, Sending     bool
}

func smtpLifecycleMessages(t *testing.T, h *harness.Harness) []smtpLifecycleMessage {
	t.Helper()
	// Include the entire isolated outbox, so unexpected types/alerts cannot hide.
	rows, err := h.App().DB().QueryContext(t.Context(), `SELECT id,message_type,
		coalesce(user_id::text,''),coalesce(contact_method_id::text,''),last_status,
		coalesce(alert_id,0),retry_count,coalesce(alert_log_id,0),sent_at IS NOT NULL,
		cycle_id IS NOT NULL,next_retry_at IS NOT NULL,sending_deadline IS NOT NULL
		FROM outgoing_messages ORDER BY id`)
	require.NoError(t, err)
	defer rows.Close()
	var result []smtpLifecycleMessage
	for rows.Next() {
		var m smtpLifecycleMessage
		require.NoError(t, rows.Scan(&m.ID, &m.Type, &m.User, &m.Contact, &m.Status,
			&m.Alert, &m.Retries, &m.LogID, &m.Sent, &m.Cycle, &m.Retry, &m.Sending))
		result = append(result, m)
	}
	require.NoError(t, rows.Err())
	return result
}

func smtpLifecycleExpectMessages(t *testing.T, h *harness.Harness, logID int64) []smtpLifecycleMessage {
	t.Helper()
	want := []smtpLifecycleMessage{
		{Type: "alert_notification", User: h.UUID("u1"), Contact: h.UUID("c1"), Alert: 198, Status: "sent", Sent: true},
		{Type: "alert_notification", User: h.UUID("u2"), Contact: h.UUID("c2"), Alert: 198, Status: "sent", Sent: true},
	}
	if logID != 0 {
		// SMTP status updates are opt-in and suppress the acting user's own update.
		want = append(want, smtpLifecycleMessage{
			Type: "alert_status_update", User: h.UUID("u2"), Contact: h.UUID("c2"),
			Alert: 198, Status: "sent", Sent: true, LogID: logID,
		})
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
	}, 15*time.Second, 10*time.Millisecond, "SMTP sends must settle durably: %+v", got)
	withoutIDs := append([]smtpLifecycleMessage(nil), got...)
	for i := range withoutIDs {
		withoutIDs[i].ID = ""
	}
	require.ElementsMatch(t, want, withoutIDs, "exact outbox multiplicity, recipients, types and terminal delivery state")
	t.Logf("durable SMTP outbox: %+v", got)
	return got
}

func newSMTPLifecycle(t *testing.T) (*harness.Harness, *pgmocktime.Mocker, time.Time) {
	t.Helper()
	h := harness.NewHarness(t, smtpLifecycleSQL, "")
	t.Cleanup(h.Close)
	var database string
	require.NoError(t, h.App().DB().QueryRowContext(t.Context(), `SELECT current_database()`).Scan(&database))
	clock, err := pgmocktime.New(t.Context(), harness.DBURL(database))
	require.NoError(t, err)
	t.Cleanup(clock.Close)
	require.NoError(t, clock.SetSpeed(t.Context(), 0))
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("failure outbox (unexpected Mailpit messages remain unread): %+v", smtpLifecycleMessages(t, h))
		}
	})

	h.SMTP().ExpectMessage(h.Email("first"), "SMTP lifecycle alert")
	h.SMTP().ExpectMessage(h.Email("second"), "SMTP lifecycle alert")
	smtpLifecycleExpectMessages(t, h, 0)
	h.SMTP().WaitAndAssert()
	t.Log("Mailpit receipts: exactly one initial paging email to First and one to Second")

	cycles := multiAckCycles(t, h, 198)
	require.Len(t, cycles, 2)
	var deadline time.Time
	for _, user := range []string{"u1", "u2"} {
		cycle, ok := cycles[h.UUID(user)]
		require.True(t, ok)
		require.False(t, cycle.MultiAck, "default-false notification cycle")
		if due := cycle.StartedAt.Add(30 * time.Minute); due.After(deadline) {
			deadline = due
		}
		var role, org, classification, orgRole, outcome string
		require.NoError(t, h.App().DB().QueryRowContext(t.Context(), `SELECT u.role,
			ua.effective_normal_organization_id,ua.effective_organization_classification,
			ua.organization_role,ua.mapping_outcome FROM users u
			JOIN user_organization_assignments ua ON ua.user_id=u.id WHERE u.id=$1`,
			h.UUID(user)).Scan(&role, &org, &classification, &orgRole, &outcome))
		require.Equal(t, "user", role)
		require.Equal(t, harness.SmokeOrganizationID, org)
		require.Equal(t, "NORMAL", classification)
		require.Equal(t, "ORG_MEMBER", orgRole)
		require.Equal(t, "EXACTLY_ONE", outcome)
	}
	var valid bool
	require.NoError(t, h.App().DB().QueryRowContext(t.Context(), `SELECT
		s.organization_id=$1 AND ep.organization_id=$1 AND NOT step.multi_ack
		FROM services s JOIN escalation_policies ep ON ep.id=s.escalation_policy_id
		JOIN escalation_policy_steps step ON step.escalation_policy_id=ep.id
		WHERE s.id=$2`, harness.SmokeOrganizationID, h.UUID("sid")).Scan(&valid))
	require.True(t, valid, "service, policy and ordinary Step belong to the fixture Organization")
	multiAckStatus(t, h, 198, "triggered")
	smtpLifecycleSubscriptions(t, h, "triggered")
	return h, clock, deadline
}

func smtpLifecycleSubscriptions(t *testing.T, h *harness.Harness, status string) {
	t.Helper()
	// Waiting for both subscriptions proves that the actor's suppressed update
	// has been processed too, rather than merely waiting for the other email.
	require.Eventually(t, func() bool {
		var count, matching int
		require.NoError(t, h.App().DB().QueryRowContext(t.Context(), `SELECT count(*),
			count(*) FILTER (WHERE last_alert_status::text=$1 AND contact_method_id IN ($2,$3))
			FROM alert_status_subscriptions WHERE alert_id=198`,
			status, h.UUID("c1"), h.UUID("c2")).Scan(&count, &matching))
		if status == "closed" {
			return count == 0
		}
		return count == 2 && matching == 2
	}, 15*time.Second, 10*time.Millisecond, "both SMTP status subscriptions must settle")
}

func smtpLifecycleChange(t *testing.T, h *harness.Harness, clock *pgmocktime.Mocker, closeAlert bool) int64 {
	t.Helper()
	// Cycle cleanup is eligible once last_tick is over one minute old, while
	// both 30-minute rules remain pending.
	require.NoError(t, clock.AdvanceTime(t.Context(), 2*time.Minute))
	var beforeDelayedRules bool
	require.NoError(t, h.App().DB().QueryRowContext(t.Context(), `SELECT
		now() < min(started_at) + '30 minutes'::interval
		FROM notification_policy_cycles WHERE alert_id=198`).Scan(&beforeDelayedRules))
	require.True(t, beforeDelayedRules, "the lifecycle action must precede the delayed rules")
	gqlStatus, status, event, text := "StatusAcknowledged", "active", "acknowledged", "Acknowledged by First"
	if closeAlert {
		gqlStatus, status, event, text = "StatusClosed", "closed", "closed", "Closed by First"
	}
	response := h.GraphQLQueryUserT(t, h.UUID("u1"), fmt.Sprintf(
		`mutation{updateAlerts(input:{alertIDs:[198],newStatus:%s}){alertID}}`, gqlStatus))
	require.Empty(t, response.Errors)
	var data struct {
		UpdateAlerts []struct{ AlertID int }
	}
	require.NoError(t, json.Unmarshal(response.Data, &data))
	require.Len(t, data.UpdateAlerts, 1)
	require.Equal(t, 198, data.UpdateAlerts[0].AlertID)
	multiAckStatus(t, h, 198, status)
	h.Trigger()
	require.Empty(t, multiAckCycles(t, h, 198), "ordinary lifecycle action cancels both pending cycles")

	var logID int64
	var actor string
	var eventCount int
	require.NoError(t, h.App().DB().QueryRowContext(t.Context(), `SELECT count(*),min(id),min(sub_user_id::text) FROM alert_logs
		WHERE alert_id=198 AND event=$1`, event).Scan(&eventCount, &logID, &actor))
	require.Equal(t, 1, eventCount, "one authenticated action produces exactly one lifecycle event")
	require.Equal(t, h.UUID("u1"), actor)
	if closeAlert {
		multiAckLogUsers(t, h, 198) // Direct Close must not manufacture an ACK.
	} else {
		multiAckLogUsers(t, h, 198, h.UUID("u1"))
	}
	h.SMTP().ExpectMessage(h.Email("second"), text, "status updates enabled")
	smtpLifecycleSubscriptions(t, h, status) // River processing is asynchronous.
	smtpLifecycleExpectMessages(t, h, logID)
	h.SMTP().WaitAndAssert()
	t.Logf("Mailpit status receipt: Second received %q; First received no self-update", text)
	return logID
}

func smtpLifecyclePastDeadline(t *testing.T, h *harness.Harness, clock *pgmocktime.Mocker, deadline time.Time, logID int64, status string) {
	t.Helper()
	before := smtpLifecycleExpectMessages(t, h, logID)
	for _, offset := range []time.Duration{time.Minute, 31 * time.Minute} {
		require.NoError(t, clock.SetTime(t.Context(), deadline.Add(offset)))
		require.True(t, h.Now().After(deadline), "the delayed rules are now overdue")
		h.Trigger()
		multiAckStatus(t, h, 198, status)
		require.Empty(t, multiAckCycles(t, h, 198))
		require.Equal(t, before, smtpLifecycleExpectMessages(t, h, logID),
			"no new, deleted, replaced or retried outgoing messages after cancellation")
		smtpLifecycleSubscriptions(t, h, status)
		h.SMTP().WaitAndAssert()
		t.Logf("overdue Engine checkpoint: now=%s delayed-deadline=%s status=%s cycles=0 outbox=3",
			h.Now().Format(time.RFC3339Nano), deadline.Format(time.RFC3339Nano), status)
	}
	// Observe asynchronous work after explicit overdue Engine checkpoints.
	// Durable equality and removed cycles are the negative oracle; unread
	// Mailpit receipts additionally expose physical duplicates of a single row.
	require.Never(t, func() bool {
		return !slices.Equal(before, smtpLifecycleMessages(t, h))
	}, time.Second, 10*time.Millisecond, "no late asynchronous paging or duplicate status job")
	h.SMTP().WaitAndAssert()
	t.Log("post-deadline: zero cycles; exactly two paging rows and one status row, all sent without retry")
}

func TestSMTPLifecycleOrdinaryACK(t *testing.T) {
	t.Parallel()
	h, clock, deadline := newSMTPLifecycle(t)
	logID := smtpLifecycleChange(t, h, clock, false)
	smtpLifecyclePastDeadline(t, h, clock, deadline, logID, "active")
}

func TestSMTPLifecycleDirectClose(t *testing.T) {
	t.Parallel()
	h, clock, deadline := newSMTPLifecycle(t)
	logID := smtpLifecycleChange(t, h, clock, true)
	smtpLifecyclePastDeadline(t, h, clock, deadline, logID, "closed")
	multiAckLogUsers(t, h, 198)
}
