package smoke

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/target/goalert/devtools/pgmocktime"
	"github.com/target/goalert/test/smoke/harness"
)

// Keep every receipt, including duplicates and unexpected destinations. The
// handler never blocks on the test consumer and is safe under the race detector.
type supportedWebhookReceipt struct {
	Path string
	Type string
	Body json.RawMessage
}

type supportedWebhookReceiver struct {
	*httptest.Server
	mu       sync.Mutex
	receipts []supportedWebhookReceipt
}

func newSupportedWebhookReceiver(t *testing.T) *supportedWebhookReceiver {
	t.Helper()
	r := new(supportedWebhookReceiver)
	r.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodPost {
			t.Error("expected Webhook POST")
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		var body json.RawMessage
		if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
			t.Error(err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		var event struct{ Type string }
		if err := json.Unmarshal(body, &event); err != nil {
			t.Error(err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		r.mu.Lock()
		r.receipts = append(r.receipts, supportedWebhookReceipt{Path: req.URL.Path, Type: event.Type, Body: body})
		r.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(r.Close)
	return r
}

func (r *supportedWebhookReceiver) events(eventType string) []supportedWebhookReceipt {
	r.mu.Lock()
	defer r.mu.Unlock()
	var result []supportedWebhookReceipt
	for _, event := range r.receipts {
		if eventType == "" || event.Type == eventType {
			result = append(result, event)
		}
	}
	return result
}

func (r *supportedWebhookReceiver) expectAlerts(t *testing.T, h *harness.Harness, paths ...string) {
	t.Helper()
	require.Eventually(t, func() bool { return len(r.events("Alert")) >= len(paths) }, 10*time.Second, 10*time.Millisecond)
	var got []string
	for _, event := range r.events("Alert") {
		var payload WebhookTestingAlert
		require.NoError(t, json.Unmarshal(event.Body, &payload))
		require.Equal(t, 198, payload.AlertID)
		require.Equal(t, "supported alert", payload.Summary)
		require.Equal(t, h.UUID("sid"), payload.ServiceID)
		require.Equal(t, "supported service", payload.ServiceName)
		got = append(got, event.Path)
	}
	require.ElementsMatch(t, paths, got, "exact recipient multiplicity, including duplicates")
}

func supportedStatus(t *testing.T, h *harness.Harness, user, status string) {
	t.Helper()
	response := h.GraphQLQueryUserT(t, h.UUID(user), fmt.Sprintf(`mutation{updateAlerts(input:{alertIDs:[198],newStatus:%s}){alertID}}`, status))
	require.Empty(t, response.Errors)
	want := "active"
	if status == "StatusClosed" {
		want = "closed"
	}
	multiAckStatus(t, h, 198, want)
}

// Notification Rules are distinct from EP steps: delayed rules complete across
// a step change, while coincident deliveries to one destination are deduplicated.
func TestSupportedNotificationRulesAndEscalation(t *testing.T) {
	t.Run("manual escalation and notification rules", func(t *testing.T) {
		r := newSupportedWebhookReceiver(t)
		fixture := fmt.Sprintf(`
			INSERT INTO users(id,name,email) VALUES({{uuid "u1"}},'First','first@example.invalid'),({{uuid "u2"}},'Second','second@example.invalid');
			INSERT INTO user_contact_methods(id,user_id,name,type,value) VALUES
				({{uuid "email"}},{{uuid "u1"}},'Email','EMAIL',{{email "first"}}),
				({{uuid "webhook1"}},{{uuid "u1"}},'Webhook','WEBHOOK','%s/first'),
				({{uuid "webhook2"}},{{uuid "u2"}},'Webhook','WEBHOOK','%s/second');
			INSERT INTO user_notification_rules(user_id,contact_method_id,delay_minutes) VALUES
				({{uuid "u1"}},{{uuid "email"}},0),({{uuid "u1"}},{{uuid "webhook1"}},0),
				({{uuid "u1"}},{{uuid "webhook1"}},30),({{uuid "u2"}},{{uuid "webhook2"}},0);
			INSERT INTO escalation_policies(id,name,repeat,organization_id) VALUES({{uuid "eid"}},'Supported',1,{{smokeOrganizationID}});
			INSERT INTO escalation_policy_steps(id,escalation_policy_id,delay) VALUES
				({{uuid "step1"}},{{uuid "eid"}},60),({{uuid "step2"}},{{uuid "eid"}},60);
			INSERT INTO escalation_policy_actions(escalation_policy_step_id,user_id) VALUES
				({{uuid "step1"}},{{uuid "u1"}}),({{uuid "step2"}},{{uuid "u1"}}),({{uuid "step2"}},{{uuid "u2"}});
			INSERT INTO services(id,name,escalation_policy_id,organization_id) VALUES({{uuid "sid"}},'supported service',{{uuid "eid"}},{{smokeOrganizationID}});
			INSERT INTO alerts(id,service_id,summary,dedup_key) VALUES(198,{{uuid "sid"}},'supported alert','auto:1:supported');
		`, r.URL, r.URL)
		h := harness.NewHarness(t, fixture, "")
		defer h.Close()
		h.SMTP().ExpectMessage(h.Email("first"), "supported alert")
		r.expectAlerts(t, h, "/first")
		h.FastForward(10 * time.Minute)
		h.Trigger()
		r.expectAlerts(t, h, "/first") // no early delayed rule, no repeated immediate rule
		h.SMTP().WaitAndAssert()

		h.Escalate(198, 0)
		h.Trigger()
		h.SMTP().ExpectMessage(h.Email("first"), "supported alert")
		r.expectAlerts(t, h, "/first", "/first", "/second")
		h.FastForward(31 * time.Minute)
		h.Trigger()
		// Two pending cycles share the same delayed destination; only one receipt.
		r.expectAlerts(t, h, "/first", "/first", "/second", "/first")
		h.SMTP().WaitAndAssert()

		h.Escalate(198, 1) // manual escalation wraps back to step 1
		h.Trigger()
		h.SMTP().ExpectMessage(h.Email("first"), "supported alert")
		r.expectAlerts(t, h, "/first", "/first", "/second", "/first", "/first")
		h.FastForward(31 * time.Minute)
		h.Trigger()
		r.expectAlerts(t, h, "/first", "/first", "/second", "/first", "/first", "/first")
		// Further cycles must neither repeat immediate rules nor invent recipients.
		h.Trigger()
		r.expectAlerts(t, h, "/first", "/first", "/second", "/first", "/first", "/first")
		h.SMTP().WaitAndAssert()
	})

	t.Run("automatic timing and finite repeat", func(t *testing.T) {
		r := newSupportedWebhookReceiver(t)
		// One immediate rule and one distinct recipient per step make each
		// activation observable independently of the manual path's delayed rules.
		fixture := fmt.Sprintf(`
			INSERT INTO users(id,name,email) VALUES({{uuid "u1"}},'First','first@example.invalid'),({{uuid "u2"}},'Second','second@example.invalid');
			INSERT INTO user_contact_methods(id,user_id,name,type,value) VALUES
				({{uuid "c1"}},{{uuid "u1"}},'Webhook','WEBHOOK','%s/first'),({{uuid "c2"}},{{uuid "u2"}},'Webhook','WEBHOOK','%s/second');
			INSERT INTO user_notification_rules(user_id,contact_method_id,delay_minutes) VALUES
				({{uuid "u1"}},{{uuid "c1"}},0),({{uuid "u2"}},{{uuid "c2"}},0);
			INSERT INTO escalation_policies(id,name,repeat,organization_id) VALUES({{uuid "eid"}},'Supported',1,{{smokeOrganizationID}});
			INSERT INTO escalation_policy_steps(id,escalation_policy_id,delay) VALUES
				({{uuid "step1"}},{{uuid "eid"}},60),({{uuid "step2"}},{{uuid "eid"}},60);
			INSERT INTO escalation_policy_actions(escalation_policy_step_id,user_id) VALUES
				({{uuid "step1"}},{{uuid "u1"}}),({{uuid "step2"}},{{uuid "u2"}});
			INSERT INTO services(id,name,escalation_policy_id,organization_id) VALUES({{uuid "sid"}},'supported service',{{uuid "eid"}},{{smokeOrganizationID}});
			INSERT INTO alerts(id,service_id,summary,dedup_key) VALUES(198,{{uuid "sid"}},'supported alert','auto:1:automatic-supported');
		`, r.URL, r.URL)
		h := harness.NewHarness(t, fixture, "")
		defer h.Close()
		r.expectAlerts(t, h, "/first")

		// Freeze the existing harness clock; all normal Engine ticks now see
		// exactly the selected database time, including background ticks.
		var database string
		require.NoError(t, h.App().DB().QueryRow(`SELECT current_database()`).Scan(&database))
		clock, err := pgmocktime.New(t.Context(), harness.DBURL(database))
		require.NoError(t, err)
		defer clock.Close()
		require.NoError(t, clock.SetSpeed(t.Context(), 0))

		type escalationState struct {
			PolicyID, StepID string
			Step, Loop       int
			Last, Next       time.Time
			Forced           bool
		}
		state := func() escalationState {
			t.Helper()
			var s escalationState
			require.NoError(t, h.App().DB().QueryRow(`SELECT escalation_policy_id,escalation_policy_step_id,
				escalation_policy_step_number,loop_count,last_escalation,next_escalation,force_escalation
				FROM escalation_policy_state WHERE alert_id=198`).Scan(&s.PolicyID, &s.StepID, &s.Step, &s.Loop, &s.Last, &s.Next, &s.Forced))
			return s
		}
		cycles := func() string {
			t.Helper()
			var snapshot string
			// last_tick is ordinary processing bookkeeping, not cycle identity.
			require.NoError(t, h.App().DB().QueryRow(`SELECT coalesce(jsonb_agg(jsonb_build_object(
				'id',id,'user',user_id,'started',started_at,'multi_ack',multi_ack) ORDER BY id),'[]'::jsonb)::text
				FROM notification_policy_cycles WHERE alert_id=198`).Scan(&snapshot))
			return snapshot
		}
		paths := []string{"/first"}
		first, second := 1, 0
		expect := func(step, loop, first, second int) {
			t.Helper()
			s := state()
			require.Equal(t, h.UUID("eid"), s.PolicyID)
			require.Equal(t, h.UUID(fmt.Sprintf("step%d", step+1)), s.StepID)
			require.Equal(t, step, s.Step)
			require.Equal(t, loop, s.Loop)
			require.False(t, s.Forced)
			require.Equal(t, time.Hour, s.Next.Sub(s.Last))
			var status string
			require.NoError(t, h.App().DB().QueryRow(`SELECT status FROM alerts WHERE id=198`).Scan(&status))
			require.Equal(t, "triggered", status, "repeat exhaustion must not silently close the alert")
			var count, firstCount, secondCount, multiAck int
			require.NoError(t, h.App().DB().QueryRow(`SELECT count(*),count(*) FILTER (WHERE user_id=$1),
				count(*) FILTER (WHERE user_id=$2),count(*) FILTER (WHERE multi_ack)
				FROM notification_policy_cycles WHERE alert_id=198`, h.UUID("u1"), h.UUID("u2")).Scan(&count, &firstCount, &secondCount, &multiAck))
			require.Equal(t, first+second, count)
			require.Equal(t, first, firstCount)
			require.Equal(t, second, secondCount)
			require.Zero(t, multiAck)
			r.expectAlerts(t, h, paths...)
			require.Len(t, r.events(""), len(paths), "no unexpected event or duplicate")
			// Drain the asynchronous sender before a negative timing checkpoint.
			require.Eventually(t, func() bool {
				var sent int
				require.NoError(t, h.App().DB().QueryRow(`SELECT count(*) FROM outgoing_messages
					WHERE alert_id=198 AND last_status='sent'`).Scan(&sent))
				return sent == len(paths)
			}, 10*time.Second, 10*time.Millisecond)
			require.NoError(t, h.App().DB().QueryRow(`SELECT count(*) FROM outgoing_messages WHERE alert_id=198`).Scan(&count))
			require.Equal(t, len(paths), count, "exact persisted message count, including pending extras")
			t.Logf("step=%d loop=%d cycles=%d Webhook=%d/%d total=%d alert=%s forced=%t", s.Step, s.Loop, first+second, first, second, len(paths), status, s.Forced)
		}
		expect(0, 0, 1, 0)
		for _, next := range []struct {
			step, loop, first, second int
			path                      string
		}{
			{1, 0, 1, 1, "/second"}, // automatic step 2, original round
			{0, 1, 2, 1, "/first"},  // the one permitted repeat
			{1, 1, 2, 2, "/second"}, // automatic step 2, repeated round
		} {
			before, beforeCycles := state(), cycles()
			// SQL uses next_escalation < now(): never test ambiguous equality.
			require.NoError(t, clock.SetTime(t.Context(), before.Next.Add(-time.Minute)))
			require.True(t, h.Now().Before(before.Next))
			h.Trigger() // normal processing only; no h.Escalate or state forcing
			require.Equal(t, before, state(), "no premature step activation")
			require.Equal(t, beforeCycles, cycles(), "no premature cycle creation or replacement")
			expect(before.Step, before.Loop, first, second)
			t.Logf("pre-deadline: now=%s due=%s", h.Now().Format(time.RFC3339Nano), before.Next.Format(time.RFC3339Nano))

			require.NoError(t, clock.SetTime(t.Context(), before.Next.Add(time.Minute)))
			require.True(t, h.Now().After(before.Next))
			h.Trigger()
			paths = append(paths, next.path)
			first, second = next.first, next.second
			expect(next.step, next.loop, next.first, next.second)
			require.Equal(t, h.Now(), state().Last, "automatic escalation uses the due database time")
			t.Logf("post-deadline: now=%s previous-due=%s next-due=%s", h.Now().Format(time.RFC3339Nano), before.Next.Format(time.RFC3339Nano), state().Next.Format(time.RFC3339Nano))
		}

		// The next wrap would be loop 2, beyond repeat=1. Both sides of that
		// deadline, and further overdue processing, must retain exact state.
		exhausted, exhaustedCycles := state(), cycles()
		for _, offset := range []time.Duration{-time.Minute, time.Minute, 2 * time.Hour} {
			require.NoError(t, clock.SetTime(t.Context(), exhausted.Next.Add(offset)))
			h.Trigger()
			require.Equal(t, exhausted, state(), "finite repeat limit retains the last step and deadline")
			require.Equal(t, exhaustedCycles, cycles(), "no extra or replacement notification cycles")
			expect(1, 1, 2, 2)
			t.Logf("exhaustion checkpoint: offset=%s now=%s due=%s", offset, h.Now().Format(time.RFC3339Nano), exhausted.Next.Format(time.RFC3339Nano))
		}
		require.Never(t, func() bool { return len(r.events("")) != 4 }, time.Second, 10*time.Millisecond,
			"no late delivery after repeat exhaustion")
		expect(1, 1, 2, 2)
		require.Equal(t, exhausted, state())
		require.Equal(t, exhaustedCycles, cycles())
	})
}

// An empty schedule must not suppress a valid user on the same EP step. A user
// with only a delayed rule still has no immediate notification.
func TestSupportedMissingUserAndNoImmediateRule(t *testing.T) {
	r := newSupportedWebhookReceiver(t)
	fixture := fmt.Sprintf(`
		INSERT INTO users(id,name,email) VALUES({{uuid "u1"}},'First','first@example.invalid'),({{uuid "u2"}},'Delayed','delayed@example.invalid');
		INSERT INTO user_contact_methods(id,user_id,name,type,value) VALUES
			({{uuid "c1"}},{{uuid "u1"}},'Webhook','WEBHOOK','%s/first'),({{uuid "c2"}},{{uuid "u2"}},'Webhook','WEBHOOK','%s/delayed');
		INSERT INTO user_notification_rules(user_id,contact_method_id,delay_minutes) VALUES
			({{uuid "u1"}},{{uuid "c1"}},0),({{uuid "u2"}},{{uuid "c2"}},30);
		INSERT INTO schedules(id,name,time_zone,organization_id) VALUES({{uuid "empty"}},'Empty','UTC',{{smokeOrganizationID}});
		INSERT INTO escalation_policies(id,name,organization_id) VALUES({{uuid "eid"}},'Supported',{{smokeOrganizationID}});
		INSERT INTO escalation_policy_steps(id,escalation_policy_id,delay) VALUES({{uuid "step"}},{{uuid "eid"}},60);
		INSERT INTO escalation_policy_actions(escalation_policy_step_id,user_id,schedule_id) VALUES
			({{uuid "step"}},NULL,{{uuid "empty"}}),({{uuid "step"}},{{uuid "u1"}},NULL),({{uuid "step"}},{{uuid "u2"}},NULL);
		INSERT INTO services(id,name,escalation_policy_id,organization_id) VALUES({{uuid "sid"}},'supported service',{{uuid "eid"}},{{smokeOrganizationID}});
		INSERT INTO alerts(id,service_id,summary,dedup_key) VALUES(198,{{uuid "sid"}},'supported alert','auto:1:missing-supported');
	`, r.URL, r.URL)
	h := harness.NewHarness(t, fixture, "")
	defer h.Close()
	r.expectAlerts(t, h, "/first")
	h.FastForward(31 * time.Minute)
	h.Trigger()
	r.expectAlerts(t, h, "/first", "/delayed")
	h.Trigger()
	r.expectAlerts(t, h, "/first", "/delayed")
}
