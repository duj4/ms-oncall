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

	h.Escalate(198, 1) // bounded repeat returns to step 1
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
