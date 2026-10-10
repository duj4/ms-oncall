package smoke

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/target/goalert/test/smoke/harness"
)

func supportedMultiAckFixture(url string, enabled bool) string {
	return fmt.Sprintf(`
		INSERT INTO users(id,name,email,role) VALUES({{uuid "u1"}},'First','first@example.invalid','user'),({{uuid "u2"}},'Second','second@example.invalid','user');
		INSERT INTO user_contact_methods(id,user_id,name,type,value,enable_status_updates) VALUES
			({{uuid "c1"}},{{uuid "u1"}},'Webhook','WEBHOOK','%s/first',true),({{uuid "c2"}},{{uuid "u2"}},'Webhook','WEBHOOK','%s/second',true);
		INSERT INTO user_notification_rules(user_id,contact_method_id,delay_minutes) VALUES
			({{uuid "u1"}},{{uuid "c1"}},0),({{uuid "u1"}},{{uuid "c1"}},30),({{uuid "u1"}},{{uuid "c1"}},60),
			({{uuid "u2"}},{{uuid "c2"}},0),({{uuid "u2"}},{{uuid "c2"}},30),({{uuid "u2"}},{{uuid "c2"}},60);
		INSERT INTO escalation_policies(id,name,organization_id) VALUES({{uuid "eid"}},'Supported',{{smokeOrganizationID}});
		INSERT INTO escalation_policy_steps(id,escalation_policy_id,multi_ack) VALUES({{uuid "esid"}},{{uuid "eid"}},%t);
		INSERT INTO escalation_policy_actions(escalation_policy_step_id,user_id) VALUES({{uuid "esid"}},{{uuid "u1"}}),({{uuid "esid"}},{{uuid "u2"}});
		INSERT INTO services(id,name,escalation_policy_id,organization_id) VALUES({{uuid "sid"}},'supported service',{{uuid "eid"}},{{smokeOrganizationID}});
		INSERT INTO alerts(id,service_id,summary,dedup_key) VALUES(198,{{uuid "sid"}},'supported alert','auto:1:supported-multiack');
	`, url, url, enabled)
}

// The existing snapshot/current-Step matrix remains intact. These positives
// add real Webhook receipts and signed-session human ACK/Close independently
// of SMS reply handling, including cancellation before a remaining delayed rule.
func TestSupportedMultiAckLifecycle(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(fmt.Sprint(enabled), func(t *testing.T) {
			r := newSupportedWebhookReceiver(t)
			h := harness.NewHarness(t, supportedMultiAckFixture(r.URL, enabled), "")
			defer h.Close()
			paths := []string{"/first", "/second"}
			r.expectAlerts(t, h, paths...)
			before := multiAckCycles(t, h, 198)
			require.Len(t, before, 2)
			for _, cycle := range before {
				require.Equal(t, enabled, cycle.MultiAck)
			}
			expectStatus := func(prefix string) {
				t.Helper()
				require.Eventually(t, func() bool {
					var got []string
					for _, receipt := range r.events("AlertStatus") {
						var payload struct{ LogEntry string }
						if json.Unmarshal(receipt.Body, &payload) != nil {
							return false
						}
						if strings.HasPrefix(payload.LogEntry, prefix) {
							got = append(got, receipt.Path)
						}
					}
					return len(got) >= 2
				}, 10*time.Second, 10*time.Millisecond)
				var got []string
				for _, receipt := range r.events("AlertStatus") {
					var payload struct{ LogEntry string }
					require.NoError(t, json.Unmarshal(receipt.Body, &payload))
					if strings.HasPrefix(payload.LogEntry, prefix) {
						got = append(got, receipt.Path)
					}
				}
				require.ElementsMatch(t, []string{"/first", "/second"}, got)
			}
			h.FastForward(time.Minute)
			supportedStatus(t, h, "u1", "StatusAcknowledged")
			h.Trigger()
			expectStatus("Acknowledged by First") // River status work is asynchronous
			multiAckStatus(t, h, 198, "active")
			multiAckLogUsers(t, h, 198, h.UUID("u1"))
			supportedStatus(t, h, "u1", "StatusAcknowledged")
			multiAckLogUsers(t, h, 198, h.UUID("u1")) // retry adds no duplicate actor

			h.FastForward(31 * time.Minute)
			h.Trigger()
			if enabled {
				paths = append(paths, "/second")
				cycles := multiAckCycles(t, h, 198)
				require.Len(t, cycles, 1)
				require.Equal(t, before[h.UUID("u2")], cycles[h.UUID("u2")])
			} else {
				require.Empty(t, multiAckCycles(t, h, 198))
			}
			r.expectAlerts(t, h, paths...)
			// updateAlerts currently updates only a strictly greater status, so
			// it cannot record a second actor's ACK of an already active alert.
			// Keep that source-backed Stage 1 gap explicit; do not pretend that
			// bulk GraphQL implements the callback's UpdateStatusTx contract.
			supportedStatus(t, h, "u1", "StatusClosed")
			h.FastForward(61 * time.Minute)
			h.Trigger()
			multiAckStatus(t, h, 198, "closed")
			require.Empty(t, multiAckCycles(t, h, 198))
			r.expectAlerts(t, h, paths...)
			// Webhook requires status updates even to the actor's destination.
			expectStatus("Closed by First")
			expectStatus("Acknowledged by First")
			require.Len(t, r.events("AlertStatus"), 4, "repeat ACK must not duplicate status delivery")
		})
	}
}

func TestSupportedCloseCancelsUnacknowledgedUser(t *testing.T) {
	r := newSupportedWebhookReceiver(t)
	h := harness.NewHarness(t, supportedMultiAckFixture(r.URL, true), "")
	defer h.Close()
	r.expectAlerts(t, h, "/first", "/second")
	h.FastForward(time.Minute)
	supportedStatus(t, h, "u1", "StatusAcknowledged")
	supportedStatus(t, h, "u1", "StatusClosed")
	h.FastForward(61 * time.Minute)
	h.Trigger()
	r.expectAlerts(t, h, "/first", "/second")
	require.Empty(t, multiAckCycles(t, h, 198))
	multiAckStatus(t, h, 198, "closed")
	h.Trigger()
	r.expectAlerts(t, h, "/first", "/second")
}
