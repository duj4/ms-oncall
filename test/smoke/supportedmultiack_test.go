package smoke

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/target/goalert/devtools/pgmocktime"
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

// Historical C8 tests remain intact. Current supported-product positives use
// ordinary single ACK with real Webhook receipts and signed-session ACK/Close.
// ACK-01 remains confirmed/unrepaired; this test preparation does not implement
// MultiAck hard-disable or repair second-human GraphQL ACK.
func TestSupportedMultiAckLifecycle(t *testing.T) {
	for _, enabled := range []bool{false} {
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
			require.Empty(t, multiAckCycles(t, h, 198), "first ordinary ACK cancels both users' cycles")
			expectStatus("Acknowledged by First") // River status work is asynchronous
			multiAckStatus(t, h, 198, "active")
			multiAckLogUsers(t, h, 198, h.UUID("u1"))
			supportedStatus(t, h, "u1", "StatusAcknowledged")
			multiAckLogUsers(t, h, 198, h.UUID("u1")) // retry adds no duplicate actor

			h.FastForward(31 * time.Minute)
			h.Trigger()
			require.Empty(t, multiAckCycles(t, h, 198))
			r.expectAlerts(t, h, paths...)
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
	h := harness.NewHarness(t, supportedMultiAckFixture(r.URL, false), "")
	defer h.Close()
	r.expectAlerts(t, h, "/first", "/second")
	multiAckStatus(t, h, 198, "triggered")
	cycles := multiAckCycles(t, h, 198)
	require.Len(t, cycles, 2, "Close must cancel cycles that still exist")
	for _, cycle := range cycles {
		require.False(t, cycle.MultiAck)
	}
	h.FastForward(time.Minute)
	supportedStatus(t, h, "u1", "StatusClosed")
	h.Trigger()
	require.Empty(t, multiAckCycles(t, h, 198))
	multiAckLogUsers(t, h, 198) // direct Close must not invent an ACK
	var closeCount int
	var closedBy string
	require.NoError(t, h.App().DB().QueryRow(`SELECT count(*), min(sub_user_id::text) FROM alert_logs WHERE alert_id=198 AND event='closed'`).Scan(&closeCount, &closedBy))
	require.Equal(t, 1, closeCount)
	require.Equal(t, h.UUID("u1"), closedBy)
	require.Eventually(t, func() bool { return len(r.events("AlertStatus")) >= 2 }, 10*time.Second, 10*time.Millisecond)
	var statusPaths []string
	for _, receipt := range r.events("AlertStatus") {
		var payload struct{ LogEntry string }
		require.NoError(t, json.Unmarshal(receipt.Body, &payload))
		require.True(t, strings.HasPrefix(payload.LogEntry, "Closed by First"))
		statusPaths = append(statusPaths, receipt.Path)
	}
	require.ElementsMatch(t, []string{"/first", "/second"}, statusPaths)
	h.FastForward(61 * time.Minute)
	h.Trigger()
	r.expectAlerts(t, h, "/first", "/second")
	require.Empty(t, multiAckCycles(t, h, 198))
	multiAckStatus(t, h, 198, "closed")
	h.Trigger()
	r.expectAlerts(t, h, "/first", "/second")
	require.Len(t, r.events("AlertStatus"), 2, "Close must not revive status or delayed activity")
}

// These retained-MultiAck controls supplement the historical false-only test
// above. ACK-01 is repaired by Core #42; an additional accepted human ACK on a
// live true Step records another event, even when that actor has ACKed before.
func supportedRetainedMultiAckHarness(t *testing.T, r *supportedWebhookReceiver) (*harness.Harness, *pgmocktime.Mocker, map[string]multiAckCycle) {
	t.Helper()
	h := harness.NewHarness(t, supportedMultiAckFixture(r.URL, true), "")
	t.Cleanup(h.Close)
	r.expectAlerts(t, h, "/first", "/second")

	var database string
	require.NoError(t, h.App().DB().QueryRow(`SELECT current_database()`).Scan(&database))
	clock, err := pgmocktime.New(t.Context(), harness.DBURL(database))
	require.NoError(t, err)
	t.Cleanup(clock.Close)
	require.NoError(t, clock.SetSpeed(t.Context(), 0))

	var service, serviceOrg, policy, policyOrg, statePolicy, step, stepPolicy string
	var enabled bool
	require.NoError(t, h.App().DB().QueryRow(`SELECT a.service_id,s.organization_id,s.escalation_policy_id,
		ep.organization_id,state.escalation_policy_id,state.escalation_policy_step_id,step.escalation_policy_id,step.multi_ack
		FROM alerts a JOIN services s ON s.id=a.service_id
		JOIN escalation_policies ep ON ep.id=s.escalation_policy_id
		JOIN escalation_policy_state state ON state.alert_id=a.id
		JOIN escalation_policy_steps step ON step.id=state.escalation_policy_step_id
		WHERE a.id=198`).Scan(&service, &serviceOrg, &policy, &policyOrg, &statePolicy, &step, &stepPolicy, &enabled))
	require.Equal(t, h.UUID("sid"), service)
	require.Equal(t, harness.SmokeOrganizationID, serviceOrg)
	require.Equal(t, harness.SmokeOrganizationID, policyOrg)
	for _, id := range []string{policy, statePolicy, stepPolicy} {
		require.Equal(t, h.UUID("eid"), id)
	}
	require.Equal(t, h.UUID("esid"), step)
	require.True(t, enabled, "the live Step explicitly opts in")
	for _, user := range []string{"u1", "u2"} {
		var role, org, normalOrg, classification, orgRole, outcome string
		require.NoError(t, h.App().DB().QueryRow(`SELECT u.role,ua.effective_organization_id,
			ua.effective_normal_organization_id,ua.effective_organization_classification,ua.organization_role,ua.mapping_outcome
			FROM users u JOIN user_organization_assignments ua ON ua.user_id=u.id
			WHERE u.id=$1`, h.UUID(user)).Scan(&role, &org, &normalOrg, &classification, &orgRole, &outcome))
		require.Equal(t, "user", role)
		require.Equal(t, harness.SmokeOrganizationID, org)
		require.Equal(t, org, normalOrg)
		require.Equal(t, "NORMAL", classification)
		require.Equal(t, "ORG_MEMBER", orgRole)
		require.Equal(t, "EXACTLY_ONE", outcome)
	}
	cycles := multiAckCycles(t, h, 198)
	require.Len(t, cycles, 2)
	for _, user := range []string{"u1", "u2"} {
		cycle, ok := cycles[h.UUID(user)]
		require.True(t, ok, "cycle belongs to the expected User/Alert")
		require.NotEmpty(t, cycle.ID)
		require.True(t, cycle.MultiAck)
		require.False(t, cycle.StartedAt.IsZero())
		require.False(t, cycle.StartedAt.After(h.Now()))
		t.Logf("alert=198 step=%s user=%s cycle=%s multi_ack=%t started=%s", step, h.UUID(user), cycle.ID, cycle.MultiAck, cycle.StartedAt.Format(time.RFC3339Nano))
	}
	require.NotEqual(t, cycles[h.UUID("u1")].ID, cycles[h.UUID("u2")].ID)
	multiAckStatus(t, h, 198, "triggered")
	supportedRetainedMultiAckCheckpoint(t, h, r, "", "", "/first", "/second")
	return h, clock, cycles
}

func supportedRetainedMultiAckTick(t *testing.T, h *harness.Harness) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	id := h.App().Engine.NextCycleID()
	go h.App().Engine.Trigger()
	require.NoError(t, h.App().Engine.WaitCycleID(ctx, id))
}

func supportedRetainedMultiAckStatus(t *testing.T, h *harness.Harness, user, status string) {
	t.Helper()
	// The signed-session HTTP GraphQL request traverses human/Organization
	// admission. A no-error response alone does not prove an accepted ACK.
	response := h.GraphQLQueryUserT(t, h.UUID(user), fmt.Sprintf(`mutation{updateAlerts(input:{alertIDs:[198],newStatus:%s}){alertID}}`, status))
	require.Empty(t, response.Errors)
	var data struct{ UpdateAlerts []struct{ AlertID int } }
	require.NoError(t, json.Unmarshal(response.Data, &data))
	require.Len(t, data.UpdateAlerts, 1)
	require.Equal(t, 198, data.UpdateAlerts[0].AlertID)
	want := "active"
	if status == "StatusClosed" {
		want = "closed"
	}
	multiAckStatus(t, h, 198, want)
	var actor string
	var timestamp time.Time
	event := map[string]string{"StatusAcknowledged": "acknowledged", "StatusClosed": "closed"}[status]
	require.NoError(t, h.App().DB().QueryRow(`SELECT sub_user_id,timestamp FROM alert_logs
		WHERE alert_id=198 AND event=$1 ORDER BY id DESC LIMIT 1`, event).Scan(&actor, &timestamp))
	require.Equal(t, h.UUID(user), actor)
	require.True(t, timestamp.Equal(h.Now()), "the accepted event uses the frozen database clock")
}

// Check receipts and persisted sends together before advancing time. AlertStatus
// is counted separately from paging. Successful sends clear cycle_id; cycle
// identity is checked separately, before and after the real Engine consumption.
func supportedRetainedMultiAckCheckpoint(t *testing.T, h *harness.Harness, r *supportedWebhookReceiver, statusEvent, statusActor string, paths ...string) {
	t.Helper()
	r.expectAlerts(t, h, paths...)
	statusCount := 0
	if statusEvent != "" {
		statusCount = 2
	}
	total := len(paths) + statusCount
	require.Eventually(t, func() bool {
		var count, sent int
		require.NoError(t, h.App().DB().QueryRow(`SELECT count(*),count(*) FILTER (WHERE last_status='sent')
			FROM outgoing_messages WHERE alert_id=198`).Scan(&count, &sent))
		return count == total && sent == total && len(r.events("")) >= total
	}, 10*time.Second, 10*time.Millisecond)
	require.Len(t, r.events(""), total, "no unexpected event, destination or duplicate")

	rows, err := h.App().DB().Query(`SELECT msg.id,msg.user_id,cm.user_id,msg.contact_method_id,msg.service_id,msg.escalation_policy_id,
		cm.type,cm.value,msg.cycle_id IS NULL AND msg.sent_at IS NOT NULL AND msg.next_retry_at IS NULL
		AND msg.sending_deadline IS NULL AND msg.retry_count=0 AND msg.channel_id IS NULL
		FROM outgoing_messages msg JOIN user_contact_methods cm ON cm.id=msg.contact_method_id
		WHERE msg.alert_id=198 AND msg.message_type='alert_notification' ORDER BY msg.id`)
	require.NoError(t, err)
	defer rows.Close()
	var persisted []string
	for rows.Next() {
		var id, user, owner, contact, service, policy, kind, destination string
		var settled bool
		require.NoError(t, rows.Scan(&id, &user, &owner, &contact, &service, &policy, &kind, &destination, &settled))
		require.NotEmpty(t, id)
		require.Equal(t, user, owner, "outgoing recipient owns the Webhook contact method")
		require.Equal(t, h.UUID("sid"), service)
		require.Equal(t, h.UUID("eid"), policy)
		require.Equal(t, "WEBHOOK", kind, "ordinary Webhook, without a Gateway target or excluded provider")
		path := map[string]string{h.UUID("u1"): "/first", h.UUID("u2"): "/second"}[user]
		require.NotEmpty(t, path, "outgoing User identity")
		cm := map[string]string{"/first": "c1", "/second": "c2"}[path]
		require.Equal(t, h.UUID(cm), contact)
		require.Equal(t, r.URL+path, destination)
		require.True(t, settled)
		persisted = append(persisted, path)
	}
	require.NoError(t, rows.Err())
	require.NoError(t, rows.Close())
	require.ElementsMatch(t, paths, persisted, "exact durable paging multiplicity")

	var statusPaths []string
	for _, receipt := range r.events("AlertStatus") {
		var payload struct {
			WebhookTestingAlert
			LogEntry string
		}
		require.NoError(t, json.Unmarshal(receipt.Body, &payload))
		require.Equal(t, 198, payload.AlertID)
		require.Equal(t, "supported alert", payload.Summary)
		require.Equal(t, h.UUID("sid"), payload.ServiceID)
		require.Equal(t, "supported service", payload.ServiceName)
		prefix := map[string]string{"acknowledged": "Acknowledged by ", "closed": "Closed by "}[statusEvent]
		name := map[string]string{"u1": "First", "u2": "Second"}[statusActor]
		require.NotEmpty(t, prefix)
		require.NotEmpty(t, name)
		require.True(t, strings.HasPrefix(payload.LogEntry, prefix+name))
		statusPaths = append(statusPaths, receipt.Path)
	}
	var wantStatus []string
	if statusCount != 0 {
		wantStatus = []string{"/first", "/second"}
	}
	require.ElementsMatch(t, wantStatus, statusPaths)
	var storedStatus []string
	rows, err = h.App().DB().Query(`SELECT msg.user_id,msg.contact_method_id,log.event,log.sub_user_id
		FROM outgoing_messages msg JOIN alert_logs log ON log.id=msg.alert_log_id AND log.alert_id=msg.alert_id
		WHERE msg.alert_id=198 AND msg.message_type='alert_status_update' ORDER BY msg.id`)
	require.NoError(t, err)
	defer rows.Close()
	for rows.Next() {
		var user, contact, event, actor string
		require.NoError(t, rows.Scan(&user, &contact, &event, &actor))
		path := map[string]string{h.UUID("u1"): "/first", h.UUID("u2"): "/second"}[user]
		require.NotEmpty(t, path)
		cm := map[string]string{"/first": "c1", "/second": "c2"}[path]
		require.Equal(t, h.UUID(cm), contact)
		require.Equal(t, statusEvent, event)
		require.Equal(t, h.UUID(statusActor), actor)
		storedStatus = append(storedStatus, path)
	}
	require.NoError(t, rows.Err())
	require.NoError(t, rows.Close())
	require.ElementsMatch(t, wantStatus, storedStatus)
}

func TestSupportedRetainedMultiAckWebhookLifecycle(t *testing.T) {
	r := newSupportedWebhookReceiver(t)
	h, clock, before := supportedRetainedMultiAckHarness(t, r)
	b := before[h.UUID("u2")]
	paths := []string{"/first", "/second"}
	h.FastForward(2 * time.Minute) // human ACK must be strictly newer than both cycles
	for _, cycle := range before {
		require.True(t, h.Now().After(cycle.StartedAt))
	}
	supportedRetainedMultiAckStatus(t, h, "u1", "StatusAcknowledged")
	multiAckLogUsers(t, h, 198, h.UUID("u1"))
	// Recording the actor is not the consumption barrier. NPCycleManager only
	// revisits last_tick < now()-1 minute, so advance beyond that strict bound.
	h.FastForward(2 * time.Minute)
	supportedRetainedMultiAckTick(t, h)
	require.Equal(t, map[string]multiAckCycle{h.UUID("u2"): b}, multiAckCycles(t, h, 198))
	supportedRetainedMultiAckCheckpoint(t, h, r, "acknowledged", "u1", paths...)

	require.True(t, h.Now().Before(b.StartedAt.Add(29*time.Minute)))
	require.NoError(t, clock.SetTime(t.Context(), b.StartedAt.Add(29*time.Minute)))
	supportedRetainedMultiAckTick(t, h)
	require.Equal(t, map[string]multiAckCycle{h.UUID("u2"): b}, multiAckCycles(t, h, 198))
	supportedRetainedMultiAckCheckpoint(t, h, r, "acknowledged", "u1", paths...)
	require.NoError(t, clock.SetTime(t.Context(), b.StartedAt.Add(31*time.Minute)))
	supportedRetainedMultiAckTick(t, h)
	paths = append(paths, "/second")
	supportedRetainedMultiAckCheckpoint(t, h, r, "acknowledged", "u1", paths...)
	require.Equal(t, map[string]multiAckCycle{h.UUID("u2"): b}, multiAckCycles(t, h, 198), "B continues its original cycle; A stays suppressed")
	multiAckStatus(t, h, 198, "active")

	h.FastForward(2 * time.Minute)
	supportedRetainedMultiAckStatus(t, h, "u2", "StatusAcknowledged")
	multiAckLogUsers(t, h, 198, h.UUID("u1"), h.UUID("u2"))
	h.FastForward(2 * time.Minute)
	supportedRetainedMultiAckTick(t, h)
	require.Empty(t, multiAckCycles(t, h, 198))
	// #42 accepts a repeated human ACK on the live true Step: three events,
	// two distinct actors. It does not change active status or page again.
	supportedRetainedMultiAckStatus(t, h, "u1", "StatusAcknowledged")
	multiAckLogUsers(t, h, 198, h.UUID("u1"), h.UUID("u2"), h.UUID("u1"))
	var events, actors int
	require.NoError(t, h.App().DB().QueryRow(`SELECT count(*),count(DISTINCT sub_user_id)
		FROM alert_logs WHERE alert_id=198 AND event='acknowledged'`).Scan(&events, &actors))
	require.Equal(t, 3, events)
	require.Equal(t, 2, actors)
	require.NoError(t, clock.SetTime(t.Context(), b.StartedAt.Add(61*time.Minute)))
	supportedRetainedMultiAckTick(t, h)
	require.Empty(t, multiAckCycles(t, h, 198))
	supportedRetainedMultiAckCheckpoint(t, h, r, "acknowledged", "u1", paths...)
	h.FastForward(2 * time.Minute)
	supportedRetainedMultiAckTick(t, h)
	require.Empty(t, multiAckCycles(t, h, 198))
	supportedRetainedMultiAckCheckpoint(t, h, r, "acknowledged", "u1", paths...)
	multiAckStatus(t, h, 198, "active")
}

func TestSupportedRetainedMultiAckDirectCloseCancelsWebhook(t *testing.T) {
	r := newSupportedWebhookReceiver(t)
	h, clock, before := supportedRetainedMultiAckHarness(t, r)
	h.FastForward(2 * time.Minute)
	supportedRetainedMultiAckStatus(t, h, "u1", "StatusClosed")
	multiAckLogUsers(t, h, 198) // neither user ACKed; Close must not invent an ACK
	var count int
	var actor string
	require.NoError(t, h.App().DB().QueryRow(`SELECT count(*),min(sub_user_id::text)
		FROM alert_logs WHERE alert_id=198 AND event='closed'`).Scan(&count, &actor))
	require.Equal(t, 1, count)
	require.Equal(t, h.UUID("u1"), actor)
	h.FastForward(2 * time.Minute)
	supportedRetainedMultiAckTick(t, h)
	require.Empty(t, multiAckCycles(t, h, 198), "Close cancels both true cycles, including unacknowledged B")
	supportedRetainedMultiAckCheckpoint(t, h, r, "closed", "u1", "/first", "/second")
	deadline := before[h.UUID("u1")].StartedAt
	if b := before[h.UUID("u2")].StartedAt; b.After(deadline) {
		deadline = b
	}
	require.NoError(t, clock.SetTime(t.Context(), deadline.Add(61*time.Minute)))
	supportedRetainedMultiAckTick(t, h)
	require.Empty(t, multiAckCycles(t, h, 198))
	supportedRetainedMultiAckCheckpoint(t, h, r, "closed", "u1", "/first", "/second")
	h.FastForward(2 * time.Minute)
	supportedRetainedMultiAckTick(t, h)
	require.Empty(t, multiAckCycles(t, h, 198))
	supportedRetainedMultiAckCheckpoint(t, h, r, "closed", "u1", "/first", "/second")
	multiAckStatus(t, h, 198, "closed")
	multiAckLogUsers(t, h, 198)
	// This bounds future-rule cancellation after consumption. It makes no
	// claim about interrupting pending retries, bundles or in-flight HTTP.
}
