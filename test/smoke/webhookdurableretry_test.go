package smoke

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/app"
	"github.com/target/goalert/devtools/pgmocktime"
	"github.com/target/goalert/notification/webhook"
	"github.com/target/goalert/test/smoke/harness"
)

type durableWebhookAttempt struct {
	Order                   int
	Method, Host, Path, Key string
	ContentType             string
	Payload                 []byte
	Status                  int
	ReadError               error
}

// Retain every HTTP attempt, including unexpected requests and duplicates.
// Stable Idempotency-Key values do not establish receiver-side deduplication
// or exactly-once processing; this receiver deliberately does neither.
type durableWebhookReceiver struct {
	*httptest.Server
	mu       sync.Mutex
	status   int
	attempts []durableWebhookAttempt
}

func newDurableWebhookReceiver(t *testing.T) *durableWebhookReceiver {
	t.Helper()
	r := &durableWebhookReceiver{status: http.StatusServiceUnavailable}
	r.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		body, err := io.ReadAll(req.Body)
		r.mu.Lock()
		defer r.mu.Unlock()
		w.WriteHeader(r.status)
		r.attempts = append(r.attempts, durableWebhookAttempt{
			Order: len(r.attempts) + 1, Method: req.Method, Host: req.Host,
			Path: req.URL.RequestURI(), Key: req.Header.Get("Idempotency-Key"),
			ContentType: req.Header.Get("Content-Type"), Payload: body,
			Status: r.status, ReadError: err,
		})
	}))
	t.Cleanup(r.Close)
	return r
}

func (r *durableWebhookReceiver) snapshot() []durableWebhookAttempt {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]durableWebhookAttempt(nil), r.attempts...)
}

func (r *durableWebhookReceiver) recover() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.status = http.StatusNoContent
}

// Exercise the ordinary Webhook Sender and durable database retry through a
// graceful Harness restart. Abrupt kills and ambiguous transport failures are
// outside this bounded HTTP 503 -> restart -> HTTP 204 scenario.
func TestWebhookDurableRetryAfterRestart(t *testing.T) {
	t.Parallel()
	r := newDurableWebhookReceiver(t)
	fixture := fmt.Sprintf(`
		INSERT INTO users(id,name,email,role) VALUES({{uuid "user"}},'Retry User','retry@example.invalid','user');
		INSERT INTO user_contact_methods(id,user_id,name,type,value) VALUES
			({{uuid "cm"}},{{uuid "user"}},'Webhook','WEBHOOK','%s/ordinary-retry');
		INSERT INTO user_notification_rules(user_id,contact_method_id,delay_minutes) VALUES
			({{uuid "user"}},{{uuid "cm"}},0);
		INSERT INTO escalation_policies(id,name,organization_id) VALUES
			({{uuid "ep"}},'Retry Policy',{{smokeOrganizationID}});
		INSERT INTO escalation_policy_steps(id,escalation_policy_id,delay) VALUES
			({{uuid "step"}},{{uuid "ep"}},60);
		INSERT INTO escalation_policy_actions(escalation_policy_step_id,user_id) VALUES
			({{uuid "step"}},{{uuid "user"}});
		INSERT INTO services(id,name,escalation_policy_id,organization_id) VALUES
			({{uuid "service"}},'retry service',{{uuid "ep"}},{{smokeOrganizationID}});
	`, r.URL)
	h := harness.NewStoppedHarness(t, fixture, nil, "")
	capture := new(c9LogCapture) // Preserve the Harness unexpected-error watcher.
	h.StartWithAppCfgHook(func(cfg *app.Config) {
		// Keep payload links stable when the restarted Core gets a new listen
		// port. This synthetic public link is never contacted by the test.
		cfg.InitialConfig.General.PublicURL = "https://core.example.invalid"
		capture.attach(cfg)
	})
	defer h.Close()

	var database string
	require.NoError(t, h.App().DB().QueryRow(`SELECT current_database()`).Scan(&database))
	clock, err := pgmocktime.New(t.Context(), harness.DBURL(database))
	require.NoError(t, err)
	defer clock.Close()
	require.NoError(t, clock.SetSpeed(t.Context(), 0))

	var validFixture bool
	require.NoError(t, h.App().DB().QueryRow(`SELECT EXISTS (
		SELECT 1 FROM users u JOIN user_organization_assignments a ON a.user_id=u.id
		JOIN normal_organizations n ON n.organization_id=a.effective_normal_organization_id
		JOIN organizations o ON o.id=n.organization_id
		JOIN services s ON s.organization_id=o.id
		JOIN escalation_policy_steps step ON step.escalation_policy_id=s.escalation_policy_id
		JOIN user_contact_methods cm ON cm.user_id=u.id
		WHERE u.id=$1 AND u.role='user' AND o.classification='NORMAL'
		AND a.effective_organization_id=o.id AND a.mapping_outcome='EXACTLY_ONE'
		AND s.id=$2 AND step.id=$3 AND NOT step.multi_ack
		AND cm.id=$4 AND cm.type='WEBHOOK' AND cm.value=$5
	)`, h.UUID("user"), h.UUID("service"), h.UUID("step"), h.UUID("cm"), r.URL+"/ordinary-retry").Scan(&validFixture))
	require.True(t, validFixture, "ordinary User/Organization/Webhook fixture and default-false step")

	type outboxMessage struct {
		ID, Type, Status, Details, CM, User, Service, Policy string
		Alert, Retries                                       int
		Created, StatusAt                                    time.Time
		Next, Sent, Fired, SendingDeadline                   sql.NullTime
		Cycle                                                sql.NullString
	}
	// Account for the entire isolated Outbox, including unexpected message types
	// and destinations, rather than querying only the expected UUID or Alert.
	outbox := func() []outboxMessage {
		t.Helper()
		rows, err := h.App().DB().Query(`SELECT id,message_type,last_status,status_details,
			contact_method_id,user_id,service_id,escalation_policy_id,alert_id,retry_count,
			created_at,last_status_at,next_retry_at,sent_at,fired_at,sending_deadline,cycle_id
			FROM outgoing_messages ORDER BY id`)
		require.NoError(t, err)
		defer rows.Close()
		var result []outboxMessage
		for rows.Next() {
			var m outboxMessage
			require.NoError(t, rows.Scan(&m.ID, &m.Type, &m.Status, &m.Details, &m.CM, &m.User,
				&m.Service, &m.Policy, &m.Alert, &m.Retries, &m.Created, &m.StatusAt,
				&m.Next, &m.Sent, &m.Fired, &m.SendingDeadline, &m.Cycle))
			result = append(result, m)
		}
		require.NoError(t, rows.Err())
		return result
	}
	require.Empty(t, outbox())
	// One exact, single-use expectation must actually be consumed. Further 503
	// errors remain unexpected; no broad backend-error suppression is installed.
	waitFailure := h.ExpectBackendError("send message: webhook request failed: HTTP status 503")
	alert := h.CreateAlertWithDetails(h.UUID("service"), "durable retry alert", "durable retry details")
	h.Trigger()
	require.Eventually(t, func() bool {
		messages := outbox()
		return len(messages) == 1 && messages[0].Status == "failed" && messages[0].Next.Valid
	}, 10*time.Second, 10*time.Millisecond, "initial HTTP failure must be durably retained")
	waitFailure()
	failed := outbox()[0]
	require.NoError(t, uuid.Validate(failed.ID))
	require.Equal(t, "alert_notification", failed.Type)
	require.Equal(t, alert.ID(), failed.Alert)
	require.Equal(t, h.UUID("cm"), failed.CM)
	require.Equal(t, h.UUID("user"), failed.User)
	require.Equal(t, h.UUID("service"), failed.Service)
	require.Equal(t, h.UUID("ep"), failed.Policy)
	require.Equal(t, "webhook request failed: HTTP status 503", failed.Details)
	require.Zero(t, failed.Retries, "the initial send is not a database retry")
	require.Equal(t, 15*time.Second, failed.Next.Time.Sub(failed.StatusAt))
	require.False(t, failed.Sent.Valid)

	type historyEntry struct{ Status, Details string }
	history := func() []historyEntry {
		t.Helper()
		rows, err := h.App().DB().Query(`SELECT status,status_details FROM message_status_history WHERE message_id=$1 ORDER BY id`, failed.ID)
		require.NoError(t, err)
		defer rows.Close()
		var result []historyEntry
		for rows.Next() {
			var entry historyEntry
			require.NoError(t, rows.Scan(&entry.Status, &entry.Details))
			require.NotContains(t, entry.Details, r.URL)
			require.NotContains(t, entry.Details, "/ordinary-retry")
			result = append(result, entry)
		}
		require.NoError(t, rows.Err())
		return result
	}
	failedHistory := []historyEntry{{Status: "pending"}, {Status: "sending"}, {Status: "failed", Details: failed.Details}}
	require.Equal(t, failedHistory, history(), "no successful delivery before recovery")
	checkAttempts := func(statuses ...int) []durableWebhookAttempt {
		t.Helper()
		attempts := r.snapshot()
		require.Len(t, attempts, len(statuses), "retain all HTTP attempts, including duplicates")
		target, err := url.Parse(r.URL)
		require.NoError(t, err)
		for i, attempt := range attempts {
			require.NoError(t, attempt.ReadError)
			require.Equal(t, i+1, attempt.Order)
			require.Equal(t, http.MethodPost, attempt.Method)
			require.Equal(t, target.Host, attempt.Host)
			require.Equal(t, "/ordinary-retry", attempt.Path)
			require.Equal(t, "application/json", attempt.ContentType)
			require.NotEmpty(t, attempt.Key)
			require.Equal(t, failed.ID, attempt.Key, "stable original Outbox identity")
			require.Equal(t, statuses[i], attempt.Status)
			var payload webhook.POSTDataAlert
			decoder := json.NewDecoder(bytes.NewReader(attempt.Payload))
			decoder.DisallowUnknownFields() // Reject a Gateway envelope or other event shape.
			require.NoError(t, decoder.Decode(&payload))
			require.Empty(t, payload.Meta)
			require.Equal(t, webhook.POSTDataAlert{
				AppName: h.Config().ApplicationName(), Type: "Alert", AlertID: alert.ID(),
				Summary: "durable retry alert", Details: "durable retry details",
				ServiceID: h.UUID("service"), ServiceName: "retry service", Meta: payload.Meta,
				GoAlertURL: h.Config().CallbackURL(fmt.Sprintf("/alerts/%d", alert.ID())),
			}, payload)
			t.Logf("HTTP attempt=%d method=%s path=%s key=%s status=%d ordinary Alert=%d Service=%s",
				attempt.Order, attempt.Method, attempt.Path, attempt.Key, attempt.Status, payload.AlertID, payload.ServiceID)
		}
		require.NotContains(t, capture.snapshot(), r.URL)
		require.NotContains(t, capture.snapshot(), "/ordinary-retry")
		return attempts
	}
	initial := checkAttempts(http.StatusServiceUnavailable)[0]
	t.Logf("persisted failure: id=%s status=%s retry_count=%d next_retry_at=%s sent_at=NULL",
		failed.ID, failed.Status, failed.Retries, failed.Next.Time.Format(time.RFC3339Nano))

	require.NoError(t, clock.SetTime(t.Context(), failed.Next.Time.Add(-time.Second)))
	require.True(t, h.Now().Before(failed.Next.Time))
	h.Trigger()
	require.Equal(t, []outboxMessage{failed}, outbox(), "pre-deadline processing preserves the original failed row")
	require.Equal(t, failedHistory, history())
	checkAttempts(http.StatusServiceUnavailable)

	beforeRestart := h.App()
	h.RestartGoAlertWithConfig(h.Config()) // Same database, Contact Method and receiver; no row reconstruction.
	require.NotSame(t, beforeRestart, h.App())
	var restartedDatabase string
	require.NoError(t, h.App().DB().QueryRow(`SELECT current_database()`).Scan(&restartedDatabase))
	require.Equal(t, database, restartedDatabase)
	require.True(t, h.Now().Before(failed.Next.Time), "database clock remains frozen across restart")
	h.Trigger()
	require.Equal(t, []outboxMessage{failed}, outbox(), "UUID, failure and retry metadata survive graceful restart")
	require.Equal(t, failedHistory, history())
	checkAttempts(http.StatusServiceUnavailable)
	t.Logf("graceful restart retained original id=%s retry_count=%d deadline=%s before due",
		failed.ID, failed.Retries, failed.Next.Time.Format(time.RFC3339Nano))

	r.recover()
	require.NoError(t, clock.SetTime(t.Context(), failed.Next.Time.Add(time.Second)))
	require.True(t, h.Now().After(failed.Next.Time))
	h.Trigger()
	require.Eventually(t, func() bool { return len(r.snapshot()) >= 2 }, 10*time.Second, 10*time.Millisecond,
		"positive HTTP receipt after the persisted retry deadline")
	require.Eventually(t, func() bool {
		messages := outbox()
		return len(messages) == 1 && messages[0].ID == failed.ID && messages[0].Status == "sent"
	}, 10*time.Second, 10*time.Millisecond)
	attempts := checkAttempts(http.StatusServiceUnavailable, http.StatusNoContent)
	require.JSONEq(t, string(initial.Payload), string(attempts[1].Payload), "ordinary payload remains semantically equivalent")
	settled := outbox()
	sent := settled[0]
	require.Equal(t, 1, sent.Retries)
	require.True(t, sent.Sent.Valid)
	require.Equal(t, h.Now(), sent.Sent.Time)
	require.False(t, sent.Next.Valid, "no active retry deadline remains")
	require.False(t, sent.SendingDeadline.Valid)
	require.False(t, sent.Fired.Valid)
	require.False(t, sent.Cycle.Valid)
	require.Empty(t, sent.Details)
	// Only the normal retry/status fields may change on the original row.
	want := failed
	want.Status, want.Details, want.Retries = "sent", "", 1
	want.StatusAt, want.Sent = h.Now(), sent.Sent
	want.Next, want.SendingDeadline, want.Fired, want.Cycle = sql.NullTime{}, sql.NullTime{}, sql.NullTime{}, sql.NullString{}
	require.Equal(t, want, sent)
	sentHistory := append(append([]historyEntry(nil), failedHistory...), historyEntry{Status: "pending"}, historyEntry{Status: "sending"}, historyEntry{Status: "sent"})
	require.Equal(t, sentHistory, history())
	t.Logf("recovered: original id=%s status=%s retry_count=%d sent_at=%s next_retry_at=NULL total_outbox=1",
		sent.ID, sent.Status, sent.Retries, sent.Sent.Time.Format(time.RFC3339Nano))

	for _, offset := range []time.Duration{time.Minute, 2 * time.Minute} {
		require.NoError(t, clock.SetTime(t.Context(), sent.Sent.Time.Add(offset)))
		h.Trigger()
		require.Equal(t, settled, outbox())
		require.Equal(t, sentHistory, history())
	}
	// Completed Engine cycles plus full durable accounting and a bounded
	// asynchronous negative observation guard against a late third request.
	require.Never(t, func() bool {
		return len(r.snapshot()) != 2 || !reflect.DeepEqual(settled, outbox()) || !reflect.DeepEqual(sentHistory, history())
	}, time.Second, 20*time.Millisecond, "no late retry, replacement row or terminal-state change")
	checkAttempts(http.StatusServiceUnavailable, http.StatusNoContent)
	require.Equal(t, settled, outbox())
	require.Equal(t, sentHistory, history())
	t.Log("post-recovery: further database time/cycles and 1s asynchronous observation; HTTP attempts=2, total_outbox=1, sent stable")
}
