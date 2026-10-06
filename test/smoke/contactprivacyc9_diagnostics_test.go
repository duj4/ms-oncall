package smoke

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/app"
	"github.com/target/goalert/auth"
	"github.com/target/goalert/limit"
	"github.com/target/goalert/notification"
	"github.com/target/goalert/notification/nfydest"
	"github.com/target/goalert/notification/nfymsg"
	"github.com/target/goalert/retry"
	"github.com/target/goalert/test/smoke/harness"
	"github.com/target/goalert/validation"
)

// Capture every application/structured/debug log without replacing the
// harness's existing unexpected-error watcher.
type c9LogCapture struct {
	mu      sync.Mutex
	entries []string
}

func (*c9LogCapture) Levels() []logrus.Level { return logrus.AllLevels }
func (c *c9LogCapture) Fire(e *logrus.Entry) error {
	text, err := e.String()
	if err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = append(c.entries, text)
	return nil
}
func (c *c9LogCapture) attach(cfg *app.Config) { cfg.LegacyLogger.Logrus().AddHook(c) }
func (c *c9LogCapture) snapshot() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return strings.Join(c.entries, "")
}

type c9DiagnosticProvider struct {
	id, raw   string
	fail      bool
	attempts  atomic.Int32
	polled    atomic.Int32
	pollError atomic.Bool
}

func (p *c9DiagnosticProvider) ID() string { return p.id }
func (p *c9DiagnosticProvider) TypeInfo(context.Context) (*nfydest.TypeInfo, error) {
	return &nfydest.TypeInfo{Enabled: true, SupportsAlertNotifications: true, SupportsUserVerification: true, SupportsStatusUpdates: true, RequiredFields: []nfydest.FieldConfig{{FieldID: "address"}}}, nil
}
func (p *c9DiagnosticProvider) ValidateField(_ context.Context, _, value string) error {
	return validation.WrapError(fmt.Errorf("invalid destination %s", value))
}
func (p *c9DiagnosticProvider) DisplayInfo(_ context.Context, args map[string]string) (*nfydest.DisplayInfo, error) {
	return nil, fmt.Errorf("display destination %s", args["address"])
}
func (p *c9DiagnosticProvider) SendMessage(_ context.Context, msg nfymsg.Message) (*nfymsg.SentMessage, error) {
	// The provider actually receives the raw destination through System/Engine.
	if msg.DestArg("address") != p.raw {
		return nil, errors.New("C9 delivery lost its destination")
	}
	n := p.attempts.Add(1)
	if p.fail {
		return nil, fmt.Errorf("failed delivery to %s", p.raw)
	}
	if n == 1 {
		return nil, retry.TemporaryError(fmt.Errorf("retry delivery to %s", p.raw))
	}
	return &nfymsg.SentMessage{ExternalID: "c9-safe-provider-id", State: nfymsg.StateSending, StateDetails: "provider echoed " + p.raw}, nil
}
func (p *c9DiagnosticProvider) MessageStatus(context.Context, string) (*nfymsg.Status, error) {
	p.polled.Add(1)
	if p.pollError.Load() {
		return nil, fmt.Errorf("poll delivery to %s", p.raw)
	}
	return &nfymsg.Status{State: nfymsg.StateDelivered, Details: "status callback echoes " + p.raw}, nil
}

func c9TraceExtensions(t *testing.T, h *harness.Harness, query string) string {
	t.Helper()
	body, err := json.Marshal(map[string]string{"query": query})
	require.NoError(t, err)
	req, err := http.NewRequest(http.MethodPost, h.URL()+"/api/graphql?trace=1", bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: h.GraphQLToken(harness.DefaultGraphQLAdminUserID)})
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, 200, resp.StatusCode)
	var result struct{ Extensions json.RawMessage }
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&result))
	require.Contains(t, string(result.Extensions), "tracing")
	return string(result.Extensions)
}

func TestC9ProviderEngineLogsHistoryAndTelemetry(t *testing.T) {
	capture := new(c9LogCapture)
	h := c9Harness(t, capture.attach)
	h.SetSystemLimit(limit.ContactMethodsPerUser, 30)
	h.SetSystemLimit(limit.NotificationRulesPerUser, 30)
	h.IgnoreErrorsWith("provider operation failed")
	rawValues := []string{"c9-provider-secret@example.invalid", "+15551234999", "https://example.invalid/private/c9-provider-secret-token"}
	for _, private := range []bool{false, true} {
		for n, raw := range rawValues {
			for _, fail := range []bool{false, true} {
				name := fmt.Sprintf("c9-provider-%t-%d-%t", private, n, fail)
				provider := &c9DiagnosticProvider{id: name, raw: raw, fail: fail}
				h.App().DestRegistry.RegisterProvider(context.Background(), provider)
				id := c9InsertCM(t, h, name, "user-a", name, "address", raw, private)
				msgID := h.UUID(name + "-message")
				_, err := h.App().DB().Exec(`INSERT INTO outgoing_messages(id,message_type,contact_method_id,user_id) VALUES($1,'test_notification',$2,$3)`, msgID, id, h.UUID("user-a"))
				require.NoError(t, err)
				require.NoError(t, h.App().Engine.Resume(context.Background()))
				h.Trigger()
				pauseStepOrganizationEngine(t, h)
				require.Positive(t, provider.attempts.Load())
				var details string
				require.NoError(t, h.App().DB().QueryRow(`SELECT status_details FROM outgoing_messages WHERE id=$1`, msgID).Scan(&details))
				require.NotContains(t, details, raw)
				if !fail {
					require.GreaterOrEqual(t, provider.attempts.Load(), int32(2), "temporary retry classification must survive sanitization")
					provider.pollError.Store(true)
					_, err = h.App().DB().Exec(`UPDATE outgoing_messages SET last_status_at=now()-'2 minutes'::interval WHERE id=$1`, msgID)
					require.NoError(t, err)
					require.NoError(t, h.App().Engine.Resume(context.Background()))
					h.Trigger()
					pauseStepOrganizationEngine(t, h)
					require.Positive(t, provider.polled.Load())
					provider.pollError.Store(false)
					_, err = h.App().DB().Exec(`UPDATE outgoing_messages SET last_status_at=now()-'2 minutes'::interval WHERE id=$1`, msgID)
					require.NoError(t, err)
					require.NoError(t, h.App().Engine.Resume(context.Background()))
					h.Trigger()
					pauseStepOrganizationEngine(t, h)
					// Callback bypasses Registry and must still sanitize persistence.
					err = h.App().Engine.SetSendResult(context.Background(), &notification.SendResult{ID: msgID, Status: notification.Status{State: notification.StateDelivered, Details: "callback to " + raw}})
					require.NoError(t, err)
				}
				var persisted string
				require.NoError(t, h.App().DB().QueryRow(`SELECT coalesce(string_agg(status_details,'|'),'') FROM message_status_history WHERE message_id=$1`, msgID).Scan(&persisted))
				require.NotContains(t, persisted, raw)
				for _, query := range []string{`{messageLogs{nodes{id destination status providerID retryCount createdAt updatedAt}}}`, `{debugMessages(input:{}){id destination status}}`, fmt.Sprintf(`{messageStatusHistory(id:%q){status details timestamp}}`, msgID)} {
					resp := c9Query(t, h, harness.DefaultGraphQLAdminUserID, query)
					require.Empty(t, resp.Errors)
					require.NotContains(t, string(resp.Data), raw)
				}
				// Provider validation and display errors are also real GraphQL
				// response/log paths, even on the owner's management surface.
				resp := c9Query(t, h, "user-a", fmt.Sprintf(`{userContactMethod(id:%q){formattedValue}}`, id))
				require.NotEmpty(t, resp.Errors)
				encoded, err := json.Marshal(resp)
				require.NoError(t, err)
				require.NotContains(t, string(encoded), raw)
				resp = c9Query(t, h, "user-a", fmt.Sprintf(`mutation{createUserContactMethod(input:{userID:%q,name:"invalid",private:%t,dest:{type:%q,args:{address:%q}}}){id}}`, h.UUID("user-a"), private, name, raw))
				require.NotEmpty(t, resp.Errors)
				encoded, err = json.Marshal(resp)
				require.NoError(t, err)
				require.NotContains(t, string(encoded), raw)
				trace := c9TraceExtensions(t, h, fmt.Sprintf(`{userContactMethod(id:%q){id dest{args}} messageStatusHistory(id:%q){status details}}`, id, msgID))
				require.NotContains(t, trace, raw)
			}
		}
	}
	// Exercise notification audit persistence with real Engine dispatch. An
	// empty EP keeps this fixture from adding unrelated recipient messages.
	_, org := c9HumanContext(t, h, "user-a")
	_, err := h.App().DB().Exec(`INSERT INTO escalation_policies(id,name,organization_id) VALUES($1,'C9 Audit',$2);`, h.UUID("c9-audit-ep"), org)
	require.NoError(t, err)
	_, err = h.App().DB().Exec(`INSERT INTO services(id,name,organization_id,escalation_policy_id) VALUES($1,'C9 Audit',$2,$3)`, h.UUID("c9-audit-svc"), org, h.UUID("c9-audit-ep"))
	require.NoError(t, err)
	var alertID int
	require.NoError(t, h.App().DB().QueryRow(`INSERT INTO alerts(service_id,summary,status,dedup_key) VALUES($1,'C9 audit fixture','triggered','auto:1:c9-audit') RETURNING id`, h.UUID("c9-audit-svc")).Scan(&alertID))
	provider := &c9DiagnosticProvider{id: "c9-audit-provider", raw: rawValues[0]}
	provider.attempts.Store(1)
	h.App().DestRegistry.RegisterProvider(context.Background(), provider)
	id := c9InsertCM(t, h, "c9-audit-cm", "user-a", provider.id, "address", provider.raw, true)
	msgID := h.UUID("c9-audit-message")
	_, err = h.App().DB().Exec(`INSERT INTO outgoing_messages(id,message_type,contact_method_id,user_id,alert_id,service_id,escalation_policy_id) VALUES($1,'alert_notification',$2,$3,$4,$5,$6)`, msgID, id, h.UUID("user-a"), alertID, h.UUID("c9-audit-svc"), h.UUID("c9-audit-ep"))
	require.NoError(t, err)
	require.NoError(t, h.App().Engine.Resume(context.Background()))
	h.Trigger()
	pauseStepOrganizationEngine(t, h)
	var audit string
	require.NoError(t, h.App().DB().QueryRow(`SELECT coalesce(string_agg(to_jsonb(l)::text,'|'),'') FROM alert_logs l WHERE alert_id=$1`, alertID).Scan(&audit))
	require.Contains(t, audit, msgID, "audit retains MessageID correlation")
	metrics, err := prometheus.DefaultGatherer.Gather()
	require.NoError(t, err)
	metricText := fmt.Sprint(metrics)
	require.Contains(t, metricText, "goalert_notification_sent_total")
	for _, raw := range rawValues {
		require.NotContains(t, capture.snapshot(), raw)
		require.NotContains(t, audit, raw)
		require.NotContains(t, metricText, raw)
	}
	require.Contains(t, capture.snapshot(), "CallbackID")
}
