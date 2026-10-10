package smoke

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/test/smoke/harness"
)

// Supplement the existing untrusted-provider diagnostic matrix with actual
// supported Webhook success/error paths. Reuse C9's authority/privacy framework.
func TestC9SupportedWebhookDiagnostics(t *testing.T) {
	capture := new(c9LogCapture)
	h := c9Harness(t, capture.attach)
	var attempts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		attempts.Add(1)
		if strings.HasPrefix(r.URL.Path, "/error/") {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	for _, private := range []bool{false, true} {
		for _, path := range []string{"/success", "/error"} {
			raw := fmt.Sprintf("%s%s/%t", srv.URL, path, private)
			id := c9InsertCM(t, h, fmt.Sprintf("supported-c9-%t-%s", private, path), "user-a", "builtin-webhook", "webhook_url", raw, private)
			before := attempts.Load()
			// Owner-only Test permission remains effective for either privacy flag.
			for _, actor := range []string{"c9-peer", harness.DefaultGraphQLAdminUserID, "user-other"} {
				require.NotEmpty(t, c9Query(t, h, actor, fmt.Sprintf(`mutation{testContactMethod(id:%q)}`, id)).Errors)
			}
			var count int
			require.NoError(t, h.App().DB().QueryRow(`SELECT count(*) FROM outgoing_messages WHERE contact_method_id=$1`, id).Scan(&count))
			require.Zero(t, count)
			require.Equal(t, before, attempts.Load())
			require.Empty(t, c9Query(t, h, "user-a", fmt.Sprintf(`mutation{testContactMethod(id:%q)}`, id)).Errors)
			var verifyError func()
			if path == "/error" {
				verifyError = h.ExpectBackendError("send message: webhook request failed: HTTP status 400")
			}
			require.NoError(t, h.App().Engine.Resume(t.Context()))
			h.Trigger()
			pauseStepOrganizationEngine(t, h)
			if verifyError != nil {
				verifyError()
			}
			require.Equal(t, before+1, attempts.Load(), "actual supported receiver observation")
			var messageID, status, details string
			require.NoError(t, h.App().DB().QueryRow(`SELECT id,last_status,status_details FROM outgoing_messages WHERE contact_method_id=$1`, id).Scan(&messageID, &status, &details))
			if path == "/success" {
				require.Equal(t, "sent", status)
			} else {
				require.Contains(t, details, "400", "real provider HTTP error must be retained safely")
				require.NotEqual(t, "sent", status)
			}
			var history string
			require.NoError(t, h.App().DB().QueryRow(`SELECT coalesce(string_agg(status_details,'|'),'') FROM message_status_history WHERE message_id=$1`, messageID).Scan(&history))
			for _, text := range []string{details, history, capture.snapshot(), c9TraceExtensions(t, h, fmt.Sprintf(`{messageStatusHistory(id:%q){status details}}`, messageID))} {
				require.NotContains(t, text, raw)
			}
			for _, query := range []string{`{messageLogs{nodes{id destination status}}}`, `{debugMessages(input:{}){id destination status}}`, fmt.Sprintf(`{messageStatusHistory(id:%q){status details}}`, messageID)} {
				response := c9Query(t, h, harness.DefaultGraphQLAdminUserID, query)
				require.Empty(t, response.Errors)
				require.NotContains(t, string(response.Data), raw)
			}
			metrics, err := prometheus.DefaultGatherer.Gather()
			require.NoError(t, err)
			require.NotContains(t, fmt.Sprint(metrics), raw)
		}
	}
}
