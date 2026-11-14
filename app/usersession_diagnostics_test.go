package app

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/target/goalert/graphql2/graphqlapp"
	"github.com/target/goalert/permission"
	"github.com/target/goalert/util/log"
)

func TestUserSessionEnclosingDiagnostics(t *testing.T) {
	for _, query := range []string{
		`mutation{SYNTHETIC_SESSION_ALIAS:endAllAuthSessionsByCurrentUser}`,
		`mutation{SYNTHETIC_SESSION_ALIAS:deleteAll(input:[{type:userSession,id:"SYNTHETIC_SESSION_SELECTOR"}])}`,
		`mutation SYNTHETIC_SESSION_OPERATION { SYNTHETIC_SESSION_ALIAS:`,
		`mutation{SYNTHETIC_SESSION_ALIAS:endAllAuthSessionsByCurrentUser(invalid:"SYNTHETIC_SESSION_INPUT")}`,
	} {
		t.Run("request", func(t *testing.T) {
			var out bytes.Buffer
			l := log.NewLogger()
			l.EnableDebug()
			l.SetOutput(&out)
			body, err := json.Marshal(map[string]any{"query": query})
			require.NoError(t, err)
			req := httptest.NewRequest(http.MethodPost, "/api/graphql?trace=1", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Referer", "https://synthetic.invalid/SYNTHETIC_SESSION_REFERER")
			req = req.WithContext(log.WithLogger(req.Context(), l))
			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				ctx := permission.SystemContext(r.Context(), "Engine")
				ctx = permission.SourceContext(ctx, &permission.SourceInfo{Type: permission.SourceTypeAuthProvider, ID: "SYNTHETIC_SESSION_SOURCE"})
				logRequestAuth(new(graphqlapp.App).Handler()).ServeHTTP(w, r.WithContext(ctx))
			})
			rec := httptest.NewRecorder()
			logRequest(true)(next).ServeHTTP(rec, req)
			require.Contains(t, out.String(), "request complete")
			require.Contains(t, out.String(), "graphql_closed_projection")
			require.False(t, strings.Contains(out.String(), "SYNTHETIC_SESSION"), "request diagnostics leaked (sample withheld)")
			require.NotContains(t, rec.Body.String(), `"tracing"`)
		})
	}
}
func TestUserSessionEnclosingPanicProjection(t *testing.T) {
	var out bytes.Buffer
	l := log.NewLogger()
	l.EnableDebug()
	l.EnableJSON()
	l.SetOutput(&out)
	body, _ := json.Marshal(map[string]string{"query": `mutation{endAllAuthSessionsByCurrentUser}`})
	req := httptest.NewRequest(http.MethodPost, "/api/graphql?trace=1", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Referer", "https://synthetic.invalid/SYNTHETIC_SESSION_REFERER")
	req = req.WithContext(log.WithLogger(permission.SystemContext(req.Context(), "Engine"), l))
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		new(graphqlapp.App).Handler().ServeHTTP(httptest.NewRecorder(), r)
		panic("SYNTHETIC_SESSION_PANIC")
	})
	rec := httptest.NewRecorder()
	logRequest(true)(next).ServeHTTP(rec, req)
	require.Equal(t, 500, rec.Code)
	require.False(t, strings.Contains(out.String(), "SYNTHETIC_SESSION"), "panic diagnostics leaked (sample withheld)")
	require.Contains(t, out.String(), "graphql_closed_projection")
}
