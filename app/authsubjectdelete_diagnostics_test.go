package app

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/graphql2/graphqlapp"
	"github.com/target/goalert/permission"
	"github.com/target/goalert/util/log"
)

func TestAuthSubjectDeleteEnclosingRequestLogRedaction(t *testing.T) {
	var out bytes.Buffer
	l := log.NewLogger()
	l.EnableDebug()
	l.SetOutput(&out)
	query := `{"query":"mutation{PRIVATE_ALIAS:deleteAuthSubject(input:{userID:\"` + uuid.NewString() + `\",providerID:\"PRIVATE_PROVIDER\",subjectID:\"PRIVATE_SUBJECT\"})}"}`
	req := httptest.NewRequest("POST", "/api/graphql?trace=1", strings.NewReader(query))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Referer", "https://synthetic.invalid/PRIVATE_REFERER")
	req = req.WithContext(log.WithLogger(req.Context(), l))
	graphqlHandler := new(graphqlapp.App).Handler()
	authenticated := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := permission.SystemContext(r.Context(), "Engine")
		ctx = permission.SourceContext(ctx, &permission.SourceInfo{Type: permission.SourceTypeAuthProvider, ID: "PRIVATE_AUTH_SOURCE"})
		logRequestAuth(graphqlHandler).ServeHTTP(w, r.WithContext(ctx))
	})
	logRequest(true)(authenticated).ServeHTTP(httptest.NewRecorder(), req)
	require.Contains(t, out.String(), "request complete")
	for _, private := range []string{"PRIVATE_", "AuthSource", "referer="} {
		if strings.Contains(out.String(), private) {
			t.Fatal("private diagnostic canary leaked (sample withheld)")
		}
	}
}

func TestAuthSubjectDeleteDiagnosticFallback(t *testing.T) {
	for _, query := range []string{
		`mutation SYNTHETIC_PRIVATE_OPERATION { SYNTHETIC_PRIVATE_ALIAS:`,
		`mutation SYNTHETIC_PRIVATE_OPERATION { SYNTHETIC_PRIVATE_ALIAS:unknownField }`,
		`mutation First { deleteAuthSubject(input:{userID:"SYNTHETIC_PRIVATE_UUID",providerID:"SYNTHETIC_PRIVATE_PROVIDER",subjectID:"SYNTHETIC_PRIVATE_SUBJECT"}) } mutation Second { __typename }`,
	} {
		t.Run(query[:8], func(t *testing.T) {
			var out bytes.Buffer
			l := log.NewLogger()
			l.EnableDebug()
			l.SetOutput(&out)
			body, err := json.Marshal(map[string]string{"query": query})
			require.NoError(t, err)
			req := httptest.NewRequest(http.MethodPost, "/api/graphql?trace=1", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Referer", "https://synthetic.invalid/SYNTHETIC_PRIVATE_REFERER")
			req = req.WithContext(log.WithLogger(permission.SystemContext(req.Context(), "Engine"), l))
			recorder := httptest.NewRecorder()
			logRequest(true)(logRequestAuth(new(graphqlapp.App).Handler())).ServeHTTP(recorder, req)
			require.Equal(t, http.StatusUnprocessableEntity, recorder.Code)
			require.Contains(t, recorder.Body.String(), `"errors"`)
			require.NotContains(t, recorder.Body.String(), `"tracing"`)
			require.Contains(t, out.String(), "request complete")
			require.Contains(t, out.String(), "graphql_closed_projection")
			if strings.Contains(out.String(), "SYNTHETIC_PRIVATE") {
				t.Fatal("fallback request log leaked; record withheld")
			}
		})
	}
}
