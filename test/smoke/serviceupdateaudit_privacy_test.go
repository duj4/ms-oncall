package smoke

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/app"
	"github.com/target/goalert/auth"
	"github.com/target/goalert/test/smoke/harness"
)

type serviceAuditCapture struct {
	mx      sync.Mutex
	records []string
}

func (*serviceAuditCapture) Levels() []logrus.Level { return logrus.AllLevels }
func (c *serviceAuditCapture) Fire(e *logrus.Entry) error {
	b, err := e.String()
	if err != nil {
		return err
	}
	c.mx.Lock()
	defer c.mx.Unlock()
	c.records = append(c.records, b)
	return nil
}
func (c *serviceAuditCapture) String() string {
	c.mx.Lock()
	defer c.mx.Unlock()
	return strings.Join(c.records, "")
}

func serviceAuditHTTP(t *testing.T, h *harness.Harness, query, header string) string {
	t.Helper()
	b, err := json.Marshal(map[string]any{"query": query})
	require.NoError(t, err)
	req, err := http.NewRequest(http.MethodPost, h.URL()+"/api/graphql?trace=1", bytes.NewReader(b))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Synthetic-Secret", header)
	req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: h.GraphQLToken(h.UUID("user-a"))})
	r, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer r.Body.Close()
	data, err := io.ReadAll(r.Body)
	require.NoError(t, err)
	return string(data)
}

func TestServiceUpdateAuditPrivacyAndResolverBoundary(t *testing.T) {
	h := harness.NewStoppedHarness(t, servicePlatformAdminSQL, nil, "")
	t.Cleanup(h.Close)
	capture := new(serviceAuditCapture)
	h.StartWithAppCfgHook(func(c *app.Config) { c.LegacyLogger.Logrus().AddHook(capture) })
	pauseStepOrganizationEngine(t, h)
	ikSetAuthority(t, h, "ORG_MEMBER", true)
	secret := "SYNTHETIC_AUDIT_TOKEN_467e9ff0"
	description := "SYNTHETIC_AUDIT_DESCRIPTION_66720e6f"
	for _, private := range []bool{true, false} {
		value := fmt.Sprintf("synthetic.audit.%t@example.invalid", private)
		_, err := h.App().DB().Exec(`INSERT INTO user_contact_methods(id,user_id,name,type,value,private) VALUES($1,$2,'Synthetic privacy','EMAIL',$3,$4)`, uuid.NewString(), h.UUID("user-a"), value, private)
		require.NoError(t, err)
	}
	r := serviceAuditHTTP(t, h, fmt.Sprintf(`mutation{updateService(input:{id:%q,name:"Synthetic Safe Name",description:%q})}`, h.UUID("service-b"), description), secret)
	require.Contains(t, r, `"updateService":true`)
	require.Contains(t, r, `"tracing"`, "exercise enabled production response tracing")
	validation := serviceAuditHTTP(t, h, fmt.Sprintf(`mutation{updateService(input:{id:%q,name:"",description:%q})}`, h.UUID("service-b"), description), secret)
	require.Contains(t, validation, `"errors"`)
	// Exercise raw DB diagnostics on the same real signed-session path.
	_, err := h.App().DB().Exec(`CREATE FUNCTION audit_privacy_sql_error() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'SYNTHETIC_SQL_SECRET_3d1832c9'; END $$;
CREATE TRIGGER audit_privacy_sql_error BEFORE UPDATE ON services FOR EACH ROW EXECUTE FUNCTION audit_privacy_sql_error()`)
	require.NoError(t, err)
	wait := h.ExpectBackendError("service.update transaction failed")
	failure := serviceAuditHTTP(t, h, fmt.Sprintf(`mutation{updateService(input:{id:%q,description:%q})}`, h.UUID("service-b"), description), secret)
	wait()
	require.Contains(t, failure, `"errors"`)
	_, err = h.App().DB().Exec(`DROP TRIGGER audit_privacy_sql_error ON services`)
	require.NoError(t, err)
	credentialLikeID := uuid.NewString()
	waitMissing := h.ExpectBackendError("sql: no rows in result set")
	missing := serviceAuditHTTP(t, h, fmt.Sprintf(`mutation{updateService(input:{id:%q,description:%q})}`, credentialLikeID, description), secret)
	waitMissing()
	require.Contains(t, missing, `"errors"`)
	rows := serviceAuditRows(t, h)
	metrics, err := prometheus.DefaultGatherer.Gather()
	require.NoError(t, err)
	metricBytes, err := json.Marshal(metrics)
	require.NoError(t, err)
	for _, sentinel := range []string{secret, credentialLikeID, description, "Synthetic Safe Name", "synthetic.audit.true@example.invalid", "synthetic.audit.false@example.invalid", "SYNTHETIC_SQL_SECRET_3d1832c9"} {
		for _, output := range []string{rows, r, validation, failure, missing, capture.String(), string(metricBytes)} {
			require.NotContains(t, output, sentinel)
		}
	}
	before := serviceAuditCount(t, h)
	beforeBusiness := serviceManagementSnapshot(t, h)
	for _, q := range []string{`mutation{updateService(input:{name:"missing ID"})}`, `mutation{updateService(input:{id:123,maintenanceExpiresAt:"invalid timestamp"})}`, `mutation{unknownField}`} {
		response := serviceAuditHTTP(t, h, q, secret)
		require.Contains(t, response, `"errors"`)
	}
	require.Equal(t, before, serviceAuditCount(t, h), "parse/coercion failures do not enter the resolver")
	require.Equal(t, beforeBusiness, serviceManagementSnapshot(t, h))
	unauthBody, err := json.Marshal(map[string]any{"query": fmt.Sprintf(`mutation{updateService(input:{id:%q,description:"must not reach resolver"})}`, h.UUID("service-b"))})
	require.NoError(t, err)
	unauth, err := http.NewRequest(http.MethodPost, h.URL()+"/api/graphql", bytes.NewReader(unauthBody))
	require.NoError(t, err)
	unauth.Header.Set("Content-Type", "application/json")
	unauth.Header.Set("Authorization", "Bearer SYNTHETIC_INVALID_CREDENTIAL")
	unauthResponse, err := http.DefaultClient.Do(unauth)
	require.NoError(t, err)
	_, err = io.Copy(io.Discard, unauthResponse.Body)
	require.NoError(t, err)
	require.NoError(t, unauthResponse.Body.Close())
	require.Equal(t, http.StatusBadRequest, unauthResponse.StatusCode, "malformed Bearer format is rejected before resolver admission")
	require.Equal(t, before, serviceAuditCount(t, h))
	require.Equal(t, beforeBusiness, serviceManagementSnapshot(t, h))
	other := stepOrganizationQuery(t, h, fmt.Sprintf(`mutation{createService(input:{name:"Adjacent Existing Capability",escalationPolicyID:%q}){id}}`, h.UUID("policy-a")))
	require.Empty(t, other.Errors)
	require.Equal(t, before, serviceAuditCount(t, h), "other Service CRUD remains outside audit coverage")
	serviceManagementEvidence(t, "audit-privacy-result", map[string]any{"sentinel_checks": "PASS", "private_values": 2, "production_tracing": true, "application_log_records": strings.Count(capture.String(), "\n"), "resolver_boundary": "parse/coercion excluded; adjacent create unchanged"})
}
