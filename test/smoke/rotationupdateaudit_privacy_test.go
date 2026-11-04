package smoke

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/app"
	"github.com/target/goalert/auth"
	"github.com/target/goalert/auth/authtoken"
	"github.com/target/goalert/test/smoke/harness"
)

// Uses the R1 probe's real signed-session HTTP path. Only locally issued test
// tokens are decoded; the server still verifies their signatures normally.
func TestRotationUpdateAuditSignedSourcePrivacy(t *testing.T) {
	h := harness.NewStoppedHarness(t, rotationUpdateAuditSQL, nil, "")
	t.Cleanup(h.Close)
	capture := new(serviceAuditCapture)
	h.StartWithAppCfgHook(func(c *app.Config) { c.LegacyLogger.Logrus().AddHook(capture) })
	pauseStepOrganizationEngine(t, h)
	token := h.GraphQLToken(h.UUID("user-a"))
	parsed, _, err := authtoken.Parse(token, nil)
	require.NoError(t, err)
	sessionID := parsed.ID.String()
	description := "SYNTHETIC_UNVERIFIED_DESCRIPTION_c2963a"
	destination := "synthetic.sourceprivacy@example.invalid"
	_, err = h.App().DB().Exec(`INSERT INTO user_contact_methods(id,user_id,name,type,value,private) VALUES($1,$2,'Synthetic privacy','EMAIL',$3,true)`, uuid.NewString(), h.UUID("user-a"), destination)
	require.NoError(t, err)
	_, err = h.App().DB().Exec(`INSERT INTO user_contact_methods(id,user_id,name,type,value,private) VALUES($1,$2,'Synthetic public privacy','EMAIL',$3,false)`, uuid.NewString(), h.UUID("user-a"), "synthetic.publicprivacy@example.invalid")
	require.NoError(t, err)
	responses := []string{}
	request := func(query string) string {
		t.Helper()
		body, err := json.Marshal(map[string]any{"query": query})
		require.NoError(t, err)
		req, err := http.NewRequest(http.MethodPost, h.URL()+"/api/graphql?trace=1", bytes.NewReader(body))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Synthetic-Token", "SYNTHETIC_HEADER_TOKEN_34fa")
		req.Header.Set("X-Synthetic-SourceInfo", "SYNTHETIC_HEADER_SOURCEINFO_34fa")
		req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: token})
		req.AddCookie(&http.Cookie{Name: "SyntheticCookie", Value: "SYNTHETIC_COOKIE_34fa"})
		r, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		data, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		require.NoError(t, r.Body.Close())
		responses = append(responses, string(data))
		return string(data)
	}
	ikSetAuthority(t, h, "ORG_MEMBER", true)
	response := request(fmt.Sprintf(`mutation{foreignAlias:updateRotation(input:{id:%q,description:%q})}`, h.UUID("rotation-a"), description))
	require.Contains(t, response, `"foreignAlias":true`)
	require.Contains(t, response, `"tracing"`, "exercise enabled response tracing")
	logText := capture.String()
	require.Contains(t, logText, `"MutationName":"updateRotation"`)
	require.Contains(t, logText, `"MutationResult":"success"`)
	require.Contains(t, logText, `"RequestID":`)
	require.NotContains(t, logText, `"MutationName":"foreignAlias"`)
	ikSetAuthority(t, h, "ORG_ADMIN", false)
	response = request(fmt.Sprintf(`mutation{homeAlias:updateRotation(input:{id:%q,description:%q})}`, h.UUID("rotation-a"), description))
	require.Contains(t, response, `"homeAlias":true`)
	response = request(fmt.Sprintf(`mutation{deniedAlias:updateRotation(input:{id:%q,description:%q})}`, h.UUID("rotation-b"), description))
	require.Contains(t, response, `"errors"`)
	response = request(fmt.Sprintf(`mutation{invalidAlias:updateRotation(input:{id:%q,name:"",description:%q})}`, h.UUID("rotation-a"), description))
	require.Contains(t, response, `"errors"`)
	response = request(fmt.Sprintf(`mutation{one:updateRotation(input:{id:%q,name:"Synthetic Name Sentinel"}) two:updateRotation(input:{id:%q,description:%q})}`, h.UUID("rotation-a"), h.UUID("rotation-c"), description))
	require.NotContains(t, response, `"errors"`)
	response = request(fmt.Sprintf(`mutation{tz:updateRotation(input:{id:%q,timeZone:"SYNTHETIC_TIMEZONE_SECRET"})}`, h.UUID("rotation-a")))
	require.Contains(t, response, `"errors"`)
	_, err = h.App().DB().Exec(`CREATE FUNCTION source_privacy_sql_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION USING ERRCODE='P0001',MESSAGE='SYNTHETIC_SQL_MESSAGE_34fa',DETAIL='SYNTHETIC_SQL_DETAIL_34fa'; END $$;
CREATE TRIGGER source_privacy_sql_failure BEFORE UPDATE ON rotations FOR EACH ROW EXECUTE FUNCTION source_privacy_sql_failure()`)
	require.NoError(t, err)
	wait := h.ExpectBackendError("rotation.update transaction failed")
	response = request(fmt.Sprintf(`mutation{sqlAlias:updateRotation(input:{id:%q,description:%q})}`, h.UUID("rotation-a"), description))
	wait()
	require.Contains(t, response, `"errors"`)
	_, err = h.App().DB().Exec(`DROP TRIGGER source_privacy_sql_failure ON rotations;
CREATE FUNCTION source_privacy_sink_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION USING MESSAGE='SYNTHETIC_SINK_SECRET_34fa',DETAIL='SYNTHETIC_SQL_DETAIL_34fa'; END $$;
CREATE TRIGGER source_privacy_sink_failure BEFORE INSERT ON schedule_rotation_update_audit_events FOR EACH ROW EXECUTE FUNCTION source_privacy_sink_failure()`)
	require.NoError(t, err)
	before := serviceManagementSnapshot(t, h)
	waitFault := h.ExpectBackendError("schedule/rotation update audit persistence unavailable")
	// This resolver returns a safe transaction error plus the explicit audit
	// persistence gap; the error presenter emits the same safe message.
	waitOperation := h.ExpectBackendError("rotation.update audit persistence unavailable")
	response = request(fmt.Sprintf(`mutation{sinkAlias:updateRotation(input:{id:%q,description:%q})}`, h.UUID("rotation-a"), description))
	waitFault()
	waitOperation()
	require.Contains(t, response, `"errors"`)
	require.Equal(t, before, serviceManagementSnapshot(t, h), "audit insert failure must roll back business write")
	require.Contains(t, capture.String(), `"AuditFault":"persistence_unavailable"`)
	_, err = h.App().DB().Exec(`DROP TRIGGER source_privacy_sink_failure ON schedule_rotation_update_audit_events`)
	require.NoError(t, err)
	rows := rotationAuditRows(t, h)
	outputs := append(responses, rows, capture.String())
	for _, sentinel := range []string{token, sessionID, "SourceTypeAuthProvider{" + sessionID + "}", "AuthSource=", "SYNTHETIC_HEADER_TOKEN_34fa", "SYNTHETIC_HEADER_SOURCEINFO_34fa", "SYNTHETIC_COOKIE_34fa", description, "Synthetic Name Sentinel", "SYNTHETIC_TIMEZONE_SECRET", destination, "synthetic.publicprivacy@example.invalid", "SYNTHETIC_SQL_MESSAGE_34fa", "SYNTHETIC_SQL_DETAIL_34fa", "SYNTHETIC_SINK_SECRET_34fa"} {
		for _, output := range outputs {
			require.NotContains(t, output, sentinel, "sensitive test-owned sentinel must not escape")
		}
	}
	// Alias text cannot opt an adjacent resolver into this policy. Its existing
	// business/authorization behavior remains in scope only as a negative control.
	response = request(fmt.Sprintf(`mutation{updateRotation:createSchedule(input:{name:"Adjacent source control",timeZone:%q}){id}}`, "Etc/UTC"))
	require.NotContains(t, response, `"errors"`)
	require.Contains(t, capture.String(), `"MutationName":"createSchedule"`)
	t.Logf("GREEN: signed HTTP PA Home, OrgAdmin home/deny, validation, SQL and sink failure; %d responses checked; actual schema operation survives alias", len(responses))
	require.NotContains(t, strings.Join(responses, ""), sessionID)
}
