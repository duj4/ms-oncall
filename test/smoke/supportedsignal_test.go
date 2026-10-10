package smoke

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/riverqueue/river"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/engine/signalmgr"
	"github.com/target/goalert/expflag"
	"github.com/target/goalert/gadb"
	"github.com/target/goalert/graphql2"
	"github.com/target/goalert/graphql2/graphqlapp"
	"github.com/target/goalert/permission"
	"github.com/target/goalert/test/smoke/harness"
)

// Queueing and scheduling are generic Signal contracts. The Engine's message
// dispatcher stays paused: ordinary queued Webhook Signal delivery is unsupported.
func TestSupportedSignalAdmissionAndQueue(t *testing.T) {
	r := newSupportedWebhookReceiver(t)
	fixture := stepParentOrganizationSQL + `
		INSERT INTO services(id,name,escalation_policy_id,organization_id) VALUES
			({{uuid "svc-a"}},'Signal local',{{uuid "policy-a"}},{{smokeOrganizationID}}),
			({{uuid "svc-other"}},'Signal foreign',{{uuid "policy-b"}},{{uuid "org-b"}});
	`
	h := harness.NewHarnessWithFlags(t, fixture, "", expflag.FlagSet{expflag.UnivKeys})
	defer h.Close()
	pauseStepOrganizationEngine(t, h)
	h.GraphQLToken(harness.DefaultGraphQLAdminUserID)
	snapshot := func() string {
		t.Helper()
		var state string
		require.NoError(t, h.App().DB().QueryRow(`SELECT jsonb_build_object(
			'channels',(SELECT coalesce(jsonb_agg(to_jsonb(c)||jsonb_build_object('row_version',c.xmin::text) ORDER BY c.id),'[]') FROM notification_channels c),
			'signals',(SELECT coalesce(jsonb_agg(to_jsonb(s) ORDER BY s.id),'[]') FROM pending_signals s),
			'jobs',(SELECT coalesce(jsonb_agg(to_jsonb(j) ORDER BY j.id),'[]') FROM river_job j WHERE queue='engine-signal-mgr'),
			'outgoing',(SELECT coalesce(jsonb_agg(to_jsonb(o) ORDER BY o.id),'[]') FROM outgoing_messages o))::text`).Scan(&state))
		return state
	}
	query := func(service, dest string) *harness.QLResponse {
		return h.GraphQLQuery2(fmt.Sprintf(`mutation{sendSignal(input:{serviceID:%q,dest:{type:"builtin-webhook",args:{webhook_url:%q}},params:{body:"queued body",content_type:"text/plain"}})}`, service, dest))
	}
	for _, service := range []string{h.UUID("svc-other"), h.UUID("missing-service")} {
		before := snapshot()
		verifyError := h.ExpectBackendError("sendSignal sql: no rows in result set")
		require.NotEmpty(t, query(service, r.URL+"/queued").Errors)
		verifyError()
		require.Equal(t, before, snapshot(), "foreign/missing Service must cause exact zero state change")
	}
	before := snapshot()
	require.NotEmpty(t, query(h.UUID("svc-a"), "relative-url").Errors)
	require.Equal(t, before, snapshot(), "invalid destination must not create a channel or signal")
	ctx := permission.UserSourceContext(t.Context(), harness.DefaultGraphQLAdminUserID, permission.RoleAdmin,
		&permission.SourceInfo{Type: permission.SourceTypeAuthProvider, ID: uuid.NewString()})
	app := graphqlapp.App{DB: h.App().DB(), ServiceStore: h.App().ServiceStore, NCStore: h.App().NCStore}
	ok, err := app.Mutation().SendSignal(expflag.Context(ctx, expflag.FlagSet{expflag.UnivKeys}), graphql2.SendSignalInput{
		ServiceID: h.UUID("svc-a"), Dest: &gadb.DestV1{Type: "builtin-webhook", Args: map[string]string{"webhook_url": r.URL + "/queued"}},
	})
	require.False(t, ok)
	require.True(t, permission.IsPermissionError(err))
	require.Equal(t, before, snapshot(), "User role without finite human authority is insufficient")
	for range 2 {
		response := query(h.UUID("svc-a"), r.URL+"/queued")
		require.Empty(t, response.Errors)
		require.JSONEq(t, `{"sendSignal":true}`, string(response.Data))
	}
	var signals, channels int
	require.NoError(t, h.App().DB().QueryRow(`SELECT count(*),count(DISTINCT dest_id) FROM pending_signals WHERE service_id=$1 AND message_id IS NULL`, h.UUID("svc-a")).Scan(&signals, &channels))
	require.Equal(t, 2, signals)
	require.Equal(t, 1, channels, "same destination maps to one channel")
	var params string
	require.NoError(t, h.App().DB().QueryRow(`SELECT params::text FROM pending_signals WHERE service_id=$1 LIMIT 1`, h.UUID("svc-a")).Scan(&params))
	require.JSONEq(t, `{"body":"queued body","content_type":"text/plain"}`, params)

	// Run the existing SignalManager River worker without running the Engine
	// message dispatcher. No mock provider or new delivery capability is involved.
	require.NoError(t, h.App().River.Start(t.Context()))
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		require.NoError(t, h.App().River.Stop(ctx))
	}()
	for range 2 {
		job, err := h.App().River.Insert(t.Context(), signalmgr.SchedMsgsArgs{ServiceID: uuid.NullUUID{UUID: uuid.MustParse(h.UUID("svc-a")), Valid: true}}, &river.InsertOpts{Queue: signalmgr.QueueName})
		require.NoError(t, err)
		require.Eventually(t, func() bool {
			var completed bool
			err := h.App().DB().QueryRow(`SELECT state='completed' FROM river_job WHERE id=$1`, job.Job.ID).Scan(&completed)
			return err == nil && completed
		}, 10*time.Second, 10*time.Millisecond)
	}
	var outgoing, scheduled, unscheduled int
	require.NoError(t, h.App().DB().QueryRow(`SELECT count(*) FROM outgoing_messages WHERE service_id=$1 AND message_type='signal_message' AND last_status='pending'`, h.UUID("svc-a")).Scan(&outgoing))
	require.NoError(t, h.App().DB().QueryRow(`SELECT count(*) FILTER(WHERE message_id IS NOT NULL),count(*) FILTER(WHERE message_id IS NULL) FROM pending_signals WHERE service_id=$1`, h.UUID("svc-a")).Scan(&scheduled, &unscheduled))
	require.Equal(t, 1, outgoing, "only one pending outgoing Signal per Service/destination")
	require.Equal(t, 1, scheduled)
	require.Equal(t, 1, unscheduled)
	require.Empty(t, r.events(""), "queue evidence is not Webhook delivery evidence")
}

// Preserve the already existing synchronous UIK Webhook path independently of
// the Slack/Twilio branches in TestSignal. Do not freeze the known content_type
// versus content-type discrepancy as a desired header contract.
func TestSupportedUIKSynchronousWebhook(t *testing.T) {
	var receipts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/direct", r.URL.Path)
		body, err := io.ReadAll(r.Body)
		assert.NoError(t, err)
		assert.Equal(t, "direct webhook body", string(body))
		receipts.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	h := harness.NewHarnessWithFlags(t, signalTestSQL, "", expflag.FlagSet{expflag.UnivKeys})
	defer h.Close()
	pauseStepOrganizationEngine(t, h)
	response := h.GraphQLQuery2(fmt.Sprintf(`mutation{createIntegrationKey(input:{name:"supported UIK",type:universal,serviceID:%q}){id href}}`, h.UUID("svc")))
	require.Empty(t, response.Errors)
	var key struct{ CreateIntegrationKey struct{ ID, Href string } }
	require.NoError(t, json.Unmarshal(response.Data, &key))
	config := fmt.Sprintf(`mutation{updateKeyConfig(input:{keyID:%q,defaultActions:[{dest:{type:"builtin-webhook",args:{webhook_url:%q}},params:{body:"req.body['body']"}}]})}`, key.CreateIntegrationKey.ID, srv.URL+"/direct")
	require.Empty(t, h.GraphQLQuery2(config).Errors)
	snapshot := func() string {
		t.Helper()
		var state string
		require.NoError(t, h.App().DB().QueryRow(`SELECT jsonb_build_object(
			'config',(SELECT to_jsonb(c) FROM uik_config c WHERE id=$1),
			'channels',(SELECT coalesce(jsonb_agg(to_jsonb(c)||jsonb_build_object('row_version',c.xmin::text) ORDER BY c.id),'[]') FROM notification_channels c),
			'signals',(SELECT coalesce(jsonb_agg(to_jsonb(s) ORDER BY s.id),'[]') FROM pending_signals s))::text`, key.CreateIntegrationKey.ID).Scan(&state))
		return state
	}
	before := snapshot()
	for _, invalid := range []string{
		strings.Replace(config, `body:"req.body['body']"`, `body:"("`, 1),
		strings.Replace(config, `body:"req.body['body']"`, `unknown:"'unexpected'"`, 1),
	} {
		require.NotEmpty(t, h.GraphQLQuery2(invalid).Errors)
		require.Equal(t, before, snapshot(), "invalid action parameters must not alter config, destinations or pending signals")
	}
	require.Zero(t, receipts.Load())
	response = h.GraphQLQuery2(fmt.Sprintf(`mutation{generateKeyToken(id:%q)}`, key.CreateIntegrationKey.ID))
	require.Empty(t, response.Errors)
	var token struct{ GenerateKeyToken string }
	require.NoError(t, json.Unmarshal(response.Data, &token))
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, key.CreateIntegrationKey.Href, strings.NewReader(`{"body":"direct webhook body"}`))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token.GenerateKeyToken)
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusNoContent, resp.StatusCode)
	require.Equal(t, int32(1), receipts.Load())
	var queued int
	require.NoError(t, h.App().DB().QueryRow(`SELECT count(*) FROM pending_signals`).Scan(&queued))
	require.Zero(t, queued, "synchronous direct delivery must not masquerade as queued Signal")
}
