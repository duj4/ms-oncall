package app

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/apikey"
	"github.com/target/goalert/auth"
	"github.com/target/goalert/executioncontext"
	"github.com/target/goalert/expflag"
	"github.com/target/goalert/gadb"
	"github.com/target/goalert/graphql2"
	"github.com/target/goalert/notification/nfydest"
	"github.com/target/goalert/permission"
	"github.com/target/goalert/validation"
)

// Use the existing API-only disposable-DB fixture to observe the complete
// enqueue state without an Engine concurrently consuming it. Provider delivery
// and Signal/River processing are covered by the sendSignal smoke tests.
type sendSignalOrganizationRuntime struct {
	*calendarPolicyRuntime
	services [2]string
	orgs     [2]string
	provider *sendSignalOrganizationProvider
}

type sendSignalOrganizationProvider struct{ calls atomic.Int64 }

func (*sendSignalOrganizationProvider) ID() string { return "c6-test-signal" }
func (p *sendSignalOrganizationProvider) TypeInfo(context.Context) (*nfydest.TypeInfo, error) {
	p.calls.Add(1)
	return &nfydest.TypeInfo{Enabled: true, SupportsSignals: true, RequiredFields: []nfydest.FieldConfig{{FieldID: "target"}}}, nil
}
func (p *sendSignalOrganizationProvider) ValidateField(_ context.Context, _, value string) error {
	p.calls.Add(1)
	if value == "" {
		return validation.NewGenericError("test target is required")
	}
	return nil
}
func (p *sendSignalOrganizationProvider) DisplayInfo(_ context.Context, args map[string]string) (*nfydest.DisplayInfo, error) {
	p.calls.Add(1)
	return &nfydest.DisplayInfo{Text: "C6 " + args["target"]}, nil
}

func newSendSignalOrganizationRuntime(t *testing.T) *sendSignalOrganizationRuntime {
	t.Helper()
	h := &sendSignalOrganizationRuntime{calendarPolicyRuntime: newCalendarPolicyRuntime(t), provider: new(sendSignalOrganizationProvider)}
	h.stop()
	h.cfg.ExpFlags = expflag.FlagSet{expflag.UnivKeys}
	h.start()
	h.app.DestRegistry.RegisterProvider(context.Background(), h.provider)
	for i, userID := range h.users {
		require.NoError(t, h.pool.QueryRow(context.Background(), `SELECT effective_normal_organization_id FROM user_organization_assignments WHERE user_id=$1`, userID).Scan(&h.orgs[i]))
		ep := uuid.NewString()
		h.services[i] = uuid.NewString()
		_, err := h.pool.Exec(context.Background(), `INSERT INTO escalation_policies(id,name,organization_id) VALUES($1,$2,$3)`, ep, fmt.Sprintf("C6 Policy %d", i), h.orgs[i])
		require.NoError(t, err)
		_, err = h.pool.Exec(context.Background(), `INSERT INTO services(id,name,escalation_policy_id,organization_id) VALUES($1,$2,$3,$4)`, h.services[i], fmt.Sprintf("C6 Service %d", i), ep, h.orgs[i])
		require.NoError(t, err)
	}
	var count int
	require.NoError(t, h.pool.QueryRow(context.Background(), `SELECT count(*) FROM gorp_migrations`).Scan(&count))
	require.Equal(t, 289, count)
	var database string
	require.NoError(t, h.pool.QueryRow(context.Background(), `SELECT current_database()`).Scan(&database))
	t.Logf("C6 disposable database: %s; canonical migrations=%d", database, count)
	return h
}

func sendSignalOrganizationQuery(serviceID, target, params string) string {
	return fmt.Sprintf(`mutation{sendSignal(input:{serviceID:%q,dest:{type:"c6-test-signal",args:{target:%q}},params:%s})}`, serviceID, target, params)
}

type sendSignalOrganizationState struct {
	Channels, Signals, Jobs, Outgoing string
	ProviderCalls                     int64
}

func (h *sendSignalOrganizationRuntime) state(t *testing.T) sendSignalOrganizationState {
	t.Helper()
	var s sendSignalOrganizationState
	// Observe full rows plus xmin, rather than counts alone: an upsert into an
	// existing destination must also be detectable, even if its name is equal.
	for _, item := range []struct {
		table, where string
		value        *string
	}{
		{"notification_channels", "", &s.Channels},
		{"pending_signals", "", &s.Signals},
		{"river_job", "WHERE queue='engine-signal-mgr'", &s.Jobs},
		{"outgoing_messages", "", &s.Outgoing},
	} {
		q := `SELECT COALESCE(jsonb_agg(to_jsonb(r) || jsonb_build_object('row_version',r.xmin::text) ORDER BY r.id)::text,'[]') FROM ` + item.table + ` r ` + item.where
		require.NoError(t, h.pool.QueryRow(context.Background(), q).Scan(item.value))
	}
	s.ProviderCalls = h.provider.calls.Load()
	return s
}

func TestSendSignalOrganizationHumanRuntime(t *testing.T) {
	h := newSendSignalOrganizationRuntime(t)
	for _, test := range []struct {
		name, who, service string
	}{
		{"Org A member", h.users[0], h.services[0]},
		{"Org B member", h.users[1], h.services[1]},
		{"Org A human Admin", h.admin, h.services[0]},
	} {
		t.Run(test.name, func(t *testing.T) {
			before := h.state(t)
			r := h.query(test.who, sendSignalOrganizationQuery(test.service, test.name, `{message:"C6 message",color:"warning"}`))
			require.Empty(t, r.Errors)
			require.JSONEq(t, `true`, string(r.Data["sendSignal"]))
			after := h.state(t)
			require.NotEqual(t, before.Channels, after.Channels)
			for _, rows := range []struct{ before, after string }{{before.Signals, after.Signals}, {before.Jobs, after.Jobs}} {
				var beforeRows, afterRows []json.RawMessage
				require.NoError(t, json.Unmarshal([]byte(rows.before), &beforeRows))
				require.NoError(t, json.Unmarshal([]byte(rows.after), &afterRows))
				require.Len(t, afterRows, len(beforeRows)+1, "each admitted mutation queues exactly one Signal and its River job")
			}
			var params string
			require.NoError(t, h.pool.QueryRow(context.Background(), `SELECT params::text FROM pending_signals WHERE service_id=$1 ORDER BY id DESC LIMIT 1`, test.service).Scan(&params))
			require.JSONEq(t, `{"message":"C6 message","color":"warning"}`, params)
		})
	}

	// An existing destination with an intentionally stale name proves denial
	// cannot even run the update half of NotifChanUpsertDest.
	_, err := h.pool.Exec(context.Background(), `UPDATE notification_channels SET name='C6 stale destination name' WHERE dest->'Args'->>'target'='Org A member'`)
	require.NoError(t, err)
	for _, test := range []struct {
		name, who, service, target string
	}{
		{"Org A knows exact Org B UUID", h.users[0], h.services[1], "foreign-new"},
		{"Org B knows exact Org A UUID", h.users[1], h.services[0], "foreign-new"},
		{"human Admin has no global bypass", h.admin, h.services[1], "foreign-new"},
		{"foreign existing destination", h.users[0], h.services[1], "Org A member"},
		{"missing Service", h.users[0], uuid.NewString(), "missing-new"},
		{"foreign Service precedes invalid destination", h.users[0], h.services[1], ""},
		{"missing Service precedes invalid destination", h.users[0], uuid.NewString(), ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			before := h.state(t)
			r := h.query(test.who, sendSignalOrganizationQuery(test.service, test.target, `{message:"denied"}`))
			require.Len(t, r.Errors, 1)
			require.Equal(t, "unexpected error", r.Errors[0].Message)
			require.Equal(t, before, h.state(t), "denial must not validate/display a destination, upsert a channel, insert a signal, enqueue a River job, or schedule delivery")
		})
	}

	t.Run("same Org invalid destination preserves validation", func(t *testing.T) {
		before := h.state(t)
		r := h.query(h.users[0], sendSignalOrganizationQuery(h.services[0], "", `{message:"invalid destination"}`))
		require.Len(t, r.Errors, 1)
		require.Equal(t, "test target is required", r.Errors[0].Message)
		after := h.state(t)
		require.Greater(t, after.ProviderCalls, before.ProviderCalls)
		after.ProviderCalls = before.ProviderCalls
		require.Equal(t, before, after)
	})
	for name, query := range map[string]string{
		"malformed ServiceID": sendSignalOrganizationQuery("invalid-service-id", "valid", `{message:"invalid ID"}`),
		"invalid params":      sendSignalOrganizationQuery(h.services[0], "valid", `{message:{invalid:"nested value"}}`),
	} {
		t.Run(name, func(t *testing.T) {
			before := h.state(t)
			r := h.query(h.users[0], query)
			require.NotEmpty(t, r.Errors)
			require.Equal(t, before, h.state(t), "existing input validation remains before side effects")
		})
	}
}

func (h *sendSignalOrganizationRuntime) humanContext(t *testing.T, userID string, role permission.Role) context.Context {
	t.Helper()
	sessionID := uuid.NewString()
	ctx := permission.UserSourceContext(context.Background(), userID, role, &permission.SourceInfo{Type: permission.SourceTypeAuthProvider, ID: sessionID})
	requester, err := auth.NewRequester(userID, sessionID)
	require.NoError(t, err)
	ctx = auth.WithRequester(ctx, requester)
	constructor, err := executioncontext.NewHumanExecutionContextConstructor(h.app.OrganizationStore)
	require.NoError(t, err)
	authority, err := constructor.Construct(ctx)
	require.NoError(t, err)
	return executioncontext.WithExecutionContext(expflag.Context(ctx, expflag.FlagSet{expflag.UnivKeys}), authority)
}

func TestSendSignalOrganizationMissingAuthorityRuntime(t *testing.T) {
	h := newSendSignalOrganizationRuntime(t)
	ctx := h.humanContext(t, h.users[0], permission.RoleUser)
	requester := auth.RequesterFromContext(ctx)
	source := permission.Source(ctx)
	withoutAuthority := auth.WithRequester(permission.UserSourceContext(context.Background(), h.users[0], permission.RoleUser, source), *requester)
	otherSession := h.humanContext(t, h.users[0], permission.RoleUser)
	otherPrincipal := h.humanContext(t, h.users[1], permission.RoleUser)
	contexts := map[string]context.Context{
		"missing Requester":              permission.UserSourceContext(context.Background(), h.users[0], permission.RoleUser, source),
		"missing ExecutionContext":       withoutAuthority,
		"invalid ExecutionContext":       executioncontext.WithExecutionContext(withoutAuthority, executioncontext.ExecutionContext{}),
		"principal mismatch":             executioncontext.WithExecutionContext(ctx, *executioncontext.ExecutionContextFromContext(otherPrincipal)),
		"authentication source mismatch": executioncontext.WithExecutionContext(ctx, *executioncontext.ExecutionContextFromContext(otherSession)),
		"Requester source mismatch":      permission.SourceContext(ctx, &permission.SourceInfo{Type: permission.SourceTypeGQLAPIKey, ID: uuid.NewString()}),
	}
	for name, ctx := range contexts {
		t.Run(name, func(t *testing.T) {
			before := h.state(t)
			ok, err := h.app.graphql2.Mutation().SendSignal(expflag.Context(ctx, expflag.FlagSet{expflag.UnivKeys}), graphql2.SendSignalInput{
				ServiceID: h.services[0], Dest: &gadb.DestV1{Type: h.provider.ID(), Args: map[string]string{"target": "missing-authority"}},
			})
			require.False(t, ok)
			require.True(t, permission.IsPermissionError(err), "%v", err)
			require.Equal(t, before, h.state(t))
		})
	}

	// The live HTTP admission seam leaves missing/Default durable human
	// authority unavailable; GraphQL then fails closed before either write.
	for _, assignment := range []string{"missing", "Default"} {
		t.Run(assignment+" HTTP admission", func(t *testing.T) {
			tx, err := h.pool.Begin(context.Background())
			require.NoError(t, err)
			defer func() { _ = tx.Rollback(context.Background()) }()
			// Create a separate test User with unavailable admission authority.
			userID := uuid.NewString()
			_, err = tx.Exec(context.Background(), `INSERT INTO users(id,name,email,role) VALUES($1,'C6 unavailable human','','user')`, userID)
			require.NoError(t, err)
			if assignment == "Default" {
				_, err = tx.Exec(context.Background(), `INSERT INTO user_organization_assignments(user_id,effective_organization_id,effective_organization_classification,organization_role,mapping_outcome,authoritative_evaluated_at,source_config_version,matched_count) SELECT $1,id,'DEFAULT','NONE','ZERO',now(),'c6-test',0 FROM organizations WHERE classification='DEFAULT'`, userID)
				require.NoError(t, err)
			}
			require.NoError(t, tx.Commit(context.Background()))
			before := h.state(t)
			payload, err := json.Marshal(map[string]string{"query": sendSignalOrganizationQuery(h.services[0], "admission-denied", `{message:"denied"}`)})
			require.NoError(t, err)
			code, body := h.request(userID, http.MethodPost, "/api/graphql", "application/json", payload)
			require.Equal(t, http.StatusOK, code)
			var result calendarGraphQLResult
			require.NoError(t, json.Unmarshal(body, &result))
			require.Len(t, result.Errors, 1)
			require.Equal(t, "access denied: normal Organization scoped authority is required", result.Errors[0].Message)
			require.Equal(t, before, h.state(t))
		})
	}
}

func TestSendSignalOrganizationBeforePostgresSideEffectLocks(t *testing.T) {
	h := newSendSignalOrganizationRuntime(t)
	r := h.query(h.users[0], sendSignalOrganizationQuery(h.services[0], "locked-existing", `{message:"setup"}`))
	require.Empty(t, r.Errors)
	var destID string
	require.NoError(t, h.pool.QueryRow(context.Background(), `SELECT id FROM notification_channels WHERE dest->'Args'->>'target'='locked-existing'`).Scan(&destID))
	before := h.state(t)
	ctx := h.humanContext(t, h.users[0], permission.RoleUser)
	tx, err := h.app.DB().BeginTx(context.Background(), nil)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback() }()
	_, err = tx.Exec(`LOCK TABLE notification_channels, pending_signals, river_job IN ACCESS EXCLUSIVE MODE`)
	require.NoError(t, err)
	for _, q := range []string{
		`UPDATE notification_channels SET name='control' WHERE id=$1`,
		`INSERT INTO pending_signals(dest_id,service_id,params) VALUES($1,$2,'{}')`,
	} {
		probe, err := h.app.DB().BeginTx(context.Background(), nil)
		require.NoError(t, err)
		_, err = probe.Exec(`SET LOCAL lock_timeout='100ms'`)
		require.NoError(t, err)
		args := []any{destID}
		if q[0] == 'I' {
			args = append(args, h.services[0])
		}
		_, err = probe.Exec(q, args...)
		var pgErr *pgconn.PgError
		require.ErrorAs(t, err, &pgErr)
		require.Equal(t, "55P03", pgErr.Code, "the control really conflicts with the side-effect lock")
		require.NoError(t, probe.Rollback())
	}
	for _, serviceID := range []string{h.services[1], uuid.NewString()} {
		bounded, cancel := context.WithTimeout(ctx, time.Second)
		ok, err := h.app.graphql2.Mutation().SendSignal(bounded, graphql2.SendSignalInput{ServiceID: serviceID, Dest: &gadb.DestV1{Type: h.provider.ID(), Args: map[string]string{"target": "locked-existing"}}})
		cancel()
		require.False(t, ok)
		require.EqualError(t, err, "sql: no rows in result set", "authorization must return without touching either locked side-effect table")
	}
	missing := permission.UserSourceContext(expflag.Context(context.Background(), expflag.FlagSet{expflag.UnivKeys}), h.users[0], permission.RoleUser, permission.Source(ctx))
	ok, err := h.app.graphql2.Mutation().SendSignal(missing, graphql2.SendSignalInput{ServiceID: h.services[0]})
	require.False(t, ok)
	require.True(t, permission.IsPermissionError(err))
	// Also exercise the real cookie-authenticated HTTP/GraphQL path while all
	// destination, enqueue, and job tables remain locked.
	r = h.query(h.users[0], sendSignalOrganizationQuery(h.services[1], "locked-existing", `{message:"denied"}`))
	require.Len(t, r.Errors, 1)
	require.Equal(t, "unexpected error", r.Errors[0].Message)
	require.NoError(t, tx.Rollback())
	require.Equal(t, before, h.state(t))
}

func TestSendSignalOrganizationRequestBoundAndNonHumanCompatibility(t *testing.T) {
	h := newSendSignalOrganizationRuntime(t)
	ctx := h.humanContext(t, h.users[0], permission.RoleUser)
	_, err := h.pool.Exec(context.Background(), `UPDATE user_organization_assignments SET effective_organization_id=$2,effective_normal_organization_id=$2 WHERE user_id=$1`, h.users[0], h.orgs[1])
	require.NoError(t, err)
	// A conflicting assignment-table lock proves the resolver/Service lookup
	// do not rediscover authority after finite-request admission.
	tx, err := h.app.DB().BeginTx(context.Background(), nil)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback() }()
	_, err = tx.Exec(`LOCK TABLE user_organization_assignments IN ACCESS EXCLUSIVE MODE`)
	require.NoError(t, err)
	bounded, cancel := context.WithTimeout(ctx, time.Second)
	ok, err := h.app.graphql2.Mutation().SendSignal(bounded, graphql2.SendSignalInput{ServiceID: h.services[0], Dest: &gadb.DestV1{Type: h.provider.ID(), Args: map[string]string{"target": "admitted-Org-A"}}})
	cancel()
	require.NoError(t, err)
	require.True(t, ok)
	require.NoError(t, tx.Rollback())
	before := h.state(t)
	r := h.query(h.users[0], sendSignalOrganizationQuery(h.services[0], "subsequent-Org-B-denied", `{message:"denied"}`))
	require.Len(t, r.Errors, 1)
	require.Equal(t, "unexpected error", r.Errors[0].Message)
	require.Equal(t, before, h.state(t))
	r = h.query(h.users[0], sendSignalOrganizationQuery(h.services[1], "subsequent-Org-B", `{message:"allowed"}`))
	require.Empty(t, r.Errors)

	// Exercise the actual existing API-key HTTP route; credentials are created
	// only in this disposable DB, held in memory, and never logged.
	query := `mutation($input:SendSignalInput!){sendSignal(input:$input)}`
	_, token, err := h.app.APIKeyStore.CreateAdminGraphQLKey(permission.UserContext(context.Background(), h.admin, permission.RoleAdmin), apikey.NewAdminGQLKeyOpts{Name: "C6 test key", Role: permission.RoleUser, Query: query, Expires: time.Now().Add(time.Hour)})
	require.NoError(t, err)
	for i, serviceID := range h.services {
		payload, err := json.Marshal(map[string]any{"query": query, "variables": map[string]any{"input": map[string]any{"serviceID": serviceID, "dest": map[string]any{"type": h.provider.ID(), "args": map[string]string{"target": fmt.Sprintf("api-key-%d", i)}}, "params": map[string]string{"message": "compatibility"}}}})
		require.NoError(t, err)
		req, err := http.NewRequest(http.MethodPost, h.app.URL()+"/api/graphql", bytes.NewReader(payload))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)
		code, body := h.do(req)
		require.Equal(t, http.StatusOK, code)
		var result calendarGraphQLResult
		require.NoError(t, json.Unmarshal(body, &result))
		require.Empty(t, result.Errors)
		require.JSONEq(t, `true`, string(result.Data["sendSignal"]))
	}
	for i, serviceID := range h.services {
		ctx := expflag.Context(permission.SystemContext(context.Background(), "C6Test"), expflag.FlagSet{expflag.UnivKeys})
		ok, err := h.app.graphql2.Mutation().SendSignal(ctx, graphql2.SendSignalInput{ServiceID: serviceID, Dest: &gadb.DestV1{Type: h.provider.ID(), Args: map[string]string{"target": fmt.Sprintf("system-%d", i)}}})
		require.NoError(t, err)
		require.True(t, ok)
	}
}
