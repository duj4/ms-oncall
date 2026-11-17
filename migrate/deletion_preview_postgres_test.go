package migrate

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/auth"
	"github.com/target/goalert/config"
	ds "github.com/target/goalert/deletionsafety"
	"github.com/target/goalert/executioncontext"
	"github.com/target/goalert/graphql2"
	"github.com/target/goalert/graphql2/graphqlapp"
	"github.com/target/goalert/organization"
	"github.com/target/goalert/permission"
)

type previewNoExternalTransport struct{ calls atomic.Int64 }

func (p *previewNoExternalTransport) RoundTrip(*http.Request) (*http.Response, error) {
	p.calls.Add(1)
	return nil, fmt.Errorf("unexpected external request")
}

type previewNativeSigner struct{}

func (previewNativeSigner) Sign(p []byte) ([]byte, error) {
	h := hmac.New(sha256.New, []byte("synthetic-preview-test-key"))
	_, _ = h.Write(p)
	return h.Sum(nil), nil
}
func (s previewNativeSigner) Verify(p, sig []byte) (bool, bool) {
	want, _ := s.Sign(p)
	return hmac.Equal(want, sig), false
}

func previewInput(typ graphql2.DeletionTargetType, id uuid.UUID) graphql2.DeletionPlanInput {
	return graphql2.DeletionPlanInput{Operation: graphql2.DeletionOperationDeleteResources, Targets: []graphql2.DeletionResourceInput{{Type: typ, ID: id.String()}}}
}

type previewNativeResponse struct {
	Data struct {
		Preview *graphql2.DeletionPreview `json:"deletionPreview"`
	} `json:"data"`
	Errors []struct {
		Message    string `json:"message"`
		Extensions struct {
			Code string `json:"code"`
		} `json:"extensions"`
	} `json:"errors"`
}

// Goes through JSON decoding, gqlgen, App.Handler, resolver and error presenter.
// App contains only a DB and in-memory signer: no provider, notification,
// channel-mapping or mutation Store is available to the Preview query.
func previewHTTP(t *testing.T, ctx context.Context, app *graphqlapp.App, input graphql2.DeletionPlanInput, first int, after *string) previewNativeResponse {
	t.Helper()
	body, err := json.Marshal(map[string]any{"query": `query($input:DeletionPlanInput!,$first:Int,$after:String){deletionPreview(input:$input,first:$first,after:$after){targets{type id name label organization{id name}} operation impactVersion policyVersion assessedAt complete canProceed requiresConfirmation notices impacts{edges{cursor node{edgeID target{type id name label} referencingResource{type id name label} parent{type id name label} relation change policy impact requiredAction canModifyReference isDerived isPlannedCoDeletion}} pageInfo{hasNextPage endCursor}}}}`, "variables": map[string]any{"input": input, "first": first, "after": after}})
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/graphql", bytes.NewReader(body)).WithContext((config.Config{}).Context(ctx))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	app.Handler().ServeHTTP(w, req)
	var response previewNativeResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))
	return response
}
func previewOK(t *testing.T, r previewNativeResponse) *graphql2.DeletionPreview {
	t.Helper()
	require.Empty(t, r.Errors)
	require.NotNil(t, r.Data.Preview)
	require.True(t, r.Data.Preview.Complete)
	return r.Data.Preview
}
func previewRejected(t *testing.T, r previewNativeResponse, code string) {
	t.Helper()
	require.Nil(t, r.Data.Preview)
	require.NotEmpty(t, r.Errors)
	require.Equal(t, code, r.Errors[0].Extensions.Code)
	require.NotContains(t, r.Errors[0].Message, "SYNTHETIC_PRIVATE")
}

func TestPostgresDeletionPreviewPoliciesPaginationAndReadOnly(t *testing.T) {
	ctx, uri, db := boundedAuditDB(t, len(Names()))
	f := newDeletionFixture(t, ctx, db)
	ctx = permission.SystemContext(ctx, "DeletionPreviewNativeTest")
	pgConfig, err := pgx.ParseConfig(uri)
	require.NoError(t, err)
	trace := &deletionReadTrace{}
	wrapped := sql.OpenDB(deletionReadConnector{Connector: stdlib.GetConnector(*pgConfig), trace: trace})
	wrapped.SetMaxOpenConns(1)
	defer wrapped.Close()
	app := &graphqlapp.App{DB: wrapped, PreviewSigner: previewNativeSigner{}}
	before := deletionSnapshot(t, ctx, db)
	outbound := &previewNoExternalTransport{}
	originalTransport := http.DefaultTransport
	http.DefaultTransport = outbound
	t.Cleanup(func() { http.DefaultTransport = originalTransport })
	policies := map[graphql2.DeletionPolicy]bool{}
	for _, tc := range []struct {
		typ     graphql2.DeletionTargetType
		id      uuid.UUID
		blocked bool
	}{
		{graphql2.DeletionTargetTypeService, f.service, true}, {graphql2.DeletionTargetTypeEscalationPolicy, f.policy, true}, {graphql2.DeletionTargetTypeSchedule, f.schedule, true},
		{graphql2.DeletionTargetTypeUser, f.user, true}, {graphql2.DeletionTargetTypeContactMethod, f.cm, false}, {graphql2.DeletionTargetTypeNotificationRule, f.nr, false},
		{graphql2.DeletionTargetTypeIntegrationKey, f.keyAudit, false}, {graphql2.DeletionTargetTypeUserOverride, f.override, false},
	} {
		t.Run(string(tc.typ), func(t *testing.T) {
			input := previewInput(tc.typ, tc.id)
			full := previewOK(t, previewHTTP(t, ctx, app, input, 100, nil))
			require.Equal(t, !tc.blocked, full.CanProceed)
			if tc.blocked {
				require.False(t, full.RequiresConfirmation)
			}
			require.NotZero(t, full.AssessedAt)
			require.Equal(t, ds.PolicyVersion, full.PolicyVersion)
			again := previewOK(t, previewHTTP(t, ctx, app, input, 100, nil))
			require.Equal(t, full.ImpactVersion, again.ImpactVersion)
			var after *string
			var seen []string
			for {
				page := previewOK(t, previewHTTP(t, ctx, app, input, 2, after))
				require.Equal(t, full.ImpactVersion, page.ImpactVersion)
				require.Equal(t, full.CanProceed, page.CanProceed)
				require.Equal(t, full.RequiresConfirmation, page.RequiresConfirmation)
				for _, edge := range page.Impacts.Edges {
					seen = append(seen, edge.Node.EdgeID)
					policies[edge.Node.Policy] = true
				}
				if !page.Impacts.PageInfo.HasNextPage {
					break
				}
				require.NotNil(t, page.Impacts.PageInfo.EndCursor)
				after = page.Impacts.PageInfo.EndCursor
			}
			var expected []string
			for _, edge := range full.Impacts.Edges {
				expected = append(expected, edge.Node.EdgeID)
			}
			require.Equal(t, expected, seen)
			require.True(t, slices.IsSorted(seen))
			raw, err := json.Marshal(full)
			require.NoError(t, err)
			for _, private := range []string{f.key.String(), f.session.String(), "SYNTHETIC_PRIVATE_ALERT", "SYNTHETIC_PRIVATE_SIGNAL", "SYNTHETIC_NOT_A_REAL_PASSWORD_HASH"} {
				require.NotContains(t, string(raw), private)
			}
			if tc.typ == graphql2.DeletionTargetTypeService {
				states := map[string]graphql2.DeletionPolicy{}
				for _, e := range full.Impacts.Edges {
					if e.Node.Relation == "SERVICE_ALERT" {
						states[e.Node.ReferencingResource.ID] = e.Node.Policy
					}
				}
				require.Equal(t, graphql2.DeletionPolicyCascade, states[fmt.Sprint(f.closed)])
				require.Equal(t, graphql2.DeletionPolicyBlock, states[fmt.Sprint(f.active)])
			}
			if tc.typ == graphql2.DeletionTargetTypeEscalationPolicy {
				paths := map[string]map[string]bool{}
				for _, e := range full.Impacts.Edges {
					n := e.Node
					if n.ReferencingResource.Type == "ESCALATION_POLICY_ACTION" {
						if paths[n.ReferencingResource.ID] == nil {
							paths[n.ReferencingResource.ID] = map[string]bool{}
						}
						paths[n.ReferencingResource.ID][n.Relation] = true
					}
				}
				found := false
				for _, relations := range paths {
					found = found || relations["POLICY_ACTION"] && relations["STEP_ACTION"]
				}
				require.True(t, found)
			}
		})
	}
	for _, p := range graphql2.AllDeletionPolicy {
		require.True(t, policies[p], string(p))
	}
	// Overlapping roots preserve co-deletion provenance and open-alert blockers.
	batch := previewInput(graphql2.DeletionTargetTypeService, f.service)
	batch.Targets = append(batch.Targets, graphql2.DeletionResourceInput{Type: graphql2.DeletionTargetTypeEscalationPolicy, ID: f.policy.String()})
	combined := previewOK(t, previewHTTP(t, ctx, app, batch, 100, nil))
	require.False(t, combined.CanProceed)
	coDeleted := false
	for _, edge := range combined.Impacts.Edges {
		coDeleted = coDeleted || edge.Node.IsPlannedCoDeletion
	}
	require.True(t, coDeleted)
	// The real populated closure is complete; its incoming references still block.
	populated := previewOK(t, previewHTTP(t, ctx, app, previewInput(graphql2.DeletionTargetTypeRotation, f.rotation), 50, nil))
	require.True(t, populated.Complete)
	require.False(t, populated.CanProceed)
	stateFound := false
	for _, edge := range populated.Impacts.Edges {
		if edge.Node.Relation == "ROTATION_STATE" {
			stateFound = true
			require.Equal(t, graphql2.DeletionPolicyCascade, edge.Node.Policy)
		}
	}
	require.True(t, stateFound)
	require.Equal(t, before, deletionSnapshot(t, ctx, db))
	require.Zero(t, outbound.calls.Load(), "Preview must not send external requests")
	require.Zero(t, wrapped.Stats().InUse)
	trace.mu.Lock()
	defer trace.mu.Unlock()
	require.Positive(t, trace.begins)
	require.Equal(t, trace.begins, trace.rollbacks)
	require.Zero(t, trace.commits)
	require.Zero(t, trace.writes)
	for _, query := range trace.queries {
		u := strings.ToUpper(strings.TrimSpace(query))
		require.True(t, strings.HasPrefix(u, "SELECT ") || strings.HasPrefix(u, "WITH "))
		for _, forbidden := range []string{"FOR UPDATE", "FOR SHARE", "FOR KEY SHARE", "FOR NO KEY UPDATE", "INSERT ", "UPDATE ", "DELETE ", "NEXTVAL", "SET_CONFIG"} {
			require.NotContains(t, u, forbidden)
		}
	}
}

func TestPostgresDeletionPreviewEmptyBatchAndBounds(t *testing.T) {
	ctx, _, db := boundedAuditDB(t, len(Names()))
	f := newDeletionFixture(t, ctx, db)
	ctx = permission.SystemContext(ctx, "DeletionPreviewNativeTest")
	app := &graphqlapp.App{DB: db, PreviewSigner: previewNativeSigner{}}
	empty := uuid.New()
	_, err := db.ExecContext(ctx, `INSERT INTO escalation_policies(id,organization_id,name) VALUES($1,$2,'empty policy')`, empty, f.org)
	require.NoError(t, err)
	input := previewInput(graphql2.DeletionTargetTypeEscalationPolicy, empty)
	p := previewOK(t, previewHTTP(t, ctx, app, input, 50, nil))
	require.Empty(t, p.Impacts.Edges)
	require.True(t, p.CanProceed)
	require.False(t, p.RequiresConfirmation)
	// Keep the real populated runtime intact throughout the Preview.
	// Missing State is an invalid closure, covered by the populated negative suite.
	rotationInput := previewInput(graphql2.DeletionTargetTypeRotation, f.rotation)
	p = previewOK(t, previewHTTP(t, ctx, app, rotationInput, 100, nil))
	require.False(t, p.CanProceed) // real incoming Schedule/EP references still block
	found := false
	for _, e := range p.Impacts.Edges {
		found = found || e.Node.Relation == "PARTICIPANT_USER"
	}
	require.True(t, found)
	batch := input
	batch.Targets = append(slices.Clone(batch.Targets), graphql2.DeletionResourceInput{Type: graphql2.DeletionTargetTypeIntegrationKey, ID: f.keyAudit.String()})
	p = previewOK(t, previewHTTP(t, ctx, app, batch, 100, nil))
	require.Len(t, p.Targets, 2)
	// Pure CASCADE and INFORMATIONAL cases have different confirmation behavior.
	_, err = db.ExecContext(ctx, `DELETE FROM escalation_policy_actions WHERE rotation_id=$1`, f.rotation)
	require.NoError(t, err)
	_, err = db.ExecContext(ctx, `DELETE FROM schedule_rules WHERE tgt_rotation_id=$1`, f.rotation)
	require.NoError(t, err)
	cascade := previewOK(t, previewHTTP(t, ctx, app, rotationInput, 100, nil))
	require.True(t, cascade.CanProceed)
	require.True(t, cascade.RequiresConfirmation)
	_, err = db.ExecContext(ctx, `UPDATE user_overrides SET start_time=$1,end_time=$2 WHERE id=$3`, f.now.Add(-2*time.Hour), f.now.Add(-time.Hour), f.override)
	require.NoError(t, err)
	informational := previewOK(t, previewHTTP(t, ctx, app, previewInput(graphql2.DeletionTargetTypeUserOverride, f.override), 100, nil))
	require.True(t, informational.CanProceed)
	require.False(t, informational.RequiresConfirmation)
	for _, edge := range informational.Impacts.Edges {
		require.Equal(t, graphql2.DeletionPolicyInformational, edge.Node.Policy)
	}
	warning := previewOK(t, previewHTTP(t, ctx, app, previewInput(graphql2.DeletionTargetTypeIntegrationKey, f.keyAudit), 100, nil))
	require.True(t, warning.CanProceed)
	require.True(t, warning.RequiresConfirmation)
	// Same selector set in another order has the same canonical domain version.
	slices.Reverse(batch.Targets)
	other := previewOK(t, previewHTTP(t, ctx, app, batch, 100, nil))
	require.Equal(t, p.ImpactVersion, other.ImpactVersion)
	// Display pagination cannot conceal an over-budget graph. This is only a
	// disposable fixture configuration; production limits are unchanged.
	_, err = db.ExecContext(ctx, `UPDATE config_limits SET max=-1 WHERE id='ep_steps_per_policy'`)
	require.NoError(t, err)
	_, err = db.ExecContext(ctx, `INSERT INTO escalation_policy_steps(id,escalation_policy_id,step_number) SELECT gen_random_uuid(),$1,n FROM generate_series(0,10000) n`, empty)
	require.NoError(t, err)
	previewRejected(t, previewHTTP(t, ctx, app, input, 1, nil), string(ds.DeletionPreviewLimitExceeded))
}

func TestPostgresDeletionPreviewMalformedAndIncomplete(t *testing.T) {
	ctx, uri, db := boundedAuditDB(t, len(Names()))
	f := newDeletionFixture(t, ctx, db)
	ctx = permission.SystemContext(ctx, "DeletionPreviewNativeTest")
	app := &graphqlapp.App{DB: db, PreviewSigner: previewNativeSigner{}}
	input := previewInput(graphql2.DeletionTargetTypeSchedule, f.schedule)
	for _, raw := range []string{`{"V1":{"TemporarySchedules":"SYNTHETIC_PRIVATE_MALFORMED","OnCallNotificationRules":[]}}`, fmt.Sprintf(`{"V1":{"TemporarySchedules":[{"Start":%q,"End":%q,"Shifts":[{"Start":%q,"End":%q,"UserID":%q}]}],"OnCallNotificationRules":[]}}`, f.now.Add(-time.Hour).Format(time.RFC3339), f.now.Add(time.Hour).Format(time.RFC3339), f.now.Add(-time.Hour).Format(time.RFC3339), f.now.Add(time.Hour).Format(time.RFC3339), uuid.NewString())} {
		_, err := db.ExecContext(ctx, `UPDATE schedule_data SET data=$1::jsonb WHERE schedule_id=$2`, raw, f.schedule)
		require.NoError(t, err)
		previewRejected(t, previewHTTP(t, ctx, app, input, 50, nil), string(ds.DeletionUnavailable))
	}
	setDeletionJSON(t, ctx, db, f, f.user.String(), f.now.Add(-time.Hour), f.now.Add(time.Hour))
	for _, stream := range []bool{false, true} {
		cfg, err := pgx.ParseConfig(uri)
		require.NoError(t, err)
		trace := &deletionReadTrace{failStream: stream}
		if !stream {
			trace.failQuery = 4
		}
		wrapped := sql.OpenDB(deletionReadConnector{Connector: stdlib.GetConnector(*cfg), trace: trace})
		app := &graphqlapp.App{DB: wrapped, PreviewSigner: previewNativeSigner{}}
		previewRejected(t, previewHTTP(t, ctx, app, input, 1, nil), string(ds.DeletionUnavailable))
		require.Zero(t, wrapped.Stats().InUse)
		require.NoError(t, wrapped.Close())
	}
	previewRejected(t, previewHTTP(t, ctx, app, previewInput(graphql2.DeletionTargetTypeIntegrationKey, f.key), 50, nil), string(ds.DeletionUnavailable))
	previewRejected(t, previewHTTP(t, ctx, app, previewInput(graphql2.DeletionTargetTypeService, uuid.New()), 50, nil), string(ds.DeletionUnavailable))
}

func previewAdmit(t *testing.T, ctx context.Context, db *sql.DB, id uuid.UUID) context.Context {
	t.Helper()
	var role permission.Role
	require.NoError(t, db.QueryRowContext(ctx, `SELECT role FROM users WHERE id=$1`, id).Scan(&role))
	session := uuid.NewString()
	ctx = permission.UserSourceContext(ctx, id.String(), role, &permission.SourceInfo{Type: permission.SourceTypeAuthProvider, ID: session})
	r, err := auth.NewRequester(id.String(), session)
	require.NoError(t, err)
	ctx = auth.WithRequester(ctx, r)
	constructor, err := executioncontext.NewHumanExecutionContextConstructor(organization.NewStore(db))
	require.NoError(t, err)
	ec, err := constructor.Construct(ctx)
	require.NoError(t, err)
	return executioncontext.WithExecutionContext(ctx, ec)
}

func TestPostgresDeletionPreviewHumanScopeAndVersions(t *testing.T) {
	ctx, _, db := boundedAuditDB(t, len(Names()))
	f := newDeletionFixture(t, ctx, db)
	app := &graphqlapp.App{DB: db, PreviewSigner: previewNativeSigner{}}
	member := previewAdmit(t, ctx, db, f.user)
	cm := previewInput(graphql2.DeletionTargetTypeContactMethod, f.cm)
	p := previewOK(t, previewHTTP(t, member, app, cm, 1, nil))
	require.True(t, p.CanProceed)
	require.True(t, p.RequiresConfirmation)
	require.NotNil(t, p.Impacts.PageInfo.EndCursor)
	cursor := p.Impacts.PageInfo.EndCursor
	fullCM := previewOK(t, previewHTTP(t, member, app, cm, 100, nil))
	canModify, readOnlyReference := false, false
	for _, edge := range fullCM.Impacts.Edges {
		canModify = canModify || edge.Node.CanModifyReference
		readOnlyReference = readOnlyReference || !edge.Node.CanModifyReference
	}
	require.True(t, canModify)
	require.True(t, readOnlyReference, "target ownership must not grant modification of every reference")
	// Reauthorize every reference before disclosing even a stale-version error.
	// An inconsistent peer identity/CM relationship must remain unavailable,
	// even when a formerly valid cursor would otherwise report a version change.
	var hiddenID int64
	require.NoError(t, db.QueryRowContext(ctx, `INSERT INTO auth_subjects(provider_id,subject_id,user_id,cm_id) VALUES('synthetic-peer',$1,$2,$3) RETURNING id`, uuid.NewString(), f.actor, f.cm).Scan(&hiddenID))
	previewRejected(t, previewHTTP(t, member, app, cm, 1, cursor), string(ds.DeletionUnavailable))
	previewRejected(t, previewHTTP(t, member, app, cm, 1, nil), string(ds.DeletionUnavailable))
	_, hiddenErr := db.ExecContext(ctx, `DELETE FROM auth_subjects WHERE id=$1`, hiddenID)
	require.NoError(t, hiddenErr)
	// A valid VerificationState belongs to the actual CM owner. Read its safe
	// identity via complete Collector facts, never its code or destination.
	verification := uuid.New()
	_, verifyErr := db.ExecContext(ctx, `INSERT INTO user_verification_codes(id,contact_method_id,code,expires_at) VALUES($1,$2,0,$3)`, verification, f.cm, f.now.Add(time.Hour))
	require.NoError(t, verifyErr)
	ownVerification := previewOK(t, previewHTTP(t, member, app, cm, 100, nil))
	foundVerification := false
	for _, edge := range ownVerification.Impacts.Edges {
		if edge.Node.Relation == "VERIFICATION" {
			require.Equal(t, verification.String(), edge.Node.ReferencingResource.ID)
			foundVerification = true
		}
	}
	require.True(t, foundVerification)
	previewRejected(t, previewHTTP(t, member, app, cm, 1, cursor), string(ds.DeletionDependencyChanged))
	_, verifyErr = db.ExecContext(ctx, `DELETE FROM user_verification_codes WHERE id=$1`, verification)
	require.NoError(t, verifyErr)
	invalid := "invalid-cursor"
	previewRejected(t, previewHTTP(t, member, app, cm, 1, &invalid), string(ds.DeletionUnavailable))
	// A validly signed cursor from an older policy must be rejected as stale.
	payload, _, _ := strings.Cut(*cursor, ".")
	data, err := base64.RawURLEncoding.DecodeString(payload)
	require.NoError(t, err)
	var older map[string]string
	require.NoError(t, json.Unmarshal(data, &older))
	older["policy"] = "older-policy"
	data, err = json.Marshal(older)
	require.NoError(t, err)
	sig, err := (previewNativeSigner{}).Sign(append([]byte("goalert.deletion-preview.v1\x00"), data...))
	require.NoError(t, err)
	stale := base64.RawURLEncoding.EncodeToString(data) + "." + base64.RawURLEncoding.EncodeToString(sig)
	previewRejected(t, previewHTTP(t, member, app, cm, 1, &stale), string(ds.DeletionDependencyChanged))
	// OrgMember can edit own contact configuration, not another member's or roots.
	actor := previewAdmit(t, ctx, db, f.actor)
	previewRejected(t, previewHTTP(t, actor, app, cm, 1, nil), string(ds.DeletionUnavailable))
	previewRejected(t, previewHTTP(t, actor, app, previewInput(graphql2.DeletionTargetTypeEscalationPolicy, f.policy), 1, nil), string(ds.DeletionUnavailable))
	_, err = db.ExecContext(ctx, `UPDATE user_organization_assignments SET organization_role='ORG_ADMIN' WHERE user_id=$1`, f.actor)
	require.NoError(t, err)
	admin := previewAdmit(t, ctx, db, f.actor)
	policy := previewInput(graphql2.DeletionTargetTypeEscalationPolicy, f.policy)
	a := previewOK(t, previewHTTP(t, admin, app, policy, 1, nil))
	require.False(t, a.CanProceed)
	previewRejected(t, previewHTTP(t, admin, app, cm, 1, nil), string(ds.DeletionUnavailable)) // OrgAdmin is not CM owner/global admin
	// A scope/role change changes the original canonical ImpactVersion.
	_, err = db.ExecContext(ctx, `UPDATE user_organization_assignments SET organization_role='ORG_ADMIN' WHERE user_id=$1`, f.user)
	require.NoError(t, err)
	elevated := previewAdmit(t, ctx, db, f.user)
	changed := previewOK(t, previewHTTP(t, elevated, app, cm, 1, nil))
	require.NotEqual(t, p.ImpactVersion, changed.ImpactVersion)
	previewRejected(t, previewHTTP(t, elevated, app, cm, 1, cursor), string(ds.DeletionUnavailable))
	// A different authorized actor cannot reuse another actor's cursor.
	_, err = db.ExecContext(ctx, `UPDATE users SET role='admin' WHERE id=$1`, f.actor)
	require.NoError(t, err)
	pa := previewAdmit(t, ctx, db, f.actor)
	previewOK(t, previewHTTP(t, pa, app, cm, 1, nil))
	previewRejected(t, previewHTTP(t, pa, app, cm, 1, changed.Impacts.PageInfo.EndCursor), string(ds.DeletionUnavailable))
	// Changed dependencies invalidate all subsequent pages, even at equal counts.
	freshAdmin := previewAdmit(t, ctx, db, f.user)
	baseline := previewOK(t, previewHTTP(t, freshAdmin, app, policy, 1, nil))
	policyCursor := baseline.Impacts.PageInfo.EndCursor
	action := uuid.New()
	_, err = db.ExecContext(ctx, `INSERT INTO escalation_policy_actions(id,escalation_policy_step_id,user_id) VALUES($1,$2,$3)`, action, f.step, f.actor)
	require.NoError(t, err)
	added := previewOK(t, previewHTTP(t, freshAdmin, app, policy, 100, nil))
	require.NotEqual(t, baseline.ImpactVersion, added.ImpactVersion)
	previewRejected(t, previewHTTP(t, freshAdmin, app, policy, 1, policyCursor), string(ds.DeletionDependencyChanged))
	_, err = db.ExecContext(ctx, `DELETE FROM escalation_policy_actions WHERE id=$1`, action)
	require.NoError(t, err)
	removed := previewOK(t, previewHTTP(t, freshAdmin, app, policy, 100, nil))
	require.Equal(t, baseline.ImpactVersion, removed.ImpactVersion)
	require.NotEqual(t, added.ImpactVersion, removed.ImpactVersion)
	var old uuid.UUID
	require.NoError(t, db.QueryRowContext(ctx, `SELECT id FROM escalation_policy_actions WHERE escalation_policy_step_id=$1 AND user_id=$2`, f.step, f.user).Scan(&old))
	_, err = db.ExecContext(ctx, `DELETE FROM escalation_policy_actions WHERE id=$1`, old)
	require.NoError(t, err)
	_, err = db.ExecContext(ctx, `INSERT INTO escalation_policy_actions(id,escalation_policy_step_id,user_id) VALUES($1,$2,$3)`, uuid.New(), f.step, f.user)
	require.NoError(t, err)
	replaced := previewOK(t, previewHTTP(t, freshAdmin, app, policy, 100, nil))
	require.NotEqual(t, removed.ImpactVersion, replaced.ImpactVersion)
	require.Len(t, replaced.Impacts.Edges, len(removed.Impacts.Edges))
	// Foreign selectors and even same-Home references to a foreign root fail closed.
	foreign := newDeletionFixture(t, ctx, db)
	denied := previewHTTP(t, freshAdmin, app, previewInput(graphql2.DeletionTargetTypeEscalationPolicy, foreign.policy), 1, nil)
	previewRejected(t, denied, string(ds.DeletionUnavailable))
	raw, err := json.Marshal(denied)
	require.NoError(t, err)
	require.NotContains(t, string(raw), foreign.policy.String())
	require.NotContains(t, string(raw), foreign.org.String())
	_, err = db.ExecContext(ctx, `UPDATE user_organization_assignments SET organization_role='ORG_ADMIN' WHERE user_id=$1`, foreign.actor)
	require.NoError(t, err)
	foreignAdmin := previewAdmit(t, ctx, db, foreign.actor)
	previewOK(t, previewHTTP(t, foreignAdmin, app, previewInput(graphql2.DeletionTargetTypeEscalationPolicy, foreign.policy), 1, nil))
	previewRejected(t, previewHTTP(t, foreignAdmin, app, previewInput(graphql2.DeletionTargetTypeEscalationPolicy, foreign.policy), 1, policyCursor), string(ds.DeletionUnavailable))
	_, err = db.ExecContext(ctx, `INSERT INTO escalation_policy_actions(escalation_policy_step_id,user_id) VALUES($1,$2)`, foreign.step, f.user)
	require.NoError(t, err)
	// User is now a platform admin so deletion eligibility itself does not hide the foreign-reference check.
	_, err = db.ExecContext(ctx, `UPDATE users SET role='admin' WHERE id=$1`, f.user)
	require.NoError(t, err)
	previewRejected(t, previewHTTP(t, previewAdmit(t, ctx, db, f.user), app, previewInput(graphql2.DeletionTargetTypeUser, f.user), 1, nil), string(ds.DeletionUnavailable))
	// Cursor body contains digests and safe position only, never manifest or authority IDs.
	payload, _, _ = strings.Cut(*cursor, ".")
	decoded, err := base64.RawURLEncoding.DecodeString(payload)
	require.NoError(t, err)
	for _, id := range []uuid.UUID{f.user, f.org, f.cm, f.key} {
		require.NotContains(t, string(decoded), id.String())
	}
}
