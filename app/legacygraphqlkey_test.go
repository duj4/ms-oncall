package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/apikey"
	"github.com/target/goalert/auth"
	"github.com/target/goalert/expflag"
	"github.com/target/goalert/gadb"
	"github.com/target/goalert/graphql2"
	"github.com/target/goalert/integrationkey"
	"github.com/target/goalert/permission"
)

const legacySignalQuery = `mutation($input:SendSignalInput!){sendSignal(input:$input)}`

// insertLegacyGraphQLKey is test-only historical issuance. It constructs exact
// persisted policy/hash/signature evidence without reopening production issuance.
func insertLegacyGraphQLKey(t *testing.T, h *calendarPolicyRuntime, policy apikey.GQLPolicy, expires time.Time, revoked bool) (uuid.UUID, string) {
	t.Helper()
	id := uuid.New()
	data, err := json.Marshal(policy)
	require.NoError(t, err)
	_, err = h.pool.Exec(context.Background(), `INSERT INTO gql_api_keys(id,name,description,policy,expires_at) VALUES($1,$2,'test only',$3,$4)`, id, "Historical "+id.String(), data, expires)
	require.NoError(t, err)
	if revoked {
		_, err = h.pool.Exec(context.Background(), `UPDATE gql_api_keys SET deleted_at=now() WHERE id=$1`, id)
		require.NoError(t, err)
	}
	hash := sha256.Sum256(data)
	token, err := h.app.APIKeyring.SignJWT(apikey.NewGraphQLClaims(id, hash[:], expires))
	if err != nil {
		t.Fatal("historical fixture signing failed")
	}
	if time.Until(expires) > 0 {
		var claims apikey.Claims
		_, err = h.app.APIKeyring.VerifyJWT(token, &claims, apikey.Issuer, apikey.Audience)
		if err != nil || !bytes.Equal(claims.PolicyHash, hash[:]) || claims.Subject != id.String() {
			t.Fatal("historical fixture signature/hash precondition failed")
		}
	}
	var stored []byte
	require.NoError(t, h.pool.QueryRow(context.Background(), `SELECT policy FROM gql_api_keys WHERE id=$1`, id).Scan(&stored))
	require.JSONEq(t, string(data), string(stored))
	return id, token
}

func legacyKeyRows(t *testing.T, h *calendarPolicyRuntime) [2]string {
	t.Helper()
	var rows [2]string
	for i, table := range []string{"gql_api_keys", "gql_api_key_usage"} {
		order := "id"
		if table == "gql_api_key_usage" {
			order = "api_key_id"
		}
		require.NoError(t, h.pool.QueryRow(context.Background(), `SELECT coalesce(jsonb_agg(to_jsonb(r) || jsonb_build_object('xmin',r.xmin::text) ORDER BY r.`+order+`)::text,'[]') FROM `+table+` r`).Scan(&rows[i]))
	}
	return rows
}

func TestLegacyGraphQLStorePostgreSQL(t *testing.T) {
	h := newSendSignalOrganizationRuntime(t)
	before := legacyKeyRows(t, h.calendarPolicyRuntime)
	for name, ctx := range map[string]context.Context{
		"human admin":    h.humanContext(t, h.admin, permission.RoleAdmin),
		"system":         permission.SystemContext(context.Background(), "LegacyRetirementTest"),
		"legacy machine": permission.UserSourceContext(context.Background(), "", permission.RoleAdmin, &permission.SourceInfo{Type: permission.SourceTypeGQLAPIKey, ID: uuid.NewString()}),
	} {
		t.Run("issuance/"+name, func(t *testing.T) {
			for _, role := range []permission.Role{permission.RoleAdmin, permission.RoleUser} {
				id, token, err := h.app.APIKeyStore.CreateAdminGraphQLKey(ctx, apikey.NewAdminGQLKeyOpts{Name: "Retired", Query: legacySignalQuery, Role: role, Expires: time.Now().Add(time.Hour)})
				require.True(t, permission.IsPermissionError(err))
				if id != uuid.Nil || token != "" {
					t.Fatal("issuance returned ID/token")
				}
			}
			require.Equal(t, before, legacyKeyRows(t, h.calendarPolicyRuntime), "issuance mutated key/policy/usage rows")
		})
	}
	for _, role := range []permission.Role{permission.RoleAdmin, permission.RoleUser} {
		for _, test := range []struct {
			name                           string
			version                        int
			expired, revoked, hashMismatch bool
		}{
			{"valid-v1", 1, false, false, false}, {"version-zero", 0, false, false, false},
			{"unknown-version", 999, false, false, false}, {"expired", 1, true, false, false},
			{"revoked", 1, false, true, false}, {"hash-mismatch", 1, false, false, true},
		} {
			t.Run(string(role)+"/"+test.name, func(t *testing.T) {
				expires := time.Now().Add(time.Hour)
				if test.expired {
					expires = time.Now().Add(-time.Hour)
				}
				id, token := insertLegacyGraphQLKey(t, h.calendarPolicyRuntime, apikey.GQLPolicy{Version: test.version, Role: role, Query: legacySignalQuery}, expires, test.revoked)
				if !test.expired && !test.revoked {
					valid, err := gadb.New(h.app.DB()).APIKeyAuthCheck(context.Background(), id)
					require.NoError(t, err)
					require.True(t, valid, "real persisted legacy validity precondition")
				}
				if test.hashMismatch {
					_, err := h.pool.Exec(context.Background(), `UPDATE gql_api_keys SET policy=jsonb_set(policy::jsonb,'{Query}','"query { user { id } }"')::json WHERE id=$1`, id)
					require.NoError(t, err)
				}
				before := legacyKeyRows(t, h.calendarPolicyRuntime)
				for _, raw := range []string{token, token + "bad-signature", "malformed", ""} {
					ctx := context.Background()
					got, err := h.app.APIKeyStore.AuthorizeGraphQL(ctx, raw, "test", "127.0.0.1")
					require.True(t, permission.IsUnauthorized(err))
					require.True(t, ctx == got)
					if permission.All(got) || permission.Admin(got) || permission.System(got) || auth.RequesterFromContext(got) != nil || apikey.PolicyFromContext(got) != nil || permission.Source(got) != nil {
						t.Fatal("authentication added authority")
					}
					if strings.Contains(err.Error(), raw) && raw != "" {
						t.Fatal("error leaked credential")
					}
				}
				require.Equal(t, before, legacyKeyRows(t, h.calendarPolicyRuntime), "denial changed persisted key/usage")
			})
		}
	}
}

func legacyHTTPRequest(t *testing.T, endpoint, carrier, token, query, service string) *http.Request {
	t.Helper()
	payload, err := json.Marshal(map[string]any{"query": query, "variables": map[string]any{"input": map[string]any{"serviceID": service, "dest": map[string]any{"type": "c6-test-signal", "args": map[string]string{"target": "must-not-execute"}}}}})
	require.NoError(t, err)
	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(payload))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	switch {
	case carrier == "bearer":
		req.Header.Set("Authorization", "Bearer "+token)
	case carrier == "basic":
		req.SetBasicAuth("synthetic", token)
	case strings.HasPrefix(carrier, "query/"):
		q := req.URL.Query()
		q.Set(strings.TrimPrefix(carrier, "query/"), token)
		req.URL.RawQuery = q.Encode()
	case strings.HasPrefix(carrier, "form/"):
		form := url.Values{strings.TrimPrefix(carrier, "form/"): {token}, "query": {query}}
		req, err = http.NewRequest(http.MethodPost, endpoint, strings.NewReader(form.Encode()))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	case carrier == "multipart":
		var buf bytes.Buffer
		w := multipart.NewWriter(&buf)
		require.NoError(t, w.WriteField("token", token))
		require.NoError(t, w.WriteField("query", query))
		require.NoError(t, w.Close())
		req, err = http.NewRequest(http.MethodPost, endpoint, &buf)
		require.NoError(t, err)
		req.Header.Set("Content-Type", w.FormDataContentType())
	default:
		t.Fatal("unknown test carrier")
	}
	return req
}

func TestLegacyGraphQLHTTPRetirement(t *testing.T) {
	h := newSendSignalOrganizationRuntime(t)
	session, err := h.app.AuthHandler.CreateSession(context.Background(), "legacy-retirement-test", h.admin)
	require.NoError(t, err)
	human, err := session.Encode(h.app.SessionKeyring.Sign)
	if err != nil {
		t.Fatal("session fixture signing failed")
	}
	for _, prefix := range []string{"", "/security-test"} {
		if prefix != "" {
			h.stop()
			h.cfg.HTTPPrefix = prefix
			h.start()
			h.app.DestRegistry.RegisterProvider(context.Background(), h.provider)
		}
		for _, role := range []permission.Role{permission.RoleAdmin, permission.RoleUser} {
			_, token := insertLegacyGraphQLKey(t, h.calendarPolicyRuntime, apikey.GQLPolicy{Version: 1, Role: role, Query: legacySignalQuery}, time.Now().Add(time.Hour), false)
			before := h.state(t)
			for _, path := range []string{"/api/graphql", "/v1/graphql2"} {
				for _, carrier := range []string{"bearer", "basic", "query/token", "query/integrationKey", "query/integration_key", "query/key", "form/token", "form/integrationKey", "form/integration_key", "form/key", "multipart"} {
					t.Run(prefix+"/"+string(role)+path+"/"+carrier, func(t *testing.T) {
						req := legacyHTTPRequest(t, h.app.URL()+prefix+path, carrier, token, legacySignalQuery, h.services[0])
						// Even a valid Human cookie cannot rescue an explicit old JWT.
						req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: human})
						code, body := h.do(req)
						want := http.StatusUnauthorized
						if path == "/v1/graphql2" || carrier == "basic" {
							want = http.StatusBadRequest
						}
						require.Equal(t, want, code)
						if bytes.Contains(body, []byte(token)) || bytes.Contains(body, []byte(human)) {
							t.Fatal("credential leaked in response")
						}
						require.Equal(t, before, h.state(t), "unauthenticated request reached business side effects")
						// Real auth handler + Store: count admission to the next handler
						// independently of the network response and GraphQL error format.
						next := false
						probe := legacyHTTPRequest(t, "http://example.test"+path, carrier, token, legacySignalQuery, h.services[0])
						probe.AddCookie(&http.Cookie{Name: auth.CookieName, Value: human})
						w := httptest.NewRecorder()
						h.app.AuthHandler.WrapHandler(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { next = true })).ServeHTTP(w, probe)
						require.Equal(t, want, w.Code)
						require.False(t, next, "GraphQL/business handler admitted")
						t.Logf("status=%d; auth denial; next/business handler admitted=false", code)
					})
				}
			}
			for _, query := range []string{"", legacySignalQuery, "query { user { id } }"} {
				req := legacyHTTPRequest(t, h.app.URL()+prefix+"/api/graphql", "bearer", token, query, h.services[0])
				code, _ := h.do(req)
				require.Equal(t, http.StatusUnauthorized, code)
			}
			for _, cookieName := range []string{auth.CookieName, "goalert_session"} {
				req := legacyHTTPRequest(t, h.app.URL()+prefix+"/api/graphql", "bearer", "", legacySignalQuery, h.services[0])
				req.Header.Del("Authorization")
				req.AddCookie(&http.Cookie{Name: cookieName, Value: token})
				code, body := h.do(req)
				require.Equal(t, http.StatusUnauthorized, code)
				if bytes.Contains(body, []byte(token)) {
					t.Fatal("cookie credential leaked")
				}
				require.Equal(t, before, h.state(t))
				var admittedAuth bool
				w := httptest.NewRecorder()
				probe := httptest.NewRequest(http.MethodPost, "http://example.test/api/graphql", nil)
				probe.AddCookie(&http.Cookie{Name: cookieName, Value: token})
				h.app.AuthHandler.WrapHandler(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
					admittedAuth = permission.All(r.Context()) || auth.RequesterFromContext(r.Context()) != nil
				})).ServeHTTP(w, probe)
				require.False(t, admittedAuth)
				t.Log("legacy JWT cookie: HTTP 401 GraphQL admission denial; no authenticated principal or business effects")
			}
		}
		// Signed Human tokens retain both cookie and explicit-token paths.
		for _, path := range []string{"/api/graphql", "/v1/graphql2"} {
			for _, cookie := range []bool{true, false} {
				req := legacyHTTPRequest(t, h.app.URL()+prefix+path, "bearer", human, `query { user { id } }`, h.services[0])
				if cookie {
					req.Header.Del("Authorization")
					req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: human})
				}
				code, body := h.do(req)
				if prefix != "" && path == "/v1/graphql2" {
					// Existing rewrite adds HTTPPrefix after StripPrefix. This
					// historical combination does not route to the GraphQL mux.
					// Keep canonical prefixed Human access as the positive control.
					require.Equal(t, http.StatusMethodNotAllowed, code)
					continue
				}
				require.Equal(t, http.StatusOK, code)
				var result calendarGraphQLResult
				require.NoError(t, json.Unmarshal(body, &result))
				require.Empty(t, result.Errors)
				require.Contains(t, string(result.Data["user"]), h.admin)
			}
		}
	}
}

func TestLegacyRetirementPreservesIntegrationUIKSystem(t *testing.T) {
	h := newSendSignalOrganizationRuntime(t)
	ctx := h.app.Context(permission.SystemContext(context.Background(), "LegacyRetirementTest"))
	for _, typ := range []integrationkey.Type{integrationkey.TypeGeneric, integrationkey.TypeUniversal} {
		key, err := h.app.IntegrationKeyStore.Create(ctx, h.app.DB(), &integrationkey.IntegrationKey{Name: "Synthetic " + string(typ) + " control", Type: typ, ServiceID: h.services[0]}, nil)
		require.NoError(t, err)
		token := key.ID
		path := "/api/v2/generic/incoming"
		if typ == integrationkey.TypeUniversal {
			path = "/api/v2/uik"
			cfg := &gadb.UIKConfigV1{DefaultActions: []gadb.UIKActionV1{{Dest: gadb.DestV1{Type: "builtin-alert"}, Params: map[string]string{"summary": "req.body.summary"}}}}
			require.NoError(t, h.app.IntegrationKeyStore.SetConfig(ctx, h.app.DB(), uuid.MustParse(key.ID), cfg))
			token, err = h.app.IntegrationKeyStore.GenerateToken(ctx, h.app.DB(), uuid.MustParse(key.ID))
			if err != nil {
				t.Fatal("synthetic UIK signing failed")
			}
		}
		req, err := http.NewRequest(http.MethodPost, h.app.URL()+path, strings.NewReader(fmt.Sprintf(`{"summary":"%s positive control"}`, typ)))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)
		code, _ := h.do(req)
		require.Equal(t, http.StatusNoContent, code)
		var count int
		require.NoError(t, h.pool.QueryRow(context.Background(), `SELECT count(*) FROM alerts WHERE service_id=$1 AND summary=$2`, h.services[0], string(typ)+" positive control").Scan(&count))
		require.Equal(t, 1, count)
		// Credentials must not cross audiences or become Human/GraphQL keys.
		for _, wrong := range []string{"/api/graphql", "/api/v2/uik"} {
			if wrong == path {
				continue
			}
			req := legacyHTTPRequest(t, h.app.URL()+wrong, "bearer", token, `query { user { id } }`, h.services[0])
			code, body := h.do(req)
			require.Equal(t, http.StatusUnauthorized, code)
			if bytes.Contains(body, []byte(token)) {
				t.Fatal("cross-audience credential leaked")
			}
		}
	}
	_, legacy := insertLegacyGraphQLKey(t, h.calendarPolicyRuntime, apikey.GQLPolicy{Version: 1, Role: permission.RoleAdmin, Query: legacySignalQuery}, time.Now().Add(time.Hour), false)
	req := legacyHTTPRequest(t, h.app.URL()+"/api/v2/uik", "bearer", legacy, legacySignalQuery, h.services[0])
	code, _ := h.do(req)
	require.Equal(t, http.StatusUnauthorized, code)
	// Existing internal System resolver access remains distinct from Machine
	// authentication. Exercise an actual enqueue in each fixture Organization.
	for i, service := range h.services {
		ok, err := h.app.graphql2.Mutation().SendSignal(expflag.Context(ctx, expflag.FlagSet{expflag.UnivKeys}), graphql2.SendSignalInput{ServiceID: service, Dest: &gadb.DestV1{Type: h.provider.ID(), Args: map[string]string{"target": fmt.Sprintf("internal-system-%d", i)}}})
		require.NoError(t, err)
		require.True(t, ok)
	}
}
