package smoke

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/apikey"
	"github.com/target/goalert/gadb"
	"github.com/target/goalert/graphql2"
	"github.com/target/goalert/permission"
	"github.com/target/goalert/test/smoke/harness"
)

func legacyRetirementKeyRows(t *testing.T, h *harness.Harness) map[string]string {
	t.Helper()
	rows := make(map[string]string)
	for _, table := range []string{"gql_api_keys", "gql_api_key_usage"} {
		var value string
		require.NoError(t, h.App().DB().QueryRow(`SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text), '[]'::jsonb)::text FROM `+table+` r`).Scan(&value))
		rows[table] = value
	}
	return rows
}

// legacyRetirementToken checks the closed issuance path, then constructs a
// valid historical credential in this test's disposable DB, as in the V2 app
// tests. It never calls production issuance to obtain a token. Signing material
// comes only from the harness's synthetic keyring; credentials stay in memory.
func legacyRetirementToken(t *testing.T, h *harness.Harness, document string) string {
	t.Helper()
	_, err := graphql2.QueryFields(document)
	require.NoError(t, err, "historical fixed query must be valid")
	before := legacyRetirementKeyRows(t, h)
	expires := time.Now().Add(time.Hour)
	for _, role := range []string{"admin", "user"} {
		response := h.GraphQLQueryUserVarsT(t, harness.DefaultGraphQLAdminUserID, `
			mutation($expires: ISOTimestamp!, $query: String!, $role: UserRole!) {
				createGQLAPIKey(input: {name: "retired", description: "synthetic historical regression",
					expiresAt: $expires, role: $role, query: $query}) {id token}
			}`, "", map[string]string{"expires": expires.Format(time.RFC3339), "query": document, "role": role})
		require.Len(t, response.Errors, 1)
		require.Equal(t, "access denied: legacy GraphQL API key issuance is disabled in MS OnCall", response.Errors[0].Message)
		var result struct{ CreateGQLAPIKey json.RawMessage }
		require.NoError(t, json.Unmarshal(response.Data, &result))
		require.True(t, len(result.CreateGQLAPIKey) == 0 || string(result.CreateGQLAPIKey) == "null", "denied issuance returned credential data")
		require.Equal(t, before, legacyRetirementKeyRows(t, h), "denied issuance changed key or usage rows")
	}

	id := uuid.New()
	policy, err := json.Marshal(apikey.GQLPolicy{Version: 1, Role: permission.RoleAdmin, Query: document})
	require.NoError(t, err)
	_, err = h.App().DB().Exec(`INSERT INTO gql_api_keys(id, name, description, policy, expires_at)
		VALUES ($1, $2, 'test-only historical fixture', $3, $4)`, id, "Historical "+id.String(), policy, expires)
	require.NoError(t, err)
	stored, err := gadb.New(h.App().DB()).APIKeyAuthPolicy(t.Context(), id)
	require.NoError(t, err)
	require.True(t, bytes.Equal(policy, stored), "fixture policy must match the persisted bytes")
	valid, err := gadb.New(h.App().DB()).APIKeyAuthCheck(t.Context(), id)
	require.NoError(t, err)
	require.True(t, valid, "historical fixture must be unexpired and not revoked")
	hash := sha256.Sum256(stored)
	token, err := h.App().APIKeyring.SignJWT(apikey.NewGraphQLClaims(id, hash[:], expires))
	if err != nil {
		t.Fatal("historical fixture signing failed")
	}
	var claims apikey.Claims
	_, err = h.App().APIKeyring.VerifyJWT(token, &claims, apikey.Issuer, apikey.Audience)
	if err != nil || claims.Subject != id.String() || !bytes.Equal(claims.PolicyHash, hash[:]) {
		t.Fatal("historical fixture signature, identity or policy hash is invalid")
	}
	t.Log("valid synthetic V1 admin fixture: signature, expiry, persisted identity and policy hash verified; issuance denied for both roles")
	return token
}

func legacyRetirementDenied(t *testing.T, h *harness.Harness, token string, body map[string]any) {
	t.Helper()
	before := legacyRetirementKeyRows(t, h)
	data, err := json.Marshal(body)
	require.NoError(t, err)
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, h.URL()+"/api/graphql", bytes.NewReader(data))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	response, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer response.Body.Close()
	require.Equal(t, http.StatusUnauthorized, response.StatusCode)
	result, err := io.ReadAll(response.Body)
	require.NoError(t, err)
	// Exact auth-layer error proves no protected GraphQL data or credential was
	// returned. Do not print a possibly sensitive body on assertion failure.
	if !bytes.Equal(result, []byte("unauthorized\n")) {
		t.Fatal("retired credential did not return the expected data-free authentication denial")
	}
	require.Equal(t, before, legacyRetirementKeyRows(t, h), "authentication denial changed key or usage rows")
	t.Log("legacy request: HTTP 401, no protected data, key and usage rows unchanged")
}
