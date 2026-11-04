package smoke

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/target/goalert/auth"
	"github.com/target/goalert/auth/authtoken"
)

func TestRotationUpdateAuditRejectedHTTPCredentials(t *testing.T) {
	h := rotationAuditHarness(t)
	ikSetAuthority(t, h, "ORG_MEMBER", true)
	token := h.GraphQLToken(h.UUID("user-a"))
	parsed, _, err := authtoken.Parse(token, nil)
	require.NoError(t, err)
	forged, err := parsed.Encode(func([]byte) ([]byte, error) { return make([]byte, 32), nil })
	require.NoError(t, err)
	request := func(cookie string) {
		t.Helper()
		before := serviceManagementSnapshot(t, h)
		n := rotationAuditCount(t, h)
		body, err := json.Marshal(map[string]any{"query": fmt.Sprintf(`mutation{updateRotation(input:{id:%q,description:"Rejected HTTP credentials"})}`, h.UUID("rotation-a"))})
		require.NoError(t, err)
		req, err := http.NewRequest(http.MethodPost, h.URL()+"/api/graphql", bytes.NewReader(body))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/json")
		if cookie != "" {
			req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: cookie})
		}
		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		data, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		require.NoError(t, resp.Body.Close())
		if resp.StatusCode == http.StatusOK {
			require.Contains(t, string(data), `"errors"`)
		} else {
			require.Contains(t, []int{http.StatusUnauthorized, http.StatusForbidden}, resp.StatusCode)
		}
		require.NotContains(t, string(data), token)
		require.NotContains(t, string(data), forged)
		require.Equal(t, before, serviceManagementSnapshot(t, h))
		require.Equal(t, n, rotationAuditCount(t, h), "pre-resolver authentication rejection is outside durable Mutation coverage")
	}
	request("")
	request(forged)
	_, err = h.App().DB().Exec(`DELETE FROM auth_user_sessions WHERE id=$1`, parsed.ID)
	require.NoError(t, err)
	request(token)
	rotationEffectEvidence(t, "rejected-http-credentials", map[string]any{"unauthenticated": true, "forged_signature": true, "revoked_signed_session": true, "business_changed": false, "resolver_entered": false})
}
