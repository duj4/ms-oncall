package usersessioncompat

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/app"
	"github.com/target/goalert/auth"
	"github.com/target/goalert/keyring"
	"github.com/target/goalert/organization"
	"github.com/target/goalert/test/smoke/harness"
)

type fixture struct {
	h                *harness.Harness
	tokens, sessions map[string]string
}

// Reuse the production app harness without importing the legacy smoke test
// package. All identities, Sessions and destinations are synthetic and private.
func newFixture(t *testing.T) *fixture {
	t.Helper()
	h := harness.NewStoppedHarness(t, "", nil, "")
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)
	h.StartWithAppCfgHook(func(c *app.Config) { c.EncryptionKeys = keyring.Keys{key, nil} })
	t.Cleanup(h.Close)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	require.NoError(t, h.App().Engine.Pause(ctx))
	f := &fixture{h: h, tokens: map[string]string{}, sessions: map[string]string{}}
	for _, org := range []string{"a", "b"} {
		execSQL(t, h, `INSERT INTO organizations(id,classification,display_name,canonical_name) VALUES($1,'NORMAL',$2,$2)`, h.UUID("s2-org-"+org), "compat-"+org)
		execSQL(t, h, `INSERT INTO normal_organizations(organization_id,organization_classification,corporate_mapping_key,iana_time_zone) VALUES($1,'NORMAL',$2,'Asia/Shanghai')`, h.UUID("s2-org-"+org), "compat-"+org)
	}
	for _, actor := range []string{"om", "oa", "pam", "paa", "b", "ba", "aowner", "pd0", "od"} {
		role, org, orole, outcome, classification, matched := "user", "a", "ORG_MEMBER", "EXACTLY_ONE", "NORMAL", 1
		if actor == "pam" || actor == "paa" || actor == "pd0" {
			role = "admin"
		}
		if actor == "oa" || actor == "paa" || actor == "ba" {
			orole = "ORG_ADMIN"
		}
		if actor == "b" || actor == "ba" {
			org = "b"
		}
		home := h.UUID("s2-org-" + org)
		var normal any = home
		if actor == "pd0" || actor == "od" {
			home, normal, orole, outcome, classification, matched = organization.DefaultOrganizationID, nil, "NONE", "ZERO", "DEFAULT", 0
		}
		execSQL(t, h, `INSERT INTO users(id,name,email,role) VALUES($1,$2,'',$3)`, h.UUID(actor), "compat-"+actor, role)
		execSQL(t, h, `INSERT INTO user_organization_assignments(user_id,effective_organization_id,effective_organization_classification,effective_normal_organization_id,organization_role,mapping_outcome,authoritative_evaluated_at,source_config_version,matched_count) VALUES($1,$2,$3,$4,$5,$6,now(),'session-compat1',$7)`, h.UUID(actor), home, classification, normal, orole, outcome, matched)
		token, err := h.App().AuthHandler.CreateSession(context.Background(), "synthetic-compat", h.UUID(actor))
		require.NoError(t, err)
		f.tokens[actor], err = token.Encode(h.App().SessionKeyring.Sign)
		require.NoError(t, err)
		f.sessions[actor] = token.ID.String()
	}
	for _, org := range []string{"a", "b"} {
		execSQL(t, h, `INSERT INTO escalation_policies(id,organization_id,name) VALUES($1,$2,$3)`, h.UUID("ep-"+org), h.UUID("s2-org-"+org), "compat-"+org)
		execSQL(t, h, `INSERT INTO services(id,organization_id,escalation_policy_id,name) VALUES($1,$2,$3,$4)`, h.UUID("svc-"+org), h.UUID("s2-org-"+org), h.UUID("ep-"+org), "compat-"+org)
		execSQL(t, h, `INSERT INTO schedules(id,organization_id,name,time_zone) VALUES($1,$2,$3,'Asia/Shanghai')`, h.UUID("sched-"+org), h.UUID("s2-org-"+org), "compat-"+org)
		execSQL(t, h, `INSERT INTO rotations(id,organization_id,name,type,time_zone) VALUES($1,$2,$3,'weekly','Asia/Shanghai')`, h.UUID("rot-"+org), h.UUID("s2-org-"+org), "compat-"+org)
	}
	execSQL(t, h, `INSERT INTO user_contact_methods(id,user_id,name,dest) VALUES($1,$2,'synthetic', '{"Type":"builtin-smtp-email","Args":{"email_address":"synthetic@example.invalid"}}')`, h.UUID("cm-om"), h.UUID("om"))
	execSQL(t, h, `INSERT INTO user_notification_rules(id,user_id,contact_method_id,delay_minutes) VALUES($1,$2,$3,0)`, h.UUID("nr-om"), h.UUID("om"), h.UUID("cm-om"))
	return f
}

func execSQL(t *testing.T, h *harness.Harness, query string, args ...any) {
	t.Helper()
	_, err := h.App().DB().ExecContext(t.Context(), query, args...)
	require.True(t, err == nil, "synthetic fixture SQL failed (details withheld)")
}

func countSQL(t *testing.T, h *harness.Harness, query string, args ...any) int64 {
	t.Helper()
	var count int64
	err := h.App().DB().QueryRowContext(t.Context(), query, args...).Scan(&count)
	require.True(t, err == nil, "native state query failed (details withheld)")
	return count
}

func createSession(t *testing.T, h *harness.Harness, owner string) (string, uuid.UUID) {
	t.Helper()
	token, err := h.App().AuthHandler.CreateSession(t.Context(), "synthetic-compat", owner)
	require.NoError(t, err)
	var safe uuid.UUID
	err = h.App().DB().QueryRowContext(t.Context(), `SELECT audit_resource_id FROM auth_user_sessions WHERE id=$1`, token.ID).Scan(&safe)
	require.True(t, err == nil, "load safe identity (details withheld)")
	return token.ID.String(), safe
}

func successCount(t *testing.T, h *harness.Harness) int64 {
	t.Helper()
	return countSQL(t, h, `SELECT count(*) FROM user_session_revoke_audit_events WHERE record_kind='success_witness'`)
}

func selectedQuery(ids ...string) string {
	input := ""
	for _, id := range ids {
		if input != "" {
			input += ","
		}
		input += fmt.Sprintf(`{type:userSession,id:%q}`, id)
	}
	return `mutation{deleteAll(input:[` + input + `])}`
}

func requestRaw(t *testing.T, h *harness.Harness, token, query string, variables map[string]any) (int, map[string]json.RawMessage) {
	t.Helper()
	body, err := json.Marshal(map[string]any{"query": query, "variables": variables})
	require.NoError(t, err)
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, h.URL()+"/api/graphql?trace=1", bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: token})
	resp, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	require.NoError(t, err)
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	var result map[string]json.RawMessage
	if resp.StatusCode == 200 || resp.StatusCode == 422 {
		require.NoError(t, json.Unmarshal(raw, &result))
	}
	return resp.StatusCode, result
}

func request(t *testing.T, h *harness.Harness, token, query string, variables map[string]any, expected ...int) map[string]json.RawMessage {
	t.Helper()
	status, result := requestRaw(t, h, token, query, variables)
	want := 200
	if len(expected) == 1 {
		want = expected[0]
	}
	require.Equal(t, want, status)
	return result
}

func businessSnapshot(t *testing.T, f *fixture) map[string]int64 {
	t.Helper()
	out := map[string]int64{}
	for _, table := range []string{"users", "services", "escalation_policies", "schedules", "rotations", "user_contact_methods", "user_notification_rules", "auth_user_sessions", "user_overrides", "integration_keys"} {
		out[table] = countSQL(t, f.h, `SELECT count(*) FROM `+table)
	}
	return out
}
