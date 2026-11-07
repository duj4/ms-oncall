package smoke

// Synthetic signed-HTTP/PG regressions retained from D02-S2-B.
import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/alert"
	"github.com/target/goalert/app"
	"github.com/target/goalert/auth"
	"github.com/target/goalert/keyring"
	"github.com/target/goalert/test/smoke/harness"
)

type s2Fixture struct {
	h        *harness.Harness
	tokens   map[string]string
	sessions map[string]string
}
type s2Result struct {
	Status int
	Raw    json.RawMessage
	Data   map[string]json.RawMessage
	Errors []map[string]any
}

func s2Save(t *testing.T, name string, value any) {
	t.Helper()
	b, e := json.MarshalIndent(value, "", "  ")
	require.NoError(t, e)
	f, e := os.CreateTemp(os.Getenv("D02_S2_B_EVIDENCE"), strings.ReplaceAll(t.Name()+"_"+name, "/", "_")+"-*.json")
	require.NoError(t, e)
	_, e = f.Write(append(b, '\n'))
	require.NoError(t, e)
	require.NoError(t, f.Close())
}
func s2Exec(t *testing.T, f *s2Fixture, q string, args ...any) {
	t.Helper()
	_, e := f.h.App().DB().ExecContext(t.Context(), q, args...)
	require.NoError(t, e)
}
func s2Scalar(t *testing.T, f *s2Fixture, q string, args ...any) string {
	t.Helper()
	var s string
	require.NoError(t, f.h.App().DB().QueryRowContext(t.Context(), q, args...).Scan(&s))
	return s
}
func s2Rows(t *testing.T, f *s2Fixture, q string, args ...any) string {
	t.Helper()
	return s2Scalar(t, f, `SELECT coalesce(jsonb_agg(to_jsonb(x) ORDER BY to_jsonb(x)::text),'[]'::jsonb)::text FROM (`+q+`) x`, args...)
}
func s2Snapshot(t *testing.T, f *s2Fixture) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, table := range []string{"organizations", "normal_organizations", "users", "user_organization_assignments", "user_contact_methods", "user_notification_rules", "services", "escalation_policies", "escalation_policy_steps", "escalation_policy_actions", "schedules", "rotations", "rotation_participants", "rotation_state", "user_overrides", "alerts", "alert_data", "alert_logs", "auth_subjects", "config_limits", "outgoing_messages", "notification_channels", "user_favorites"} {
		out[table] = s2Rows(t, f, "SELECT * FROM "+table)
	}
	// No session token, signing material, password hash or encrypted config bytes are exported.
	out["session_identity"] = s2Rows(t, f, "SELECT id,user_id,user_agent,created_at FROM auth_user_sessions")
	out["basic_identity"] = s2Rows(t, f, "SELECT user_id,username FROM auth_basic_users")
	out["basic_integrity"] = s2Rows(t, f, "SELECT user_id,md5(password_hash) AS synthetic_hash_digest FROM auth_basic_users")
	out["config_integrity"] = s2Rows(t, f, "SELECT id,md5(data::text) AS encrypted_payload_digest FROM config")
	out["keyring_integrity"] = s2Rows(t, f, "SELECT id,md5(signing_key::text) AS signing_ciphertext_digest,md5(next_key::text) AS next_ciphertext_digest FROM keyring")
	out["verification_integrity"] = s2Rows(t, f, "SELECT id,contact_method_id,expires_at,sent,md5(code::text) AS synthetic_code_digest FROM user_verification_codes")
	out["config_public_url"] = f.h.App().ConfigStore.Config().General.PublicURL
	return out
}
func s2New(t *testing.T) *s2Fixture {
	t.Helper()
	var endpoint string
	t.Cleanup(func() {
		if endpoint == "" {
			return
		}
		u, e := url.Parse(endpoint)
		require.NoError(t, e)
		c, dialErr := net.DialTimeout("tcp", u.Host, 500*time.Millisecond)
		if c != nil {
			c.Close()
		}
		s2Save(t, "HTTP-cleanup", map[string]any{"test_pid": os.Getpid(), "url": endpoint, "listener_closed_after_harness_cleanup": dialErr != nil})
		assert.Error(t, dialErr, "task HTTP listener must be closed before PG cleanup")
	})
	h := harness.NewStoppedHarness(t, "", nil, "")
	testKey := make([]byte, 32)
	_, e := rand.Read(testKey)
	require.NoError(t, e)
	h.StartWithAppCfgHook(func(c *app.Config) { c.EncryptionKeys = keyring.Keys{testKey, nil} })
	endpoint = h.URL()
	t.Cleanup(h.Close)
	pauseStepOrganizationEngine(t, h)
	h.IgnoreErrorsWith("sql: no rows in result set")
	f := &s2Fixture{h: h, tokens: map[string]string{}, sessions: map[string]string{}}
	for _, org := range []string{"a", "b"} {
		id := h.UUID("s2-org-" + org)
		s2Exec(t, f, `INSERT INTO organizations(id,classification,display_name,canonical_name) VALUES($1,'NORMAL',$2,$3)`, id, "Synthetic "+org, "s2."+org)
		s2Exec(t, f, `INSERT INTO normal_organizations(organization_id,organization_classification,corporate_mapping_key,iana_time_zone) VALUES($1,'NORMAL',$2,'Asia/Shanghai')`, id, "s2:"+org)
	}
	for _, actor := range []string{"om", "oa", "pam", "paa", "b", "ba", "aowner", "spare"} {
		role, org, orole := "user", "a", "ORG_MEMBER"
		if actor == "pam" || actor == "paa" {
			role = "admin"
		}
		if actor == "oa" || actor == "paa" || actor == "ba" {
			orole = "ORG_ADMIN"
		}
		if actor == "b" || actor == "ba" {
			org = "b"
		}
		s2Exec(t, f, `INSERT INTO users(id,name,email,role) VALUES($1,$2,$3,$4)`, h.UUID(actor), "S2 SYNTHETIC "+actor, actor+"@example.invalid", role)
		s2Exec(t, f, `INSERT INTO user_organization_assignments(user_id,effective_organization_id,effective_organization_classification,effective_normal_organization_id,organization_role,mapping_outcome,authoritative_evaluated_at,source_config_version,matched_count) VALUES($1,$2,'NORMAL',$2,$3,'EXACTLY_ONE',now(),'d02-s2-b',1)`, h.UUID(actor), h.UUID("s2-org-"+org), orole)
		tok, e := h.App().AuthHandler.CreateSession(context.Background(), "D02-S2-B synthetic "+actor, h.UUID(actor))
		require.NoError(t, e)
		f.tokens[actor], e = tok.Encode(h.App().SessionKeyring.Sign)
		require.NoError(t, e)
		f.sessions[actor] = s2Scalar(t, f, `SELECT id::text FROM auth_user_sessions WHERE user_id=$1`, h.UUID(actor))
	}
	for _, org := range []string{"a", "b"} {
		s2Exec(t, f, `INSERT INTO escalation_policies(id,organization_id,name,description,repeat) VALUES($1,$2,$3,'s2 sentinel',1)`, h.UUID("ep-"+org), h.UUID("s2-org-"+org), "S2 EP "+org)
		s2Exec(t, f, `INSERT INTO services(id,organization_id,escalation_policy_id,name,description) VALUES($1,$2,$3,$4,'s2 sentinel')`, h.UUID("svc-"+org), h.UUID("s2-org-"+org), h.UUID("ep-"+org), "S2 Service "+org)
		s2Exec(t, f, `INSERT INTO schedules(id,organization_id,name,time_zone) VALUES($1,$2,$3,'Asia/Shanghai')`, h.UUID("sched-"+org), h.UUID("s2-org-"+org), "S2 Schedule "+org)
		for i := 0; i < 2; i++ {
			step := fmt.Sprintf("step-%s-%d", org, i)
			s2Exec(t, f, `INSERT INTO escalation_policy_steps(id,escalation_policy_id,delay,step_number) VALUES($1,$2,1,$3)`, h.UUID(step), h.UUID("ep-"+org), i)
			owner := "aowner"
			if org == "b" {
				owner = "b"
			}
			s2Exec(t, f, `INSERT INTO escalation_policy_actions(id,escalation_policy_step_id,user_id) VALUES($1,$2,$3)`, h.UUID("action-"+step), h.UUID(step), h.UUID(owner))
		}
	}
	for _, owner := range []string{"om", "aowner", "b"} {
		dest, _ := json.Marshal(map[string]any{"Type": "builtin-smtp-email", "Args": map[string]string{"email_address": owner + "@example.invalid"}})
		s2Exec(t, f, `INSERT INTO user_contact_methods(id,user_id,name,dest,private,disabled,pending) VALUES($1,$2,$3,$4,true,false,false)`, h.UUID("cm-"+owner), h.UUID(owner), "S2 CM "+owner, dest)
		s2Exec(t, f, `INSERT INTO user_notification_rules(id,user_id,contact_method_id,delay_minutes) VALUES($1,$2,$3,0)`, h.UUID("nr-"+owner), h.UUID(owner), h.UUID("cm-"+owner))
	}
	s2Save(t, "environment", map[string]any{"test_pid": os.Getpid(), "http_url": h.URL(), "database": s2Scalar(t, f, `SELECT current_database()`), "cluster": s2Scalar(t, f, `SELECT system_identifier::text FROM pg_control_system()`), "actor": s2Rows(t, f, `SELECT u.id,u.role,a.* FROM users u JOIN user_organization_assignments a ON a.user_id=u.id`), "fixture": s2Snapshot(t, f), "sessions": f.sessions})
	return f
}
func s2Call(t *testing.T, f *s2Fixture, label, actor, q string, vars any) *s2Result {
	t.Helper()
	before := s2Snapshot(t, f)
	identity := s2Rows(t, f, `SELECT u.id,u.role,a.effective_organization_id,a.organization_role,a.mapping_outcome FROM users u LEFT JOIN user_organization_assignments a ON a.user_id=u.id WHERE u.id=$1`, f.h.UUID(actor))
	body, e := json.Marshal(map[string]any{"query": q, "variables": vars})
	require.NoError(t, e)
	req, e := http.NewRequestWithContext(t.Context(), http.MethodPost, f.h.URL()+"/api/graphql", bytes.NewReader(body))
	require.NoError(t, e)
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: f.tokens[actor]})
	client := &http.Client{Timeout: 20 * time.Second}
	resp, e := client.Do(req)
	require.NoError(t, e)
	defer resp.Body.Close()
	raw, e := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	require.NoError(t, e)
	r := &s2Result{Status: resp.StatusCode, Raw: raw}
	if resp.StatusCode == 200 {
		require.NoError(t, json.Unmarshal(raw, r))
	}
	sum := sha256.Sum256([]byte(f.tokens[actor]))
	qlog := q
	// All credential inputs are generated/synthetic; omit them from exported requests anyway.
	for _, password := range []string{"S2-Synthetic-Password-Only-814!", "S2-Synthetic-Password-Only-915!"} {
		qlog = strings.ReplaceAll(qlog, password, "[synthetic credential omitted]")
	}
	var exportedResponse any = r.Raw
	if !json.Valid(raw) {
		exportedResponse = string(raw)
	}
	loggedVars := vars
	if v, ok := vars.(map[string]any); ok {
		copyV := map[string]any{}
		for k, value := range v {
			if strings.Contains(strings.ToLower(k), "token") {
				copyV[k] = "[synthetic token omitted]"
			} else {
				copyV[k] = value
			}
		}
		loggedVars = copyV
	}
	s2Save(t, label, map[string]any{"actor": json.RawMessage(identity), "session_id": f.sessions[actor], "session_fingerprint": hex.EncodeToString(sum[:]), "request": map[string]any{"method": "POST", "path": "/api/graphql", "query": qlog, "variables": loggedVars}, "http_status": r.Status, "response": exportedResponse, "before": before, "after": s2Snapshot(t, f)})
	t.Logf("REQUEST %s actor=%s HTTP=%d response=%s", label, actor, r.Status, r.Raw)
	return r
}
func s2Allow(t *testing.T, r *s2Result, field string) {
	t.Helper()
	assert.Equal(t, 200, r.Status)
	assert.Empty(t, r.Errors)
	assert.NotEqual(t, "null", string(r.Data[field]))
	assert.NotEqual(t, "false", string(r.Data[field]))
	assert.NotEmpty(t, r.Data[field])
}
func s2Deny(t *testing.T, r *s2Result) {
	t.Helper()
	assert.Equal(t, 200, r.Status)
	assert.NotEmpty(t, r.Errors)
	if len(r.Errors) > 0 {
		assert.NotContains(t, fmt.Sprint(r.Errors), "GRAPHQL_VALIDATION_FAILED", "invalid test input is not authorization evidence")
		for _, e := range r.Errors {
			m := fmt.Sprint(e["message"])
			assert.True(t, strings.Contains(m, "access denied") || m == "contact method not found" || m == "invalid code" || m == "uuid does not exist on policy" || m == "invalid link token", "unclassified/generic error does not prove authorization: %s", m)
		}
	}
}

func TestD02S2B_B1(t *testing.T) {
	f := s2New(t)
	h := f.h
	for _, actor := range []string{"om", "oa"} {
		for _, form := range []string{"direct", "variables-alias-fragment"} {
			t.Run("PF01/"+actor+"/"+form, func(t *testing.T) {
				q := fmt.Sprintf(`query{user(id:%q){id name email role}}`, h.UUID("b"))
				var vars any
				field := "user"
				if form != "direct" {
					q = `query Foreign($id:ID!){foreignProfile:user(id:$id){...P}} fragment P on User{id name email role}`
					vars = map[string]any{"id": h.UUID("b")}
					field = "foreignProfile"
				}
				r := s2Call(t, f, "PF01-foreign-"+form, actor, q, vars)
				assert.Equal(t, 200, r.Status)
				assert.True(t, string(r.Data[field]) == "null" || len(r.Errors) > 0, "PF01 expected Foreign non-OnCall Profile hidden; actual %s", r.Raw)
			})
		}
		t.Run("PF01/"+actor+"/controls", func(t *testing.T) {
			r := s2Call(t, f, "users-list-control", actor, `query{users(first:100){nodes{id name email role}}}`, nil)
			s2Allow(t, r, "users")
			assert.NotContains(t, string(r.Raw), h.UUID("b"))
			r = s2Call(t, f, "same-org-profile", actor, fmt.Sprintf(`query{user(id:%q){id name email role}}`, h.UUID("aowner")), nil)
			s2Allow(t, r, "user")
			assert.Contains(t, string(r.Raw), "aowner@example.invalid")
			r = s2Call(t, f, "missing-user", actor, fmt.Sprintf(`query{user(id:%q){id name email role}}`, h.UUID("missing")), nil)
			assert.Equal(t, "null", string(r.Data["user"]))
		})
		for _, target := range []string{actor, "aowner", "b"} {
			t.Run("profile/"+actor+"/"+target, func(t *testing.T) {
				before := s2Snapshot(t, f)
				r := s2Call(t, f, "profile-name", actor, fmt.Sprintf(`mutation{updateUser(input:{id:%q,name:%q,email:%q})}`, h.UUID(target), "S2 updated "+actor, "s2-updated-"+actor+"@example.invalid"), nil)
				if target == actor {
					s2Allow(t, r, "updateUser")
					assert.Equal(t, "S2 updated "+actor, s2Scalar(t, f, `SELECT name FROM users WHERE id=$1`, h.UUID(target)))
					assert.Equal(t, "s2-updated-"+actor+"@example.invalid", s2Scalar(t, f, `SELECT email FROM users WHERE id=$1`, h.UUID(target)))
				} else {
					s2Deny(t, r)
					assert.Equal(t, before, s2Snapshot(t, f))
				}
			})
		}
		t.Run("role-escalation/"+actor, func(t *testing.T) {
			before := s2Snapshot(t, f)
			r := s2Call(t, f, "role-escalation", actor, fmt.Sprintf(`mutation{updateUser(input:{id:%q,role:admin})}`, h.UUID(actor)), nil)
			s2Deny(t, r)
			assert.Equal(t, before, s2Snapshot(t, f))
		})
	}
	// Existing related User resolver, with legitimate same-Organization parent and foreign-parent control.
	t.Run("related-user", func(t *testing.T) {
		s2Exec(t, f, `INSERT INTO user_overrides(id,tgt_schedule_id,add_user_id,start_time,end_time) VALUES($1,$2,$3,now()-interval '2 hours',now()-interval '1 hour')`, h.UUID("ov-a"), h.UUID("sched-a"), h.UUID("aowner"))
		s2Exec(t, f, `INSERT INTO user_overrides(id,tgt_schedule_id,add_user_id,start_time,end_time) VALUES($1,$2,$3,now()-interval '2 hours',now()-interval '1 hour')`, h.UUID("ov-b"), h.UUID("sched-b"), h.UUID("b"))
		r := s2Call(t, f, "related-UserOverride-AddUser", "om", fmt.Sprintf(`query{userOverride(id:%q){id addUser{id name email role}}}`, h.UUID("ov-a")), nil)
		s2Allow(t, r, "userOverride")
		assert.Contains(t, string(r.Raw), h.UUID("aowner"))
		r = s2Call(t, f, "foreign-related-parent-hidden", "om", fmt.Sprintf(`query{userOverride(id:%q){id addUser{id name email role}}}`, h.UUID("ov-b")), nil)
		assert.Equal(t, "null", string(r.Data["userOverride"]))
		assert.NotContains(t, string(r.Raw), "b@example.invalid")
	})
	s2Exec(t, f, `INSERT INTO auth_subjects(provider_id,subject_id,user_id) VALUES('s2-query-proof','s2-query-proof',$1)`, h.UUID("b"))
	for _, actor := range []string{"om", "oa", "pam", "paa"} {
		t.Run("independent-guards/"+actor, func(t *testing.T) {
			pa := actor == "pam" || actor == "paa"
			for _, op := range []string{"role", "config", "limits", "reEncrypt", "config-all", "configHints", "providerSubjects", "public-config"} {
				before := s2Snapshot(t, f)
				q := ""
				field := ""
				switch op {
				case "role":
					q = fmt.Sprintf(`mutation{updateUser(input:{id:%q,role:admin})}`, h.UUID("spare"))
					field = "updateUser"
				case "config":
					q = `mutation{setConfig(input:[{id:"General.PublicURL",value:"https://s2.example.invalid"}])}`
					field = "setConfig"
				case "limits":
					q = `mutation{setSystemLimits(input:[{id:RulesPerSchedule,value:49}])}`
					field = "setSystemLimits"
				case "reEncrypt":
					q = `mutation{reEncryptKeyringsAndConfig}`
					field = "reEncryptKeyringsAndConfig"
				case "config-all":
					q = `query{config(all:true){id}}`
					field = "config"
				case "configHints":
					q = `query{configHints{id}}`
					field = "configHints"
				case "providerSubjects":
					q = `query{authSubjectsForProvider(providerID:"s2-query-proof"){nodes{providerID subjectID userID}}}`
					field = "authSubjectsForProvider"
				case "public-config":
					q = `query{config{id}}`
					field = "config"
				}
				r := s2Call(t, f, "guard-"+op, actor, q, nil)
				if pa || op == "public-config" {
					s2Allow(t, r, field)
					if op == "providerSubjects" {
						assert.Contains(t, string(r.Raw), h.UUID("b"))
					}
					if op == "role" {
						assert.Equal(t, "admin", s2Scalar(t, f, `SELECT role FROM users WHERE id=$1`, h.UUID("spare")))
					}
					if op == "config" {
						assert.Equal(t, "https://s2.example.invalid", h.App().ConfigStore.Config().General.PublicURL)
					}
					if op == "limits" {
						assert.Equal(t, "49", s2Scalar(t, f, `SELECT max::text FROM config_limits WHERE id='rules_per_schedule'`))
					}
				} else {
					s2Deny(t, r)
					assert.Equal(t, before, s2Snapshot(t, f))
				}
			}
		})
	}
	s2AccountGuards(t, f)
	for _, actor := range []string{"pam", "paa"} {
		t.Run("PA-revocation/"+actor, func(t *testing.T) {
			s2Exec(t, f, `UPDATE users SET role='user' WHERE id=$1`, h.UUID(actor))
			before := s2Snapshot(t, f)
			r := s2Call(t, f, "PA-revoked-new-request", actor, fmt.Sprintf(`mutation{updateUser(input:{id:%q,role:user})}`, h.UUID("spare")), nil)
			s2Deny(t, r)
			assert.Equal(t, before, s2Snapshot(t, f))
		})
	}
}

func TestD02S2B_B2(t *testing.T) {
	f := s2New(t)
	h := f.h
	actor := "om"
	initialToken := f.tokens[actor]
	initialSession := f.sessions[actor]
	q := func(org string) string { return fmt.Sprintf(`query{service(id:%q){id name}}`, h.UUID("svc-"+org)) }
	r := s2Call(t, f, "before-transfer-A", actor, q("a"), nil)
	s2Allow(t, r, "service")
	beforeRoots := map[string]string{"services": s2Rows(t, f, `SELECT * FROM services`), "ep": s2Rows(t, f, `SELECT * FROM escalation_policies`)}
	// An explicit transaction commits before the next request; no admission/in-flight claim.
	tx, e := h.App().DB().BeginTx(t.Context(), nil)
	require.NoError(t, e)
	_, e = tx.ExecContext(t.Context(), `UPDATE user_organization_assignments SET effective_organization_id=$2,effective_normal_organization_id=$2 WHERE user_id=$1`, h.UUID(actor), h.UUID("s2-org-b"))
	require.NoError(t, e)
	require.NoError(t, tx.Commit())
	t.Run("home-transfer", func(t *testing.T) {
		before := s2Snapshot(t, f)
		r = s2Call(t, f, "after-transfer-A-hidden", actor, q("a"), nil)
		assert.Equal(t, "null", string(r.Data["service"]))
		assert.NotContains(t, string(r.Raw), h.UUID("svc-a"))
		r = s2Call(t, f, "after-transfer-B-allowed", actor, q("b"), nil)
		s2Allow(t, r, "service")
		assert.Equal(t, before, s2Snapshot(t, f))
		assert.Equal(t, initialToken, f.tokens[actor])
		assert.Equal(t, initialSession, f.sessions[actor])
		assert.Equal(t, h.UUID("s2-org-a"), s2Scalar(t, f, `SELECT organization_id::text FROM services WHERE id=$1`, h.UUID("svc-a")))
	})
	t.Run("personal-resources", func(t *testing.T) {
		r := s2Call(t, f, "self-CM-NR-after-transfer", actor, fmt.Sprintf(`query{user(id:%q){id contactMethods{id name value private} notificationRules{id contactMethod{id name}}}}`, h.UUID(actor)), nil)
		s2Allow(t, r, "user")
		assert.Contains(t, string(r.Raw), h.UUID("cm-om"))
		assert.Contains(t, string(r.Raw), h.UUID("nr-om"))
		r = s2Call(t, f, "self-CM-update-after-transfer", actor, fmt.Sprintf(`mutation{updateUserContactMethod(input:{id:%q,name:"Transferred self CM"})}`, h.UUID("cm-om")), nil)
		s2Allow(t, r, "updateUserContactMethod")
		assert.Equal(t, "Transferred self CM", s2Scalar(t, f, `SELECT name FROM user_contact_methods WHERE id=$1`, h.UUID("cm-om")))
	})
	t.Run("override-ID-current-home", func(t *testing.T) {
		for _, org := range []string{"a", "b"} {
			owner := "aowner"
			if org == "b" {
				owner = "b"
			}
			s2Exec(t, f, `INSERT INTO user_overrides(id,tgt_schedule_id,add_user_id,start_time,end_time) VALUES($1,$2,$3,now()-interval '2 hours',now()-interval '1 hour')`, h.UUID("ov-"+org), h.UUID("sched-"+org), h.UUID(owner))
		}
		before := s2Snapshot(t, f)
		r := s2Call(t, f, "old-A-override-hidden", actor, fmt.Sprintf(`query{userOverride(id:%q){id addUser{id name}}}`, h.UUID("ov-a")), nil)
		assert.Equal(t, 200, r.Status)
		assert.Empty(t, r.Errors)
		assert.Equal(t, "null", string(r.Data["userOverride"]))
		r = s2Call(t, f, "current-B-override-allowed", actor, fmt.Sprintf(`query{userOverride(id:%q){id addUser{id name}}}`, h.UUID("ov-b")), nil)
		s2Allow(t, r, "userOverride")
		assert.Contains(t, string(r.Raw), h.UUID("ov-b"))
		assert.Equal(t, before, s2Snapshot(t, f))
	})
	t.Run("assignment-removal", func(t *testing.T) {
		s2Exec(t, f, `DELETE FROM user_organization_assignments WHERE user_id=$1`, h.UUID(actor))
		before := s2Snapshot(t, f)
		r := s2Call(t, f, "assignment-removed-business-deny", actor, q("b"), nil)
		assert.True(t, r.Status == 401 || r.Status == 403 || len(r.Errors) > 0 || string(r.Data["service"]) == "null")
		assert.NotContains(t, string(r.Raw), h.UUID("svc-b"))
		assert.Equal(t, before, s2Snapshot(t, f))
	})
	// Restore only this task's authority for independent authentication-revocation test.
	s2Exec(t, f, `INSERT INTO user_organization_assignments(user_id,effective_organization_id,effective_organization_classification,effective_normal_organization_id,organization_role,mapping_outcome,authoritative_evaluated_at,source_config_version,matched_count) VALUES($1,$2,'NORMAL',$2,'ORG_MEMBER','EXACTLY_ONE',now(),'s2-restore',1)`, h.UUID(actor), h.UUID("s2-org-b"))
	t.Run("session-revocation", func(t *testing.T) {
		r := s2Call(t, f, "before-session-revoke", actor, q("b"), nil)
		s2Allow(t, r, "service")
		second, e := h.App().AuthHandler.CreateSession(context.Background(), "D02-S2-B second valid Session", h.UUID(actor))
		require.NoError(t, e)
		secondToken, e := second.Encode(h.App().SessionKeyring.Sign)
		require.NoError(t, e)
		s2Exec(t, f, `DELETE FROM auth_user_sessions WHERE id=$1`, initialSession)
		r = s2Call(t, f, "old-signed-session-after-revoke", actor, q("b"), nil)
		assert.Equal(t, 401, r.Status)
		assert.NotContains(t, string(r.Raw), h.UUID("svc-b"))
		f.tokens[actor] = secondToken
		f.sessions[actor] = s2Scalar(t, f, `SELECT id::text FROM auth_user_sessions WHERE user_id=$1`, h.UUID(actor))
		r = s2Call(t, f, "second-valid-session-control", actor, q("b"), nil)
		s2Allow(t, r, "service")
		assert.NotEqual(t, initialSession, f.sessions[actor])
	})
	assert.Equal(t, beforeRoots["services"], s2Rows(t, f, `SELECT * FROM services`))
	assert.Equal(t, beforeRoots["ep"], s2Rows(t, f, `SELECT * FROM escalation_policies`))
}

func TestD02S2B_B2AlertFixtureControl(t *testing.T) {
	// Prior exploratory SQL used s2-a/s2-b rather than a valid serialized DedupID.
	// Bind its exact scanner error, then change only that fixture precondition.
	var invalid alert.DedupID
	err := invalid.Scan("s2-b")
	require.EqualError(t, err, "invalid format")
	f := s2New(t)
	h := f.h
	s2Save(t, "prior-Alert-fixture-diagnosis", map[string]any{"old_dedup": "s2-b", "real_DedupID_Scan_error": err.Error(), "replacement": "user:1:s2-b", "production_source_changed": false})
	var a, b int
	require.NoError(t, h.App().DB().QueryRow(`INSERT INTO alerts(service_id,summary,dedup_key) VALUES($1,'S2 Alert A','user:1:s2-a') RETURNING id`, h.UUID("svc-a")).Scan(&a))
	require.NoError(t, h.App().DB().QueryRow(`INSERT INTO alerts(service_id,summary,dedup_key) VALUES($1,'S2 Alert B','user:1:s2-b') RETURNING id`, h.UUID("svc-b")).Scan(&b))
	r := s2Call(t, f, "valid-Alert-before-transfer", "om", fmt.Sprintf(`query{alert(id:%d){alertID summary}}`, a), nil)
	s2Allow(t, r, "alert")
	tx, e := h.App().DB().BeginTx(t.Context(), nil)
	require.NoError(t, e)
	_, e = tx.ExecContext(t.Context(), `UPDATE user_organization_assignments SET effective_organization_id=$2,effective_normal_organization_id=$2 WHERE user_id=$1`, h.UUID("om"), h.UUID("s2-org-b"))
	require.NoError(t, e)
	require.NoError(t, tx.Commit())
	before := s2Snapshot(t, f)
	r = s2Call(t, f, "valid-old-A-Alert-after-transfer", "om", fmt.Sprintf(`mutation{updateAlerts(input:{alertIDs:[%d],newStatus:StatusAcknowledged}){alertID status}}`, a), nil)
	assert.Equal(t, 200, r.Status)
	assert.Empty(t, r.Errors)
	assert.Equal(t, "null", string(r.Data["updateAlerts"]))
	assert.Equal(t, before, s2Snapshot(t, f))
	r = s2Call(t, f, "valid-current-B-Alert-after-transfer", "om", fmt.Sprintf(`mutation{updateAlerts(input:{alertIDs:[%d],newStatus:StatusAcknowledged}){alertID status}}`, b), nil)
	s2Allow(t, r, "updateAlerts")
	assert.JSONEq(t, fmt.Sprintf(`[{"alertID":%d,"status":"StatusAcknowledged"}]`, b), string(r.Data["updateAlerts"]))
	assert.Equal(t, "triggered", s2Scalar(t, f, `SELECT status FROM alerts WHERE id=$1`, a))
	assert.Equal(t, "active", s2Scalar(t, f, `SELECT status FROM alerts WHERE id=$1`, b))
	assert.Equal(t, h.UUID("s2-org-a"), s2Scalar(t, f, `SELECT organization_id::text FROM services WHERE id=$1`, h.UUID("svc-a")))
}

func TestD02S2B_B3(t *testing.T) {
	f := s2New(t)
	h := f.h
	sentinel := s2Rows(t, f, `SELECT * FROM user_contact_methods WHERE user_id<>$1`, h.UUID("b"))
	for _, actor := range []string{"pam", "paa", "b", "oa", "om"} {
		for _, op := range []string{"create", "update"} {
			t.Run("PF02/"+actor+"/"+op, func(t *testing.T) {
				before := s2Snapshot(t, f)
				q, field := "", ""
				if op == "create" {
					q = fmt.Sprintf(`mutation{createUserContactMethod(input:{userID:%q,name:%q,type:EMAIL,value:%q}){id name}}`, h.UUID("b"), "S2 created "+actor, actor+"-created@example.invalid")
					field = "createUserContactMethod"
				} else {
					q = fmt.Sprintf(`mutation{updateUserContactMethod(input:{id:%q,name:%q})}`, h.UUID("cm-b"), "S2 updated "+actor)
					field = "updateUserContactMethod"
				}
				r := s2Call(t, f, "PF02-"+op, actor, q, nil)
				if actor == "pam" || actor == "paa" || actor == "b" {
					s2Allow(t, r, field)
					if op == "update" {
						assert.Equal(t, "S2 updated "+actor, s2Scalar(t, f, `SELECT name FROM user_contact_methods WHERE id=$1`, h.UUID("cm-b")))
					} else if len(r.Errors) > 0 {
						assert.Equal(t, before, s2Snapshot(t, f))
					}
				} else {
					s2Deny(t, r)
					assert.Equal(t, before, s2Snapshot(t, f))
				}
				assert.Equal(t, sentinel, s2Rows(t, f, `SELECT * FROM user_contact_methods WHERE user_id<>$1`, h.UUID("b")))
			})
		}
	}
	for i, actor := range []string{"pam", "paa"} {
		for j, fields := range []string{"id", `id contactMethod{id name private}`} {
			t.Run(fmt.Sprintf("foreign-NR-projection/%s/%d", actor, j), func(t *testing.T) {
				delay := 10 + i*2 + j
				r := s2Call(t, f, "foreign-NR-create-projection", actor, fmt.Sprintf(`mutation{createUserNotificationRule(input:{userID:%q,contactMethodID:%q,delayMinutes:%d}){%s}}`, h.UUID("b"), h.UUID("cm-b"), delay, fields), nil)
				s2Allow(t, r, "createUserNotificationRule")
				assert.Equal(t, "1", s2Scalar(t, f, `SELECT count(*)::text FROM user_notification_rules WHERE user_id=$1 AND contact_method_id=$2 AND delay_minutes=$3`, h.UUID("b"), h.UUID("cm-b"), delay))
				r = s2Call(t, f, "foreign-user-NR-followup", actor, fmt.Sprintf(`query{user(id:%q){id notificationRules{id delayMinutes contactMethod{id name private}}}}`, h.UUID("b")), nil)
				s2Save(t, "projection-disposition", map[string]any{"store_row_exists": true, "followup_response": r.Raw, "nullable_contactMethod": true, "policy": "G-CM-FIELDS remains open"})
			})
		}
	}
	t.Run("privacy-regression", func(t *testing.T) {
		r := s2Call(t, f, "owner-private-raw-control", "aowner", fmt.Sprintf(`query{userContactMethod(id:%q){id name private value}}`, h.UUID("cm-aowner")), nil)
		s2Allow(t, r, "userContactMethod")
		assert.Contains(t, string(r.Raw), "aowner@example.invalid")
		for _, actor := range []string{"om", "oa", "pam", "paa"} {
			r := s2Call(t, f, "nonowner-private-raw", actor, fmt.Sprintf(`query{userContactMethod(id:%q){id name private value formattedValue}}`, h.UUID("cm-aowner")), nil)
			s2Allow(t, r, "userContactMethod")
			assert.NotContains(t, string(r.Raw), "aowner@example.invalid")
			before := s2Snapshot(t, f)
			r = s2Call(t, f, "nonowner-private-setter", actor, fmt.Sprintf(`mutation{updateUserContactMethod(input:{id:%q,private:false})}`, h.UUID("cm-aowner")), nil)
			s2Deny(t, r)
			assert.Equal(t, before, s2Snapshot(t, f))
			before = s2Snapshot(t, f)
			r = s2Call(t, f, "nonowner-test-refused", actor, fmt.Sprintf(`mutation{testContactMethod(id:%q)}`, h.UUID("cm-aowner")), nil)
			s2Deny(t, r)
			assert.Equal(t, before, s2Snapshot(t, f))
		}
		before := s2Snapshot(t, f)
		r = s2Call(t, f, "owner-wrong-verification-code", "aowner", fmt.Sprintf(`mutation{verifyContactMethod(input:{contactMethodID:%q,code:123456})}`, h.UUID("cm-aowner")), nil)
		s2Deny(t, r)
		assert.Equal(t, before, s2Snapshot(t, f))
	})
	t.Run("verify-owner-and-code", func(t *testing.T) {
		s2Exec(t, f, `UPDATE user_contact_methods SET disabled=true,pending=true WHERE id=$1`, h.UUID("cm-aowner"))
		s2Exec(t, f, `INSERT INTO user_verification_codes(id,contact_method_id,code,expires_at,sent) VALUES($1,$2,654321,now()+interval '1 hour',false)`, h.UUID("s2-vcode"), h.UUID("cm-aowner"))
		for _, actor := range []string{"om", "oa"} {
			before := s2Snapshot(t, f)
			r := s2Call(t, f, "nonowner-valid-code-denied", actor, fmt.Sprintf(`mutation{verifyContactMethod(input:{contactMethodID:%q,code:654321})}`, h.UUID("cm-aowner")), nil)
			s2Deny(t, r)
			assert.Equal(t, before, s2Snapshot(t, f))
		}
		for _, actor := range []string{"pam", "paa"} {
			before := s2Snapshot(t, f)
			r := s2Call(t, f, "PA-wrong-verification-code", actor, fmt.Sprintf(`mutation{verifyContactMethod(input:{contactMethodID:%q,code:123456})}`, h.UUID("cm-aowner")), nil)
			s2Deny(t, r)
			assert.Equal(t, before, s2Snapshot(t, f))
		}
		before := s2Snapshot(t, f)
		r := s2Call(t, f, "owner-incorrect-existing-code", "aowner", fmt.Sprintf(`mutation{verifyContactMethod(input:{contactMethodID:%q,code:123456})}`, h.UUID("cm-aowner")), nil)
		s2Deny(t, r)
		assert.Equal(t, before, s2Snapshot(t, f))
		r = s2Call(t, f, "owner-correct-code-control", "aowner", fmt.Sprintf(`mutation{verifyContactMethod(input:{contactMethodID:%q,code:654321})}`, h.UUID("cm-aowner")), nil)
		s2Allow(t, r, "verifyContactMethod")
		assert.Equal(t, "false", s2Scalar(t, f, `SELECT disabled::text FROM user_contact_methods WHERE id=$1`, h.UUID("cm-aowner")))
	})
}

func TestD02S2B_B4(t *testing.T) {
	f := s2New(t)
	h := f.h
	base := s2Snapshot(t, f)
	query := func(ids []string) string {
		parts := []string{}
		for _, id := range ids {
			parts = append(parts, fmt.Sprintf("%q", h.UUID(id)))
		}
		return fmt.Sprintf(`mutation{updateEscalationPolicy(input:{id:%q,stepIDs:[%s]})}`, h.UUID("ep-b"), strings.Join(parts, ","))
	}
	order := func() string {
		return s2Rows(t, f, `SELECT id,step_number FROM escalation_policy_steps WHERE escalation_policy_id=$1 ORDER BY step_number`, h.UUID("ep-b"))
	}
	t.Run("foreign-OA-denied", func(t *testing.T) {
		before := s2Snapshot(t, f)
		r := s2Call(t, f, "foreign-OA-reorder", "oa", query([]string{"step-b-1", "step-b-0"}), nil)
		assert.Equal(t, 200, r.Status)
		require.NotEmpty(t, r.Errors)
		// Generic error is paired with exact durable no-op and same-target OrgAdmin success below.
		assert.Equal(t, "unexpected error", fmt.Sprint(r.Errors[0]["message"]))
		assert.Equal(t, before, s2Snapshot(t, f))
	})
	t.Run("target-B-OrgAdmin-positive", func(t *testing.T) {
		r := s2Call(t, f, "target-B-OrgAdmin-reorder", "ba", query([]string{"step-b-1", "step-b-0"}), nil)
		s2Allow(t, r, "updateEscalationPolicy")
		r = s2Call(t, f, "target-B-OrgAdmin-restore", "ba", query([]string{"step-b-0", "step-b-1"}), nil)
		s2Allow(t, r, "updateEscalationPolicy")
		assert.Equal(t, base, s2Snapshot(t, f))
	})
	t.Run("foreign-PA-reorder", func(t *testing.T) {
		r := s2Call(t, f, "foreign-PA-reorder", "pam", query([]string{"step-b-1", "step-b-0"}), nil)
		s2Allow(t, r, "updateEscalationPolicy")
		assert.Equal(t, "0", s2Scalar(t, f, `SELECT step_number::text FROM escalation_policy_steps WHERE id=$1`, h.UUID("step-b-1")))
		assert.Equal(t, "1", s2Scalar(t, f, `SELECT step_number::text FROM escalation_policy_steps WHERE id=$1`, h.UUID("step-b-0")))
		s2Save(t, "persisted-reordered", order())
	})
	t.Run("wrong-foreign-parent-denied", func(t *testing.T) {
		before := s2Snapshot(t, f)
		r := s2Call(t, f, "PA-wrong-parent", "pam", query([]string{"step-b-1", "step-a-0"}), nil)
		s2Deny(t, r)
		assert.Equal(t, before, s2Snapshot(t, f))
	})
	t.Run("foreign-PA-remove", func(t *testing.T) {
		r := s2Call(t, f, "foreign-PA-remove", "pam", query([]string{"step-b-1"}), nil)
		s2Allow(t, r, "updateEscalationPolicy")
		assert.Equal(t, "0", s2Scalar(t, f, `SELECT count(*)::text FROM escalation_policy_steps WHERE id=$1`, h.UUID("step-b-0")))
		assert.Equal(t, "0", s2Scalar(t, f, `SELECT count(*)::text FROM escalation_policy_actions WHERE id=$1`, h.UUID("action-step-b-0")))
		assert.Equal(t, "1", s2Scalar(t, f, `SELECT count(*)::text FROM escalation_policy_actions WHERE id=$1`, h.UUID("action-step-b-1")))
		s2Save(t, "persisted-removed", order())
	})
	after := s2Snapshot(t, f)
	for table, rows := range base {
		if table == "escalation_policies" || table == "escalation_policy_steps" || table == "escalation_policy_actions" {
			var all, expected []map[string]any
			require.NoError(t, json.Unmarshal([]byte(rows), &all))
			for _, row := range all {
				if row["id"] == h.UUID("step-b-0") || row["id"] == h.UUID("action-step-b-0") {
					continue
				}
				if table == "escalation_policies" && row["id"] == h.UUID("ep-b") {
					row["step_count"] = float64(1)
				}
				if table == "escalation_policy_steps" && row["id"] == h.UUID("step-b-1") {
					row["step_number"] = float64(0)
				}
				expected = append(expected, row)
			}
			encoded, e := json.Marshal(expected)
			require.NoError(t, e)
			assert.JSONEq(t, string(encoded), after[table], table)
		} else {
			assert.Equal(t, rows, after[table], table)
		}
	}
	assert.Equal(t, "2", s2Scalar(t, f, `SELECT count(*)::text FROM escalation_policy_steps WHERE escalation_policy_id=$1`, h.UUID("ep-a")))
	assert.Equal(t, "2", s2Scalar(t, f, `SELECT count(*)::text FROM escalation_policy_actions WHERE escalation_policy_step_id IN (SELECT id FROM escalation_policy_steps WHERE escalation_policy_id=$1)`, h.UUID("ep-a")))
}
