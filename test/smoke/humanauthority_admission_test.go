package smoke

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/target/goalert/auth"
	"github.com/target/goalert/graphql2"
	"github.com/target/goalert/graphql2/graphqlapp"
	"github.com/target/goalert/organization"
	"github.com/target/goalert/permission"
	"github.com/target/goalert/user"
)

// The existing smoke entry point supplies private PostgreSQL and real signed
// sessions. Exported evidence contains identities/digests, never token or hash
// material. No notification is dispatched by this matrix.
func authorityHTTP(t *testing.T, f *s2Fixture, actor, query string) *s2Result {
	t.Helper()
	body, err := json.Marshal(map[string]any{"query": query})
	require.NoError(t, err)
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, f.h.URL()+"/api/graphql", bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: f.tokens[actor]})
	resp, err := (&http.Client{Timeout: 20 * time.Second}).Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	r := &s2Result{Status: resp.StatusCode, Raw: raw}
	require.Equal(t, http.StatusOK, resp.StatusCode, "%s", raw)
	require.NoError(t, json.Unmarshal(raw, r))
	return r
}

func authorityCleanupExec(t *testing.T, f *s2Fixture, query string, args ...any) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := f.h.App().DB().ExecContext(ctx, query, args...)
	require.NoError(t, err)
}

func authorityDenied(t *testing.T, r *s2Result) {
	t.Helper()
	require.Equal(t, http.StatusOK, r.Status)
	require.NotEmpty(t, r.Errors)
	for _, e := range r.Errors {
		require.Contains(t, fmt.Sprint(e["message"]), "access denied")
		require.NotContains(t, fmt.Sprint(e), "GRAPHQL_VALIDATION_FAILED")
	}
}

func authorityOperations(f *s2Fixture, actor, secondSession string) []string {
	id := f.h.UUID(actor)
	return []string{
		fmt.Sprintf(`mutation{updateUser(input:{id:%q,name:"Forbidden invalid authority"})}`, id),
		fmt.Sprintf(`mutation{addAuthSubject(input:{userID:%q,providerID:"synthetic-authority",subjectID:"forbidden"})}`, id),
		fmt.Sprintf(`mutation{deleteAuthSubject(input:{userID:%q,providerID:"synthetic-authority",subjectID:%q})}`, id, actor+"-existing"),
		fmt.Sprintf(`mutation{createBasicAuth(input:{userID:%q,username:"forbidden-authority",password:"S2-Synthetic-Password-Only-915!"})}`, f.h.UUID("spare")),
		fmt.Sprintf(`mutation{updateBasicAuth(input:{userID:%q,oldPassword:"S2-Synthetic-Password-Only-814!",password:"S2-Synthetic-Password-Only-915!"})}`, id),
		`mutation{endAllAuthSessionsByCurrentUser}`,
		fmt.Sprintf(`mutation{deleteAll(input:[{type:userSession,id:%q}])}`, secondSession),
		fmt.Sprintf(`mutation{deleteAll(input:[{type:user,id:%q}])}`, f.h.UUID("spare")),
		fmt.Sprintf(`mutation{deleteAll(input:[{type:contactMethod,id:%q},{type:notificationRule,id:%q}])}`, f.h.UUID("authority-cm-"+actor), f.h.UUID("authority-nr-"+actor)),
		fmt.Sprintf(`mutation{updateUserContactMethod(input:{id:%q,name:"Forbidden CM"})}`, f.h.UUID("authority-cm-"+actor)),
		fmt.Sprintf(`mutation{createUserNotificationRule(input:{userID:%q,contactMethodID:%q,delayMinutes:7}){id}}`, id, f.h.UUID("authority-cm-"+actor)),
		`{currentOrganizationContext{userID isPlatformAdmin}}`,
		fmt.Sprintf(`mutation{createService(input:{name:"Forbidden Service",targetOrganizationID:%q,newEscalationPolicy:{name:"Forbidden nested EP"}}){id}}`, f.h.UUID("s2-org-b")),
		fmt.Sprintf(`mutation{createEscalationPolicy(input:{name:"Forbidden EP",targetOrganizationID:%q}){id}}`, f.h.UUID("s2-org-b")),
		fmt.Sprintf(`mutation{createSchedule(input:{name:"Forbidden Schedule",timeZone:"Asia/Shanghai",targetOrganizationID:%q}){id}}`, f.h.UUID("s2-org-b")),
		fmt.Sprintf(`mutation{createRotation(input:{name:"Forbidden Rotation",timeZone:"Asia/Shanghai",type:weekly,start:"2026-11-08T00:00:00Z",shiftLength:1,targetOrganizationID:%q}){id}}`, f.h.UUID("s2-org-b")),
	}
}

func TestHumanAuthoritySignedHTTPAdmission(t *testing.T) {
	f := globalOrganizationFixture(t)
	// Add the missing ordinary / Default MULTIPLE row without changing shared
	// fixtures used by the other product tests.
	s2Exec(t, f, `INSERT INTO users(id,name,email,role) VALUES($1,'Synthetic ordinary multiple','','user')`, f.h.UUID("odm"))
	s2Exec(t, f, `INSERT INTO user_organization_assignments(user_id,effective_organization_id,effective_organization_classification,organization_role,mapping_outcome,authoritative_evaluated_at,source_config_version,matched_count) VALUES($1,$2,'DEFAULT','NONE','MULTIPLE',now(),'authority-regression',2)`, f.h.UUID("odm"), organization.DefaultOrganizationID)
	token, err := f.h.App().AuthHandler.CreateSession(t.Context(), "Synthetic ordinary multiple", f.h.UUID("odm"))
	require.NoError(t, err)
	f.tokens["odm"], err = token.Encode(f.h.App().SessionKeyring.Sign)
	require.NoError(t, err)
	f.sessions["odm"] = token.ID.String()
	// Corrupt-state control is restricted to this disposable database. Retain
	// and restore the actual constraint, never edit a migration or shared DB.
	constraint := s2Scalar(t, f, `SELECT pg_get_constraintdef(oid) FROM pg_constraint WHERE conrelid='user_organization_assignments'::regclass AND conname='user_organization_assignments_mapping_truth'`)
	s2Exec(t, f, `ALTER TABLE user_organization_assignments DROP CONSTRAINT user_organization_assignments_mapping_truth`)
	t.Cleanup(func() {
		authorityCleanupExec(t, f, `ALTER TABLE user_organization_assignments ADD CONSTRAINT user_organization_assignments_mapping_truth `+constraint)
	})
	system := permission.SystemContext(f.h.App().Context(t.Context()), "AuthorityFixture")
	password, err := f.h.App().AuthBasicStore.NewHashedPassword(system, "S2-Synthetic-Password-Only-814!")
	require.NoError(t, err)
	for _, actor := range []string{"pd0", "pdm", "od", "odm", "pam", "oa", "om"} {
		t.Run(actor, func(t *testing.T) {
			id := f.h.UUID(actor)
			initialToken, initialSession := f.tokens[actor], f.sessions[actor]
			assignment := s2Scalar(t, f, `SELECT to_jsonb(a)::text FROM user_organization_assignments a WHERE user_id=$1`, id)
			restore := func() {
				authorityCleanupExec(t, f, `DELETE FROM user_organization_assignments WHERE user_id=$1`, id)
				authorityCleanupExec(t, f, `INSERT INTO user_organization_assignments SELECT * FROM jsonb_populate_record(NULL::user_organization_assignments,$1::jsonb)`, assignment)
			}
			t.Cleanup(restore)
			s2Exec(t, f, `INSERT INTO auth_subjects(user_id,provider_id,subject_id) VALUES($1,'synthetic-authority',$2)`, id, actor+"-existing")
			tx, err := f.h.App().DB().BeginTx(t.Context(), nil)
			require.NoError(t, err)
			require.NoError(t, f.h.App().AuthBasicStore.CreateTx(system, tx, id, "authority-"+actor, password))
			require.NoError(t, tx.Commit())
			second, err := f.h.App().AuthHandler.CreateSession(t.Context(), "Synthetic other session", id)
			require.NoError(t, err)
			dest, err := json.Marshal(map[string]any{"Type": "builtin-smtp-email", "Args": map[string]string{"email_address": "authority-" + actor + "@example.invalid"}})
			require.NoError(t, err)
			s2Exec(t, f, `INSERT INTO user_contact_methods(id,user_id,name,dest,private,disabled,pending) VALUES($1,$2,'Authority CM',$3,true,false,false)`, f.h.UUID("authority-cm-"+actor), id, dest)
			s2Exec(t, f, `INSERT INTO user_notification_rules(id,user_id,contact_method_id,delay_minutes) VALUES($1,$2,$3,0)`, f.h.UUID("authority-nr-"+actor), id, f.h.UUID("authority-cm-"+actor))
			q := fmt.Sprintf(`mutation{updateUser(input:{id:%q,name:"Valid Normal self"})}`, id)
			identity := a12Call(t, f, "valid-current-authority", actor, `{currentOrganizationContext{userID isPlatformAdmin}}`, nil)
			require.Empty(t, identity.Errors)
			valid := a12Call(t, f, "valid-self-profile-boundary", actor, q, nil)
			isDefault := actor == "pd0" || actor == "pdm" || actor == "od" || actor == "odm"
			if isDefault {
				authorityDenied(t, valid)
			} else {
				require.Empty(t, valid.Errors)
			}
			operations := authorityOperations(f, actor, second.ID.String())
			if isDefault {
				before, auditBefore := a12BusinessSnapshot(t, f), a12AuditSnapshot(t, f)
				for _, query := range operations[:11] {
					query = strings.ReplaceAll(query, f.h.UUID("spare"), id)
					authorityDenied(t, a12Call(t, f, "valid-Default-self-sensitive-denied", actor, query, nil))
					require.Equal(t, before, a12BusinessSnapshot(t, f))
					require.Equal(t, auditBefore, a12AuditSnapshot(t, f))
				}
			}
			for _, scenario := range []string{"assignment-missing", "assignment-contradictory", "authority-read-error"} {
				t.Run(scenario, func(t *testing.T) {
					restore()
					switch scenario {
					case "assignment-missing":
						s2Exec(t, f, `DELETE FROM user_organization_assignments WHERE user_id=$1`, id)
					case "assignment-contradictory":
						s2Exec(t, f, `UPDATE user_organization_assignments SET matched_count=-1 WHERE user_id=$1`, id)
					}
					before, auditBefore := a12BusinessSnapshot(t, f), a12AuditSnapshot(t, f)
					if scenario == "authority-read-error" {
						// Canonical authentication still reads its real Session/User;
						// only the following authority SELECT fails in PostgreSQL.
						s2Exec(t, f, `ALTER TABLE user_organization_assignments RENAME TO authority_unavailable`)
						defer func() {
							s2Exec(t, f, `ALTER TABLE authority_unavailable RENAME TO user_organization_assignments`)
							require.Equal(t, before, a12BusinessSnapshot(t, f))
							require.Equal(t, auditBefore, a12AuditSnapshot(t, f))
							s2Save(t, "authority-read-error-complete-state", map[string]any{"before": before, "after": a12BusinessSnapshot(t, f), "audit_before": auditBefore, "audit_after": a12AuditSnapshot(t, f)})
						}()
					}
					for index, query := range operations {
						r := authorityHTTP(t, f, actor, query)
						s2Save(t, fmt.Sprintf("authority-%s-%d", scenario, index), map[string]any{"actor": actor, "session_id": initialSession, "http_status": r.Status, "response": r.Raw, "operation_index": index})
						if scenario != "authority-read-error" {
							after := a12BusinessSnapshot(t, f)
							s2Save(t, fmt.Sprintf("authority-%s-%d-state", scenario, index), map[string]any{"before": before, "after": after, "audit_before": auditBefore, "audit_after": a12AuditSnapshot(t, f)})
							require.Equal(t, before, after)
							require.Equal(t, auditBefore, a12AuditSnapshot(t, f))
						}
						authorityDenied(t, r)
					}
					if scenario == "authority-read-error" {
						// Restore before taking complete snapshots. The deferred undo
						// above also protects early test exits.
						return
					}
					// All business/auth/basic/session and unrelated sentinel rows
					// remain identical. Admission rejection creates no audit event.
					require.Equal(t, before, a12BusinessSnapshot(t, f))
					require.Equal(t, auditBefore, a12AuditSnapshot(t, f))
					s2Save(t, scenario+"-complete-state", map[string]any{"before": before, "after": a12BusinessSnapshot(t, f), "audit_before": auditBefore, "audit_after": a12AuditSnapshot(t, f)})
				})
				if scenario == "authority-read-error" {
					// The failed read must leave all material unchanged too.
					require.Equal(t, "1", s2Scalar(t, f, `SELECT count(*)::text FROM auth_user_sessions WHERE id=$1`, second.ID.String()))
				}
			}
			restore()
			require.Empty(t, a12Call(t, f, "same-session-authority-restored", actor, `{currentOrganizationContext{userID}}`, nil).Errors)
			require.Equal(t, initialToken, f.tokens[actor])
			require.Equal(t, initialSession, f.sessions[actor])
			if actor == "pd0" || actor == "pdm" || actor == "pam" {
				q = fmt.Sprintf(`mutation{updateUser(input:{id:%q,name:"Approved Global Normal target"})}`, f.h.UUID("b"))
				require.Empty(t, a12Call(t, f, "valid-PA-global-management", actor, q, nil).Errors)
				s2Exec(t, f, `UPDATE users SET role='user' WHERE id=$1`, id)
				before := a12BusinessSnapshot(t, f)
				authorityDenied(t, a12Call(t, f, "same-session-PA-revoked", actor, q, nil))
				require.Equal(t, before, a12BusinessSnapshot(t, f))
				s2Exec(t, f, `UPDATE users SET role='admin' WHERE id=$1`, id)
			}
		})
	}
}

func TestHumanAuthorityValidNormalSelfService(t *testing.T) {
	f := globalOrganizationFixture(t)
	for _, actor := range []string{"pam", "oa", "om"} {
		t.Run(actor, func(t *testing.T) {
			id := f.h.UUID(actor)
			for _, query := range []string{
				fmt.Sprintf(`mutation{updateUser(input:{id:%q,name:"Approved self profile"})}`, id),
				fmt.Sprintf(`mutation{addAuthSubject(input:{userID:%q,providerID:"synthetic-self",subjectID:%q})}`, id, actor),
				fmt.Sprintf(`mutation{deleteAuthSubject(input:{userID:%q,providerID:"synthetic-self",subjectID:%q})}`, id, actor),
				fmt.Sprintf(`mutation{createBasicAuth(input:{userID:%q,username:%q,password:"S2-Synthetic-Password-Only-814!"})}`, id, "self-"+actor),
				fmt.Sprintf(`mutation{updateBasicAuth(input:{userID:%q,oldPassword:"S2-Synthetic-Password-Only-814!",password:"S2-Synthetic-Password-Only-915!"})}`, id),
			} {
				r := a12Call(t, f, "Normal-self-service", actor, query, nil)
				if strings.Contains(query, "deleteAuthSubject") && actor != "pam" {
					authorityDenied(t, r) // existing Store contract: Admin/System only
				} else {
					require.Empty(t, r.Errors)
				}
			}
			other, err := f.h.App().AuthHandler.CreateSession(context.Background(), "Synthetic session to end", id)
			require.NoError(t, err)
			r := a12Call(t, f, "Normal-end-other-sessions", actor, `mutation{endAllAuthSessionsByCurrentUser}`, nil)
			require.Empty(t, r.Errors)
			require.Equal(t, "0", s2Scalar(t, f, `SELECT count(*)::text FROM auth_user_sessions WHERE id=$1`, other.ID.String()))
			require.Equal(t, "1", s2Scalar(t, f, `SELECT count(*)::text FROM auth_user_sessions WHERE id=$1`, f.sessions[actor]))
		})
	}
}

func TestHumanAuthoritySystemAndIntegrationCompatibility(t *testing.T) {
	f := globalOrganizationFixture(t)
	ctx := permission.SystemContext(f.h.App().Context(t.Context()), "AuthorityRegression")
	direct := &graphqlapp.App{DB: f.h.App().DB(), UserStore: f.h.App().UserStore}
	name := "Trusted System profile update"
	ok, err := direct.Mutation().UpdateUser(ctx, graphql2.UpdateUserInput{ID: f.h.UUID("om"), Name: &name})
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, name, s2Scalar(t, f, `SELECT name FROM users WHERE id=$1`, f.h.UUID("om")))
	subject := user.AuthSubject{UserID: f.h.UUID("om"), ProviderID: "synthetic-system", SubjectID: "trusted-system"}
	ok, err = direct.Mutation().AddAuthSubject(ctx, subject)
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, "1", s2Scalar(t, f, `SELECT count(*)::text FROM auth_subjects WHERE provider_id='synthetic-system'`))
	ok, err = direct.Mutation().DeleteAuthSubject(ctx, subject)
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, "0", s2Scalar(t, f, `SELECT count(*)::text FROM auth_subjects WHERE provider_id='synthetic-system'`))
	s2Exec(t, f, `INSERT INTO integration_keys(id,service_id,name,type) VALUES($1,$2,'Synthetic IntegrationPrincipal','generic')`, f.h.UUID("authority-integration"), f.h.UUID("svc-b"))
	request := func(path string, payload any, bearer bool, want int) {
		t.Helper()
		body, err := json.Marshal(payload)
		require.NoError(t, err)
		req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, f.h.URL()+path, bytes.NewReader(body))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")
		if bearer {
			req.Header.Set("Authorization", "Bearer "+f.h.UUID("authority-integration"))
		}
		resp, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		raw, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		require.Equal(t, want, resp.StatusCode)
		s2Save(t, "non-Human-HTTP", map[string]any{"path": path, "bearer": "synthetic IntegrationPrincipal; token omitted", "http_status": resp.StatusCode, "response": string(raw)})
	}
	request("/api/v2/generic/incoming", map[string]any{"summary": "Synthetic approved integration", "details": "No notification dispatch", "dedup": "authority-regression"}, true, 200)
	require.Equal(t, "1", s2Scalar(t, f, `SELECT count(*)::text FROM alerts WHERE service_id=$1 AND summary='Synthetic approved integration'`, f.h.UUID("svc-b")))
	require.Equal(t, "0", s2Scalar(t, f, `SELECT count(*)::text FROM alerts WHERE service_id=$1`, f.h.UUID("svc-a")))
	before := a12BusinessSnapshot(t, f)
	request("/api/graphql", map[string]any{"query": `{currentOrganizationContext{userID}}`}, true, 401)
	request("/api/graphql", map[string]any{"query": `mutation{endAllAuthSessionsByCurrentUser}`}, false, 401)
	require.Equal(t, before, a12BusinessSnapshot(t, f))
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, f.h.URL()+"/health", nil)
	require.NoError(t, err)
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	require.Equal(t, http.StatusOK, resp.StatusCode)
}
