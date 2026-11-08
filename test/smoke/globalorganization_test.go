package smoke

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/target/goalert/auth"
	"github.com/target/goalert/executioncontext"
	"github.com/target/goalert/graphql2/graphqlapp"
	"github.com/target/goalert/organization"
	"github.com/target/goalert/permission"
)

func a12Call(t *testing.T, f *s2Fixture, label, actor, query string, variables any) *s2Result {
	t.Helper()
	before := a12BusinessSnapshot(t, f)
	beforeAudit := a12AuditSnapshot(t, f)
	r := s2Call(t, f, label, actor, query, variables)
	var response any = r.Raw
	if !json.Valid(r.Raw) {
		response = string(r.Raw)
	}
	s2Save(t, label+"-complete-business-state", map[string]any{
		"actor": actor, "actor_id": f.h.UUID(actor), "http_status": r.Status, "response": response,
		"before": before, "after": a12BusinessSnapshot(t, f),
		"audit_before": beforeAudit, "audit_after": a12AuditSnapshot(t, f),
	})
	require.Equal(t, http.StatusOK, r.Status, "a schema/transport error is not a successful GraphQL operation: %s", r.Raw)
	return r
}

func a12AuditSnapshot(t *testing.T, f *s2Fixture) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, table := range []string{"global_root_create_audit_events", "service_update_audit_events", "schedule_rotation_update_audit_events"} {
		out[table] = s2Rows(t, f, "SELECT * FROM "+table)
	}
	return out
}

func a12HumanContext(t *testing.T, f *s2Fixture, actor string) context.Context {
	t.Helper()
	role := permission.Role(s2Scalar(t, f, `SELECT role FROM users WHERE id=$1`, f.h.UUID(actor)))
	ctx := permission.UserSourceContext(t.Context(), f.h.UUID(actor), role, &permission.SourceInfo{Type: permission.SourceTypeAuthProvider, ID: f.sessions[actor]})
	requester, err := auth.NewRequester(f.h.UUID(actor), f.sessions[actor])
	require.NoError(t, err)
	constructor, err := executioncontext.NewHumanExecutionContextConstructor(f.h.App().OrganizationStore)
	require.NoError(t, err)
	ctx = auth.WithRequester(ctx, requester)
	value, err := constructor.Construct(ctx)
	require.NoError(t, err)
	return executioncontext.WithExecutionContext(ctx, value)
}

func TestGlobalOrganizationClientCannotSupplyAuthority(t *testing.T) {
	f := globalOrganizationFixture(t)
	before := a12BusinessSnapshot(t, f)
	for _, signed := range []bool{false, true} {
		for _, q := range []string{`{manageableOrganizations{nodes{id}}}`, fmt.Sprintf(`{services(input:{targetOrganizationID:%q}){nodes{id}}}`, f.h.UUID("s2-org-b"))} {
			body, err := json.Marshal(map[string]any{"query": q})
			require.NoError(t, err)
			req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, f.h.URL()+"/api/graphql", bytes.NewReader(body))
			require.NoError(t, err)
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Platform-Admin", "true")
			req.Header.Set("X-User-ID", f.h.UUID("pam"))
			req.Header.Set("X-Organization-ID", f.h.UUID("s2-org-b"))
			if signed {
				req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: f.tokens["oa"]})
			}
			resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
			require.NoError(t, err)
			raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
			require.NoError(t, err)
			require.NoError(t, resp.Body.Close())
			s2Save(t, "untrusted-headers", map[string]any{"signed_as_ordinary_org_admin": signed, "query": q, "header_names": []string{"X-Platform-Admin", "X-User-ID", "X-Organization-ID"}, "http_status": resp.StatusCode, "response": string(raw), "before": before, "after": a12BusinessSnapshot(t, f)})
			if signed {
				var r s2Result
				require.NoError(t, json.Unmarshal(raw, &r))
				r.Status = resp.StatusCode
				s2Deny(t, &r)
			} else {
				require.Equal(t, 401, resp.StatusCode)
			}
			require.NotContains(t, string(raw), f.h.UUID("svc-b"))
			require.Equal(t, before, a12BusinessSnapshot(t, f))
		}
	}
}

func globalOrganizationFixture(t *testing.T) *s2Fixture {
	t.Helper()
	f := s2New(t)
	for _, actor := range []string{"pd0", "pdm", "od"} {
		role, outcome, count := "admin", "ZERO", 0
		if actor == "pdm" {
			outcome = "MULTIPLE"
			count = 2
		}
		if actor == "od" {
			role = "user"
		}
		s2Exec(t, f, `INSERT INTO users(id,name,email,role) VALUES($1,$2,'',$3)`, f.h.UUID(actor), "A12 synthetic "+actor, role)
		s2Exec(t, f, `INSERT INTO user_organization_assignments(user_id,effective_organization_id,effective_organization_classification,effective_normal_organization_id,organization_role,mapping_outcome,authoritative_evaluated_at,source_config_version,matched_count)
		 VALUES($1,$2,'DEFAULT',NULL,'NONE',$3,now(),'a12-synthetic',$4)`, f.h.UUID(actor), organization.DefaultOrganizationID, outcome, count)
		token, err := f.h.App().AuthHandler.CreateSession(context.Background(), "A12 synthetic "+actor, f.h.UUID(actor))
		require.NoError(t, err)
		f.tokens[actor], err = token.Encode(f.h.App().SessionKeyring.Sign)
		require.NoError(t, err)
		f.sessions[actor] = s2Scalar(t, f, `SELECT id::text FROM auth_user_sessions WHERE user_id=$1`, f.h.UUID(actor))
	}
	for _, org := range []string{"a", "b"} {
		s2Exec(t, f, `INSERT INTO rotations(id,organization_id,name,type,start_time,shift_length,time_zone) VALUES($1,$2,$3,'weekly',now(),1,'Asia/Shanghai')`, f.h.UUID("rot-"+org), f.h.UUID("s2-org-"+org), "A12 Rotation "+org)
		owner := "aowner"
		if org == "b" {
			owner = "b"
		}
		s2Exec(t, f, `INSERT INTO rotation_participants(id,rotation_id,user_id,position) VALUES($1,$2,$3,0)`, f.h.UUID("participant-"+org), f.h.UUID("rot-"+org), f.h.UUID(owner))
	}
	return f
}

func TestGlobalOrganizationCurrentAuthority(t *testing.T) {
	f := globalOrganizationFixture(t)
	q := `{currentOrganizationContext{userID isPlatformAdmin} manageableOrganizations{nodes{id}}}`
	r := a12Call(t, f, "current-Default-PA-positive", "pd0", q, nil)
	require.Empty(t, r.Errors)
	s2Exec(t, f, `UPDATE users SET role='user' WHERE id=$1`, f.h.UUID("pd0"))
	before := a12BusinessSnapshot(t, f)
	r = a12Call(t, f, "current-PA-revoked-same-signed-session", "pd0", q, nil)
	s2Deny(t, r)
	r = a12Call(t, f, "current-revoked-PA-minimal-identity", "pd0", `{currentOrganizationContext{userID isPlatformAdmin}}`, nil)
	require.Empty(t, r.Errors)
	require.Contains(t, string(r.Data["currentOrganizationContext"]), `"isPlatformAdmin":false`)
	input := a12CreateInput("Schedule", "A12 revoked PA must not create")
	input["targetOrganizationID"] = f.h.UUID("s2-org-b")
	s2Deny(t, a12Create(t, f, "pd0", "Schedule", input))
	require.Equal(t, before, a12BusinessSnapshot(t, f))
	s2Exec(t, f, `UPDATE users SET role='admin' WHERE id=$1`, f.h.UUID("pd0"))
	require.Empty(t, a12Call(t, f, "current-PA-restored-control", "pd0", q, nil).Errors)
	s2Exec(t, f, `DELETE FROM auth_user_sessions WHERE id=$1`, f.sessions["pd0"])
	r = s2Call(t, f, "revoked-Default-PA-session", "pd0", q, nil)
	require.Equal(t, 401, r.Status)
	s2Exec(t, f, `DELETE FROM user_organization_assignments WHERE user_id=$1`, f.h.UUID("pdm"))
	before = a12BusinessSnapshot(t, f)
	r = s2Call(t, f, "missing-Default-assignment", "pdm", q, nil)
	require.True(t, r.Status == 401 || r.Status == 403 || len(r.Errors) > 0)
	require.NotContains(t, string(r.Raw), f.h.UUID("s2-org-b"))
	require.Equal(t, before, a12BusinessSnapshot(t, f))
}

func TestGlobalOrganizationCursorAndFallback(t *testing.T) {
	f := globalOrganizationFixture(t)
	direct := &graphqlapp.App{DB: f.h.App().DB(), ServiceStore: f.h.App().ServiceStore, PolicyStore: f.h.App().EscalationStore, ScheduleStore: f.h.App().ScheduleStore, RotationStore: f.h.App().RotationStore}
	before := a12BusinessSnapshot(t, f)
	for _, row := range []struct{ single, list, key string }{{"service", "services", "svc"}, {"escalationPolicy", "escalationPolicies", "ep"}, {"schedule", "schedules", "sched"}, {"rotation", "rotations", "rot"}} {
		t.Run(row.single, func(t *testing.T) {
			query := fmt.Sprintf(`query($target:ID,$after:String){result:%s(input:{targetOrganizationID:$target,first:1,after:$after}){nodes{id organization{id}}pageInfo{endCursor}}}`, row.list)
			r := a12Call(t, f, "Home-cursor", "pam", query, map[string]any{"target": f.h.UUID("s2-org-a")})
			require.Empty(t, r.Errors)
			var c struct{ PageInfo struct{ EndCursor string } }
			require.NoError(t, json.Unmarshal(r.Data["result"], &c))
			require.NotEmpty(t, c.PageInfo.EndCursor)
			r = a12Call(t, f, "cursor-cannot-restore-Home-target", "pam", query, map[string]any{"target": f.h.UUID("s2-org-b"), "after": c.PageInfo.EndCursor})
			require.Empty(t, r.Errors)
			require.NotContains(t, string(r.Data["result"]), f.h.UUID(row.key+"-a"))
			r = a12Call(t, f, "ordinary-cursor-cannot-grant-Foreign", "oa", query, map[string]any{"target": f.h.UUID("s2-org-b"), "after": c.PageInfo.EndCursor})
			s2Deny(t, r)
			for _, actor := range []string{"pam", "pd0", "pdm", "oa"} {
				ctx := a12HumanContext(t, f, actor)
				var got any
				var err error
				id := f.h.UUID(row.key + "-b")
				switch row.single {
				case "service":
					v, e := direct.FindOneService(ctx, id)
					err = e
					if v != nil {
						got = v.ID
					}
				case "escalationPolicy":
					v, e := direct.FindOnePolicy(ctx, id)
					err = e
					if v != nil {
						got = v.ID
					}
				case "schedule":
					v, e := direct.FindOneSchedule(ctx, id)
					err = e
					if v != nil {
						got = v.ID
					}
				case "rotation":
					v, e := direct.FindOneRotation(ctx, id)
					err = e
					if v != nil {
						got = v.ID
					}
				}
				if actor != "oa" {
					require.NoError(t, err)
					require.Equal(t, id, got)
				} else {
					require.ErrorIs(t, err, sql.ErrNoRows)
					require.NotEqual(t, id, got)
				}
				s2Save(t, "nonloader-root-read", map[string]any{"actor": actor, "root": row.single, "target": f.h.UUID("s2-org-b"), "returned_id": got})
			}
		})
	}
	require.Equal(t, before, a12BusinessSnapshot(t, f))
}

func TestGlobalOrganizationReadDirectory(t *testing.T) {
	f := globalOrganizationFixture(t)
	before := s2Snapshot(t, f)
	for _, actor := range []string{"paa", "pam", "pd0", "pdm", "oa", "om", "od"} {
		t.Run(actor, func(t *testing.T) {
			r := a12Call(t, f, "identity", actor, `{currentOrganizationContext{userID homeOrganization{id displayName} homeClassification homeOrgRole isPlatformAdmin canManageOrganizations canReadGlobalRoots canCreateGlobalRoots}}`, nil)
			require.Empty(t, r.Errors)
			require.Equal(t, 200, r.Status)
			require.Contains(t, string(r.Raw), f.h.UUID(actor))
			pa := actor == "paa" || actor == "pam" || actor == "pd0" || actor == "pdm"
			r = a12Call(t, f, "bounded-directory", actor, `{manageableOrganizations(first:1){nodes{id displayName}pageInfo{hasNextPage endCursor}}}`, nil)
			if !pa {
				s2Deny(t, r)
				return
			}
			require.Empty(t, r.Errors)
			require.NotContains(t, string(r.Raw), organization.DefaultOrganizationID)
			var conn struct {
				Nodes    []struct{ ID, DisplayName string }
				PageInfo struct {
					HasNextPage bool
					EndCursor   string
				}
			}
			require.NoError(t, json.Unmarshal(r.Data["manageableOrganizations"], &conn))
			require.Len(t, conn.Nodes, 1)
			require.True(t, conn.PageInfo.HasNextPage)
			r = a12Call(t, f, "directory-second-page", actor, `query($after:String){manageableOrganizations(first:1,after:$after){nodes{id displayName}pageInfo{hasNextPage endCursor}}}`, map[string]any{"after": conn.PageInfo.EndCursor})
			require.Empty(t, r.Errors)
			require.NotContains(t, string(r.Data["manageableOrganizations"]), conn.Nodes[0].ID)
		})
	}
	require.Equal(t, before, s2Snapshot(t, f), "read operations changed business state")
}

func TestGlobalOrganizationFourRootReads(t *testing.T) {
	f := globalOrganizationFixture(t)
	roots := []struct{ single, list, typ, key, nested string }{
		{"service", "services", "Service", "svc", `escalationPolicy{id name steps{id targets{id type name}}}`},
		{"escalationPolicy", "escalationPolicies", "EscalationPolicy", "ep", `steps{id targets{id type name}} assignedTo{id type name}`},
		{"schedule", "schedules", "Schedule", "sched", `targets{scheduleID target{id type name}} assignedTo{id type name} temporarySchedules{start end} onCallNotificationRules{id}`},
		{"rotation", "rotations", "Rotation", "rot", `users{id name} userIDs`},
	}
	before := s2Snapshot(t, f)
	for _, actor := range []string{"paa", "pam", "pd0", "pdm", "oa", "om", "od"} {
		for _, root := range roots {
			t.Run(actor+"/"+root.single, func(t *testing.T) {
				pa := actor == "paa" || actor == "pam" || actor == "pd0" || actor == "pdm"
				query := fmt.Sprintf(`query($target:ID){result:%s(input:{targetOrganizationID:$target,first:5}){nodes{...Root}pageInfo{hasNextPage endCursor}}} fragment Root on %s{id name organization{id displayName}}`, root.list, root.typ)
				r := a12Call(t, f, "explicit-foreign-list", actor, query, map[string]any{"target": f.h.UUID("s2-org-b")})
				if pa {
					require.Empty(t, r.Errors)
					require.Contains(t, string(r.Data["result"]), f.h.UUID(root.key+"-b"))
					require.NotContains(t, string(r.Data["result"]), f.h.UUID(root.key+"-a"))
				} else {
					s2Deny(t, r)
				}
				direct := fmt.Sprintf(`query($id:ID!){result:%s(id:$id){id name organization{id displayName} %s}}`, root.single, root.nested)
				r = a12Call(t, f, "direct-root-and-nested", actor, direct, map[string]any{"id": f.h.UUID(root.key + "-b")})
				if pa {
					require.Empty(t, r.Errors)
					require.Contains(t, string(r.Data["result"]), f.h.UUID("s2-org-b"))
				} else {
					require.True(t, len(r.Errors) > 0 || string(r.Data["result"]) == "null")
				}
				r = a12Call(t, f, "implicit-list", actor, fmt.Sprintf(`{result:%s{nodes{id}}}`, root.list), nil)
				if actor == "pd0" || actor == "pdm" || actor == "od" {
					s2Deny(t, r)
				} else {
					require.Empty(t, r.Errors)
					require.Contains(t, string(r.Data["result"]), f.h.UUID(root.key+"-a"))
					require.NotContains(t, string(r.Data["result"]), f.h.UUID(root.key+"-b"))
				}
				if pa {
					q := fmt.Sprintf(`query($a:ID,$b:ID){a:%s(input:{targetOrganizationID:$a}){nodes{id organization{id}}} b:%s(input:{targetOrganizationID:$b}){nodes{id organization{id}}}}`, root.list, root.list)
					r = a12Call(t, f, "independent-alias-targets", actor, q, map[string]any{"a": f.h.UUID("s2-org-a"), "b": f.h.UUID("s2-org-b")})
					require.Empty(t, r.Errors)
					require.Contains(t, string(r.Data["a"]), f.h.UUID(root.key+"-a"))
					require.NotContains(t, string(r.Data["a"]), f.h.UUID(root.key+"-b"))
					require.Contains(t, string(r.Data["b"]), f.h.UUID(root.key+"-b"))
				}
			})
		}
	}
	require.Equal(t, before, s2Snapshot(t, f))
}
