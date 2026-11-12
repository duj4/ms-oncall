package smoke

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/assignment"
	"github.com/target/goalert/auth"
	"github.com/target/goalert/organization"
	"github.com/target/goalert/permission"
	"github.com/target/goalert/test/smoke/harness"
)

// Real signed-session transport; credentials and headers are never recorded.
func sd8HTTP(t *testing.T, h *harness.Harness, query, token string) (int, *stepOrganizationResponse) {
	t.Helper()
	body, err := json.Marshal(map[string]string{"query": query})
	require.NoError(t, err)
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, h.URL()+"/api/graphql", bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: auth.CookieName, Value: token})
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	require.NoError(t, err)
	var result stepOrganizationResponse
	if resp.StatusCode == http.StatusOK {
		require.NoError(t, json.Unmarshal(raw, &result))
	}
	require.NotContains(t, string(raw), "SYNTHETIC_PRIVATE")
	return resp.StatusCode, &result
}

func sd8DefaultAssignment(t *testing.T, h *harness.Harness, u string) {
	t.Helper()
	sd8Exec(t, h, `UPDATE users SET role='user' WHERE id=$1 AND role='unknown'`, u)
	sd8Exec(t, h, `INSERT INTO user_organization_assignments(user_id,effective_organization_id,effective_organization_classification,effective_normal_organization_id,organization_role,mapping_outcome,matched_count,source_config_version,authoritative_evaluated_at) VALUES($1,$2,'DEFAULT',NULL,'NONE','ZERO',0,'sd8-synthetic',now()) ON CONFLICT(user_id) DO UPDATE SET effective_organization_id=$2,effective_organization_classification='DEFAULT',effective_normal_organization_id=NULL,organization_role='NONE',mapping_outcome='ZERO',matched_count=0`, u, organization.DefaultOrganizationID)
}

func TestUserDeleteAuditHTTPOrganizations(t *testing.T) {
	h := sd1Harness(t)
	ikSetAuthority(t, h, "ORG_MEMBER", true)
	normalToken := h.GraphQLToken(h.UUID("user-a"))
	defaultToken := h.GraphQLToken(harness.DefaultGraphQLAdminUserID)
	sd8DefaultAssignment(t, h, harness.DefaultGraphQLAdminUserID)
	for _, actor := range []string{"normal", "default"} {
		for _, target := range []string{"home", "foreign", "default", "unknown", "missing", "self"} {
			if actor == "normal" && target == "self" {
				continue
			}
			t.Run(actor+"/"+target, func(t *testing.T) {
				token := normalToken
				if actor == "default" {
					token = defaultToken
				}
				u := sd7User(t, h)
				switch target {
				case "home":
					sd8Assign(t, h, u, harness.SmokeOrganizationID)
				case "foreign":
					sd8Assign(t, h, u, h.UUID("org-b"))
				case "default":
					sd8DefaultAssignment(t, h, u)
				case "missing":
					u = uuid.NewString()
				case "self":
					u = harness.DefaultGraphQLAdminUserID
				}
				cm := ""
				if target != "missing" && target != "self" {
					cm, _ = sd8CMNR(t, h, u)
				}
				extra := []string{}
				if cm != "" {
					extra = append(extra, fmt.Sprintf(`{type:contactMethod,id:%q}`, cm))
				}
				status, result := sd8HTTP(t, h, sd8Query(u, extra...), token)
				require.Equal(t, 200, status)
				allowed := actor == "normal" || target == "home" || target == "foreign"
				if !allowed {
					require.NotEmpty(t, result.Errors)
					require.Zero(t, sd8Scalar(t, h, `SELECT count(*) FROM user_delete_audit_events WHERE root_id=$1 AND record_kind='success_witness'`, u))
					if target != "missing" {
						require.EqualValues(t, 1, sd8Scalar(t, h, `SELECT count(*) FROM users WHERE id=$1`, u))
					}
					return
				}
				require.Empty(t, result.Errors)
				if target == "missing" {
					require.Zero(t, sd8Scalar(t, h, `SELECT count(*) FROM user_delete_audit_events WHERE root_id=$1`, u))
					return
				}
				var home, resolution string
				var org *string
				require.NoError(t, h.App().DB().QueryRow(`SELECT home_organization_id,target_org_resolution,target_organization_id FROM user_delete_audit_events WHERE root_id=$1 AND record_kind='success_witness'`, u).Scan(&home, &resolution, &org))
				wantHome := harness.SmokeOrganizationID
				if actor == "default" {
					wantHome = organization.DefaultOrganizationID
				}
				require.Equal(t, wantHome, home)
				switch target {
				case "home":
					require.Equal(t, "known_normal", resolution)
					require.Equal(t, harness.SmokeOrganizationID, *org)
				case "foreign":
					require.Equal(t, "known_normal", resolution)
					require.Equal(t, h.UUID("org-b"), *org)
				case "default":
					require.Equal(t, "known_default", resolution)
					require.Equal(t, organization.DefaultOrganizationID, *org)
				case "unknown":
					require.Equal(t, "unknown", resolution)
					require.Nil(t, org)
				}
			})
		}
	}
	status, _ := sd8HTTP(t, h, sd8Query(uuid.NewString()), "invalid-session-signature")
	require.Equal(t, 401, status)
}

func TestUserDeleteAuditHTTPLastAdminAndSelf(t *testing.T) {
	h := sd1Harness(t)
	u := h.UUID("user-a")
	sd8Exec(t, h, `UPDATE users SET role='user'`)
	sd8Exec(t, h, `UPDATE users SET role='admin' WHERE id=$1`, u)
	require.EqualValues(t, 1, sd8Scalar(t, h, `SELECT count(*) FROM users WHERE role='admin'`))
	token := h.GraphQLToken(u)
	status, result := sd8HTTP(t, h, sd8Query(u), token)
	require.Equal(t, 200, status)
	require.Empty(t, result.Errors)
	require.Zero(t, sd8Scalar(t, h, `SELECT count(*) FROM users WHERE id=$1`, u))
	require.EqualValues(t, 1, sd8Scalar(t, h, `SELECT count(*) FROM user_delete_audit_events WHERE actor_id=$1 AND root_id=$1 AND record_kind='success_witness'`, u))
	status, _ = sd8HTTP(t, h, sd8Query(uuid.NewString()), token)
	require.Equal(t, 401, status)
}

func TestUserDeleteAuditHTTPDeniedRolesAndMissingHome(t *testing.T) {
	h := sd1Harness(t)
	actor := h.UUID("user-a")
	for _, role := range []string{"ORG_MEMBER", "ORG_ADMIN"} {
		ikSetAuthority(t, h, role, false)
		for _, target := range []string{"home", "foreign", "self"} {
			t.Run(role+"/"+target, func(t *testing.T) {
				u := actor
				if target != "self" {
					u = sd7User(t, h)
					org := harness.SmokeOrganizationID
					if target == "foreign" {
						org = h.UUID("org-b")
					}
					sd8Assign(t, h, u, org)
				}
				status, result := sd8HTTP(t, h, sd8Query(u), h.GraphQLToken(actor))
				require.Equal(t, 200, status)
				require.NotEmpty(t, result.Errors)
				require.EqualValues(t, 1, sd8Scalar(t, h, `SELECT count(*) FROM users WHERE id=$1`, u))
				require.Zero(t, sd8Scalar(t, h, `SELECT count(*) FROM user_delete_audit_events WHERE record_kind='success_witness'`))
			})
		}
	}
	ikSetAuthority(t, h, "ORG_MEMBER", true)
	sd8Exec(t, h, `DELETE FROM user_organization_assignments WHERE user_id=$1`, actor)
	u := sd7User(t, h)
	sd8Assign(t, h, u, h.UUID("org-b"))
	status, result := sd8HTTP(t, h, sd8Query(u), h.GraphQLToken(actor))
	require.Equal(t, 200, status)
	require.NotEmpty(t, result.Errors)
	require.EqualValues(t, 1, sd8Scalar(t, h, `SELECT count(*) FROM users WHERE id=$1`, u))
	require.Zero(t, sd8Scalar(t, h, `SELECT count(*) FROM user_delete_audit_events WHERE record_kind='success_witness'`))
}

func TestUserDeleteAuditConflictingAdmission(t *testing.T) {
	h := sd1Harness(t)
	u := sd7User(t, h)
	sd8Assign(t, h, u, h.UUID("org-b"))
	valid := integrationKeyOrganizationContext(t, h)
	other, err := auth.NewRequester(h.UUID("user-a"), uuid.NewString())
	require.NoError(t, err)
	// Deliberately contradictory internal admission carriers. This supplements
	// signed HTTP bad-signature coverage and is not itself an HTTP request.
	ok, err := sd7App(h).Mutation().DeleteAll(auth.WithRequester(valid, other), []assignment.RawTarget{{Type: assignment.TargetTypeUser, ID: u}})
	require.False(t, ok)
	require.True(t, permission.IsPermissionError(err))
	require.EqualValues(t, 1, sd8Scalar(t, h, `SELECT count(*) FROM users WHERE id=$1`, u))
	require.Zero(t, sd8Scalar(t, h, `SELECT count(*) FROM user_delete_audit_events WHERE record_kind='success_witness'`))
}

func TestUserDeleteAuditHTTPMixedAndPrivacy(t *testing.T) {
	h := sd1Harness(t)
	ikSetAuthority(t, h, "ORG_MEMBER", true)
	token := h.GraphQLToken(h.UUID("user-a"))
	db := h.App().DB()
	for _, mode := range []string{"mixed", "double_user", "duplicate_missing", "foreign_default_cm", "cm_count", "nr_count", "append_failure"} {
		t.Run(mode, func(t *testing.T) {
			u, v := sd7User(t, h), sd7User(t, h)
			cm, nr := sd8CMNR(t, h, u)
			extra := []string{fmt.Sprintf(`{type:contactMethod,id:%q}`, cm), fmt.Sprintf(`{type:notificationRule,id:%q}`, nr)}
			if mode == "mixed" || mode == "double_user" {
				s := sd6Root(t, h, "schedule", harness.SmokeOrganizationID)
				o1, o2 := uuid.NewString(), uuid.NewString()
				sd8Exec(t, h, `INSERT INTO user_overrides(id,tgt_schedule_id,add_user_id,remove_user_id,start_time,end_time) VALUES($1,$3,$4,$5,'2020-01-01','2020-01-02'),($2,$3,$4,$5,'2020-01-02','2020-01-03')`, o1, o2, s, u, v)
				extra = append(extra, fmt.Sprintf(`{type:userOverride,id:%q}`, o1))
				if mode == "double_user" {
					extra = append(extra, fmt.Sprintf(`{type:user,id:%q}`, v))
				}
			}
			if mode == "duplicate_missing" {
				extra = append(extra, extra[0], extra[1], fmt.Sprintf(`{type:contactMethod,id:%q}`, uuid.NewString()), fmt.Sprintf(`{type:notificationRule,id:%q}`, uuid.NewString()), fmt.Sprintf(`{type:user,id:%q}`, u))
			}
			if mode == "foreign_default_cm" {
				sd8DefaultAssignment(t, h, v)
				foreign, _ := sd8CMNR(t, h, v)
				extra = append(extra, fmt.Sprintf(`{type:contactMethod,id:%q}`, foreign))
			}
			if mode == "cm_count" || mode == "nr_count" {
				typ, id := "contactMethod", cm
				if mode == "nr_count" {
					typ, id = "notificationRule", nr
				}
				for range 50 {
					extra = append(extra, fmt.Sprintf(`{type:%s,id:%q}`, typ, id))
				}
			}
			var expected func()
			if mode == "append_failure" {
				sd8Exec(t, h, `CREATE FUNCTION sd8_private_fail() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'SYNTHETIC_PRIVATE' USING HINT='SYNTHETIC_PRIVATE';END;$$;CREATE TRIGGER sd8_private_fail BEFORE INSERT ON user_delete_audit_events FOR EACH ROW WHEN (NEW.record_kind='success_witness') EXECUTE FUNCTION sd8_private_fail()`)
				expected = h.ExpectBackendError("deleteAll transaction failed")
			}
			status, result := sd8HTTP(t, h, sd8Query(u, extra...), token)
			require.Equal(t, 200, status)
			if expected != nil {
				expected()
			}
			failed := strings.Contains(mode, "count") || mode == "foreign_default_cm" || mode == "append_failure"
			if failed {
				require.NotEmpty(t, result.Errors)
				require.EqualValues(t, 1, sd8Scalar(t, h, `SELECT count(*) FROM users WHERE id=$1`, u))
				require.Zero(t, sd8Scalar(t, h, `SELECT count(*) FROM user_delete_audit_events WHERE root_id=$1 AND record_kind='success_witness'`, u))
			} else {
				require.Empty(t, result.Errors)
				require.EqualValues(t, 2, sd8Scalar(t, h, `SELECT count(*) FROM user_cmnr_delete_audit_events c JOIN user_delete_audit_events e ON e.event_id=c.cause_event_id WHERE e.root_id=$1 AND c.schema_version=2`, u))
				require.Zero(t, sd8Scalar(t, h, `SELECT count(*) FROM user_delete_audit_effects f JOIN user_cmnr_delete_audit_events c ON c.root_id::text=f.resource_key AND c.root_type=f.resource_type WHERE c.cause_root_id=$1`, u))
			}
			if mode == "append_failure" {
				sd8Exec(t, h, `DROP TRIGGER sd8_private_fail ON user_delete_audit_events;DROP FUNCTION sd8_private_fail()`)
			}
			var pii bool
			require.NoError(t, db.QueryRow(`SELECT EXISTS(SELECT FROM user_delete_audit_events WHERE before_context::text LIKE '%SYNTHETIC_PRIVATE%') OR EXISTS(SELECT FROM user_delete_audit_effects WHERE payload::text LIKE '%SYNTHETIC_PRIVATE%')`).Scan(&pii))
			require.False(t, pii)
		})
	}
}
