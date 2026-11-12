package smoke

import (
	"fmt"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/test/smoke/harness"
)

func sd8Scalar(t *testing.T, h *harness.Harness, q string, args ...any) int64 {
	t.Helper()
	var n int64
	require.NoError(t, h.App().DB().QueryRow(q, args...).Scan(&n))
	return n
}
func sd8Exec(t *testing.T, h *harness.Harness, q string, args ...any) {
	t.Helper()
	_, err := h.App().DB().Exec(q, args...)
	require.NoError(t, err)
}
func sd8CMNR(t *testing.T, h *harness.Harness, u string) (string, string) {
	t.Helper()
	cm, nr := uuid.NewString(), uuid.NewString()
	sd8Exec(t, h, `INSERT INTO user_contact_methods(id,user_id,name,type,value) VALUES($1,$2,'SYNTHETIC_PRIVATE','EMAIL',$3)`, cm, u, uuid.NewString()+"@example.invalid")
	sd8Exec(t, h, `INSERT INTO user_notification_rules(id,user_id,contact_method_id) VALUES($1,$2,$3)`, nr, u, cm)
	return cm, nr
}
func sd8Query(user string, extra ...string) string {
	return `mutation{deleteAll(input:[` + strings.Join(append([]string{fmt.Sprintf(`{type:user,id:%q}`, user)}, extra...), ",") + `])}`
}

func TestUserDeleteAuditHTTPFoundation(t *testing.T) {
	for _, mode := range []string{"pure_unknown", "normal", "duplicate_missing", "member_denied", "orgadmin_denied", "cm", "nr", "cmnr", "late_uuid", "late_count", "self"} {
		t.Run(mode, func(t *testing.T) {
			h := sd1Harness(t)
			ikSetAuthority(t, h, "ORG_MEMBER", true)
			db := h.App().DB()
			u := sd7User(t, h)
			extra := []string{}
			if mode == "normal" {
				sd8Exec(t, h, `INSERT INTO user_organization_assignments(user_id,effective_organization_id,effective_organization_classification,effective_normal_organization_id,organization_role,mapping_outcome,matched_count,source_config_version,authoritative_evaluated_at) SELECT $1,effective_organization_id,effective_organization_classification,effective_normal_organization_id,organization_role,mapping_outcome,matched_count,source_config_version,authoritative_evaluated_at FROM user_organization_assignments WHERE user_id=$2`, u, h.UUID("user-a"))
			}
			if mode == "self" {
				u = h.UUID("user-a")
			}
			if mode == "member_denied" {
				ikSetAuthority(t, h, "ORG_MEMBER", false)
			}
			if mode == "orgadmin_denied" {
				ikSetAuthority(t, h, "ORG_ADMIN", false)
			}
			cm, nr := sd8CMNR(t, h, u)
			if mode == "cm" || mode == "cmnr" {
				extra = append(extra, fmt.Sprintf(`{type:contactMethod,id:%q}`, cm))
			}
			if mode == "nr" || mode == "cmnr" {
				extra = append(extra, fmt.Sprintf(`{type:notificationRule,id:%q}`, nr))
			}
			if mode == "duplicate_missing" {
				extra = append(extra, fmt.Sprintf(`{type:user,id:%q}`, u), fmt.Sprintf(`{type:user,id:%q}`, uuid.NewString()))
			}
			if mode == "late_uuid" {
				extra = append(extra, `{type:notificationRule,id:"invalid"}`)
			}
			if mode == "late_count" {
				for range 51 {
					extra = append(extra, fmt.Sprintf(`{type:contactMethod,id:%q}`, cm))
				}
			}
			r := sd1HTTP(t, h, sd8Query(u, extra...), "")
			denied := strings.HasSuffix(mode, "denied") || strings.HasPrefix(mode, "late_")
			if denied {
				require.NotEmpty(t, r.Errors)
				require.EqualValues(t, 1, sd8Scalar(t, h, `SELECT count(*) FROM users WHERE id=$1`, u))
				require.Zero(t, sd8Scalar(t, h, `SELECT count(*) FROM user_delete_audit_events WHERE record_kind='success_witness'`))
				return
			}
			require.Empty(t, r.Errors)
			require.JSONEq(t, `{"deleteAll":true}`, string(r.Data))
			require.Zero(t, sd8Scalar(t, h, `SELECT count(*) FROM users WHERE id=$1`, u))
			require.EqualValues(t, 1, sd8Scalar(t, h, `SELECT count(*) FROM user_delete_audit_events WHERE record_kind='success_witness'`))
			var actor, home string
			require.NoError(t, db.QueryRow(`SELECT actor_id,home_organization_id FROM user_delete_audit_events WHERE record_kind='success_witness'`).Scan(&actor, &home))
			require.Equal(t, h.UUID("user-a"), actor)
			require.Equal(t, harness.SmokeOrganizationID, home)
			want := int64(0)
			if mode == "cm" || mode == "nr" {
				want = 1
			}
			if mode == "cmnr" {
				want = 2
			}
			require.Equal(t, want, sd8Scalar(t, h, `SELECT count(*) FROM user_cmnr_delete_audit_events WHERE schema_version=2`))
			require.Zero(t, sd8Scalar(t, h, `SELECT count(*) FROM user_delete_audit_effects f JOIN user_cmnr_delete_audit_events c ON f.resource_type=c.root_type AND f.resource_key=c.root_id::text WHERE c.schema_version=2`))
			require.Equal(t, sd8Scalar(t, h, `SELECT effect_count FROM user_delete_audit_events WHERE record_kind='success_witness'`), sd8Scalar(t, h, `SELECT count(*) FROM user_delete_audit_effects`))
			if mode == "self" {
				status, _ := sd8HTTP(t, h, sd8Query(uuid.NewString()), h.GraphQLToken(u))
				require.Equal(t, 401, status)
			}
		})
	}
}
