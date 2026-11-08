package smoke

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/target/goalert/organization"
)

func TestGlobalOrganizationDefaultUpdateAudit(t *testing.T) {
	f := globalOrganizationFixture(t)
	for _, actor := range []string{"pam", "paa", "pd0", "pdm"} {
		for _, root := range []struct{ typ, id, table, column string }{
			{"Service", "svc-b", "service_update_audit_events", "service_id"},
			{"Schedule", "sched-b", "schedule_rotation_update_audit_events", "target_id"},
			{"Rotation", "rot-b", "schedule_rotation_update_audit_events", "target_id"},
		} {
			t.Run(actor+"/"+root.typ, func(t *testing.T) {
				name := "A12 UPDATE " + actor + root.typ
				r := a12Call(t, f, "Default-existing-update", actor, fmt.Sprintf(`mutation($id:ID!,$name:String){result:update%s(input:{id:$id,name:$name})}`, root.typ), map[string]any{"id": f.h.UUID(root.id), "name": name})
				require.Empty(t, r.Errors)
				require.Equal(t, "true", string(r.Data["result"]))
				home := f.h.UUID("s2-org-a")
				orgRole := "ORG_MEMBER"
				if actor == "paa" {
					orgRole = "ORG_ADMIN"
				}
				if actor == "pd0" || actor == "pdm" {
					home = organization.DefaultOrganizationID
					orgRole = "NONE"
				}
				require.Equal(t, "1", s2Scalar(t, f, `SELECT count(*)::text FROM `+root.table+` WHERE `+root.column+`=$1 AND actor_id=$2 AND home_organization_id=$3 AND organization_role=$4 AND target_organization_id=$5 AND outcome='committed'`, f.h.UUID(root.id), f.h.UUID(actor), home, orgRole, f.h.UUID("s2-org-b")))
			})
		}
	}
	before := a12BusinessSnapshot(t, f)
	r := a12Call(t, f, "ordinary-Default-cannot-forge-update", "od", `mutation($id:ID!){updateService(input:{id:$id,name:"denied"})}`, map[string]any{"id": f.h.UUID("svc-b")})
	s2Deny(t, r)
	require.Equal(t, before, a12BusinessSnapshot(t, f))
	s2Save(t, "durable-update-rows", map[string]any{"service": s2Rows(t, f, `SELECT * FROM service_update_audit_events`), "schedule_rotation": s2Rows(t, f, `SELECT * FROM schedule_rotation_update_audit_events`)})
}

func TestGlobalOrganizationDefaultExistingManagement(t *testing.T) {
	for _, actor := range []string{"pd0", "pdm"} {
		t.Run(actor, func(t *testing.T) {
			f := globalOrganizationFixture(t)
			for _, q := range []string{
				fmt.Sprintf(`mutation{updateEscalationPolicy(input:{id:%q,name:"A12 Default EP"})}`, f.h.UUID("ep-b")),
				fmt.Sprintf(`mutation{createEscalationPolicyStep(input:{escalationPolicyID:%q,delayMinutes:3,actions:[]}){id}}`, f.h.UUID("ep-b")),
				fmt.Sprintf(`mutation{updateUserContactMethod(input:{id:%q,name:"A12 Default CM"})}`, f.h.UUID("cm-b")),
				fmt.Sprintf(`mutation{createUserNotificationRule(input:{userID:%q,contactMethodID:%q,delayMinutes:7}){id}}`, f.h.UUID("b"), f.h.UUID("cm-b")),
			} {
				require.Empty(t, a12Call(t, f, "Default-approved-existing-management", actor, q, nil).Errors)
			}
			for _, fields := range []string{"private:false", "value:\"a12-replacement@example.invalid\"", "enableStatusUpdates:true"} {
				before := a12BusinessSnapshot(t, f)
				r := a12Call(t, f, "Default-unapproved-CM-field", actor, fmt.Sprintf(`mutation{updateUserContactMethod(input:{id:%q,%s})}`, f.h.UUID("cm-b"), fields), nil)
				require.NotEmpty(t, r.Errors)
				require.Equal(t, before, a12BusinessSnapshot(t, f))
			}
			before := a12BusinessSnapshot(t, f)
			r := a12Call(t, f, "Default-private-CM-result", actor, fmt.Sprintf(`mutation{createUserContactMethod(input:{userID:%q,name:"A12 private result",private:true,type:EMAIL,value:"a12-private@example.invalid"}){id name private value formattedValue}}`, f.h.UUID("b")), nil)
			require.Empty(t, r.Errors)
			require.NotContains(t, string(r.Raw), "a12-private@example.invalid")
			require.Contains(t, string(r.Raw), "Private contact method")
			after := a12BusinessSnapshot(t, f)
			before["user_contact_methods"] = after["user_contact_methods"]
			require.Equal(t, before, after)
			r = a12Call(t, f, "Default-four-root-delete", actor, fmt.Sprintf(`mutation{deleteAll(input:[{type:service,id:%q},{type:escalationPolicy,id:%q},{type:schedule,id:%q},{type:rotation,id:%q}])}`, f.h.UUID("svc-b"), f.h.UUID("ep-b"), f.h.UUID("sched-b"), f.h.UUID("rot-b")), nil)
			require.Empty(t, r.Errors)
			for _, table := range []string{"services", "escalation_policies", "schedules", "rotations"} {
				require.Equal(t, "0", s2Scalar(t, f, "SELECT count(*)::text FROM "+table+" WHERE organization_id=$1", f.h.UUID("s2-org-b")))
			}
		})
	}
}

func TestGlobalOrganizationDefaultOperationBoundary(t *testing.T) {
	f := globalOrganizationFixture(t)
	for _, actor := range []string{"od", "pd0", "pdm"} {
		t.Run(actor, func(t *testing.T) {
			for _, q := range []string{
				`{config(all:true){id}}`, `{alert(id:123){id}}`, `mutation{setSystemLimits(input:[])}`,
				fmt.Sprintf(`mutation{updateUser(input:{id:%q,name:"A12 forbidden Default recovery"})}`, f.h.UUID(actor)),
				fmt.Sprintf(`mutation{setFavorite(input:{target:{type:service,id:%q},favorite:true})}`, f.h.UUID("svc-b")),
				fmt.Sprintf(`mutation{deleteAll(input:[{type:user,id:%q}])}`, f.h.UUID(actor)),
			} {
				before := a12BusinessSnapshot(t, f)
				s2Deny(t, a12Call(t, f, "Default-unapproved-operation-no-write", actor, q, nil))
				require.Equal(t, before, a12BusinessSnapshot(t, f))
			}
			if actor == "od" {
				s2Deny(t, a12Call(t, f, "ordinary-Default-no-public-business-config", actor, `{config{id}}`, nil))
				return
			}
			require.Empty(t, a12Call(t, f, "Default-PA-public-UI-config", actor, `{config{id}}`, nil).Errors)
			before := a12BusinessSnapshot(t, f)
			r := a12Call(t, f, "Default-PA-existing-Normal-User", actor, fmt.Sprintf(`mutation{updateUser(input:{id:%q,name:%q})}`, f.h.UUID("b"), "A12 managed User "+actor), nil)
			require.Empty(t, r.Errors)
			after := a12BusinessSnapshot(t, f)
			before["users"] = after["users"]
			require.Equal(t, before, after)
		})
	}
}

func TestGlobalOrganizationDefaultSingleRootDelete(t *testing.T) {
	for _, actor := range []string{"pd0", "pdm"} {
		t.Run(actor, func(t *testing.T) {
			f := globalOrganizationFixture(t)
			for _, row := range []struct{ typ, key, table string }{{"service", "svc", "services"}, {"escalationPolicy", "ep", "escalation_policies"}, {"schedule", "sched", "schedules"}, {"rotation", "rot", "rotations"}} {
				t.Run(row.typ, func(t *testing.T) {
					home := s2Rows(t, f, "SELECT * FROM "+row.table+" WHERE organization_id=$1", f.h.UUID("s2-org-a"))
					r := a12Call(t, f, "Default-single-Root-delete", actor, fmt.Sprintf(`mutation{deleteAll(input:[{type:%s,id:%q}])}`, row.typ, f.h.UUID(row.key+"-b")), nil)
					require.Empty(t, r.Errors)
					require.Equal(t, "0", s2Scalar(t, f, "SELECT count(*)::text FROM "+row.table+" WHERE id=$1", f.h.UUID(row.key+"-b")))
					require.Equal(t, home, s2Rows(t, f, "SELECT * FROM "+row.table+" WHERE organization_id=$1", f.h.UUID("s2-org-a")))
				})
			}
		})
	}
}
