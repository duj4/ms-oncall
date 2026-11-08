package smoke

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/target/goalert/organization"
)

func a12BusinessSnapshot(t *testing.T, f *s2Fixture) map[string]string {
	t.Helper()
	s := s2Snapshot(t, f)
	for _, table := range []string{"schedule_rules", "schedule_data", "integration_keys"} {
		s[table] = s2Rows(t, f, "SELECT * FROM "+table)
	}
	return s
}

func a12CreateInput(typ, name string) map[string]any {
	input := map[string]any{"name": name}
	switch typ {
	case "Service":
		input["newEscalationPolicy"] = map[string]any{"name": name + " EP"}
	case "Schedule":
		input["timeZone"] = "Asia/Shanghai"
	case "Rotation":
		input["timeZone"] = "Asia/Shanghai"
		input["type"] = "weekly"
		input["start"] = "2026-11-08T00:00:00Z"
		input["shiftLength"] = 1
	}
	return input
}

func a12Create(t *testing.T, f *s2Fixture, actor, typ string, input map[string]any) *s2Result {
	t.Helper()
	q := fmt.Sprintf(`mutation($input:Create%sInput!){root:create%s(input:$input){id name organization{id displayName}}}`, typ, typ)
	return a12Call(t, f, "create-"+typ, actor, q, map[string]any{"input": input})
}

func TestGlobalOrganizationCreateMatrix(t *testing.T) {
	f := globalOrganizationFixture(t)
	for _, actor := range []string{"paa", "pam", "pd0", "pdm", "oa", "om", "od"} {
		for _, typ := range []string{"Service", "EscalationPolicy", "Schedule", "Rotation"} {
			t.Run(actor+"/"+typ, func(t *testing.T) {
				input := a12CreateInput(typ, "A12 "+actor+" "+typ)
				target := f.h.UUID("s2-org-b")
				pa := actor == "paa" || actor == "pam" || actor == "pd0" || actor == "pdm"
				if pa {
					input["targetOrganizationID"] = target
				} else {
					target = f.h.UUID("s2-org-a")
				}
				before := a12BusinessSnapshot(t, f)
				r := a12Create(t, f, actor, typ, input)
				if actor == "om" || actor == "od" {
					s2Deny(t, r)
					require.Equal(t, before, a12BusinessSnapshot(t, f))
					return
				}
				require.Empty(t, r.Errors)
				require.Equal(t, 200, r.Status)
				var root struct {
					ID           string
					Organization struct{ ID string }
				}
				require.NoError(t, json.Unmarshal(r.Data["root"], &root))
				require.NotEmpty(t, root.ID)
				require.Equal(t, target, root.Organization.ID)
				if pa {
					require.Equal(t, "1", s2Scalar(t, f, `SELECT count(*)::text FROM global_root_create_audit_events WHERE root_id=$1 AND actor_id=$2 AND target_organization_id=$3 AND outcome='committed'`, root.ID, f.h.UUID(actor), target))
					home := f.h.UUID("s2-org-a")
					orole := "ORG_MEMBER"
					if actor == "paa" {
						orole = "ORG_ADMIN"
					}
					if actor == "pd0" || actor == "pdm" {
						home = organization.DefaultOrganizationID
						orole = "NONE"
					}
					require.Equal(t, "1", s2Scalar(t, f, `SELECT count(*)::text FROM global_root_create_audit_events WHERE root_id=$1 AND home_organization_id=$2 AND organization_role=$3 AND authority_role='platform_admin'`, root.ID, home, orole))
				}
				require.Equal(t, "0", s2Scalar(t, f, `SELECT count(*)::text FROM user_favorites WHERE user_id=$1 AND (tgt_service_id=$2 OR tgt_schedule_id=$2 OR tgt_rotation_id=$2 OR tgt_escalation_policy_id=$2)`, f.h.UUID(actor), root.ID))
				single := strings.ToLower(typ[:1]) + typ[1:]
				r = a12Call(t, f, "read-created-Root", actor, fmt.Sprintf(`query($id:ID!){root:%s(id:$id){id organization{id}}}`, single), map[string]any{"id": root.ID})
				require.Empty(t, r.Errors)
				require.Contains(t, string(r.Data["root"]), target)
				if pa && actor != "pd0" && actor != "pdm" {
					homeInput := a12CreateInput(typ, "A12 HOME "+actor+typ)
					homeInput["targetOrganizationID"] = f.h.UUID("s2-org-a")
					homeInput["favorite"] = true
					r = a12Create(t, f, actor, typ, homeInput)
					require.Empty(t, r.Errors)
				}
			})
		}
	}
}

func TestGlobalOrganizationCreateRejections(t *testing.T) {
	f := globalOrganizationFixture(t)
	for _, typ := range []string{"Service", "EscalationPolicy", "Schedule", "Rotation"} {
		for _, scenario := range []string{"missing PA target", "Default target", "unknown target", "empty target", "Foreign favorite", "ordinary Foreign target", "Default favorite"} {
			t.Run(typ+"/"+scenario, func(t *testing.T) {
				actor := "pam"
				input := a12CreateInput(typ, "A12 REJECT "+scenario+typ)
				input["targetOrganizationID"] = f.h.UUID("s2-org-b")
				switch scenario {
				case "missing PA target":
					delete(input, "targetOrganizationID")
				case "Default target":
					input["targetOrganizationID"] = organization.DefaultOrganizationID
				case "unknown target":
					input["targetOrganizationID"] = f.h.UUID("missing-org")
				case "empty target":
					input["targetOrganizationID"] = ""
				case "Foreign favorite":
					input["favorite"] = true
				case "ordinary Foreign target":
					actor = "oa"
				case "Default favorite":
					actor = "pd0"
					input["favorite"] = true
				}
				before := a12BusinessSnapshot(t, f)
				r := a12Create(t, f, actor, typ, input)
				require.NotEmpty(t, r.Errors)
				require.NotContains(t, string(r.Raw), "Cannot query field")
				require.NotContains(t, string(r.Raw), "Unknown argument")
				require.Equal(t, before, a12BusinessSnapshot(t, f), "rejected Create changed business state")
			})
		}
	}
}

func TestGlobalOrganizationNestedCreateAtomicity(t *testing.T) {
	f := globalOrganizationFixture(t)
	for _, actor := range []string{"pam", "pd0", "pdm"} {
		for _, scenario := range []string{"success", "target conflict", "parent conflict", "Foreign participant"} {
			t.Run(actor+"/"+scenario, func(t *testing.T) {
				name := "A12 TREE " + actor + scenario
				rotation := map[string]any{"name": name + " Rotation", "timeZone": "Asia/Shanghai", "type": "weekly", "start": "2026-11-08T00:00:00Z", "shiftLength": 1, "userIDs": []string{f.h.UUID("b")}}
				target := map[string]any{"newRotation": rotation, "rules": []any{map[string]any{}}}
				sched := map[string]any{"name": name + " Schedule", "timeZone": "Asia/Shanghai", "targets": []any{target}}
				step := map[string]any{"delayMinutes": 1, "newSchedule": sched}
				policy := map[string]any{"name": name + " EP", "steps": []any{step}}
				input := map[string]any{"name": name, "targetOrganizationID": f.h.UUID("s2-org-b"), "newEscalationPolicy": policy}
				switch scenario {
				case "target conflict":
					rotation["targetOrganizationID"] = f.h.UUID("s2-org-a")
				case "parent conflict":
					step["escalationPolicyID"] = f.h.UUID("ep-b")
				case "Foreign participant":
					rotation["userIDs"] = []string{f.h.UUID(actor)}
				}
				before := a12BusinessSnapshot(t, f)
				r := a12Create(t, f, actor, "Service", input)
				if scenario != "success" {
					require.NotEmpty(t, r.Errors)
					require.Equal(t, before, a12BusinessSnapshot(t, f))
					return
				}
				require.Empty(t, r.Errors)
				for _, table := range []string{"services", "escalation_policies", "schedules", "rotations"} {
					require.Equal(t, "1", s2Scalar(t, f, `SELECT count(*)::text FROM `+table+` WHERE name LIKE $1 AND organization_id=$2`, name+"%", f.h.UUID("s2-org-b")))
				}
				var root struct{ ID string }
				require.NoError(t, json.Unmarshal(r.Data["root"], &root))
				r = a12Call(t, f, "nested-tree-read", actor, `query($id:ID!){service(id:$id){organization{id} escalationPolicy{organization{id} steps{id targets{id name}}}}}`, map[string]any{"id": root.ID})
				require.Empty(t, r.Errors)
				require.Equal(t, "1", s2Scalar(t, f, `SELECT count(*)::text FROM global_root_create_audit_events WHERE root_id=$1 AND outcome='committed'`, root.ID))
			})
		}
	}
}

func TestGlobalOrganizationSiblingCarrierIsolation(t *testing.T) {
	f := globalOrganizationFixture(t)
	r := a12Call(t, f, "verified-target-must-not-escape-sibling", "pd0", `mutation($target:ID!){first:createSchedule(input:{name:"A12 sibling explicit",timeZone:"Asia/Shanghai",targetOrganizationID:$target}){id organization{id}} second:createSchedule(input:{name:"A12 sibling omitted",timeZone:"Asia/Shanghai"}){id}}`, map[string]any{"target": f.h.UUID("s2-org-b")})
	require.NotEmpty(t, r.Errors)
	require.Contains(t, string(r.Data["first"]), f.h.UUID("s2-org-b"))
	require.Equal(t, "null", string(r.Data["second"]))
	require.Equal(t, "1", s2Scalar(t, f, `SELECT count(*)::text FROM schedules WHERE name='A12 sibling explicit' AND organization_id=$1`, f.h.UUID("s2-org-b")))
	require.Equal(t, "0", s2Scalar(t, f, `SELECT count(*)::text FROM schedules WHERE name='A12 sibling omitted'`))
	require.Equal(t, "1", s2Scalar(t, f, `SELECT count(*)::text FROM global_root_create_audit_events WHERE actor_id=$1 AND outcome='committed'`, f.h.UUID("pd0")))
}
