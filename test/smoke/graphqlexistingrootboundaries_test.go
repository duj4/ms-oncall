package smoke

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExistingRootGlobalDeleteCompleteSet(t *testing.T) {
	for _, a := range []f01Actor{f01Actors[0], f01Actors[2]} {
		for _, kind := range []string{"EP", "Schedule", "Rotation"} {
			t.Run(a.name+"_"+kind, func(t *testing.T) {
				h := f01Harness(t)
				f01Set(t, h, a)
				token := h.GraphQLToken(h.UUID("user-a"))
				typ := f01Type(kind)
				id := h.UUID(f01Root(kind) + "-a")
				for _, tc := range []struct{ name, input string }{
					{"missing", fmt.Sprintf(`{type:%s,id:%q}`, typ, h.UUID("missing"))},
					{"home_missing", fmt.Sprintf(`{type:%s,id:%q},{type:%s,id:%q}`, typ, id, typ, h.UUID("missing"))},
					{"invalid", fmt.Sprintf(`{type:%s,id:"not-a-uuid"}`, typ)},
					{"home_foreign", fmt.Sprintf(`{type:%s,id:%q},{type:%s,id:%q}`, typ, id, typ, h.UUID(f01Root(kind)+"-b"))},
				} {
					r, rec := f01Call(t, h, tc.name, "mutation{deleteAll(input:["+tc.input+"])}", "user-a", token)
					require.NotEmpty(t, r.Errors)
					rec["expected_rejection"] = true
					f01Save(t, tc.name, rec)
				}
				other := f01OrgRows(t, h, h.UUID("org-b"))
				q := fmt.Sprintf(`mutation{deleteAll(input:[{type:%s,id:%q},{type:%s,id:%q}])}`, typ, id, typ, id)
				r, rec := f01Call(t, h, "duplicate", q, "user-a", token)
				require.Empty(t, r.Errors)
				f01RootPersist(t, h, kind, "delete", "a", "", true)
				require.Equal(t, other, f01OrgRows(t, h, h.UUID("org-b")))
				rec["duplicate_semantics"] = "accepted; deduplicated target count"
				f01Save(t, "duplicate", rec)
			})
		}
	}
}

func TestExistingRootGlobalMixedHomeCascade(t *testing.T) {
	h := f01Harness(t)
	f01Set(t, h, f01Actors[2])
	token := h.GraphQLToken(h.UUID("user-a"))
	epB1Exec(t, h, `INSERT INTO escalation_policy_actions(escalation_policy_step_id,schedule_id) VALUES($1,$2)`, h.UUID("step-a"), h.UUID("schedule-a"))
	epB1Exec(t, h, `INSERT INTO escalation_policy_actions(escalation_policy_step_id,rotation_id) VALUES($1,$2)`, h.UUID("step-a"), h.UUID("rotation-a"))
	epB1Exec(t, h, `INSERT INTO schedule_rules(schedule_id,tgt_rotation_id) VALUES($1,$2)`, h.UUID("schedule-a"), h.UUID("rotation-a"))
	require.Equal(t, "0", f01InvalidRelationships(t, h))
	other := f01OrgRows(t, h, h.UUID("org-b"))
	q := fmt.Sprintf(`mutation{deleteAll(input:[{type:rotation,id:%q},{type:schedule,id:%q},{type:escalationPolicy,id:%q}])}`, h.UUID("rotation-a"), h.UUID("schedule-a"), h.UUID("policy-a"))
	r, rec := f01Call(t, h, "mixed_home_populated", q, "user-a", token)
	require.Empty(t, r.Errors)
	for _, kind := range []string{"EP", "Schedule", "Rotation"} {
		f01RootPersist(t, h, kind, "delete", "a", "", true)
	}
	require.Equal(t, other, f01OrgRows(t, h, h.UUID("org-b")))
	rec["actual_populated_cascade_verified"] = true
	f01Save(t, "mixed_home_populated", rec)
}

func TestExistingRootGlobalRollbackAfterDelete(t *testing.T) {
	h := f01Harness(t)
	f01Set(t, h, f01Actors[2])
	token := h.GraphQLToken(h.UUID("user-a"))
	epB1Exec(t, h, `CREATE SEQUENCE f01_delete_attempt`)
	epB1Exec(t, h, `CREATE FUNCTION f01_delete_witness() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN PERFORM nextval('f01_delete_attempt'); RETURN OLD; END$$`)
	epB1Exec(t, h, `CREATE TRIGGER f01_delete_witness BEFORE DELETE ON rotations FOR EACH ROW EXECUTE FUNCTION f01_delete_witness()`)
	q := fmt.Sprintf(`mutation{deleteAll(input:[{type:rotation,id:%q},{type:escalationPolicy,id:%q}])}`, h.UUID("rotation-a"), h.UUID("missing-policy"))
	r, rec := f01Call(t, h, "rollback_after_rotation_delete", q, "user-a", token)
	require.NotEmpty(t, r.Errors)
	witness := f01Scalar(t, h, `SELECT is_called::text FROM f01_delete_attempt`)
	require.Equal(t, "true", witness)
	rec["nontransactional_sequence_witness"] = witness
	rec["meaning"] = "rotation DELETE was attempted; all 25 selected business tables exactly restored after later EP complete-set failure; sequence is disposable instrumentation"
	f01Save(t, "rollback_after_rotation_delete", rec)
}

func TestExistingRootGlobalCrossOrganizationCascade(t *testing.T) {
	for _, rel := range []string{"foreign_ep_schedule", "foreign_ep_rotation", "foreign_schedule_rotation"} {
		t.Run(rel, func(t *testing.T) {
			h := f01Harness(t)
			f01Set(t, h, f01Actors[2])
			token := h.GraphQLToken(h.UUID("user-a"))
			kind := "Rotation"
			switch rel {
			case "foreign_ep_schedule":
				kind = "Schedule"
				epB1Exec(t, h, `INSERT INTO escalation_policy_actions(escalation_policy_step_id,schedule_id) VALUES($1,$2)`, h.UUID("step-b"), h.UUID("schedule-a"))
			case "foreign_ep_rotation":
				epB1Exec(t, h, `INSERT INTO escalation_policy_actions(escalation_policy_step_id,rotation_id) VALUES($1,$2)`, h.UUID("step-b"), h.UUID("rotation-a"))
			case "foreign_schedule_rotation":
				epB1Exec(t, h, `INSERT INTO schedule_rules(id,schedule_id,tgt_rotation_id) VALUES($1,$2,$3)`, h.UUID("historical-invalid-rule"), h.UUID("schedule-b"), h.UUID("rotation-a"))
			}
			require.Equal(t, "1", f01InvalidRelationships(t, h))
			other := f01OrgRows(t, h, h.UUID("org-b"))
			r, rec := f01Call(t, h, rel, f01RootQuery(h, kind, "delete", "a", ""), "user-a", token)
			rec["precondition"] = "one explicitly injected historical-invalid cross-Organization relation; not created by API; initially valid fixture separately verified"
			rec["other_org_before"] = other
			rec["other_org_after"] = f01OrgRows(t, h, h.UUID("org-b"))
			rec["policy_expected_allow"] = false
			if len(r.Errors) == 0 {
				rec["foreign_business_change"] = fmt.Sprint(other) != fmt.Sprint(f01OrgRows(t, h, h.UUID("org-b")))
			}
			f01Save(t, rel, rec)
			assert.NotEmpty(t, r.Errors, "cross-Organization cascade should reject")
			assert.Equal(t, other, f01OrgRows(t, h, h.UUID("org-b")), "foreign business configuration must remain")
		})
	}
}

func TestExistingRootGlobalRelationshipRejections(t *testing.T) {
	for _, a := range []f01Actor{f01Actors[0], f01Actors[2]} {
		t.Run(a.name, func(t *testing.T) {
			h := f01Harness(t)
			f01Set(t, h, a)
			token := h.GraphQLToken(h.UUID("user-a"))
			queries := map[string]string{
				"step_update_foreign_user":     fmt.Sprintf(`mutation{updateEscalationPolicyStep(input:{id:%q,delayMinutes:9,actions:[{type:"builtin-user",args:{user_id:%q}}]})}`, h.UUID("step-a"), h.UUID("user-b")),
				"step_update_foreign_schedule": fmt.Sprintf(`mutation{updateEscalationPolicyStep(input:{id:%q,delayMinutes:9,actions:[{type:"builtin-schedule",args:{schedule_id:%q}}]})}`, h.UUID("step-a"), h.UUID("schedule-b")),
				"step_create_foreign_rotation": fmt.Sprintf(`mutation{createEscalationPolicyStep(input:{escalationPolicyID:%q,delayMinutes:7,actions:[{type:"builtin-rotation",args:{rotation_id:%q}}]}){id}}`, h.UUID("policy-a"), h.UUID("rotation-b")),
				"rule_foreign_user":            fmt.Sprintf(`mutation{updateScheduleTarget(input:{scheduleID:%q,target:{type:user,id:%q},rules:[{}]})}`, h.UUID("schedule-a"), h.UUID("user-b")),
				"rule_foreign_rotation":        fmt.Sprintf(`mutation{updateScheduleTarget(input:{scheduleID:%q,target:{type:rotation,id:%q},rules:[{}]})}`, h.UUID("schedule-a"), h.UUID("rotation-b")),
				"rotation_foreign_user":        fmt.Sprintf(`mutation{updateRotation(input:{id:%q,userIDs:[%q,%q]})}`, h.UUID("rotation-a"), h.UUID("user-a2"), h.UUID("user-b")),
			}
			for name, q := range queries {
				r, rec := f01Call(t, h, name, q, "user-a", token)
				require.NotEmpty(t, r.Errors)
				rec["expected_rejection"] = true
				f01Save(t, name, rec)
				require.Equal(t, "0", f01InvalidRelationships(t, h))
			}
		})
	}
}

func TestExistingRootGlobalCurrentAuthority(t *testing.T) {
	h := f01Harness(t)
	token := h.GraphQLToken(h.UUID("user-a"))
	for _, stage := range []struct {
		name, role string
		pa, home   bool
	}{
		{"pa_member", "ORG_MEMBER", true, true}, {"pa_admin", "ORG_ADMIN", true, true}, {"revoked_pa_kept_orgadmin", "ORG_ADMIN", false, true}, {"revoked_all_management", "ORG_MEMBER", false, false}, {"pa_restored", "ORG_MEMBER", true, true},
	} {
		ikSetAuthority(t, h, stage.role, stage.pa)
		for _, kind := range []string{"EP", "Schedule", "Rotation"} {
			for _, s := range []string{"a", "b"} {
				label := stage.name + "_" + kind + "_" + s
				q := f01RootQuery(h, kind, "update", s, label)
				r, rec := f01Call(t, h, label, q, "user-a", token)
				wantObserved := stage.pa || (stage.home && s == "a")
				rec["same_signed_session_reused"] = true
				rec["expected_current_source_behavior_allow"] = wantObserved
				rec["product_policy_allow"] = stage.pa || (stage.role == "ORG_ADMIN" && s == "a")
				f01Save(t, label, rec)
				require.Equal(t, wantObserved, len(r.Errors) == 0)
				f01RootPersist(t, h, kind, "update", s, label, len(r.Errors) == 0)
				if stage.name == "revoked_all_management" {
					r, rec = f01Call(t, h, label+"_delete", f01RootQuery(h, kind, "delete", s, label), "user-a", token)
					require.NotEmpty(t, r.Errors)
					rec["same_signed_session_reused"] = true
					f01Save(t, label+"_delete", rec)
				}
			}
		}
		if stage.name == "revoked_all_management" {
			for _, op := range []string{"step_update", "step_create", "rule_user", "rule_rotation", "participants", "active_index"} {
				r, rec := f01Call(t, h, stage.name+"_"+op, f01NestedQuery(h, op, "a"), "user-a", token)
				require.NotEmpty(t, r.Errors)
				rec["same_signed_session_reused"] = true
				f01Save(t, stage.name+"_"+op, rec)
			}
		}
	}
}

func TestExistingRootGlobalCatalog(t *testing.T) {
	h := f01Harness(t)
	constraints := f01Scalar(t, h, `SELECT coalesce(jsonb_agg(jsonb_build_object('table',c.conrelid::regclass::text,'referenced_table',c.confrelid::regclass::text,'name',c.conname,'delete_action',c.confdeltype,'definition',pg_get_constraintdef(c.oid)) ORDER BY c.conrelid::regclass::text,c.conname),'[]')::text FROM pg_constraint c WHERE c.contype='f' AND (c.confrelid IN ('escalation_policies'::regclass,'escalation_policy_steps'::regclass,'schedules'::regclass,'rotations'::regclass,'rotation_participants'::regclass) OR c.conrelid IN ('escalation_policy_actions'::regclass,'schedule_rules'::regclass,'rotation_participants'::regclass,'rotation_state'::regclass))`)
	triggers := f01Scalar(t, h, `SELECT coalesce(jsonb_agg(jsonb_build_object('table',tgrelid::regclass::text,'name',tgname,'definition',pg_get_triggerdef(oid),'function',pg_get_functiondef(tgfoid)) ORDER BY tgrelid::regclass::text,tgname),'[]')::text FROM pg_trigger WHERE NOT tgisinternal AND tgrelid IN ('escalation_policies'::regclass,'escalation_policy_steps'::regclass,'escalation_policy_actions'::regclass,'schedule_rules'::regclass,'schedules'::regclass,'rotations'::regclass,'rotation_participants'::regclass,'rotation_state'::regclass)`)
	f01Save(t, "live-schema-catalog", map[string]any{"foreign_keys": json.RawMessage(constraints), "triggers": json.RawMessage(triggers), "snapshot_tables": strings.Join(f01Tables, ","), "actor": f01Identity(t, h, "user-a")})
}
