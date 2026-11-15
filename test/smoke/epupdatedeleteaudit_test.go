package smoke

import (
	"encoding/json"
	"fmt"
	"slices"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	epaudit "github.com/target/goalert/escalation/deleteaudit"
	"github.com/target/goalert/gadb"
	"github.com/target/goalert/graphql2"
	"github.com/target/goalert/test/smoke/harness"
	"github.com/target/goalert/user"
)

// Native PostgreSQL/HTTP regressions. The standard harness applies migrations;
// these tests must not be executed under a source-only migration authorization.
func euSuccessCount(t *testing.T, h *harness.Harness) int {
	t.Helper()
	var n int
	require.NoError(t, h.App().DB().QueryRow(`SELECT count(*) FROM escalation_policy_delete_audit_events WHERE schema_version=2 AND record_kind='success_witness'`).Scan(&n))
	return n
}

func euAddedUser(t *testing.T, h *harness.Harness) {
	t.Helper()
	_, err := h.App().DB().Exec(`INSERT INTO users(id,name) VALUES($1,'EU additional synthetic target')`, h.UUID("user-b"))
	require.NoError(t, err)
}

func euActions(t *testing.T, h *harness.Harness, step string) map[string]string {
	t.Helper()
	rows, err := h.App().DB().Query(`SELECT id,coalesce(user_id,schedule_id,rotation_id,channel_id) FROM escalation_policy_actions WHERE escalation_policy_step_id=$1`, step)
	require.NoError(t, err)
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var id, target string
		require.NoError(t, rows.Scan(&id, &target))
		out[id] = target
	}
	require.NoError(t, rows.Err())
	return out
}

func euEffects(t *testing.T, h *harness.Harness, operation, root, parent string) []epaudit.Effect {
	t.Helper()
	var raw, actualOperation, actualRoot, actualParent, org string
	var schema, version int
	require.NoError(t, h.App().DB().QueryRow(`SELECT operation,root_id,coalesce(parent_policy_id::text,''),target_organization_id,schema_version,effects_version,effects::text FROM escalation_policy_delete_audit_events WHERE schema_version=2 AND record_kind='success_witness' AND root_id=$1`, root).Scan(&actualOperation, &actualRoot, &actualParent, &org, &schema, &version, &raw))
	require.Equal(t, operation, actualOperation)
	require.Equal(t, root, actualRoot)
	require.Equal(t, parent, actualParent)
	require.Equal(t, harness.SmokeOrganizationID, org)
	require.Equal(t, 2, schema)
	require.Equal(t, 2, version)
	var effects []epaudit.Effect
	require.NoError(t, json.Unmarshal([]byte(raw), &effects))
	ids := map[string]bool{}
	for _, f := range effects {
		require.Equal(t, root, f.RootID.String())
		require.Equal(t, "deleted", f.Change)
		require.NotNil(t, f.ResourceUUID)
		require.False(t, ids[f.ResourceUUID.String()])
		ids[f.ResourceUUID.String()] = true
	}
	require.NotContains(t, sd5Rows(t, h), "SYNTHETIC_PRIVATE")
	return effects
}

func TestEPUpdateDeleteAuditStepSetsPostgres(t *testing.T) {
	for _, mode := range []string{"nil", "same", "reorder", "remove_one", "remove_multiple", "empty", "invalid_owner", "audit_failure"} {
		t.Run(mode, func(t *testing.T) {
			h := sd1Harness(t)
			db := h.App().DB()
			root := sd5EP(t, h, harness.SmokeOrganizationID)
			steps := []string{sd5Step(t, h, root), sd5Step(t, h, root), sd5Step(t, h, root)}
			actions := map[string]string{}
			for _, step := range steps {
				id := uuid.NewString()
				_, err := db.Exec(`INSERT INTO escalation_policy_actions(id,escalation_policy_step_id,user_id) VALUES($1,$2,$3);`, id, step, h.UUID("user-a"))
				require.NoError(t, err)
				actions[id] = step
				_, err = db.Exec(`INSERT INTO ep_step_on_call_users(ep_step_id,user_id) VALUES($1,$2)`, step, h.UUID("user-a"))
				require.NoError(t, err)
			}
			var desired []string
			switch mode {
			case "same":
				desired = slices.Clone(steps)
			case "reorder":
				desired = []string{steps[2], steps[0], steps[1]}
			case "remove_one", "audit_failure":
				desired = steps[:2]
			case "remove_multiple":
				desired = steps[:1]
			case "empty":
				desired = []string{}
			case "invalid_owner":
				desired = []string{steps[0], sd5Step(t, h, sd5EP(t, h, harness.SmokeOrganizationID))}
			}
			if mode == "audit_failure" {
				_, err := db.Exec(`CREATE FUNCTION eu_append_fail() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'SYNTHETIC_PRIVATE';END;$$; CREATE TRIGGER eu_append_fail BEFORE INSERT ON escalation_policy_delete_audit_events FOR EACH ROW WHEN(NEW.schema_version=2 AND NEW.record_kind='success_witness') EXECUTE FUNCTION eu_append_fail()`)
				require.NoError(t, err)
			}
			var originalName string
			require.NoError(t, db.QueryRow(`SELECT name FROM escalation_policies WHERE id=$1`, root).Scan(&originalName))
			var nameInput *string
			if mode == "invalid_owner" || mode == "audit_failure" {
				name := "EU mixed rollback " + uuid.NewString()
				nameInput = &name
			}
			_, err := sd5App(h).Mutation().UpdateEscalationPolicy(sd3System(), graphql2.UpdateEscalationPolicyInput{ID: root, StepIDs: desired, Name: nameInput})
			if mode == "invalid_owner" || mode == "audit_failure" {
				require.Error(t, err)
				require.Zero(t, euSuccessCount(t, h))
				for _, step := range steps {
					require.Equal(t, 1, serviceManagementCount(t, h, "escalation_policy_steps", step))
				}
				for id := range actions {
					require.Equal(t, 1, serviceManagementCount(t, h, "escalation_policy_actions", id))
				}
				var afterName string
				require.NoError(t, db.QueryRow(`SELECT name FROM escalation_policies WHERE id=$1`, root).Scan(&afterName))
				require.Equal(t, originalName, afterName, "a failed Step update rolls back the earlier EP field update")
				return
			}
			require.NoError(t, err)
			removed := map[string]bool{}
			if desired != nil {
				for _, step := range steps {
					if !slices.Contains(desired, step) {
						removed[step] = true
					}
				}
			}
			if len(removed) == 0 {
				require.Zero(t, euSuccessCount(t, h))
				return
			}
			require.Equal(t, 1, euSuccessCount(t, h))
			effects := euEffects(t, h, epaudit.PolicyUpdate, root, "")
			require.Len(t, effects, len(removed)*2)
			for _, f := range effects {
				switch f.ResourceType {
				case epaudit.Step:
					require.True(t, removed[f.ResourceUUID.String()])
					require.Equal(t, "EXPLICIT", f.Provenance)
					require.Equal(t, "update_induced", f.Cause)
				case epaudit.Action:
					require.True(t, removed[actions[f.ResourceUUID.String()]])
					require.Equal(t, actions[f.ResourceUUID.String()], f.ParentStepID.String())
					require.Equal(t, h.UUID("user-a"), f.TargetID.String())
					require.Equal(t, "CASCADE", f.Provenance)
					require.Equal(t, "step_delete", f.Cause)
				default:
					t.Fatal("derived/state/ordering rows are outside the effect whitelist")
				}
			}
			for step := range removed {
				var n int
				require.NoError(t, db.QueryRow(`SELECT count(*) FROM ep_step_on_call_users WHERE ep_step_id=$1`, step).Scan(&n))
				require.Zero(t, n, "derived rows are physically cascaded without business effects")
			}
			require.Equal(t, 1, serviceManagementCount(t, h, "escalation_policies", root))
		})
	}
}

func TestEPUpdateDeleteAuditActionSetsPostgres(t *testing.T) {
	for _, mode := range []string{"nil", "same", "reorder", "duplicate_retained", "remove_one", "remove_multiple", "empty", "retain_add_remove", "invalid_target", "duplicate_new", "audit_failure"} {
		t.Run(mode, func(t *testing.T) {
			h := sd1Harness(t)
			euAddedUser(t, h)
			db := h.App().DB()
			root := sd5EP(t, h, harness.SmokeOrganizationID)
			step := sd5Step(t, h, root)
			channel := uuid.NewString()
			_, err := db.Exec(`INSERT INTO notification_channels(id,name,type,value) VALUES($1,'EU synthetic channel','WEBHOOK','https://synthetic.invalid/SYNTHETIC_PRIVATE')`, channel)
			require.NoError(t, err)
			for column, id := range map[string]string{"user_id": h.UUID("user-a"), "schedule_id": h.UUID("schedule-a"), "rotation_id": h.UUID("oncall-rotation"), "channel_id": channel} {
				_, err = db.Exec(`INSERT INTO escalation_policy_actions(escalation_policy_step_id,`+column+`) VALUES($1,$2)`, step, id)
				require.NoError(t, err)
			}
			app := sd5App(h)
			existing, err := app.PolicyStore.FindAllStepActionsTx(sd3System(), nil, uuid.MustParse(step))
			require.NoError(t, err)
			require.Len(t, existing, 4)
			before := euActions(t, h, step)
			var desired []gadb.DestV1
			expected := 0
			fail := false
			switch mode {
			case "same":
				desired = slices.Clone(existing)
			case "reorder":
				desired = slices.Clone(existing)
				slices.Reverse(desired)
			case "duplicate_retained":
				desired = append(slices.Clone(existing), existing[0])
			case "remove_one":
				desired = existing[:3]
				expected = 1
			case "remove_multiple":
				desired = existing[:2]
				expected = 2
			case "empty":
				desired = []gadb.DestV1{}
				expected = 4
			case "retain_add_remove":
				desired = append(slices.Clone(existing[:1]), user.DestFromID(h.UUID("user-b")))
				expected = 3
			case "invalid_target":
				desired = []gadb.DestV1{user.DestFromID(uuid.NewString())}
				fail = true
			case "duplicate_new":
				desired = []gadb.DestV1{user.DestFromID(h.UUID("user-b")), user.DestFromID(h.UUID("user-b"))}
				fail = true
			case "audit_failure":
				desired = []gadb.DestV1{}
				fail = true
				_, err = db.Exec(`CREATE FUNCTION eu_action_append_fail() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'SYNTHETIC_PRIVATE';END;$$; CREATE TRIGGER eu_action_append_fail BEFORE INSERT ON escalation_policy_delete_audit_events FOR EACH ROW WHEN(NEW.schema_version=2 AND NEW.record_kind='success_witness') EXECUTE FUNCTION eu_action_append_fail()`)
				require.NoError(t, err)
			}
			var oldDelay int
			require.NoError(t, db.QueryRow(`SELECT delay FROM escalation_policy_steps WHERE id=$1`, step).Scan(&oldDelay))
			delay := oldDelay + 1
			_, err = app.Mutation().UpdateEscalationPolicyStep(sd3System(), graphql2.UpdateEscalationPolicyStepInput{ID: step, Actions: desired, DelayMinutes: &delay})
			after := euActions(t, h, step)
			var afterDelay int
			require.NoError(t, db.QueryRow(`SELECT delay FROM escalation_policy_steps WHERE id=$1`, step).Scan(&afterDelay))
			if fail {
				require.Error(t, err)
				require.Equal(t, before, after)
				require.Zero(t, euSuccessCount(t, h))
				require.Equal(t, oldDelay, afterDelay, "failed target/insert/audit rolls back the earlier Delay update")
				if mode == "duplicate_new" {
					require.EqualError(t, err, "same user cannot be assigned twice to the same step")
				}
				return
			}
			require.NoError(t, err)
			require.Equal(t, delay, afterDelay)
			if expected == 0 {
				require.Zero(t, euSuccessCount(t, h))
				require.Equal(t, before, after)
				return
			}
			effects := euEffects(t, h, epaudit.StepUpdate, step, root)
			require.Len(t, effects, expected)
			for _, f := range effects {
				require.Equal(t, epaudit.Action, f.ResourceType)
				target, ok := before[f.ResourceUUID.String()]
				require.True(t, ok)
				require.NotContains(t, after, f.ResourceUUID.String())
				require.Equal(t, target, f.TargetID.String())
				require.Equal(t, step, f.ParentStepID.String())
				require.Equal(t, "EXPLICIT", f.Provenance)
				require.Equal(t, "update_induced", f.Cause)
				delete(before, f.ResourceUUID.String())
			}
			for id, target := range before {
				require.Equal(t, target, after[id], "retained Action identity must survive")
			}
			for table, id := range map[string]string{"escalation_policies": root, "escalation_policy_steps": step, "users": h.UUID("user-a"), "schedules": h.UUID("schedule-a"), "rotations": h.UUID("oncall-rotation"), "notification_channels": channel} {
				require.Equal(t, 1, serviceManagementCount(t, h, table, id))
			}
			if mode == "retain_add_remove" {
				require.Len(t, after, 2)
			}
		})
	}
}

func TestEPUpdateDeleteAuditRolesHTTP(t *testing.T) {
	for _, operation := range []string{epaudit.PolicyUpdate, epaudit.StepUpdate} {
		for _, mode := range []string{"org_admin", "member", "foreign_org_admin", "foreign_pa", "default_pa"} {
			t.Run(operation+"/"+mode, func(t *testing.T) {
				h := sd1Harness(t)
				pa := mode == "foreign_pa" || mode == "default_pa"
				role := "ORG_ADMIN"
				if mode == "member" {
					role = "ORG_MEMBER"
				}
				ikSetAuthority(t, h, role, pa)
				target := harness.SmokeOrganizationID
				if mode == "foreign_pa" || mode == "foreign_org_admin" {
					target = h.UUID("org-b")
				}
				if mode == "default_pa" {
					_, err := h.App().DB().Exec(`UPDATE user_organization_assignments SET effective_organization_id='296e2656-7221-53fe-bd0a-832d24ccfd03',effective_organization_classification='DEFAULT',effective_normal_organization_id=NULL,organization_role='NONE',mapping_outcome='ZERO',matched_count=0 WHERE user_id=$1`, h.UUID("user-a"))
					require.NoError(t, err)
				}
				root := sd5EP(t, h, target)
				step := sd5Step(t, h, root)
				_, err := h.App().DB().Exec(`INSERT INTO escalation_policy_actions(escalation_policy_step_id,user_id) VALUES($1,$2)`, step, h.UUID("user-a"))
				require.NoError(t, err)
				input := fmt.Sprintf(`id:%q,stepIDs:[]`, root)
				if operation == epaudit.StepUpdate {
					input = fmt.Sprintf(`id:%q,actions:[]`, step)
				}
				var expectedLog func()
				if mode == "foreign_org_admin" && operation == epaudit.PolicyUpdate {
					expectedLog = h.ExpectBackendError("GraphQL operation failed")
				}
				response := stepOrganizationQuery(t, h, fmt.Sprintf(`mutation { alias:%s(input:{%s}) }`, operation, input))
				if expectedLog != nil {
					expectedLog()
				}
				allowed := mode != "member" && mode != "foreign_org_admin"
				if !allowed {
					require.NotEmpty(t, response.Errors)
					require.Zero(t, euSuccessCount(t, h))
					return
				}
				require.Empty(t, response.Errors)
				require.Equal(t, 1, euSuccessCount(t, h))
				var actor, org, home, authority string
				require.NoError(t, h.App().DB().QueryRow(`SELECT actor_id,target_organization_id,home_organization_id,authority_role FROM escalation_policy_delete_audit_events WHERE schema_version=2 AND record_kind='success_witness'`).Scan(&actor, &org, &home, &authority))
				require.Equal(t, h.UUID("user-a"), actor)
				require.Equal(t, target, org)
				if mode == "default_pa" {
					require.Equal(t, "296e2656-7221-53fe-bd0a-832d24ccfd03", home)
				} else {
					require.Equal(t, harness.SmokeOrganizationID, home)
				}
				if pa {
					require.Equal(t, "platform_admin", authority)
				} else {
					require.Equal(t, "org_admin", authority)
				}
			})
		}
	}
}
