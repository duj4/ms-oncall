package smoke

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/test/smoke/harness"
)

func TestExistingRootGlobalForeignRelations(t *testing.T) {
	for _, actor := range f01Actors[:2] {
		t.Run(actor.name, func(t *testing.T) {
			h := f01Harness(t)
			f01Set(t, h, actor)
			queries := map[string]string{
				"step_user":     fmt.Sprintf(`mutation{updateEscalationPolicyStep(input:{id:%q,delayMinutes:19,actions:[{type:"builtin-user",args:{user_id:%q}}]})}`, h.UUID("step-b"), h.UUID("user-a2")),
				"step_schedule": fmt.Sprintf(`mutation{updateEscalationPolicyStep(input:{id:%q,delayMinutes:19,actions:[{type:"builtin-schedule",args:{schedule_id:%q}}]})}`, h.UUID("step-b"), h.UUID("schedule-a")),
				"step_rotation": fmt.Sprintf(`mutation{createEscalationPolicyStep(input:{escalationPolicyID:%q,delayMinutes:7,actions:[{type:"builtin-rotation",args:{rotation_id:%q}}]}){id}}`, h.UUID("policy-b"), h.UUID("rotation-a")),
				"step_parent":   fmt.Sprintf(`mutation{updateEscalationPolicy(input:{id:%q,description:"must roll back",stepIDs:[%q]})}`, h.UUID("policy-b"), h.UUID("step-a")),
				"rule_user":     fmt.Sprintf(`mutation{updateScheduleTarget(input:{scheduleID:%q,target:{type:user,id:%q},rules:[{}]})}`, h.UUID("schedule-b"), h.UUID("user-a2")),
				"rule_rotation": fmt.Sprintf(`mutation{updateScheduleTarget(input:{scheduleID:%q,target:{type:rotation,id:%q},rules:[{}]})}`, h.UUID("schedule-b"), h.UUID("rotation-a")),
				"rotation_user": fmt.Sprintf(`mutation{updateRotation(input:{id:%q,description:"must roll back",userIDs:[%q,%q]})}`, h.UUID("rotation-b"), h.UUID("user-b"), h.UUID("user-a2")),
			}
			for name, query := range queries {
				r, _ := f01Call(t, h, name, query, "user-a", h.GraphQLToken(h.UUID("user-a")))
				require.NotEmpty(t, r.Errors)
				require.Equal(t, "0", f01InvalidRelationships(t, h))
			}
		})
	}
}

func TestExistingRootGlobalDefaultPlatformAdmin(t *testing.T) {
	h := f01Harness(t)
	f01Set(t, h, f01Actor{name: "DefaultPlatformAdmin", role: "ORG_MEMBER", pa: true, restricted: true})
	token := h.GraphQLToken(h.UUID("user-a"))
	for _, org := range []string{"a", "b"} {
		for _, kind := range []string{"EP", "Schedule", "Rotation"} {
			for _, op := range []string{"update", "delete"} {
				r, _ := f01Call(t, h, "restricted_"+kind+"_"+op+"_"+org, f01RootQuery(h, kind, op, org, "must remain unchanged"), "user-a", token)
				require.NotEmpty(t, r.Errors)
			}
		}
		for _, op := range []string{"step_update", "step_create", "rule_user", "rule_rotation", "participants", "active_index"} {
			r, _ := f01Call(t, h, "restricted_"+op+"_"+org, f01NestedQuery(h, op, org), "user-a", token)
			require.NotEmpty(t, r.Errors)
		}
	}
}

func TestExistingRootGlobalNestedRootBoundary(t *testing.T) {
	for _, actor := range f01Actors[:2] {
		t.Run(actor.name, func(t *testing.T) {
			h := f01Harness(t)
			f01Set(t, h, actor)
			rotation := fmt.Sprintf(`{name:"F01 nested rotation",type:daily,timeZone:"Etc/UTC",start:"2090-01-01T00:00:00Z",favorite:true,userIDs:[%q]}`, h.UUID("user-a2"))
			schedule := `{name:"F01 nested schedule",timeZone:"Etc/UTC",favorite:true}`
			for _, nested := range []string{"newRotation:" + rotation, "newSchedule:" + schedule, "newSchedule:{name:\"F01 deep schedule\",timeZone:\"Etc/UTC\",targets:[{newRotation:" + rotation + ",rules:[{}]}]}"} {
				query := fmt.Sprintf(`mutation{createEscalationPolicyStep(input:{escalationPolicyID:%q,delayMinutes:3,%s}){id}}`, h.UUID("policy-b"), nested)
				r, _ := f01Call(t, h, "foreign_nested", query, "user-a", h.GraphQLToken(h.UUID("user-a")))
				require.NotEmpty(t, r.Errors)
			}
			for _, nested := range []string{"newRotation:" + rotation, "newSchedule:" + schedule} {
				query := fmt.Sprintf(`mutation{createEscalationPolicyStep(input:{escalationPolicyID:%q,delayMinutes:3,%s}){id}}`, h.UUID("policy-a"), nested)
				r, _ := f01Call(t, h, "home_nested", query, "user-a", h.GraphQLToken(h.UUID("user-a")))
				require.Empty(t, r.Errors)
			}
			for _, row := range []struct{ table, name string }{{"rotations", "F01 nested rotation"}, {"schedules", "F01 nested schedule"}} {
				require.Equal(t, harness.SmokeOrganizationID, f01Scalar(t, h, "SELECT organization_id::text FROM "+row.table+" WHERE name=$1", row.name))
			}
			for _, query := range []string{
				`mutation{createEscalationPolicy(input:{name:"F01 home EP"}){id}}`,
				`mutation{createSchedule(input:{name:"F01 home Schedule",timeZone:"Etc/UTC"}){id}}`,
				fmt.Sprintf(`mutation{createRotation(input:%s){id}}`, strings.Replace(rotation, "F01 nested rotation", "F01 home Rotation", 1)),
			} {
				r, _ := f01Call(t, h, "home_root_create", query, "user-a", h.GraphQLToken(h.UUID("user-a")))
				require.Empty(t, r.Errors)
			}
			for kind, table := range map[string]string{"EP": "escalation_policies", "Schedule": "schedules", "Rotation": "rotations"} {
				require.Equal(t, harness.SmokeOrganizationID, f01Scalar(t, h, "SELECT organization_id::text FROM "+table+" WHERE name=$1", "F01 home "+kind))
			}
			for _, op := range []string{"temporary_set", "temporary_clear", "notification_clear"} {
				query := srB1ManagementQueries(h)[op]
				if op == "temporary_set" {
					query = fmt.Sprintf(`mutation{setTemporarySchedule(input:{scheduleID:%q,start:"2090-01-01T00:00:00Z",end:"2090-01-01T04:00:00Z",shifts:[]})}`, h.UUID("schedule-a"))
				}
				homeControl, _ := f01Call(t, h, "unchanged_home_control_"+op, query, "user-a", h.GraphQLToken(h.UUID("user-a")))
				require.Empty(t, homeControl.Errors)
				query = strings.ReplaceAll(query, h.UUID("schedule-a"), h.UUID("schedule-b"))
				r, _ := f01Call(t, h, "unchanged_home_only_"+op, query, "user-a", h.GraphQLToken(h.UUID("user-a")))
				require.NotEmpty(t, r.Errors)
			}
			require.Equal(t, "0", f01InvalidRelationships(t, h))
		})
	}
}

func TestExistingRootGlobalMixedGroupScopes(t *testing.T) {
	for _, actor := range f01Actors[:2] {
		for _, reverse := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/reverse=%t", actor.name, reverse), func(t *testing.T) {
				h := f01Harness(t)
				f01Set(t, h, actor)
				for _, org := range []string{"a", "b"} {
					epB1Exec(t, h, `INSERT INTO services(id,organization_id,escalation_policy_id,name) VALUES($1,$2,$3,$4)`, h.UUID("service-"+org), f01Org(h, org), h.UUID("policy-"+org), "F01 mixed service "+org)
				}
				a, b := "a", "b"
				if reverse {
					a, b = b, a
				}
				query := fmt.Sprintf(`mutation{deleteAll(input:[{type:rotation,id:%q},{type:schedule,id:%q},{type:service,id:%q},{type:escalationPolicy,id:%q}])}`, h.UUID("rotation-"+b), h.UUID("schedule-"+a), h.UUID("service-"+b), h.UUID("policy-"+b))
				r, rec := f01Call(t, h, "mixed_distinct_scopes", query, "user-a", h.GraphQLToken(h.UUID("user-a")))
				require.Empty(t, r.Errors)
				for _, row := range []struct{ table, id string }{{"rotations", "rotation-" + b}, {"schedules", "schedule-" + a}, {"services", "service-" + b}, {"escalation_policies", "policy-" + b}} {
					require.Equal(t, "0", f01Scalar(t, h, "SELECT count(*)::text FROM "+row.table+" WHERE id=$1", h.UUID(row.id)))
				}
				for _, row := range []struct{ table, id string }{{"rotations", "rotation-" + a}, {"schedules", "schedule-" + b}, {"services", "service-" + a}, {"escalation_policies", "policy-" + a}} {
					require.Equal(t, "1", f01Scalar(t, h, "SELECT count(*)::text FROM "+row.table+" WHERE id=$1", h.UUID(row.id)))
				}
				rec["independent_group_scopes_and_persistence_verified"] = true
				f01Save(t, "mixed_scopes_asserted", rec)
			})
		}
	}
}

func TestExistingRootGlobalForeignCascade(t *testing.T) {
	for _, actor := range f01Actors[:2] {
		for _, rel := range []string{"rotation_rule", "rotation_action", "schedule_action"} {
			t.Run(actor.name+"/"+rel, func(t *testing.T) {
				h := f01Harness(t)
				f01Set(t, h, actor)
				kind := "Rotation"
				switch rel {
				case "rotation_rule":
					epB1Exec(t, h, `INSERT INTO schedule_rules(schedule_id,tgt_rotation_id) VALUES($1,$2)`, h.UUID("schedule-a"), h.UUID("rotation-b"))
				case "rotation_action":
					epB1Exec(t, h, `INSERT INTO escalation_policy_actions(escalation_policy_step_id,rotation_id) VALUES($1,$2)`, h.UUID("step-a"), h.UUID("rotation-b"))
				case "schedule_action":
					kind = "Schedule"
					epB1Exec(t, h, `INSERT INTO escalation_policy_actions(escalation_policy_step_id,schedule_id) VALUES($1,$2)`, h.UUID("step-a"), h.UUID("schedule-b"))
				}
				require.Equal(t, "1", f01InvalidRelationships(t, h), "explicit isolated historical-invalid fixture")
				r, _ := f01Call(t, h, "foreign_cascade_denied", f01RootQuery(h, kind, "delete", "b", ""), "user-a", h.GraphQLToken(h.UUID("user-a")))
				require.NotEmpty(t, r.Errors)
				// Even an independently authorized EP group cannot legitimize the
				// illegal relationship or let its Action disappear via CASCADE.
				query := fmt.Sprintf(`mutation{deleteAll(input:[{type:%s,id:%q},{type:escalationPolicy,id:%q}])}`, f01Type(kind), h.UUID(f01Root(kind)+"-b"), h.UUID("policy-a"))
				r, _ = f01Call(t, h, "mixed_invalid_cascade_denied", query, "user-a", h.GraphQLToken(h.UUID("user-a")))
				require.NotEmpty(t, r.Errors)
			})
		}
	}
}

func TestExistingRootGlobalParentAfterLock(t *testing.T) {
	for _, kind := range []string{"step", "schedule"} {
		t.Run(kind, func(t *testing.T) {
			h := f01Harness(t)
			f01Set(t, h, f01Actors[0])
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			writer, observer := lc1Connection(t, ctx, h), lc1Connection(t, ctx, h)
			gate, err := writer.Begin(ctx)
			require.NoError(t, err)
			var requests sync.WaitGroup
			defer func() { _ = gate.Rollback(context.Background()); cancel(); requests.Wait() }()
			query := f01NestedQuery(h, "step_update", "b")
			if kind == "step" {
				_, err = gate.Exec(ctx, `SELECT id FROM escalation_policy_steps WHERE id=$1 FOR UPDATE`, h.UUID("step-b"))
			} else {
				epB1Exec(t, h, `DELETE FROM schedule_rules WHERE schedule_id=$1`, h.UUID("schedule-a"))
				_, err = gate.Exec(ctx, `SELECT id FROM schedules WHERE id=$1 FOR UPDATE`, h.UUID("schedule-a"))
				query = f01RootQuery(h, "Schedule", "update", "a", "F01 after lock")
			}
			require.NoError(t, err)
			before := f01Snapshot(t, h)
			request := lc1Request(t, ctx, h, &requests, query)
			pid := lc1BlockedBy(t, ctx, observer, int(writer.PgConn().PID()))
			if kind == "step" {
				// Step Parent IDs are immutable in PostgreSQL. Change only the
				// actual Parent's Organization in this isolated external-writer probe.
				_, err = gate.Exec(ctx, `UPDATE escalation_policies SET organization_id=$1 WHERE id=$2`, harness.SmokeOrganizationID, h.UUID("policy-b"))
			} else {
				_, err = gate.Exec(ctx, `UPDATE schedules SET organization_id=$1 WHERE id=$2`, h.UUID("org-b"), h.UUID("schedule-a"))
			}
			require.NoError(t, err)
			require.NoError(t, gate.Commit(ctx))
			result := <-request
			rotationRuleDeleteResult(t, result, kind == "step")
			if kind == "step" {
				require.Equal(t, "1", f01Scalar(t, h, `SELECT delay::text FROM escalation_policy_steps WHERE id=$1`, h.UUID("step-b")))
				after := f01Snapshot(t, h)
				for table := range before {
					if table != "escalation_policies" {
						require.Equal(t, before[table], after[table], table)
					}
				}
			} else {
				require.Equal(t, "F01 after lock", f01Scalar(t, h, `SELECT description FROM schedules WHERE id=$1`, h.UUID("schedule-a")))
				require.Equal(t, h.UUID("org-b"), f01Scalar(t, h, `SELECT target_organization_id::text FROM schedule_rotation_update_audit_events WHERE target_id=$1 AND outcome='committed'`, h.UUID("schedule-a")))
			}
			f01Save(t, "actual_lock_wait", map[string]any{"writer_pid": writer.PgConn().PID(), "request_pid": pid, "response": result.response, "before": before, "after": f01Snapshot(t, h), "external_fixture_writer": kind})
		})
	}
}

func TestExistingRootGlobalNaturalDeadlock(t *testing.T) {
	for _, actor := range f01Actors[:2] {
		t.Run(actor.name, func(t *testing.T) {
			h := f01Harness(t)
			f01Set(t, h, actor)
			epB1Exec(t, h, `INSERT INTO schedule_rules(id,schedule_id,tgt_rotation_id) VALUES($1,$2,$3)`, h.UUID("global-rule"), h.UUID("schedule-b"), h.UUID("rotation-b"))
			ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
			defer cancel()
			writer, observer := lc1Connection(t, ctx, h), lc1Connection(t, ctx, h)
			gate, err := writer.Begin(ctx)
			require.NoError(t, err)
			var requests sync.WaitGroup
			defer func() { _ = gate.Rollback(context.Background()); cancel(); requests.Wait() }()
			_, err = gate.Exec(ctx, `SELECT id FROM schedules WHERE id=$1 FOR UPDATE`, h.UUID("schedule-b"))
			require.NoError(t, err)
			before := f01Snapshot(t, h)
			request := lc1Request(t, ctx, h, &requests, f01RootQuery(h, "Rotation", "delete", "b", ""))
			pid := lc1BlockedBy(t, ctx, observer, int(writer.PgConn().PID()))
			_, updateErr := gate.Exec(ctx, `UPDATE schedule_rules SET schedule_id=$1 WHERE id=$2`, h.UUID("schedule-a"), h.UUID("global-rule"))
			writerAborted := updateErr != nil
			if writerAborted {
				var pgErr *pgconn.PgError
				require.ErrorAs(t, updateErr, &pgErr)
				require.Equal(t, "40P01", pgErr.Code)
				require.NoError(t, gate.Rollback(ctx))
			} else {
				require.NoError(t, gate.Commit(ctx))
			}
			result := <-request
			rotationRuleDeleteResult(t, result, !writerAborted)
			if !writerAborted {
				after := f01Snapshot(t, h)
				for table := range before {
					if table != "schedule_rules" {
						require.Equal(t, before[table], after[table], table)
					}
				}
			} else {
				require.Equal(t, "0", f01Scalar(t, h, `SELECT count(*)::text FROM rotations WHERE id=$1`, h.UUID("rotation-b")))
			}
			f01Save(t, "natural_deadlock", map[string]any{"request_pid": pid, "writer_aborted_40P01": writerAborted, "before": before, "after": f01Snapshot(t, h), "response": result.response})
		})
	}
}

func TestExistingRootGlobalRetryRevalidates(t *testing.T) {
	h := f01Harness(t)
	f01Set(t, h, f01Actors[0])
	epB1Exec(t, h, `CREATE SEQUENCE global_retry_witness;
		CREATE FUNCTION global_retry_once() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
		IF nextval('global_retry_witness')=1 THEN RAISE EXCEPTION 'F01 injected temporary failure' USING ERRCODE='40P01'; END IF; RETURN OLD; END $$;
		CREATE TRIGGER global_retry_once BEFORE DELETE ON rotations FOR EACH ROW EXECUTE FUNCTION global_retry_once()`)
	h.IgnoreErrorsWith("F01 injected temporary failure")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	var requests sync.WaitGroup
	defer func() { cancel(); requests.Wait() }()
	before := f01Snapshot(t, h)
	request := lc1Request(t, ctx, h, &requests, f01RootQuery(h, "Rotation", "delete", "b", ""))
	require.Eventually(t, func() bool { return f01Scalar(t, h, `SELECT is_called::text FROM global_retry_witness`) == "true" }, 5*time.Second, 5*time.Millisecond)
	epB1Exec(t, h, `INSERT INTO schedule_rules(schedule_id,tgt_rotation_id) VALUES($1,$2)`, h.UUID("schedule-a"), h.UUID("rotation-b"))
	result := <-request
	rotationRuleDeleteResult(t, result, true)
	after := f01Snapshot(t, h)
	for table := range before {
		if table != "schedule_rules" {
			require.Equal(t, before[table], after[table], table)
		}
	}
	require.Equal(t, "1", f01Scalar(t, h, `SELECT last_value::text FROM global_retry_witness`))
	f01Save(t, "retry_revalidated", map[string]any{"before": before, "after": after, "response": result.response, "explicit_injected_sqlstate": "40P01", "delete_attempts": 1})
}
