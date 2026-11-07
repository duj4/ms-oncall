package smoke

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/test/smoke/harness"
)

const rotationRuleDeleteSQL = epB1SQL + `
DELETE FROM escalation_policy_actions;
INSERT INTO escalation_policy_actions(id,escalation_policy_step_id,rotation_id)
VALUES ({{uuid "f02-action"}},{{uuid "step-a1"}},{{uuid "rotation-a"}});
INSERT INTO schedule_rules(id,schedule_id,tgt_rotation_id) VALUES
 ({{uuid "f02-rule-a"}},{{uuid "schedule-a"}},{{uuid "rotation-a"}}),
 ({{uuid "f02-rule-b"}},{{uuid "schedule-b"}},{{uuid "rotation-b"}});
INSERT INTO rotation_participants(id,rotation_id,user_id,position) VALUES
 ({{uuid "f02-part-a"}},{{uuid "rotation-a"}},{{uuid "user-a"}},0),
 ({{uuid "f02-part-b"}},{{uuid "rotation-b"}},{{uuid "user-other"}},0);
INSERT INTO user_favorites(user_id,tgt_rotation_id) VALUES
 ({{uuid "user-a"}},{{uuid "rotation-a"}}),
 ({{uuid "user-other"}},{{uuid "rotation-b"}});
INSERT INTO integration_keys(id,service_id,name,type)
VALUES ({{uuid "f02-key"}},{{uuid "service-a"}},'Synthetic F02 key','generic');
`

func rotationRuleDeleteHarness(t *testing.T, foreign bool) *harness.Harness {
	t.Helper()
	h := harness.NewHarness(t, rotationRuleDeleteSQL, "")
	t.Cleanup(h.Close)
	pauseStepOrganizationEngine(t, h)
	h.GraphQLToken(h.UUID("user-a"))
	h.IgnoreErrorsWith("sql: no rows in result set")
	for _, org := range []string{"a", "b"} {
		epB1Exec(t, h, `INSERT INTO rotation_state(rotation_id,position,rotation_participant_id,shift_start)
			VALUES($1,0,$2,now()) ON CONFLICT(rotation_id) DO UPDATE SET position=0,rotation_participant_id=$2`, h.UUID("rotation-"+org), h.UUID("f02-part-"+org))
	}
	if foreign {
		epB1Exec(t, h, `INSERT INTO schedule_rules(id,schedule_id,tgt_rotation_id) VALUES($1,$2,$3)`, h.UUID("f02-foreign"), h.UUID("schedule-b"), h.UUID("rotation-a"))
	}
	rotationRuleDeleteSave(t, "identity", map[string]any{
		"fixture":           "rotationRuleDeleteSQL v1; historical-invalid Rule injected only through fixture SQL",
		"database":          epB1Scalar(t, h, `SELECT current_database()`),
		"system_identifier": epB1Scalar(t, h, `SELECT system_identifier::text FROM pg_control_system()`),
		"actor":             rotationRuleDeleteActor(t, h),
	})
	return h
}

func rotationRuleDeleteSave(t *testing.T, label string, v any) {
	t.Helper()
	if dir := os.Getenv("D02_F02_EVIDENCE"); dir != "" {
		b, err := json.MarshalIndent(v, "", "  ")
		require.NoError(t, err)
		name := strings.ReplaceAll(t.Name(), "/", "_") + "-" + label + "-*.json"
		file, err := os.CreateTemp(dir, name)
		require.NoError(t, err)
		defer file.Close()
		_, err = file.Write(append(b, '\n'))
		require.NoError(t, err)
	}
}

func rotationRuleDeleteActor(t *testing.T, h *harness.Harness) string {
	t.Helper()
	return epB1Scalar(t, h, `SELECT row_to_json(r)::text FROM (
		SELECT u.id,u.role,a.effective_organization_id,a.organization_role,a.mapping_outcome
		FROM users u LEFT JOIN user_organization_assignments a ON a.user_id=u.id WHERE u.id=$1) r`, h.UUID("user-a"))
}

func rotationRuleDeleteSnapshot(t *testing.T, h *harness.Harness) map[string]string {
	t.Helper()
	out := epB1Snapshot(t, h)
	for _, table := range []string{"schedule_data", "schedule_on_call_users", "user_overrides", "integration_keys", "uik_config"} {
		out[table] = epB1Scalar(t, h, `SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text),'[]'::jsonb)::text FROM `+table+` r`)
	}
	return out
}

func rotationRuleDeleteForeignSnapshot(t *testing.T, h *harness.Harness) map[string]string {
	t.Helper()
	out := make(map[string]string)
	for table, query := range map[string]string{
		"rotations":    `SELECT * FROM rotations WHERE organization_id=$1`,
		"participants": `SELECT p.* FROM rotation_participants p JOIN rotations r ON r.id=p.rotation_id WHERE r.organization_id=$1`,
		"state":        `SELECT p.* FROM rotation_state p JOIN rotations r ON r.id=p.rotation_id WHERE r.organization_id=$1`,
		"favorites":    `SELECT p.* FROM user_favorites p JOIN rotations r ON r.id=p.tgt_rotation_id WHERE r.organization_id=$1`,
		"schedules":    `SELECT * FROM schedules WHERE organization_id=$1`,
		"rules":        `SELECT p.* FROM schedule_rules p JOIN schedules s ON s.id=p.schedule_id WHERE s.organization_id=$1`,
		"policies":     `SELECT * FROM escalation_policies WHERE organization_id=$1`,
		"steps":        `SELECT p.* FROM escalation_policy_steps p JOIN escalation_policies e ON e.id=p.escalation_policy_id WHERE e.organization_id=$1`,
	} {
		out[table] = epB1Scalar(t, h, `SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text),'[]'::jsonb)::text FROM (`+query+`) r`, h.UUID("org-b"))
	}
	return out
}

func rotationRuleDeleteCall(t *testing.T, h *harness.Harness, query string, denied bool) {
	t.Helper()
	before := rotationRuleDeleteSnapshot(t, h)
	foreignBefore := rotationRuleDeleteForeignSnapshot(t, h)
	response := stepOrganizationQuery(t, h, query)
	after := rotationRuleDeleteSnapshot(t, h)
	rotationRuleDeleteSave(t, "http-sql", map[string]any{
		"query": query, "authentication": "real signed Human session; credential omitted", "http_status": http.StatusOK,
		"actor": rotationRuleDeleteActor(t, h), "response": response, "before": before, "after": after,
	})
	require.Equal(t, foreignBefore, rotationRuleDeleteForeignSnapshot(t, h), "all unrelated foreign business rows must remain byte-equivalent")
	if denied {
		require.NotEmpty(t, response.Errors)
		require.Equal(t, before, after, "the complete business transaction must roll back")
		for _, sensitive := range []string{h.UUID("org-b"), h.UUID("schedule-b"), h.UUID("f02-foreign")} {
			b, err := json.Marshal(response.Errors)
			require.NoError(t, err)
			require.NotContains(t, string(b), sensitive)
		}
	} else {
		require.Empty(t, response.Errors)
		for _, table := range []string{"rotations", "schedules", "escalation_policies"} {
			require.Equal(t, "1", epB1Count(t, h, table, h.UUID(map[string]string{"rotations": "rotation-b", "schedules": "schedule-b", "escalation_policies": "policy-b"}[table])))
		}
		require.Equal(t, "1", epB1Count(t, h, "schedule_rules", h.UUID("f02-rule-b")))
	}
}

func TestRotationRuleDeleteRoles(t *testing.T) {
	for _, actor := range []struct {
		name, role     string
		pa, restricted bool
	}{
		{"OrgAdmin", "ORG_ADMIN", false, false},
		{"PAHomeMember", "ORG_MEMBER", true, false},
		{"PAHomeAdmin", "ORG_ADMIN", true, false},
		{"OrgMember", "ORG_MEMBER", false, false},
		{"Default", "ORG_MEMBER", false, true},
		{"DefaultPA", "ORG_MEMBER", true, true},
	} {
		for _, foreign := range []bool{true, false} {
			t.Run(fmt.Sprintf("%s/foreign=%t", actor.name, foreign), func(t *testing.T) {
				h := rotationRuleDeleteHarness(t, foreign)
				ikSetAuthority(t, h, actor.role, actor.pa)
				if actor.restricted {
					epB1Exec(t, h, `DELETE FROM user_organization_assignments WHERE user_id=$1`, h.UUID("user-a"))
				}
				denied := foreign || actor.restricted || (!actor.pa && actor.role == "ORG_MEMBER")
				before := rotationRuleDeleteSnapshot(t, h)
				rotationRuleDeleteCall(t, h, lc1Delete(h, "rotation-a"), denied)
				if !denied {
					for _, table := range []string{"rotations", "schedule_rules", "rotation_participants", "escalation_policy_actions"} {
						key := map[string]string{"rotations": "rotation-a", "schedule_rules": "f02-rule-a", "rotation_participants": "f02-part-a", "escalation_policy_actions": "f02-action"}[table]
						require.Equal(t, "0", epB1Count(t, h, table, h.UUID(key)))
					}
					require.Equal(t, "0", epB1Scalar(t, h, `SELECT count(*)::text FROM rotation_state WHERE rotation_id=$1`, h.UUID("rotation-a")))
					require.Equal(t, "0", epB1Scalar(t, h, `SELECT count(*)::text FROM user_favorites WHERE tgt_rotation_id=$1`, h.UUID("rotation-a")))
					require.Equal(t, before["schedules"], rotationRuleDeleteSnapshot(t, h)["schedules"])
				}
			})
		}
	}
}

func rotationRuleDeleteWitness(t *testing.T, h *harness.Harness) {
	t.Helper()
	epB1Exec(t, h, `CREATE SEQUENCE f02_delete_witness;
		CREATE FUNCTION f02_witness() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
		PERFORM nextval('f02_delete_witness'); RETURN OLD; END $$;
		CREATE TRIGGER f02_witness BEFORE DELETE ON rotations FOR EACH ROW EXECUTE FUNCTION f02_witness()`)
}

func TestRotationRuleDeleteCompleteSet(t *testing.T) {
	for _, tc := range []struct {
		name                       string
		targets                    []string
		denied, foreign, attempted bool
	}{
		{"multiple", []string{"rotation-a", "rotation-a2"}, false, false, true},
		{"duplicate", []string{"rotation-a", "rotation-a"}, false, false, true},
		{"missing", []string{"rotation-missing"}, true, false, false},
		{"valid-missing", []string{"rotation-a", "rotation-missing"}, true, false, false},
		{"mixed", []string{"rotation-a", "schedule-a", "service-service-a", "escalationPolicy-policy-a"}, false, false, true},
		{"integration-key", []string{"rotation-a", "integrationKey-f02-key"}, false, false, true},
		{"foreign-mixed", []string{"rotation-a2", "rotation-a", "schedule-a", "escalationPolicy-policy-a", "integrationKey-f02-key"}, true, true, false},
		{"late-missing-policy", []string{"rotation-a", "schedule-a", "escalationPolicy-missing"}, true, false, true},
		{"late-foreign-policy", []string{"rotation-a", "escalationPolicy-policy-b"}, true, false, true},
		{"late-missing-key", []string{"rotation-a", "integrationKey-missing"}, true, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := rotationRuleDeleteHarness(t, tc.foreign)
			rotationRuleDeleteWitness(t, h)
			var targets []string
			for _, target := range tc.targets {
				kind, key, _ := strings.Cut(target, "-")
				if kind == "rotation" || kind == "schedule" {
					key = target
				}
				targets = append(targets, fmt.Sprintf(`{type:%s,id:%q}`, kind, h.UUID(key)))
			}
			rotationRuleDeleteCall(t, h, `mutation{deleteAll(input:[`+strings.Join(targets, ",")+`])}`, tc.denied)
			if !tc.denied {
				for _, target := range tc.targets {
					kind, key, _ := strings.Cut(target, "-")
					if kind == "rotation" || kind == "schedule" {
						key = target
					}
					table := map[string]string{"rotation": "rotations", "schedule": "schedules", "escalationPolicy": "escalation_policies", "service": "services", "integrationKey": "integration_keys"}[kind]
					require.Equal(t, "0", epB1Count(t, h, table, h.UUID(key)), target)
				}
			}
			witness := epB1Scalar(t, h, `SELECT is_called::text FROM f02_delete_witness`)
			require.Equal(t, fmt.Sprint(tc.attempted), witness, "nontransactional witness proves actual DELETE attempts, including rolled-back ones")
			rotationRuleDeleteSave(t, "witness", map[string]any{"delete_attempted": witness, "transaction_denied": tc.denied})
		})
	}
	for _, count := range []int{50, 51} {
		t.Run(fmt.Sprintf("limit-%d", count), func(t *testing.T) {
			h := rotationRuleDeleteHarness(t, false)
			targets := make([]string, count)
			for i := range targets {
				targets[i] = fmt.Sprintf("rotation-limit-%d", i)
				epB1Exec(t, h, `INSERT INTO rotations(id,organization_id,name,type,start_time,shift_length,time_zone)
					VALUES($1,$2,$3,'daily',now(),1,'Etc/UTC')`, h.UUID(targets[i]), harness.SmokeOrganizationID, targets[i])
			}
			rotationRuleDeleteCall(t, h, lc1Delete(h, targets...), count > 50)
			if count == 50 {
				for _, target := range targets {
					require.Equal(t, "0", epB1Count(t, h, "rotations", h.UUID(target)))
				}
			}
		})
	}
	t.Run("invalid-uuid", func(t *testing.T) {
		h := rotationRuleDeleteHarness(t, false)
		rotationRuleDeleteCall(t, h, `mutation{deleteAll(input:[{type:rotation,id:"invalid"}])}`, true)
	})
}

func TestRotationRuleDeleteCurrentAuthority(t *testing.T) {
	h := rotationRuleDeleteHarness(t, false)
	// Reuse exactly the same signed Session across persistent authority changes.
	h.GraphQLToken(h.UUID("user-a"))
	ikSetAuthority(t, h, "ORG_MEMBER", false)
	rotationRuleDeleteCall(t, h, lc1Delete(h, "rotation-a"), true)
	// F01 approves PA Foreign Existing Root deletion. Keep this Foreign
	// rejection control under ordinary OrgAdmin; the F01 matrix verifies PA.
	ikSetAuthority(t, h, "ORG_ADMIN", false)
	rotationRuleDeleteCall(t, h, lc1Delete(h, "rotation-b"), true)
	ikSetAuthority(t, h, "ORG_MEMBER", true)
	epB1Exec(t, h, `INSERT INTO schedule_rules(id,schedule_id,tgt_rotation_id) VALUES($1,$2,$3)`, h.UUID("f02-foreign"), h.UUID("schedule-b"), h.UUID("rotation-a"))
	rotationRuleDeleteCall(t, h, lc1Delete(h, "rotation-a"), true)
	epB1Exec(t, h, `DELETE FROM schedule_rules WHERE id=$1`, h.UUID("f02-foreign"))
	rotationRuleDeleteCall(t, h, lc1Delete(h, "rotation-a"), false)
}

func TestRotationRuleDeleteWithoutEPAction(t *testing.T) {
	h := rotationRuleDeleteHarness(t, true)
	epB1Exec(t, h, `DELETE FROM escalation_policy_actions`)
	rotationRuleDeleteCall(t, h, lc1Delete(h, "rotation-a"), true)
	epB1Exec(t, h, `DELETE FROM schedule_rules WHERE id=$1`, h.UUID("f02-foreign"))
	rotationRuleDeleteCall(t, h, lc1Delete(h, "rotation-a"), false)
	require.Equal(t, "0", epB1Count(t, h, "rotations", h.UUID("rotation-a")))
}

func rotationRuleDeleteResult(t *testing.T, result lc1HTTPResult, denied bool) {
	t.Helper()
	require.NoError(t, result.err)
	require.Equal(t, http.StatusOK, result.status)
	if denied {
		require.NotEmpty(t, result.response.Errors)
	} else {
		require.Empty(t, result.response.Errors)
	}
}

func TestRotationRuleDeleteConcurrentReparent(t *testing.T) {
	for _, kind := range []string{"schedule-id", "rotation-away", "rotation-into", "schedule-organization", "rule-deleted"} {
		t.Run(kind, func(t *testing.T) {
			h := rotationRuleDeleteHarness(t, false)
			before := rotationRuleDeleteSnapshot(t, h)
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			writer, observer := lc1Connection(t, ctx, h), lc1Connection(t, ctx, h)
			gate, err := writer.Begin(ctx)
			require.NoError(t, err)
			var requests sync.WaitGroup
			defer func() { _ = gate.Rollback(context.Background()); cancel(); requests.Wait() }()
			switch kind {
			case "schedule-organization":
				_, err = gate.Exec(ctx, `SELECT id FROM schedules WHERE id=$1 FOR UPDATE`, h.UUID("schedule-a"))
			case "rotation-into":
				_, err = gate.Exec(ctx, `UPDATE schedule_rules SET tgt_rotation_id=$1 WHERE id=$2`, h.UUID("rotation-a"), h.UUID("f02-rule-b"))
			default:
				_, err = gate.Exec(ctx, `SELECT id FROM schedule_rules WHERE id=$1 FOR UPDATE`, h.UUID("f02-rule-a"))
			}
			require.NoError(t, err)
			request := lc1Request(t, ctx, h, &requests, lc1Delete(h, "rotation-a"))
			pid := lc1BlockedBy(t, ctx, observer, int(writer.PgConn().PID()))
			blockedQuery := ""
			require.NoError(t, observer.QueryRow(ctx, `SELECT query FROM pg_stat_activity WHERE pid=$1`, pid).Scan(&blockedQuery))
			switch kind {
			case "schedule-id":
				_, err = gate.Exec(ctx, `UPDATE schedule_rules SET schedule_id=$1 WHERE id=$2`, h.UUID("schedule-b"), h.UUID("f02-rule-a"))
			case "rotation-away":
				_, err = gate.Exec(ctx, `UPDATE schedule_rules SET tgt_rotation_id=$1,schedule_id=$2 WHERE id=$3`, h.UUID("rotation-b"), h.UUID("schedule-b"), h.UUID("f02-rule-a"))
			case "schedule-organization":
				_, err = gate.Exec(ctx, `UPDATE schedules SET organization_id=$1 WHERE id=$2`, h.UUID("org-b"), h.UUID("schedule-a"))
			case "rule-deleted":
				_, err = gate.Exec(ctx, `DELETE FROM schedule_rules WHERE id=$1`, h.UUID("f02-rule-a"))
			}
			require.NoError(t, err)
			require.NoError(t, gate.Commit(ctx))
			result := <-request
			denied := kind == "schedule-id" || kind == "rotation-into" || kind == "schedule-organization"
			rotationRuleDeleteResult(t, result, denied)
			after := rotationRuleDeleteSnapshot(t, h)
			if denied {
				for table := range before {
					if table != "schedule_rules" && table != "schedules" {
						require.Equal(t, before[table], after[table], table)
					}
				}
				require.Equal(t, "1", epB1Count(t, h, "rotations", h.UUID("rotation-a")))
			} else {
				require.Equal(t, "0", epB1Count(t, h, "rotations", h.UUID("rotation-a")))
			}
			if kind != "rule-deleted" {
				require.Equal(t, "1", epB1Count(t, h, "schedule_rules", h.UUID("f02-rule-"+map[bool]string{true: "b", false: "a"}[kind == "rotation-into"])))
			}
			rotationRuleDeleteSave(t, "lock-sql", map[string]any{"blocked_query": blockedQuery, "delete_pid": pid, "writer_pid": writer.PgConn().PID(), "before": before, "after": after, "response": result.response, "external_fixture_transaction": kind})
		})
	}
}

func TestRotationRuleDeleteConcurrentFences(t *testing.T) {
	h := rotationRuleDeleteHarness(t, false)
	before := rotationRuleDeleteSnapshot(t, h)
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	writer, observer := lc1Connection(t, ctx, h), lc1Connection(t, ctx, h)
	gate, err := writer.Begin(ctx)
	require.NoError(t, err)
	var requests sync.WaitGroup
	defer func() { _ = gate.Rollback(context.Background()); cancel(); requests.Wait() }()
	// Stall after the new guard and existing Action/Step locks, at the EP parent.
	_, err = gate.Exec(ctx, `SELECT id FROM escalation_policies WHERE id=$1 FOR UPDATE`, h.UUID("policy-a"))
	require.NoError(t, err)
	request := lc1Request(t, ctx, h, &requests, lc1Delete(h, "rotation-a"))
	deletePID := lc1BlockedBy(t, ctx, observer, int(writer.PgConn().PID()))
	for _, target := range []struct{ table, id string }{{"schedule_rules", "f02-rule-a"}, {"schedules", "schedule-a"}, {"rotations", "rotation-a"}} {
		_, err := observer.Exec(ctx, `SELECT id FROM `+target.table+` WHERE id=$1 FOR UPDATE NOWAIT`, h.UUID(target.id))
		var pgErr *pgconn.PgError
		require.ErrorAs(t, err, &pgErr)
		require.Equal(t, "55P03", pgErr.Code)
		t.Logf("%s fenced by DeleteAll; SQLSTATE %s", target.table, pgErr.Code)
	}
	inserter := lc1Connection(t, ctx, h)
	inserted := make(chan error, 1)
	requests.Add(1)
	go func() {
		defer requests.Done()
		_, err := inserter.Exec(ctx, `INSERT INTO schedule_rules(id,schedule_id,tgt_rotation_id) VALUES($1,$2,$3)`, h.UUID("f02-late-rule"), h.UUID("schedule-b"), h.UUID("rotation-a"))
		inserted <- err
	}()
	require.Equal(t, int(inserter.PgConn().PID()), lc1BlockedBy(t, ctx, observer, deletePID))
	// Independent signed sessions reach the real DB instead of a session limiter.
	second := serviceDeleteF1SecondRequest(t, ctx, h, &requests, lc1Delete(h, "rotation-a"))
	var secondPID int
	require.Eventually(t, func() bool {
		err := observer.QueryRow(ctx, `SELECT coalesce(max(pid),0) FROM pg_stat_activity
			WHERE datname=current_database() AND $1=ANY(pg_blocking_pids(pid)) AND pid<>$2`, deletePID, int(inserter.PgConn().PID())).Scan(&secondPID)
		return err == nil && secondPID != 0
	}, 5*time.Second, 10*time.Millisecond, "second signed-session DeleteAll must actually wait on the first transaction")
	require.NoError(t, gate.Rollback(ctx))
	result := <-request
	rotationRuleDeleteResult(t, result, false)
	secondResult := <-second
	rotationRuleDeleteResult(t, secondResult, true)
	var pgErr *pgconn.PgError
	require.ErrorAs(t, <-inserted, &pgErr)
	require.Equal(t, "23503", pgErr.Code, "late Rule must fail its real FK after deletion commits")
	require.Equal(t, "0", epB1Count(t, h, "schedule_rules", h.UUID("f02-late-rule")))
	require.Equal(t, "1", epB1Count(t, h, "schedule_rules", h.UUID("f02-rule-b")))
	rotationRuleDeleteSave(t, "lock-sql", map[string]any{"before": before, "after": rotationRuleDeleteSnapshot(t, h), "delete_pid": deletePID, "second_delete_pid": secondPID, "late_insert_sqlstate": pgErr.Code, "response": result.response, "second_response": secondResult.response})
}

func TestRotationRuleDeleteScheduleRuleDeadlock(t *testing.T) {
	h := rotationRuleDeleteHarness(t, false)
	before := rotationRuleDeleteSnapshot(t, h)
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	writer, observer := lc1Connection(t, ctx, h), lc1Connection(t, ctx, h)
	gate, err := writer.Begin(ctx)
	require.NoError(t, err)
	var requests sync.WaitGroup
	defer func() { _ = gate.Rollback(context.Background()); cancel(); requests.Wait() }()
	// Ordinary Schedule management takes the parent before its Rules. The
	// deletion guard takes the Rotation and Rule before the dependent parent.
	_, err = gate.Exec(ctx, `SELECT id FROM schedules WHERE id=$1 FOR UPDATE`, h.UUID("schedule-a"))
	require.NoError(t, err)
	request := lc1Request(t, ctx, h, &requests, lc1Delete(h, "rotation-a"))
	deletePID := lc1BlockedBy(t, ctx, observer, int(writer.PgConn().PID()))
	// Close an actual lock cycle: writer owns Schedule, deletion owns Rule.
	_, updateErr := gate.Exec(ctx, `UPDATE schedule_rules SET schedule_id=$1 WHERE id=$2`, h.UUID("schedule-b"), h.UUID("f02-rule-a"))
	writerAborted := updateErr != nil
	if writerAborted {
		var pgErr *pgconn.PgError
		require.ErrorAs(t, updateErr, &pgErr)
		require.Equal(t, "40P01", pgErr.Code)
		require.NoError(t, gate.Rollback(ctx))
	} else {
		// Deletion was the victim and must retry in a new transaction. The
		// writer's committed Foreign parent must be seen by that retry.
		require.NoError(t, gate.Commit(ctx))
	}
	result := <-request
	rotationRuleDeleteResult(t, result, !writerAborted)
	after := rotationRuleDeleteSnapshot(t, h)
	if !writerAborted {
		for table := range before {
			if table != "schedule_rules" {
				require.Equal(t, before[table], after[table], table)
			}
		}
		require.Equal(t, "1", epB1Count(t, h, "schedule_rules", h.UUID("f02-rule-a")))
	} else {
		require.Equal(t, "0", epB1Count(t, h, "rotations", h.UUID("rotation-a")))
	}
	rotationRuleDeleteSave(t, "actual-deadlock", map[string]any{"delete_pid": deletePID, "writer_aborted_40P01": writerAborted, "before": before, "after": after, "response": result.response})
}

func TestRotationRuleDeleteRetryRevalidates(t *testing.T) {
	h := rotationRuleDeleteHarness(t, false)
	// A real PostgreSQL trigger injects one explicitly labelled temporary
	// error. This complements, and does not replace, the actual deadlock test.
	epB1Exec(t, h, `CREATE SEQUENCE f02_retry_witness;
		CREATE FUNCTION f02_retry_once() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
		IF nextval('f02_retry_witness')=1 THEN
		RAISE EXCEPTION 'F02 injected temporary failure' USING ERRCODE='40P01';
		END IF; RETURN OLD; END $$;
		CREATE TRIGGER f02_retry_once BEFORE DELETE ON rotations FOR EACH ROW EXECUTE FUNCTION f02_retry_once()`)
	h.IgnoreErrorsWith("F02 injected temporary failure")
	before := rotationRuleDeleteSnapshot(t, h)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	var requests sync.WaitGroup
	defer func() { cancel(); requests.Wait() }()
	request := lc1Request(t, ctx, h, &requests, lc1Delete(h, "rotation-a"))
	require.Eventually(t, func() bool {
		return epB1Scalar(t, h, `SELECT is_called::text FROM f02_retry_witness`) == "true"
	}, 5*time.Second, 5*time.Millisecond)
	// The failed transaction has released its Rotation lock; this write commits
	// during the existing bounded retry backoff, before the next guard runs.
	epB1Exec(t, h, `INSERT INTO schedule_rules(id,schedule_id,tgt_rotation_id) VALUES($1,$2,$3)`, h.UUID("f02-foreign"), h.UUID("schedule-b"), h.UUID("rotation-a"))
	result := <-request
	rotationRuleDeleteResult(t, result, true)
	after := rotationRuleDeleteSnapshot(t, h)
	for table := range before {
		if table != "schedule_rules" {
			require.Equal(t, before[table], after[table], table)
		}
	}
	require.Equal(t, "1", epB1Count(t, h, "schedule_rules", h.UUID("f02-foreign")))
	require.Equal(t, "1", epB1Scalar(t, h, `SELECT last_value::text FROM f02_retry_witness`), "retry must reject before attempting another DELETE")
	rotationRuleDeleteSave(t, "retry", map[string]any{"before": before, "after": after, "response": result.response, "injected_sqlstate": "40P01", "delete_attempts": 1})
}

func TestRotationRuleDeleteCatalog(t *testing.T) {
	h := rotationRuleDeleteHarness(t, false)
	fk := epB1Scalar(t, h, `SELECT pg_get_constraintdef(oid) FROM pg_constraint
		WHERE conrelid='schedule_rules'::regclass AND confrelid='rotations'::regclass AND contype='f'`)
	require.Contains(t, fk, "FOREIGN KEY (tgt_rotation_id)")
	require.Contains(t, fk, "ON DELETE CASCADE")
	rotationRuleDeleteSave(t, "catalog", map[string]any{
		"rotation_rule_fk": fk,
		"constraints": epB1Scalar(t, h, `SELECT jsonb_agg(to_jsonb(r) ORDER BY r.oid)::text FROM (
			SELECT oid,conrelid::regclass::text,confrelid::regclass::text,pg_get_constraintdef(oid) AS definition
			FROM pg_constraint WHERE contype='f' AND (confrelid IN ('rotations'::regclass,'schedules'::regclass,'escalation_policies'::regclass,'escalation_policy_steps'::regclass) OR conrelid='schedule_rules'::regclass)) r`),
		"triggers": epB1Scalar(t, h, `SELECT jsonb_agg(to_jsonb(r) ORDER BY r.oid)::text FROM (
			SELECT oid,tgrelid::regclass::text,tgenabled,tgisinternal,pg_get_triggerdef(oid) AS definition FROM pg_trigger
			WHERE tgrelid IN ('rotations'::regclass,'schedule_rules'::regclass,'schedules'::regclass)) r`),
	})
}
