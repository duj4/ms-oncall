package smoke

import (
	"context"
	"database/sql"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
	epaudit "github.com/target/goalert/escalation/deleteaudit"
	"github.com/target/goalert/gadb"
	"github.com/target/goalert/graphql2"
	"github.com/target/goalert/test/smoke/harness"
)

// These native tests intentionally use the established isolated smoke harness.
// They are not executable under a prohibition on running migrations.
func TestEPUpdateDeleteAuditCapturedChildLocksPostgres(t *testing.T) {
	for _, operation := range []string{epaudit.PolicyUpdate, epaudit.StepUpdate} {
		t.Run(operation, func(t *testing.T) {
			h := sd1Harness(t)
			euAddedUser(t, h)
			db := h.App().DB()
			root := sd5EP(t, h, harness.SmokeOrganizationID)
			step, other := sd5Step(t, h, root), sd5Step(t, h, sd5EP(t, h, harness.SmokeOrganizationID))
			action := uuid.NewString()
			_, err := db.Exec(`INSERT INTO escalation_policy_actions(id,escalation_policy_step_id,user_id) VALUES($1,$2,$3)`, action, step, h.UUID("user-a"))
			require.NoError(t, err)
			writers := sd5ExternalDB(t, h, "")
			gate, err := writers.Conn(t.Context())
			require.NoError(t, err)
			defer gate.Close()
			var pid int
			require.NoError(t, gate.QueryRowContext(t.Context(), `SELECT pg_backend_pid()`).Scan(&pid))
			_, err = gate.ExecContext(t.Context(), `SELECT pg_advisory_lock(990105,$1)`, pid)
			require.NoError(t, err)
			defer func() { _, _ = gate.ExecContext(context.Background(), `SELECT pg_advisory_unlock(990105,$1)`, pid) }()
			table := "escalation_policy_steps"
			if operation == epaudit.StepUpdate {
				table = "escalation_policy_actions"
			}
			_, err = db.Exec(fmt.Sprintf(`CREATE FUNCTION eu_capture_gate() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN PERFORM pg_advisory_xact_lock(990105,%d); RETURN OLD; END$$; CREATE TRIGGER eu_capture_gate BEFORE DELETE ON %s FOR EACH ROW EXECUTE FUNCTION eu_capture_gate()`, pid, table))
			require.NoError(t, err)
			ctx, cancel := context.WithTimeout(sd3System(), 20*time.Second)
			defer cancel()
			done := make(chan error, 1)
			go func() {
				var err error
				if operation == epaudit.PolicyUpdate {
					_, err = sd5App(h).Mutation().UpdateEscalationPolicy(ctx, graphql2.UpdateEscalationPolicyInput{ID: root, StepIDs: []string{}})
				} else {
					_, err = sd5App(h).Mutation().UpdateEscalationPolicyStep(ctx, graphql2.UpdateEscalationPolicyStepInput{ID: step, Actions: []gadb.DestV1{}})
				}
				done <- err
			}()
			sd3WaitBlocked(t, db, pid)
			for _, tc := range []struct {
				name, query string
				args        []any
			}{
				{"action_insert", `INSERT INTO escalation_policy_actions(escalation_policy_step_id,user_id) VALUES($1,$2)`, []any{step, h.UUID("user-b")}},
				{"action_delete", `DELETE FROM escalation_policy_actions WHERE id=$1`, []any{action}},
				{"action_reparent", `UPDATE escalation_policy_actions SET escalation_policy_step_id=$2 WHERE id=$1`, []any{action, other}},
				{"action_target_change", `UPDATE escalation_policy_actions SET user_id=$2 WHERE id=$1`, []any{action, h.UUID("user-b")}},
			} {
				t.Run(tc.name, func(t *testing.T) {
					tx, err := writers.BeginTx(t.Context(), nil)
					require.NoError(t, err)
					defer func() { _ = tx.Rollback() }()
					_, err = tx.Exec(`SET LOCAL lock_timeout='80ms'`)
					require.NoError(t, err)
					_, err = tx.Exec(tc.query, tc.args...)
					var pg *pgconn.PgError
					require.ErrorAs(t, err, &pg)
					require.Equal(t, "55P03", pg.Code)
				})
			}
			require.Zero(t, euSuccessCount(t, h), "the witness must not commit while the business mutation is blocked")
			_, err = gate.ExecContext(t.Context(), `SELECT pg_advisory_unlock(990105,$1)`, pid)
			require.NoError(t, err)
			require.NoError(t, <-done)
			actualRoot, parent := root, ""
			if operation == epaudit.StepUpdate {
				actualRoot, parent = step, root
			}
			effects := euEffects(t, h, operation, actualRoot, parent)
			expected := 1
			if operation == epaudit.PolicyUpdate {
				expected = 2
			}
			require.Len(t, effects, expected)
			require.Equal(t, 1, euSuccessCount(t, h))
		})
	}
}

func TestEPUpdateDeleteAuditStateSetNullPostgres(t *testing.T) {
	h := sd1Harness(t)
	db := h.App().DB()
	root := sd5EP(t, h, harness.SmokeOrganizationID)
	step := sd5Step(t, h, root)
	svc := uuid.NewString()
	_, err := db.Exec(`INSERT INTO services(id,organization_id,escalation_policy_id,name) VALUES($1,$2,$3,'EU state service')`, svc, harness.SmokeOrganizationID, root)
	require.NoError(t, err)
	var alertID int
	require.NoError(t, db.QueryRow(`INSERT INTO alerts(service_id,summary,dedup_key) VALUES($1,'EU state synthetic','eu-state') RETURNING id`, svc).Scan(&alertID))
	// Alert insertion already creates its State through the existing trigger.
	// Point that actual row at the Step and retain its independent identity.
	var stateID int64
	require.NoError(t, db.QueryRow(`UPDATE escalation_policy_state SET escalation_policy_step_id=$2 WHERE alert_id=$1 AND escalation_policy_id=$3 AND service_id=$4 RETURNING id`, alertID, step, root, svc).Scan(&stateID))
	_, err = sd5App(h).Mutation().UpdateEscalationPolicy(sd3System(), graphql2.UpdateEscalationPolicyInput{ID: root, StepIDs: []string{}})
	require.NoError(t, err)
	var surviving sql.NullString
	var afterID int64
	require.NoError(t, db.QueryRow(`SELECT id,escalation_policy_step_id FROM escalation_policy_state WHERE alert_id=$1`, alertID).Scan(&afterID, &surviving))
	require.Equal(t, stateID, afterID)
	require.False(t, surviving.Valid, "SET NULL preserves the State object")
	effects := euEffects(t, h, epaudit.PolicyUpdate, root, "")
	require.Len(t, effects, 1)
	require.Equal(t, epaudit.Step, effects[0].ResourceType)
}

// Retarget an already locked Action while the Update waits. U01 must capture
// the committed target after its lock wait. U02 must use its actual DELETE
// receipt: the original destination no longer matches, so nothing was deleted.
func TestEPUpdateDeleteAuditWaitedActionReceiptPostgres(t *testing.T) {
	for _, operation := range []string{epaudit.PolicyUpdate, epaudit.StepUpdate} {
		t.Run(operation, func(t *testing.T) {
			h := sd1Harness(t)
			euAddedUser(t, h)
			db := h.App().DB()
			root := sd5EP(t, h, harness.SmokeOrganizationID)
			step := sd5Step(t, h, root)
			action := uuid.NewString()
			_, err := db.Exec(`INSERT INTO escalation_policy_actions(id,escalation_policy_step_id,user_id) VALUES($1,$2,$3)`, action, step, h.UUID("user-a"))
			require.NoError(t, err)
			writer, err := db.BeginTx(t.Context(), nil)
			require.NoError(t, err)
			defer func() { _ = writer.Rollback() }()
			var pid int
			require.NoError(t, writer.QueryRow(`SELECT pg_backend_pid() FROM escalation_policy_actions WHERE id=$1 FOR UPDATE`, action).Scan(&pid))
			ctx, cancel := context.WithTimeout(sd3System(), 20*time.Second)
			defer cancel()
			done := make(chan error, 1)
			go func() {
				var err error
				if operation == epaudit.PolicyUpdate {
					_, err = sd5App(h).Mutation().UpdateEscalationPolicy(ctx, graphql2.UpdateEscalationPolicyInput{ID: root, StepIDs: []string{}})
				} else {
					_, err = sd5App(h).Mutation().UpdateEscalationPolicyStep(ctx, graphql2.UpdateEscalationPolicyStepInput{ID: step, Actions: []gadb.DestV1{}})
				}
				done <- err
			}()
			sd3WaitBlocked(t, db, pid)
			require.Zero(t, euSuccessCount(t, h))
			_, err = writer.Exec(`UPDATE escalation_policy_actions SET user_id=$2 WHERE id=$1`, action, h.UUID("user-b"))
			require.NoError(t, err)
			require.NoError(t, writer.Commit())
			require.NoError(t, <-done)
			if operation == epaudit.PolicyUpdate {
				effects := euEffects(t, h, operation, root, "")
				require.Len(t, effects, 2)
				var actionEffects int
				for _, effect := range effects {
					if effect.ResourceType == epaudit.Action {
						actionEffects++
						require.Equal(t, action, effect.ResourceUUID.String())
						require.Equal(t, step, effect.ParentStepID.String())
						require.Equal(t, h.UUID("user-b"), effect.TargetID.String())
						require.Equal(t, "CASCADE", effect.Provenance)
					}
				}
				require.Equal(t, 1, actionEffects)
				require.Zero(t, serviceManagementCount(t, h, "escalation_policy_steps", step))
				require.Zero(t, serviceManagementCount(t, h, "escalation_policy_actions", action))
			} else {
				require.Zero(t, euSuccessCount(t, h), "no DELETE receipt means no deletion witness")
				require.Equal(t, map[string]string{action: h.UUID("user-b")}, euActions(t, h, step))
				require.Equal(t, 1, serviceManagementCount(t, h, "escalation_policy_steps", step))
			}
			require.Equal(t, 1, serviceManagementCount(t, h, "escalation_policies", root))
			require.Equal(t, 1, serviceManagementCount(t, h, "users", h.UUID("user-b")))
		})
	}
}
