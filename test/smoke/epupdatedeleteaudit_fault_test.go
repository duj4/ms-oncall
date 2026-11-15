package smoke

import (
	"context"
	"database/sql"
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/escalation"
	epaudit "github.com/target/goalert/escalation/deleteaudit"
	"github.com/target/goalert/gadb"
	"github.com/target/goalert/graphql2"
	"github.com/target/goalert/graphql2/graphqlapp"
	"github.com/target/goalert/test/smoke/harness"
)

// The established fault connector changes acknowledgements around real PG
// Commit/Rollback. This is controlled evidence, not a network disconnect test.
func TestEPUpdateDeleteAuditControlledCommitUnknownPostgres(t *testing.T) {
	for _, operation := range []string{epaudit.PolicyUpdate, epaudit.StepUpdate} {
		for _, mode := range []string{"commit_then_error", "completion_unknown", "rollback_then_error"} {
			t.Run(operation+"/"+mode, func(t *testing.T) {
				h := sd1Harness(t)
				root := sd5EP(t, h, harness.SmokeOrganizationID)
				step := sd5Step(t, h, root)
				action := uuid.NewString()
				_, err := h.App().DB().Exec(`INSERT INTO escalation_policy_actions(id,escalation_policy_step_id,user_id) VALUES($1,$2,$3)`, action, step, h.UUID("user-a"))
				require.NoError(t, err)
				var database string
				require.NoError(t, h.App().DB().QueryRow(`SELECT current_database()`).Scan(&database))
				cfg, err := pgx.ParseConfig(harness.DBURL(database))
				require.NoError(t, err)
				connector := &serviceAuditFaultConnector{base: stdlib.GetConnector(*cfg), mode: mode}
				db := sql.OpenDB(connector)
				db.SetMaxOpenConns(1)
				defer db.Close()
				store, err := escalation.NewStore(context.Background(), db, escalation.Config{LogStore: h.App().AlertLogStore, Registry: h.App().DestRegistry})
				require.NoError(t, err)
				app := &graphqlapp.App{DB: db, PolicyStore: store}
				if operation == epaudit.PolicyUpdate {
					_, err = app.Mutation().UpdateEscalationPolicy(sd3System(), graphql2.UpdateEscalationPolicyInput{ID: root, StepIDs: []string{}})
				} else {
					_, err = app.Mutation().UpdateEscalationPolicyStep(sd3System(), graphql2.UpdateEscalationPolicyStepInput{ID: step, Actions: []gadb.DestV1{}})
				}
				require.Error(t, err)
				require.NotContains(t, err.Error(), "SYNTHETIC_")
				var success, unknown, badEffects, requests, executions, attempts int
				require.NoError(t, h.App().DB().QueryRow(`SELECT count(*) FILTER(WHERE record_kind='success_witness'),count(*) FILTER(WHERE outcome='commit_unknown'),count(*) FILTER(WHERE record_kind='attempt_observation' AND effects<>'[]'::jsonb),count(DISTINCT request_id),count(DISTINCT execution_id),count(DISTINCT attempt_id) FROM escalation_policy_delete_audit_events WHERE schema_version=2`).Scan(&success, &unknown, &badEffects, &requests, &executions, &attempts))
				require.Equal(t, 1, unknown)
				require.Zero(t, badEffects)
				require.Equal(t, 1, requests)
				require.Equal(t, 1, executions)
				require.Equal(t, 1, attempts)
				if mode == "rollback_then_error" {
					require.Zero(t, success)
					require.Equal(t, 1, serviceManagementCount(t, h, "escalation_policy_actions", action))
					require.Equal(t, 1, serviceManagementCount(t, h, "escalation_policy_steps", step))
				} else {
					require.Equal(t, 1, success)
					require.Zero(t, serviceManagementCount(t, h, "escalation_policy_actions", action))
					if operation == epaudit.PolicyUpdate {
						require.Zero(t, serviceManagementCount(t, h, "escalation_policy_steps", step))
					} else {
						require.Equal(t, 1, serviceManagementCount(t, h, "escalation_policy_steps", step))
					}
				}
				require.EqualValues(t, 2, connector.begins.Load(), "one business attempt plus one observation; no replay")
				require.Equal(t, 1, serviceManagementCount(t, h, "escalation_policies", root))
			})
		}
	}
}

func TestEPUpdateDeleteAuditMixedFragmentHTTP(t *testing.T) {
	h := sd1Harness(t)
	ikSetAuthority(t, h, "ORG_ADMIN", false)
	roots, steps := []string{}, []string{}
	for range 3 {
		root := sd5EP(t, h, harness.SmokeOrganizationID)
		step := sd5Step(t, h, root)
		_, err := h.App().DB().Exec(`INSERT INTO escalation_policy_actions(escalation_policy_step_id,user_id) VALUES($1,$2)`, step, h.UUID("user-a"))
		require.NoError(t, err)
		roots = append(roots, root)
		steps = append(steps, step)
	}
	var oldDelay int
	require.NoError(t, h.App().DB().QueryRow(`SELECT delay FROM escalation_policy_steps WHERE id=$1`, steps[2]).Scan(&oldDelay))
	query := fmt.Sprintf(`mutation SYNTHETIC_OPERATION { ...Updates } fragment Updates on Mutation {
 SYNTHETIC_FIRST:updateEscalationPolicy(input:{id:%q,name:"SYNTHETIC_PRIVATE_EP_NAME",stepIDs:[]})
 SYNTHETIC_SECOND:updateEscalationPolicyStep(input:{id:%q,actions:[]})
 SYNTHETIC_FAILED:updateEscalationPolicyStep(input:{id:%q,delayMinutes:%d,targets:[{type:user,id:%q}]})
}`, roots[0], steps[1], steps[2], oldDelay+1, uuid.NewString())
	response := stepOrganizationQuery(t, h, query)
	require.NotEmpty(t, response.Errors)
	require.Equal(t, 2, euSuccessCount(t, h), "earlier top-level field commits retain the original GraphQL transaction behavior")
	require.Zero(t, serviceManagementCount(t, h, "escalation_policy_steps", steps[0]))
	require.Empty(t, euActions(t, h, steps[1]))
	require.Len(t, euActions(t, h, steps[2]), 1, "failed target validation rolls back preceding Action removal")
	var delay int
	require.NoError(t, h.App().DB().QueryRow(`SELECT delay FROM escalation_policy_steps WHERE id=$1`, steps[2]).Scan(&delay))
	require.Equal(t, oldDelay, delay)
	var requests, executions, attempts, failures, badEffects int
	require.NoError(t, h.App().DB().QueryRow(`SELECT count(DISTINCT request_id),count(DISTINCT execution_id),count(DISTINCT attempt_id),count(*) FILTER(WHERE record_kind='attempt_observation'),count(*) FILTER(WHERE record_kind='attempt_observation' AND effects<>'[]'::jsonb) FROM escalation_policy_delete_audit_events WHERE schema_version=2`).Scan(&requests, &executions, &attempts, &failures, &badEffects))
	require.Equal(t, 1, requests)
	require.Equal(t, 3, executions)
	require.Equal(t, 3, attempts)
	require.Equal(t, 1, failures)
	require.Zero(t, badEffects)
	require.NotContains(t, sd5Rows(t, h), "SYNTHETIC_")
}
