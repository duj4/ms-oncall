package smoke

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/escalation"
	"github.com/target/goalert/permission"
	"github.com/target/goalert/test/smoke/harness"
)

func epLogHarness(t *testing.T) *harness.Harness {
	t.Helper()
	h := epB1Harness(t)
	ikSetAuthority(t, h, "ORG_ADMIN", false)
	epB1Exec(t, h, `INSERT INTO services(id,organization_id,escalation_policy_id,name) VALUES
		($1,$2,$3,'Synthetic Second Linked Service'),
		($4,$5,$6,'Synthetic Unrelated Service')`,
		h.UUID("log-service-a2"), harness.SmokeOrganizationID, h.UUID("policy-a"),
		h.UUID("log-service-b"), h.UUID("org-b"), h.UUID("policy-b"))
	for _, a := range []struct{ key, service, status string }{
		{"log-triggered", "service-a", "triggered"},
		{"log-active", "service-a", "active"},
		{"log-second", "log-service-a2", "triggered"},
		{"log-closed", "service-a", "closed"},
		{"log-unrelated", "log-service-b", "triggered"},
	} {
		epB1Exec(t, h, `INSERT INTO alerts(service_id,summary,dedup_key,status)
			VALUES($1,$2,CASE WHEN $3::enum_alert_status='closed' THEN NULL ELSE $2 END,$3::enum_alert_status)`, h.UUID(a.service), a.key, a.status)
	}
	return h
}

func epLogSave(t *testing.T, name string, value any) {
	t.Helper()
	epB1Save(t, strings.ReplaceAll(t.Name(), "/", "_")+"-"+name, value)
}

// Each selected Alert receives exactly one event with the original Human actor
// and payload. Closed and unrelated Alerts must receive none.
func epLogAssertEvents(t *testing.T, h *harness.Harness, expected []string) {
	t.Helper()
	rows, err := h.App().DB().Query(`SELECT a.summary,l.event,l.sub_type,l.sub_user_id::text,
		l.sub_classifier,l.meta::text IS NOT DISTINCT FROM 'null',l.message,
		l.sub_channel_id IS NULL AND l.sub_integration_key_id IS NULL AND l.sub_hb_monitor_id IS NULL
		FROM alert_logs l JOIN alerts a ON a.id=l.alert_id ORDER BY a.summary,l.id`)
	require.NoError(t, err)
	defer rows.Close()
	var keys []string
	for rows.Next() {
		var key, event, subject, actor, classifier, message string
		var jsonNullMeta, nullOtherSubjects bool
		require.NoError(t, rows.Scan(&key, &event, &subject, &actor, &classifier, &jsonNullMeta, &message, &nullOtherSubjects))
		require.Equal(t, "policy_updated", event)
		require.Equal(t, "user", subject)
		require.Equal(t, h.UUID("user-a"), actor)
		require.Equal(t, "Web", classifier)
		require.True(t, jsonNullMeta)
		require.True(t, nullOtherSubjects)
		require.Empty(t, message)
		keys = append(keys, key)
	}
	require.NoError(t, rows.Err())
	require.ElementsMatch(t, expected, keys, "exact event multiplicity and target Alert set")
}

func TestEscalationPolicyTransactionalLogHTTPRollback(t *testing.T) {
	t.Parallel()
	for _, test := range []struct{ name, step string }{
		{"invalid_step_id", "invalid"},
		{"missing_step_id", "step-missing"},
		{"foreign_step_id", "step-b1"},
	} {
		t.Run(test.name, func(t *testing.T) {
			h := epLogHarness(t)
			step := test.step
			if step != "invalid" {
				step = h.UUID(step)
			}
			before := epB1Snapshot(t, h)
			// A valid first Step is reordered and omitted Steps/actions are
			// deleted before a well-formed foreign/missing second ID fails.
			q := fmt.Sprintf(`mutation{updateEscalationPolicy(input:{id:%q,name:"Must Roll Back",description:"Must Roll Back",repeat:4,stepIDs:[%q,%q]})}`,
				h.UUID("policy-a"), h.UUID("step-a2"), step)
			response := epB1Call(t, h, "rejected_update", q, "", false)
			after := epB1Snapshot(t, h)
			epLogSave(t, "durable_rollback", map[string]any{"before": before, "after": after, "errors": response.Errors})
			require.Len(t, response.Errors, 1)
			if test.step != "invalid" {
				require.Equal(t, "uuid does not exist on policy", response.Errors[0].Message)
				require.Equal(t, "steps[1]", response.Errors[0].Extensions["fieldName"])
			}
			for _, table := range []string{"escalation_policies", "escalation_policy_steps", "escalation_policy_actions"} {
				require.Equal(t, before[table], after[table], table)
			}
			require.Equal(t, before, after, "rejected EP update must not persist policy_updated or other artifacts")
		})
	}
}

func TestEscalationPolicyTransactionalLogHTTPSuccess(t *testing.T) {
	t.Parallel()
	for _, pa := range []bool{false, true} {
		t.Run(fmt.Sprintf("platform_admin_%t", pa), func(t *testing.T) {
			h := epLogHarness(t)
			ikSetAuthority(t, h, "ORG_ADMIN", pa)
			q := fmt.Sprintf(`mutation{updateEscalationPolicy(input:{id:%q,name:"Committed Synthetic EP",description:"Committed together",repeat:4})}`, h.UUID("policy-a"))
			require.Empty(t, epB1Call(t, h, "committed_update", q, "", false).Errors)
			require.Equal(t, "Committed Synthetic EP/Committed together/4", epB1Scalar(t, h,
				`SELECT name||'/'||description||'/'||repeat::text FROM escalation_policies WHERE id=$1`, h.UUID("policy-a")))
			epLogAssertEvents(t, h, []string{"log-triggered", "log-active", "log-second"})
		})
	}
}

func TestEscalationPolicyTransactionalLogStore(t *testing.T) {
	t.Parallel()
	for _, mode := range []string{"commit", "rollback", "later_sql_failure", "nil_transaction"} {
		t.Run(mode, func(t *testing.T) {
			h := epLogHarness(t)
			baseCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			ctx := permission.UserSourceContext(baseCtx, h.UUID("user-a"), permission.RoleUser,
				&permission.SourceInfo{Type: permission.SourceTypeAuthProvider})
			org := uuid.MustParse(harness.SmokeOrganizationID)
			p := &escalation.Policy{ID: h.UUID("policy-a"), OrganizationID: org, Name: "Store Synthetic EP", Description: "Store attempted change", Repeat: 3}
			before := epB1Snapshot(t, h)
			if mode == "nil_transaction" {
				// This shape is supported by the existing root-ownership PG tests.
				require.NoError(t, h.App().EscalationStore.UpdatePolicyTx(ctx, nil, p, nil))
				epLogSave(t, "committed", epB1Snapshot(t, h))
				require.Equal(t, p.Name, epB1Scalar(t, h, "SELECT name FROM escalation_policies WHERE id=$1", p.ID))
				epLogAssertEvents(t, h, []string{"log-triggered", "log-active", "log-second"})
				return
			}
			tx, err := h.App().DB().BeginTx(ctx, nil)
			require.NoError(t, err)
			defer func() { _ = tx.Rollback() }()
			// A transaction-local Alert proves INSERT's selection uses this
			// connection and snapshot, in addition to testing log rollback.
			_, err = tx.ExecContext(ctx, `INSERT INTO alerts(service_id,summary,dedup_key) VALUES($1,'log-tx-local','log-tx-local')`, h.UUID("service-a"))
			require.NoError(t, err)
			require.NoError(t, h.App().EscalationStore.UpdatePolicyTx(ctx, tx, p, &org))
			var insideName string
			var insideLogs, localLogs int
			require.NoError(t, tx.QueryRowContext(ctx, "SELECT name FROM escalation_policies WHERE id=$1", p.ID).Scan(&insideName))
			require.Equal(t, p.Name, insideName)
			require.NoError(t, tx.QueryRowContext(ctx, "SELECT count(*) FROM alert_logs WHERE event='policy_updated'").Scan(&insideLogs))
			require.NoError(t, tx.QueryRowContext(ctx, `SELECT count(*) FROM alert_logs l JOIN alerts a ON a.id=l.alert_id WHERE a.dedup_key='log-tx-local'`).Scan(&localLogs))
			outside := epB1Snapshot(t, h)
			epLogSave(t, "uncommitted", map[string]any{"outside_before": before, "outside_during": outside, "inside_name": insideName, "inside_policy_updated": insideLogs, "inside_transaction_local_alert_logs": localLogs})
			switch mode {
			case "later_sql_failure":
				_, err = tx.ExecContext(ctx, "SELECT 1/0")
				require.Error(t, err)
				require.Error(t, tx.Commit(), "aborted transaction cannot commit EP fields or logs")
			case "rollback":
				require.NoError(t, tx.Rollback())
			default:
				require.NoError(t, tx.Commit())
			}
			require.ErrorIs(t, tx.Rollback(), sql.ErrTxDone)
			after := epB1Snapshot(t, h)
			epLogSave(t, "finished", map[string]any{"before": before, "after": after})
			if mode != "commit" {
				require.Equal(t, before, after, "business data and all related logs roll back together")
			} else {
				require.Equal(t, p.Name, epB1Scalar(t, h, "SELECT name FROM escalation_policies WHERE id=$1", p.ID))
				epLogAssertEvents(t, h, []string{"log-triggered", "log-active", "log-second", "log-tx-local"})
			}
			require.Equal(t, before, outside, "uncommitted EP fields and logs must be invisible to an independent connection")
			require.Equal(t, 4, insideLogs)
			require.Equal(t, 1, localLogs)
		})
	}
}

func TestEscalationPolicyTransactionalLogLaterReorderFailure(t *testing.T) {
	t.Parallel()
	h := epLogHarness(t)
	// A transaction-local deferred trigger rejects final Step ordering at
	// commit, after all resolver work and attempted Alert Log inserts succeed.
	epB1Exec(t, h, `CREATE FUNCTION ep_log_reject_reorder() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN RAISE EXCEPTION 'synthetic late reorder failure'; END $$;
		CREATE CONSTRAINT TRIGGER ep_log_late_reorder AFTER UPDATE ON escalation_policy_steps
		DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION ep_log_reject_reorder()`)
	before := epB1Snapshot(t, h)
	wait := h.ExpectBackendError("synthetic late reorder failure")
	q := fmt.Sprintf(`mutation{updateEscalationPolicy(input:{id:%q,description:"Late rollback",stepIDs:[%q,%q,%q]})}`,
		h.UUID("policy-a"), h.UUID("step-a2"), h.UUID("step-a1"), h.UUID("step-a3"))
	response := epB1Call(t, h, "deferred_reorder_failure", q, "", false)
	wait()
	after := epB1Snapshot(t, h)
	epLogSave(t, "rollback", map[string]any{"before": before, "after": after, "errors": response.Errors})
	require.NotEmpty(t, response.Errors)
	require.Equal(t, before, after)
}

func TestEscalationPolicyTransactionalLogConcurrentUpdates(t *testing.T) {
	t.Parallel()
	h := epLogHarness(t)
	baseCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ctx := permission.UserSourceContext(baseCtx, h.UUID("user-a"), permission.RoleUser,
		&permission.SourceInfo{Type: permission.SourceTypeAuthProvider})
	org := uuid.MustParse(harness.SmokeOrganizationID)
	id := h.UUID("policy-a")
	start, results := make(chan struct{}), make(chan error, 2)
	for i := range 2 {
		go func() {
			<-start
			results <- func() error {
				tx, err := h.App().DB().BeginTx(ctx, nil)
				if err != nil {
					return err
				}
				defer func() { _ = tx.Rollback() }()
				p, err := h.App().EscalationStore.FindOnePolicyForUpdateTx(ctx, tx, id, &org)
				if err != nil {
					return err
				}
				p.Description = fmt.Sprintf("Concurrent synthetic update %d", i)
				if err := h.App().EscalationStore.UpdatePolicyTx(ctx, tx, p, &org); err != nil {
					return err
				}
				return tx.Commit()
			}()
		}()
	}
	close(start)
	var errs []error
	for range 2 {
		errs = append(errs, <-results)
	}
	for _, err := range errs {
		require.NoError(t, err)
	}
	epLogSave(t, "committed", epB1Snapshot(t, h))
	// Two successful business updates yield two events per eligible Alert.
	epLogAssertEvents(t, h, []string{"log-triggered", "log-active", "log-second", "log-triggered", "log-active", "log-second"})
}
