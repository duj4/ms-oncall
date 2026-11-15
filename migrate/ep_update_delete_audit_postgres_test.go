package migrate

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
	epaudit "github.com/target/goalert/escalation/deleteaudit"
)

func ep305Event(operation string) epaudit.Event {
	e := sd5SchemaEvent()
	e.SchemaVersion, e.EffectsVersion, e.Operation = 2, 2, operation
	e.Reason, e.Cause = "children_deleted", "update_induced"
	step := sd5SchemaEffect(e, 0)
	step.Provenance, step.DeletionMechanism, step.Cause = "EXPLICIT", "explicit_sql", "update_induced"
	parent := *step.ResourceUUID
	if operation == epaudit.StepUpdate {
		e.ParentPolicyID = uuid.New()
		parent = e.RootID
	} else {
		e.Effects = append(e.Effects, step)
	}
	id, target := uuid.New(), uuid.New()
	action := epaudit.Effect{EffectID: uuid.New(), ResourceType: epaudit.Action, RootID: e.RootID, TargetOrganizationID: e.TargetOrganizationID,
		ResourceUUID: &id, ParentStepID: &parent, Relation: "escalation_policy.step.action", Change: "deleted", TargetKind: "notification_channel", TargetID: &target,
		Provenance: "EXPLICIT", DeletionMechanism: "explicit_sql", Cause: "update_induced"}
	if operation == epaudit.PolicyUpdate {
		action.Provenance, action.DeletionMechanism, action.Cause = "CASCADE", "fk_cascade", "step_delete"
	}
	e.Effects = append(e.Effects, action)
	return e
}

func ep305Append(t *testing.T, ctx context.Context, db *sql.DB, e epaudit.Event) {
	t.Helper()
	tx, err := db.BeginTx(ctx, nil)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback() }()
	require.NoError(t, epaudit.Append(ctx, tx, e))
	require.NoError(t, tx.Commit())
}

func ep305HistoricalRow(t *testing.T, ctx context.Context, db *sql.DB, id uuid.UUID) string {
	t.Helper()
	var raw string
	require.NoError(t, db.QueryRowContext(ctx, `SELECT (to_jsonb(e)-'parent_policy_id')::text FROM escalation_policy_delete_audit_events e WHERE event_id=$1`, id).Scan(&raw))
	return raw
}

func TestPostgresEPUpdateDeleteAudit305InstallUpgradeAndCompatibility(t *testing.T) {
	for _, start := range []int{0, 304} {
		t.Run(fmt.Sprint(start), func(t *testing.T) {
			ctx := t.Context()
			name, uri := newPostgresTestDatabaseDetails(t, postgresIntegrationURL(t))
			db, err := sql.Open("pgx", uri)
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, db.Close()) })
			var directory, address, database string
			var port int
			var tls bool
			require.NoError(t, db.QueryRowContext(ctx, `SELECT current_setting('data_directory'),host(inet_server_addr()),inet_server_port(),current_database(),(SELECT ssl FROM pg_stat_ssl WHERE pid=pg_backend_pid())`).Scan(&directory, &address, &port, &database, &tls))
			require.Equal(t, os.Getenv("MS_ONCALL_EP_UPDATE_TEST_DATA_DIRECTORY"), directory)
			require.Equal(t, "127.0.0.1", address)
			require.Equal(t, name, database)
			require.True(t, tls)
			t.Logf("isolated native database=%s server=%s port=%d verified TLS=%t", database, address, port, tls)
			old := sd5SchemaEvent()
			var before string
			if start == 304 {
				n, err := Up(ctx, uri, Names()[303])
				require.NoError(t, err)
				require.Equal(t, 304, n)
				ep305Append(t, ctx, db, old) // the unchanged v1 writer on the actual old schema
				before = ep305HistoricalRow(t, ctx, db, old.EventID)
			}
			n, err := Up(ctx, uri, "")
			require.NoError(t, err)
			require.Equal(t, 305-start, n)
			require.NoError(t, VerifyAll(ctx, uri))
			require.NoError(t, VerifyIsLatest(ctx, uri))
			h, err := loadEmbeddedHistory()
			require.NoError(t, err)
			require.Len(t, assertDeterministicProvenanceState(t, ctx, uri, h), 305)
			if start == 304 {
				require.Equal(t, before, ep305HistoricalRow(t, ctx, db, old.EventID), "305 must preserve every old v1 field")
			} else {
				ep305Append(t, ctx, db, old)
			}
			ep305Append(t, ctx, db, old) // exact v1 replay remains idempotent after upgrade
			for _, op := range []string{epaudit.PolicyUpdate, epaudit.StepUpdate} {
				e := ep305Event(op)
				require.NoError(t, e.Validate())
				ep305Append(t, ctx, db, e)
				ep305Append(t, ctx, db, e)
				var count int
				require.NoError(t, db.QueryRowContext(ctx, `SELECT count(*) FROM escalation_policy_delete_audit_events WHERE event_id=$1`, e.EventID).Scan(&count))
				require.Equal(t, 1, count)
				changed := e
				changed.Reason = "children_deleted"
				changed.Effects = append([]epaudit.Effect{}, e.Effects...)
				target := uuid.New()
				changed.Effects[len(changed.Effects)-1].TargetID = &target
				tx, err := db.BeginTx(ctx, nil)
				require.NoError(t, err)
				require.ErrorIs(t, epaudit.Append(ctx, tx, changed), epaudit.ErrConflict)
				require.NoError(t, tx.Rollback())
				var raw string
				require.NoError(t, db.QueryRowContext(ctx, `SELECT to_jsonb(e)::text FROM escalation_policy_delete_audit_events e WHERE event_id=$1`, e.EventID).Scan(&raw))
				ep305ClosedSQL(t, ctx, db, e, raw)
			}
			for _, statement := range []string{`UPDATE escalation_policy_delete_audit_events SET outcome=outcome`, `DELETE FROM escalation_policy_delete_audit_events`, `TRUNCATE escalation_policy_delete_audit_events`} {
				_, err := db.ExecContext(ctx, statement)
				var pg *pgconn.PgError
				require.ErrorAs(t, err, &pg)
				require.Equal(t, "55000", pg.Code)
			}
			n, err = Up(ctx, uri, "")
			require.NoError(t, err)
			require.Zero(t, n)
		})
	}
}

func ep305ClosedSQL(t *testing.T, ctx context.Context, db *sql.DB, original epaudit.Event, raw string) {
	t.Helper()
	for _, mode := range []string{"correct", "wrong_operation", "wrong_root", "missing_policy", "wrong_effect_root", "wrong_target_org", "wrong_parent", "wrong_cause", "duplicate_object", "duplicate_effect_id", "derived_type", "empty_success", "unknown_json_key"} {
		t.Run(original.Operation+"/"+mode, func(t *testing.T) {
			e := original
			encoded, err := json.Marshal(original.Effects)
			require.NoError(t, err)
			require.NoError(t, json.Unmarshal(encoded, &e.Effects)) // independent pointer-bearing projection
			e.EventID, e.AttemptID = uuid.New(), uuid.New()
			switch mode {
			case "wrong_operation":
				e.Operation = "updateScheduleTarget"
			case "wrong_root":
				e.RootID = uuid.Nil
			case "missing_policy":
				if e.Operation == epaudit.StepUpdate {
					e.ParentPolicyID = uuid.Nil
				} else {
					e.ParentPolicyID = uuid.New()
				}
			case "wrong_effect_root":
				e.Effects[0].RootID = uuid.New()
			case "wrong_target_org":
				e.Effects[0].TargetOrganizationID = uuid.New()
			case "wrong_parent":
				id := uuid.New()
				e.Effects[len(e.Effects)-1].ParentStepID = &id
			case "wrong_cause":
				e.Effects[len(e.Effects)-1].Cause = "escalation_policy_delete"
			case "duplicate_object":
				f := e.Effects[0]
				f.EffectID = uuid.New()
				e.Effects = append(e.Effects, f)
			case "duplicate_effect_id":
				f := e.Effects[len(e.Effects)-1]
				id := uuid.New()
				f.ResourceUUID = &id
				e.Effects = append(e.Effects, f)
			case "derived_type":
				e.Effects[0].ResourceType = "ep_step_on_call_users"
			case "empty_success":
				e.Effects = nil
			}
			var row map[string]any
			require.NoError(t, json.Unmarshal([]byte(raw), &row))
			row["event_id"], row["attempt_id"], row["root_id"], row["operation"], row["root_type"] = e.EventID, e.AttemptID, e.RootID, e.Operation, e.RootType()
			row["parent_policy_id"] = nil
			if e.ParentPolicyID != uuid.Nil {
				row["parent_policy_id"] = e.ParentPolicyID
			}
			row["effects"] = e.Canonical().Effects
			if mode == "unknown_json_key" {
				var effects []map[string]any
				require.NoError(t, json.Unmarshal(encoded, &effects))
				effects[0]["destination"] = "SYNTHETIC_PRIVATE"
				row["effects"] = effects
			} else {
				require.Equal(t, mode == "correct", e.Validate() == nil, "Go projection classification")
			}
			payload, err := json.Marshal(row)
			require.NoError(t, err)
			_, err = db.ExecContext(ctx, `INSERT INTO escalation_policy_delete_audit_events SELECT (jsonb_populate_record(NULL::escalation_policy_delete_audit_events,$1::jsonb)).*`, string(payload))
			if mode == "correct" {
				require.NoError(t, err)
			} else {
				var pg *pgconn.PgError
				require.ErrorAs(t, err, &pg)
				require.Equal(t, "23514", pg.Code, "SQL must reject the same invalid contract")
			}
		})
	}
}
