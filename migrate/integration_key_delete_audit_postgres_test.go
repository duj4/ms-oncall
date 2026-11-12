package migrate

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
	keyaudit "github.com/target/goalert/integrationkey/deleteaudit"
)

func TestIntegrationKeyDeleteAudit298CanonicalHistory(t *testing.T) {
	h, err := loadEmbeddedHistory()
	require.NoError(t, err)
	require.Len(t, h.entries, 302)
	e := h.entries[297]
	require.Equal(t, "20261111004634-integration-key-delete-audit.sql", e.ID)
	require.Equal(t, h.entries[296].ID, e.PredecessorID)
	marker := []byte(",\n    {\n      \"id\": \"ms-oncall-integration-key-delete-audit-d09-sd4\",")
	i := bytes.Index(h.manifest, marker)
	require.Positive(t, i)
	prefix := append(append([]byte{}, h.manifest[:i]...), []byte("\n  ]\n}\n")...)
	require.Equal(t, "25128ab8440376947a0162aa3f81926e6d6fa77b7d9b7adfc9d644127952feeb", fmt.Sprintf("%x", sha256.Sum256(prefix)))
}
func TestPostgresIntegrationKeyDeleteAuditSchemaAndReplay(t *testing.T) {
	for _, start := range []int{297, 298} {
		t.Run(fmt.Sprint(start), func(t *testing.T) { integrationKeyDeleteAuditSchemaAndReplay(t, start) })
	}
}
func integrationKeyDeleteAuditSchemaAndReplay(t *testing.T, start int) {
	ctx, uri, db := boundedAuditDB(t, start)
	var version string
	require.NoError(t, db.QueryRowContext(ctx, `SELECT current_setting('server_version')`).Scan(&version))
	t.Log("Actual PostgreSQL version:", version)
	f := newBoundedFixture(t, ctx, db)
	policy, svc, credential := uuid.New(), uuid.New(), uuid.New()
	_, err := db.ExecContext(ctx, `INSERT INTO escalation_policies(id,organization_id,name) VALUES($1,$2,'SD4 synthetic')`, policy, f.org)
	require.NoError(t, err)
	_, err = db.ExecContext(ctx, `INSERT INTO services(id,organization_id,name,escalation_policy_id) VALUES($1,$2,'SD4 synthetic',$3)`, svc, f.org, policy)
	require.NoError(t, err)
	var safe uuid.UUID
	require.NoError(t, db.QueryRowContext(ctx, `INSERT INTO integration_keys(id,service_id,name,type) VALUES($1,$2,'SYNTHETIC_NAME_SECRET','generic') RETURNING audit_resource_id`, credential, svc).Scan(&safe))
	n, err := Up(ctx, uri, "")
	require.NoError(t, err)
	require.Equal(t, len(Names())-start, n)
	require.NoError(t, VerifyAll(ctx, uri))
	require.NoError(t, VerifyIsLatest(ctx, uri))
	var unchanged uuid.UUID
	require.NoError(t, db.QueryRowContext(ctx, `SELECT audit_resource_id FROM integration_keys WHERE id=$1`, credential).Scan(&unchanged))
	require.Equal(t, safe, unchanged)
	var owner, insertOK, execOK, publicTable, publicFunction bool
	require.NoError(t, db.QueryRowContext(ctx, `SELECT pg_get_userbyid(c.relowner)=current_user,has_table_privilege(current_user,c.oid,'INSERT'),has_function_privilege(current_user,'integration_key_delete_append_only()','EXECUTE'),EXISTS(SELECT FROM aclexplode(coalesce(c.relacl,acldefault('r',c.relowner))) WHERE grantee=0),EXISTS(SELECT FROM pg_proc p,LATERAL aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a WHERE p.oid='integration_key_delete_append_only()'::regprocedure AND a.grantee=0) FROM pg_class c WHERE c.oid='integration_key_delete_audit_events'::regclass`).Scan(&owner, &insertOK, &execOK, &publicTable, &publicFunction))
	require.True(t, owner)
	require.True(t, insertOK)
	require.True(t, execOK)
	require.False(t, publicTable)
	require.False(t, publicFunction)
	e := keyaudit.Event{SchemaVersion: 1, EventID: uuid.New(), RequestID: uuid.New(), ExecutionID: uuid.New(), AttemptID: uuid.New(), RecordKind: "success_witness", ResourceID: safe, ParentServiceID: svc, TargetOrganizationID: f.org, TargetOrgResolution: "known_normal", Provenance: "EXPLICIT", DeletionMechanism: "explicit_sql", Cause: "explicit_target", ActorKind: "internal_system", AuthoritySource: "trusted_internal_system", AuthorityRole: "internal_system", OrganizationRole: "unknown", Outcome: "committed", Reason: "deleted", OccurredAt: time.Now()}
	tx, err := db.BeginTx(ctx, nil)
	require.NoError(t, err)
	require.NoError(t, keyaudit.Append(ctx, tx, e))
	require.NoError(t, keyaudit.Append(ctx, tx, e))
	// The same migrated PostgreSQL identity stages audit INSERT and business DELETE.
	_, err = tx.ExecContext(ctx, `DELETE FROM integration_keys WHERE id=$1`, credential)
	require.NoError(t, err)
	require.NoError(t, tx.Commit())
	var raw string
	require.NoError(t, db.QueryRowContext(ctx, `SELECT to_jsonb(e)::text FROM integration_key_delete_audit_events e WHERE event_id=$1`, e.EventID).Scan(&raw))
	require.NotContains(t, raw, credential.String())
	require.NotContains(t, raw, "SYNTHETIC_")
	tx, err = db.BeginTx(ctx, nil)
	require.NoError(t, err)
	conflict := e
	conflict.ParentServiceID = uuid.New()
	require.ErrorIs(t, keyaudit.Append(ctx, tx, conflict), keyaudit.ErrConflict)
	require.NoError(t, tx.Rollback())
	tx, err = db.BeginTx(ctx, nil)
	require.NoError(t, err)
	duplicate := e
	duplicate.EventID = uuid.New()
	require.ErrorIs(t, keyaudit.Append(ctx, tx, duplicate), keyaudit.ErrUnavailable)
	require.NoError(t, tx.Rollback())
	// Bypass the typed writer: SQL itself rejects invalid/null closed fields.
	for field, value := range map[string]any{"root_type": "other", "cause": "SYNTHETIC_SECRET", "schema_version": 2, "operation": "other", "record_kind": "other", "root_resource_id": nil, "parent_service_id": nil, "target_organization_id": nil, "target_org_resolution": "unknown", "actor_kind": "unknown", "authority_source": "caller", "provenance": "CASCADE", "deletion_mechanism": "fk_cascade", "outcome": "tx_failed", "reason_code": "SYNTHETIC_SECRET", "actor_id": uuid.NewString(), "occurred_at": "infinity"} {
		t.Run(field, func(t *testing.T) {
			var row map[string]any
			require.NoError(t, json.Unmarshal([]byte(raw), &row))
			row["event_id"], row["attempt_id"] = uuid.NewString(), uuid.NewString()
			row[field] = value
			b, err := json.Marshal(row)
			require.NoError(t, err)
			_, err = db.ExecContext(ctx, `INSERT INTO integration_key_delete_audit_events SELECT (jsonb_populate_record(NULL::integration_key_delete_audit_events,$1::jsonb)).*`, string(b))
			var pg *pgconn.PgError
			require.ErrorAs(t, err, &pg)
			require.Equal(t, "23514", pg.Code)
		})
	}
	for _, q := range []string{`UPDATE integration_key_delete_audit_events SET reason_code=reason_code`, `DELETE FROM integration_key_delete_audit_events`, `TRUNCATE integration_key_delete_audit_events`} {
		_, err = db.ExecContext(ctx, q)
		var pg *pgconn.PgError
		require.ErrorAs(t, err, &pg)
		require.Equal(t, "55000", pg.Code)
	}
	var fk int
	require.NoError(t, db.QueryRowContext(ctx, `SELECT count(*) FROM pg_constraint WHERE conrelid='integration_key_delete_audit_events'::regclass AND contype='f'`).Scan(&fk))
	require.Zero(t, fk)
	_, err = db.ExecContext(ctx, `DELETE FROM services WHERE id=$1`, svc)
	require.NoError(t, err)
	var after string
	require.NoError(t, db.QueryRowContext(ctx, `SELECT to_jsonb(e)::text FROM integration_key_delete_audit_events e WHERE event_id=$1`, e.EventID).Scan(&after))
	require.Equal(t, raw, after)
	_, err = Down(ctx, uri, "service-cascade-b2-effects")
	require.Error(t, err)
}
