package migrate

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"math"
	"testing"
	"testing/fstest"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
	audit "github.com/target/goalert/user/authsubjectdeleteaudit"
	useraudit "github.com/target/goalert/user/deleteaudit"
)

func TestAuthSubjectDeleteCanonicalAppend(t *testing.T) {
	h, err := loadEmbeddedHistory()
	require.NoError(t, err)
	require.Len(t, h.entries, 304)
	marker := []byte(",\n    {\n      \"id\": \"ms-oncall-auth-subject-delete-audit-d09-sd9\",")
	i := bytes.Index(h.manifest, marker)
	require.Positive(t, i)
	prefix := append(append([]byte{}, h.manifest[:i]...), []byte("\n  ]\n}\n")...)
	require.Equal(t, "ad4a601d4840112952c6d138cbf1791cbcd70643e535869a3eca7b082bc169f1", fmt.Sprintf("%x", sha256.Sum256(prefix)))
	require.Equal(t, h.entries[301].ID, h.entries[302].PredecessorID)
}

func asSchemaEvent(id int64) audit.Event {
	now := time.Now().UTC().Truncate(time.Microsecond)
	identity := audit.Identity(id)
	owner := uuid.New()
	return audit.Event{SchemaVersion: 1, EventID: uuid.New(), RequestID: uuid.New(), ExecutionID: uuid.New(), AttemptID: uuid.New(), Operation: "auth_subject.delete", RootType: "auth_subject", RootID: &identity, RootOwnerUserID: &owner, RecordKind: "success_witness", ActorKind: "internal_system", AuthoritySource: "trusted_internal_system", AuthorityRole: "internal_system", OrganizationRole: "unknown", TargetOrgResolution: "unknown", BeforeContext: &audit.Before{Version: 1, ID: identity, UserID: owner, RowVersion: 42}, Outcome: "committed", Reason: "deleted", Provenance: "EXPLICIT", DeletionMechanism: "explicit_sql", Cause: "explicit_target", OccurredAt: now, RecordedAt: now}
}

func TestPostgresAuthSubjectDeleteMigration(t *testing.T) {
	for _, start := range []int{0, 302} {
		t.Run(fmt.Sprint(start), func(t *testing.T) {
			ctx := context.Background()
			var uri string
			var db *sql.DB
			if start == 0 {
				uri = newPostgresTestDatabase(t, postgresIntegrationURL(t))
				var err error
				db, err = sql.Open("pgx", uri)
				require.NoError(t, err)
				t.Cleanup(func() { require.NoError(t, db.Close()) })
			} else {
				ctx, uri, db = boundedAuditDB(t, start)
				tx, err := db.BeginTx(ctx, nil)
				require.NoError(t, err)
				require.NoError(t, useraudit.Append(ctx, tx, sd8SchemaEvent()))
				require.NoError(t, tx.Commit())
				require.Error(t, VerifyAll(ctx, uri))
				require.Error(t, VerifyIsLatest(ctx, uri))
			}
			n, err := Up(ctx, uri, "")
			require.NoError(t, err)
			require.Equal(t, len(Names())-start, n)
			require.NoError(t, VerifyAll(ctx, uri))
			require.NoError(t, VerifyIsLatest(ctx, uri))
			n, err = Up(ctx, uri, "")
			require.NoError(t, err)
			require.Zero(t, n)
			if start == 302 {
				var count int
				require.NoError(t, db.QueryRow(`SELECT count(*) FROM user_delete_audit_events`).Scan(&count))
				require.Equal(t, 1, count)
			}
			for _, id := range []int64{math.MinInt64, -1, 0, 1<<53 + 1, math.MaxInt64} {
				e := asSchemaEvent(id)
				tx, err := db.BeginTx(ctx, nil)
				require.NoError(t, err)
				require.NoError(t, audit.Append(ctx, tx, e))
				require.NoError(t, tx.Commit())
				var actual int64
				var beforeID string
				require.NoError(t, db.QueryRow(`SELECT root_id,before_context->>'id' FROM auth_subject_delete_audit_events WHERE event_id=$1`, e.EventID).Scan(&actual, &beforeID))
				require.Equal(t, id, actual)
				require.Equal(t, fmt.Sprint(id), beforeID)
			}
			var fks int
			require.NoError(t, db.QueryRow(`SELECT count(*) FROM pg_constraint WHERE conrelid='auth_subject_delete_audit_events'::regclass AND contype='f'`).Scan(&fks))
			require.Zero(t, fks)
		})
	}
}

func TestPostgresAuthSubjectDeleteClosedConstraints(t *testing.T) {
	ctx, _, db := boundedAuditDB(t, len(Names()))
	const columns = `schema_version,event_id,request_id,execution_id,attempt_id,record_kind,operation,root_type,root_id,root_owner_user_id,parent_cm_id,actor_kind,actor_id,home_organization_id,authority_source,authority_role,organization_role,target_organization_id,target_org_resolution,before_context,provenance,deletion_mechanism,cause,outcome,reason_code,occurred_at,recorded_at`
	insert := `INSERT INTO auth_subject_delete_audit_events (` + columns + `) SELECT ` + columns + ` FROM jsonb_populate_record(NULL::auth_subject_delete_audit_events,$1::jsonb)`
	for _, change := range []func(map[string]any){
		func(e map[string]any) { e["root_id"] = nil }, func(e map[string]any) { e["root_owner_user_id"] = nil }, func(e map[string]any) { e["actor_kind"] = "unknown" }, func(e map[string]any) { e["outcome"] = "no_op" }, func(e map[string]any) { e["provenance"] = nil }, func(e map[string]any) { e["reason_code"] = "SYNTHETIC_PRIVATE" }, func(e map[string]any) { e["before_context"] = nil },
		func(e map[string]any) { e["before_context"].(map[string]any)["id"] = "01" }, func(e map[string]any) { e["before_context"].(map[string]any)["row_version"] = nil }, func(e map[string]any) { delete(e["before_context"].(map[string]any), "cm_id") }, func(e map[string]any) { e["before_context"].(map[string]any)["ProviderID"] = "SYNTHETIC_PRIVATE" },
	} {
		e := asSchemaEvent(1)
		raw, err := json.Marshal(e)
		require.NoError(t, err)
		var fields map[string]any
		require.NoError(t, json.Unmarshal(raw, &fields))
		change(fields)
		raw, err = json.Marshal(fields)
		require.NoError(t, err)
		tx, err := db.BeginTx(ctx, nil)
		require.NoError(t, err)
		_, err = tx.ExecContext(ctx, insert, string(raw))
		if err == nil {
			t.Fatal("invalid closed projection accepted (sample withheld)")
		}
		require.NoError(t, tx.Rollback())
	}
	e := asSchemaEvent(5)
	tx, err := db.BeginTx(ctx, nil)
	require.NoError(t, err)
	require.NoError(t, audit.Append(ctx, tx, e))
	require.NoError(t, tx.Commit())
	for _, query := range []string{`UPDATE auth_subject_delete_audit_events SET outcome='committed'`, `DELETE FROM auth_subject_delete_audit_events`, `TRUNCATE auth_subject_delete_audit_events`} {
		_, err = db.ExecContext(ctx, query)
		require.Error(t, err)
	}
	for _, duplicate := range []audit.Event{e, func() audit.Event { x := e; x.EventID = uuid.New(); return x }()} {
		tx, err := db.BeginTx(ctx, nil)
		require.NoError(t, err)
		require.Error(t, audit.Append(ctx, tx, duplicate))
		require.NoError(t, tx.Rollback())
	}
	var count int
	require.NoError(t, db.QueryRow(`SELECT count(*) FROM auth_subject_delete_audit_events`).Scan(&count))
	require.Equal(t, 1, count)
}

func TestPostgresAuthSubjectFailureObservation(t *testing.T) {
	ctx, _, db := boundedAuditDB(t, len(Names()))
	e := asSchemaEvent(5)
	e.EventID = uuid.New()
	e.RecordKind = "attempt_observation"
	e.RootID = nil
	e.RootOwnerUserID = nil
	e.BeforeContext = nil
	e.Provenance = ""
	e.DeletionMechanism = ""
	e.Cause = ""
	e.Outcome = "tx_failed"
	e.Reason = "delete_failed"
	tx, err := db.BeginTx(ctx, nil)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback() }()
	require.NoError(t, audit.Append(ctx, tx, e))
	require.NoError(t, tx.Commit())
	var count int
	require.NoError(t, db.QueryRow(`SELECT count(*) FROM auth_subject_delete_audit_events WHERE event_id=$1 AND root_id IS NULL AND before_context='null'`, e.EventID).Scan(&count))
	require.Equal(t, 1, count)
}

func TestPostgresAuthSubjectOldHistoryGate(t *testing.T) {
	ctx, uri, _ := boundedAuditDB(t, len(Names()))
	h, err := loadEmbeddedHistory()
	require.NoError(t, err)
	marker := []byte(",\n    {\n      \"id\": \"ms-oncall-auth-subject-delete-audit-d09-sd9\",")
	i := bytes.Index(h.manifest, marker)
	require.Positive(t, i)
	prefix := append(append([]byte{}, h.manifest[:i]...), []byte("\n  ]\n}\n")...)
	files := fstest.MapFS{"history.json": &fstest.MapFile{Data: prefix}}
	for _, entry := range h.entries[:302] {
		raw, err := migrationFS.ReadFile("migrations/" + entry.ID)
		require.NoError(t, err)
		files["migrations/"+entry.ID] = &fstest.MapFile{Data: raw}
	}
	old, err := loadCanonicalHistory(files)
	require.NoError(t, err)
	conn, err := pgx.Connect(ctx, uri)
	require.NoError(t, err)
	defer conn.Close(ctx)
	_, err = loadAppliedHistory(ctx, conn, old)
	require.Error(t, err, "the actual production history gate rejects a 303 DB against frozen 302 history")
}
