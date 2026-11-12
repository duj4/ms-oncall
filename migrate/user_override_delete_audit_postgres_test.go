package migrate

import (
	"bytes"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
	uoaudit "github.com/target/goalert/override/deleteaudit"
)

func uoSchemaEvent() uoaudit.Event {
	u := uuid.New()
	b := &uoaudit.Before{Version: 1, RootID: uuid.New(), ParentScheduleID: uuid.New(), TargetOrganizationID: uuid.New(), AddUserID: &u, RemoveUserID: &u, Start: time.Date(9998, 1, 1, 0, 0, 0, 123456000, time.UTC), End: time.Date(9999, 12, 31, 23, 59, 59, 999999000, time.UTC), RowVersion: 4294967295}
	return uoaudit.Event{SchemaVersion: 1, EventID: uuid.New(), RequestID: uuid.New(), ExecutionID: uuid.New(), AttemptID: uuid.New(), RecordKind: "success_witness", Operation: "user_override.delete", RootType: "user_override", RootID: b.RootID, ParentScheduleID: b.ParentScheduleID, TargetOrganizationID: b.TargetOrganizationID, TargetOrgResolution: "known_normal", BeforeContext: b, Provenance: "EXPLICIT", DeletionMechanism: "explicit_sql", Cause: "explicit_target", ActorKind: "human", ActorID: uuid.New(), HomeOrganizationID: b.TargetOrganizationID, AuthoritySource: "current_local_user_organization_at_admission", AuthorityRole: "platform_admin", OrganizationRole: "ORG_MEMBER", Outcome: "committed", Reason: "deleted", OccurredAt: time.Now()}
}

func TestUODeleteAudit301CanonicalHistory(t *testing.T) {
	h, err := loadEmbeddedHistory()
	require.NoError(t, err)
	require.Len(t, h.entries, 302)
	e := h.entries[300]
	require.Equal(t, "20261112140817-user-override-delete-audit.sql", e.ID)
	require.Equal(t, h.entries[299].ID, e.PredecessorID)
	marker := []byte(",\n    {\n      \"id\": \"ms-oncall-user-override-delete-audit-d09-sd7\",")
	i := bytes.Index(h.manifest, marker)
	require.Positive(t, i)
	prefix := append(append([]byte{}, h.manifest[:i]...), []byte("\n  ]\n}\n")...)
	require.Equal(t, "c569dff7491a091028824b9b1064884d4d1408dfe71af526801560ed92975c19", fmt.Sprintf("%x", sha256.Sum256(prefix)))
}

func TestPostgresUODeleteSchemaReplayAndAtomicity(t *testing.T) {
	for _, start := range []int{300, 301} {
		t.Run(fmt.Sprint(start), func(t *testing.T) {
			ctx, uri, db := boundedAuditDB(t, start)
			n, err := Up(ctx, uri, "")
			require.NoError(t, err)
			require.Equal(t, 302-start, n)
			require.NoError(t, VerifyAll(ctx, uri))
			require.NoError(t, VerifyIsLatest(ctx, uri))
			n, err = Up(ctx, uri, "")
			require.NoError(t, err)
			require.Zero(t, n)
			app, err := sql.Open("pgx", uri)
			require.NoError(t, err)
			defer app.Close()
			var mid, aid, version string
			require.NoError(t, db.QueryRowContext(ctx, `SELECT system_identifier::text,current_setting('server_version') FROM pg_control_system()`).Scan(&mid, &version))
			require.NoError(t, app.QueryRowContext(ctx, `SELECT system_identifier::text FROM pg_control_system()`).Scan(&aid))
			require.Equal(t, mid, aid)
			t.Log("Migration/Application System ID", aid, "PostgreSQL", version)
			f := newBoundedFixture(t, ctx, db)
			id := uuid.New()
			_, err = db.ExecContext(ctx, `INSERT INTO user_overrides(id,tgt_schedule_id,add_user_id,start_time,end_time) VALUES($1,$2,$3,'2020-01-01','2020-01-02')`, id, f.schedule, f.user)
			require.NoError(t, err)
			e := uoSchemaEvent()
			e.RootID, e.ParentScheduleID, e.TargetOrganizationID, e.HomeOrganizationID = id, f.schedule, f.org, f.org
			e.BeforeContext.RootID, e.BeforeContext.ParentScheduleID, e.BeforeContext.TargetOrganizationID = id, f.schedule, f.org
			for _, commit := range []bool{false, true} {
				tx, err := app.BeginTx(ctx, nil)
				require.NoError(t, err)
				defer func() { _ = tx.Rollback() }()
				_, err = tx.ExecContext(ctx, `DELETE FROM user_overrides WHERE id=$1`, id)
				require.NoError(t, err)
				require.NoError(t, uoaudit.Append(ctx, tx, e))
				require.NoError(t, uoaudit.Append(ctx, tx, e))
				changed := e
				changed.ActorID = uuid.New()
				require.ErrorIs(t, uoaudit.Append(ctx, tx, changed), uoaudit.ErrConflict)
				if commit {
					require.NoError(t, tx.Commit())
				} else {
					require.NoError(t, tx.Rollback())
				}
				var roots, events int
				require.NoError(t, app.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM user_overrides WHERE id=$1),(SELECT count(*) FROM user_override_delete_audit_events)`, id).Scan(&roots, &events))
				if commit {
					require.Zero(t, roots)
					require.Equal(t, 1, events)
				} else {
					require.Equal(t, 1, roots)
					require.Zero(t, events)
				}
			}
			for _, q := range []string{`UPDATE user_override_delete_audit_events SET outcome=outcome`, `DELETE FROM user_override_delete_audit_events WHERE false`, `TRUNCATE user_override_delete_audit_events`} {
				_, err = app.ExecContext(ctx, q)
				var pg *pgconn.PgError
				require.ErrorAs(t, err, &pg)
				require.Equal(t, "55000", pg.Code)
			}
			var liveFK, publicGrant bool
			require.NoError(t, db.QueryRowContext(ctx, `SELECT EXISTS(SELECT FROM pg_constraint WHERE conrelid='user_override_delete_audit_events'::regclass AND contype='f'),EXISTS(SELECT FROM pg_class c,LATERAL aclexplode(coalesce(c.relacl,acldefault('r',c.relowner))) a WHERE c.oid='user_override_delete_audit_events'::regclass AND a.grantee=0)`).Scan(&liveFK, &publicGrant))
			require.False(t, liveFK)
			require.False(t, publicGrant)
			_, err = Down(ctx, uri, "schedule-rotation-delete-audit")
			require.Error(t, err)
		})
	}
}

func TestPostgresUODeleteClosedProjectionAndBudgets(t *testing.T) {
	ctx, _, db := boundedAuditDB(t, 301)
	e := uoSchemaEvent()
	tx, err := db.BeginTx(ctx, nil)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback() }()
	goBytes := 0
	for range uoaudit.MaxRoots {
		e.EventID, e.RootID = uuid.New(), uuid.New()
		b := *e.BeforeContext
		b.RootID = e.RootID
		e.BeforeContext = &b
		require.NoError(t, uoaudit.Append(ctx, tx, e))
		raw, err := json.Marshal(e.Canonical())
		require.NoError(t, err)
		goBytes += len(raw)
	}
	var maxSize, total int
	require.NoError(t, tx.QueryRowContext(ctx, `SELECT max(octet_length(to_jsonb(e)::text)),sum(octet_length(to_jsonb(e)::text)) FROM user_override_delete_audit_events e`).Scan(&maxSize, &total))
	require.LessOrEqual(t, maxSize, uoaudit.MaxRootJSONBytes)
	require.LessOrEqual(t, total, uoaudit.MaxJSONBytes)
	t.Logf("50 full projections Go=%d PG JSONB=%d max PG root=%d limits=%d/%d", goBytes, total, maxSize, uoaudit.MaxRootJSONBytes, uoaudit.MaxJSONBytes)
	require.NoError(t, tx.Commit())
	for name, patch := range map[string]string{
		"unknown_before": `jsonb_build_object('before_context',before_context||'{"email":"SYNTHETIC_PRIVATE"}'::jsonb)`,
		"no_before":      `jsonb_build_object('before_context',NULL)`, "wrong_root": `jsonb_build_object('root_type','user')`, "wrong_operation": `jsonb_build_object('operation','schedule.delete')`, "wrong_parent": `jsonb_build_object('parent_schedule_id',gen_random_uuid())`, "wrong_org": `jsonb_build_object('target_organization_id',gen_random_uuid())`,
		"unknown_actor": `jsonb_build_object('actor_kind','unknown')`, "foreign_pa": `jsonb_build_object('home_organization_id',gen_random_uuid())`, "false_effect": `jsonb_build_object('effects','[{"deleted_user":"SYNTHETIC_PRIVATE"}]'::jsonb)`,
		"missing_users": `jsonb_build_object('before_context',before_context||'{"add_user_id":null,"remove_user_id":null}'::jsonb)`, "row_overflow": `jsonb_build_object('before_context',before_context||'{"row_version":4294967296}'::jsonb)`, "float": `jsonb_build_object('before_context',before_context||'{"row_version":1.5}'::jsonb)`, "infinity": `jsonb_build_object('before_context',before_context||'{"end":"infinity"}'::jsonb)`, "oversize": `jsonb_build_object('before_context',before_context||jsonb_build_object('start',repeat('X',4097)))`,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := db.ExecContext(ctx, `INSERT INTO user_override_delete_audit_events SELECT (jsonb_populate_record(NULL::user_override_delete_audit_events,to_jsonb(e)||jsonb_build_object('event_id',gen_random_uuid(),'attempt_id',gen_random_uuid())||`+patch+`)).* FROM user_override_delete_audit_events e LIMIT 1`)
			var pg *pgconn.PgError
			require.ErrorAs(t, err, &pg)
			if name == "no_before" {
				require.Equal(t, "23502", pg.Code)
			} else {
				require.Equal(t, "23514", pg.Code)
			}
		})
	}
}
