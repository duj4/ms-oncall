package migrate

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
	pgdump "github.com/target/goalert/devtools/pgdump-lite"
	audit "github.com/target/goalert/user/cmnrdeleteaudit"
)

func cmnrDBEvent() audit.Event {
	owner, org := uuid.New(), uuid.New()
	return audit.Event{EventID: uuid.New(), RequestID: uuid.New(), ExecutionID: uuid.New(), AttemptID: uuid.New(), RecordKind: "success_witness", Operation: "contact_method.delete", RootType: "contact_method", RootID: uuid.New(), RootOwnerUserID: owner, TargetOrganizationID: org, TargetOrgResolution: "known_normal", Provenance: "EXPLICIT", DeletionMechanism: "explicit_sql", ActorKind: "human", ActorID: owner, HomeOrganizationID: org, AuthoritySource: "current_local_user_organization_at_admission", AuthorityRole: "org_member", OrganizationRole: "ORG_MEMBER", Outcome: "committed", Reason: "deleted", OccurredAt: time.Now()}
}

func TestCMNRDeleteAuditCanonicalPrefix(t *testing.T) {
	h, err := loadEmbeddedHistory()
	require.NoError(t, err)
	require.Len(t, h.entries, 302)
	marker := []byte(",\n    {\n      \"id\": \"ms-oncall-user-cmnr-delete-audit-d09-sd2\",")
	i := bytes.Index(h.manifest, marker)
	require.Positive(t, i)
	prefix := append(append([]byte(nil), h.manifest[:i]...), []byte("\n  ]\n}\n")...)
	require.Equal(t, "3ff84b3cb83bc1bbcb5c0c76cba4bdf111cc87977daf659c7f83e569dcf812fa", fmt.Sprintf("%x", sha256.Sum256(prefix)), "complete accepted manifest is an exact byte prefix")
	e := h.entries[295]
	require.Equal(t, "20261110115605-user-cmnr-delete-audit.sql", e.ID)
	require.Equal(t, h.entries[294].ID, e.PredecessorID)
	raw, err := migrationFS.ReadFile("migrations/" + e.ID)
	require.NoError(t, err)
	require.Equal(t, e.SHA256, fmt.Sprintf("%x", sha256.Sum256(raw)))
	require.Equal(t, "062dd95cde1a2880178074c2f5884c1cdd1a4da69f00090662dcd81dd917509f", h.entries[294].SHA256)
}

func TestPostgresCMNRDeleteAuditUpgradeReplayAndStrictSQL(t *testing.T) {
	ctx, uri, db := boundedAuditDB(t, 294)
	n, err := Up(ctx, uri, "service-delete-audit")
	require.NoError(t, err)
	require.Equal(t, 1, n)
	old := serviceDeleteDBEvent()
	tx, err := db.BeginTx(ctx, nil)
	require.NoError(t, err)
	// The accepted SD1 table and historical values must survive 296 unchanged.
	require.NoError(t, appendLegacyServiceDelete(ctx, tx, old))
	require.NoError(t, tx.Commit())
	var before string
	require.NoError(t, db.QueryRowContext(ctx, `SELECT to_jsonb(e)::text FROM service_delete_audit_events e`).Scan(&before))
	n, err = Up(ctx, uri, "user-cmnr-delete-audit")
	require.NoError(t, err)
	require.Equal(t, 1, n)
	var after string
	require.NoError(t, db.QueryRowContext(ctx, `SELECT to_jsonb(e)::text FROM service_delete_audit_events e`).Scan(&after))
	require.Equal(t, before, after)
	_, err = Up(ctx, uri, "")
	require.NoError(t, err)
	require.NoError(t, VerifyAll(ctx, uri))
	require.NoError(t, VerifyIsLatest(ctx, uri))
	e := cmnrDBEvent()
	numeric := int64(9223372036854775807)
	e.Effects = []audit.Effect{{EffectID: uuid.New(), ResourceType: "auth_subject", ResourceNumericID: &numeric, OwnerUserID: uuid.New(), OrgResolution: "unknown", Relation: "contact_method.auth_subject", Change: "deleted", Provenance: "IMPLICIT_FK_CASCADE"}}
	e.RelatedExplicitEvents = []audit.RelatedExplicitEvent{{EventID: uuid.New(), Relation: "parent_cm"}}
	tx, err = db.BeginTx(ctx, nil)
	require.NoError(t, err)
	require.NoError(t, audit.Append(ctx, tx, e))
	require.NoError(t, audit.Append(ctx, tx, e))
	for _, kind := range []string{"effects", "actor", "time", "related"} {
		changed := e.Canonical()
		switch kind {
		case "effects":
			changed.Effects[0].EffectID = uuid.New()
		case "actor":
			changed.AuthorityRole = "platform_admin"
			changed.ActorID = uuid.New()
		case "time":
			changed.OccurredAt = changed.OccurredAt.Add(time.Second)
		case "related":
			changed.RelatedExplicitEvents[0].EventID = uuid.New()
		}
		require.ErrorIs(t, audit.Append(ctx, tx, changed), audit.ErrConflict)
	}
	require.NoError(t, tx.Commit())
	var eventBefore string
	require.NoError(t, db.QueryRowContext(ctx, `SELECT to_jsonb(e)::text FROM user_cmnr_delete_audit_events e`).Scan(&eventBefore))
	for _, q := range []string{`UPDATE user_cmnr_delete_audit_events SET reason_code=reason_code`, `UPDATE user_cmnr_delete_audit_events SET reason_code=reason_code WHERE false`, `DELETE FROM user_cmnr_delete_audit_events WHERE false`, `TRUNCATE user_cmnr_delete_audit_events`} {
		_, err = db.ExecContext(ctx, q)
		var pg *pgconn.PgError
		require.ErrorAs(t, err, &pg)
		require.Equal(t, "55000", pg.Code)
	}
	for name, expr := range map[string]string{
		"unknown key": `jsonb_set(effects,'{0,provider_id}','"SYNTHETIC_SECRET"')`,
		"float":       `jsonb_set(effects,'{0,resource_numeric_id}','1.5')`,
		"overflow":    `jsonb_set(effects,'{0,resource_numeric_id}','9223372036854775808')`,
		"zero owner":  `jsonb_set(effects,'{0,owner_user_id}','"00000000-0000-0000-0000-000000000000"')`,
		"duplicate":   `effects||effects`, "object": `'{}'::jsonb`,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := db.ExecContext(ctx, `INSERT INTO user_cmnr_delete_audit_events SELECT (jsonb_populate_record(NULL::user_cmnr_delete_audit_events,to_jsonb(e)||jsonb_build_object('event_id',gen_random_uuid(),'attempt_id',gen_random_uuid(),'effects',`+expr+`))).* FROM user_cmnr_delete_audit_events e LIMIT 1`)
			var pg *pgconn.PgError
			require.ErrorAs(t, err, &pg)
			require.Equal(t, "23514", pg.Code)
		})
	}
	for name, patch := range map[string]string{"represented": `jsonb_build_object('represented_human_id',gen_random_uuid())`, "unknown success": `jsonb_build_object('actor_kind','unknown')`, "false reason": `jsonb_build_object('reason_code','write_failed')`, "missing provenance": `jsonb_build_object('provenance',NULL)`, "wrong root": `jsonb_build_object('root_type','user')`, "invalid related": `jsonb_build_object('related_explicit_events','[{"event_id":"00000000-0000-0000-0000-000000000000","relation":"parent_cm"}]'::jsonb)`} {
		t.Run(name, func(t *testing.T) {
			_, err := db.ExecContext(ctx, `INSERT INTO user_cmnr_delete_audit_events SELECT (jsonb_populate_record(NULL::user_cmnr_delete_audit_events,to_jsonb(e)||jsonb_build_object('event_id',gen_random_uuid(),'attempt_id',gen_random_uuid())||`+patch+`)).* FROM user_cmnr_delete_audit_events e LIMIT 1`)
			var pg *pgconn.PgError
			require.ErrorAs(t, err, &pg)
			require.Equal(t, "23514", pg.Code)
		})
	}
	var persistence string
	var fks, grants int
	require.NoError(t, db.QueryRowContext(ctx, `SELECT relpersistence FROM pg_class WHERE oid='user_cmnr_delete_audit_events'::regclass`).Scan(&persistence))
	require.Equal(t, "p", persistence)
	require.NoError(t, db.QueryRowContext(ctx, `SELECT count(*) FROM pg_constraint WHERE contype='f' AND conrelid='user_cmnr_delete_audit_events'::regclass`).Scan(&fks))
	require.Zero(t, fks)
	require.NoError(t, db.QueryRowContext(ctx, `SELECT count(*) FROM pg_class c,LATERAL aclexplode(c.relacl) a WHERE c.oid='user_cmnr_delete_audit_events'::regclass AND a.grantee=0`).Scan(&grants))
	require.Zero(t, grants)
	n, err = Down(ctx, uri, "service-delete-audit")
	require.Error(t, err)
	require.Zero(t, n)
	require.NoError(t, db.QueryRowContext(ctx, `SELECT to_jsonb(e)::text FROM user_cmnr_delete_audit_events e`).Scan(&after))
	require.JSONEq(t, eventBefore, after)
	// A second EventID for an identical successful attempt/root is rejected.
	e.EventID = uuid.New()
	tx, err = db.BeginTx(ctx, nil)
	require.NoError(t, err)
	require.ErrorIs(t, audit.Append(ctx, tx, e), audit.ErrUnavailable)
	require.NoError(t, tx.Rollback())
	var parsed map[string]any
	require.NoError(t, json.Unmarshal([]byte(after), &parsed))
	require.NotContains(t, after, "SYNTHETIC_SECRET")
}

func TestPostgresCMNRDeleteAuditFreshSchema(t *testing.T) {
	ctx, uri, db := boundedAuditDB(t, len(Names()))
	require.NoError(t, VerifyAll(ctx, uri))
	require.NoError(t, VerifyIsLatest(ctx, uri))
	conn, err := pgx.Connect(ctx, uri)
	require.NoError(t, err)
	defer conn.Close(ctx)
	entries, err := migrationFS.ReadDir("migrations")
	require.NoError(t, err)
	var disk, data []string
	for _, entry := range entries {
		raw, err := migrationFS.ReadFile("migrations/" + entry.Name())
		require.NoError(t, err)
		disk = append(disk, entry.Name()+"\n")
		data = append(data, fmt.Sprintf("%x  migrate/migrations/%s\n", sha256.Sum256(raw), entry.Name()))
	}
	sort.Strings(disk)
	sort.Strings(data)
	var applied []string
	rows, err := db.QueryContext(ctx, `SELECT id FROM gorp_migrations ORDER BY id`)
	require.NoError(t, err)
	for rows.Next() {
		var id string
		require.NoError(t, rows.Scan(&id))
		applied = append(applied, id+"\n")
	}
	require.NoError(t, rows.Err())
	require.NoError(t, rows.Close())
	require.Equal(t, disk, applied)
	schema, err := pgdump.DumpSchema(ctx, conn)
	require.NoError(t, err)
	result := []byte(fmt.Sprintf("-- This file is auto-generated by \"make db-schema\"; DO NOT EDIT\n-- DATA=%x  -\n-- DISK=%x  -\n-- PSQL=%x  -\n--\n-- pgdump-lite database dump\n--\n\n%s", sha256.Sum256([]byte(strings.Join(data, ""))), sha256.Sum256([]byte(strings.Join(disk, ""))), sha256.Sum256([]byte(strings.Join(applied, ""))), schema.String()))
	if out := os.Getenv("SD2_AUDIT_SCHEMA"); out != "" {
		require.NoError(t, os.WriteFile(out, result, 0600))
	} else {
		canonical, err := os.ReadFile("schema.sql")
		require.NoError(t, err)
		require.Equal(t, string(canonical), string(result))
	}
}
