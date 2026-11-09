package migrate

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/organization"
	createaudit "github.com/target/goalert/rootcreateaudit"
	serviceaudit "github.com/target/goalert/service/updateaudit"
)

func TestGlobalRootAuditCanonicalAppendOnlyPrefix(t *testing.T) {
	h, err := loadEmbeddedHistory()
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(h.entries), 294)
	marker := []byte(",\n    {\n      \"id\": \"ms-oncall-default-pa-update-audit-d02-s3-a12\",")
	i := bytes.Index(h.manifest, marker)
	require.Positive(t, i)
	prefix := append(append([]byte(nil), h.manifest[:i]...), []byte("\n  ]\n}\n")...)
	require.Equal(t, "d6053e935ddf8b64dcece7a295ff5a7b8c0df41dc46ca513bc960ec9118c96c7", fmt.Sprintf("%x", sha256.Sum256(prefix)))
	for i := 292; i < 294; i++ {
		require.EqualValues(t, i+1, h.entries[i].Position)
		require.Equal(t, h.entries[i-1].ID, h.entries[i].PredecessorID)
	}
}

func TestPostgresGlobalRootAuditUpgradeAndHistory(t *testing.T) {
	ctx, uri, db := boundedAuditDB(t, 292)
	e := serviceaudit.Event{EventID: uuid.New(), AttemptID: uuid.New(), RequestID: uuid.New(), ActorKind: "human", ActorID: uuid.New(), HomeOrganizationID: uuid.New(), AuthoritySource: "current_local_user_organization_at_admission", AuthorityRole: "platform_admin", OrganizationRole: "ORG_MEMBER", ServiceID: uuid.New(), TargetOrganizationID: uuid.New(), Outcome: "committed", Reason: "updated", OccurredAt: time.Now()}
	tx, err := db.BeginTx(ctx, nil)
	require.NoError(t, err)
	require.NoError(t, serviceaudit.Append(ctx, tx, e))
	require.NoError(t, tx.Commit())
	queries := []string{
		`SELECT jsonb_agg(to_jsonb(e) ORDER BY event_id)::text FROM service_update_audit_events e`,
		`SELECT jsonb_agg(to_jsonb(e) ORDER BY id)::text FROM gorp_migrations e`,
		`SELECT jsonb_agg(to_jsonb(e) ORDER BY canonical_position)::text FROM ms_oncall_migration_provenance e`,
	}
	before := make([]string, len(queries))
	for i, q := range queries {
		require.NoError(t, db.QueryRowContext(ctx, q).Scan(&before[i]))
	}
	n, err := Up(ctx, uri, "")
	require.NoError(t, err)
	require.Equal(t, len(Names())-292, n)
	queries[1] = `SELECT jsonb_agg(to_jsonb(e) ORDER BY id)::text FROM gorp_migrations e WHERE id IN (SELECT migration_id FROM ms_oncall_migration_provenance WHERE canonical_position<=292)`
	queries[2] = `SELECT jsonb_agg(to_jsonb(e) ORDER BY canonical_position)::text FROM ms_oncall_migration_provenance e WHERE canonical_position<=292`
	for i, q := range queries {
		var after string
		require.NoError(t, db.QueryRowContext(ctx, q).Scan(&after))
		require.Equal(t, before[i], after)
	}
	e.EventID = uuid.New()
	e.HomeOrganizationID = uuid.MustParse(organization.DefaultOrganizationID)
	e.OrganizationRole = "NONE"
	tx, err = db.BeginTx(ctx, nil)
	require.NoError(t, err)
	require.NoError(t, serviceaudit.Append(ctx, tx, e))
	require.NoError(t, tx.Commit())
	for _, tc := range []struct{ home, authority, role string }{
		{uuid.NewString(), "platform_admin", "NONE"}, {organization.DefaultOrganizationID, "org_admin", "NONE"}, {organization.DefaultOrganizationID, "org_member", "NONE"},
	} {
		_, err := db.ExecContext(ctx, `INSERT INTO service_update_audit_events(event_id,attempt_id,request_id,actor_kind,actor_id,home_organization_id,authority_source,authority_role,organization_role,requested_fields,outcome,reason_code,occurred_at)
		 VALUES($1,$2,$3,'human',$4,$5,'current_local_user_organization_at_admission',$6,$7,0,'denied','authority_denied',now())`, uuid.New(), uuid.New(), uuid.New(), e.ActorID, tc.home, tc.authority, tc.role)
		var pg *pgconn.PgError
		require.ErrorAs(t, err, &pg)
		require.Equal(t, "23514", pg.Code)
	}
	ce := createaudit.Event{EventID: uuid.New(), AttemptID: uuid.New(), RequestID: uuid.New(), ActorID: e.ActorID, HomeOrganizationID: e.HomeOrganizationID, OrganizationRole: "NONE", RootType: "service", RootID: uuid.New(), TargetOrganizationID: e.TargetOrganizationID, Outcome: "committed", Reason: "created", OccurredAt: time.Now()}
	tx, err = db.BeginTx(ctx, nil)
	require.NoError(t, err)
	require.NoError(t, createaudit.Append(ctx, tx, ce))
	require.NoError(t, tx.Commit())
	for _, table := range []string{"service_update_audit_events", "schedule_rotation_update_audit_events", "global_root_create_audit_events"} {
		for _, q := range []string{"UPDATE " + table + " SET event_id=event_id", "DELETE FROM " + table, "TRUNCATE " + table} {
			_, err := db.ExecContext(ctx, q)
			var pg *pgconn.PgError
			require.ErrorAs(t, err, &pg)
			require.Equal(t, "55000", pg.Code)
		}
	}
	n, err = Down(ctx, uri, "existing-root-global-update-audit")
	require.Error(t, err)
	require.Zero(t, n)
	require.NoError(t, VerifyAll(ctx, uri))
	require.NoError(t, VerifyIsLatest(ctx, uri))
	var count int
	require.NoError(t, db.QueryRowContext(ctx, `SELECT count(*) FROM global_root_create_audit_events`).Scan(&count))
	require.Equal(t, 1, count)
}
