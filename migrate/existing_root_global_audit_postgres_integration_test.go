package migrate

import (
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
	audit "github.com/target/goalert/schedule/updateaudit"
)

func TestPostgresExistingRootGlobalAuditUpgrade(t *testing.T) {
	ctx, uri, db := boundedAuditDB(t, 291)
	f := newBoundedFixture(t, ctx, db)
	e := f.event(audit.ScheduleUpdate)
	tx, err := db.BeginTx(ctx, nil)
	require.NoError(t, err)
	require.NoError(t, audit.Append(ctx, tx, e))
	require.NoError(t, tx.Commit())
	queries := []string{
		`SELECT jsonb_agg(to_jsonb(e) ORDER BY event_id)::text FROM schedule_rotation_update_audit_events e`,
		`SELECT jsonb_agg(to_jsonb(e) ORDER BY id)::text FROM gorp_migrations e WHERE id<>'20261107115255-existing-root-global-update-audit.sql'`,
		`SELECT jsonb_agg(to_jsonb(e) ORDER BY canonical_position)::text FROM ms_oncall_migration_provenance e WHERE canonical_position<=291`,
		`SELECT jsonb_agg(pg_get_triggerdef(oid) ORDER BY tgname)::text FROM pg_trigger WHERE tgrelid='schedule_rotation_update_audit_events'::regclass`,
		`SELECT jsonb_agg(pg_get_constraintdef(oid) ORDER BY conname)::text FROM pg_constraint WHERE conrelid='schedule_rotation_update_audit_events'::regclass AND conname<>'schedule_rotation_update_audit_events_check4'`,
		`SELECT jsonb_agg(pg_get_constraintdef(oid) ORDER BY conrelid,conname)::text FROM pg_constraint WHERE contype='f'`,
	}
	before := make([]string, len(queries))
	for i, query := range queries {
		require.NoError(t, db.QueryRowContext(ctx, query).Scan(&before[i]))
	}
	n, err := Up(ctx, uri, "")
	require.NoError(t, err)
	require.Equal(t, 1, n)
	for i, query := range queries {
		var after string
		require.NoError(t, db.QueryRowContext(ctx, query).Scan(&after))
		require.Equal(t, before[i], after, "history, append-only constraints and all business FKs are preserved")
	}
	require.NoError(t, VerifyAll(ctx, uri))
	require.NoError(t, VerifyIsLatest(ctx, uri))
	for _, role := range []string{"ORG_MEMBER", "ORG_ADMIN"} {
		e := f.event(audit.ScheduleUpdate)
		e.HomeOrganizationID, e.AuthorityRole, e.OrganizationRole = uuid.New(), "platform_admin", role
		tx, err := db.BeginTx(ctx, nil)
		require.NoError(t, err)
		require.NoError(t, audit.Append(ctx, tx, e))
		require.NoError(t, tx.Commit())
		var home, target string
		require.NoError(t, db.QueryRowContext(ctx, `SELECT home_organization_id,target_organization_id FROM schedule_rotation_update_audit_events WHERE event_id=$1`, e.EventID).Scan(&home, &target))
		require.Equal(t, e.HomeOrganizationID.String(), home)
		require.Equal(t, f.org.String(), target)
	}
	rows, err := db.QueryContext(ctx, `SELECT column_name FROM information_schema.columns WHERE table_name=$1 ORDER BY ordinal_position`, boundedAuditTable)
	require.NoError(t, err)
	var cols []string
	for rows.Next() {
		var c string
		require.NoError(t, rows.Scan(&c))
		cols = append(cols, c)
	}
	require.NoError(t, rows.Err())
	require.NoError(t, rows.Close())
	for name, overrides := range map[string]map[string]string{
		"ordinary_foreign": {"home_organization_id": "gen_random_uuid()"},
		"member":           {"authority_role": "'org_member'", "organization_role": "'ORG_MEMBER'"},
		"untrusted_source": {"authority_role": "'platform_admin'", "authority_source": "'untrusted'"},
		"missing_target":   {"authority_role": "'platform_admin'", "target_id": "NULL", "target_organization_id": "NULL"},
		"unknown":          {"actor_kind": "'unknown'", "actor_id": "NULL", "home_organization_id": "NULL"},
	} {
		t.Run(name, func(t *testing.T) {
			exprs := append([]string(nil), cols...)
			for i, c := range cols {
				if c == "event_id" {
					exprs[i] = "gen_random_uuid()"
				}
				if v, ok := overrides[c]; ok {
					exprs[i] = v
				}
			}
			_, err := db.ExecContext(ctx, "INSERT INTO "+boundedAuditTable+" ("+strings.Join(cols, ",")+") SELECT "+strings.Join(exprs, ",")+" FROM "+boundedAuditTable+" WHERE event_id=$1", e.EventID)
			var pgErr *pgconn.PgError
			require.ErrorAs(t, err, &pgErr)
			require.Contains(t, []string{"23514", "23502"}, pgErr.Code)
		})
	}
	for _, statement := range []string{"UPDATE " + boundedAuditTable + " SET reason_code=reason_code", "DELETE FROM " + boundedAuditTable, "TRUNCATE " + boundedAuditTable} {
		_, err := db.ExecContext(ctx, statement)
		require.Error(t, err)
	}
	h, err := loadEmbeddedHistory()
	require.NoError(t, err)
	n, err = Down(ctx, uri, h.entries[290].Name)
	require.Error(t, err, "downgrade must preserve immutable foreign-target audit history")
	require.Zero(t, n)
	require.Equal(t, 3, boundedCount(t, db))
	boundedEvidence(t, db, "global-existing-root-upgrade")
}
