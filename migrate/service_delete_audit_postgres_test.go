package migrate

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/organization"
	"github.com/target/goalert/service/deleteaudit"
	serviceaudit "github.com/target/goalert/service/updateaudit"
)

func TestServiceDeleteAuditCanonicalPrefix(t *testing.T) {
	h, err := loadEmbeddedHistory()
	require.NoError(t, err)
	marker := []byte(",\n    {\n      \"id\": \"ms-oncall-service-delete-audit-d09-sd1\",")
	i := bytes.Index(h.manifest, marker)
	require.Positive(t, i)
	prefix := append(append([]byte(nil), h.manifest[:i]...), []byte("\n  ]\n}\n")...)
	// Exact complete formal-parent manifest, not a regenerated JSON equivalent.
	require.Equal(t, "a601ab22bca759dccfe7c6548ce4d10a568de5d143c25e9b5c3f1850e894c4de", fmt.Sprintf("%x", sha256.Sum256(prefix)))
	e := h.entries[294]
	require.EqualValues(t, 295, e.Position)
	require.Equal(t, "20261109081541-service-delete-audit.sql", e.ID)
	require.Equal(t, h.entries[293].ID, e.PredecessorID)
	require.Equal(t, "MS_ONCALL", e.Provenance)
	source, err := parseCanonicalSourceBinding(e.SourceBinding)
	require.NoError(t, err)
	require.Equal(t, "94360610d85d4bfbaf647276f07e4385c54760ae", source.BaseCommit)
	require.Equal(t, "3483ca6ea17d979dd136fe434d0ae2aa80e68fa7", source.BaseTree)
	require.Equal(t, "48eefdae896f94a5fa22a0160480e5c3cccf55ae", source.AuthorizationCommit)
	raw, err := migrationFS.ReadFile("migrations/" + e.ID)
	require.NoError(t, err)
	require.Equal(t, e.SHA256, fmt.Sprintf("%x", sha256.Sum256(raw)))
}

func serviceDeleteDBEvent() deleteaudit.Event {
	home := uuid.New()
	return deleteaudit.Event{EventID: uuid.New(), AttemptID: uuid.New(), RequestID: uuid.New(), ActorKind: "human", ActorID: uuid.New(), HomeOrganizationID: home, AuthoritySource: "current_local_user_organization_at_admission", AuthorityRole: "org_admin", OrganizationRole: "ORG_ADMIN", ServiceID: uuid.New(), TargetOrganizationID: home, Outcome: "committed", Reason: "deleted", OccurredAt: time.Now()}
}

func TestPostgresServiceDeleteAuditUpgradeAndIntegrity(t *testing.T) {
	ctx, uri, db := boundedAuditDB(t, 294)
	old := serviceaudit.Event{EventID: uuid.New(), AttemptID: uuid.New(), RequestID: uuid.New(), ActorKind: "human", ActorID: uuid.New(), HomeOrganizationID: uuid.New(), AuthoritySource: "current_local_user_organization_at_admission", AuthorityRole: "platform_admin", OrganizationRole: "ORG_MEMBER", ServiceID: uuid.New(), TargetOrganizationID: uuid.New(), Outcome: "committed", Reason: "updated", OccurredAt: time.Now()}
	tx, err := db.BeginTx(ctx, nil)
	require.NoError(t, err)
	require.NoError(t, serviceaudit.Append(ctx, tx, old))
	require.NoError(t, tx.Commit())
	queries := []string{
		`SELECT jsonb_agg(to_jsonb(r) ORDER BY event_id)::text FROM service_update_audit_events r`,
		`SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY event_id),'[]')::text FROM global_root_create_audit_events r`,
		`SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY event_id),'[]')::text FROM schedule_rotation_update_audit_events r`,
		`SELECT jsonb_agg(to_jsonb(r) ORDER BY canonical_position)::text FROM ms_oncall_migration_provenance r WHERE canonical_position<=294`,
		`SELECT jsonb_agg(to_jsonb(r) ORDER BY id)::text FROM gorp_migrations r WHERE id<>'20261109081541-service-delete-audit.sql'`,
	}
	before := make([]string, len(queries))
	for i, q := range queries {
		require.NoError(t, db.QueryRowContext(ctx, q).Scan(&before[i]))
	}
	n, err := Up(ctx, uri, "service-delete-audit")
	require.NoError(t, err)
	require.Equal(t, 1, n)
	for i, q := range queries {
		var after string
		require.NoError(t, db.QueryRowContext(ctx, q).Scan(&after))
		require.Equal(t, before[i], after)
	}
	// Keep the SD1 upgrade/downgrade assertions at exactly 295. The newer
	// forward migration is deliberately absent until those guards are tested.
	require.Error(t, VerifyAll(ctx, uri))
	e := serviceDeleteDBEvent()
	tx, err = db.BeginTx(ctx, nil)
	require.NoError(t, err)
	require.NoError(t, deleteaudit.Append(ctx, tx, e))
	require.NoError(t, deleteaudit.Append(ctx, tx, e), "identical EventID replay is idempotent")
	conflict := e
	conflict.OccurredAt = e.OccurredAt.Add(time.Second)
	require.ErrorIs(t, deleteaudit.Append(ctx, tx, conflict), deleteaudit.ErrConflict)
	require.NoError(t, tx.Commit())
	var count int
	require.NoError(t, db.QueryRowContext(ctx, `SELECT count(*) FROM service_delete_audit_events`).Scan(&count))
	require.Equal(t, 1, count)
	for _, q := range []string{`UPDATE service_delete_audit_events SET reason_code=reason_code`, `DELETE FROM service_delete_audit_events`, `TRUNCATE service_delete_audit_events`} {
		_, err := db.ExecContext(ctx, q)
		var pg *pgconn.PgError
		require.ErrorAs(t, err, &pg)
		require.Equal(t, "55000", pg.Code)
	}
	n, err = Down(ctx, uri, "global-root-create-audit")
	require.Error(t, err)
	require.Zero(t, n)
	n, err = Up(ctx, uri, "")
	require.NoError(t, err)
	require.Equal(t, len(Names())-295, n)
	require.NoError(t, VerifyAll(ctx, uri))
	require.NoError(t, db.QueryRowContext(ctx, `SELECT count(*) FROM service_delete_audit_events`).Scan(&count))
	require.Equal(t, 1, count)
}

func TestPostgresServiceDeleteAuditFreshAndInvalidEvents(t *testing.T) {
	ctx, uri, db := boundedAuditDB(t, len(Names()))
	require.NoError(t, VerifyAll(ctx, uri))
	require.NoError(t, VerifyIsLatest(ctx, uri))
	var persistence string
	var fks, publicGrants int
	require.NoError(t, db.QueryRowContext(ctx, `SELECT relpersistence FROM pg_class WHERE oid='service_delete_audit_events'::regclass`).Scan(&persistence))
	require.Equal(t, "p", persistence)
	require.NoError(t, db.QueryRowContext(ctx, `SELECT count(*) FROM pg_constraint WHERE contype='f' AND conrelid='service_delete_audit_events'::regclass`).Scan(&fks))
	require.Zero(t, fks)
	require.NoError(t, db.QueryRowContext(ctx, `SELECT count(*) FROM pg_class c,LATERAL aclexplode(c.relacl) a WHERE c.oid='service_delete_audit_events'::regclass AND a.grantee=0`).Scan(&publicGrants))
	require.Zero(t, publicGrants)
	e := serviceDeleteDBEvent()
	tx, err := db.BeginTx(ctx, nil)
	require.NoError(t, err)
	require.NoError(t, deleteaudit.Append(ctx, tx, e))
	require.NoError(t, tx.Commit())
	columns := []string{"schema_version", "event_id", "attempt_id", "request_id", "operation", "actor_kind", "actor_id", "home_organization_id", "authority_source", "authority_role", "organization_role", "service_id", "target_organization_id", "outcome", "reason_code", "occurred_at"}
	for name, overrides := range map[string]map[string]string{
		"version": {"schema_version": "2"}, "operation": {"operation": "'service.update'"},
		"nil event":     {"event_id": "'00000000-0000-0000-0000-000000000000'"},
		"nil attempt":   {"attempt_id": "'00000000-0000-0000-0000-000000000000'"},
		"nil request":   {"request_id": "'00000000-0000-0000-0000-000000000000'"},
		"nil actor":     {"actor_id": "'00000000-0000-0000-0000-000000000000'"},
		"missing actor": {"actor_id": "NULL"}, "missing home": {"home_organization_id": "NULL"},
		"unknown source": {"authority_source": "'client'"}, "machine": {"actor_kind": "'machine'"},
		"ordinary foreign": {"target_organization_id": "gen_random_uuid()"},
		"member committed": {"authority_role": "'org_member'", "organization_role": "'ORG_MEMBER'"},
		"default target":   {"target_organization_id": "'" + organization.DefaultOrganizationID + "'"},
		"unpaired target":  {"target_organization_id": "NULL"}, "unpaired service": {"service_id": "NULL"},
		"default mismatch":  {"home_organization_id": "'" + organization.DefaultOrganizationID + "'"},
		"false reason":      {"reason_code": "'commit_unconfirmed'"},
		"infinite time":     {"occurred_at": "'infinity'::timestamptz"},
		"unknown committed": {"actor_kind": "'unknown'", "actor_id": "NULL", "home_organization_id": "NULL", "authority_source": "'unknown'", "authority_role": "'unknown'", "organization_role": "'unknown'"},
	} {
		t.Run(name, func(t *testing.T) {
			expressions := append([]string(nil), columns...)
			for i, column := range columns {
				if column == "event_id" || column == "attempt_id" {
					expressions[i] = "gen_random_uuid()"
				}
				if value, ok := overrides[column]; ok {
					expressions[i] = value
				}
			}
			_, err := db.ExecContext(ctx, `INSERT INTO service_delete_audit_events (`+strings.Join(columns, ",")+`) SELECT `+strings.Join(expressions, ",")+` FROM service_delete_audit_events WHERE event_id=$1`, e.EventID)
			var pg *pgconn.PgError
			require.ErrorAs(t, err, &pg)
			require.Contains(t, []string{"23514", "23502"}, pg.Code)
		})
	}
	duplicate := e
	duplicate.EventID = uuid.New()
	tx, err = db.BeginTx(ctx, nil)
	require.NoError(t, err)
	require.ErrorIs(t, deleteaudit.Append(ctx, tx, duplicate), deleteaudit.ErrUnavailable, "one committed witness per distinct target per attempt")
	require.NoError(t, tx.Rollback())
	// Default PA is valid, Default ordinary is only valid as a failed observation.
	e.EventID, e.AttemptID = uuid.New(), uuid.New()
	e.HomeOrganizationID = uuid.MustParse(organization.DefaultOrganizationID)
	e.OrganizationRole, e.AuthorityRole = "NONE", "platform_admin"
	tx, err = db.BeginTx(ctx, nil)
	require.NoError(t, err)
	require.NoError(t, deleteaudit.Append(ctx, tx, e))
	require.NoError(t, tx.Commit())
	e.EventID, e.AttemptID = uuid.New(), uuid.New()
	e.AuthorityRole = "none"
	e.Outcome, e.Reason = "denied", "authority_denied"
	require.NoError(t, deleteaudit.RecordFailures(db, []deleteaudit.Event{e}))
	var count int
	require.NoError(t, db.QueryRowContext(ctx, `SELECT count(*) FROM service_delete_audit_events`).Scan(&count))
	require.Equal(t, 3, count)
}
