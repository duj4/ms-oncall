package migrate

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
	pgdump "github.com/target/goalert/devtools/pgdump-lite"
)

func TestServiceUpdateAuditCanonicalBundle(t *testing.T) {
	h, err := loadEmbeddedHistory()
	require.NoError(t, err)
	require.Len(t, h.entries, 290)
	e := h.latest()
	require.EqualValues(t, 290, e.Position)
	require.Equal(t, "20261103125657-service-update-audit.sql", e.ID)
	require.Equal(t, "MS_ONCALL", e.Provenance)
	require.Equal(t, h.entries[288].ID, e.PredecessorID)
}

func TestPostgresServiceUpdateAuditMigration(t *testing.T) {
	baseURL := postgresIntegrationURL(t)
	testURL := newPostgresTestDatabase(t, baseURL)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	h, err := loadEmbeddedHistory()
	require.NoError(t, err)
	n, err := Up(ctx, testURL, h.entries[288].Name)
	require.NoError(t, err)
	require.Equal(t, 289, n)
	conn, err := pgx.Connect(ctx, testURL)
	require.NoError(t, err)
	defer conn.Close(ctx)
	var prior int
	require.NoError(t, conn.QueryRow(ctx, `SELECT count(*) FROM ms_oncall_migration_provenance`).Scan(&prior))
	require.Equal(t, 289, prior)
	n, err = Up(ctx, testURL, "")
	require.NoError(t, err)
	require.Equal(t, 1, n)
	n, err = Up(ctx, testURL, "")
	require.NoError(t, err)
	require.Zero(t, n)
	require.NoError(t, VerifyAll(ctx, testURL))
	require.NoError(t, VerifyIsLatest(ctx, testURL))
	var persistence string
	require.NoError(t, conn.QueryRow(ctx, `SELECT relpersistence FROM pg_class WHERE oid='service_update_audit_events'::regclass`).Scan(&persistence))
	require.Equal(t, "p", persistence)
	var version string
	require.NoError(t, conn.QueryRow(ctx, `SHOW server_version`).Scan(&version))
	t.Log("real PostgreSQL", version)
	n, err = Down(ctx, testURL, h.entries[288].Name)
	require.Error(t, err)
	require.Zero(t, n)
	var pg *pgconn.PgError
	require.ErrorAs(t, err, &pg)
	require.Equal(t, "55000", pg.Code)
	require.NoError(t, VerifyAll(ctx, testURL))
	require.NoError(t, VerifyIsLatest(ctx, testURL))
	var after int
	require.NoError(t, conn.QueryRow(ctx, `SELECT count(*) FROM ms_oncall_migration_provenance`).Scan(&after))
	require.Equal(t, 290, after)
	if path := os.Getenv("SERVICE_UPDATE_AUDIT_SCHEMA"); path != "" {
		schema, err := pgdump.DumpSchema(ctx, conn)
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(path, []byte("--\n-- pgdump-lite database dump\n--\n\n"+schema.String()), 0600))
	}
	t.Log("289 -> 290, repeat no-op, logged storage, provenance and fail-closed Down verified")
}
