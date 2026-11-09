package migrate

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
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
	require.GreaterOrEqual(t, len(h.entries), 294)
	// Pin the entire exact original manifest, not merely its entry count.
	marker := []byte(",\n    {\n      \"id\": \"ms-oncall-schedule-rotation-update-audit-d09-c4\",")
	i := bytes.Index(h.manifest, marker)
	require.Positive(t, i)
	prefix := append(append([]byte(nil), h.manifest[:i]...), []byte("\n  ]\n}\n")...)
	require.Equal(t, "175dd15fc52e4c1fbf6cd4e551523eff9218030d1bcbd2caa6eab6059b1a895e", fmt.Sprintf("%x", sha256.Sum256(prefix)))
	e := h.entries[289]
	require.EqualValues(t, 290, e.Position)
	require.Equal(t, "20261103125657-service-update-audit.sql", e.ID)
	require.Equal(t, "MS_ONCALL", e.Provenance)
	require.Equal(t, "11d7032837f206adb04888835782ac14c1aa4be582f0f92a8fa69d0e633aa165", e.SHA256)
	raw, err := migrationFS.ReadFile("migrations/" + e.ID)
	require.NoError(t, err)
	require.Equal(t, e.SHA256, fmt.Sprintf("%x", sha256.Sum256(raw)))
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
	// Keep the original 289 -> explicit 290 leg independently exercised.
	n, err = Up(ctx, testURL, h.entries[289].Name)
	require.NoError(t, err)
	require.Equal(t, 1, n)
	var at290 int
	require.NoError(t, conn.QueryRow(ctx, `SELECT count(*) FROM ms_oncall_migration_provenance`).Scan(&at290))
	require.Equal(t, 290, at290)
	n, err = Down(ctx, testURL, h.entries[288].Name)
	require.Error(t, err)
	require.Zero(t, n)
	var originalDown *pgconn.PgError
	require.ErrorAs(t, err, &originalDown)
	require.Equal(t, "55000", originalDown.Code)
	n, err = Up(ctx, testURL, h.entries[289].Name)
	require.NoError(t, err)
	require.Zero(t, n)
	n, err = Up(ctx, testURL, "")
	require.NoError(t, err)
	require.Equal(t, len(h.entries)-290, n)
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
	require.Equal(t, len(h.entries), after)
	if path := os.Getenv("SERVICE_UPDATE_AUDIT_SCHEMA"); path != "" {
		schema, err := pgdump.DumpSchema(ctx, conn)
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(path, []byte("--\n-- pgdump-lite database dump\n--\n\n"+schema.String()), 0600))
	}
	t.Log("289 -> explicit 290 -> latest, repeat no-op, logged storage, provenance and fail-closed Down verified")
}
