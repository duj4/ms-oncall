package migrate

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

const postgresIntegrationEnableEnv = "MS_ONCALL_CORE_MIGRATION_TEST_POSTGRES_ENABLE"

func TestPostgresFreshInstallCanonicalProvenance(t *testing.T) {
	baseURL := postgresIntegrationURL(t)
	testURL := newPostgresTestDatabase(t, baseURL)
	history, err := loadEmbeddedHistory()
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	count, err := Up(ctx, testURL, "")
	if err != nil {
		t.Fatal(err)
	}
	if count != len(history.entries) {
		t.Fatalf("applied migration count = %d, want %d", count, len(history.entries))
	}
	if err := VerifyAll(ctx, testURL); err != nil {
		t.Fatal(err)
	}
	if err := VerifyIsLatest(ctx, testURL); err != nil {
		t.Fatal(err)
	}

	conn, err := pgx.Connect(ctx, testURL)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(ctx)
	resolved, err := loadAppliedHistory(ctx, conn, history)
	if err != nil {
		t.Fatal(err)
	}
	if got := resolvedAppliedCount(resolved); got != len(history.entries) {
		t.Fatalf("resolved applied count = %d, want %d", got, len(history.entries))
	}
	var canonicalCount, legacyCount int
	if err := conn.QueryRow(ctx, `
		select
			count(*) filter (where record_origin = 'CANONICAL_EXECUTION'),
			count(*) filter (where record_origin = 'LEGACY_GORP_BOOTSTRAP')
		from ms_oncall_migration_provenance
	`).Scan(&canonicalCount, &legacyCount); err != nil {
		t.Fatal(err)
	}
	if canonicalCount != len(history.entries) || legacyCount != 0 {
		t.Fatalf("fresh provenance origins = canonical:%d legacy:%d, want canonical:%d legacy:0", canonicalCount, legacyCount, len(history.entries))
	}

	count, err = Up(ctx, testURL, "")
	if err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("second Up applied %d migrations, want 0", count)
	}
}

func TestPostgresLegacyBootstrapAndFoundationRollback(t *testing.T) {
	baseURL := postgresIntegrationURL(t)
	testURL := newPostgresTestDatabase(t, baseURL)
	history, err := loadEmbeddedHistory()
	if err != nil {
		t.Fatal(err)
	}
	legacyCount := history.provenanceStoreIndex

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	conn, err := pgx.Connect(ctx, testURL)
	if err != nil {
		t.Fatal(err)
	}
	if err := ensureMigrationTable(ctx, conn); err != nil {
		conn.Close(ctx)
		t.Fatal(err)
	}
	legacyAppliedAt := make(map[string]time.Time, legacyCount)
	for index, entry := range history.entries[:legacyCount] {
		appliedAt := time.Date(2020, time.January, 1, 0, 0, index, 0, time.UTC)
		legacyAppliedAt[entry.ID] = appliedAt
		if _, err := conn.Exec(ctx, `insert into gorp_migrations (id, applied_at) values ($1, $2)`, entry.ID, appliedAt); err != nil {
			conn.Close(ctx)
			t.Fatal(err)
		}
	}
	if err := conn.Close(ctx); err != nil {
		t.Fatal(err)
	}

	count, err := Up(ctx, testURL, "")
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("legacy continuation applied %d migrations, want 1", count)
	}
	assertLegacyBootstrapState(t, ctx, testURL, history, legacyAppliedAt)

	count, err = Up(ctx, testURL, "")
	if err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("second legacy continuation applied %d migrations, want 0", count)
	}

	target := history.entries[legacyCount-1].Name
	count, err = Down(ctx, testURL, target)
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("foundation rollback count = %d, want 1", count)
	}
	conn, err = pgx.Connect(ctx, testURL)
	if err != nil {
		t.Fatal(err)
	}
	var hasProvenance bool
	if err := conn.QueryRow(ctx, `select to_regclass(current_schema() || '.ms_oncall_migration_provenance') is not null`).Scan(&hasProvenance); err != nil {
		conn.Close(ctx)
		t.Fatal(err)
	}
	if hasProvenance {
		conn.Close(ctx)
		t.Fatal("provenance table still exists after foundation rollback")
	}
	var appliedCount int
	if err := conn.QueryRow(ctx, `select count(*) from gorp_migrations`).Scan(&appliedCount); err != nil {
		conn.Close(ctx)
		t.Fatal(err)
	}
	if appliedCount != legacyCount {
		conn.Close(ctx)
		t.Fatalf("gorp_migrations count after rollback = %d, want %d", appliedCount, legacyCount)
	}
	if err := conn.Close(ctx); err != nil {
		t.Fatal(err)
	}

	count, err = Up(ctx, testURL, "")
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("foundation reapplication count = %d, want 1", count)
	}
	assertLegacyBootstrapState(t, ctx, testURL, history, legacyAppliedAt)
}

func TestPostgresDownRejectsDivergentHistory(t *testing.T) {
	baseURL := postgresIntegrationURL(t)
	testURL := newPostgresTestDatabase(t, baseURL)
	history, err := loadEmbeddedHistory()
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	conn, err := pgx.Connect(ctx, testURL)
	if err != nil {
		t.Fatal(err)
	}
	if err := ensureMigrationTable(ctx, conn); err != nil {
		conn.Close(ctx)
		t.Fatal(err)
	}
	for _, index := range []int{0, 2} {
		if _, err := conn.Exec(ctx, `insert into gorp_migrations (id, applied_at) values ($1, now())`, history.entries[index].ID); err != nil {
			conn.Close(ctx)
			t.Fatal(err)
		}
	}
	if err := conn.Close(ctx); err != nil {
		t.Fatal(err)
	}

	_, err = Down(ctx, testURL, history.entries[0].Name)
	if err == nil || !strings.Contains(err.Error(), "history has a gap") {
		t.Fatalf("Down error = %v, want canonical history gap", err)
	}
}

func assertLegacyBootstrapState(t *testing.T, ctx context.Context, testURL string, history *canonicalHistory, legacyAppliedAt map[string]time.Time) {
	t.Helper()
	conn, err := pgx.Connect(ctx, testURL)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(ctx)
	resolved, err := loadAppliedHistory(ctx, conn, history)
	if err != nil {
		t.Fatal(err)
	}
	if got := resolvedAppliedCount(resolved); got != len(history.entries) {
		t.Fatalf("resolved applied count = %d, want %d", got, len(history.entries))
	}
	var legacyCount, canonicalCount int
	if err := conn.QueryRow(ctx, `
		select
			count(*) filter (where record_origin = 'LEGACY_GORP_BOOTSTRAP'),
			count(*) filter (where record_origin = 'CANONICAL_EXECUTION')
		from ms_oncall_migration_provenance
	`).Scan(&legacyCount, &canonicalCount); err != nil {
		t.Fatal(err)
	}
	if legacyCount != history.provenanceStoreIndex || canonicalCount != 1 {
		t.Fatalf("bootstrap provenance origins = legacy:%d canonical:%d, want legacy:%d canonical:1", legacyCount, canonicalCount, history.provenanceStoreIndex)
	}
	for id, want := range legacyAppliedAt {
		var got time.Time
		if err := conn.QueryRow(ctx, `select applied_at from gorp_migrations where id = $1`, id).Scan(&got); err != nil {
			t.Fatal(err)
		}
		if !got.Equal(want) {
			t.Fatalf("legacy gorp_migrations timestamp for %q changed from %s to %s", id, want, got)
		}
	}
}

func postgresIntegrationURL(t *testing.T) string {
	t.Helper()
	if os.Getenv(postgresIntegrationEnableEnv) != "1" {
		t.Skipf("set %s=1 to run PostgreSQL migration integration tests", postgresIntegrationEnableEnv)
	}
	value := os.Getenv("DB_URL")
	if value == "" {
		t.Fatal("DB_URL must be configured for PostgreSQL migration integration tests")
	}
	if _, err := url.Parse(value); err != nil {
		t.Fatalf("parse DB_URL: %v", err)
	}
	return value
}

func newPostgresTestDatabase(t *testing.T, baseURL string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	admin, err := pgx.Connect(ctx, baseURL)
	if err != nil {
		t.Fatalf("connect to PostgreSQL integration server: %v", err)
	}
	var random [4]byte
	if _, err := rand.Read(random[:]); err != nil {
		admin.Close(ctx)
		t.Fatal(err)
	}
	dbName := fmt.Sprintf("msoc_migrate_provenance_%d_%s", time.Now().Unix(), hex.EncodeToString(random[:]))
	quotedName := pgx.Identifier{dbName}.Sanitize()
	if _, err := admin.Exec(ctx, "create database "+quotedName); err != nil {
		admin.Close(ctx)
		t.Fatalf("create PostgreSQL integration database: %v", err)
	}
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cleanupCancel()
		cleanupConn, err := pgx.Connect(cleanupCtx, baseURL)
		if err != nil {
			t.Errorf("connect for PostgreSQL integration cleanup: %v", err)
			return
		}
		defer cleanupConn.Close(cleanupCtx)
		if _, err := cleanupConn.Exec(cleanupCtx, "drop database if exists "+quotedName+" with (force)"); err != nil {
			t.Errorf("drop PostgreSQL integration database: %v", err)
		}
	})
	if err := admin.Close(ctx); err != nil {
		t.Fatal(err)
	}

	parsed, err := url.Parse(baseURL)
	if err != nil {
		t.Fatal(err)
	}
	parsed.Path = "/" + dbName
	return parsed.String()
}
