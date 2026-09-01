package migrate

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

const postgresIntegrationEnableEnv = "MS_ONCALL_CORE_MIGRATION_TEST_POSTGRES_ENABLE"

const (
	postgresTestDatabaseCleanupTimeout      = 30 * time.Second
	postgresTestDatabaseCleanupPollInterval = 25 * time.Millisecond
)

func TestPostgresInterruptedFreshInstallDeterministicProvenance(t *testing.T) {
	baseURL := postgresIntegrationURL(t)
	history, err := loadEmbeddedHistory()
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()
	interruptionPoints := []struct {
		name   string
		prefix int
	}{
		{name: "zero historical migrations", prefix: 0},
		{name: "middle historical prefix", prefix: history.provenanceFoundationIndex / 2},
		{name: "immediately before Foundation", prefix: history.provenanceFoundationIndex},
	}
	var uninterrupted []provenanceSemanticRecord
	for _, point := range interruptionPoints {
		t.Run(point.name, func(t *testing.T) {
			testURL := newPostgresTestDatabase(t, baseURL)
			if point.prefix > 0 {
				count, err := Up(ctx, testURL, history.entries[point.prefix-1].Name)
				if err != nil {
					t.Fatal(err)
				}
				if count != point.prefix {
					t.Fatalf("initial prefix applied %d migrations, want %d", count, point.prefix)
				}
			}
			assertProvenanceTableAbsent(t, ctx, testURL)

			count, err := Up(ctx, testURL, "")
			if err != nil {
				t.Fatal(err)
			}
			if count != len(history.entries)-point.prefix {
				t.Fatalf("resumed Up applied %d migrations, want %d", count, len(history.entries)-point.prefix)
			}
			got := assertDeterministicProvenanceState(t, ctx, testURL, history)
			if err := VerifyAll(ctx, testURL); err != nil {
				t.Fatal(err)
			}
			if err := VerifyIsLatest(ctx, testURL); err != nil {
				t.Fatal(err)
			}
			if uninterrupted == nil {
				uninterrupted = append([]provenanceSemanticRecord(nil), got...)
			} else if !slices.Equal(got, uninterrupted) {
				t.Fatal("immutable provenance semantics depend on fresh-install interruption point")
			}

			count, err = Up(ctx, testURL, "")
			if err != nil {
				t.Fatal(err)
			}
			if count != 0 {
				t.Fatalf("second complete Up applied %d migrations, want 0", count)
			}
		})
	}
}

func TestPostgresExistingPreFoundationDatabaseBootstrapsDeterministically(t *testing.T) {
	baseURL := postgresIntegrationURL(t)
	testURL := newPostgresTestDatabase(t, baseURL)
	history, err := loadEmbeddedHistory()
	if err != nil {
		t.Fatal(err)
	}
	preLedgerCount := history.provenanceFoundationIndex

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	count, err := Up(ctx, testURL, history.entries[preLedgerCount-1].Name)
	if err != nil {
		t.Fatal(err)
	}
	if count != preLedgerCount {
		t.Fatalf("existing pre-Foundation schema setup applied %d migrations, want %d", count, preLedgerCount)
	}
	assertProvenanceTableAbsent(t, ctx, testURL)

	conn, err := pgx.Connect(ctx, testURL)
	if err != nil {
		t.Fatal(err)
	}
	preLedgerAppliedAt := make(map[string]time.Time, preLedgerCount)
	for index, entry := range history.entries[:preLedgerCount] {
		appliedAt := time.Date(2020, time.January, 1, 0, 0, index, 0, time.UTC)
		preLedgerAppliedAt[entry.ID] = appliedAt
		if _, err := conn.Exec(ctx, `update gorp_migrations set applied_at = $2 where id = $1`, entry.ID, appliedAt); err != nil {
			conn.Close(ctx)
			t.Fatal(err)
		}
	}
	if err := conn.Close(ctx); err != nil {
		t.Fatal(err)
	}

	count, err = Up(ctx, testURL, "")
	if err != nil {
		t.Fatal(err)
	}
	wantContinuation := len(history.entries) - preLedgerCount
	if count != wantContinuation {
		t.Fatalf("existing-database continuation applied %d migrations, want %d", count, wantContinuation)
	}
	assertDeterministicProvenanceState(t, ctx, testURL, history)
	assertAppliedTimes(t, ctx, testURL, preLedgerAppliedAt)

	count, err = Up(ctx, testURL, "")
	if err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("second existing-database continuation applied %d migrations, want 0", count)
	}
}

func TestPostgresFoundationRollbackReapplyPreservesProvenance(t *testing.T) {
	baseURL := postgresIntegrationURL(t)
	testURL := newPostgresTestDatabase(t, baseURL)
	history, err := loadEmbeddedHistory()
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	if _, err := Up(ctx, testURL, ""); err != nil {
		t.Fatal(err)
	}
	before := assertDeterministicProvenanceState(t, ctx, testURL, history)
	historicalAppliedAt := readAppliedTimes(t, ctx, testURL, history.entries[:history.provenanceFoundationIndex])

	target := history.entries[history.provenanceFoundationIndex-1].Name
	count, err := Down(ctx, testURL, target)
	if err != nil {
		t.Fatal(err)
	}
	wantRollback := len(history.entries) - history.provenanceFoundationIndex
	if count != wantRollback {
		t.Fatalf("Foundation-plus-tail rollback count = %d, want %d", count, wantRollback)
	}
	conn, err := pgx.Connect(ctx, testURL)
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
	if appliedCount != history.provenanceFoundationIndex {
		conn.Close(ctx)
		t.Fatalf("gorp_migrations count after rollback = %d, want %d", appliedCount, history.provenanceFoundationIndex)
	}
	if err := conn.Close(ctx); err != nil {
		t.Fatal(err)
	}

	count, err = Up(ctx, testURL, "")
	if err != nil {
		t.Fatal(err)
	}
	if count != wantRollback {
		t.Fatalf("Foundation-plus-tail reapplication count = %d, want %d", count, wantRollback)
	}
	after := assertDeterministicProvenanceState(t, ctx, testURL, history)
	if !slices.Equal(after, before) {
		t.Fatal("Foundation rollback/reapply changed immutable provenance semantics")
	}
	assertAppliedTimes(t, ctx, testURL, historicalAppliedAt)
}

func TestPostgresFoundationInterruptionRollsBackAtomically(t *testing.T) {
	baseURL := postgresIntegrationURL(t)
	testURL := newPostgresTestDatabase(t, baseURL)
	history, err := loadEmbeddedHistory()
	if err != nil {
		t.Fatal(err)
	}
	migrations, err := parseMigrations(history)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	count, err := Up(ctx, testURL, history.entries[history.provenanceFoundationIndex-1].Name)
	if err != nil {
		t.Fatal(err)
	}
	if count != history.provenanceFoundationIndex {
		t.Fatalf("pre-Foundation Up applied %d migrations, want %d", count, history.provenanceFoundationIndex)
	}

	conn, err := pgx.Connect(ctx, testURL)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Begin(ctx); err != nil {
		conn.Close(ctx)
		t.Fatal(err)
	}
	foundation := migrations[history.provenanceFoundationIndex]
	for _, stmt := range foundation.Up.statements {
		if _, err := conn.Exec(ctx, stmt); err != nil {
			conn.Close(ctx)
			t.Fatal(err)
		}
	}
	if _, err := conn.Exec(ctx, insertMigrationRecord, foundation.ID); err != nil {
		conn.Close(ctx)
		t.Fatal(err)
	}
	applied, err := readAppliedMigrationRecords(ctx, conn)
	if err != nil {
		conn.Close(ctx)
		t.Fatal(err)
	}
	_, appliedByID, err := validateAppliedPrefix(history, applied)
	if err != nil {
		conn.Close(ctx)
		t.Fatal(err)
	}
	partialCount := history.provenanceFoundationIndex / 2
	for index := 0; index < partialCount; index++ {
		origin, err := expectedRecordOrigin(history, index)
		if err != nil {
			conn.Close(ctx)
			t.Fatal(err)
		}
		entry := history.entries[index]
		if err := insertAppliedProvenance(ctx, conn, entry, appliedByID[entry.ID].AppliedAt, origin); err != nil {
			conn.Close(ctx)
			t.Fatal(err)
		}
	}
	// Closing the connection with the transaction open models a process/connection
	// interruption after Foundation DDL and a partial ledger bootstrap but before commit.
	if err := conn.Close(ctx); err != nil {
		t.Fatal(err)
	}

	assertProvenanceTableAbsent(t, ctx, testURL)
	conn, err = pgx.Connect(ctx, testURL)
	if err != nil {
		t.Fatal(err)
	}
	var appliedCount int
	if err := conn.QueryRow(ctx, `select count(*) from gorp_migrations`).Scan(&appliedCount); err != nil {
		conn.Close(ctx)
		t.Fatal(err)
	}
	if err := conn.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if appliedCount != history.provenanceFoundationIndex {
		t.Fatalf("applied count after interrupted Foundation = %d, want %d", appliedCount, history.provenanceFoundationIndex)
	}

	count, err = Up(ctx, testURL, "")
	if err != nil {
		t.Fatal(err)
	}
	wantRecovery := len(history.entries) - history.provenanceFoundationIndex
	if count != wantRecovery {
		t.Fatalf("Foundation recovery plus canonical tail applied %d migrations, want %d", count, wantRecovery)
	}
	assertDeterministicProvenanceState(t, ctx, testURL, history)
}

func TestPostgresUnsupportedPartialLedgerFailsClosed(t *testing.T) {
	baseURL := postgresIntegrationURL(t)
	testURL := newPostgresTestDatabase(t, baseURL)
	history, err := loadEmbeddedHistory()
	if err != nil {
		t.Fatal(err)
	}
	migrations, err := parseMigrations(history)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	if _, err := Up(ctx, testURL, history.entries[history.provenanceFoundationIndex-1].Name); err != nil {
		t.Fatal(err)
	}
	conn, err := pgx.Connect(ctx, testURL)
	if err != nil {
		t.Fatal(err)
	}
	foundation := migrations[history.provenanceFoundationIndex]
	for _, stmt := range foundation.Up.statements {
		if _, err := conn.Exec(ctx, stmt); err != nil {
			conn.Close(ctx)
			t.Fatal(err)
		}
	}
	var appliedAt sql.NullTime
	first := history.entries[0]
	if err := conn.QueryRow(ctx, `select applied_at from gorp_migrations where id = $1`, first.ID).Scan(&appliedAt); err != nil {
		conn.Close(ctx)
		t.Fatal(err)
	}
	if err := insertAppliedProvenance(ctx, conn, first, appliedAt, recordOriginPreLedgerBootstrap); err != nil {
		conn.Close(ctx)
		t.Fatal(err)
	}
	if err := conn.Close(ctx); err != nil {
		t.Fatal(err)
	}

	_, err = Up(ctx, testURL, "")
	if err == nil || !strings.Contains(err.Error(), "provenance table exists before canonical migration") {
		t.Fatalf("Up error = %v, want fail-closed partial-ledger error", err)
	}
}

func TestPostgresProvenanceOriginAndLedgerCorruptionFailClosed(t *testing.T) {
	baseURL := postgresIntegrationURL(t)
	testURL := newPostgresTestDatabase(t, baseURL)
	history, err := loadEmbeddedHistory()
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	if _, err := Up(ctx, testURL, ""); err != nil {
		t.Fatal(err)
	}
	conn, err := pgx.Connect(ctx, testURL)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(ctx)
	upstreamSourceBinding := history.entries[0].SourceBinding
	msOnCallSourceBinding := history.entries[history.provenanceFoundationIndex].SourceBinding

	tests := []struct {
		name    string
		mutate  func(context.Context, *pgx.Conn) error
		wantErr string
	}{
		{
			name: "pre-ledger origin changed to canonical execution",
			mutate: func(ctx context.Context, conn *pgx.Conn) error {
				_, err := conn.Exec(ctx, `update ms_oncall_migration_provenance set record_origin = $1 where migration_id = $2`, recordOriginCanonical, history.entries[0].ID)
				return err
			},
			wantErr: "field record_origin",
		},
		{
			name: "Foundation origin changed to pre-ledger bootstrap",
			mutate: func(ctx context.Context, conn *pgx.Conn) error {
				_, err := conn.Exec(ctx, `update ms_oncall_migration_provenance set record_origin = $1 where migration_id = $2`, recordOriginPreLedgerBootstrap, history.entries[history.provenanceFoundationIndex].ID)
				return err
			},
			wantErr: "field record_origin",
		},
		{
			name: "invalid origin enum",
			mutate: func(ctx context.Context, conn *pgx.Conn) error {
				if _, err := conn.Exec(ctx, `alter table ms_oncall_migration_provenance drop constraint ms_oncall_migration_provenance_record_origin_check`); err != nil {
					return err
				}
				_, err := conn.Exec(ctx, `update ms_oncall_migration_provenance set record_origin = 'UNKNOWN' where migration_id = $1`, history.entries[0].ID)
				return err
			},
			wantErr: "field record_origin",
		},
		{
			name: "upstream provenance paired with MS OnCall source",
			mutate: func(ctx context.Context, conn *pgx.Conn) error {
				_, err := conn.Exec(ctx, `update ms_oncall_migration_provenance set source_binding = $1 where migration_id = $2`, msOnCallSourceBinding, history.entries[0].ID)
				return err
			},
			wantErr: "incompatible provenance/source kind pairing",
		},
		{
			name: "MS OnCall provenance paired with upstream source",
			mutate: func(ctx context.Context, conn *pgx.Conn) error {
				_, err := conn.Exec(ctx, `update ms_oncall_migration_provenance set source_binding = $1 where migration_id = $2`, upstreamSourceBinding, history.entries[history.provenanceFoundationIndex].ID)
				return err
			},
			wantErr: "incompatible provenance/source kind pairing",
		},
		{
			name: "partial ledger",
			mutate: func(ctx context.Context, conn *pgx.Conn) error {
				_, err := conn.Exec(ctx, `truncate ms_oncall_migration_provenance`)
				return err
			},
			wantErr: "provenance count",
		},
		{
			name: "Foundation provenance missing",
			mutate: func(ctx context.Context, conn *pgx.Conn) error {
				_, err := conn.Exec(ctx, `
					delete from ms_oncall_migration_provenance
					where canonical_position >= $1
				`, history.entries[history.provenanceFoundationIndex].Position)
				return err
			},
			wantErr: "provenance count",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			tx, err := conn.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if mutationErr := test.mutate(ctx, conn); mutationErr != nil {
				if rollbackErr := tx.Rollback(ctx); rollbackErr != nil {
					t.Fatalf("mutate provenance: %v; roll back mutation: %v", mutationErr, rollbackErr)
				}
				t.Fatal(mutationErr)
			}
			_, err = loadAppliedHistory(ctx, conn, history)
			if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				if rollbackErr := tx.Rollback(ctx); rollbackErr != nil {
					t.Fatalf("unexpected validation result %v; roll back mutation: %v", err, rollbackErr)
				}
				t.Fatalf("loadAppliedHistory error = %v, want containing %q", err, test.wantErr)
			}
			if err := tx.Rollback(ctx); err != nil {
				t.Fatal(err)
			}
			if _, err := loadAppliedHistory(ctx, conn, history); err != nil {
				t.Fatalf("valid provenance did not recover after rollback: %v", err)
			}
		})
	}

	if _, err := conn.Exec(ctx, `drop table ms_oncall_migration_provenance`); err != nil {
		t.Fatal(err)
	}
	if err := VerifyAll(ctx, testURL); err == nil || !strings.Contains(err.Error(), "provenance table is missing") {
		t.Fatalf("VerifyAll error = %v, want missing-ledger failure", err)
	}
}

func TestPostgresFutureBundleOriginIntegrityFailsClosed(t *testing.T) {
	baseURL := postgresIntegrationURL(t)
	testURL := newPostgresTestDatabase(t, baseURL)
	history, err := loadEmbeddedHistory()
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	if _, err := Up(ctx, testURL, ""); err != nil {
		t.Fatal(err)
	}

	futureHistory := &canonicalHistory{
		entries:                   append([]canonicalMigration(nil), history.entries...),
		byID:                      make(map[string]int, len(history.byID)+1),
		byName:                    make(map[string]int, len(history.byName)+1),
		provenanceFoundationIndex: history.provenanceFoundationIndex,
		manifest:                  append([]byte(nil), history.manifest...),
	}
	for id, index := range history.byID {
		futureHistory.byID[id] = index
	}
	for name, index := range history.byName {
		futureHistory.byName[name] = index
	}
	predecessor := history.latest()
	futureID := "20990101000000-ms-oncall-future-origin-integrity.sql"
	futureName, err := migrationNameFromID(futureID)
	if err != nil {
		t.Fatal(err)
	}
	futureSourceBinding := mustTestSourceBinding(t, historySourceSpec{
		Kind:                    sourceKindMSOnCallBase,
		Repository:              "https://example.invalid/ms-oncall",
		Checkpoint:              "future-origin-integrity-test",
		BaseCommit:              strings.Repeat("1", 40),
		BaseTree:                strings.Repeat("2", 40),
		AuthorizationRepository: "https://example.invalid/ms-oncall-project",
		AuthorizationCommit:     strings.Repeat("3", 40),
		AuthorizationTree:       strings.Repeat("4", 40),
	})
	future := canonicalMigration{
		Position:           predecessor.Position + 1,
		ID:                 futureID,
		Name:               futureName,
		Provenance:         provenanceMSOnCall,
		OriginalID:         futureID,
		SHA256:             strings.Repeat("a", 64),
		SourceBinding:      futureSourceBinding,
		BundleID:           "ms-oncall-test-future-origin-integrity",
		PredecessorID:      predecessor.ID,
		DependencyEvidence: fmt.Sprintf("BUNDLE_DEPENDENCY|bundle=%s|id=%s|sha256=%s|evidence=TEST_FUTURE_APPEND", predecessor.BundleID, predecessor.ID, predecessor.SHA256),
		AdaptationEvidence: "NOT_APPLICABLE_TEST_FUTURE_ORIGIN_INTEGRITY",
	}
	futureHistory.byID[future.ID] = len(futureHistory.entries)
	futureHistory.byName[future.Name] = len(futureHistory.entries)
	futureHistory.entries = append(futureHistory.entries, future)

	conn, err := pgx.Connect(ctx, testURL)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(ctx)
	if _, err := conn.Exec(ctx, insertMigrationRecord, future.ID); err != nil {
		t.Fatal(err)
	}
	var appliedAt sql.NullTime
	if err := conn.QueryRow(ctx, `select applied_at from gorp_migrations where id = $1`, future.ID).Scan(&appliedAt); err != nil {
		t.Fatal(err)
	}
	if err := insertAppliedProvenance(ctx, conn, future, appliedAt, recordOriginCanonical); err != nil {
		t.Fatal(err)
	}
	resolved, err := loadAppliedHistory(ctx, conn, futureHistory)
	if err != nil {
		t.Fatal(err)
	}
	if got := resolvedAppliedCount(resolved); got != len(futureHistory.entries) {
		t.Fatalf("resolved future-bundle applied count = %d, want %d", got, len(futureHistory.entries))
	}

	if _, err := conn.Exec(ctx, `update ms_oncall_migration_provenance set record_origin = $1 where migration_id = $2`, recordOriginPreLedgerBootstrap, future.ID); err != nil {
		t.Fatal(err)
	}
	_, err = loadAppliedHistory(ctx, conn, futureHistory)
	if err == nil || !strings.Contains(err.Error(), "field record_origin") || !strings.Contains(err.Error(), "expected CANONICAL_EXECUTION") {
		t.Fatalf("loadAppliedHistory future-bundle error = %v, want canonical-origin mismatch", err)
	}
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

func TestPostgresOrganizationPersistenceFreshAndFoundationUpgrade(t *testing.T) {
	baseURL := postgresIntegrationURL(t)
	history, err := loadEmbeddedHistory()
	if err != nil {
		t.Fatal(err)
	}
	foundation := history.entries[history.provenanceFoundationIndex]
	organizationFoundation := history.entries[len(history.entries)-2]
	if organizationFoundation.Position != 276 || organizationFoundation.ID != "20260901100808-ms-oncall-organization-persistence.sql" {
		t.Fatalf("unexpected Organization persistence entry: %#v", organizationFoundation)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()
	freshURL := newPostgresTestDatabase(t, baseURL)
	if count, err := Up(ctx, freshURL, ""); err != nil {
		t.Fatal(err)
	} else if count != len(history.entries) {
		t.Fatalf("fresh install applied %d migrations, want %d", count, len(history.entries))
	}
	freshDefault := readDefaultOrganizationIdentity(t, ctx, freshURL)
	assertOrganizationPersistenceProvenance(t, ctx, freshURL, organizationFoundation)

	upgradeURL := newPostgresTestDatabase(t, baseURL)
	if count, err := Up(ctx, upgradeURL, foundation.Name); err != nil {
		t.Fatal(err)
	} else if count != history.provenanceFoundationIndex+1 {
		t.Fatalf("Foundation-only setup applied %d migrations, want %d", count, history.provenanceFoundationIndex+1)
	}
	assertOrganizationTablesAbsent(t, ctx, upgradeURL)
	if count, err := Up(ctx, upgradeURL, ""); err != nil {
		t.Fatal(err)
	} else if count != 2 {
		t.Fatalf("Foundation-only upgrade applied %d migrations, want 2", count)
	}
	upgradeDefault := readDefaultOrganizationIdentity(t, ctx, upgradeURL)
	assertOrganizationPersistenceProvenance(t, ctx, upgradeURL, organizationFoundation)

	if freshDefault != upgradeDefault {
		t.Fatalf("fresh and Foundation upgrade produced different Default identity: fresh=%#v upgrade=%#v", freshDefault, upgradeDefault)
	}
	if freshDefault.ID != "296e2656-7221-53fe-bd0a-832d24ccfd03" ||
		freshDefault.CanonicalName != "ms-oncall.default" ||
		freshDefault.Classification != "DEFAULT" || freshDefault.DisplayName != "Default Organization" ||
		freshDefault.Lifecycle != "ACTIVE" {
		t.Fatalf("unexpected deterministic Default identity: %#v", freshDefault)
	}
}

func TestPostgresOrganizationPersistenceRollbackReapply(t *testing.T) {
	baseURL := postgresIntegrationURL(t)
	testURL := newPostgresTestDatabase(t, baseURL)
	history, err := loadEmbeddedHistory()
	if err != nil {
		t.Fatal(err)
	}
	foundation := history.entries[history.provenanceFoundationIndex]
	organizationFoundation := history.entries[len(history.entries)-2]
	latest := history.latest()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	if _, err := Up(ctx, testURL, ""); err != nil {
		t.Fatal(err)
	}
	before := readDefaultOrganizationIdentity(t, ctx, testURL)
	if count, err := Down(ctx, testURL, foundation.Name); err != nil {
		t.Fatal(err)
	} else if count != 2 {
		t.Fatalf("Organization persistence rollback count = %d, want 2", count)
	}
	assertOrganizationTablesAbsent(t, ctx, testURL)

	conn, err := pgx.Connect(ctx, testURL)
	if err != nil {
		t.Fatal(err)
	}
	var latestMigrationCount, latestProvenanceCount int
	if err := conn.QueryRow(ctx, `select count(*) from gorp_migrations where id = $1`, latest.ID).Scan(&latestMigrationCount); err != nil {
		conn.Close(ctx)
		t.Fatal(err)
	}
	if err := conn.QueryRow(ctx, `select count(*) from ms_oncall_migration_provenance where migration_id = $1`, latest.ID).Scan(&latestProvenanceCount); err != nil {
		conn.Close(ctx)
		t.Fatal(err)
	}
	if err := conn.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if latestMigrationCount != 0 || latestProvenanceCount != 0 {
		t.Fatalf("rollback left migration/provenance rows: %d/%d", latestMigrationCount, latestProvenanceCount)
	}

	if count, err := Up(ctx, testURL, ""); err != nil {
		t.Fatal(err)
	} else if count != 2 {
		t.Fatalf("Organization persistence reapply count = %d, want 2", count)
	}
	after := readDefaultOrganizationIdentity(t, ctx, testURL)
	if after != before {
		t.Fatalf("Organization persistence rollback/reapply changed Default identity: before=%#v after=%#v", before, after)
	}
	assertOrganizationPersistenceProvenance(t, ctx, testURL, organizationFoundation)
}

func TestPostgresOrganizationPersistenceRejectsPartialSchema(t *testing.T) {
	baseURL := postgresIntegrationURL(t)
	testURL := newPostgresTestDatabase(t, baseURL)
	history, err := loadEmbeddedHistory()
	if err != nil {
		t.Fatal(err)
	}
	foundation := history.entries[history.provenanceFoundationIndex]
	organizationFoundation := history.entries[len(history.entries)-2]

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	if _, err := Up(ctx, testURL, foundation.Name); err != nil {
		t.Fatal(err)
	}
	conn, err := pgx.Connect(ctx, testURL)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(ctx, `create table organizations (partial_state_marker text not null)`); err != nil {
		conn.Close(ctx)
		t.Fatal(err)
	}
	if _, err := conn.Exec(ctx, `insert into organizations (partial_state_marker) values ('preserve-me')`); err != nil {
		conn.Close(ctx)
		t.Fatal(err)
	}
	if err := conn.Close(ctx); err != nil {
		t.Fatal(err)
	}

	if _, err := Up(ctx, testURL, ""); err == nil || !strings.Contains(err.Error(), `relation "organizations" already exists`) {
		t.Fatalf("partial-schema Up error = %v, want fail-closed existing-relation error", err)
	}
	conn, err = pgx.Connect(ctx, testURL)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(ctx)
	var marker string
	if err := conn.QueryRow(ctx, `select partial_state_marker from organizations`).Scan(&marker); err != nil {
		t.Fatal(err)
	}
	if marker != "preserve-me" {
		t.Fatalf("partial state was rewritten to %q", marker)
	}
	var migrationCount, provenanceCount int
	if err := conn.QueryRow(ctx, `select count(*) from gorp_migrations where id = $1`, organizationFoundation.ID).Scan(&migrationCount); err != nil {
		t.Fatal(err)
	}
	if err := conn.QueryRow(ctx, `select count(*) from ms_oncall_migration_provenance where migration_id = $1`, organizationFoundation.ID).Scan(&provenanceCount); err != nil {
		t.Fatal(err)
	}
	if migrationCount != 0 || provenanceCount != 0 {
		t.Fatalf("failed partial-schema migration recorded execution/provenance: %d/%d", migrationCount, provenanceCount)
	}
	var classificationTypeExists bool
	if err := conn.QueryRow(ctx, `select to_regtype('ms_oncall_organization_classification') is not null`).Scan(&classificationTypeExists); err != nil {
		t.Fatal(err)
	}
	if classificationTypeExists {
		t.Fatal("failed partial-schema migration left its enum type behind")
	}
}

func TestPostgresUserOrganizationAssignmentFreshUpgradeRollbackReapply(t *testing.T) {
	baseURL := postgresIntegrationURL(t)
	history, err := loadEmbeddedHistory()
	if err != nil {
		t.Fatal(err)
	}
	organizationFoundation := history.entries[len(history.entries)-2]
	latest := history.latest()
	if organizationFoundation.Position != 276 ||
		organizationFoundation.ID != "20260901100808-ms-oncall-organization-persistence.sql" ||
		latest.Position != 277 ||
		latest.ID != "20260901220323-ms-oncall-user-organization-assignment-persistence.sql" {
		t.Fatalf("unexpected assignment migration boundary: predecessor=%#v latest=%#v", organizationFoundation, latest)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()

	freshURL := newPostgresTestDatabase(t, baseURL)
	if count, err := Up(ctx, freshURL, ""); err != nil {
		t.Fatal(err)
	} else if count != len(history.entries) {
		t.Fatalf("fresh install applied %d migrations, want %d", count, len(history.entries))
	}
	assertUserOrganizationAssignmentTable(t, ctx, freshURL, true, 0)
	assertAssignmentPersistenceProvenance(t, ctx, freshURL, latest)

	upgradeURL := newPostgresTestDatabase(t, baseURL)
	if count, err := Up(ctx, upgradeURL, organizationFoundation.Name); err != nil {
		t.Fatal(err)
	} else if count != int(organizationFoundation.Position) {
		t.Fatalf("position-276 setup applied %d migrations, want %d", count, organizationFoundation.Position)
	}
	assertUserOrganizationAssignmentTable(t, ctx, upgradeURL, false, 0)

	conn, err := pgx.Connect(ctx, upgradeURL)
	if err != nil {
		t.Fatal(err)
	}
	existingUserID := uuid.New()
	if _, err := conn.Exec(ctx, `
		INSERT INTO public.users (id, name, email)
		VALUES ($1, 'Existing User', 'existing-user@example.invalid')
	`, existingUserID); err != nil {
		conn.Close(ctx)
		t.Fatal(err)
	}
	if err := conn.Close(ctx); err != nil {
		t.Fatal(err)
	}

	if count, err := Up(ctx, upgradeURL, ""); err != nil {
		t.Fatal(err)
	} else if count != 1 {
		t.Fatalf("position-276 upgrade applied %d migrations, want 1", count)
	}
	assertUserOrganizationAssignmentTable(t, ctx, upgradeURL, true, 0)
	assertAssignmentPersistenceProvenance(t, ctx, upgradeURL, latest)

	conn, err = pgx.Connect(ctx, upgradeURL)
	if err != nil {
		t.Fatal(err)
	}
	var existingUserCount int
	if err := conn.QueryRow(ctx, `SELECT count(*) FROM public.users WHERE id = $1`, existingUserID).Scan(&existingUserCount); err != nil {
		conn.Close(ctx)
		t.Fatal(err)
	}
	if err := conn.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if existingUserCount != 1 {
		t.Fatalf("position-276 upgrade changed existing User count to %d", existingUserCount)
	}

	if count, err := Down(ctx, upgradeURL, organizationFoundation.Name); err != nil {
		t.Fatal(err)
	} else if count != 1 {
		t.Fatalf("assignment rollback count = %d, want 1", count)
	}
	assertUserOrganizationAssignmentTable(t, ctx, upgradeURL, false, 0)

	conn, err = pgx.Connect(ctx, upgradeURL)
	if err != nil {
		t.Fatal(err)
	}
	var migrationCount, provenanceCount int
	if err := conn.QueryRow(ctx, `SELECT count(*) FROM public.gorp_migrations WHERE id = $1`, latest.ID).Scan(&migrationCount); err != nil {
		conn.Close(ctx)
		t.Fatal(err)
	}
	if err := conn.QueryRow(ctx, `SELECT count(*) FROM public.ms_oncall_migration_provenance WHERE migration_id = $1`, latest.ID).Scan(&provenanceCount); err != nil {
		conn.Close(ctx)
		t.Fatal(err)
	}
	if err := conn.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if migrationCount != 0 || provenanceCount != 0 {
		t.Fatalf("assignment rollback left migration/provenance rows: %d/%d", migrationCount, provenanceCount)
	}

	if count, err := Up(ctx, upgradeURL, ""); err != nil {
		t.Fatal(err)
	} else if count != 1 {
		t.Fatalf("assignment reapply count = %d, want 1", count)
	}
	assertUserOrganizationAssignmentTable(t, ctx, upgradeURL, true, 0)
	assertAssignmentPersistenceProvenance(t, ctx, upgradeURL, latest)
}

func assertUserOrganizationAssignmentTable(t *testing.T, ctx context.Context, testURL string, wantExists bool, wantRows int) {
	t.Helper()
	conn, err := pgx.Connect(ctx, testURL)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(ctx)
	var exists bool
	if err := conn.QueryRow(ctx, `SELECT to_regclass('public.user_organization_assignments') IS NOT NULL`).Scan(&exists); err != nil {
		t.Fatal(err)
	}
	if exists != wantExists {
		t.Fatalf("UserOrganizationAssignment table exists = %v, want %v", exists, wantExists)
	}
	if !exists {
		return
	}
	var rows int
	if err := conn.QueryRow(ctx, `SELECT count(*) FROM public.user_organization_assignments`).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != wantRows {
		t.Fatalf("UserOrganizationAssignment row count = %d, want %d", rows, wantRows)
	}
}

func assertAssignmentPersistenceProvenance(t *testing.T, ctx context.Context, testURL string, entry canonicalMigration) {
	t.Helper()
	conn, err := pgx.Connect(ctx, testURL)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(ctx)
	var position int64
	var origin, dependency string
	if err := conn.QueryRow(ctx, `
		SELECT canonical_position, record_origin, dependency_evidence
		FROM public.ms_oncall_migration_provenance
		WHERE migration_id = $1
	`, entry.ID).Scan(&position, &origin, &dependency); err != nil {
		t.Fatal(err)
	}
	if position != 277 || origin != recordOriginCanonical || dependency != entry.DependencyEvidence {
		t.Fatalf("assignment persistence provenance = position %d, origin %q, dependency %q", position, origin, dependency)
	}
}

type defaultOrganizationIdentity struct {
	ID             string
	Classification string
	DisplayName    string
	CanonicalName  string
	Lifecycle      string
}

func readDefaultOrganizationIdentity(t *testing.T, ctx context.Context, testURL string) defaultOrganizationIdentity {
	t.Helper()
	conn, err := pgx.Connect(ctx, testURL)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(ctx)
	var identity defaultOrganizationIdentity
	if err := conn.QueryRow(ctx, `
		select id::text, classification::text, display_name, canonical_name, lifecycle::text
		from organizations
		where classification = 'DEFAULT'
	`).Scan(&identity.ID, &identity.Classification, &identity.DisplayName, &identity.CanonicalName, &identity.Lifecycle); err != nil {
		t.Fatal(err)
	}
	var defaultCount, subtypeCount int
	if err := conn.QueryRow(ctx, `select count(*) from organizations where classification = 'DEFAULT'`).Scan(&defaultCount); err != nil {
		t.Fatal(err)
	}
	if err := conn.QueryRow(ctx, `select count(*) from normal_organizations where organization_id = $1`, identity.ID).Scan(&subtypeCount); err != nil {
		t.Fatal(err)
	}
	if defaultCount != 1 || subtypeCount != 0 {
		t.Fatalf("Default cardinality/subtype count = %d/%d, want 1/0", defaultCount, subtypeCount)
	}
	return identity
}

func assertOrganizationPersistenceProvenance(t *testing.T, ctx context.Context, testURL string, entry canonicalMigration) {
	t.Helper()
	conn, err := pgx.Connect(ctx, testURL)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(ctx)
	var position int64
	var origin, dependency string
	if err := conn.QueryRow(ctx, `
		select canonical_position, record_origin, dependency_evidence
		from ms_oncall_migration_provenance
		where migration_id = $1
	`, entry.ID).Scan(&position, &origin, &dependency); err != nil {
		t.Fatal(err)
	}
	if position != entry.Position || origin != recordOriginCanonical || dependency != entry.DependencyEvidence {
		t.Fatalf("Organization persistence provenance = position %d, origin %q, dependency %q", position, origin, dependency)
	}
}

func assertOrganizationTablesAbsent(t *testing.T, ctx context.Context, testURL string) {
	t.Helper()
	conn, err := pgx.Connect(ctx, testURL)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(ctx)
	var organizationsExist, normalOrganizationsExist bool
	if err := conn.QueryRow(ctx, `
		select
			to_regclass(current_schema() || '.organizations') is not null,
			to_regclass(current_schema() || '.normal_organizations') is not null
	`).Scan(&organizationsExist, &normalOrganizationsExist); err != nil {
		t.Fatal(err)
	}
	if organizationsExist || normalOrganizationsExist {
		t.Fatalf("Organization tables unexpectedly exist: organizations=%v normal_organizations=%v", organizationsExist, normalOrganizationsExist)
	}
}

func TestPostgresTestDatabaseCleanupWaitsForSessionsToDrain(t *testing.T) {
	baseURL := postgresIntegrationURL(t)
	dbName, testURL := newPostgresTestDatabaseDetails(t, baseURL)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	heldConn, err := pgx.Connect(ctx, testURL)
	if err != nil {
		t.Fatal(err)
	}
	defer heldConn.Close(context.Background())

	dropResult := make(chan error, 1)
	go func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cleanupCancel()
		dropResult <- dropPostgresTestDatabase(cleanupCtx, baseURL, dbName)
	}()

	select {
	case err := <-dropResult:
		if closeErr := heldConn.Close(ctx); closeErr != nil {
			t.Fatalf("cleanup returned early with %v; close held session: %v", err, closeErr)
		}
		t.Fatalf("cleanup returned before the held database session drained: %v", err)
	case <-time.After(100 * time.Millisecond):
	}

	if err := heldConn.Close(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-dropResult:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatalf("cleanup did not finish after the held database session drained: %v", ctx.Err())
	}

	admin, err := pgx.Connect(ctx, baseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close(context.Background())
	var exists bool
	if err := admin.QueryRow(ctx, `select exists (select 1 from pg_database where datname = $1)`, dbName).Scan(&exists); err != nil {
		t.Fatal(err)
	}
	if exists {
		t.Fatalf("PostgreSQL integration database %q still exists after cleanup", dbName)
	}
}

type provenanceSemanticRecord struct {
	CanonicalPosition   int64
	MigrationID         string
	MigrationName       string
	ProvenanceClass     string
	OriginalMigrationID string
	ContentSHA256       string
	SourceBinding       string
	BundleID            string
	PredecessorID       sql.NullString
	DependencyEvidence  string
	AdaptationEvidence  string
	RecordOrigin        string
}

func assertDeterministicProvenanceState(t *testing.T, ctx context.Context, testURL string, history *canonicalHistory) []provenanceSemanticRecord {
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
	var preLedgerCount, canonicalCount int
	if err := conn.QueryRow(ctx, `
		select
			count(*) filter (where record_origin = $1),
			count(*) filter (where record_origin = $2)
		from ms_oncall_migration_provenance
	`, recordOriginPreLedgerBootstrap, recordOriginCanonical).Scan(&preLedgerCount, &canonicalCount); err != nil {
		t.Fatal(err)
	}
	if preLedgerCount != history.provenanceFoundationIndex || canonicalCount != len(history.entries)-history.provenanceFoundationIndex {
		t.Fatalf("provenance origins = pre-ledger:%d canonical:%d, want pre-ledger:%d canonical:%d", preLedgerCount, canonicalCount, history.provenanceFoundationIndex, len(history.entries)-history.provenanceFoundationIndex)
	}
	var timestampMismatchCount int
	if err := conn.QueryRow(ctx, `
		select count(*)
		from ms_oncall_migration_provenance p
		join gorp_migrations g on g.id = p.migration_id
		where p.applied_at is distinct from g.applied_at
	`).Scan(&timestampMismatchCount); err != nil {
		t.Fatal(err)
	}
	if timestampMismatchCount != 0 {
		t.Fatalf("provenance has %d applied_at values different from gorp_migrations", timestampMismatchCount)
	}

	rows, err := conn.Query(ctx, `
		select canonical_position, migration_id, migration_name, provenance_class,
			original_migration_id, content_sha256, source_binding, bundle_id,
			predecessor_migration_id, dependency_evidence, adaptation_evidence,
			record_origin
		from ms_oncall_migration_provenance
		order by canonical_position
	`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var snapshot []provenanceSemanticRecord
	for rows.Next() {
		var record provenanceSemanticRecord
		if err := rows.Scan(
			&record.CanonicalPosition,
			&record.MigrationID,
			&record.MigrationName,
			&record.ProvenanceClass,
			&record.OriginalMigrationID,
			&record.ContentSHA256,
			&record.SourceBinding,
			&record.BundleID,
			&record.PredecessorID,
			&record.DependencyEvidence,
			&record.AdaptationEvidence,
			&record.RecordOrigin,
		); err != nil {
			t.Fatal(err)
		}
		snapshot = append(snapshot, record)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if len(snapshot) != len(history.entries) {
		t.Fatalf("provenance snapshot length = %d, want %d", len(snapshot), len(history.entries))
	}
	return snapshot
}

func assertProvenanceTableAbsent(t *testing.T, ctx context.Context, testURL string) {
	t.Helper()
	conn, err := pgx.Connect(ctx, testURL)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(ctx)
	var exists bool
	if err := conn.QueryRow(ctx, `select to_regclass(current_schema() || '.ms_oncall_migration_provenance') is not null`).Scan(&exists); err != nil {
		t.Fatal(err)
	}
	if exists {
		t.Fatal("provenance table exists before the Foundation migration is durably applied")
	}
}

func readAppliedTimes(t *testing.T, ctx context.Context, testURL string, entries []canonicalMigration) map[string]time.Time {
	t.Helper()
	conn, err := pgx.Connect(ctx, testURL)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(ctx)
	times := make(map[string]time.Time, len(entries))
	for _, entry := range entries {
		var appliedAt time.Time
		if err := conn.QueryRow(ctx, `select applied_at from gorp_migrations where id = $1`, entry.ID).Scan(&appliedAt); err != nil {
			t.Fatal(err)
		}
		times[entry.ID] = appliedAt
	}
	return times
}

func assertAppliedTimes(t *testing.T, ctx context.Context, testURL string, want map[string]time.Time) {
	t.Helper()
	conn, err := pgx.Connect(ctx, testURL)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(ctx)
	for id, expected := range want {
		var got time.Time
		if err := conn.QueryRow(ctx, `select applied_at from gorp_migrations where id = $1`, id).Scan(&got); err != nil {
			t.Fatal(err)
		}
		if !got.Equal(expected) {
			t.Fatalf("gorp_migrations timestamp for %q changed from %s to %s", id, expected, got)
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
	_, testURL := newPostgresTestDatabaseDetails(t, baseURL)
	return testURL
}

func newPostgresTestDatabaseDetails(t *testing.T, baseURL string) (string, string) {
	t.Helper()
	parsed, err := url.Parse(baseURL)
	if err != nil {
		t.Fatal(err)
	}
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
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), postgresTestDatabaseCleanupTimeout)
		defer cleanupCancel()
		if err := dropPostgresTestDatabase(cleanupCtx, baseURL, dbName); err != nil {
			t.Errorf("drop PostgreSQL integration database: %v", err)
		}
	})
	if err := admin.Close(ctx); err != nil {
		t.Fatal(err)
	}

	parsed.Path = "/" + dbName
	return dbName, parsed.String()
}

func dropPostgresTestDatabase(ctx context.Context, baseURL, dbName string) (returnErr error) {
	cleanupConn, err := pgx.Connect(ctx, baseURL)
	if err != nil {
		return fmt.Errorf("connect for PostgreSQL integration cleanup: %w", err)
	}
	defer func() {
		closeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := cleanupConn.Close(closeCtx); err != nil {
			returnErr = errors.Join(returnErr, fmt.Errorf("close PostgreSQL integration cleanup connection: %w", err))
		}
	}()

	quotedName := pgx.Identifier{dbName}.Sanitize()
	ticker := time.NewTicker(postgresTestDatabaseCleanupPollInterval)
	defer ticker.Stop()
	var activeSessions int
	var lastDropErr error
	for {
		if err := cleanupConn.QueryRow(ctx, `select count(*) from pg_stat_activity where datname = $1 and pid <> pg_backend_pid()`, dbName).Scan(&activeSessions); err != nil {
			return fmt.Errorf("inspect active sessions for PostgreSQL integration database %q: %w", dbName, err)
		}
		if activeSessions == 0 {
			if _, err := cleanupConn.Exec(ctx, "drop database if exists "+quotedName); err == nil {
				return nil
			} else if !isPostgresDatabaseInUseError(err) {
				return fmt.Errorf("drop PostgreSQL integration database %q: %w", dbName, err)
			} else {
				lastDropErr = err
			}
		}

		select {
		case <-ctx.Done():
			if lastDropErr != nil {
				return fmt.Errorf("timed out dropping PostgreSQL integration database %q with %d active session(s); last transient drop error: %v: %w", dbName, activeSessions, lastDropErr, ctx.Err())
			}
			return fmt.Errorf("timed out waiting for %d active session(s) on PostgreSQL integration database %q to drain: %w", activeSessions, dbName, ctx.Err())
		case <-ticker.C:
		}
	}
}

func isPostgresDatabaseInUseError(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "55006"
}
