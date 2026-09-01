package organization

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/target/goalert/migrate"
	"github.com/target/goalert/util/sqlutil"
)

const organizationPostgresIntegrationEnableEnv = "MS_ONCALL_CORE_MIGRATION_TEST_POSTGRES_ENABLE"

func TestPostgresStorePersistenceAndLifecycle(t *testing.T) {
	db := newOrganizationPostgresDatabase(t)
	store := NewStore(db)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	defaultOrg, err := store.FindDefault(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if defaultOrg.ID.String() != DefaultOrganizationID ||
		defaultOrg.CanonicalName != DefaultOrganizationCanonicalName ||
		defaultOrg.Classification != ClassificationDefault ||
		defaultOrg.DisplayName != "Default Organization" ||
		defaultOrg.Lifecycle != LifecycleActive {
		t.Fatalf("unexpected distinguished Default Organization: %#v", defaultOrg)
	}
	if _, err := store.FindNormalByID(ctx, defaultOrg.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("FindNormalByID(Default) error = %v, want ErrNotFound", err)
	}

	normal, err := store.CreateNormal(ctx, CreateNormalOrganizationInput{
		DisplayName:         "Example Organization",
		CanonicalName:       "example.organization",
		CorporateMappingKey: "corp:example",
		TimeZone:            "Asia/Chongqing",
	})
	if err != nil {
		t.Fatal(err)
	}
	if normal.ID == uuid.Nil || normal.Classification != ClassificationNormal || normal.Lifecycle != LifecycleActive {
		t.Fatalf("unexpected created Normal Organization: %#v", normal)
	}
	if normal.TimeZone != "Asia/Shanghai" {
		t.Fatalf("stored time zone = %q, want canonical Asia/Shanghai", normal.TimeZone)
	}
	stableID := normal.ID
	stableCanonicalName := normal.CanonicalName
	stableMappingKey := normal.CorporateMappingKey
	createdAt := normal.CreatedAt
	initialUpdatedAt := normal.UpdatedAt

	base, err := store.FindByID(ctx, stableID)
	if err != nil {
		t.Fatal(err)
	}
	byID, err := store.FindNormalByID(ctx, stableID)
	if err != nil {
		t.Fatal(err)
	}
	byKey, err := store.FindNormalByCorporateMappingKey(ctx, stableMappingKey)
	if err != nil {
		t.Fatal(err)
	}
	if base.ID != stableID || byID.ID != stableID || byKey.ID != stableID {
		t.Fatal("stable-ID or corporate-mapping-key lookup returned a different Organization")
	}

	updatedDisplay, err := store.UpdateDisplayName(ctx, stableID, "Renamed Organization")
	if err != nil {
		t.Fatal(err)
	}
	if !updatedDisplay.UpdatedAt.After(initialUpdatedAt) || updatedDisplay.DisplayName != "Renamed Organization" {
		t.Fatalf("display update did not advance audit timestamp: %#v", updatedDisplay)
	}
	displayUpdatedAt := updatedDisplay.UpdatedAt

	updatedZone, err := store.UpdateTimeZone(ctx, stableID, "UTC")
	if err != nil {
		t.Fatal(err)
	}
	if updatedZone.TimeZone != "Etc/UTC" || !updatedZone.UpdatedAt.After(displayUpdatedAt) {
		t.Fatalf("time-zone update did not canonicalize and advance base audit timestamp: %#v", updatedZone)
	}
	zoneUpdatedAt := updatedZone.UpdatedAt

	suspended, err := store.TransitionLifecycle(ctx, stableID, LifecycleSuspended)
	if err != nil {
		t.Fatal(err)
	}
	if suspended.Lifecycle != LifecycleSuspended || !suspended.UpdatedAt.After(zoneUpdatedAt) {
		t.Fatalf("ACTIVE -> SUSPENDED did not persist and advance audit timestamp: %#v", suspended)
	}
	active, err := store.TransitionLifecycle(ctx, stableID, LifecycleActive)
	if err != nil {
		t.Fatal(err)
	}
	if active.Lifecycle != LifecycleActive || !active.UpdatedAt.After(suspended.UpdatedAt) {
		t.Fatalf("SUSPENDED -> ACTIVE did not persist and advance audit timestamp: %#v", active)
	}
	retired, err := store.TransitionLifecycle(ctx, stableID, LifecycleRetired)
	if err != nil {
		t.Fatal(err)
	}
	if retired.Lifecycle != LifecycleRetired || !retired.UpdatedAt.After(active.UpdatedAt) {
		t.Fatalf("ACTIVE -> RETIRED did not persist and advance audit timestamp: %#v", retired)
	}
	same, err := store.TransitionLifecycle(ctx, stableID, LifecycleRetired)
	if err != nil {
		t.Fatal(err)
	}
	if !same.UpdatedAt.Equal(retired.UpdatedAt) {
		t.Fatalf("same-state RETIRED transition changed audit timestamp from %s to %s", retired.UpdatedAt, same.UpdatedAt)
	}
	if _, err := store.TransitionLifecycle(ctx, stableID, LifecycleActive); !errors.Is(err, ErrInvalidLifecycleTransition) {
		t.Fatalf("RETIRED -> ACTIVE error = %v, want ErrInvalidLifecycleTransition", err)
	}
	if _, err := store.TransitionLifecycle(ctx, stableID, "UNKNOWN"); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("unknown lifecycle error = %v, want ErrInvalidInput", err)
	}

	final, err := store.FindNormalByID(ctx, stableID)
	if err != nil {
		t.Fatal(err)
	}
	if final.ID != stableID || final.CanonicalName != stableCanonicalName ||
		final.CorporateMappingKey != stableMappingKey || !final.CreatedAt.Equal(createdAt) ||
		final.Classification != ClassificationNormal {
		t.Fatalf("mutable updates changed stable identity: %#v", final)
	}

	missingID := uuid.New()
	if _, err := store.FindByID(ctx, missingID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing FindByID error = %v, want ErrNotFound", err)
	}
	if _, err := store.FindNormalByCorporateMappingKey(ctx, "corp:missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing mapping lookup error = %v, want ErrNotFound", err)
	}
	if _, err := store.FindByID(ctx, uuid.Nil); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("nil ID error = %v, want ErrInvalidInput", err)
	}
	if _, err := store.UpdateTimeZone(ctx, stableID, "+08:00"); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("invalid time-zone update error = %v, want ErrInvalidInput", err)
	}
	if _, err := store.UpdateDisplayName(ctx, defaultOrg.ID, "Changed Default"); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("Default display update error = %v, want ErrInvalidInput", err)
	}
	if _, err := store.UpdateTimeZone(ctx, defaultOrg.ID, "Etc/UTC"); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("Default time-zone update error = %v, want ErrInvalidInput", err)
	}
	if _, err := store.TransitionLifecycle(ctx, defaultOrg.ID, LifecycleSuspended); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("Default lifecycle update error = %v, want ErrInvalidInput", err)
	}
}

func TestPostgresCreateNormalIsAtomicAndUnique(t *testing.T) {
	db := newOrganizationPostgresDatabase(t)
	store := NewStore(db)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	first, err := store.CreateNormal(ctx, CreateNormalOrganizationInput{
		DisplayName:         "First",
		CanonicalName:       "normal.first",
		CorporateMappingKey: "corp:duplicate",
		TimeZone:            "Asia/Shanghai",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateNormal(ctx, CreateNormalOrganizationInput{
		DisplayName:         "Second",
		CanonicalName:       "normal.second",
		CorporateMappingKey: "corp:duplicate",
		TimeZone:            "Etc/UTC",
	}); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate mapping key error = %v, want ErrConflict", err)
	}
	var orphanCount int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM organizations WHERE canonical_name = 'normal.second'`).Scan(&orphanCount); err != nil {
		t.Fatal(err)
	}
	if orphanCount != 0 {
		t.Fatalf("duplicate mapping failure left %d orphan base rows", orphanCount)
	}
	if _, err := store.CreateNormal(ctx, CreateNormalOrganizationInput{
		DisplayName:         "Duplicate Canonical",
		CanonicalName:       first.CanonicalName,
		CorporateMappingKey: "corp:unique",
		TimeZone:            "Etc/UTC",
	}); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate canonical identity error = %v, want ErrConflict", err)
	}
	if _, err := store.CreateNormal(ctx, CreateNormalOrganizationInput{
		DisplayName:         "Invalid Zone",
		CanonicalName:       "normal.invalid-zone",
		CorporateMappingKey: "corp:invalid-zone",
		TimeZone:            "+08:00",
	}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("invalid time-zone create error = %v, want ErrInvalidInput", err)
	}
}

func TestPostgresConcurrentCorporateMappingKeyCreate(t *testing.T) {
	db := newOrganizationPostgresDatabase(t)
	db.SetMaxOpenConns(4)
	store := NewStore(db)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	start := make(chan struct{})
	results := make(chan error, 2)
	var wg sync.WaitGroup
	for index := 0; index < 2; index++ {
		index := index
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, err := store.CreateNormal(ctx, CreateNormalOrganizationInput{
				DisplayName:         fmt.Sprintf("Concurrent %d", index),
				CanonicalName:       fmt.Sprintf("normal.concurrent.%d", index),
				CorporateMappingKey: "corp:concurrent",
				TimeZone:            "Asia/Shanghai",
			})
			results <- err
		}()
	}
	close(start)
	wg.Wait()
	close(results)

	var successCount, conflictCount int
	for err := range results {
		switch {
		case err == nil:
			successCount++
		case errors.Is(err, ErrConflict):
			conflictCount++
		default:
			t.Fatalf("concurrent create error = %v", err)
		}
	}
	if successCount != 1 || conflictCount != 1 {
		t.Fatalf("concurrent create results = %d success, %d conflict; want 1 and 1", successCount, conflictCount)
	}
	var baseCount, subtypeCount int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM organizations WHERE canonical_name LIKE 'normal.concurrent.%'`).Scan(&baseCount); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM normal_organizations WHERE corporate_mapping_key = 'corp:concurrent'`).Scan(&subtypeCount); err != nil {
		t.Fatal(err)
	}
	if baseCount != 1 || subtypeCount != 1 {
		t.Fatalf("concurrent durable rows = %d base, %d subtype; want 1 and 1", baseCount, subtypeCount)
	}
}

func TestPostgresRelationalAndImmutableInvariants(t *testing.T) {
	db := newOrganizationPostgresDatabase(t)
	store := NewStore(db)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	defaultID := uuid.MustParse(DefaultOrganizationID)
	normal, err := store.CreateNormal(ctx, CreateNormalOrganizationInput{
		DisplayName:         "Invariant Test",
		CanonicalName:       "normal.invariant-test",
		CorporateMappingKey: "corp:invariant-test",
		TimeZone:            "Asia/Shanghai",
	})
	if err != nil {
		t.Fatal(err)
	}

	assertDBConstraintError(t, db, ctx, `
		INSERT INTO organizations (id, classification, display_name, canonical_name, lifecycle)
		VALUES ($1, 'DEFAULT', 'Another Default', 'ms-oncall.another-default', 'ACTIVE')
	`, uuid.New())
	assertDBConstraintError(t, db, ctx, `UPDATE organizations SET classification = 'NORMAL' WHERE id = $1`, defaultID)
	assertDBConstraintError(t, db, ctx, `UPDATE organizations SET canonical_name = 'changed.default' WHERE id = $1`, defaultID)
	assertDBConstraintError(t, db, ctx, `UPDATE organizations SET id = $2 WHERE id = $1`, defaultID, uuid.New())
	assertDBConstraintError(t, db, ctx, `UPDATE organizations SET lifecycle = 'SUSPENDED' WHERE id = $1`, defaultID)
	assertDBConstraintError(t, db, ctx, `DELETE FROM organizations WHERE id = $1`, defaultID)
	assertDBConstraintError(t, db, ctx, `
		INSERT INTO normal_organizations (
			organization_id, organization_classification, corporate_mapping_key, iana_time_zone
		) VALUES ($1, 'NORMAL', 'corp:default-forbidden', 'Asia/Shanghai')
	`, defaultID)

	assertDBConstraintError(t, db, ctx, `UPDATE organizations SET canonical_name = 'changed.normal' WHERE id = $1`, normal.ID)
	assertDBConstraintError(t, db, ctx, `UPDATE organizations SET classification = 'DEFAULT' WHERE id = $1`, normal.ID)
	assertDBConstraintError(t, db, ctx, `UPDATE organizations SET id = $2 WHERE id = $1`, normal.ID, uuid.New())
	assertDBConstraintError(t, db, ctx, `UPDATE normal_organizations SET corporate_mapping_key = 'corp:changed' WHERE organization_id = $1`, normal.ID)

	if _, err := store.TransitionLifecycle(ctx, normal.ID, LifecycleRetired); err != nil {
		t.Fatal(err)
	}
	assertDBConstraintError(t, db, ctx, `UPDATE organizations SET lifecycle = 'ACTIVE' WHERE id = $1`, normal.ID)
	assertDBConstraintError(t, db, ctx, `
		INSERT INTO organizations (id, classification, display_name, canonical_name, lifecycle)
		VALUES ($1, 'UNKNOWN', 'Invalid', 'normal.invalid-classification', 'ACTIVE')
	`, uuid.New())
	assertDBConstraintError(t, db, ctx, `
		INSERT INTO organizations (id, classification, display_name, canonical_name, lifecycle)
		VALUES ($1, 'NORMAL', 'Invalid', 'normal.invalid-lifecycle', 'UNKNOWN')
	`, uuid.New())

	if _, err := db.ExecContext(ctx, `
		CREATE TABLE organization_owner_fk_test (
			id uuid PRIMARY KEY,
			organization_id uuid NOT NULL REFERENCES normal_organizations (organization_id)
		)
	`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO organization_owner_fk_test (id, organization_id) VALUES ($1, $2)`, uuid.New(), normal.ID); err != nil {
		t.Fatalf("normal Organization did not satisfy operational-owner-shaped FK: %v", err)
	}
	assertDBConstraintError(t, db, ctx, `INSERT INTO organization_owner_fk_test (id, organization_id) VALUES ($1, $2)`, uuid.New(), defaultID)

	defaultOrg, err := store.FindDefault(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if defaultOrg.ID != defaultID || defaultOrg.CanonicalName != DefaultOrganizationCanonicalName {
		t.Fatalf("Default identity drifted after rejected mutations: %#v", defaultOrg)
	}
}

type contextExecer interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}

func assertDBConstraintError(t *testing.T, db contextExecer, ctx context.Context, query string, args ...any) {
	t.Helper()
	_, err := db.ExecContext(ctx, query, args...)
	if err == nil {
		t.Fatal("database mutation unexpectedly succeeded")
	}
	dbErr := sqlutil.MapError(err)
	if dbErr == nil {
		t.Fatalf("database mutation returned non-PostgreSQL error: %v", err)
	}
	switch dbErr.Code {
	case "23503", "23505", "23514", "22P02":
	default:
		t.Fatalf("database mutation error code = %q, want constraint or enum rejection: %v", dbErr.Code, err)
	}
}

func organizationPostgresURL(t *testing.T) string {
	t.Helper()
	if os.Getenv(organizationPostgresIntegrationEnableEnv) != "1" {
		t.Skipf("set %s=1 to run Organization PostgreSQL integration tests", organizationPostgresIntegrationEnableEnv)
	}
	value := os.Getenv("DB_URL")
	if value == "" {
		t.Fatal("DB_URL must be configured for Organization PostgreSQL integration tests")
	}
	if _, err := url.Parse(value); err != nil {
		t.Fatalf("parse DB_URL: %v", err)
	}
	return value
}

func newOrganizationPostgresDatabase(t *testing.T) *sql.DB {
	t.Helper()
	baseURL := organizationPostgresURL(t)
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
	dbName := fmt.Sprintf("msoc_organization_%d_%s", time.Now().Unix(), hex.EncodeToString(random[:]))
	if _, err := admin.Exec(ctx, "create database "+pgx.Identifier{dbName}.Sanitize()); err != nil {
		admin.Close(ctx)
		t.Fatalf("create Organization PostgreSQL integration database: %v", err)
	}
	if err := admin.Close(ctx); err != nil {
		t.Fatal(err)
	}
	parsed.Path = "/" + dbName
	testURL := parsed.String()

	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cleanupCancel()
		cleanup, err := pgx.Connect(cleanupCtx, baseURL)
		if err != nil {
			t.Errorf("connect for Organization PostgreSQL cleanup: %v", err)
			return
		}
		defer cleanup.Close(context.Background())
		if _, err := cleanup.Exec(cleanupCtx, "drop database if exists "+pgx.Identifier{dbName}.Sanitize()+" with (force)"); err != nil {
			t.Errorf("drop Organization PostgreSQL integration database: %v", err)
		}
	})

	if _, err := migrate.ApplyAll(ctx, testURL); err != nil {
		t.Fatalf("apply canonical migrations: %v", err)
	}
	db, err := sql.Open("pgx", testURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close Organization PostgreSQL database: %v", err)
		}
	})
	if err := db.PingContext(ctx); err != nil {
		t.Fatal(err)
	}
	return db
}
