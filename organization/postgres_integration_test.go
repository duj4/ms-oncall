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
	"github.com/jackc/pgx/v5/pgconn"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/target/goalert/migrate"
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

func TestPostgresNormalOrganizationTouchCannotBeShadowed(t *testing.T) {
	tests := []struct {
		name              string
		temporary         bool
		foundationUpgrade bool
	}{
		{name: "fresh permanent schema"},
		{name: "fresh temporary schema", temporary: true},
		{name: "Foundation upgrade permanent schema", foundationUpgrade: true},
		{name: "Foundation upgrade temporary schema", temporary: true, foundationUpgrade: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			db := newOrganizationPostgresDatabaseWithMode(t, test.foundationUpgrade)
			store := NewStore(db)
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()

			normal, err := store.CreateNormal(ctx, CreateNormalOrganizationInput{
				DisplayName:         "Shadow Resolution Test",
				CanonicalName:       "normal.shadow-resolution",
				CorporateMappingKey: "corp:shadow-resolution",
				TimeZone:            "Asia/Shanghai",
			})
			if err != nil {
				t.Fatal(err)
			}

			conn, err := db.Conn(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()

			shadowTable := "pg_temp.organizations"
			searchPath := "pg_temp, public, pg_catalog"
			if test.temporary {
				if _, err := conn.ExecContext(ctx, `
					CREATE TEMP TABLE organizations (
						id uuid PRIMARY KEY,
						classification text NOT NULL,
						updated_at timestamp with time zone NOT NULL
					)
				`); err != nil {
					t.Fatal(err)
				}
			} else {
				shadowSchema := pgx.Identifier{newPostgresTestIdentifier(t, "msoc_org_shadow")}.Sanitize()
				shadowTable = shadowSchema + ".organizations"
				searchPath = shadowSchema + ", public, pg_catalog"
				if _, err := conn.ExecContext(ctx, "CREATE SCHEMA "+shadowSchema); err != nil {
					t.Fatal(err)
				}
				if _, err := conn.ExecContext(ctx, `
					CREATE TABLE `+shadowTable+` (
						id uuid PRIMARY KEY,
						classification text NOT NULL,
						updated_at timestamp with time zone NOT NULL
					)
				`); err != nil {
					t.Fatal(err)
				}
			}

			shadowUpdatedAt := time.Date(2000, time.January, 1, 0, 0, 0, 0, time.UTC)
			if _, err := conn.ExecContext(ctx, `INSERT INTO `+shadowTable+` (id, classification, updated_at) VALUES ($1, 'NORMAL', $2)`, normal.ID, shadowUpdatedAt); err != nil {
				t.Fatal(err)
			}
			if _, err := conn.ExecContext(ctx, `SELECT set_config('search_path', $1, false)`, searchPath); err != nil {
				t.Fatal(err)
			}

			if _, err := conn.ExecContext(ctx, `UPDATE public.normal_organizations SET iana_time_zone = 'Etc/UTC' WHERE organization_id = $1`, normal.ID); err != nil {
				t.Fatal(err)
			}

			var id uuid.UUID
			var classification, canonicalName, timeZone string
			var realUpdatedAt, actualShadowUpdatedAt time.Time
			if err := conn.QueryRowContext(ctx, `
				SELECT o.id, o.classification::text, o.canonical_name, o.updated_at, n.iana_time_zone
				FROM public.organizations o
				JOIN public.normal_organizations n ON n.organization_id = o.id
				WHERE o.id = $1
			`, normal.ID).Scan(&id, &classification, &canonicalName, &realUpdatedAt, &timeZone); err != nil {
				t.Fatal(err)
			}
			if err := conn.QueryRowContext(ctx, `SELECT updated_at FROM `+shadowTable+` WHERE id = $1`, normal.ID).Scan(&actualShadowUpdatedAt); err != nil {
				t.Fatal(err)
			}
			if id != normal.ID || classification != string(ClassificationNormal) || canonicalName != normal.CanonicalName {
				t.Fatalf("Organization immutable identity changed: id=%s classification=%q canonical=%q", id, classification, canonicalName)
			}
			if timeZone != "Etc/UTC" {
				t.Fatalf("Normal Organization time zone = %q, want Etc/UTC", timeZone)
			}
			realAdvanced := realUpdatedAt.After(normal.UpdatedAt)
			shadowUntouched := actualShadowUpdatedAt.Equal(shadowUpdatedAt)
			if !realAdvanced || !shadowUntouched {
				t.Fatalf("trigger resolution: public updated_at advanced=%v; shadow table untouched=%v", realAdvanced, shadowUntouched)
			}
		})
	}
}

func TestPostgresOrganizationTriggerMetadata(t *testing.T) {
	db := newOrganizationPostgresDatabase(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	functions := []string{
		"ms_oncall_enforce_organization_invariants",
		"ms_oncall_enforce_normal_organization_invariants",
		"ms_oncall_touch_organization_from_normal_organization",
	}
	for _, functionName := range functions {
		t.Run(functionName, func(t *testing.T) {
			var schemaName, actualName string
			var proconfig string
			var securityDefiner bool
			if err := db.QueryRowContext(ctx, `
				SELECT n.nspname, p.proname, pg_catalog.array_to_string(p.proconfig, E'\n'), p.prosecdef
				FROM pg_catalog.pg_proc p
				JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
				WHERE p.oid = pg_catalog.to_regprocedure($1)
			`, "public."+functionName+"()").Scan(&schemaName, &actualName, &proconfig, &securityDefiner); err != nil {
				t.Fatal(err)
			}
			if schemaName != "public" || actualName != functionName {
				t.Fatalf("trigger function identity = %s.%s", schemaName, actualName)
			}
			if proconfig != "search_path=pg_catalog, pg_temp" {
				t.Fatalf("trigger function proconfig = %q, want fixed safe search_path", proconfig)
			}
			if securityDefiner {
				t.Fatal("trigger function unexpectedly uses SECURITY DEFINER")
			}
		})
	}

	triggers := []struct {
		name     string
		table    string
		function string
	}{
		{name: "organizations_enforce_invariants", table: "organizations", function: "ms_oncall_enforce_organization_invariants"},
		{name: "normal_organizations_enforce_invariants", table: "normal_organizations", function: "ms_oncall_enforce_normal_organization_invariants"},
		{name: "normal_organizations_touch_base", table: "normal_organizations", function: "ms_oncall_touch_organization_from_normal_organization"},
	}
	for _, trigger := range triggers {
		t.Run(trigger.name, func(t *testing.T) {
			var tableSchema, tableName, functionSchema, functionName string
			var exactFunctionOID bool
			if err := db.QueryRowContext(ctx, `
				SELECT tn.nspname, c.relname, pn.nspname, p.proname,
					t.tgfoid = pg_catalog.to_regprocedure($2)::oid
				FROM pg_catalog.pg_trigger t
				JOIN pg_catalog.pg_class c ON c.oid = t.tgrelid
				JOIN pg_catalog.pg_namespace tn ON tn.oid = c.relnamespace
				JOIN pg_catalog.pg_proc p ON p.oid = t.tgfoid
				JOIN pg_catalog.pg_namespace pn ON pn.oid = p.pronamespace
				WHERE t.tgname = $1 AND NOT t.tgisinternal
			`, trigger.name, "public."+trigger.function+"()").Scan(
				&tableSchema, &tableName, &functionSchema, &functionName, &exactFunctionOID,
			); err != nil {
				t.Fatal(err)
			}
			if tableSchema != "public" || tableName != trigger.table ||
				functionSchema != "public" || functionName != trigger.function || !exactFunctionOID {
				t.Fatalf("trigger binding = %s.%s -> %s.%s exact_oid=%v", tableSchema, tableName, functionSchema, functionName, exactFunctionOID)
			}
		})
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
	_, err = store.CreateNormal(ctx, CreateNormalOrganizationInput{
		DisplayName:         "Second",
		CanonicalName:       "normal.second",
		CorporateMappingKey: "corp:duplicate",
		TimeZone:            "Etc/UTC",
	})
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate mapping key error = %v, want ErrConflict", err)
	}
	assertPGError(t, err, pgErrorExpectation{SQLState: "23505", ConstraintName: "normal_organizations_corporate_mapping_key_key", SchemaName: "public", TableName: "normal_organizations"})
	var orphanCount int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM organizations WHERE canonical_name = 'normal.second'`).Scan(&orphanCount); err != nil {
		t.Fatal(err)
	}
	if orphanCount != 0 {
		t.Fatalf("duplicate mapping failure left %d orphan base rows", orphanCount)
	}
	_, err = store.CreateNormal(ctx, CreateNormalOrganizationInput{
		DisplayName:         "Duplicate Canonical",
		CanonicalName:       first.CanonicalName,
		CorporateMappingKey: "corp:unique",
		TimeZone:            "Etc/UTC",
	})
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate canonical identity error = %v, want ErrConflict", err)
	}
	assertPGError(t, err, pgErrorExpectation{SQLState: "23505", ConstraintName: "organizations_canonical_name_key", SchemaName: "public", TableName: "organizations"})
	if _, err := store.CreateNormal(ctx, CreateNormalOrganizationInput{
		DisplayName:         "Invalid Zone",
		CanonicalName:       "normal.invalid-zone",
		CorporateMappingKey: "corp:invalid-zone",
		TimeZone:            "+08:00",
	}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("invalid time-zone create error = %v, want ErrInvalidInput", err)
	}
}

func TestPostgresStoreErrorMappingUsesExactConstraintIdentity(t *testing.T) {
	db := newOrganizationPostgresDatabase(t)
	store := NewStore(db)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	normal, err := store.CreateNormal(ctx, CreateNormalOrganizationInput{
		DisplayName:         "Store Mapping Test",
		CanonicalName:       "normal.store-mapping-test",
		CorporateMappingKey: "corp:store-mapping-test",
		TimeZone:            "Asia/Shanghai",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.TransitionLifecycle(ctx, normal.ID, LifecycleRetired); err != nil {
		t.Fatal(err)
	}

	_, rawLifecycleErr := db.ExecContext(ctx, `UPDATE public.organizations SET lifecycle = 'ACTIVE' WHERE id = $1`, normal.ID)
	assertPGError(t, rawLifecycleErr, pgErrorExpectation{SQLState: "23514", ConstraintName: "organizations_lifecycle_transition", SchemaName: "public", TableName: "organizations", ColumnName: "lifecycle"})
	mappedLifecycleErr := mapWriteError("integration lifecycle transition", rawLifecycleErr)
	if !errors.Is(mappedLifecycleErr, ErrInvalidLifecycleTransition) || errors.Is(mappedLifecycleErr, ErrConflict) || errors.Is(mappedLifecycleErr, ErrInvariantViolation) {
		t.Fatalf("lifecycle mapping = %v", mappedLifecycleErr)
	}
	assertPGError(t, mappedLifecycleErr, pgErrorExpectation{SQLState: "23514", ConstraintName: "organizations_lifecycle_transition", SchemaName: "public", TableName: "organizations", ColumnName: "lifecycle"})

	_, rawInvariantErr := db.ExecContext(ctx, `UPDATE public.organizations SET canonical_name = 'changed.store-mapping-test' WHERE id = $1`, normal.ID)
	assertPGError(t, rawInvariantErr, pgErrorExpectation{SQLState: "23514", ConstraintName: "organizations_canonical_name_immutable", SchemaName: "public", TableName: "organizations", ColumnName: "canonical_name"})
	mappedInvariantErr := mapWriteError("integration immutable identity", rawInvariantErr)
	if !errors.Is(mappedInvariantErr, ErrInvariantViolation) || errors.Is(mappedInvariantErr, ErrConflict) || errors.Is(mappedInvariantErr, ErrInvalidLifecycleTransition) {
		t.Fatalf("trigger invariant mapping = %v", mappedInvariantErr)
	}
	assertPGError(t, mappedInvariantErr, pgErrorExpectation{SQLState: "23514", ConstraintName: "organizations_canonical_name_immutable", SchemaName: "public", TableName: "organizations", ColumnName: "canonical_name"})

	if _, err := db.ExecContext(ctx, `
		ALTER TABLE public.organizations
		ADD CONSTRAINT organization_store_test_unknown_display_key UNIQUE (display_name)
	`); err != nil {
		t.Fatal(err)
	}
	_, unknownUniqueErr := store.UpdateDisplayName(ctx, normal.ID, "Default Organization")
	if unknownUniqueErr == nil {
		t.Fatal("unknown unique constraint unexpectedly allowed the Store update")
	}
	for _, semantic := range []error{ErrConflict, ErrInvalidLifecycleTransition, ErrInvariantViolation} {
		if errors.Is(unknownUniqueErr, semantic) {
			t.Fatalf("unknown unique constraint mapped to %v: %v", semantic, unknownUniqueErr)
		}
	}
	assertPGError(t, unknownUniqueErr, pgErrorExpectation{SQLState: "23505", ConstraintName: "organization_store_test_unknown_display_key", SchemaName: "public", TableName: "organizations"})

	if _, err := db.ExecContext(ctx, `
		ALTER TABLE public.organizations
		ADD CONSTRAINT organization_store_test_unknown_check CHECK (display_name <> 'blocked-by-future-check')
	`); err != nil {
		t.Fatal(err)
	}
	_, unknownCheckErr := store.UpdateDisplayName(ctx, normal.ID, "blocked-by-future-check")
	if unknownCheckErr == nil {
		t.Fatal("unknown check constraint unexpectedly allowed the Store update")
	}
	for _, semantic := range []error{ErrConflict, ErrInvalidLifecycleTransition, ErrInvariantViolation} {
		if errors.Is(unknownCheckErr, semantic) {
			t.Fatalf("unknown check constraint mapped to %v: %v", semantic, unknownCheckErr)
		}
	}
	assertPGError(t, unknownCheckErr, pgErrorExpectation{SQLState: "23514", ConstraintName: "organization_store_test_unknown_check", SchemaName: "public", TableName: "organizations"})

	if _, err := store.FindByID(ctx, uuid.New()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("not-found mapping = %v, want ErrNotFound", err)
	} else {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) {
			t.Fatalf("not-found unexpectedly wrapped PostgreSQL invariant error: %v", err)
		}
	}
	unchanged, err := store.FindNormalByID(ctx, normal.ID)
	if err != nil {
		t.Fatal(err)
	}
	if unchanged.DisplayName != normal.DisplayName || unchanged.CanonicalName != normal.CanonicalName || unchanged.Lifecycle != LifecycleRetired {
		t.Fatalf("failed Store writes changed durable state: %#v", unchanged)
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
	defaultOrg, err := store.FindDefault(ctx)
	if err != nil {
		t.Fatal(err)
	}
	normal, err := store.CreateNormal(ctx, CreateNormalOrganizationInput{
		DisplayName:         "Invariant Test",
		CanonicalName:       "normal.invariant-test",
		CorporateMappingKey: "corp:invariant-test",
		TimeZone:            "Asia/Shanghai",
	})
	if err != nil {
		t.Fatal(err)
	}
	retired, err := store.TransitionLifecycle(ctx, normal.ID, LifecycleRetired)
	if err != nil {
		t.Fatal(err)
	}
	normal.Organization = *retired

	if _, err := db.ExecContext(ctx, `
		CREATE TABLE public.organization_owner_fk_test (
			id uuid PRIMARY KEY,
			organization_id uuid NOT NULL,
			CONSTRAINT organization_owner_fk_test_organization_id_fkey
				FOREIGN KEY (organization_id) REFERENCES public.normal_organizations (organization_id)
		)
	`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO public.organization_owner_fk_test (id, organization_id) VALUES ($1, $2)`, uuid.New(), normal.ID); err != nil {
		t.Fatalf("normal Organization did not satisfy operational-owner-shaped FK: %v", err)
	}

	insertBase := func(id uuid.UUID, canonicalName string) {
		t.Helper()
		if _, err := db.ExecContext(ctx, `
			INSERT INTO public.organizations (id, classification, display_name, canonical_name, lifecycle)
			VALUES ($1, 'NORMAL', 'Invariant Setup', $2, 'ACTIVE')
		`, id, canonicalName); err != nil {
			t.Fatal(err)
		}
	}
	duplicateMappingBaseID := uuid.New()
	blankMappingBaseID := uuid.New()
	blankTimeZoneBaseID := uuid.New()
	classificationCheckBaseID := uuid.New()
	insertBase(duplicateMappingBaseID, "normal.duplicate-mapping-base")
	insertBase(blankMappingBaseID, "normal.blank-mapping-base")
	insertBase(blankTimeZoneBaseID, "normal.blank-time-zone-base")
	insertBase(classificationCheckBaseID, "normal.classification-check-base")

	assertDefaultStable := func(t *testing.T) {
		t.Helper()
		actual, err := store.FindDefault(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if *actual != *defaultOrg {
			t.Fatalf("Default durable state changed: got %#v, want %#v", actual, defaultOrg)
		}
	}
	assertNormalStable := func(t *testing.T) {
		t.Helper()
		actual, err := store.FindNormalByID(ctx, normal.ID)
		if err != nil {
			t.Fatal(err)
		}
		if *actual != *normal {
			t.Fatalf("Normal Organization durable state changed: got %#v, want %#v", actual, normal)
		}
	}
	assertOrganizationAbsent := func(id uuid.UUID) func(*testing.T) {
		return func(t *testing.T) {
			t.Helper()
			var count int
			if err := db.QueryRowContext(ctx, `SELECT count(*) FROM public.organizations WHERE id = $1`, id).Scan(&count); err != nil {
				t.Fatal(err)
			}
			if count != 0 {
				t.Fatalf("rejected mutation left %d Organization rows", count)
			}
		}
	}
	assertBaseWithoutSubtype := func(id uuid.UUID) func(*testing.T) {
		return func(t *testing.T) {
			t.Helper()
			var baseCount, subtypeCount int
			if err := db.QueryRowContext(ctx, `SELECT count(*) FROM public.organizations WHERE id = $1`, id).Scan(&baseCount); err != nil {
				t.Fatal(err)
			}
			if err := db.QueryRowContext(ctx, `SELECT count(*) FROM public.normal_organizations WHERE organization_id = $1`, id).Scan(&subtypeCount); err != nil {
				t.Fatal(err)
			}
			if baseCount != 1 || subtypeCount != 0 {
				t.Fatalf("base/subtype durable rows = %d/%d, want 1/0", baseCount, subtypeCount)
			}
		}
	}

	secondDefaultID := uuid.New()
	duplicateCanonicalID := uuid.New()
	invalidClassificationID := uuid.New()
	invalidLifecycleID := uuid.New()
	nullDisplayID := uuid.New()
	blankDisplayID := uuid.New()
	blankCanonicalID := uuid.New()
	changedDefaultID := uuid.New()
	changedNormalID := uuid.New()

	type invariantCase struct {
		name                    string
		prepare                 func(*testing.T, *sql.Tx)
		query                   string
		args                    []any
		expected                pgErrorExpectation
		durableState            string
		transactionMustRollback bool
		assertState             func(*testing.T)
	}
	tests := []invariantCase{
		{
			name: "second Default exact partial unique index",
			query: `INSERT INTO public.organizations (id, classification, display_name, canonical_name, lifecycle)
				VALUES ($1, 'DEFAULT', 'Another Default', 'ms-oncall.another-default', 'ACTIVE')`,
			args:         []any{secondDefaultID},
			expected:     pgErrorExpectation{SQLState: "23505", ConstraintName: "organizations_single_default_idx", SchemaName: "public", TableName: "organizations"},
			durableState: "second Default absent and distinguished Default unchanged", transactionMustRollback: true,
			assertState: func(t *testing.T) { assertOrganizationAbsent(secondDefaultID)(t); assertDefaultStable(t) },
		},
		{
			name: "Default cannot satisfy Normal subtype composite foreign key",
			query: `INSERT INTO public.normal_organizations (organization_id, organization_classification, corporate_mapping_key, iana_time_zone)
				VALUES ($1, 'NORMAL', 'corp:default-forbidden', 'Asia/Shanghai')`,
			args:         []any{defaultID},
			expected:     pgErrorExpectation{SQLState: "23503", ConstraintName: "normal_organizations_organization_classification_fkey", SchemaName: "public", TableName: "normal_organizations"},
			durableState: "Default has no Normal subtype", transactionMustRollback: true,
			assertState: assertDefaultStable,
		},
		{
			name: "duplicate corporate mapping key exact unique constraint",
			query: `INSERT INTO public.normal_organizations (organization_id, organization_classification, corporate_mapping_key, iana_time_zone)
				VALUES ($1, 'NORMAL', $2, 'Asia/Shanghai')`,
			args:         []any{duplicateMappingBaseID, normal.CorporateMappingKey},
			expected:     pgErrorExpectation{SQLState: "23505", ConstraintName: "normal_organizations_corporate_mapping_key_key", SchemaName: "public", TableName: "normal_organizations"},
			durableState: "setup base remains without subtype", transactionMustRollback: true,
			assertState: assertBaseWithoutSubtype(duplicateMappingBaseID),
		},
		{
			name: "subtype base one-to-one exact primary key",
			query: `INSERT INTO public.normal_organizations (organization_id, organization_classification, corporate_mapping_key, iana_time_zone)
				VALUES ($1, 'NORMAL', 'corp:duplicate-subtype', 'Asia/Shanghai')`,
			args:         []any{normal.ID},
			expected:     pgErrorExpectation{SQLState: "23505", ConstraintName: "normal_organizations_pkey", SchemaName: "public", TableName: "normal_organizations"},
			durableState: "original subtype remains unchanged", transactionMustRollback: true,
			assertState: assertNormalStable,
		},
		{
			name: "duplicate canonical identity exact unique constraint",
			query: `INSERT INTO public.organizations (id, classification, display_name, canonical_name, lifecycle)
				VALUES ($1, 'NORMAL', 'Duplicate Canonical', $2, 'ACTIVE')`,
			args:         []any{duplicateCanonicalID, normal.CanonicalName},
			expected:     pgErrorExpectation{SQLState: "23505", ConstraintName: "organizations_canonical_name_key", SchemaName: "public", TableName: "organizations"},
			durableState: "duplicate row absent", transactionMustRollback: true,
			assertState: assertOrganizationAbsent(duplicateCanonicalID),
		},
		{
			name: "invalid classification enum input",
			query: `INSERT INTO public.organizations (id, classification, display_name, canonical_name, lifecycle)
				VALUES ($1, 'UNKNOWN', 'Invalid', 'normal.invalid-classification', 'ACTIVE')`,
			args:         []any{invalidClassificationID},
			expected:     pgErrorExpectation{SQLState: "22P02"},
			durableState: "invalid row absent", transactionMustRollback: true,
			assertState: assertOrganizationAbsent(invalidClassificationID),
		},
		{
			name: "invalid lifecycle enum input",
			query: `INSERT INTO public.organizations (id, classification, display_name, canonical_name, lifecycle)
				VALUES ($1, 'NORMAL', 'Invalid', 'normal.invalid-lifecycle', 'UNKNOWN')`,
			args:         []any{invalidLifecycleID},
			expected:     pgErrorExpectation{SQLState: "22P02"},
			durableState: "invalid row absent", transactionMustRollback: true,
			assertState: assertOrganizationAbsent(invalidLifecycleID),
		},
		{
			name: "display name not null native metadata",
			query: `INSERT INTO public.organizations (id, classification, display_name, canonical_name, lifecycle)
				VALUES ($1, 'NORMAL', NULL, 'normal.null-display', 'ACTIVE')`,
			args:         []any{nullDisplayID},
			expected:     pgErrorExpectation{SQLState: "23502", SchemaName: "public", TableName: "organizations", ColumnName: "display_name"},
			durableState: "null-domain row absent", transactionMustRollback: true,
			assertState: assertOrganizationAbsent(nullDisplayID),
		},
		{
			name: "display name nonblank check",
			query: `INSERT INTO public.organizations (id, classification, display_name, canonical_name, lifecycle)
				VALUES ($1, 'NORMAL', ' ', 'normal.blank-display', 'ACTIVE')`,
			args:         []any{blankDisplayID},
			expected:     pgErrorExpectation{SQLState: "23514", ConstraintName: "organizations_display_name_not_blank", SchemaName: "public", TableName: "organizations"},
			durableState: "blank-domain row absent", transactionMustRollback: true,
			assertState: assertOrganizationAbsent(blankDisplayID),
		},
		{
			name: "canonical identity nonblank check",
			query: `INSERT INTO public.organizations (id, classification, display_name, canonical_name, lifecycle)
				VALUES ($1, 'NORMAL', 'Blank Canonical', '', 'ACTIVE')`,
			args:         []any{blankCanonicalID},
			expected:     pgErrorExpectation{SQLState: "23514", ConstraintName: "organizations_canonical_name_not_blank", SchemaName: "public", TableName: "organizations"},
			durableState: "blank-domain row absent", transactionMustRollback: true,
			assertState: assertOrganizationAbsent(blankCanonicalID),
		},
		{
			name: "Normal subtype classification check",
			query: `INSERT INTO public.normal_organizations (organization_id, organization_classification, corporate_mapping_key, iana_time_zone)
				VALUES ($1, 'DEFAULT', 'corp:invalid-subtype-classification', 'Asia/Shanghai')`,
			args:         []any{classificationCheckBaseID},
			expected:     pgErrorExpectation{SQLState: "23514", ConstraintName: "normal_organizations_classification_normal", SchemaName: "public", TableName: "normal_organizations"},
			durableState: "setup base remains without subtype", transactionMustRollback: true,
			assertState: assertBaseWithoutSubtype(classificationCheckBaseID),
		},
		{
			name: "corporate mapping key nonblank check",
			query: `INSERT INTO public.normal_organizations (organization_id, organization_classification, corporate_mapping_key, iana_time_zone)
				VALUES ($1, 'NORMAL', '', 'Asia/Shanghai')`,
			args:         []any{blankMappingBaseID},
			expected:     pgErrorExpectation{SQLState: "23514", ConstraintName: "normal_organizations_corporate_mapping_key_not_blank", SchemaName: "public", TableName: "normal_organizations"},
			durableState: "setup base remains without subtype", transactionMustRollback: true,
			assertState: assertBaseWithoutSubtype(blankMappingBaseID),
		},
		{
			name: "IANA time zone nonblank check",
			query: `INSERT INTO public.normal_organizations (organization_id, organization_classification, corporate_mapping_key, iana_time_zone)
				VALUES ($1, 'NORMAL', 'corp:blank-time-zone', ' ')`,
			args:         []any{blankTimeZoneBaseID},
			expected:     pgErrorExpectation{SQLState: "23514", ConstraintName: "normal_organizations_iana_time_zone_not_blank", SchemaName: "public", TableName: "normal_organizations"},
			durableState: "setup base remains without subtype", transactionMustRollback: true,
			assertState: assertBaseWithoutSubtype(blankTimeZoneBaseID),
		},
		{
			name:  "Default UUID immutable",
			query: `UPDATE public.organizations SET id = $2 WHERE id = $1`, args: []any{defaultID, changedDefaultID},
			expected:     pgErrorExpectation{SQLState: "23514", ConstraintName: "organizations_id_immutable", SchemaName: "public", TableName: "organizations", ColumnName: "id"},
			durableState: "Default identity unchanged", transactionMustRollback: true, assertState: assertDefaultStable,
		},
		{
			name:  "Default classification immutable",
			query: `UPDATE public.organizations SET classification = 'NORMAL' WHERE id = $1`, args: []any{defaultID},
			expected:     pgErrorExpectation{SQLState: "23514", ConstraintName: "organizations_classification_immutable", SchemaName: "public", TableName: "organizations", ColumnName: "classification"},
			durableState: "Default classification unchanged", transactionMustRollback: true, assertState: assertDefaultStable,
		},
		{
			name:  "Default canonical identity immutable",
			query: `UPDATE public.organizations SET canonical_name = 'changed.default' WHERE id = $1`, args: []any{defaultID},
			expected:     pgErrorExpectation{SQLState: "23514", ConstraintName: "organizations_canonical_name_immutable", SchemaName: "public", TableName: "organizations", ColumnName: "canonical_name"},
			durableState: "Default canonical identity unchanged", transactionMustRollback: true, assertState: assertDefaultStable,
		},
		{
			name:  "Default lifecycle immutable",
			query: `UPDATE public.organizations SET lifecycle = 'SUSPENDED' WHERE id = $1`, args: []any{defaultID},
			expected:     pgErrorExpectation{SQLState: "23514", ConstraintName: "organizations_default_lifecycle_immutable", SchemaName: "public", TableName: "organizations", ColumnName: "lifecycle"},
			durableState: "Default lifecycle unchanged", transactionMustRollback: true, assertState: assertDefaultStable,
		},
		{
			name:  "Default delete prohibited",
			query: `DELETE FROM public.organizations WHERE id = $1`, args: []any{defaultID},
			expected:     pgErrorExpectation{SQLState: "23514", ConstraintName: "organizations_default_delete_forbidden", SchemaName: "public", TableName: "organizations", ColumnName: "classification"},
			durableState: "Default row remains", transactionMustRollback: true, assertState: assertDefaultStable,
		},
		{
			name:  "Normal Organization UUID immutable",
			query: `UPDATE public.organizations SET id = $2 WHERE id = $1`, args: []any{normal.ID, changedNormalID},
			expected:     pgErrorExpectation{SQLState: "23514", ConstraintName: "organizations_id_immutable", SchemaName: "public", TableName: "organizations", ColumnName: "id"},
			durableState: "Normal identity unchanged", transactionMustRollback: true, assertState: assertNormalStable,
		},
		{
			name:  "Normal Organization classification immutable",
			query: `UPDATE public.organizations SET classification = 'DEFAULT' WHERE id = $1`, args: []any{normal.ID},
			expected:     pgErrorExpectation{SQLState: "23514", ConstraintName: "organizations_classification_immutable", SchemaName: "public", TableName: "organizations", ColumnName: "classification"},
			durableState: "Normal classification unchanged", transactionMustRollback: true, assertState: assertNormalStable,
		},
		{
			name:  "Normal Organization canonical identity immutable",
			query: `UPDATE public.organizations SET canonical_name = 'changed.normal' WHERE id = $1`, args: []any{normal.ID},
			expected:     pgErrorExpectation{SQLState: "23514", ConstraintName: "organizations_canonical_name_immutable", SchemaName: "public", TableName: "organizations", ColumnName: "canonical_name"},
			durableState: "Normal canonical identity unchanged", transactionMustRollback: true, assertState: assertNormalStable,
		},
		{
			name:  "Organization created timestamp immutable",
			query: `UPDATE public.organizations SET created_at = created_at + interval '1 second' WHERE id = $1`, args: []any{normal.ID},
			expected:     pgErrorExpectation{SQLState: "23514", ConstraintName: "organizations_created_at_immutable", SchemaName: "public", TableName: "organizations", ColumnName: "created_at"},
			durableState: "creation timestamp unchanged", transactionMustRollback: true, assertState: assertNormalStable,
		},
		{
			name:  "invalid lifecycle transition",
			query: `UPDATE public.organizations SET lifecycle = 'ACTIVE' WHERE id = $1`, args: []any{normal.ID},
			expected:     pgErrorExpectation{SQLState: "23514", ConstraintName: "organizations_lifecycle_transition", SchemaName: "public", TableName: "organizations", ColumnName: "lifecycle"},
			durableState: "RETIRED lifecycle unchanged", transactionMustRollback: true, assertState: assertNormalStable,
		},
		{
			name:  "Normal subtype Organization ID immutable",
			query: `UPDATE public.normal_organizations SET organization_id = $2 WHERE organization_id = $1`, args: []any{normal.ID, uuid.New()},
			expected:     pgErrorExpectation{SQLState: "23514", ConstraintName: "normal_organizations_organization_id_immutable", SchemaName: "public", TableName: "normal_organizations", ColumnName: "organization_id"},
			durableState: "subtype identity unchanged", transactionMustRollback: true, assertState: assertNormalStable,
		},
		{
			name:  "Normal subtype classification immutable",
			query: `UPDATE public.normal_organizations SET organization_classification = 'DEFAULT' WHERE organization_id = $1`, args: []any{normal.ID},
			expected:     pgErrorExpectation{SQLState: "23514", ConstraintName: "normal_organizations_classification_immutable", SchemaName: "public", TableName: "normal_organizations", ColumnName: "organization_classification"},
			durableState: "subtype classification unchanged", transactionMustRollback: true, assertState: assertNormalStable,
		},
		{
			name:  "corporate mapping key immutable",
			query: `UPDATE public.normal_organizations SET corporate_mapping_key = 'corp:changed' WHERE organization_id = $1`, args: []any{normal.ID},
			expected:     pgErrorExpectation{SQLState: "23514", ConstraintName: "normal_organizations_corporate_mapping_key_immutable", SchemaName: "public", TableName: "normal_organizations", ColumnName: "corporate_mapping_key"},
			durableState: "mapping key unchanged", transactionMustRollback: true, assertState: assertNormalStable,
		},
		{
			name: "missing Normal base trigger invariant",
			prepare: func(t *testing.T, tx *sql.Tx) {
				t.Helper()
				if _, err := tx.ExecContext(ctx, `ALTER TABLE public.normal_organizations DROP CONSTRAINT normal_organizations_organization_classification_fkey`); err != nil {
					t.Fatal(err)
				}
				if _, err := tx.ExecContext(ctx, `DELETE FROM public.organizations WHERE id = $1`, normal.ID); err != nil {
					t.Fatal(err)
				}
			},
			query: `UPDATE public.normal_organizations SET iana_time_zone = 'Etc/UTC' WHERE organization_id = $1`, args: []any{normal.ID},
			expected:     pgErrorExpectation{SQLState: "23514", ConstraintName: "normal_organizations_base_invariant", SchemaName: "public", TableName: "organizations", ColumnName: "id"},
			durableState: "transaction rollback restores base and subtype", transactionMustRollback: true, assertState: assertNormalStable,
		},
		{
			name:  "Default rejected by operational-owner-shaped foreign key",
			query: `INSERT INTO public.organization_owner_fk_test (id, organization_id) VALUES ($1, $2)`, args: []any{uuid.New(), defaultID},
			expected:     pgErrorExpectation{SQLState: "23503", ConstraintName: "organization_owner_fk_test_organization_id_fkey", SchemaName: "public", TableName: "organization_owner_fk_test"},
			durableState: "no Default-owned row", transactionMustRollback: true,
			assertState: func(t *testing.T) {
				var count int
				if err := db.QueryRowContext(ctx, `SELECT count(*) FROM public.organization_owner_fk_test WHERE organization_id = $1`, defaultID).Scan(&count); err != nil {
					t.Fatal(err)
				}
				if count != 0 {
					t.Fatalf("rejected Default owner left %d rows", count)
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if test.durableState == "" || !test.transactionMustRollback || test.assertState == nil {
				t.Fatal("invariant matrix case must declare durable state, rollback behavior, and state assertion")
			}
			tx, err := db.BeginTx(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			if test.prepare != nil {
				test.prepare(t, tx)
			}
			_, err = tx.ExecContext(ctx, test.query, test.args...)
			assertPGError(t, err, test.expected)
			_, abortedErr := tx.ExecContext(ctx, `SELECT 1`)
			assertPGError(t, abortedErr, pgErrorExpectation{SQLState: "25P02"})
			if err := tx.Rollback(); err != nil {
				t.Fatal(err)
			}
			test.assertState(t)
		})
	}
}

type pgErrorExpectation struct {
	SQLState       string
	ConstraintName string
	SchemaName     string
	TableName      string
	ColumnName     string
	DataTypeName   string
}

func assertPGError(t *testing.T, err error, expected pgErrorExpectation) {
	t.Helper()
	if err == nil {
		t.Fatal("database operation unexpectedly succeeded")
	}
	var dbErr *pgconn.PgError
	if !errors.As(err, &dbErr) {
		t.Fatalf("database operation returned non-PostgreSQL error: %v", err)
	}
	if dbErr.Code != expected.SQLState ||
		dbErr.ConstraintName != expected.ConstraintName ||
		dbErr.SchemaName != expected.SchemaName ||
		dbErr.TableName != expected.TableName ||
		dbErr.ColumnName != expected.ColumnName ||
		dbErr.DataTypeName != expected.DataTypeName {
		t.Fatalf("PostgreSQL error metadata = code=%q constraint=%q schema=%q table=%q column=%q datatype=%q; want code=%q constraint=%q schema=%q table=%q column=%q datatype=%q: %v",
			dbErr.Code, dbErr.ConstraintName, dbErr.SchemaName, dbErr.TableName, dbErr.ColumnName, dbErr.DataTypeName,
			expected.SQLState, expected.ConstraintName, expected.SchemaName, expected.TableName, expected.ColumnName, expected.DataTypeName, err)
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
	return newOrganizationPostgresDatabaseWithMode(t, false)
}

func newOrganizationPostgresDatabaseWithMode(t *testing.T, foundationUpgrade bool) *sql.DB {
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

	var db *sql.DB
	t.Cleanup(func() {
		if db != nil {
			if err := db.Close(); err != nil {
				t.Errorf("close Organization PostgreSQL database: %v", err)
			}
		}
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cleanupCancel()
		if err := dropOrganizationPostgresDatabase(cleanupCtx, baseURL, dbName); err != nil {
			t.Errorf("drop Organization PostgreSQL integration database: %v", err)
		}
	})

	if foundationUpgrade {
		if _, err := migrate.Up(ctx, testURL, "ms-oncall-migration-provenance"); err != nil {
			t.Fatalf("apply through migration-provenance Foundation: %v", err)
		}
		if _, err := migrate.Up(ctx, testURL, ""); err != nil {
			t.Fatalf("upgrade from migration-provenance Foundation: %v", err)
		}
	} else if _, err := migrate.ApplyAll(ctx, testURL); err != nil {
		t.Fatalf("apply canonical migrations: %v", err)
	}
	db, err = sql.Open("pgx", testURL)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.PingContext(ctx); err != nil {
		t.Fatal(err)
	}
	return db
}

func dropOrganizationPostgresDatabase(ctx context.Context, baseURL, dbName string) error {
	cleanup, err := pgx.Connect(ctx, baseURL)
	if err != nil {
		return fmt.Errorf("connect for cleanup: %w", err)
	}
	defer cleanup.Close(context.Background())

	quotedName := pgx.Identifier{dbName}.Sanitize()
	ticker := time.NewTicker(25 * time.Millisecond)
	defer ticker.Stop()
	for {
		var activeSessions int
		if err := cleanup.QueryRow(ctx, `
			SELECT count(*)
			FROM pg_catalog.pg_stat_activity
			WHERE datname = $1 AND pid <> pg_catalog.pg_backend_pid()
		`, dbName).Scan(&activeSessions); err != nil {
			return fmt.Errorf("inspect active sessions: %w", err)
		}
		if activeSessions == 0 {
			if _, err := cleanup.Exec(ctx, "drop database if exists "+quotedName); err == nil {
				return nil
			} else {
				var dbErr *pgconn.PgError
				if !errors.As(err, &dbErr) || dbErr.Code != "55006" {
					return fmt.Errorf("drop database: %w", err)
				}
			}
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("wait for %d active session(s) to drain: %w", activeSessions, ctx.Err())
		case <-ticker.C:
		}
	}
}

func newPostgresTestIdentifier(t *testing.T, prefix string) string {
	t.Helper()
	var random [6]byte
	if _, err := rand.Read(random[:]); err != nil {
		t.Fatal(err)
	}
	return prefix + "_" + hex.EncodeToString(random[:])
}
