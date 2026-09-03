package user

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
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
	"github.com/target/goalert/permission"
)

const humanSecurityGenerationPostgresIntegrationEnableEnv = "MS_ONCALL_CORE_MIGRATION_TEST_POSTGRES_ENABLE"

func TestPostgresHumanSecurityGenerationPersistence(t *testing.T) {
	db := newHumanSecurityGenerationPostgresDatabase(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	store, err := NewStore(ctx, db)
	if err != nil {
		t.Fatal(err)
	}

	unpersistedUserID := insertHumanSecurityGenerationTestUser(t, ctx, db, "No Automatic Security State")
	if _, err := store.FindHumanSecurityGeneration(ctx, unpersistedUserID); !errors.Is(err, ErrHumanSecurityGenerationNotFound) {
		t.Fatalf("new User lookup error = %v, want not found", err)
	}
	assertHumanSecurityGenerationRowCount(t, ctx, db, unpersistedUserID, 0)

	userID := insertHumanSecurityGenerationTestUser(t, ctx, db, "Explicit Security State")
	created, err := store.CreateHumanSecurityGeneration(ctx, userID)
	if err != nil {
		t.Fatal(err)
	}
	if created.UserID != userID || created.Generation != InitialHumanSecurityGeneration {
		t.Fatalf("created state = %#v", created)
	}
	found, err := store.FindHumanSecurityGeneration(ctx, userID)
	if err != nil {
		t.Fatal(err)
	}
	if *found != *created {
		t.Fatalf("found state = %#v, want %#v", found, created)
	}
	if _, err := store.CreateHumanSecurityGeneration(ctx, userID); !errors.Is(err, ErrHumanSecurityGenerationConflict) {
		t.Fatalf("duplicate create error = %v, want conflict", err)
	}

	nonexistentUserID := uuid.New()
	_, err = store.CreateHumanSecurityGeneration(ctx, nonexistentUserID)
	if !errors.Is(err, ErrInvalidHumanSecurityGenerationInput) {
		t.Fatalf("nonexistent User create error = %v, want invalid input", err)
	}
	assertHumanSecurityGenerationPGError(t, err, humanSecurityGenerationPGErrorExpectation{
		SQLState: "23503", ConstraintName: "user_human_security_generations_user_id_fkey",
		SchemaName: "public", TableName: "user_human_security_generations",
	})

	advanced, err := store.AdvanceHumanSecurityGeneration(ctx, AdvanceHumanSecurityGenerationInput{
		UserID: userID, ExpectedGeneration: InitialHumanSecurityGeneration,
	})
	if err != nil {
		t.Fatal(err)
	}
	if advanced.UserID != userID || advanced.Generation != InitialHumanSecurityGeneration+1 {
		t.Fatalf("advanced state = %#v", advanced)
	}
	if _, err := store.AdvanceHumanSecurityGeneration(ctx, AdvanceHumanSecurityGenerationInput{
		UserID: userID, ExpectedGeneration: InitialHumanSecurityGeneration,
	}); !errors.Is(err, ErrStaleHumanSecurityGeneration) {
		t.Fatalf("stale advance error = %v, want stale generation", err)
	}
	if _, err := store.AdvanceHumanSecurityGeneration(ctx, AdvanceHumanSecurityGenerationInput{
		UserID: uuid.New(), ExpectedGeneration: InitialHumanSecurityGeneration,
	}); !errors.Is(err, ErrHumanSecurityGenerationNotFound) {
		t.Fatalf("missing advance error = %v, want not found", err)
	}

	deleteUserID := insertHumanSecurityGenerationTestUser(t, ctx, db, "Cascade Security State")
	if _, err := store.CreateHumanSecurityGeneration(ctx, deleteUserID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `DELETE FROM public.users WHERE id = $1`, deleteUserID); err != nil {
		t.Fatal(err)
	}
	assertHumanSecurityGenerationRowCount(t, ctx, db, deleteUserID, 0)
}

func TestPostgresHumanSecurityGenerationConcurrentCreateAndAdvance(t *testing.T) {
	db := newHumanSecurityGenerationPostgresDatabase(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	store, err := NewStore(ctx, db)
	if err != nil {
		t.Fatal(err)
	}

	const attempts = 8
	userID := insertHumanSecurityGenerationTestUser(t, ctx, db, "Concurrent Security State")
	start := make(chan struct{})
	results := make(chan humanSecurityGenerationConcurrentResult, attempts)
	var wg sync.WaitGroup
	for range attempts {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			state, err := store.CreateHumanSecurityGeneration(ctx, userID)
			results <- humanSecurityGenerationConcurrentResult{state: state, err: err}
		}()
	}
	close(start)
	wg.Wait()
	close(results)

	var createSuccess, createConflict int
	for result := range results {
		switch {
		case result.err == nil:
			createSuccess++
			if result.state.Generation != InitialHumanSecurityGeneration {
				t.Fatalf("concurrent create generation = %d", result.state.Generation)
			}
		case errors.Is(result.err, ErrHumanSecurityGenerationConflict):
			createConflict++
		default:
			t.Fatalf("concurrent create error = %v", result.err)
		}
	}
	if createSuccess != 1 || createConflict != attempts-1 {
		t.Fatalf("concurrent create success/conflict = %d/%d, want 1/%d", createSuccess, createConflict, attempts-1)
	}
	assertHumanSecurityGenerationRowCount(t, ctx, db, userID, 1)

	start = make(chan struct{})
	results = make(chan humanSecurityGenerationConcurrentResult, attempts)
	for range attempts {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			state, err := store.AdvanceHumanSecurityGeneration(ctx, AdvanceHumanSecurityGenerationInput{
				UserID: userID, ExpectedGeneration: InitialHumanSecurityGeneration,
			})
			results <- humanSecurityGenerationConcurrentResult{state: state, err: err}
		}()
	}
	close(start)
	wg.Wait()
	close(results)

	var advanceSuccess, advanceStale int
	for result := range results {
		switch {
		case result.err == nil:
			advanceSuccess++
			if result.state.Generation != InitialHumanSecurityGeneration+1 {
				t.Fatalf("concurrent advance generation = %d", result.state.Generation)
			}
		case errors.Is(result.err, ErrStaleHumanSecurityGeneration):
			advanceStale++
		default:
			t.Fatalf("concurrent advance error = %v", result.err)
		}
	}
	if advanceSuccess != 1 || advanceStale != attempts-1 {
		t.Fatalf("concurrent advance success/stale = %d/%d, want 1/%d", advanceSuccess, advanceStale, attempts-1)
	}
	final, err := store.FindHumanSecurityGeneration(ctx, userID)
	if err != nil {
		t.Fatal(err)
	}
	if final.Generation != InitialHumanSecurityGeneration+1 {
		t.Fatalf("durable final generation = %d, want %d", final.Generation, InitialHumanSecurityGeneration+1)
	}
}

type humanSecurityGenerationConcurrentResult struct {
	state *HumanSecurityGeneration
	err   error
}

func TestPostgresHumanSecurityGenerationDatabaseInvariants(t *testing.T) {
	db := newHumanSecurityGenerationPostgresDatabase(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	store, err := NewStore(ctx, db)
	if err != nil {
		t.Fatal(err)
	}

	initialError := humanSecurityGenerationPGErrorExpectation{
		SQLState: "23514", ConstraintName: "user_human_security_generations_initial_generation",
		SchemaName: "public", TableName: "user_human_security_generations", ColumnName: "human_security_generation",
	}
	_, err = db.ExecContext(ctx, `
		INSERT INTO public.user_human_security_generations (user_id, human_security_generation)
		VALUES ($1, 1)
	`, uuid.Nil)
	assertHumanSecurityGenerationPGError(t, err, humanSecurityGenerationPGErrorExpectation{
		SQLState: "23514", ConstraintName: "user_human_security_generations_user_id_non_nil",
		SchemaName: "public", TableName: "user_human_security_generations",
	})
	for _, generation := range []int64{0, -1, 2} {
		userID := insertHumanSecurityGenerationTestUser(t, ctx, db, fmt.Sprintf("Invalid Initial %d", generation))
		_, err := db.ExecContext(ctx, `
			INSERT INTO public.user_human_security_generations (user_id, human_security_generation)
			VALUES ($1, $2)
		`, userID, generation)
		assertHumanSecurityGenerationPGError(t, err, initialError)
		assertHumanSecurityGenerationRowCount(t, ctx, db, userID, 0)
	}

	userID := insertHumanSecurityGenerationTestUser(t, ctx, db, "Raw Update Invariants")
	if _, err := store.CreateHumanSecurityGeneration(ctx, userID); err != nil {
		t.Fatal(err)
	}
	stepError := humanSecurityGenerationPGErrorExpectation{
		SQLState: "23514", ConstraintName: "user_human_security_generations_generation_step",
		SchemaName: "public", TableName: "user_human_security_generations", ColumnName: "human_security_generation",
	}
	for name, generation := range map[string]int64{
		"unchanged": 1,
		"decrease":  0,
		"skip":      3,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := db.ExecContext(ctx, `
				UPDATE public.user_human_security_generations
				SET human_security_generation = $2
				WHERE user_id = $1
			`, userID, generation)
			assertHumanSecurityGenerationPGError(t, err, stepError)
		})
	}

	otherUserID := insertHumanSecurityGenerationTestUser(t, ctx, db, "Raw Identity Mutation")
	_, err = db.ExecContext(ctx, `
		UPDATE public.user_human_security_generations
		SET user_id = $2, human_security_generation = human_security_generation + 1
		WHERE user_id = $1
	`, userID, otherUserID)
	assertHumanSecurityGenerationPGError(t, err, humanSecurityGenerationPGErrorExpectation{
		SQLState: "23514", ConstraintName: "user_human_security_generations_user_id_immutable",
		SchemaName: "public", TableName: "user_human_security_generations", ColumnName: "user_id",
	})
	state, err := store.FindHumanSecurityGeneration(ctx, userID)
	if err != nil {
		t.Fatal(err)
	}
	if state.Generation != InitialHumanSecurityGeneration {
		t.Fatalf("rejected raw updates changed generation to %d", state.Generation)
	}

	maxUserID := insertHumanSecurityGenerationTestUser(t, ctx, db, "Maximum Generation Boundary")
	if _, err := store.CreateHumanSecurityGeneration(ctx, maxUserID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `
		ALTER TABLE public.user_human_security_generations
			DISABLE TRIGGER user_human_security_generations_enforce_invariants
	`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `
		UPDATE public.user_human_security_generations
		SET human_security_generation = $2
		WHERE user_id = $1
	`, maxUserID, int64(math.MaxInt64)); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `
		ALTER TABLE public.user_human_security_generations
			ENABLE TRIGGER user_human_security_generations_enforce_invariants
	`); err != nil {
		t.Fatal(err)
	}
	_, err = db.ExecContext(ctx, `
		UPDATE public.user_human_security_generations
		SET human_security_generation = human_security_generation
		WHERE user_id = $1
	`, maxUserID)
	assertHumanSecurityGenerationPGError(t, err, stepError)

	var functionConfig string
	var securityDefiner bool
	if err := db.QueryRowContext(ctx, `
		SELECT config, p.prosecdef
		FROM pg_catalog.pg_proc p
		JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
		CROSS JOIN LATERAL unnest(p.proconfig) AS config
		WHERE n.nspname = 'public'
			AND p.proname = 'ms_oncall_enforce_user_human_security_generation_invariants'
			AND config LIKE 'search_path=%'
	`).Scan(&functionConfig, &securityDefiner); err != nil {
		t.Fatal(err)
	}
	if functionConfig != "search_path=pg_catalog, pg_temp" || securityDefiner {
		t.Fatalf("trigger function hardening = config %q security-definer %v", functionConfig, securityDefiner)
	}
}

func TestPostgresHumanSecurityGenerationLoadedStateFailsClosed(t *testing.T) {
	db := newHumanSecurityGenerationPostgresDatabase(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	store, err := NewStore(ctx, db)
	if err != nil {
		t.Fatal(err)
	}
	userID := insertHumanSecurityGenerationTestUser(t, ctx, db, "Corrupt Loaded Security State")
	if _, err := store.CreateHumanSecurityGeneration(ctx, userID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `
		ALTER TABLE public.user_human_security_generations
			DISABLE TRIGGER user_human_security_generations_enforce_invariants
	`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `
		ALTER TABLE public.user_human_security_generations
			DROP CONSTRAINT user_human_security_generations_generation_positive
	`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `
		UPDATE public.user_human_security_generations
		SET human_security_generation = 0
		WHERE user_id = $1
	`, userID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.FindHumanSecurityGeneration(ctx, userID); !errors.Is(err, ErrHumanSecurityGenerationInvariantViolation) {
		t.Fatalf("corrupt loaded state error = %v, want invariant violation", err)
	}
}

func TestPostgresSetUserRoleDoesNotCreateOrAdvanceHumanSecurityGeneration(t *testing.T) {
	db := newHumanSecurityGenerationPostgresDatabase(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	store, err := NewStore(ctx, db)
	if err != nil {
		t.Fatal(err)
	}
	systemCtx := permission.SystemContext(ctx, "HumanSecurityGenerationTest")
	userID := insertHumanSecurityGenerationTestUser(t, ctx, db, "Role Is Not Coupled")

	setHumanSecurityGenerationTestRole(t, systemCtx, db, store, userID, permission.RoleAdmin)
	if _, err := store.FindHumanSecurityGeneration(ctx, userID); !errors.Is(err, ErrHumanSecurityGenerationNotFound) {
		t.Fatalf("role update created security state: %v", err)
	}
	if _, err := store.CreateHumanSecurityGeneration(ctx, userID); err != nil {
		t.Fatal(err)
	}
	setHumanSecurityGenerationTestRole(t, systemCtx, db, store, userID, permission.RoleUser)
	state, err := store.FindHumanSecurityGeneration(ctx, userID)
	if err != nil {
		t.Fatal(err)
	}
	if state.Generation != InitialHumanSecurityGeneration {
		t.Fatalf("role update advanced generation to %d", state.Generation)
	}
}

func TestPostgresHumanSecurityGenerationPreservesContextErrors(t *testing.T) {
	db := newHumanSecurityGenerationPostgresDatabase(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	store, err := NewStore(ctx, db)
	if err != nil {
		t.Fatal(err)
	}
	userID := insertHumanSecurityGenerationTestUser(t, ctx, db, "Canceled Security State")
	if _, err := store.CreateHumanSecurityGeneration(ctx, userID); err != nil {
		t.Fatal(err)
	}

	canceledCtx, cancelNow := context.WithCancel(context.Background())
	cancelNow()
	if _, err := store.FindHumanSecurityGeneration(canceledCtx, userID); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled find error = %v", err)
	}
	if _, err := store.AdvanceHumanSecurityGeneration(canceledCtx, AdvanceHumanSecurityGenerationInput{
		UserID: userID, ExpectedGeneration: InitialHumanSecurityGeneration,
	}); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled advance error = %v", err)
	}

	deadlineCtx, cancelDeadline := context.WithDeadline(context.Background(), time.Unix(1, 0))
	defer cancelDeadline()
	otherUserID := insertHumanSecurityGenerationTestUser(t, ctx, db, "Expired Security State")
	if _, err := store.CreateHumanSecurityGeneration(deadlineCtx, otherUserID); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expired create error = %v", err)
	}
}

func setHumanSecurityGenerationTestRole(t *testing.T, ctx context.Context, db *sql.DB, store *Store, userID uuid.UUID, role permission.Role) {
	t.Helper()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := store.SetUserRoleTx(ctx, tx, userID.String(), role); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
}

func assertHumanSecurityGenerationRowCount(t *testing.T, ctx context.Context, db *sql.DB, userID uuid.UUID, want int) {
	t.Helper()
	var count int
	if err := db.QueryRowContext(ctx, `
		SELECT count(*) FROM public.user_human_security_generations WHERE user_id = $1
	`, userID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != want {
		t.Fatalf("security generation row count = %d, want %d", count, want)
	}
}

func insertHumanSecurityGenerationTestUser(t *testing.T, ctx context.Context, db *sql.DB, name string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	if _, err := db.ExecContext(ctx, `
		INSERT INTO public.users (id, name, email) VALUES ($1, $2, '')
	`, id, name); err != nil {
		t.Fatal(err)
	}
	return id
}

type humanSecurityGenerationPGErrorExpectation struct {
	SQLState       string
	ConstraintName string
	SchemaName     string
	TableName      string
	ColumnName     string
}

func assertHumanSecurityGenerationPGError(t *testing.T, err error, expected humanSecurityGenerationPGErrorExpectation) {
	t.Helper()
	if err == nil {
		t.Fatal("database operation unexpectedly succeeded")
	}
	var dbErr *pgconn.PgError
	if !errors.As(err, &dbErr) {
		t.Fatalf("database operation returned non-PostgreSQL error: %v", err)
	}
	if dbErr.Code != expected.SQLState || dbErr.ConstraintName != expected.ConstraintName ||
		dbErr.SchemaName != expected.SchemaName || dbErr.TableName != expected.TableName ||
		dbErr.ColumnName != expected.ColumnName {
		t.Fatalf("PostgreSQL error metadata = code=%q constraint=%q schema=%q table=%q column=%q; want code=%q constraint=%q schema=%q table=%q column=%q: %v",
			dbErr.Code, dbErr.ConstraintName, dbErr.SchemaName, dbErr.TableName, dbErr.ColumnName,
			expected.SQLState, expected.ConstraintName, expected.SchemaName, expected.TableName, expected.ColumnName, err)
	}
}

func newHumanSecurityGenerationPostgresDatabase(t *testing.T) *sql.DB {
	t.Helper()
	if os.Getenv(humanSecurityGenerationPostgresIntegrationEnableEnv) != "1" {
		t.Skipf("set %s=1 to run human security generation PostgreSQL integration tests", humanSecurityGenerationPostgresIntegrationEnableEnv)
	}
	baseURL := os.Getenv("DB_URL")
	if baseURL == "" {
		t.Fatal("DB_URL must be configured for human security generation PostgreSQL integration tests")
	}
	parsed, err := url.Parse(baseURL)
	if err != nil {
		t.Fatalf("parse DB_URL: %v", err)
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
	dbName := fmt.Sprintf("msoc_human_security_generation_%d_%s", time.Now().Unix(), hex.EncodeToString(random[:]))
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{dbName}.Sanitize()); err != nil {
		admin.Close(ctx)
		t.Fatalf("create human security generation PostgreSQL database: %v", err)
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
				t.Errorf("close human security generation PostgreSQL database: %v", err)
			}
		}
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cleanupCancel()
		cleanup, err := pgx.Connect(cleanupCtx, baseURL)
		if err != nil {
			t.Errorf("connect for human security generation cleanup: %v", err)
			return
		}
		defer cleanup.Close(context.Background())
		if _, err := cleanup.Exec(cleanupCtx, "DROP DATABASE "+pgx.Identifier{dbName}.Sanitize()); err != nil {
			t.Errorf("drop human security generation PostgreSQL database: %v", err)
		}
	})

	if _, err := migrate.ApplyAll(ctx, testURL); err != nil {
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
