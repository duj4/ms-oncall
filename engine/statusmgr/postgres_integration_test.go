package statusmgr

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/riverqueue/river"
	"github.com/target/goalert/config"
	"github.com/target/goalert/engine/processinglock"
	"github.com/target/goalert/migrate"
)

func TestPostgresStatusMgrLockedRow(t *testing.T) {
	for _, lockedRow := range []string{"subscription", "alert"} {
		t.Run(lockedRow, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
			defer cancel()
			dbURL, workerDB := newStatusMgrPostgresDatabase(t, ctx)
			blocker := connectStatusMgrPostgres(t, ctx, dbURL)
			defer blocker.Close(ctx)
			subID, alertID := insertStatusMgrPostgresFixture(t, ctx, blocker)
			manager, err := NewDB(ctx, workerDB, nil, config.Static{})
			if err != nil {
				t.Fatal(err)
			}
			var workerPID int
			if err := workerDB.QueryRowContext(ctx, `SELECT pg_backend_pid()`).Scan(&workerPID); err != nil {
				t.Fatal(err)
			}
			blockTx, err := blocker.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = blockTx.Rollback(ctx) }()
			if lockedRow == "subscription" {
				_, err = blockTx.Exec(ctx, `SELECT id FROM alert_status_subscriptions WHERE id = $1 FOR UPDATE`, subID)
			} else {
				_, err = blockTx.Exec(ctx, `SELECT id FROM alerts WHERE id = $1 FOR UPDATE`, alertID)
			}
			if err != nil {
				t.Fatal(err)
			}
			job := &river.Job[ProcessArgs]{Args: ProcessArgs{SubscriptionID: subID}}
			done := make(chan error, 1)
			go func() { done <- manager.processSubscription(ctx, job) }()
			waitForStatusMgrRowLock(t, ctx, blocker, workerPID, done)
			if err := blockTx.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			if err := receiveStatusMgrResult(t, ctx, done); err != nil {
				t.Fatal(err)
			}
			assertStatusMgrDurableWork(t, ctx, blocker, subID, alertID, "active", 1)
			// Duplicate delivery remains harmless after the required work commits.
			if err := manager.processSubscription(ctx, job); err != nil {
				t.Fatal(err)
			}
			assertStatusMgrDurableWork(t, ctx, blocker, subID, alertID, "active", 1)
			t.Logf("%s lock: actual River worker blocked, proceeded after release, persisted exactly one status message, duplicate was harmless", lockedRow)
		})
	}
}

func TestPostgresStatusMgrLockTimeoutRetry(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	dbURL, workerDB := newStatusMgrPostgresDatabase(t, ctx)
	blocker := connectStatusMgrPostgres(t, ctx, dbURL)
	defer blocker.Close(ctx)
	subID, alertID := insertStatusMgrPostgresFixture(t, ctx, blocker)
	manager, err := NewDB(ctx, workerDB, nil, config.Static{})
	if err != nil {
		t.Fatal(err)
	}
	var workerPID int
	if err := workerDB.QueryRowContext(ctx, `SELECT pg_backend_pid()`).Scan(&workerPID); err != nil {
		t.Fatal(err)
	}
	baseline := statusMgrLockTimeout(t, ctx, workerDB)
	blockTx, err := blocker.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = blockTx.Rollback(ctx) }()
	if _, err := blockTx.Exec(ctx, `SELECT id FROM alert_status_subscriptions WHERE id = $1 FOR UPDATE`, subID); err != nil {
		t.Fatal(err)
	}
	job := &river.Job[ProcessArgs]{Args: ProcessArgs{SubscriptionID: subID}}
	done := make(chan error, 1)
	started := time.Now()
	go func() { done <- manager.processSubscription(ctx, job) }()
	waitForStatusMgrRowLock(t, ctx, blocker, workerPID, done)
	err = receiveStatusMgrResult(t, ctx, done)
	assertStatusMgrLockTimeoutError(t, err, time.Since(started))
	assertStatusMgrDurableWork(t, ctx, blocker, subID, alertID, "triggered", 0)
	if got := statusMgrLockTimeout(t, ctx, workerDB); got != baseline {
		t.Fatalf("timeout leaked after rollback: %q, baseline %q", got, baseline)
	}
	if err := blockTx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := manager.processSubscription(ctx, job); err != nil {
		t.Fatalf("retry after lock release: %v", err)
	}
	assertStatusMgrDurableWork(t, ctx, blocker, subID, alertID, "active", 1)
	if got := statusMgrLockTimeout(t, ctx, workerDB); got != baseline {
		t.Fatalf("timeout leaked after successful commit: %q, baseline %q", got, baseline)
	}
	if _, err := blocker.Exec(ctx, `DELETE FROM alert_status_subscriptions WHERE id = $1`, subID); err != nil {
		t.Fatal(err)
	}
	if err := manager.processSubscription(ctx, job); err != nil {
		t.Fatalf("actual deleted subscription should be a no-op: %v", err)
	}
	t.Logf("actual River worker returned SQLSTATE 55P03, preserved pending work, retry succeeded, actual deletion remained a no-op; session lock_timeout=%q", baseline)
}

// Directly exercise WithTxShared as well as the StatusMgr worker above. The
// callback writes one unlocked row before waiting on a competing lock, proving
// that timeout errors roll back all callback effects rather than committing
// partial work.
func TestPostgresWithTxSharedLockTimeoutRetry(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	dbURL, workerDB := newStatusMgrPostgresDatabase(t, ctx)
	blocker := connectStatusMgrPostgres(t, ctx, dbURL)
	defer blocker.Close(ctx)
	if _, err := blocker.Exec(ctx, `CREATE TABLE c2_shared_lock_probe (id int PRIMARY KEY, value int NOT NULL); INSERT INTO c2_shared_lock_probe VALUES (1, 0), (2, 0)`); err != nil {
		t.Fatal(err)
	}
	lock, err := processinglock.NewLock(ctx, workerDB, processinglock.Config{
		Type: processinglock.TypeStatusUpdate, Version: 5,
	})
	if err != nil {
		t.Fatal(err)
	}
	// A nonzero session baseline makes both override and restoration observable.
	if _, err := workerDB.ExecContext(ctx, `SET lock_timeout = '1200ms'`); err != nil {
		t.Fatal(err)
	}
	baseline := statusMgrLockTimeout(t, ctx, workerDB)
	var workerPID int
	if err := workerDB.QueryRowContext(ctx, `SELECT pg_backend_pid()`).Scan(&workerPID); err != nil {
		t.Fatal(err)
	}
	callback := func(ctx context.Context, tx *sql.Tx) error {
		var timeout string
		var pid int
		if err := tx.QueryRowContext(ctx, `SELECT current_setting('lock_timeout'), pg_backend_pid()`).Scan(&timeout, &pid); err != nil {
			return err
		}
		if timeout != "8s" || pid != workerPID {
			return fmt.Errorf("shared transaction lock_timeout/PID = %q/%d, want 8s/%d", timeout, pid, workerPID)
		}
		if _, err := tx.ExecContext(ctx, `UPDATE c2_shared_lock_probe SET value = value + 1 WHERE id = 2`); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `UPDATE c2_shared_lock_probe SET value = value + 1 WHERE id = 1`)
		return err
	}
	blockTx, err := blocker.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = blockTx.Rollback(ctx) }()
	if _, err := blockTx.Exec(ctx, `SELECT id FROM c2_shared_lock_probe WHERE id = 1 FOR UPDATE`); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	started := time.Now()
	go func() { done <- lock.WithTxShared(ctx, callback) }()
	waitForStatusMgrRowLock(t, ctx, blocker, workerPID, done)
	err = receiveStatusMgrResult(t, ctx, done)
	assertStatusMgrLockTimeoutError(t, err, time.Since(started))
	var total int
	if err := blocker.QueryRow(ctx, `SELECT sum(value) FROM c2_shared_lock_probe`).Scan(&total); err != nil || total != 0 {
		t.Fatalf("callback effects after timeout = (%d, %v), want zero", total, err)
	}
	if got := statusMgrLockTimeout(t, ctx, workerDB); got != baseline {
		t.Fatalf("shared timeout leaked after rollback: %q, baseline %q", got, baseline)
	}
	if err := blockTx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := lock.WithTxShared(ctx, callback); err != nil {
		t.Fatalf("shared callback retry: %v", err)
	}
	if err := blocker.QueryRow(ctx, `SELECT sum(value) FROM c2_shared_lock_probe`).Scan(&total); err != nil || total != 2 {
		t.Fatalf("successful retry effects = (%d, %v), want two", total, err)
	}
	if got := statusMgrLockTimeout(t, ctx, workerDB); got != baseline {
		t.Fatalf("shared timeout leaked after commit: %q, baseline %q", got, baseline)
	}
	// Exclusive processing retains its prior session timeout semantics.
	if err := lock.WithTx(ctx, func(ctx context.Context, tx *sql.Tx) error {
		var timeout string
		if err := tx.QueryRowContext(ctx, `SHOW lock_timeout`).Scan(&timeout); err != nil {
			return err
		}
		if timeout != baseline {
			return fmt.Errorf("exclusive timeout changed: %q, want %q", timeout, baseline)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	t.Logf("WithTxShared PID=%d: local 8s overrides %q, real timeout rolls back both rows, retry commits once, baseline restored after rollback/commit, exclusive behavior preserved", workerPID, baseline)
}

func newStatusMgrPostgresDatabase(t *testing.T, ctx context.Context) (string, *sql.DB) {
	t.Helper()
	if os.Getenv("MS_ONCALL_CORE_MIGRATION_TEST_POSTGRES_ENABLE") != "1" {
		t.Skip("set MS_ONCALL_CORE_MIGRATION_TEST_POSTGRES_ENABLE=1 for disposable PostgreSQL tests")
	}
	baseURL := os.Getenv("DB_URL")
	if baseURL == "" {
		t.Fatal("DB_URL must be configured")
	}
	parsed, err := url.Parse(baseURL)
	if err != nil {
		t.Fatal(err)
	}
	admin := connectStatusMgrPostgres(t, ctx, baseURL)
	defer admin.Close(ctx)
	dbName := "msoc_c2_status_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{dbName}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		conn, err := pgx.Connect(cleanupCtx, baseURL)
		if err != nil {
			t.Error(err)
			return
		}
		defer conn.Close(cleanupCtx)
		if _, err := conn.Exec(cleanupCtx, "DROP DATABASE "+pgx.Identifier{dbName}.Sanitize()); err != nil {
			t.Error(err)
			return
		}
		var exists bool
		if err := conn.QueryRow(cleanupCtx, `SELECT EXISTS (SELECT FROM pg_database WHERE datname = $1)`, dbName).Scan(&exists); err != nil {
			t.Error(err)
		} else if exists {
			t.Errorf("task-owned database %s remains after cleanup", dbName)
		} else {
			t.Logf("cleanup verified: %s absent", dbName)
		}
	})
	parsed.Path = "/" + dbName
	testURL := parsed.String()
	if count, err := migrate.Up(ctx, testURL, ""); err != nil {
		t.Fatal(err)
	} else {
		t.Logf("task-owned database %s: canonical migrations=%d", dbName, count)
	}
	dbConfig, err := pgx.ParseConfig(testURL)
	if err != nil {
		t.Fatal(err)
	}
	db := stdlib.OpenDB(*dbConfig)
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Error(err)
		}
	})
	var version string
	if err := db.QueryRowContext(ctx, `SHOW server_version`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	t.Logf("PostgreSQL %s; worker pool pinned to one physical session", version)
	return testURL, db
}

func connectStatusMgrPostgres(t *testing.T, ctx context.Context, dbURL string) *pgx.Conn {
	t.Helper()
	conn, err := pgx.Connect(ctx, dbURL)
	if err != nil {
		t.Fatal(err)
	}
	return conn
}

func insertStatusMgrPostgresFixture(t *testing.T, ctx context.Context, conn *pgx.Conn) (subID, alertID int64) {
	t.Helper()
	orgID, policyID, serviceID, channelID := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	for _, stmt := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO organizations (id, classification, display_name, canonical_name) VALUES ($1, 'NORMAL', 'C2 Status Org', 'c2.status')`, []any{orgID}},
		{`INSERT INTO normal_organizations (organization_id, organization_classification, corporate_mapping_key, iana_time_zone) VALUES ($1, 'NORMAL', 'c2.status', 'Asia/Shanghai')`, []any{orgID}},
		{`INSERT INTO escalation_policies (id, organization_id, name) VALUES ($1, $2, 'C2 Status Policy')`, []any{policyID, orgID}},
		{`INSERT INTO services (id, organization_id, escalation_policy_id, name) VALUES ($1, $2, $3, 'C2 Status Service')`, []any{serviceID, orgID, policyID}},
		{`INSERT INTO notification_channels (id, type, name, value) VALUES ($1, 'SLACK', 'C2 Synthetic Channel', 'C2_SYNTHETIC_CHANNEL')`, []any{channelID}},
	} {
		if _, err := conn.Exec(ctx, stmt.sql, stmt.args...); err != nil {
			t.Fatal(err)
		}
	}
	if err := conn.QueryRow(ctx, `INSERT INTO alerts (service_id, status, summary, dedup_key) VALUES ($1, 'active', 'C2 Status Alert', 'c2-status') RETURNING id`, serviceID).Scan(&alertID); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(ctx, `INSERT INTO alert_logs (alert_id, event, message) VALUES ($1, 'acknowledged', 'C2 synthetic acknowledgement')`, alertID); err != nil {
		t.Fatal(err)
	}
	if err := conn.QueryRow(ctx, `INSERT INTO alert_status_subscriptions (alert_id, channel_id, last_alert_status) VALUES ($1, $2, 'triggered') RETURNING id`, alertID, channelID).Scan(&subID); err != nil {
		t.Fatal(err)
	}
	return subID, alertID
}

func waitForStatusMgrRowLock(t *testing.T, ctx context.Context, blocker *pgx.Conn, workerPID int, done <-chan error) {
	t.Helper()
	waitCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		var blocked bool
		if err := blocker.QueryRow(waitCtx, `SELECT $2::int = ANY(pg_blocking_pids($1::int))`, workerPID, blocker.PgConn().PID()).Scan(&blocked); err != nil {
			t.Fatal(err)
		}
		if blocked {
			t.Logf("deterministic synchronization: worker PID %d blocked by PID %d", workerPID, blocker.PgConn().PID())
			return
		}
		select {
		case err := <-done:
			t.Fatalf("worker returned before waiting for the existing row: %v (locked row must not become a successful missing-row no-op)", err)
		case <-waitCtx.Done():
			t.Fatal("worker did not enter PostgreSQL lock wait")
		case <-ticker.C:
		}
	}
}

func receiveStatusMgrResult(t *testing.T, ctx context.Context, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		t.Fatal("worker did not complete within the test deadline")
		return ctx.Err()
	}
}

func assertStatusMgrLockTimeoutError(t *testing.T, err error, elapsed time.Duration) {
	t.Helper()
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "55P03" {
		t.Fatalf("worker result = %v, want PostgreSQL lock timeout SQLSTATE 55P03", err)
	}
	if elapsed < 7*time.Second || elapsed > 20*time.Second {
		t.Fatalf("lock timeout elapsed %s, want approximately 8s", elapsed)
	}
	t.Logf("retryable worker error: SQLSTATE=%s message=%q elapsed=%s", pgErr.Code, pgErr.Message, elapsed)
}

func assertStatusMgrDurableWork(t *testing.T, ctx context.Context, conn *pgx.Conn, subID, alertID int64, expectedStatus string, expectedMessages int) {
	t.Helper()
	var status string
	var messages int
	if err := conn.QueryRow(ctx, `SELECT last_alert_status FROM alert_status_subscriptions WHERE id = $1`, subID).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if err := conn.QueryRow(ctx, `SELECT count(*) FROM outgoing_messages WHERE alert_id = $1 AND message_type = 'alert_status_update'`, alertID).Scan(&messages); err != nil {
		t.Fatal(err)
	}
	if status != expectedStatus || messages != expectedMessages {
		t.Fatalf("durable status/messages = %q/%d, want %q/%d", status, messages, expectedStatus, expectedMessages)
	}
}

func statusMgrLockTimeout(t *testing.T, ctx context.Context, db *sql.DB) string {
	t.Helper()
	var timeout string
	if err := db.QueryRowContext(ctx, `SHOW lock_timeout`).Scan(&timeout); err != nil {
		t.Fatal(err)
	}
	return timeout
}
