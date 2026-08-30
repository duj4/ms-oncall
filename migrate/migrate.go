package migrate

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/pkg/errors"
	"github.com/target/goalert/lock"
	"github.com/target/goalert/retry"
	"github.com/target/goalert/util/log"
	"github.com/target/goalert/util/sqlutil"
)

// LatestID will return the ID of the latest migration.
func LatestID() string {
	history := mustEmbeddedHistory()
	return history.latest().ID
}

// Names will return all migration names without the timestamps and extensions.
func Names() []string {
	history := mustEmbeddedHistory()
	names := make([]string, len(history.entries))
	for i, entry := range history.entries {
		names[i] = entry.Name
	}
	return names
}

// VerifyIsLatest will verify the latest migration is the same as the latest available migration.
//
// This ensures the DB isn't newer than the currently running code.
func VerifyIsLatest(ctx context.Context, url string) error {
	history, err := loadEmbeddedHistory()
	if err != nil {
		return err
	}
	conn, err := getConn(ctx, url)
	if err != nil {
		return err
	}
	defer conn.Close(ctx)
	if err := aquireLock(ctx, conn); err != nil {
		return err
	}

	resolved, err := loadAppliedHistory(ctx, conn, history)
	if err != nil {
		return fmt.Errorf("verify canonical migration history: %w", err)
	}
	appliedCount := resolvedAppliedCount(resolved)
	if appliedCount != len(history.entries) {
		dbLatest := ""
		if appliedCount > 0 {
			dbLatest = history.entries[appliedCount-1].ID
		}
		return errors.Errorf("latest migration in DB is '%s' but expected '%s'; local GoAlert version is likely older than the DB's latest migration (not allowed in SWO-mode)", dbLatest, history.latest().ID)
	}
	return nil
}

// VerifyAll will verify all migrations have already been applied.
func VerifyAll(ctx context.Context, url string) error {
	history, err := loadEmbeddedHistory()
	if err != nil {
		return err
	}
	conn, err := getConn(ctx, url)
	if err != nil {
		return err
	}
	defer conn.Close(ctx)
	if err := aquireLock(ctx, conn); err != nil {
		return err
	}

	resolved, err := loadAppliedHistory(ctx, conn, history)
	if err != nil {
		return fmt.Errorf("verify canonical migration history: %w", err)
	}
	if resolvedAppliedCount(resolved) == len(history.entries) {
		return nil
	}
	return errors.Errorf("latest migration '%s' has not been applied", history.latest().Name)
}

// ApplyAll will atomically perform all UP migrations.
func ApplyAll(ctx context.Context, url string) (int, error) {
	return Up(ctx, url, "")
}

func getConn(ctx context.Context, url string) (*pgx.Conn, error) {
	var conn *pgx.Conn
	err := retry.DoTemporaryError(func(int) error {
		var err error
		conn, err = pgx.Connect(ctx, url)
		return err
	},
		retry.Limit(12),
		retry.FibBackoff(time.Millisecond*100),
	)
	if err != nil {
		return nil, err
	}

	_, err = conn.Exec(ctx, "set lock_timeout = 15000")
	if err != nil {
		conn.Close(ctx)
		return nil, errors.Wrap(err, "set lock timeout")
	}

	return conn, nil
}

func aquireLock(ctx context.Context, conn *pgx.Conn) error {
	for {
		_, err := conn.Exec(ctx, "select pg_advisory_lock($1)", lock.GlobalMigrate)
		if err == nil {
			return nil
		}
		// 55P03 is lock_not_available
		// https://www.postgresql.org/docs/9.6/static/errcodes-appendix.html
		//
		// If the lock gets a timeout, terminate stale backends and try again.
		if e := sqlutil.MapError(err); e != nil && e.Code == "55P03" {
			log.Log(ctx, errors.Wrap(err, "get migration lock (will retry)"))
			_, err = conn.Exec(ctx, `
				select pg_terminate_backend(l.pid)
					from pg_locks l
					join pg_stat_activity act on act.pid = l.pid and state = 'idle' and state_change < now() - '30 seconds'::interval
					where locktype = 'advisory' and objid = $1 and granted
			`, lock.GlobalMigrate)
			if err != nil {
				conn.Close(ctx)
				return errors.Wrap(err, "terminate stale backends")
			}
			continue
		}
		return errors.Wrap(err, "get migration lock")
	}
}

func ensureMigrationTable(ctx context.Context, conn *pgx.Conn) error {
	_, err := conn.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS gorp_migrations (
			id text PRIMARY KEY,
			applied_at timestamp with time zone
		)
	`)
	if err != nil {
		return errors.Wrap(err, "ensure gorp_migrations table")
	}
	return nil
}

// Up will apply all migrations up to, and including, targetName.
// If targetName is empty, all available migrations are applied.
func Up(ctx context.Context, url, targetName string) (int, error) {
	history, err := loadEmbeddedHistory()
	if err != nil {
		return 0, err
	}
	if targetName == "" {
		targetName = history.latest().Name
	}
	targetIndex, ok := history.indexByName(targetName)
	if !ok {
		return 0, errors.Errorf("unknown migration target name '%s'", targetName)
	}

	conn, err := getConn(ctx, url)
	if err != nil {
		return 0, err
	}
	defer conn.Close(ctx)
	if err := ensureMigrationTable(ctx, conn); err != nil {
		return 0, err
	}
	if err := aquireLock(ctx, conn); err != nil {
		return 0, err
	}

	resolved, err := loadAppliedHistory(ctx, conn, history)
	if err != nil {
		return 0, fmt.Errorf("validate canonical migration history before Up: %w", err)
	}
	appliedCount := resolvedAppliedCount(resolved)
	if targetIndex < appliedCount {
		return 0, nil
	}

	migrations, err := parseMigrations(history)
	if err != nil {
		return 0, err
	}
	return performMigrations(ctx, conn, history, true, appliedCount, planUpMigrations(migrations, appliedCount, targetIndex))
}

// Down will roll back all migrations up to, but NOT including, targetName.
//
// If the DB contains unknown, gapped, or divergent history, err is returned.
func Down(ctx context.Context, url, targetName string) (int, error) {
	history, err := loadEmbeddedHistory()
	if err != nil {
		return 0, err
	}
	targetIndex, ok := history.indexByName(targetName)
	if !ok {
		return 0, errors.Errorf("unknown migration target name '%s'", targetName)
	}

	conn, err := getConn(ctx, url)
	if err != nil {
		return 0, err
	}
	defer conn.Close(ctx)
	if err := ensureMigrationTable(ctx, conn); err != nil {
		return 0, err
	}
	if err := aquireLock(ctx, conn); err != nil {
		return 0, err
	}

	resolved, err := loadAppliedHistory(ctx, conn, history)
	if err != nil {
		return 0, fmt.Errorf("validate canonical migration history before Down: %w", err)
	}
	appliedCount := resolvedAppliedCount(resolved)
	if targetIndex >= appliedCount-1 {
		return 0, nil
	}

	migrations, err := parseMigrations(history)
	if err != nil {
		return 0, err
	}
	return performMigrations(ctx, conn, history, false, appliedCount, planDownMigrations(migrations, appliedCount, targetIndex))
}

func planUpMigrations(migrations []migration, appliedCount, targetIndex int) []migration {
	return migrations[appliedCount : targetIndex+1]
}

func planDownMigrations(migrations []migration, appliedCount, targetIndex int) []migration {
	rollback := make([]migration, 0, appliedCount-targetIndex-1)
	for index := appliedCount - 1; index > targetIndex; index-- {
		rollback = append(rollback, migrations[index])
	}
	return rollback
}

func readMigration(id string) ([]byte, error) {
	data, err := migrationFS.ReadFile("migrations/" + id)
	if err != nil {
		return nil, fmt.Errorf("read 'migrations/%s': %w", id, err)
	}
	return data, nil
}

// DumpMigrations writes the validated canonical migration files and history manifest.
func DumpMigrations(dest string) error {
	history, err := loadEmbeddedHistory()
	if err != nil {
		return err
	}
	for _, entry := range history.entries {
		fullPath := filepath.Join(dest, "migrations", entry.ID)
		if err := os.MkdirAll(filepath.Dir(fullPath), 0o755); err != nil {
			return err
		}
		data, err := readMigration(entry.ID)
		if err != nil {
			return err
		}
		if err := os.WriteFile(fullPath, data, 0o644); err != nil {
			return errors.Wrapf(err, "write to %s", fullPath)
		}
	}
	manifestPath := filepath.Join(dest, "migration-history.json")
	if err := os.WriteFile(manifestPath, history.manifest, 0o644); err != nil {
		return errors.Wrapf(err, "write to %s", manifestPath)
	}
	return nil
}

type migration struct {
	ID   string
	Name string

	Up   migrationStep
	Down migrationStep
}

type migrationStep struct {
	statements []string
	disableTx  bool
	isUp       bool
	*migration
}

func parseMigrations(history *canonicalHistory) ([]migration, error) {
	migrations := make([]migration, len(history.entries))
	for index, entry := range history.entries {
		m := &migrations[index]
		m.ID = entry.ID
		m.Name = entry.Name
		data, err := readMigration(entry.ID)
		if err != nil {
			return nil, err
		}

		var up, down strings.Builder
		var isUp, isDown bool
		r := bufio.NewScanner(bytes.NewReader(data))
		for r.Scan() {
			line := r.Text()
			if strings.HasPrefix(line, "-- +migrate Up") {
				isUp = true
				isDown = false
				m.Up.disableTx = strings.Contains(line, "notransaction")
				continue
			}
			if strings.HasPrefix(line, "-- +migrate Down") {
				isUp = false
				isDown = true
				m.Down.disableTx = strings.Contains(line, "notransaction")
				continue
			}
			switch {
			case isUp:
				up.WriteString(line)
				up.WriteString("\n")
			case isDown:
				down.WriteString(line)
				down.WriteString("\n")
			}
		}
		if err := r.Err(); err != nil {
			return nil, fmt.Errorf("parse migration %q: %w", entry.ID, err)
		}

		m.Up.statements = sqlutil.SplitQuery(up.String())
		m.Up.isUp = true
		m.Up.migration = m
		m.Down.statements = sqlutil.SplitQuery(down.String())
		m.Down.migration = m
	}
	return migrations, nil
}

const (
	deleteMigrationRecord = "delete from gorp_migrations where id = $1"
	insertMigrationRecord = "insert into gorp_migrations (id, applied_at) values ($1, now())"
)

func (step migrationStep) applyNoTx(ctx context.Context, conn *pgx.Conn, history *canonicalHistory, legacyBoundary int) error {
	for index, stmt := range step.statements {
		if _, err := conn.Exec(ctx, stmt); err != nil {
			return errors.Wrapf(err, "statement #%d\n%s", index+1, stmt)
		}
	}

	if step.isUp {
		if _, err := conn.Exec(ctx, insertMigrationRecord, step.ID); err != nil {
			return errors.Wrap(err, "update gorp_migrations")
		}
		if err := recordAppliedProvenance(ctx, conn, history, step.ID, legacyBoundary); err != nil {
			return err
		}
		return nil
	}

	if err := deleteAppliedProvenance(ctx, conn, history, step.ID); err != nil {
		return err
	}
	tag, err := conn.Exec(ctx, deleteMigrationRecord, step.ID)
	if err != nil {
		return errors.Wrap(err, "update gorp_migrations")
	}
	if tag.RowsAffected() != 1 {
		return errors.Errorf("delete gorp_migrations record for %q affected %d rows, expected 1", step.ID, tag.RowsAffected())
	}
	return nil
}

func (step migrationStep) apply(ctx context.Context, conn *pgx.Conn, history *canonicalHistory, legacyBoundary int) error {
	if step.disableTx {
		return step.applyNoTx(ctx, conn, history, legacyBoundary)
	}

	tx, err := conn.Begin(ctx)
	if err != nil {
		return errors.Wrap(err, "begin tx")
	}
	defer sqlutil.RollbackContext(ctx, "migrate: apply", tx)

	// The transaction applies to the connection, so applyNoTx executes in it.
	if err := step.applyNoTx(ctx, conn, history, legacyBoundary); err != nil {
		return err
	}
	return errors.Wrap(tx.Commit(ctx), "commit")
}

func performMigrations(ctx context.Context, conn *pgx.Conn, history *canonicalHistory, applyUp bool, legacyBoundary int, migrations []migration) (int, error) {
	typ := "DOWN"
	if applyUp {
		typ = "UP"
	}

	for index, migration := range migrations {
		step := migration.Down
		if applyUp {
			step = migration.Up
		}

		start := time.Now()
		if err := step.apply(ctx, conn, history, legacyBoundary); err != nil {
			return index, errors.Wrapf(err, "apply '%s'", migration.Name)
		}
		log.Logf(ctx, "Applied %s migration '%s' in %s", typ, migration.Name, time.Since(start).Truncate(time.Millisecond))
	}
	return len(migrations), nil
}

func resolvedAppliedCount(resolved []resolvedCanonicalMigration) int {
	count := 0
	for _, entry := range resolved {
		if !entry.Applied {
			break
		}
		count++
	}
	return count
}
