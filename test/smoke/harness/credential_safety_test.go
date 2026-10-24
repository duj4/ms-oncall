package harness

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	pkgerrors "github.com/pkg/errors"
)

type dbDiagnosticRecorder struct {
	output string
	fatal  int
	errors int
}

func (*dbDiagnosticRecorder) Helper() {}
func (r *dbDiagnosticRecorder) Fatalf(format string, args ...any) {
	r.fatal++
	r.output += fmt.Sprintf(format, args...)
}
func (r *dbDiagnosticRecorder) Errorf(format string, args ...any) {
	r.errors++
	r.output += fmt.Sprintf(format, args...)
}

// Formatting this error is itself a regression: diagnostics must never invoke
// an arbitrary Error method, including on an error wrapped by another error.
type unprintableDBError struct{}

func (unprintableDBError) Error() string { panic("unsafe Error method invoked") }

type credentialRollbackDriver struct{}
type credentialRollbackConn struct{ mode string }
type credentialRollbackTx struct{ mode string }

func (credentialRollbackDriver) Open(mode string) (driver.Conn, error) {
	return credentialRollbackConn{mode}, nil
}
func (credentialRollbackConn) Prepare(string) (driver.Stmt, error) { return nil, driver.ErrSkip }
func (credentialRollbackConn) Close() error                        { return nil }
func (c credentialRollbackConn) Begin() (driver.Tx, error)         { return credentialRollbackTx{c.mode}, nil }
func (credentialRollbackTx) Commit() error                         { return nil }
func (tx credentialRollbackTx) Rollback() error {
	switch tx.mode {
	case "rollback-success":
		return nil
	case "rollback-txdone":
		return sql.ErrTxDone
	case "rollback-conndone":
		return sql.ErrConnDone
	case "rollback-wrapped-txdone":
		return fmt.Errorf("r02_child_wrapped_txdone_secret: %w", sql.ErrTxDone)
	case "rollback-wrapped-conndone":
		return fmt.Errorf("r02_child_wrapped_conndone_secret: %w", sql.ErrConnDone)
	}
	err := errors.New("postgres://r02_child_rollback_user:r02_child_rollback_password@127.0.0.1/test?password=r02_child_rollback_query")
	if tx.mode == "rollback-wrapped" {
		return fmt.Errorf("r02_child_rollback_wrapper_secret: %w", err)
	}
	return err
}

func TestDBCredentialDiagnostics(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want string
	}{
		{"username and password URL", errors.New("postgres://r02_user_a:r02_password_a@127.0.0.1/test"), "database error (details withheld)"},
		{"escaped password URL", errors.New("postgres://r02_user_b:r02%40password%3Ab%2F%25@127.0.0.1/test"), "database error (details withheld)"},
		{"sensitive query parameters", pgconn.NewParseConfigError("postgres://r02_user_c@127.0.0.1/test?password=r02_query_password&sslpassword=r02_ssl_password&options=r02_options", "r02_parse_message", errors.New("r02_parse_cause")), "invalid PostgreSQL connection configuration"},
		{"URL without credentials", errors.New("postgres://127.0.0.1/test?sslmode=verify-full"), "database error (details withheld)"},
		{"username and metadata without password", errors.New("postgres://r02_user_d@127.0.0.1/test?application_name=r02_app&sslrootcert=r02_cert_path"), "database error (details withheld)"},
		{"connection error containing full DSN", fmt.Errorf("connect: %w", pgconn.NewParseConfigError("postgres://r02_user_e:r02_password_e@127.0.0.1/test", "r02_connect_message", nil)), "invalid PostgreSQL connection configuration"},
		{"wrapped password", pkgerrors.Wrap(errors.New("r02_wrapped_password"), "r02_wrapper_password"), "database error (details withheld)"},
		{"PostgreSQL SQLSTATE", fmt.Errorf("r02_pg_wrapper: %w", &pgconn.PgError{Code: "28P01", Message: "r02_pg_password", Detail: "r02_pg_detail", Hint: "r02_pg_hint", Where: "r02_pg_where"}), "PostgreSQL error (SQLSTATE 28P01)"},
		{"generic embedded credentials", errors.New("password=r02_generic_password sslpassword=r02_generic_ssl_password"), "database error (details withheld)"},
		{"invalid SQLSTATE", &pgconn.PgError{Code: "r02_sqlstate_password", Message: "r02_sqlstate_message"}, "PostgreSQL error (SQLSTATE unavailable)"},
		{"lowercase SQLSTATE", &pgconn.PgError{Code: "ab123"}, "PostgreSQL error (SQLSTATE unavailable)"},
		{"connection classification", &pgconn.ConnectError{Config: &pgconn.Config{User: "r02_config_user", Password: "r02_config_password", Database: "r02_config_database"}}, "PostgreSQL connection error"},
		{"deadline", fmt.Errorf("r02_deadline_password: %w", context.DeadlineExceeded), "database operation timed out"},
		{"cancellation", fmt.Errorf("r02_cancel_password: %w", context.Canceled), "database operation canceled"},
		{"network error", &net.OpError{Op: "r02_network_password", Err: errors.New("r02_network_cause")}, "database network error"},
		{"arbitrary Error method", unprintableDBError{}, "database error (details withheld)"},
		{"wrapped arbitrary Error method", pkgerrors.WithStack(unprintableDBError{}), "database error (details withheld)"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, fatal := range []bool{true, false} {
				r := new(dbDiagnosticRecorder)
				if fatal {
					requireDBNoError(r, tc.err, "connect to db")
				} else {
					assertDBNoError(r, tc.err, "connect to db")
				}
				if r.output != "connect to db: "+tc.want || strings.Contains(r.output, "r02_") || strings.Contains(r.output, "postgres://") {
					t.Fatalf("unexpected diagnostic: %q", r.output)
				}
				if (fatal && (r.fatal != 1 || r.errors != 0)) || (!fatal && (r.fatal != 0 || r.errors != 1)) {
					t.Fatal("fatal/nonfatal reporting behavior changed")
				}
			}
		})
	}
	r := new(dbDiagnosticRecorder)
	requireDBNoError(r, nil, "connect to db")
	assertDBNoError(r, nil, "connect to db")
	if r.output != "" || r.fatal != 0 || r.errors != 0 {
		t.Fatal("successful operations must not report errors")
	}
}

func TestDBURLCredentialCompatibility(t *testing.T) {
	originalString, originalURL := dbURLStr, dbURL
	t.Cleanup(func() { dbURLStr, dbURL = originalString, originalURL })
	for _, raw := range []string{
		"postgres://r02_url_user:r02_url_password@127.0.0.1/original?sslmode=verify-full",
		"postgres://r02_escaped_user:r02%40escaped%3Apassword%2F%25@127.0.0.1/original?sslmode=verify-full",
		"postgres://r02_query_user@127.0.0.1/original?password=r02_query_secret&sslpassword=r02_ssl_secret&options=r02_option_secret",
		"postgres://127.0.0.1/original",
		"postgres://r02_metadata_user@127.0.0.1/original?application_name=r02_metadata_app&sslmode=verify-full&sslrootcert=r02_metadata_path",
	} {
		var err error
		dbURLStr, dbURL = raw, nil
		dbURL, err = url.Parse(raw)
		if err != nil {
			t.Fatal("synthetic fixture must parse")
		}
		if DBURL("") != raw {
			t.Fatal("empty database name must return exact original bytes")
		}
		for _, name := range []string{"smoketest_r02", "space name", "slash/name", "percent%name"} {
			// Preserve the exact pre-repair implementation, including its escaping
			// behavior. No normalization or configuration rewriting is permitted.
			want := *dbURL
			want.Path = "/" + url.PathEscape(name)
			if DBURL(name) != want.String() {
				t.Fatal("named database connection URL changed")
			}
			got, err := url.Parse(DBURL(name))
			if err != nil || got.User.String() != dbURL.User.String() || got.RawQuery != dbURL.RawQuery || got.Host != dbURL.Host || got.Scheme != dbURL.Scheme {
				t.Fatal("connection credentials, query parameters or endpoint changed")
			}
		}
		if dbURLStr != raw || dbURL.String() != raw {
			t.Fatal("DBURL mutated the stored connection configuration")
		}
	}
}

func TestHarnessCredentialOutput(t *testing.T) {
	const marker = "GOALERT_R02_DIAGNOSTIC_CHILD"
	const dsn = "postgres://r02_child_user:r02_child_password@127.0.0.1/r02_child_db?connect_timeout=r02_child_query_secret"
	if mode := os.Getenv(marker); mode != "" {
		h := &Harness{t: t, dbURL: dsn, dbName: "smoketest_debug", closing: true, logsDone: make(chan struct{})}
		switch mode {
		case "connect":
			NewStoppedHarness(t, "", nil, "")
		case "organization":
			h.ensureSmokeOrganization()
		case "user-organization":
			h.ensureSmokeUserOrganizationAssignments()
		case "query":
			h.execQuery("-- "+dsn, nil)
		case "dump":
			h.dumpDB()
		case "migration":
			h.Migrate("")
		case "debug":
			stopForDebugDB(t, h.dbName)
		case "rollback", "rollback-wrapped", "rollback-success", "rollback-txdone", "rollback-conndone", "rollback-wrapped-txdone", "rollback-wrapped-conndone":
			sql.Register("r02-synthetic-rollback", credentialRollbackDriver{})
			db, err := sql.Open("r02-synthetic-rollback", mode)
			if err != nil {
				t.Fatal("synthetic database setup failed")
			}
			defer db.Close()
			tx, err := db.Begin()
			if err != nil {
				t.Fatal("synthetic transaction setup failed")
			}
			SQLRollback(t, dsn, tx)
			SQLRollback(t, dsn, tx) // database/sql's own ErrTxDone after the first rollback
		case "watch-error", "watch-fatal", "watch-info", "watch-ignored", "watch-sql", "watch-unknown":
			level := strings.TrimPrefix(mode, "watch-")
			if mode == "watch-ignored" {
				level = "error"
				wait := h.ExpectBackendError("r02_child_password")
				defer wait()
			}
			if mode == "watch-unknown" {
				level = "r02_child_level_secret"
			}
			entry := `{"level":"` + level + `","Source":"` + dsn + `","msg":"` + dsn + `","error":"` + dsn + `","extra":"` + dsn + `"}`
			if mode == "watch-sql" {
				entry = `{"level":"error","SQL":"r02_child_sql_secret","error":"` + dsn + `"}`
			}
			h.watchBackendLogs(strings.NewReader(entry))
		case "watch-structured":
			h.watchBackendLogs(strings.NewReader(`{"level":"error","error":{"Code":"28P01","Message":"` + dsn + `"}}`))
		case "watch-invalid-code":
			h.watchBackendLogs(strings.NewReader(`{"level":"error","error":{"Code":"r02_child_code_secret","Message":"` + dsn + `"}}`))
		case "watch-invalid-entry":
			h.watchBackendLogs(strings.NewReader(`{"msg":{"dsn":"` + dsn + `"},"error":"` + dsn + `"}`))
		case "watch-invalid-json":
			h.closing = false
			h.watchBackendLogs(strings.NewReader(`{"error":"` + dsn + `" invalid}`))
		case "watch-unmatched":
			h.ExpectBackendError(dsn)()
		}
		return
	}
	cases := []struct {
		mode string
		want string
		fail bool
	}{
		{"init", "parse smoke database URL:", true},
		{"connect", "connect to db: invalid PostgreSQL connection configuration", true},
		{"organization", "connect to install smoke Organization: invalid PostgreSQL connection configuration", true},
		{"user-organization", "connect to install smoke user Organization assignments: invalid PostgreSQL connection configuration", true},
		{"query", "exec query: invalid PostgreSQL connection configuration", true},
		{"dump", "connect to dump database: invalid PostgreSQL connection configuration", true},
		{"migration", "run migration: invalid PostgreSQL connection configuration", true},
		{"debug", `DEBUG DB: database "smoketest_debug"`, true},
		{"rollback", "rollback database transaction:", true},
		{"rollback-wrapped", "rollback database transaction:", true},
		{"rollback-success", "PASS", false},
		{"rollback-txdone", "PASS", false},
		{"rollback-conndone", "PASS", false},
		{"rollback-wrapped-txdone", "PASS", false},
		{"rollback-wrapped-conndone", "PASS", false},
		{"watch-error", "Backend: ERROR:", true},
		{"watch-fatal", "Backend: FATAL:", true},
		{"watch-info", "Backend: INFO:", false},
		{"watch-ignored", "Backend: IGNORE[ERROR]:", false},
		{"watch-unknown", "Backend: UNKNOWN:", false},
		{"watch-sql", "PASS", false},
		{"watch-structured", "SQLSTATE 28P01", true},
		{"watch-invalid-code", "SQLSTATE unavailable", true},
		{"watch-invalid-entry", "failed to parse log entry", false},
		{"watch-invalid-json", "failed to read JSON logs", true},
		{"watch-unmatched", "expected backend error was not observed", true},
	}
	for _, tc := range cases {
		t.Run(tc.mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestHarnessCredentialOutput$", "-test.v", "-test.timeout=12s")
			cmd.Dir = t.TempDir()
			for _, entry := range os.Environ() {
				if !strings.HasPrefix(entry, "DB_URL=") && !strings.HasPrefix(entry, marker+"=") && !strings.HasPrefix(entry, "PG") {
					cmd.Env = append(cmd.Env, entry)
				}
			}
			cmd.Env = append(cmd.Env, marker+"="+tc.mode, "DB_URL="+dsn)
			if tc.mode == "init" {
				cmd.Env[len(cmd.Env)-1] = "DB_URL=" + strings.Replace(dsn, "r02_child_password", "r02_child_init_secret%zz", 1)
			}
			output, err := cmd.CombinedOutput()
			if ctx.Err() != nil {
				t.Fatal("diagnostic subprocess exceeded deadline")
			}
			if tc.fail {
				var exitErr *exec.ExitError
				if !errors.As(err, &exitErr) || exitErr.ExitCode() == 0 {
					t.Fatal("expected intentional test failure or initialization panic")
				}
			} else if err != nil {
				t.Fatalf("expected success: %s", output)
			}
			if !strings.Contains(string(output), tc.want) {
				t.Fatalf("expected diagnostic %q: %s", tc.want, output)
			}
			if strings.Contains(string(output), "r02_child_") || strings.Contains(string(output), "postgres://") {
				t.Fatalf("credential-bearing diagnostic: %s", output)
			}
		})
	}
}

func TestBackendLogDrainAfterMalformedInput(t *testing.T) {
	h := &Harness{t: t, closing: true, logsDone: make(chan struct{})}
	r, w := io.Pipe()
	t.Cleanup(func() { r.Close(); w.Close() })
	go h.watchBackendLogs(r)
	written := make(chan error, 1)
	go func() {
		_, err := io.WriteString(w, "invalid JSON "+strings.Repeat("r02_drain_synthetic_secret", 10000))
		w.Close()
		written <- err
	}()
	select {
	case err := <-written:
		if err != nil {
			t.Fatal("watcher failed to drain the writer")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("watcher blocked the writer after a JSON error")
	}
	select {
	case <-h.logsDone:
	case <-time.After(3 * time.Second):
		t.Fatal("watcher did not signal completion")
	}
}
