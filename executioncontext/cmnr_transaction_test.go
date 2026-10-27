package executioncontext

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"testing"

	"github.com/target/goalert/gadb"
	"github.com/target/goalert/permission"
)

type cmnrTransactionDriver struct{ state *cmnrTransactionState }
type cmnrTransactionState struct{ begins, commits, rollbacks int }
type cmnrTransactionConn struct{ state *cmnrTransactionState }
type cmnrTransactionTx struct{ state *cmnrTransactionState }

func (d cmnrTransactionDriver) Open(string) (driver.Conn, error)             { return cmnrTransactionConn(d), nil }
func (d cmnrTransactionDriver) Connect(context.Context) (driver.Conn, error) { return d.Open("") }
func (d cmnrTransactionDriver) Driver() driver.Driver                        { return d }
func (c cmnrTransactionConn) Prepare(string) (driver.Stmt, error)            { return nil, errors.New("unused") }
func (c cmnrTransactionConn) Close() error                                   { return nil }
func (c cmnrTransactionConn) Begin() (driver.Tx, error) {
	c.state.begins++
	return cmnrTransactionTx(c), nil
}
func (c cmnrTransactionConn) ExecContext(context.Context, string, []driver.NamedValue) (driver.Result, error) {
	return driver.RowsAffected(1), nil
}
func (tx cmnrTransactionTx) Commit() error   { tx.state.commits++; return nil }
func (tx cmnrTransactionTx) Rollback() error { tx.state.rollbacks++; return nil }

func TestCMNRTransactionOwnership(t *testing.T) {
	for _, supplied := range []bool{false, true} {
		for _, reject := range []bool{false, true} {
			name := "owned"
			if supplied {
				name = "caller"
			}
			if reject {
				name += " rejection"
			}
			t.Run(name, func(t *testing.T) {
				state := new(cmnrTransactionState)
				db := sql.OpenDB(cmnrTransactionDriver{state})
				defer db.Close()
				var input gadb.DBTX = db
				var caller *sql.Tx
				var err error
				if supplied {
					caller, err = db.BeginTx(t.Context(), nil)
					if err != nil {
						t.Fatal(err)
					}
					defer func() { _ = caller.Rollback() }()
					input = caller
				}
				sentinel := errors.New("authorization rejected")
				err = WithCMNRTransaction(t.Context(), input, func(actual *sql.Tx) error {
					if supplied && actual != caller {
						t.Fatal("transaction identity changed")
					}
					if reject {
						return sentinel
					}
					return nil
				})
				if reject != errors.Is(err, sentinel) {
					t.Fatal("operation error not preserved")
				}
				if !reject && err != nil {
					t.Fatal(err)
				}
				if supplied {
					if state.commits != 0 || state.rollbacks != 0 {
						t.Fatal("Store completed caller transaction")
					}
					if _, err := caller.ExecContext(t.Context(), "probe"); err != nil {
						t.Fatal("caller transaction is no longer usable")
					}
				} else if (reject && state.rollbacks != 1) || (!reject && state.commits != 1) {
					t.Fatal("owned transaction did not commit or roll back as required")
				}
				if state.begins != 1 {
					t.Fatal("unexpected transaction count")
				}
			})
		}
	}
}

func TestCMNRConnectionOwnsItsTransaction(t *testing.T) {
	state := new(cmnrTransactionState)
	db := sql.OpenDB(cmnrTransactionDriver{state})
	defer db.Close()
	conn, err := db.Conn(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := WithCMNRTransaction(t.Context(), conn, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(t.Context(), "probe")
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if state.begins != 1 || state.commits != 1 || state.rollbacks != 0 {
		t.Fatal("connection-backed path did not own exactly one transaction")
	}
}

func TestCMNRUnsupportedDBTXFailsClosed(t *testing.T) {
	type unsupported struct{ *sql.DB }
	db := sql.OpenDB(cmnrTransactionDriver{new(cmnrTransactionState)})
	defer db.Close()
	var nilTx *sql.Tx
	var nilDB *sql.DB
	var nilConn *sql.Conn
	for _, input := range []gadb.DBTX{nil, unsupported{db}, nilTx, nilDB, nilConn} {
		called := false
		err := WithCMNRTransaction(t.Context(), input, func(*sql.Tx) error { called = true; return nil })
		if called || !permission.IsPermissionError(err) {
			t.Fatal("unsupported DBTX executed an unprotected operation")
		}
	}
}
