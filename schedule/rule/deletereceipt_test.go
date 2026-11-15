package rule

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/assignment"
	"github.com/target/goalert/permission"
)

type receiptFixture struct {
	rows    [][]driver.Value
	columns int
	lateErr error
	query   string
	args    []driver.NamedValue
}

func (f *receiptFixture) Connect(context.Context) (driver.Conn, error) { return &receiptConn{f}, nil }
func (*receiptFixture) Driver() driver.Driver                          { return receiptDriver{} }

type receiptDriver struct{}

func (receiptDriver) Open(string) (driver.Conn, error) { return nil, errors.New("connector required") }

type receiptConn struct{ f *receiptFixture }

func (*receiptConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("unexpected prepare")
}
func (*receiptConn) Close() error              { return nil }
func (*receiptConn) Begin() (driver.Tx, error) { return receiptTx{}, nil }
func (c *receiptConn) QueryContext(_ context.Context, q string, a []driver.NamedValue) (driver.Rows, error) {
	c.f.query = q
	c.f.args = a
	return &receiptRows{c.f, 0}, nil
}

type receiptTx struct{}

func (receiptTx) Commit() error   { return nil }
func (receiptTx) Rollback() error { return nil }

type receiptRows struct {
	f *receiptFixture
	i int
}

func (r *receiptRows) Columns() []string { return make([]string, r.f.columns) }
func (*receiptRows) Close() error        { return nil }
func (r *receiptRows) Next(d []driver.Value) error {
	if r.i == len(r.f.rows) {
		if r.f.lateErr != nil {
			return r.f.lateErr
		}
		return io.EOF
	}
	copy(d, r.f.rows[r.i])
	r.i++
	return nil
}
func receiptTestTx(t *testing.T, f *receiptFixture) (context.Context, *sql.Tx) {
	t.Helper()
	db := sql.OpenDB(f)
	t.Cleanup(func() { require.NoError(t, db.Close()) })
	ctx := permission.SystemContext(context.Background(), "RuleReceiptTest")
	tx, err := db.BeginTx(ctx, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = tx.Rollback() })
	return ctx, tx
}

func TestDeleteManyReceiptActualRowsAndClosedIdentity(t *testing.T) {
	for _, kind := range []string{"user", "rotation"} {
		t.Run(kind, func(t *testing.T) {
			id, parent, target := uuid.New(), uuid.New(), uuid.New()
			var u, rot driver.Value
			var selected assignment.Target = assignment.UserTarget(target.String())
			if kind == "user" {
				u = target.String()
			} else {
				rot = target.String()
				selected = assignment.RotationTarget(target.String())
			}
			for _, mode := range []string{"one_of_two", "zero", "ambiguous", "no_target", "wrong_parent", "wrong_target", "nil_id", "invalid_scan", "late_error"} {
				t.Run(mode, func(t *testing.T) {
					row := []driver.Value{id.String(), parent.String(), u, rot}
					f := &receiptFixture{columns: 4, rows: [][]driver.Value{row}}
					switch mode {
					case "zero":
						f.rows = nil
					case "ambiguous":
						row[2], row[3] = target.String(), target.String()
					case "no_target":
						row[2], row[3] = nil, nil
					case "wrong_parent":
						row[1] = uuid.NewString()
					case "wrong_target":
						if kind == "user" {
							row[2] = uuid.NewString()
						} else {
							row[3] = uuid.NewString()
						}
					case "nil_id":
						row[0] = uuid.Nil.String()
					case "invalid_scan":
						row[0] = "synthetic-invalid-uuid"
					case "late_error":
						f.lateErr = errors.New("synthetic late row failure")
					}
					ctx, tx := receiptTestTx(t, f)
					result, err := new(Store).DeleteManyReceiptTx(ctx, tx, parent.String(), selected, []string{id.String(), uuid.NewString()})
					if mode == "zero" {
						require.NoError(t, err)
						require.Empty(t, result)
					} else if mode == "one_of_two" {
						require.NoError(t, err)
						require.Equal(t, []DeleteReceipt{{ID: id, ScheduleID: parent, TargetKind: kind, TargetID: target}}, result)
					} else {
						require.Error(t, err)
						require.Nil(t, result)
					}
					require.Equal(t, deleteManyReceiptSQL, f.query)
					require.Len(t, f.args, 4)
				})
			}
		})
	}
}

func TestRuleReceiptAndLockRequireTransactionAndAuthority(t *testing.T) {
	s := new(Store)
	ctx := permission.SystemContext(context.Background(), "RuleReceiptTest")
	id := uuid.NewString()
	_, err := s.DeleteManyReceiptTx(ctx, nil, id, assignment.UserTarget(id), []string{id})
	require.Error(t, err)
	require.Error(t, s.LockScheduleRulesTx(ctx, nil, id))
	f := &receiptFixture{columns: 1, rows: [][]driver.Value{{uuid.NewString()}}}
	ctx, tx := receiptTestTx(t, f)
	require.NoError(t, s.LockScheduleRulesTx(ctx, tx, id))
	require.Equal(t, `SELECT id FROM schedule_rules WHERE schedule_id=$1 ORDER BY id FOR UPDATE`, f.query)
	f.lateErr = errors.New("late lock failure")
	require.Error(t, s.LockScheduleRulesTx(ctx, tx, id))
	require.Error(t, s.LockScheduleRulesTx(context.Background(), tx, id))
	_, err = s.DeleteManyReceiptTx(context.Background(), tx, id, assignment.UserTarget(id), []string{id})
	require.Error(t, err)
}
