package graphqlapp

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/rootcreateaudit"
	"github.com/target/goalert/validation"
)

// Deterministic transport/transaction fault tests complement real signed HTTP
// and PostgreSQL tests. They do not substitute for identity authorization.
type createFaultState struct {
	mode                    string
	creates, committedRoots int
	events                  [][]driver.NamedValue
}
type createFaultConnector struct{ state *createFaultState }

func (c createFaultConnector) Connect(context.Context) (driver.Conn, error) {
	return &createFaultConn{state: c.state}, nil
}
func (createFaultConnector) Driver() driver.Driver { return createFaultDriver{} }

type createFaultDriver struct{}

func (createFaultDriver) Open(string) (driver.Conn, error) {
	return nil, errors.New("connector required")
}

type createFaultConn struct {
	state *createFaultState
	tx    *createFaultTx
}

func (c *createFaultConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("unexpected prepare")
}
func (*createFaultConn) Close() error { return nil }
func (c *createFaultConn) Begin() (driver.Tx, error) {
	c.tx = &createFaultTx{conn: c}
	return c.tx, nil
}

type createFaultRows struct{ value driver.Value }

func (*createFaultRows) Columns() []string { return []string{"organization_id"} }
func (*createFaultRows) Close() error      { return nil }
func (r *createFaultRows) Next(out []driver.Value) error {
	if r.value == nil {
		return io.EOF
	}
	out[0] = r.value
	r.value = nil
	return nil
}
func (*createFaultConn) QueryContext(_ context.Context, q string, args []driver.NamedValue) (driver.Rows, error) {
	if !strings.Contains(q, "SELECT o.id FROM organizations") {
		return nil, errors.New("unexpected authority query")
	}
	return &createFaultRows{value: args[0].Value}, nil
}
func (c *createFaultConn) ExecContext(_ context.Context, q string, args []driver.NamedValue) (driver.Result, error) {
	if q == "A12 synthetic root create" {
		c.state.creates++
		c.tx.roots++
		return driver.RowsAffected(1), nil
	}
	if !strings.Contains(q, "INSERT INTO global_root_create_audit_events") {
		return nil, errors.New("unexpected write")
	}
	c.tx.events = append(c.tx.events, append([]driver.NamedValue(nil), args...))
	return driver.RowsAffected(1), nil
}

type createFaultTx struct {
	conn   *createFaultConn
	roots  int
	events [][]driver.NamedValue
}

func (tx *createFaultTx) Commit() error {
	s := tx.conn.state
	if tx.roots > 0 && s.mode == "rejected" {
		return &pgconn.PgError{Code: "23514"}
	}
	s.committedRoots += tx.roots
	s.events = append(s.events, tx.events...)
	if tx.roots > 0 && s.mode == "unknown" {
		return errors.New("synthetic lost commit response")
	}
	return nil
}
func (*createFaultTx) Rollback() error { return nil }

func TestRootCreateCommitUnknownAndRollbackAudit(t *testing.T) {
	for _, mode := range []string{"success", "unknown", "rejected", "validation"} {
		t.Run(mode, func(t *testing.T) {
			state := &createFaultState{mode: mode}
			db := sql.OpenDB(createFaultConnector{state})
			t.Cleanup(func() { require.NoError(t, db.Close()) })
			id, target := uuid.New(), uuid.New()
			e := rootcreateaudit.Event{EventID: uuid.New(), AttemptID: uuid.New(), RequestID: uuid.New(), ActorID: uuid.New(), HomeOrganizationID: uuid.New(), OrganizationRole: "ORG_MEMBER", RootType: "service", TargetOrganizationID: target, Outcome: "validation_failed", Reason: "invalid_fields", OccurredAt: time.Now()}
			p := &rootCreatePlan{ctx: t.Context(), db: db, target: target, audited: true, event: e}
			err := p.withTx(t.Context(), func(ctx context.Context, tx *sql.Tx) error {
				_, err := tx.ExecContext(ctx, "A12 synthetic root create")
				if err != nil {
					return err
				}
				if mode == "validation" {
					return validation.NewFieldError("input", "synthetic invalid child")
				}
				return nil
			}, func() string { return id.String() })
			err = p.finish(err)
			require.Equal(t, 1, state.creates, "Create must never replay after commit uncertainty")
			switch mode {
			case "success":
				require.NoError(t, err)
				require.Equal(t, 1, state.committedRoots)
				require.Len(t, state.events, 1)
				require.Equal(t, "committed", state.events[0][9].Value)
			case "unknown":
				require.Error(t, err)
				require.Equal(t, 1, state.committedRoots)
				require.Len(t, state.events, 2)
				require.Equal(t, "committed", state.events[0][9].Value)
				require.Equal(t, "commit_unknown", state.events[1][9].Value)
				require.Equal(t, state.events[0][1].Value, state.events[1][1].Value)
				require.NotEqual(t, state.events[0][0].Value, state.events[1][0].Value)
			case "rejected":
				require.Error(t, err)
				require.Zero(t, state.committedRoots)
				require.Len(t, state.events, 1)
				require.Equal(t, "tx_failed", state.events[0][9].Value)
			case "validation":
				require.Error(t, err)
				require.Zero(t, state.committedRoots)
				require.Len(t, state.events, 1)
				require.Equal(t, "validation_failed", state.events[0][9].Value)
				require.Nil(t, state.events[0][7].Value)
			}
		})
	}
}
