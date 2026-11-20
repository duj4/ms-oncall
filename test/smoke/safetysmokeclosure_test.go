package smoke

import (
	"context"
	"database/sql/driver"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/target/goalert/test/smoke/harness"
)

// These observers are private to the five SAFETY-SMOKE-CLOSURE1 tests. The
// accepted Preview/Confirmation and fault helpers remain byte-for-byte intact.
func safetySmokeSuccessState(t *testing.T, h *harness.Harness) map[string]string {
	t.Helper()
	result := make(map[string]string)
	for _, table := range []string{"service_delete_audit_events", "escalation_policy_delete_audit_events", "schedule_rotation_delete_audit_events", "user_override_delete_audit_events", "user_cmnr_delete_audit_events", "integration_key_delete_audit_events", "user_delete_audit_events", "user_delete_audit_effects"} {
		predicate := "record_kind='success_witness'"
		switch table {
		case "service_delete_audit_events":
			predicate = "outcome='committed'"
		case "user_delete_audit_effects":
			predicate = "true"
		}
		var digest string
		require.NoError(t, h.App().DB().QueryRow(`SELECT md5(coalesce(jsonb_agg(to_jsonb(e) ORDER BY to_jsonb(e)::text),'[]')::text) FROM `+table+` e WHERE `+predicate).Scan(&digest))
		result[table] = digest
	}
	return result
}

// This wrapper sits BELOW the unchanged acknowledgement injector. Each event
// therefore reports the result of the actual PostgreSQL Commit/Rollback call,
// before the injector replaces its response. No error is mocked here.
type safetySmokeNativeEvent struct {
	PID       int
	Operation string
	Succeeded bool
}

type safetySmokeNativeConnector struct {
	base   driver.Connector
	mu     sync.Mutex
	events []safetySmokeNativeEvent
}

func (c *safetySmokeNativeConnector) Driver() driver.Driver { return c.base.Driver() }
func (c *safetySmokeNativeConnector) Connect(ctx context.Context) (driver.Conn, error) {
	native, err := c.base.Connect(ctx)
	if err != nil {
		return nil, err
	}
	return &safetySmokeNativeConn{Conn: native, owner: c}, nil
}
func (c *safetySmokeNativeConnector) record(pid int, operation string, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.events = append(c.events, safetySmokeNativeEvent{PID: pid, Operation: operation, Succeeded: err == nil})
}
func (c *safetySmokeNativeConnector) snapshot() []safetySmokeNativeEvent {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]safetySmokeNativeEvent(nil), c.events...)
}

type safetySmokeNativeConn struct {
	driver.Conn
	owner *safetySmokeNativeConnector
}

func (c *safetySmokeNativeConn) BeginTx(ctx context.Context, opts driver.TxOptions) (driver.Tx, error) {
	pid, err := sd8NativePID(ctx, c.Conn)
	if err != nil {
		return nil, err
	}
	tx, err := c.Conn.(driver.ConnBeginTx).BeginTx(ctx, opts)
	c.owner.record(pid, "begin", err)
	if err != nil {
		return nil, err
	}
	return &safetySmokeNativeTx{Tx: tx, owner: c.owner, pid: pid}, nil
}
func (c *safetySmokeNativeConn) QueryContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Rows, error) {
	return c.Conn.(driver.QueryerContext).QueryContext(ctx, q, args)
}
func (c *safetySmokeNativeConn) ExecContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Result, error) {
	return c.Conn.(driver.ExecerContext).ExecContext(ctx, q, args)
}
func (c *safetySmokeNativeConn) PrepareContext(ctx context.Context, q string) (driver.Stmt, error) {
	return c.Conn.(driver.ConnPrepareContext).PrepareContext(ctx, q)
}

type safetySmokeNativeTx struct {
	driver.Tx
	owner *safetySmokeNativeConnector
	pid   int
}

func (tx *safetySmokeNativeTx) Commit() error {
	err := tx.Tx.Commit()
	tx.owner.record(tx.pid, "commit", err)
	return err
}
func (tx *safetySmokeNativeTx) Rollback() error {
	err := tx.Tx.Rollback()
	tx.owner.record(tx.pid, "rollback", err)
	return err
}
