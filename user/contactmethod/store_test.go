package contactmethod

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"net/http"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/target/goalert/config"
	"github.com/target/goalert/notification/nfydest"
	"github.com/target/goalert/notification/webhook"
	"github.com/target/goalert/permission"
	"github.com/target/goalert/validation"
)

const (
	testOnlyContactMethodUserID = "11111111-1111-1111-8111-111111111111"
	testOnlyContactMethodID     = "22222222-2222-4222-8222-222222222222"
)

type contactMethodUpdateTestConnector struct {
	state *contactMethodUpdateTestState
}

func (c contactMethodUpdateTestConnector) Connect(context.Context) (driver.Conn, error) {
	return &contactMethodUpdateTestConn{state: c.state}, nil
}

func (c contactMethodUpdateTestConnector) Driver() driver.Driver {
	return contactMethodUpdateTestDriver(c)
}

type contactMethodUpdateTestDriver struct {
	state *contactMethodUpdateTestState
}

func (d contactMethodUpdateTestDriver) Open(string) (driver.Conn, error) {
	return &contactMethodUpdateTestConn{state: d.state}, nil
}

type contactMethodUpdateTestState struct {
	mu         sync.Mutex
	queryCalls int
	execCalls  int
	currentURL string
}

type contactMethodUpdateTestConn struct {
	state *contactMethodUpdateTestState
}

func (*contactMethodUpdateTestConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("test-only prepare must not be used")
}

func (*contactMethodUpdateTestConn) Close() error { return nil }

func (*contactMethodUpdateTestConn) Begin() (driver.Tx, error) {
	return nil, errors.New("test-only transaction must not be used")
}

func (*contactMethodUpdateTestConn) CheckNamedValue(value *driver.NamedValue) error {
	if id, ok := value.Value.(uuid.UUID); ok {
		value.Value = id.String()
	}
	return nil
}

func (c *contactMethodUpdateTestConn) QueryContext(context.Context, string, []driver.NamedValue) (driver.Rows, error) {
	c.state.mu.Lock()
	defer c.state.mu.Unlock()
	c.state.queryCalls++
	destination, err := webhook.NewWebhookDest(c.state.currentURL).Value()
	if err != nil {
		return nil, errors.New("test-only destination encoding failed")
	}
	return &contactMethodUpdateTestRows{values: []driver.Value{
		destination,
		false,
		true,
		testOnlyContactMethodID,
		nil,
		nil,
		"Test-only Contact Method",
		false,
		"WEBHOOK",
		testOnlyContactMethodUserID,
		c.state.currentURL,
	}}, nil
}

func (c *contactMethodUpdateTestConn) ExecContext(context.Context, string, []driver.NamedValue) (driver.Result, error) {
	c.state.mu.Lock()
	defer c.state.mu.Unlock()
	c.state.execCalls++
	return nil, errors.New("test-only update must not execute")
}

type contactMethodUpdateTestRows struct {
	values []driver.Value
	done   bool
}

func (*contactMethodUpdateTestRows) Columns() []string { return make([]string, 11) }
func (*contactMethodUpdateTestRows) Close() error      { return nil }

func (r *contactMethodUpdateTestRows) Next(values []driver.Value) error {
	if r.done {
		return io.EOF
	}
	copy(values, r.values)
	r.done = true
	return nil
}

func TestContactMethodUpdateStillRejectsDestinationChange(t *testing.T) {
	state := &contactMethodUpdateTestState{currentURL: "https://current.test.invalid"}
	db := sql.OpenDB(contactMethodUpdateTestConnector{state: state})
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })

	var appConfig config.Config
	appConfig.Webhook.Enable = true
	ctx := appConfig.Context(permission.UserContext(context.Background(), testOnlyContactMethodUserID, permission.RoleAdmin))
	registry := nfydest.NewRegistry()
	registry.RegisterProvider(ctx, webhook.NewSender(ctx, http.DefaultClient))
	store := NewStore(registry)

	replacement := &ContactMethod{
		ID:     uuid.MustParse(testOnlyContactMethodID),
		Name:   "Test-only Contact Method",
		Dest:   webhook.NewWebhookDest("https://replacement.test.invalid"),
		UserID: testOnlyContactMethodUserID,
	}
	err := store.Update(ctx, db, replacement)
	fieldError, ok := err.(validation.FieldError)
	if !ok || fieldError.Field() != "Dest" || fieldError.Reason() != "cannot update destination of contact method" {
		t.Fatal("ordinary Contact Method update did not preserve destination immutability")
	}

	state.mu.Lock()
	defer state.mu.Unlock()
	if state.queryCalls != 1 || state.execCalls != 0 {
		t.Fatal("ordinary Contact Method destination rejection used an invalid database sequence")
	}
}

var _ driver.Connector = contactMethodUpdateTestConnector{}
var _ driver.QueryerContext = (*contactMethodUpdateTestConn)(nil)
var _ driver.ExecerContext = (*contactMethodUpdateTestConn)(nil)
var _ driver.NamedValueChecker = (*contactMethodUpdateTestConn)(nil)
