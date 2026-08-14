package webhook

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/target/goalert/gadb"
	"github.com/target/goalert/permission"
)

var testOnlyGatewayCASContactMethodID = uuid.MustParse("123e4567-e89b-12d3-a456-426614174001")

type gatewayDestinationTokenURLCASSpy struct {
	mu          sync.Mutex
	calls       int
	expected    gadb.DestV1
	replacement gadb.DestV1
	rows        int64
	err         error
}

func (s *gatewayDestinationTokenURLCASSpy) CompareAndSwapGatewayDestination(_ context.Context, _ uuid.UUID, expected, replacement gadb.DestV1) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	s.expected = expected
	s.replacement = replacement
	return s.rows, s.err
}

func (s *gatewayDestinationTokenURLCASSpy) callCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

func testOnlyGatewayCASReplacementToken(seed byte) string {
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = seed + byte(i)
	}
	return "mso1_" + base64.RawURLEncoding.EncodeToString(raw)
}

func testOnlyGatewayCASSuccessRequest() GatewayDestinationTokenURLCASRequest {
	return NewGatewayDestinationTokenURLCASRequest(
		testOnlyGatewayCASContactMethodID,
		testOnlyGatewayURL,
		testOnlyGatewayCASReplacementToken(0x40),
	)
}

func testOnlyGatewayCASService(t *testing.T, repository gatewayDestinationTokenURLCASRepository) *GatewayDestinationTokenURLCAS {
	t.Helper()
	matcher, err := NewGatewayTargetMatcher(testOnlyGatewayOrigin)
	if err != nil {
		t.Fatal("failed to create test-only Gateway matcher")
	}
	service, err := newGatewayDestinationTokenURLCASWithRepository(matcher, repository)
	if err != nil {
		t.Fatal("failed to create test-only Gateway CAS service")
	}
	return service
}

func testOnlyGatewayCASSystemContext() context.Context {
	return permission.SystemContext(context.Background(), "GatewayTokenCASTest")
}

func requireGatewayCASFixedError(t *testing.T, got, want, private error) {
	t.Helper()
	if got != want {
		t.Fatal("unexpected fixed Gateway CAS error classification")
	}
	if private != nil && errors.Is(got, private) {
		t.Fatal("Gateway CAS error retained a private dependency chain")
	}
	if private != nil && strings.Contains(got.Error(), private.Error()) {
		t.Fatal("Gateway CAS error exposed private dependency content")
	}
}

func TestGatewayDestinationTokenURLCASBuildsTokenOnlyReplacement(t *testing.T) {
	repository := &gatewayDestinationTokenURLCASSpy{rows: 1}
	service := testOnlyGatewayCASService(t, repository)
	replacementToken := testOnlyGatewayCASReplacementToken(0x40)
	expectedURL := "https://gateway.test.invalid:443" + testOnlyGatewayPath
	request := NewGatewayDestinationTokenURLCASRequest(testOnlyGatewayCASContactMethodID, expectedURL, replacementToken)

	if err := service.CompareAndSwap(testOnlyGatewayCASSystemContext(), request); err != nil {
		t.Fatal("valid Gateway CAS request failed")
	}
	if repository.callCount() != 1 {
		t.Fatal("valid Gateway CAS request did not call repository exactly once")
	}
	if repository.expected.Type != DestTypeWebhook || len(repository.expected.Args) != 1 ||
		repository.replacement.Type != DestTypeWebhook || len(repository.replacement.Args) != 1 {
		t.Fatal("Gateway CAS constructed an invalid destination shape")
	}
	if repository.expected.Arg(FieldWebhookURL) != expectedURL {
		t.Fatal("Gateway CAS changed the expected URL")
	}
	replacementURL := repository.replacement.Arg(FieldWebhookURL)
	if replacementURL != strings.TrimSuffix(expectedURL, testOnlyGatewayToken)+replacementToken {
		t.Fatal("Gateway CAS changed bytes outside the token segment")
	}
	if !strings.Contains(replacementURL, ":443/") {
		t.Fatal("Gateway CAS did not preserve the explicit canonical port")
	}
}

func TestGatewayDestinationTokenURLCASRejectsInvalidInputsBeforeRepository(t *testing.T) {
	replacement := testOnlyGatewayCASReplacementToken(0x40)
	tests := []struct {
		name     string
		id       uuid.UUID
		expected string
		token    string
	}{
		{name: "zero contact method ID", expected: testOnlyGatewayURL, token: replacement},
		{name: "ordinary webhook", id: testOnlyGatewayCASContactMethodID, expected: "https://hooks.test.invalid/notify", token: replacement},
		{name: "wrong origin", id: testOnlyGatewayCASContactMethodID, expected: "https://other.test.invalid" + testOnlyGatewayPath, token: replacement},
		{name: "HTTP", id: testOnlyGatewayCASContactMethodID, expected: "http://gateway.test.invalid" + testOnlyGatewayPath, token: replacement},
		{name: "host case", id: testOnlyGatewayCASContactMethodID, expected: "https://Gateway.test.invalid" + testOnlyGatewayPath, token: replacement},
		{name: "wrong port", id: testOnlyGatewayCASContactMethodID, expected: "https://gateway.test.invalid:444" + testOnlyGatewayPath, token: replacement},
		{name: "userinfo", id: testOnlyGatewayCASContactMethodID, expected: "https://user@gateway.test.invalid" + testOnlyGatewayPath, token: replacement},
		{name: "query", id: testOnlyGatewayCASContactMethodID, expected: testOnlyGatewayURL + "?route=test", token: replacement},
		{name: "empty query", id: testOnlyGatewayCASContactMethodID, expected: testOnlyGatewayURL + "?", token: replacement},
		{name: "fragment", id: testOnlyGatewayCASContactMethodID, expected: testOnlyGatewayURL + "#test", token: replacement},
		{name: "empty fragment", id: testOnlyGatewayCASContactMethodID, expected: testOnlyGatewayURL + "#", token: replacement},
		{name: "encoded route", id: testOnlyGatewayCASContactMethodID, expected: testOnlyGatewayOrigin + "/v1/goalert/contact%2Dmethod/" + testOnlyGatewayToken, token: replacement},
		{name: "encoded token", id: testOnlyGatewayCASContactMethodID, expected: testOnlyGatewayOrigin + gatewayContactMethodPathPrefix + "mso1_%41AECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8", token: replacement},
		{name: "duplicate slash", id: testOnlyGatewayCASContactMethodID, expected: testOnlyGatewayOrigin + "/v1/goalert//contact-method/" + testOnlyGatewayToken, token: replacement},
		{name: "dot segment", id: testOnlyGatewayCASContactMethodID, expected: testOnlyGatewayOrigin + "/v1/goalert/./contact-method/" + testOnlyGatewayToken, token: replacement},
		{name: "path suffix", id: testOnlyGatewayCASContactMethodID, expected: testOnlyGatewayURL + "/extra", token: replacement},
		{name: "wrong prefix", id: testOnlyGatewayCASContactMethodID, expected: testOnlyGatewayOrigin + gatewayContactMethodPathPrefix + "mso2_" + strings.TrimPrefix(testOnlyGatewayToken, "mso1_"), token: replacement},
		{name: "padded old token", id: testOnlyGatewayCASContactMethodID, expected: testOnlyGatewayURL + "=", token: replacement},
		{name: "wrong old token length", id: testOnlyGatewayCASContactMethodID, expected: testOnlyGatewayURL[:len(testOnlyGatewayURL)-1], token: replacement},
		{name: "old token alphabet", id: testOnlyGatewayCASContactMethodID, expected: testOnlyGatewayURL[:len(testOnlyGatewayURL)-1] + "+", token: replacement},
		{name: "same token", id: testOnlyGatewayCASContactMethodID, expected: testOnlyGatewayURL, token: testOnlyGatewayToken},
		{name: "empty replacement", id: testOnlyGatewayCASContactMethodID, expected: testOnlyGatewayURL},
		{name: "replacement prefix", id: testOnlyGatewayCASContactMethodID, expected: testOnlyGatewayURL, token: "mso2_" + strings.TrimPrefix(replacement, "mso1_")},
		{name: "replacement padding", id: testOnlyGatewayCASContactMethodID, expected: testOnlyGatewayURL, token: replacement + "="},
		{name: "replacement length", id: testOnlyGatewayCASContactMethodID, expected: testOnlyGatewayURL, token: replacement[:len(replacement)-1]},
		{name: "replacement alphabet", id: testOnlyGatewayCASContactMethodID, expected: testOnlyGatewayURL, token: replacement[:len(replacement)-1] + "+"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			repository := &gatewayDestinationTokenURLCASSpy{rows: 1}
			service := testOnlyGatewayCASService(t, repository)
			request := NewGatewayDestinationTokenURLCASRequest(test.id, test.expected, test.token)
			err := service.CompareAndSwap(testOnlyGatewayCASSystemContext(), request)
			requireGatewayCASFixedError(t, err, ErrGatewayDestinationTokenURLCASInvalid, nil)
			if repository.callCount() != 0 {
				t.Fatal("invalid Gateway CAS request reached repository")
			}
		})
	}
}

func TestGatewayDestinationTokenURLCASValidatesDependencies(t *testing.T) {
	matcher, err := NewGatewayTargetMatcher(testOnlyGatewayOrigin)
	if err != nil {
		t.Fatal("failed to create test-only Gateway matcher")
	}
	var typedNilRepository *gatewayDestinationTokenURLCASSpy

	for _, test := range []struct {
		name       string
		matcher    *GatewayTargetMatcher
		repository gatewayDestinationTokenURLCASRepository
	}{
		{name: "nil matcher", repository: &gatewayDestinationTokenURLCASSpy{}},
		{name: "invalid matcher", matcher: &GatewayTargetMatcher{}, repository: &gatewayDestinationTokenURLCASSpy{}},
		{name: "nil repository", matcher: matcher},
		{name: "typed nil repository", matcher: matcher, repository: typedNilRepository},
	} {
		t.Run(test.name, func(t *testing.T) {
			service, err := newGatewayDestinationTokenURLCASWithRepository(test.matcher, test.repository)
			if service != nil {
				t.Fatal("invalid Gateway CAS dependency returned a service")
			}
			requireGatewayCASFixedError(t, err, ErrGatewayDestinationTokenURLCASInvalid, nil)
		})
	}

	service, err := NewGatewayDestinationTokenURLCAS(matcher, nil)
	if service != nil {
		t.Fatal("nil database returned a Gateway CAS service")
	}
	requireGatewayCASFixedError(t, err, ErrGatewayDestinationTokenURLCASInvalid, nil)

	err = new(GatewayDestinationTokenURLCAS).CompareAndSwap(testOnlyGatewayCASSystemContext(), testOnlyGatewayCASSuccessRequest())
	requireGatewayCASFixedError(t, err, ErrGatewayDestinationTokenURLCASInvalid, nil)
}

func TestGatewayDestinationTokenURLCASRequiresSystemPermission(t *testing.T) {
	contexts := []struct {
		name string
		ctx  context.Context
	}{
		{name: "unauthenticated", ctx: context.Background()},
		{name: "user", ctx: permission.UserContext(context.Background(), "11111111-1111-1111-8111-111111111111", permission.RoleUser)},
		{name: "admin", ctx: permission.UserContext(context.Background(), "11111111-1111-1111-8111-111111111111", permission.RoleAdmin)},
		{name: "service", ctx: permission.ServiceContext(context.Background(), "11111111-1111-1111-8111-111111111111")},
		{name: "team", ctx: permission.TeamContext(context.Background(), "11111111-1111-1111-8111-111111111111")},
	}

	for _, test := range contexts {
		t.Run(test.name, func(t *testing.T) {
			repository := &gatewayDestinationTokenURLCASSpy{rows: 1}
			service := testOnlyGatewayCASService(t, repository)
			err := service.CompareAndSwap(test.ctx, testOnlyGatewayCASSuccessRequest())
			requireGatewayCASFixedError(t, err, ErrGatewayDestinationTokenURLCASPermissionDenied, nil)
			if repository.callCount() != 0 {
				t.Fatal("non-System Gateway CAS request reached repository")
			}
		})
	}

	repository := &gatewayDestinationTokenURLCASSpy{rows: 1}
	service := testOnlyGatewayCASService(t, repository)
	if err := service.CompareAndSwap(testOnlyGatewayCASSystemContext(), testOnlyGatewayCASSuccessRequest()); err != nil {
		t.Fatal("System Gateway CAS request failed")
	}
	if repository.callCount() != 1 {
		t.Fatal("System Gateway CAS request did not reach repository exactly once")
	}
}

func TestGatewayDestinationTokenURLCASContextBoundaries(t *testing.T) {
	tests := []struct {
		name string
		ctx  func() context.Context
		want error
	}{
		{
			name: "canceled",
			ctx: func() context.Context {
				ctx, cancel := context.WithCancel(testOnlyGatewayCASSystemContext())
				cancel()
				return ctx
			},
			want: ErrGatewayDestinationTokenURLCASCanceled,
		},
		{
			name: "deadline",
			ctx: func() context.Context {
				ctx, cancel := context.WithDeadline(testOnlyGatewayCASSystemContext(), time.Unix(1, 0))
				cancel()
				return ctx
			},
			want: ErrGatewayDestinationTokenURLCASDeadlineExceeded,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			repository := &gatewayDestinationTokenURLCASSpy{rows: 1}
			service := testOnlyGatewayCASService(t, repository)
			err := service.CompareAndSwap(test.ctx(), testOnlyGatewayCASSuccessRequest())
			requireGatewayCASFixedError(t, err, test.want, nil)
			if repository.callCount() != 0 {
				t.Fatal("pre-failed Gateway CAS context reached repository")
			}
		})
	}
}

func TestGatewayDestinationTokenURLCASAffectedRowsAndSafeErrors(t *testing.T) {
	private := errors.New("test-only-private-repository-marker:" + testOnlyGatewayToken)
	tests := []struct {
		name string
		rows int64
		err  error
		want error
	}{
		{name: "one row", rows: 1},
		{name: "zero rows", want: ErrGatewayDestinationTokenURLCASConflict},
		{name: "multiple rows", rows: 2, want: ErrGatewayDestinationTokenURLCASUnavailable},
		{name: "negative rows", rows: -1, want: ErrGatewayDestinationTokenURLCASUnavailable},
		{name: "safe unavailable", err: ErrGatewayDestinationTokenURLCASUnavailable, want: ErrGatewayDestinationTokenURLCASUnavailable},
		{name: "safe conflict", err: ErrGatewayDestinationTokenURLCASConflict, want: ErrGatewayDestinationTokenURLCASConflict},
		{name: "safe outcome unknown", err: ErrGatewayDestinationTokenURLCASOutcomeUnknown, want: ErrGatewayDestinationTokenURLCASOutcomeUnknown},
		{name: "private dependency", err: private, want: ErrGatewayDestinationTokenURLCASOutcomeUnknown},
		{name: "wrapped private dependency", err: fmt.Errorf("test-only outer: %w", private), want: ErrGatewayDestinationTokenURLCASOutcomeUnknown},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			repository := &gatewayDestinationTokenURLCASSpy{rows: test.rows, err: test.err}
			service := testOnlyGatewayCASService(t, repository)
			err := service.CompareAndSwap(testOnlyGatewayCASSystemContext(), testOnlyGatewayCASSuccessRequest())
			if test.want == nil {
				if err != nil {
					t.Fatal("successful Gateway CAS returned an error")
				}
			} else {
				requireGatewayCASFixedError(t, err, test.want, private)
			}
			if repository.callCount() != 1 {
				t.Fatal("Gateway CAS retried repository operation")
			}
		})
	}
}

type gatewayCASAtomicRepository struct {
	mu      sync.Mutex
	current string
	calls   int
}

func (r *gatewayCASAtomicRepository) CompareAndSwapGatewayDestination(_ context.Context, _ uuid.UUID, expected, replacement gadb.DestV1) (int64, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls++
	if r.current != expected.Arg(FieldWebhookURL) {
		return 0, nil
	}
	r.current = replacement.Arg(FieldWebhookURL)
	return 1, nil
}

func TestGatewayDestinationTokenURLCASConcurrentLosersCannotOverwriteWinner(t *testing.T) {
	const attempts = 32
	repository := &gatewayCASAtomicRepository{current: testOnlyGatewayURL}
	service := testOnlyGatewayCASService(t, repository)
	ctx := testOnlyGatewayCASSystemContext()

	results := make(chan error, attempts)
	var wg sync.WaitGroup
	for i := 0; i < attempts; i++ {
		wg.Add(1)
		go func(seed byte) {
			defer wg.Done()
			request := NewGatewayDestinationTokenURLCASRequest(
				testOnlyGatewayCASContactMethodID,
				testOnlyGatewayURL,
				testOnlyGatewayCASReplacementToken(seed),
			)
			results <- service.CompareAndSwap(ctx, request)
		}(byte(0x40 + i))
	}
	wg.Wait()
	close(results)

	var success, conflicts int
	for err := range results {
		switch err {
		case nil:
			success++
		case ErrGatewayDestinationTokenURLCASConflict:
			conflicts++
		default:
			t.Fatal("concurrent Gateway CAS returned an invalid classification")
		}
	}
	if success != 1 || conflicts != attempts-1 {
		t.Fatal("concurrent Gateway CAS did not preserve single-winner semantics")
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	if repository.calls != attempts || repository.current == testOnlyGatewayURL {
		t.Fatal("concurrent Gateway CAS repository state is invalid")
	}
}

func TestGatewayDestinationTokenURLCASSensitiveFormatting(t *testing.T) {
	repository := &gatewayDestinationTokenURLCASSpy{}
	service := testOnlyGatewayCASService(t, repository)
	request := testOnlyGatewayCASSuccessRequest()

	for _, value := range []any{request, &request, *service, service} {
		if fmt.Sprintf("%v", value) != "[redacted]" ||
			fmt.Sprintf("%+v", value) != "[redacted]" ||
			fmt.Sprintf("%#v", value) != "[redacted]" ||
			fmt.Sprintf("%s", value) != "[redacted]" {
			t.Fatal("Gateway CAS sensitive value formatting was not redacted")
		}
	}
}

type gatewayCASTestConnector struct {
	conn *gatewayCASTestDriverConn
}

func (c gatewayCASTestConnector) Connect(context.Context) (driver.Conn, error) { return c.conn, nil }
func (gatewayCASTestConnector) Driver() driver.Driver                          { return gatewayCASTestDriver{} }

type gatewayCASTestDriver struct{}

func (gatewayCASTestDriver) Open(string) (driver.Conn, error) {
	return nil, errors.New("test-only unsupported driver open")
}

type gatewayCASTestDriverConn struct {
	mu         sync.Mutex
	calls      int
	closed     int
	physical   *gatewayCASTestPhysicalConnection
	query      string
	args       []driver.NamedValue
	result     driver.Result
	err        error
	beforeExec func()
}

type gatewayCASTestPhysicalConnection struct {
	mu     sync.Mutex
	closed int
}

func (c *gatewayCASTestPhysicalConnection) Close(context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed++
	return nil
}

func (c *gatewayCASTestPhysicalConnection) closeCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed
}

func (c *gatewayCASTestDriverConn) gatewayDestinationTokenURLCASConnection() gatewayDestinationTokenURLCASConnectionCloser {
	return c.physical
}

func (c *gatewayCASTestDriverConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("test-only prepare must not be used")
}

func (c *gatewayCASTestDriverConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed++
	return nil
}

func (c *gatewayCASTestDriverConn) Begin() (driver.Tx, error) {
	return nil, errors.New("test-only transaction must not be used")
}

func (*gatewayCASTestDriverConn) CheckNamedValue(value *driver.NamedValue) error {
	valuer, ok := value.Value.(driver.Valuer)
	if !ok {
		return nil
	}
	converted, err := valuer.Value()
	if err != nil {
		return err
	}
	if raw, ok := converted.(json.RawMessage); ok {
		converted = []byte(raw)
	}
	value.Value = converted
	return nil
}

func (c *gatewayCASTestDriverConn) ExecContext(_ context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	c.mu.Lock()
	c.calls++
	c.query = query
	c.args = append([]driver.NamedValue(nil), args...)
	result, err, beforeExec := c.result, c.err, c.beforeExec
	c.mu.Unlock()
	if beforeExec != nil {
		beforeExec()
	}
	return result, err
}

type gatewayCASTestResult struct {
	rows int64
	err  error
}

func (gatewayCASTestResult) LastInsertId() (int64, error) {
	return 0, errors.New("test-only unsupported last insert ID")
}
func (r gatewayCASTestResult) RowsAffected() (int64, error) { return r.rows, r.err }

type gatewayCASTestPointerResult struct{}

func (*gatewayCASTestPointerResult) LastInsertId() (int64, error) {
	return 0, errors.New("test-only unsupported last insert ID")
}
func (*gatewayCASTestPointerResult) RowsAffected() (int64, error) {
	return 0, errors.New("test-only typed nil result must not be called")
}

func testOnlyGatewayCASDatabase(t *testing.T, conn *gatewayCASTestDriverConn) *sql.DB {
	t.Helper()
	db := sql.OpenDB(gatewayCASTestConnector{conn: conn})
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func testOnlyGatewayCASPublicService(t *testing.T, db *sql.DB) *GatewayDestinationTokenURLCAS {
	t.Helper()
	matcher, err := NewGatewayTargetMatcher(testOnlyGatewayOrigin)
	if err != nil {
		t.Fatal("failed to create test-only Gateway matcher")
	}
	service, err := NewGatewayDestinationTokenURLCAS(matcher, db)
	if err != nil {
		t.Fatal("failed to create test-only SQL Gateway CAS service")
	}
	return service
}

func TestGatewayDestinationTokenURLCASSQLUsesExactSingleConditionalUpdate(t *testing.T) {
	conn := &gatewayCASTestDriverConn{result: gatewayCASTestResult{rows: 1}}
	service := testOnlyGatewayCASPublicService(t, testOnlyGatewayCASDatabase(t, conn))
	if err := service.CompareAndSwap(testOnlyGatewayCASSystemContext(), testOnlyGatewayCASSuccessRequest()); err != nil {
		t.Fatal("SQL Gateway CAS request failed")
	}

	conn.mu.Lock()
	defer conn.mu.Unlock()
	if conn.calls != 1 || len(conn.args) != 3 {
		t.Fatal("SQL Gateway CAS did not execute exactly one statement with three parameters")
	}
	query := strings.ToLower(conn.query)
	if strings.Count(query, "update") != 1 || strings.Contains(query, "select") ||
		!strings.Contains(query, "set") || !strings.Contains(query, "dest =") ||
		!strings.Contains(query, "where") || !strings.Contains(query, "id =") ||
		!strings.Contains(query, "and dest =") {
		t.Fatal("SQL Gateway CAS statement is not the approved conditional update")
	}
	if !testOnlyGatewayCASIDArgument(conn.args[1].Value) {
		t.Fatal("SQL Gateway CAS Contact Method ID parameter is invalid")
	}

	replacement, replacementOK := testOnlyGatewayCASDestinationArgument(conn.args[0].Value)
	expected, expectedOK := testOnlyGatewayCASDestinationArgument(conn.args[2].Value)
	if !replacementOK || !expectedOK {
		t.Fatal("SQL Gateway CAS destination parameters could not be decoded")
	}
	if replacement.Type != DestTypeWebhook || expected.Type != DestTypeWebhook ||
		len(replacement.Args) != 1 || len(expected.Args) != 1 ||
		expected.Arg(FieldWebhookURL) != testOnlyGatewayURL ||
		replacement.Arg(FieldWebhookURL) == testOnlyGatewayURL {
		t.Fatal("SQL Gateway CAS destination parameters are invalid")
	}
}

func testOnlyGatewayCASIDArgument(value any) bool {
	switch id := value.(type) {
	case uuid.UUID:
		return id == testOnlyGatewayCASContactMethodID
	case string:
		return id == testOnlyGatewayCASContactMethodID.String()
	case []byte:
		parsed, err := uuid.ParseBytes(id)
		return err == nil && parsed == testOnlyGatewayCASContactMethodID
	default:
		return false
	}
}

func testOnlyGatewayCASDestinationArgument(value any) (gadb.DestV1, bool) {
	switch destination := value.(type) {
	case gadb.NullDestV1:
		return destination.DestV1, destination.Valid
	case gadb.DestV1:
		return destination, true
	default:
		var parsed gadb.DestV1
		if parsed.Scan(value) != nil {
			return gadb.DestV1{}, false
		}
		return parsed, true
	}
}

func TestGatewayDestinationTokenURLCASSQLClassificationsAndNoReplay(t *testing.T) {
	private := errors.New("test-only-private-SQL-marker:" + testOnlyGatewayToken)
	tests := []struct {
		name   string
		result driver.Result
		err    error
		want   error
	}{
		{name: "one row", result: gatewayCASTestResult{rows: 1}},
		{name: "zero rows", result: gatewayCASTestResult{}, want: ErrGatewayDestinationTokenURLCASConflict},
		{name: "multiple rows", result: gatewayCASTestResult{rows: 2}, want: ErrGatewayDestinationTokenURLCASUnavailable},
		{name: "destination unique", err: &pgconn.PgError{Code: "23505", ConstraintName: "user_contact_methods_dest_key", Message: private.Error()}, want: ErrGatewayDestinationTokenURLCASConflict},
		{name: "compatibility unique", err: &pgconn.PgError{Code: "23505", ConstraintName: "user_contact_methods_type_value_key", Message: private.Error()}, want: ErrGatewayDestinationTokenURLCASConflict},
		{name: "other unique", err: &pgconn.PgError{Code: "23505", ConstraintName: "test_only_other_constraint", Message: private.Error()}, want: ErrGatewayDestinationTokenURLCASUnavailable},
		{name: "ordinary PostgreSQL failure", err: &pgconn.PgError{Code: "42501", Message: private.Error()}, want: ErrGatewayDestinationTokenURLCASUnavailable},
		{name: "statement outcome unknown", err: &pgconn.PgError{Code: "40003", Message: private.Error()}, want: ErrGatewayDestinationTokenURLCASOutcomeUnknown},
		{name: "connection interruption", err: &pgconn.PgError{Code: "08006", Message: private.Error()}, want: ErrGatewayDestinationTokenURLCASOutcomeUnknown},
		{name: "safe bad connection", err: driver.ErrBadConn, want: ErrGatewayDestinationTokenURLCASUnavailable},
		{name: "in-flight canceled", err: context.Canceled, want: ErrGatewayDestinationTokenURLCASOutcomeUnknown},
		{name: "in-flight deadline", err: context.DeadlineExceeded, want: ErrGatewayDestinationTokenURLCASOutcomeUnknown},
		{name: "ambiguous execution", err: private, want: ErrGatewayDestinationTokenURLCASOutcomeUnknown},
		{name: "nil result", want: ErrGatewayDestinationTokenURLCASOutcomeUnknown},
		{name: "typed nil result", result: (*gatewayCASTestPointerResult)(nil), want: ErrGatewayDestinationTokenURLCASOutcomeUnknown},
		{name: "rows affected private failure", result: gatewayCASTestResult{err: private}, want: ErrGatewayDestinationTokenURLCASOutcomeUnknown},
		{name: "rows affected bad connection", result: gatewayCASTestResult{err: driver.ErrBadConn}, want: ErrGatewayDestinationTokenURLCASOutcomeUnknown},
		{name: "rows affected unique failure", result: gatewayCASTestResult{err: &pgconn.PgError{Code: "23505", ConstraintName: "user_contact_methods_dest_key", Message: private.Error()}}, want: ErrGatewayDestinationTokenURLCASOutcomeUnknown},
		{name: "rows affected PostgreSQL failure", result: gatewayCASTestResult{err: &pgconn.PgError{Code: "42501", Message: private.Error()}}, want: ErrGatewayDestinationTokenURLCASOutcomeUnknown},
		{name: "rows affected cancellation", result: gatewayCASTestResult{err: context.Canceled}, want: ErrGatewayDestinationTokenURLCASOutcomeUnknown},
		{name: "joined unique and failure", err: errors.Join(&pgconn.PgError{Code: "23505", ConstraintName: "user_contact_methods_dest_key"}, private), want: ErrGatewayDestinationTokenURLCASOutcomeUnknown},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			physical := &gatewayCASTestPhysicalConnection{}
			conn := &gatewayCASTestDriverConn{result: test.result, err: test.err, physical: physical}
			service := testOnlyGatewayCASPublicService(t, testOnlyGatewayCASDatabase(t, conn))
			err := service.CompareAndSwap(testOnlyGatewayCASSystemContext(), testOnlyGatewayCASSuccessRequest())
			if test.want == nil {
				if err != nil {
					t.Fatal("successful SQL Gateway CAS returned an error")
				}
			} else {
				requireGatewayCASFixedError(t, err, test.want, private)
			}
			conn.mu.Lock()
			defer conn.mu.Unlock()
			if conn.calls != 1 {
				t.Fatal("SQL Gateway CAS retried or skipped the update")
			}
			if test.want == ErrGatewayDestinationTokenURLCASOutcomeUnknown && conn.closed == 0 {
				t.Fatal("outcome-unknown SQL Gateway CAS did not discard its connection")
			}
			physicalCloseCount := physical.closeCount()
			if test.want == ErrGatewayDestinationTokenURLCASOutcomeUnknown && physicalCloseCount != 1 {
				t.Fatal("outcome-unknown SQL Gateway CAS did not destroy its physical connection")
			}
			if test.want != ErrGatewayDestinationTokenURLCASOutcomeUnknown && physicalCloseCount != 0 {
				t.Fatal("confirmed SQL Gateway CAS unexpectedly destroyed its physical connection")
			}
		})
	}
}

func TestGatewayDestinationTokenURLCASSQLPreCanceledContextDoesNotExecute(t *testing.T) {
	conn := &gatewayCASTestDriverConn{result: gatewayCASTestResult{rows: 1}}
	service := testOnlyGatewayCASPublicService(t, testOnlyGatewayCASDatabase(t, conn))
	ctx, cancel := context.WithCancel(testOnlyGatewayCASSystemContext())
	cancel()
	err := service.CompareAndSwap(ctx, testOnlyGatewayCASSuccessRequest())
	requireGatewayCASFixedError(t, err, ErrGatewayDestinationTokenURLCASCanceled, nil)
	conn.mu.Lock()
	defer conn.mu.Unlock()
	if conn.calls != 0 {
		t.Fatal("pre-canceled SQL Gateway CAS executed the update")
	}
}

func TestGatewayDestinationTokenURLCASExecutionClassifier(t *testing.T) {
	private := errors.New("test-only-classifier-marker")
	if classifyGatewayDestinationTokenURLCASExecutionError(fmt.Errorf("outer: %w", driver.ErrBadConn)) != ErrGatewayDestinationTokenURLCASUnavailable {
		t.Fatal("single-cause safe execution error was misclassified")
	}
	if classifyGatewayDestinationTokenURLCASExecutionError(errors.Join(driver.ErrBadConn, private)) != ErrGatewayDestinationTokenURLCASOutcomeUnknown {
		t.Fatal("multi-cause safe execution error was not fail-closed")
	}
	if classifyGatewayDestinationTokenURLCASExecutionError(fmt.Errorf("outer: %w", &pgconn.PgError{Code: "23505", ConstraintName: "user_contact_methods_dest_key"})) != ErrGatewayDestinationTokenURLCASConflict {
		t.Fatal("single-cause unique failure was misclassified")
	}
	if classifyGatewayDestinationTokenURLCASExecutionError(errors.Join(&pgconn.PgError{Code: "42501"}, private)) != ErrGatewayDestinationTokenURLCASOutcomeUnknown {
		t.Fatal("multi-cause PostgreSQL error was not fail-closed")
	}
}

var _ driver.ExecerContext = (*gatewayCASTestDriverConn)(nil)
var _ driver.Connector = gatewayCASTestConnector{}
var _ io.Closer = (*gatewayCASTestDriverConn)(nil)
