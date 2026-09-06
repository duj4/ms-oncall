package auth

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/target/goalert/auth/authtoken"
	"github.com/target/goalert/integrationkey"
	"github.com/target/goalert/keyring"
	"github.com/target/goalert/permission"
)

type requesterSessionState struct {
	mu                   sync.Mutex
	present              bool
	userID               uuid.UUID
	role                 permission.Role
	lookups              int
	integrationPresent   bool
	integrationServiceID uuid.UUID
	integrationLookups   int
}

func (s *requesterSessionState) sessionResult() (bool, uuid.UUID, permission.Role) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lookups++
	return s.present, s.userID, s.role
}

func (s *requesterSessionState) lookupCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lookups
}

func (s *requesterSessionState) integrationResult() (bool, uuid.UUID) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.integrationLookups++
	return s.integrationPresent, s.integrationServiceID
}

func (s *requesterSessionState) integrationLookupCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.integrationLookups
}

type requesterSessionConnector struct{ state *requesterSessionState }

func (c requesterSessionConnector) Connect(context.Context) (driver.Conn, error) {
	return &requesterSessionConn{state: c.state}, nil
}

func (requesterSessionConnector) Driver() driver.Driver { return requesterSessionDriver{} }

type requesterSessionDriver struct{}

func (requesterSessionDriver) Open(string) (driver.Conn, error) {
	return nil, errors.New("requester Session test driver requires Connector")
}

type requesterSessionConn struct{ state *requesterSessionState }

func (c *requesterSessionConn) Prepare(query string) (driver.Stmt, error) {
	return &requesterSessionStmt{state: c.state, query: query}, nil
}

func (c *requesterSessionConn) PrepareContext(_ context.Context, query string) (driver.Stmt, error) {
	return c.Prepare(query)
}

func (*requesterSessionConn) Close() error { return nil }

func (*requesterSessionConn) Begin() (driver.Tx, error) {
	return nil, errors.New("transactions are unsupported by requester Session test driver")
}

type requesterSessionStmt struct {
	state *requesterSessionState
	query string
}

func (*requesterSessionStmt) Close() error  { return nil }
func (*requesterSessionStmt) NumInput() int { return -1 }

func (*requesterSessionStmt) Exec([]driver.Value) (driver.Result, error) {
	return driver.RowsAffected(1), nil
}

func (s *requesterSessionStmt) Query([]driver.Value) (driver.Rows, error) {
	return s.queryRows()
}

func (s *requesterSessionStmt) ExecContext(context.Context, []driver.NamedValue) (driver.Result, error) {
	return driver.RowsAffected(1), nil
}

func (s *requesterSessionStmt) QueryContext(context.Context, []driver.NamedValue) (driver.Rows, error) {
	return s.queryRows()
}

func (s *requesterSessionStmt) queryRows() (driver.Rows, error) {
	normalizedQuery := strings.ToLower(s.query)
	if strings.Contains(normalizedQuery, "from auth_user_sessions sess") {
		present, userID, role := s.state.sessionResult()
		rows := &requesterSessionRows{columns: []string{"user_id", "role"}}
		if present {
			rows.values = [][]driver.Value{{userID.String(), string(role)}}
		}
		return rows, nil
	}
	if strings.Contains(normalizedQuery, "integration_keys") {
		present, serviceID := s.state.integrationResult()
		rows := &requesterSessionRows{columns: []string{"service_id"}}
		if present {
			rows.values = [][]driver.Value{{serviceID.String()}}
		}
		return rows, nil
	}
	return nil, errors.New("unexpected query in requester authentication test driver")
}

type requesterSessionRows struct {
	columns []string
	values  [][]driver.Value
	index   int
}

func (r *requesterSessionRows) Columns() []string { return r.columns }
func (*requesterSessionRows) Close() error        { return nil }

func (r *requesterSessionRows) Next(dest []driver.Value) error {
	if r.index >= len(r.values) {
		return io.EOF
	}
	copy(dest, r.values[r.index])
	r.index++
	return nil
}

type requesterTestKeyring struct{ key []byte }

func (*requesterTestKeyring) RotateKeys(context.Context) error { return nil }

func (k *requesterTestKeyring) Sign(payload []byte) ([]byte, error) {
	mac := hmac.New(sha256.New, k.key)
	_, _ = mac.Write(payload)
	return mac.Sum(nil), nil
}

func (k *requesterTestKeyring) Verify(payload, signature []byte) (bool, bool) {
	want, _ := k.Sign(payload)
	return hmac.Equal(want, signature), false
}

func (*requesterTestKeyring) SignJWT(jwt.Claims) (string, error) {
	return "", errors.New("JWT signing is unsupported by requester test keyring")
}

func (*requesterTestKeyring) VerifyJWT(string, jwt.Claims, string, string) (bool, error) {
	return false, nil
}

func (*requesterTestKeyring) Shutdown(context.Context) error { return nil }

var _ keyring.Keyring = (*requesterTestKeyring)(nil)

func newRequesterAuthHandler(
	t *testing.T,
	state *requesterSessionState,
	sessionKeyring keyring.Keyring,
	configure ...func(*sql.DB, *HandlerConfig),
) *Handler {
	t.Helper()
	db := sql.OpenDB(requesterSessionConnector{state: state})
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })
	cfg := HandlerConfig{SessionKeyring: sessionKeyring}
	for _, configureHandler := range configure {
		configureHandler(db, &cfg)
	}
	handler, err := NewHandler(context.Background(), db, cfg)
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	return handler
}

func signedRequesterTestToken(t *testing.T, signer *requesterTestKeyring, token authtoken.Token) string {
	t.Helper()
	encoded, err := token.Encode(signer.Sign)
	if err != nil {
		t.Fatalf("encode token: %v", err)
	}
	return encoded
}

func requestWithInheritedRequester(t *testing.T, path string, userID, sessionID uuid.UUID) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "http://example.test"+path, nil)
	ctx := permission.UserSourceContext(req.Context(), userID.String(), permission.RoleUser, &permission.SourceInfo{
		Type: permission.SourceTypeAuthProvider,
		ID:   sessionID.String(),
	})
	requester, err := NewRequester(userID.String(), sessionID.String())
	if err != nil {
		t.Fatalf("NewRequester: %v", err)
	}
	return req.WithContext(WithRequester(ctx, requester))
}

func requesterFromWrappedRequest(t *testing.T, handler *Handler, req *http.Request) (*Requester, *permission.SourceInfo, string) {
	t.Helper()
	var requester *Requester
	var source *permission.SourceInfo
	var legacyUserID string
	next := http.HandlerFunc(func(_ http.ResponseWriter, req *http.Request) {
		requester = RequesterFromContext(req.Context())
		source = permission.Source(req.Context())
		legacyUserID = permission.UserID(req.Context())
	})
	handler.WrapHandler(next).ServeHTTP(httptest.NewRecorder(), req)
	return requester, source, legacyUserID
}

func TestWrapHandlerCanonicalSessionInstallsRequester(t *testing.T) {
	userID := uuid.MustParse("afc9097f-b88d-4895-9cc7-4a643e70bd76")
	sessionID := uuid.MustParse("ef4f827b-83ca-4c8f-a725-e95e94f9b1d6")
	state := &requesterSessionState{present: true, userID: userID, role: permission.RoleUser}
	sessionKeyring := &requesterTestKeyring{key: []byte("requester-session-test-key")}
	handler := newRequesterAuthHandler(t, state, sessionKeyring)
	token := signedRequesterTestToken(t, sessionKeyring, authtoken.Token{Version: 1, Type: authtoken.TypeSession, ID: sessionID})
	req := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
	req.AddCookie(&http.Cookie{Name: CookieName, Value: token})

	requester, source, legacyUserID := requesterFromWrappedRequest(t, handler, req)
	if requester == nil || !requester.Valid() || requester.UserID() != userID || requester.SessionID() != sessionID {
		t.Fatalf("Requester = %#v, want canonical lookup User and token Session", requester)
	}
	if source == nil || source.Type != permission.SourceTypeAuthProvider || source.ID != sessionID.String() || legacyUserID != userID.String() {
		t.Fatalf("legacy auth = (%#v, %q), want preserved canonical Session/User", source, legacyUserID)
	}
	if state.lookupCount() != 1 {
		t.Fatalf("FindCurrentUserSession query count = %d, want exactly 1", state.lookupCount())
	}
}

func TestWrapHandlerClearsInheritedRequesterBeforeAuthenticationBranches(t *testing.T) {
	oldUserID := uuid.MustParse("afc9097f-b88d-4895-9cc7-4a643e70bd76")
	oldSessionID := uuid.MustParse("ef4f827b-83ca-4c8f-a725-e95e94f9b1d6")

	tests := []struct {
		name        string
		path        string
		present     bool
		cookie      func(*testing.T, *requesterTestKeyring) string
		wantLookups int
	}{
		{name: "anonymous", path: "/", present: true},
		{
			name:        "forged Session",
			path:        "/",
			present:     true,
			wantLookups: 0,
			cookie: func(t *testing.T, _ *requesterTestKeyring) string {
				forgedKeyring := &requesterTestKeyring{key: []byte("forged-inherited-requester-test-key")}
				return signedRequesterTestToken(t, forgedKeyring, authtoken.Token{Version: 1, Type: authtoken.TypeSession, ID: oldSessionID})
			},
		},
		{
			name:        "deleted Session",
			path:        "/",
			present:     false,
			wantLookups: 1,
			cookie: func(t *testing.T, sessionKeyring *requesterTestKeyring) string {
				return signedRequesterTestToken(t, sessionKeyring, authtoken.Token{Version: 1, Type: authtoken.TypeSession, ID: oldSessionID})
			},
		},
		{
			name:        "Slack bypass",
			path:        "/api/v2/slack/events",
			present:     true,
			wantLookups: 0,
			cookie: func(t *testing.T, sessionKeyring *requesterTestKeyring) string {
				return signedRequesterTestToken(t, sessionKeyring, authtoken.Token{Version: 1, Type: authtoken.TypeSession, ID: oldSessionID})
			},
		},
		{
			name:        "Mailgun v2 bypass",
			path:        "/api/v2/mailgun/incoming",
			present:     true,
			wantLookups: 0,
			cookie: func(t *testing.T, sessionKeyring *requesterTestKeyring) string {
				return signedRequesterTestToken(t, sessionKeyring, authtoken.Token{Version: 1, Type: authtoken.TypeSession, ID: oldSessionID})
			},
		},
		{
			name:        "Mailgun v1 bypass",
			path:        "/v1/webhooks/mailgun",
			present:     true,
			wantLookups: 0,
			cookie: func(t *testing.T, sessionKeyring *requesterTestKeyring) string {
				return signedRequesterTestToken(t, sessionKeyring, authtoken.Token{Version: 1, Type: authtoken.TypeSession, ID: oldSessionID})
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			state := &requesterSessionState{present: test.present, userID: oldUserID, role: permission.RoleUser}
			sessionKeyring := &requesterTestKeyring{key: []byte("inherited-requester-session-test-key")}
			handler := newRequesterAuthHandler(t, state, sessionKeyring)
			req := requestWithInheritedRequester(t, test.path, oldUserID, oldSessionID)
			if test.cookie != nil {
				req.AddCookie(&http.Cookie{Name: CookieName, Value: test.cookie(t, sessionKeyring)})
			}

			requester, source, legacyUserID := requesterFromWrappedRequest(t, handler, req)
			if requester != nil {
				t.Fatalf("inherited Requester = %#v, want absent downstream", requester)
			}
			if source == nil || source.Type != permission.SourceTypeAuthProvider || source.ID != oldSessionID.String() || legacyUserID != oldUserID.String() {
				t.Fatalf("legacy compatibility context = (%#v, %q), want inherited metadata preserved without typed Requester", source, legacyUserID)
			}
			if state.lookupCount() != test.wantLookups {
				t.Fatalf("FindCurrentUserSession query count = %d, want %d", state.lookupCount(), test.wantLookups)
			}
		})
	}
}

func TestWrapHandlerClearsInheritedRequesterOnIntegrationAuthentication(t *testing.T) {
	oldUserID := uuid.MustParse("afc9097f-b88d-4895-9cc7-4a643e70bd76")
	oldSessionID := uuid.MustParse("ef4f827b-83ca-4c8f-a725-e95e94f9b1d6")
	integrationKeyID := uuid.MustParse("da3530ff-1d99-42f2-9ac0-f8f1ef7f3eb9")
	serviceID := uuid.MustParse("886131d7-1f0c-496f-a05a-b4ab16d86fca")
	state := &requesterSessionState{
		integrationPresent:   true,
		integrationServiceID: serviceID,
	}
	sessionKeyring := &requesterTestKeyring{key: []byte("integration-requester-session-test-key")}
	handler := newRequesterAuthHandler(t, state, sessionKeyring, func(db *sql.DB, cfg *HandlerConfig) {
		cfg.IntKeyStore = integrationkey.NewStore(context.Background(), db, nil, nil, nil)
	})
	req := requestWithInheritedRequester(t, "/api/v2/generic/incoming", oldUserID, oldSessionID)
	req.Header.Set("Authorization", "Bearer "+integrationKeyID.String())

	var requester *Requester
	var source *permission.SourceInfo
	var deliveredServiceID string
	handler.WrapHandler(http.HandlerFunc(func(_ http.ResponseWriter, req *http.Request) {
		requester = RequesterFromContext(req.Context())
		source = permission.Source(req.Context())
		deliveredServiceID = permission.ServiceID(req.Context())
	})).ServeHTTP(httptest.NewRecorder(), req)

	if requester != nil {
		t.Fatalf("inherited Requester = %#v, want absent after integration authentication", requester)
	}
	if source == nil || source.Type != permission.SourceTypeIntegrationKey || source.ID != integrationKeyID.String() || deliveredServiceID != serviceID.String() {
		t.Fatalf("integration context = (%#v, %q), want current IntegrationKey service", source, deliveredServiceID)
	}
	if state.lookupCount() != 0 || state.integrationLookupCount() != 1 {
		t.Fatalf("authentication lookup counts = Session:%d Integration:%d, want 0/1", state.lookupCount(), state.integrationLookupCount())
	}
}

func TestWrapHandlerReplacesInheritedRequesterAfterCanonicalSessionAuthentication(t *testing.T) {
	oldUserID := uuid.MustParse("afc9097f-b88d-4895-9cc7-4a643e70bd76")
	oldSessionID := uuid.MustParse("ef4f827b-83ca-4c8f-a725-e95e94f9b1d6")
	newUserID := uuid.MustParse("8fdd88e8-6633-4e2f-87e2-5b6ac594830a")
	newSessionID := uuid.MustParse("bcd5cc51-36d5-4340-aa65-395e15dd3a24")
	state := &requesterSessionState{present: true, userID: newUserID, role: permission.RoleUser}
	sessionKeyring := &requesterTestKeyring{key: []byte("replacement-requester-session-test-key")}
	handler := newRequesterAuthHandler(t, state, sessionKeyring)
	token := signedRequesterTestToken(t, sessionKeyring, authtoken.Token{Version: 1, Type: authtoken.TypeSession, ID: newSessionID})
	req := requestWithInheritedRequester(t, "/", oldUserID, oldSessionID)
	req.AddCookie(&http.Cookie{Name: CookieName, Value: token})

	requester, source, legacyUserID := requesterFromWrappedRequest(t, handler, req)
	if requester == nil || !requester.Valid() || requester.UserID() != newUserID || requester.SessionID() != newSessionID {
		t.Fatalf("replacement Requester = %#v, want newly authenticated User/Session", requester)
	}
	if requester.UserID() == oldUserID || requester.SessionID() == oldSessionID {
		t.Fatal("inherited Requester identity survived successful replacement")
	}
	if source == nil || source.Type != permission.SourceTypeAuthProvider || source.ID != newSessionID.String() || legacyUserID != newUserID.String() {
		t.Fatalf("legacy replacement context = (%#v, %q), want newly authenticated Session/User", source, legacyUserID)
	}
	if state.lookupCount() != 1 {
		t.Fatalf("FindCurrentUserSession query count = %d, want exactly 1", state.lookupCount())
	}
}

func TestWrapHandlerFailedOrNonHumanAuthenticationInstallsNoRequester(t *testing.T) {
	userID := uuid.MustParse("afc9097f-b88d-4895-9cc7-4a643e70bd76")
	sessionID := uuid.MustParse("ef4f827b-83ca-4c8f-a725-e95e94f9b1d6")

	tests := []struct {
		name        string
		present     bool
		cookie      func(*testing.T, *requesterTestKeyring) string
		legacyInput bool
		wantLookups int
	}{
		{
			name:        "forged Session",
			present:     true,
			wantLookups: 0,
			cookie: func(t *testing.T, _ *requesterTestKeyring) string {
				otherKeyring := &requesterTestKeyring{key: []byte("forged-session-test-key")}
				return signedRequesterTestToken(t, otherKeyring, authtoken.Token{Version: 1, Type: authtoken.TypeSession, ID: sessionID})
			},
		},
		{
			name:        "missing or deleted Session",
			present:     false,
			wantLookups: 1,
			cookie: func(t *testing.T, keyring *requesterTestKeyring) string {
				return signedRequesterTestToken(t, keyring, authtoken.Token{Version: 1, Type: authtoken.TypeSession, ID: sessionID})
			},
		},
		{name: "anonymous", present: true, wantLookups: 0},
		{
			name:        "non-Session token signed by Session keyring",
			present:     true,
			wantLookups: 0,
			cookie: func(t *testing.T, keyring *requesterTestKeyring) string {
				return signedRequesterTestToken(t, keyring, authtoken.Token{Version: 3, Type: authtoken.TypeCalSub, ID: sessionID})
			},
		},
		{
			name:        "unsigned legacy UUID matching Session identity",
			present:     true,
			wantLookups: 0,
			cookie: func(*testing.T, *requesterTestKeyring) string {
				return sessionID.String()
			},
		},
		{name: "preexisting integration permission context", present: true, legacyInput: true, wantLookups: 0},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			state := &requesterSessionState{present: test.present, userID: userID, role: permission.RoleUser}
			sessionKeyring := &requesterTestKeyring{key: []byte("requester-session-test-key")}
			handler := newRequesterAuthHandler(t, state, sessionKeyring)
			req := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
			if test.cookie != nil {
				req.AddCookie(&http.Cookie{Name: CookieName, Value: test.cookie(t, sessionKeyring)})
			}
			if test.legacyInput {
				ctx := permission.ServiceSourceContext(req.Context(), uuid.NewString(), &permission.SourceInfo{
					Type: permission.SourceTypeIntegrationKey,
					ID:   uuid.NewString(),
				})
				req = req.WithContext(ctx)
			}

			requester, _, _ := requesterFromWrappedRequest(t, handler, req)
			if requester != nil {
				t.Fatalf("Requester = %#v, want none", requester)
			}
			if state.lookupCount() != test.wantLookups {
				t.Fatalf("FindCurrentUserSession query count = %d, want %d", state.lookupCount(), test.wantLookups)
			}
		})
	}
}
