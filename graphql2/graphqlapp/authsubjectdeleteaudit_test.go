package graphqlapp

import (
	"bytes"
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/99designs/gqlgen/graphql"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/executioncontext"
	"github.com/target/goalert/organization"
	"github.com/target/goalert/permission"
	"github.com/target/goalert/user"
	audit "github.com/target/goalert/user/authsubjectdeleteaudit"
	"github.com/target/goalert/util/log"
	"github.com/vektah/gqlparser/v2/ast"
)

// Controlled database/sql driver. Persistent counters model a transaction only;
// real PostgreSQL and signed HTTP are tested separately in smoke/migrate.
type asState struct {
	mu                                                      sync.Mutex
	mode                                                    string
	owner, org                                              uuid.UUID
	begin, commit, rollback, deletes, success, observations int
	order                                                   []string
	events                                                  []audit.Event
	gate, entered                                           chan struct{}
	closeArmed                                              bool
	closeOnce                                               sync.Once
}
type asConnector struct{ s *asState }

func (c asConnector) Driver() driver.Driver                        { return asDriver{} }
func (c asConnector) Connect(context.Context) (driver.Conn, error) { return &asConn{s: c.s}, nil }

type asDriver struct{}

func (asDriver) Open(string) (driver.Conn, error) { return nil, errors.New("connector required") }

type asConn struct {
	s  *asState
	tx *asTx
}

func (c *asConn) Prepare(q string) (driver.Stmt, error) { return &asStmt{c: c, q: q}, nil }
func (c *asConn) Close() error {
	c.s.mu.Lock()
	wait := c.s.mode == "close-late" && c.s.closeArmed
	c.s.mu.Unlock()
	if wait {
		c.s.closeOnce.Do(func() { close(c.s.entered) })
		<-c.s.gate
	}
	return nil
}
func (c *asConn) Begin() (driver.Tx, error) {
	c.s.mu.Lock()
	defer c.s.mu.Unlock()
	c.s.begin++
	if c.s.mode == "begin" && c.s.begin == 1 {
		return nil, errors.New("SYNTHETIC_DB_SECRET")
	}
	c.tx = &asTx{s: c.s, number: c.s.begin}
	return c.tx, nil
}

type asStmt struct {
	c *asConn
	q string
}

func (s *asStmt) Close() error  { return nil }
func (s *asStmt) NumInput() int { return -1 }
func (s *asStmt) Exec([]driver.Value) (driver.Result, error) {
	return nil, errors.New("unexpected legacy Exec")
}
func (s *asStmt) Query(v []driver.Value) (driver.Rows, error) {
	n := make([]driver.NamedValue, len(v))
	for i, x := range v {
		n[i] = driver.NamedValue{Ordinal: i + 1, Value: x}
	}
	return s.c.QueryContext(context.Background(), s.q, n)
}

type asRows struct {
	values        [][]driver.Value
	err, closeErr error
}

func (r *asRows) Columns() []string {
	if len(r.values) > 0 {
		n := make([]string, len(r.values[0]))
		return n
	}
	return []string{"id", "user_id", "cm_id", "xmin"}
}
func (r *asRows) Close() error { return r.closeErr }
func (r *asRows) Next(v []driver.Value) error {
	if len(r.values) == 0 {
		if r.err != nil {
			err := r.err
			r.err = nil
			return err
		}
		return io.EOF
	}
	copy(v, r.values[0])
	r.values = r.values[1:]
	return nil
}
func (c *asConn) QueryContext(_ context.Context, q string, _ []driver.NamedValue) (driver.Rows, error) {
	s := c.s
	s.mu.Lock()
	defer s.mu.Unlock()
	s.order = append(s.order, q)
	if q == "SHOW transaction_isolation" {
		return &asRows{values: [][]driver.Value{{"read committed"}}}, nil
	}
	if strings.Contains(q, "NOT EXISTS(SELECT FROM auth_subjects") {
		if s.mode == "post-error" {
			return nil, errors.New("SYNTHETIC_DB_SECRET")
		}
		return &asRows{values: [][]driver.Value{{s.mode != "post-false"}}}, nil
	}
	if strings.Contains(q, "FROM auth_subjects") {
		deleting := strings.Contains(q, "DELETE")
		if deleting {
			s.deletes++
			if s.mode == "query" || s.mode == "rollback-error" {
				return nil, errors.New("SYNTHETIC_DB_SECRET")
			}
		}
		if s.mode == "zero" || s.mode == "suppressed" && deleting || s.mode == "insert-race" && !deleting {
			return &asRows{}, nil
		}
		id, version := int64(9007199254740993), int64(42)
		if deleting && s.mode == "mismatch" {
			id++
		}
		row := []driver.Value{id, s.owner.String(), nil, version}
		if s.mode == "owner-null" {
			row[1] = nil
		}
		if deleting && s.mode == "scan" {
			row[0] = "bad integer"
		}
		r := &asRows{values: [][]driver.Value{row}}
		if deleting {
			switch s.mode {
			case "rows-error":
				r.err = errors.New("SYNTHETIC_DB_SECRET")
			case "close":
				r.closeErr = errors.New("SYNTHETIC_DB_SECRET")
			case "multiple":
				r.values = append(r.values, row)
			}
		}
		return r, nil
	}
	if strings.Contains(q, "SELECT a.user_id") {
		if s.mode == "guard" {
			return &asRows{values: nil}, nil
		}
		return &asRows{values: [][]driver.Value{{s.owner.String()}}}, nil
	}
	if strings.Contains(q, "CASE WHEN o.classification") {
		return &asRows{values: [][]driver.Value{{s.org.String(), "known_normal"}}}, nil
	}
	if strings.Contains(q, "SELECT organization_id") || strings.Contains(q, "SELECT a.effective_organization_id") {
		return &asRows{values: [][]driver.Value{{s.org.String()}}}, nil
	}
	return nil, errors.New("unexpected query")
}
func (c *asConn) ExecContext(_ context.Context, q string, v []driver.NamedValue) (driver.Result, error) {
	s := c.s
	s.mu.Lock()
	defer s.mu.Unlock()
	s.order = append(s.order, q)
	if strings.HasPrefix(q, "SELECT pg_advisory_xact_lock") {
		return driver.RowsAffected(0), nil
	}
	if strings.Contains(q, "INSERT INTO auth_subject_delete_audit_events") {
		var e audit.Event
		if json.Unmarshal([]byte(v[0].Value.(string)), &e) != nil {
			return nil, errors.New("bad typed event")
		}
		if e.RecordKind == "success_witness" && (s.mode == "audit" || s.mode == "failure-late" || strings.HasPrefix(s.mode, "writer-")) {
			return nil, errors.New("SYNTHETIC_DB_SECRET")
		}
		if e.RecordKind == "attempt_observation" && s.mode == "writer-insert" {
			return nil, errors.New("SYNTHETIC_DB_SECRET")
		}
		c.tx.events = append(c.tx.events, e)
		return driver.RowsAffected(1), nil
	}
	return nil, errors.New("unexpected write")
}

type asTx struct {
	s      *asState
	number int
	events []audit.Event
}

func (tx *asTx) Commit() error {
	s := tx.s
	if tx.number == 1 && s.mode == "late" {
		close(s.entered)
		<-s.gate
	}
	if tx.number == 2 && s.mode == "failure-late" {
		close(s.entered)
		<-s.gate
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.commit++
	if tx.number == 2 && s.mode == "writer-commit" {
		return errors.New("SYNTHETIC_DB_SECRET")
	}
	if tx.number == 1 && s.mode == "rejected" {
		return &pgconn.PgError{Code: "23514", Message: "SYNTHETIC_DB_SECRET"}
	}
	for _, e := range tx.events {
		s.events = append(s.events, e)
		if e.RecordKind == "success_witness" {
			s.success++
		} else {
			s.observations++
		}
	}
	if tx.number == 1 {
		switch s.mode {
		case "commit-cancel":
			return context.Canceled
		case "commit-timeout":
			return context.DeadlineExceeded
		case "txdone":
			return sql.ErrTxDone
		case "close-late":
			s.closeArmed = true
		}
	}
	if tx.number == 1 && s.mode == "unknown" {
		return errors.New("SYNTHETIC_DB_SECRET")
	}
	return nil
}
func (tx *asTx) Rollback() error {
	tx.s.mu.Lock()
	defer tx.s.mu.Unlock()
	tx.s.rollback++
	if tx.s.mode == "rollback-error" {
		return errors.New("SYNTHETIC_DB_SECRET")
	}
	return nil
}

func asApp(t *testing.T, mode string, ctx context.Context) (*Mutation, *asState) {
	t.Helper()
	s := &asState{mode: mode, owner: uuid.New(), org: uuid.New(), gate: make(chan struct{}), entered: make(chan struct{})}
	db := sql.OpenDB(asConnector{s})
	if mode == "close-late" {
		db.SetMaxIdleConns(0)
	}
	t.Cleanup(func() { require.NoError(t, db.Close()) })
	store, err := user.NewStore(ctx, db)
	require.NoError(t, err)
	return (*Mutation)(&App{DB: db, UserStore: store}), s
}

func TestAuthSubjectDeleteControlledAtomicity(t *testing.T) {
	for _, mode := range []string{"ok", "zero", "suppressed", "begin", "query", "scan", "owner-null", "rows-error", "close", "multiple", "insert-race", "mismatch", "post-false", "post-error", "audit", "rejected", "unknown", "commit-cancel", "commit-timeout", "txdone", "rollback-error", "writer-insert", "writer-commit", "panic"} {
		t.Run(mode, func(t *testing.T) {
			ctx := permission.SystemContext(t.Context(), "Engine")
			a, s := asApp(t, mode, ctx)
			if mode == "panic" {
				a.UserStore = nil
			} // panic outside database/sql's native-call locks
			ok, err := a.DeleteAuthSubject(ctx, user.AuthSubject{UserID: s.owner.String(), ProviderID: "SYNTHETIC_PROVIDER", SubjectID: "SYNTHETIC_SUBJECT"})
			s.mu.Lock()
			defer s.mu.Unlock()
			if mode == "ok" || mode == "zero" || mode == "suppressed" {
				require.True(t, ok)
				require.NoError(t, err)
				require.Equal(t, 1, s.begin)
				require.Equal(t, 1, s.commit)
				if mode == "ok" {
					require.Equal(t, 1, s.success)
				} else {
					require.Zero(t, s.success)
				}
				return
			}
			require.False(t, ok)
			require.Error(t, err)
			require.NotContains(t, err.Error(), "SYNTHETIC")
			if mode == "unknown" || mode == "commit-cancel" || mode == "commit-timeout" || mode == "txdone" {
				require.Equal(t, 1, s.success)
				require.Equal(t, "commit_unknown", s.events[len(s.events)-1].Outcome)
			} else {
				require.Zero(t, s.success)
			}
			if strings.HasPrefix(mode, "writer-") {
				require.Zero(t, s.observations)
				require.Equal(t, 2, s.begin)
			} else {
				require.Equal(t, 1, s.observations)
			}
			require.LessOrEqual(t, s.deletes, 1)
			for _, e := range s.events {
				raw, _ := json.Marshal(e)
				require.NotContains(t, string(raw), "SYNTHETIC")
			}
		})
	}
}

func TestAuthSubjectDeleteAuthorizationAndInherited(t *testing.T) {
	for _, pa := range []bool{false, true} {
		ctx, _, f := ikAuthorityContext(t, organization.OrganizationRoleMember, pa)
		a, s := asApp(t, "ok", ctx)
		ok, err := a.DeleteAuthSubject(ctx, user.AuthSubject{UserID: s.owner.String(), ProviderID: "provider", SubjectID: "subject"})
		if pa {
			require.True(t, ok)
			require.NoError(t, err)
			require.Equal(t, f.user, *s.events[0].ActorID)
			require.Equal(t, f.home, *s.events[0].HomeOrganizationID)
		} else {
			require.False(t, ok)
			require.True(t, permission.IsPermissionError(err))
			require.Zero(t, s.deletes)
			for _, q := range s.order {
				require.NotContains(t, q, "FROM auth_subjects")
			}
		}
	}
	ctx := permission.SystemContext(t.Context(), "Engine")
	a, s := asApp(t, "ok", ctx)
	tx, err := a.DB.BeginTx(ctx, nil)
	require.NoError(t, err)
	ok, err := a.DeleteAuthSubject(context.WithValue(ctx, txKey, tx), user.AuthSubject{})
	require.False(t, ok)
	require.EqualError(t, err, "auth_subject.delete transaction ownership unavailable")
	require.Equal(t, 1, s.begin)
	require.Zero(t, s.deletes)
	require.Zero(t, s.commit)
	require.Zero(t, s.observations)
	require.NoError(t, tx.Rollback())
	type untrustedAuthSubjectKey string
	fakeCtx := context.WithValue(ctx, untrustedAuthSubjectKey("txKey"), new(sql.Tx))
	fakeApp, fakeState := asApp(t, "ok", fakeCtx)
	fakeOK, fakeErr := fakeApp.DeleteAuthSubject(fakeCtx, user.AuthSubject{UserID: fakeState.owner.String(), ProviderID: "provider", SubjectID: "subject"})
	require.NoError(t, fakeErr)
	require.True(t, fakeOK)
	require.Equal(t, 1, fakeState.begin)
	// Reconstruct Default admission using the existing canonical fixture reader.
	for _, mode := range []string{"ok", "guard"} {
		ctx, db, f := ikAuthorityContext(t, organization.OrganizationRoleMember, true)
		f.home = uuid.MustParse(organization.DefaultOrganizationID)
		f.role = organization.OrganizationRoleNone
		constructor, err := executioncontext.NewHumanExecutionContextConstructor(organization.NewStore(db))
		require.NoError(t, err)
		ec, err := constructor.Construct(ctx)
		require.NoError(t, err)
		ctx = executioncontext.WithExecutionContext(ctx, ec)
		a, s := asApp(t, mode, ctx)
		input := user.AuthSubject{UserID: s.owner.String(), ProviderID: "provider", SubjectID: "subject"}
		if mode == "guard" {
			input.ProviderID = ""
			input.SubjectID = ""
		}
		ok, err := a.DeleteAuthSubject(ctx, input)
		if mode == "ok" {
			require.True(t, ok)
			require.NoError(t, err)
			require.Equal(t, 1, s.begin)
			require.Equal(t, 1, s.success)
			require.True(t, strings.HasPrefix(s.order[1], "SELECT pg_advisory_xact_lock"))
			require.Contains(t, s.order[2], "SELECT a.user_id")
		} else {
			require.False(t, ok)
			require.True(t, permission.IsPermissionError(err))
			require.Zero(t, s.deletes)
		}
	}
}

func TestAuthSubjectDeleteDiagnosticProjection(t *testing.T) {
	ctx, _, f := ikAuthorityContext(t, organization.OrganizationRoleAdmin, true)
	var out bytes.Buffer
	logger := log.NewLogger()
	logger.SetOutput(&out)
	ctx = log.WithLogger(log.WithField(ctx, "Cookie", "SYNTHETIC_PRIVATE"), logger)
	ctx = log.SetRequestID(ctx)
	ctx = graphql.WithFieldContext(ctx, &graphql.FieldContext{Object: "Mutation", Field: graphql.CollectedField{Field: &ast.Field{Name: "deleteAuthSubject", Alias: "SYNTHETIC_ALIAS"}}})
	log.Logf(authSubjectDeleteDiagnosticContext(ctx), "Mutation.")
	require.NotContains(t, out.String(), "SYNTHETIC")
	require.NotContains(t, out.String(), f.session.String())
	require.Contains(t, out.String(), log.RequestID(ctx))
	require.Equal(t, f.session.String(), permission.Source(ctx).ID)
}

func TestAuthSubjectDeleteLateNativeOwnerReleaseBarrier(t *testing.T) {
	ctx := permission.SystemContext(t.Context(), "Engine")
	a, s := asApp(t, "late", ctx)
	result := make(chan error, 1)
	go func() {
		_, err := a.DeleteAuthSubject(ctx, user.AuthSubject{UserID: s.owner.String(), ProviderID: "provider", SubjectID: "subject"})
		result <- err
	}()
	select {
	case <-s.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("native Commit not entered")
	}
	select {
	case err := <-result:
		require.Error(t, err)
	case <-time.After(6 * time.Second):
		t.Fatal("bounded owner did not return")
	}
	s.mu.Lock()
	require.Equal(t, 1, s.begin)
	require.Zero(t, s.success)
	require.Zero(t, s.observations)
	s.mu.Unlock()
	close(s.gate)
	require.Eventually(t, func() bool { s.mu.Lock(); defer s.mu.Unlock(); return s.success == 1 }, time.Second, 10*time.Millisecond)
	s.mu.Lock()
	defer s.mu.Unlock()
	require.Equal(t, 1, s.commit)
	require.Equal(t, 1, s.deletes)
	require.Zero(t, s.observations)
}

func TestAuthSubjectDeleteFailureWriterLateCommit(t *testing.T) {
	ctx := permission.SystemContext(t.Context(), "Engine")
	a, s := asApp(t, "failure-late", ctx)
	result := make(chan error, 1)
	go func() {
		_, err := a.DeleteAuthSubject(ctx, user.AuthSubject{UserID: s.owner.String(), ProviderID: "provider", SubjectID: "subject"})
		result <- err
	}()
	select {
	case <-s.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("failure writer Commit not entered")
	}
	select {
	case err := <-result:
		require.Error(t, err)
	case <-time.After(4 * time.Second):
		t.Fatal("failure writer was not bounded")
	}
	s.mu.Lock()
	require.Equal(t, 2, s.begin)
	require.Zero(t, s.success)
	require.Zero(t, s.observations)
	require.Equal(t, 1, s.rollback)
	s.mu.Unlock()
	close(s.gate)
	require.Eventually(t, func() bool { s.mu.Lock(); defer s.mu.Unlock(); return s.observations == 1 }, time.Second, 10*time.Millisecond)
	s.mu.Lock()
	defer s.mu.Unlock()
	require.Equal(t, 1, s.commit)
	require.Equal(t, 1, s.deletes)
}

func TestAuthSubjectDeleteCommittedReleaseLate(t *testing.T) {
	ctx := permission.SystemContext(t.Context(), "Engine")
	a, s := asApp(t, "close-late", ctx)
	type outcome struct {
		ok  bool
		err error
	}
	result := make(chan outcome, 1)
	go func() {
		ok, err := a.DeleteAuthSubject(ctx, user.AuthSubject{UserID: s.owner.String(), ProviderID: "provider", SubjectID: "subject"})
		result <- outcome{ok, err}
	}()
	select {
	case <-s.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("native Close not entered")
	}
	select {
	case r := <-result:
		require.True(t, r.ok)
		require.NoError(t, r.err)
	case <-time.After(4 * time.Second):
		t.Fatal("release observation was not bounded")
	}
	s.mu.Lock()
	require.Equal(t, 1, s.success)
	require.Equal(t, 1, s.commit)
	require.Zero(t, s.observations)
	s.mu.Unlock()
	close(s.gate)
	require.Eventually(t, func() bool { return a.DB.Stats().InUse == 0 }, time.Second, 10*time.Millisecond)
}

func TestAuthSubjectDeleteCancellationKeepsNativeOwner(t *testing.T) {
	ctx, cancel := context.WithCancel(permission.SystemContext(t.Context(), "Engine"))
	defer cancel()
	a, s := asApp(t, "late", ctx)
	result := make(chan error, 1)
	go func() {
		_, err := a.DeleteAuthSubject(ctx, user.AuthSubject{UserID: s.owner.String(), ProviderID: "provider", SubjectID: "subject"})
		result <- err
	}()
	select {
	case <-s.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("native Commit not entered")
	}
	cancel()
	select {
	case err := <-result:
		require.Error(t, err)
	case <-time.After(4 * time.Second):
		t.Fatal("canceled owner was not bounded")
	}
	s.mu.Lock()
	require.Equal(t, 1, s.begin)
	require.Zero(t, s.observations)
	s.mu.Unlock()
	close(s.gate)
	require.Eventually(t, func() bool { s.mu.Lock(); defer s.mu.Unlock(); return s.success == 1 && s.commit == 1 }, time.Second, 10*time.Millisecond)
}

func TestAuthSubjectDeleteCanceledBeforeBegin(t *testing.T) {
	ctx, cancel := context.WithCancel(permission.SystemContext(t.Context(), "Engine"))
	a, s := asApp(t, "ok", ctx)
	cancel()
	ok, err := a.DeleteAuthSubject(ctx, user.AuthSubject{UserID: s.owner.String(), ProviderID: "provider", SubjectID: "subject"})
	require.False(t, ok)
	require.Error(t, err)
	require.Zero(t, s.deletes)
	require.Zero(t, s.success)
	require.Equal(t, 1, s.observations)
	require.Equal(t, 1, s.begin, "only the independent failure writer may begin")
}
