package graphqlapp

import (
	"bytes"
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/assignment"
	"github.com/target/goalert/auth"
	"github.com/target/goalert/organization"
	"github.com/target/goalert/permission"
	"github.com/target/goalert/retry"
	"github.com/target/goalert/service/deleteaudit"
	"github.com/target/goalert/util/log"
	"github.com/target/goalert/validation"
)

func TestServiceDeleteAuditMixedErrorMapping(t *testing.T) {
	for _, tc := range []struct{ code, constraint, detail, hint, field, reason string }{
		{"23503", "services_escalation_policy_id_fkey", "is still referenced SYNTHETIC_SQL_SECRET", "SYNTHETIC_HINT_SECRET", "EscalationPolicyID", "is currently in use"},
		{"23503", "services_escalation_policy_id_fkey", "is not present SYNTHETIC_SQL_SECRET", "", "EscalationPolicyID", "does not exist"},
		{"23503", "rotation_participants_user_id_fkey", "SYNTHETIC_SQL_SECRET", "", "UserID", "user does not exist"},
		{"23514", "user_override_no_conflict_allowed", "", "SYNTHETIC_HINT_SECRET", "UserID", "cannot override the same user twice at the same time"},
	} {
		err := serviceDeleteSafeError(&pgconn.PgError{Code: tc.code, ConstraintName: tc.constraint, Detail: tc.detail, Hint: tc.hint, Message: "SYNTHETIC_MESSAGE_SECRET"})
		var field validation.FieldError
		require.ErrorAs(t, err, &field)
		require.Equal(t, tc.field, field.Field())
		require.Contains(t, field.Reason(), tc.reason)
		require.NotContains(t, err.Error(), "SYNTHETIC_")
	}
	err := serviceDeleteSafeError(&pgconn.PgError{Code: "08006", Message: "SYNTHETIC_CONNECTION_SECRET"})
	require.EqualError(t, err, "service.delete transaction failed")
	require.False(t, retry.IsTemporaryError(err), "only finish can mark a confirmed non-commit retryable")
}

func TestServiceDeleteAuditIdentityAndScope(t *testing.T) {
	input := []assignment.RawTarget{{Type: assignment.TargetTypeService, ID: "SYNTHETIC_UNTRUSTED_ID"}}
	ctx, _, f := ikAuthorityContext(t, organization.OrganizationRoleAdmin, true)
	ctx = log.SetRequestID(ctx)
	p := newServiceDeleteAudit(ctx, nil, input)
	a, b := p.nextAttempt(), p.nextAttempt()
	require.Equal(t, f.user, a.event.ActorID)
	require.Equal(t, f.home, a.event.HomeOrganizationID)
	require.Equal(t, "platform_admin", a.event.AuthorityRole)
	require.Equal(t, log.RequestID(ctx), a.event.RequestID.String())
	require.Equal(t, a.event.RequestID, b.event.RequestID)
	require.NotEqual(t, a.event.AttemptID, b.event.AttemptID)
	require.NotEqual(t, a.event.EventID, b.event.EventID)
	require.Equal(t, uuid.Nil, a.event.ServiceID)
	require.Equal(t, uuid.Nil, a.event.TargetOrganizationID)
	require.Nil(t, newServiceDeleteAudit(ctx, nil, []assignment.RawTarget{{Type: assignment.TargetTypeSchedule, ID: uuid.NewString()}}))
	other, err := auth.NewRequester(uuid.NewString(), uuid.NewString())
	require.NoError(t, err)
	for _, bad := range []context.Context{nil, context.Background(), auth.WithRequester(ctx, other), permission.SystemContext(ctx, "forged"), permission.ServiceContext(ctx, uuid.NewString())} {
		e := newServiceDeleteAudit(bad, nil, input).nextAttempt().event
		require.Equal(t, "unknown", e.ActorKind)
		require.Equal(t, uuid.Nil, e.ActorID)
		require.Equal(t, uuid.Nil, e.HomeOrganizationID)
	}
	e := newServiceDeleteAudit(permission.SystemContext(context.Background(), "Engine"), nil, input).nextAttempt().event
	require.Equal(t, "internal_system", e.ActorKind)
	require.Equal(t, "trusted_internal_system", e.AuthoritySource)
	require.Equal(t, 1, f.queries)
}

// This in-memory driver is a deterministic lifecycle experiment, not native
// PostgreSQL fault evidence. Real PG transaction tests live in test/smoke.
type sd1DriverState struct {
	mu                 sync.Mutex
	mode               string
	gate, completed    chan struct{}
	deletes, committed int
	events             [][]driver.NamedValue
}
type sd1Connector struct{ state *sd1DriverState }

func (c sd1Connector) Connect(context.Context) (driver.Conn, error) {
	return &sd1Conn{state: c.state}, nil
}
func (sd1Connector) Driver() driver.Driver { return sd1Driver{} }

type sd1Driver struct{}

func (sd1Driver) Open(string) (driver.Conn, error) { return nil, errors.New("connector required") }

type sd1Conn struct {
	state *sd1DriverState
	tx    *sd1Tx
}

func (*sd1Conn) Prepare(string) (driver.Stmt, error) { return nil, errors.New("unexpected prepare") }
func (*sd1Conn) Close() error                        { return nil }
func (c *sd1Conn) Begin() (driver.Tx, error)         { c.tx = &sd1Tx{state: c.state}; return c.tx, nil }
func (c *sd1Conn) ExecContext(_ context.Context, q string, args []driver.NamedValue) (driver.Result, error) {
	if q == "SD1 synthetic delete" {
		c.state.mu.Lock()
		c.state.deletes++
		n := c.state.deletes
		c.state.mu.Unlock()
		if c.state.mode == "temporary" && n <= 2 {
			return nil, &pgconn.PgError{Code: "40001", Message: "SYNTHETIC_SQL_SECRET"}
		}
		if c.state.mode == "exhaust" {
			return nil, &pgconn.PgError{Code: "40P01"}
		}
		c.tx.business = true
		return driver.RowsAffected(1), nil
	}
	if !strings.Contains(q, "INSERT INTO service_delete_audit_events") {
		return nil, errors.New("unexpected write")
	}
	if c.state.mode == "audit_failed" && args[11].Value == "committed" {
		return nil, errors.New("SYNTHETIC_AUDIT_SECRET")
	}
	c.tx.events = append(c.tx.events, append([]driver.NamedValue(nil), args...))
	return driver.RowsAffected(1), nil
}

type sd1Tx struct {
	state    *sd1DriverState
	business bool
	events   [][]driver.NamedValue
}

func (tx *sd1Tx) Commit() error {
	if tx.business && tx.state.mode == "rejected" {
		return &pgconn.PgError{Code: "23514", Message: "SYNTHETIC_COMMIT_SECRET"}
	}
	if tx.business && tx.state.mode == "gated" {
		<-tx.state.gate
	}
	tx.state.mu.Lock()
	if tx.business {
		tx.state.committed++
	}
	tx.state.events = append(tx.state.events, tx.events...)
	tx.state.mu.Unlock()
	if tx.business && tx.state.mode == "gated" {
		close(tx.state.completed)
	}
	if tx.business && tx.state.mode == "unknown" {
		return errors.New("SYNTHETIC_ACK_SECRET")
	}
	if tx.business && tx.state.mode == "completion_unknown" {
		return &pgconn.PgError{Code: "40003"}
	}
	return nil
}
func (tx *sd1Tx) Rollback() error {
	if tx.state.mode == "rollback_unconfirmed" {
		return errors.New("SYNTHETIC_ROLLBACK_SECRET")
	}
	return nil
}

func sd1TestPlan(t *testing.T, state *sd1DriverState) *serviceDeleteAudit {
	t.Helper()
	db := sql.OpenDB(sd1Connector{state})
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { require.NoError(t, db.Close()) })
	home := uuid.New()
	return &serviceDeleteAudit{ctx: t.Context(), db: db, identity: deleteaudit.Event{RequestID: uuid.New(), ActorKind: "human", ActorID: uuid.New(), HomeOrganizationID: home, AuthoritySource: "current_local_user_organization_at_admission", AuthorityRole: "org_admin", OrganizationRole: "ORG_ADMIN"}}
}
func sd1TestAttempt(t *testing.T, p *serviceDeleteAudit) error {
	t.Helper()
	a := p.nextAttempt()
	tx, err := a.begin(t.Context())
	require.NoError(t, err)
	_, err = tx.ExecContext(t.Context(), "SD1 synthetic delete")
	if err == nil {
		e := a.event
		e.ServiceID, e.TargetOrganizationID = uuid.New(), e.HomeOrganizationID
		a.targets = []deleteaudit.Event{e}
		if a.plan.db != nil {
			e.Outcome, e.Reason = "committed", "deleted"
			err = deleteaudit.Append(t.Context(), tx, e)
			a.auditFailed = err != nil
		}
	}
	if err == nil {
		err = a.commit(t.Context())
	}
	return a.finish(err)
}

func TestServiceDeleteAuditSimulatedLifecycle(t *testing.T) {
	for _, mode := range []string{"success", "unknown", "completion_unknown", "rejected", "audit_failed", "temporary", "exhaust"} {
		t.Run(mode, func(t *testing.T) {
			s := &sd1DriverState{mode: mode}
			p := sd1TestPlan(t, s)
			err := retry.DoTemporaryError(func(int) error { return sd1TestAttempt(t, p) }, retry.Limit(5))
			s.mu.Lock()
			defer s.mu.Unlock()
			wantDeletes, wantCommitted, wantEvents := 1, 0, 1
			switch mode {
			case "success":
				wantCommitted = 1
				require.NoError(t, err)
			case "unknown", "completion_unknown":
				wantCommitted, wantEvents = 1, 2
				require.Error(t, err)
				require.False(t, retry.IsTemporaryError(err))
				require.Equal(t, "commit_unknown", s.events[1][11].Value)
				require.Equal(t, s.events[0][1].Value, s.events[1][1].Value)
				require.NotEqual(t, s.events[0][0].Value, s.events[1][0].Value)
			case "temporary":
				wantDeletes, wantCommitted, wantEvents = 3, 1, 3
				require.NoError(t, err)
			case "exhaust":
				wantDeletes, wantEvents = 5, 5
				require.Error(t, err)
			default:
				require.Error(t, err)
			}
			require.Equal(t, wantDeletes, s.deletes)
			require.Equal(t, wantCommitted, s.committed)
			require.Len(t, s.events, wantEvents)
			attempts := map[driver.Value]bool{}
			for _, e := range s.events {
				require.Equal(t, p.identity.RequestID.String(), e[2].Value)
				attempts[e[1].Value] = true
			}
			require.Len(t, attempts, wantDeletes)
			if err != nil {
				require.NotContains(t, err.Error(), "SYNTHETIC_")
			}
		})
	}
}

func TestServiceDeleteAuditDelayedCommitReleaseBarrier(t *testing.T) {
	s := &sd1DriverState{mode: "gated", gate: make(chan struct{}), completed: make(chan struct{})}
	p := sd1TestPlan(t, s)
	closed := false
	defer func() {
		if !closed {
			close(s.gate)
		}
	}()
	start := time.Now()
	err := sd1TestAttempt(t, p)
	require.Error(t, err)
	require.False(t, retry.IsTemporaryError(err))
	require.Contains(t, err.Error(), "audit persistence unavailable")
	require.Less(t, time.Since(start), 8*time.Second)
	require.Equal(t, 1, p.db.Stats().InUse)
	s.mu.Lock()
	require.Equal(t, 1, s.deletes)
	require.Empty(t, s.events)
	s.mu.Unlock()
	close(s.gate)
	closed = true
	select {
	case <-s.completed:
	case <-time.After(3 * time.Second):
		t.Fatal("controlled Commit did not complete")
	}
	require.Eventually(t, func() bool { return p.db.Stats().InUse == 0 }, 3*time.Second, 10*time.Millisecond)
	s.mu.Lock()
	defer s.mu.Unlock()
	require.Equal(t, 1, s.deletes)
	require.Equal(t, 1, s.committed)
	require.Len(t, s.events, 1)
	require.Equal(t, "committed", s.events[0][11].Value)
}

func TestServiceDeleteAuditUnavailableFaultProjection(t *testing.T) {
	ctx, _, _ := ikAuthorityContext(t, organization.OrganizationRoleMember, false)
	logger := log.NewLogger()
	var out bytes.Buffer
	logger.SetOutput(&out)
	ctx = log.SetRequestID(log.WithField(log.WithLogger(ctx, logger), "Authorization", "SYNTHETIC_LOG_SECRET"))
	_, err := new(App).Mutation().DeleteAll(ctx, []assignment.RawTarget{{Type: assignment.TargetTypeService, ID: uuid.NewString()}})
	require.True(t, permission.IsPermissionError(err))
	require.Contains(t, err.Error(), "audit persistence unavailable")
	require.Contains(t, out.String(), log.RequestID(ctx))
	require.NotContains(t, out.String(), "SYNTHETIC_LOG_SECRET")
	require.NotContains(t, out.String(), "AuthSource")
}
