package graphqlapp

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/assignment"
	"github.com/target/goalert/auth"
	"github.com/target/goalert/executioncontext"
	"github.com/target/goalert/organization"
	"github.com/target/goalert/override"
	"github.com/target/goalert/permission"

	uoaudit "github.com/target/goalert/override/deleteaudit"
	"github.com/target/goalert/retry"
)

// The same controller fault model with a typed Override storage adapter. Real FK,
// migration and atomicity claims are checked separately against PostgreSQL.
type sd7Connector struct{ s *sd2State }

func (c sd7Connector) Connect(context.Context) (driver.Conn, error) {
	return &sd7Conn{&sd2Conn{s: c.s}}, nil
}
func (sd7Connector) Driver() driver.Driver { return sd2Driver{} }

type sd7Conn struct{ *sd2Conn }

func (c *sd7Conn) ExecContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Result, error) {
	q = strings.ReplaceAll(q, "schedule_rotation_delete_audit_events", "escalation_policy_delete_audit_events")
	q = strings.ReplaceAll(q, "user_override_delete_audit_events", "escalation_policy_delete_audit_events")
	return c.sd2Conn.ExecContext(ctx, q, args)
}
func (c *sd7Conn) QueryContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Rows, error) {
	if strings.Contains(q, "FROM user_override_delete_audit_events") {
		return &sd3Rows{[]string{"roots", "units", "bytes"}, [][]driver.Value{{int64(c.tx.eps), int64(0), int64(1)}}}, nil
	}
	return c.sd2Conn.QueryContext(ctx, q, args)
}
func sd7Plan(t *testing.T, s *sd2State) *deleteAllAudit {
	t.Helper()
	db := sql.OpenDB(sd7Connector{s})
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { require.NoError(t, db.Close()) })
	return newDeleteAllAudit(sd3InternalSystemContext(), db, []assignment.RawTarget{{Type: assignment.TargetTypeUserOverride}})
}
func sd7Before() uoaudit.Before {
	user := uuid.New()
	return uoaudit.Before{Version: 1, RootID: uuid.New(), ParentScheduleID: uuid.New(), TargetOrganizationID: uuid.New(), AddUserID: &user, Start: time.Now(), End: time.Now().Add(time.Hour), RowVersion: 1}
}
func sd7Attempt(t *testing.T, p *deleteAllAudit) error {
	t.Helper()
	a := p.nextAttempt()
	tx, err := a.begin(t.Context())
	if err != nil {
		return a.finish(err)
	}
	a.groupsStarted = true
	_, err = tx.ExecContext(t.Context(), "SD2 synthetic delete")
	if err == nil {
		b := sd7Before()
		a.collectUO(override.DeleteResult{Targets: []uoaudit.Before{b}, Receipts: []uoaudit.Before{b}})
		err = a.commit(t.Context())
	}
	return a.finish(err)
}
func TestUODeleteControllerLifecycle(t *testing.T) {
	for _, mode := range []string{"success", "reject:23514", "reject:40001", "reject:40P01", "unknown:40003", "unknown:08006", "commit_then_error", "rollback_then_error", "rollback_unconfirmed", "audit_failed", "temporary", "exhaust", "failure_begin", "failure_append", "failure_commit", "failure_commit_after"} {
		t.Run(mode, func(t *testing.T) {
			s := &sd2State{mode: mode}
			p := sd7Plan(t, s)
			err := retry.DoTemporaryError(func(int) error { return sd7Attempt(t, p) }, retry.Limit(5))
			want := 1
			if mode == "temporary" {
				want = 3
			}
			if mode == "exhaust" || mode == "reject:40001" || mode == "reject:40P01" {
				want = 5
			}
			require.Equal(t, want, s.deletes)
			if mode == "success" || mode == "temporary" {
				require.NoError(t, err)
				require.Equal(t, 1, s.witnesses)
			} else {
				require.Error(t, err)
				require.NotContains(t, err.Error(), "SYNTHETIC_")
			}
			if mode == "commit_then_error" || strings.HasPrefix(mode, "unknown:") {
				require.Equal(t, 1, s.witnesses)
				require.Equal(t, 1, s.observations)
			}
			for _, ids := range s.correlations {
				require.Equal(t, p.identity.RequestID.String(), ids[0])
				require.Equal(t, p.identity.ExecutionID.String(), ids[1])
			}
		})
	}
}
func TestUODeleteUncertainty(t *testing.T) {
	for _, mode := range []string{"failure_release", "failure_begin_gated", "failure_append_gated", "failure_commit_gated", "gated"} {
		t.Run(mode, func(t *testing.T) {
			s := &sd2State{mode: mode, gate: make(chan struct{}), completed: make(chan struct{})}
			p := sd7Plan(t, s)
			start := time.Now()
			err := sd7Attempt(t, p)
			close(s.gate)
			require.Eventually(t, func() bool { return p.db.Stats().InUse == 0 }, 3*time.Second, 10*time.Millisecond)
			require.Error(t, err)
			require.False(t, retry.IsTemporaryError(err))
			require.Less(t, time.Since(start), 8*time.Second)
			require.Equal(t, 1, s.deletes)
		})
	}
}

func TestUOFailureCapacity400(t *testing.T) {
	s := &sd2State{}
	p := sd7Plan(t, s)
	persisted, released := SD7FailureBatchForTest(p.db, 50, 50, 50)
	require.True(t, persisted)
	require.True(t, released)
	require.Equal(t, 400, s.observations)
	require.Equal(t, 1, s.begins)
	for _, v := range [][3]int{{50, 50, 51}, {51, 50, 49}, {50, 51, 49}} {
		persisted, released = SD7FailureBatchForTest(p.db, v[0], v[1], v[2])
		require.False(t, persisted)
		require.True(t, released)
	}
	require.Equal(t, 1, s.begins)
	for _, n := range [][7]int{{50, 100, 50, 50, 50, 50, 51}, {51, 99, 50, 50, 50, 50, 50}, {50, 101, 49, 50, 50, 50, 50}, {0, 0, 0, 0, 0, 0, -1}} {
		require.False(t, deleteAllFailureCapacity(n[0], n[1], n[2], n[3], n[4], n[5], n[6]))
	}
}
func TestUORoutesAndStrictIdentity(t *testing.T) {
	for _, other := range []assignment.TargetType{assignment.TargetTypeUser, assignment.TargetTypeSchedule, assignment.TargetTypeRotation, assignment.TargetTypeEscalationPolicy, assignment.TargetTypeService, assignment.TargetTypeContactMethod, assignment.TargetTypeNotificationRule, assignment.TargetTypeIntegrationKey} {
		p := newDeleteAllAudit(sd3InternalSystemContext(), nil, []assignment.RawTarget{{Type: assignment.TargetTypeUserOverride}, {Type: other}})
		require.NotNil(t, p)
		require.True(t, p.hasUO)
	}
	// SD8 routes pure User deletion through the same controller.
	require.True(t, newDeleteAllAudit(t.Context(), nil, []assignment.RawTarget{{Type: assignment.TargetTypeUser}}).hasUser)
	a := sd7Plan(t, &sd2State{}).nextAttempt()
	b := sd7Before()
	a.collectUO(override.DeleteResult{Targets: []uoaudit.Before{b}})
	require.Empty(t, a.uoSuccesses)
	require.Error(t, a.appendUO(t.Context()))
	require.Error(t, a.uoCaptureError(uoaudit.ErrInvalid))
	require.True(t, a.auditFailed)
}

func TestUOAuditIdentityCarriers(t *testing.T) {
	ctx, _, f := ikAuthorityContext(t, organization.OrganizationRoleMember, true)
	other, err := auth.NewRequester(uuid.NewString(), uuid.NewString())
	require.NoError(t, err)
	bare := auth.WithRequester(permission.UserSourceContext(context.Background(), f.user.String(), permission.RoleAdmin, &permission.SourceInfo{Type: permission.SourceTypeAuthProvider, ID: f.session.String()}), *auth.RequesterFromContext(ctx))
	for name, c := range map[string]context.Context{"requester": auth.WithRequester(ctx, other), "session": permission.SourceContext(ctx, &permission.SourceInfo{Type: permission.SourceTypeAuthProvider, ID: uuid.NewString()}), "source": permission.SourceContext(ctx, &permission.SourceInfo{Type: permission.SourceTypeGQLAPIKey, ID: uuid.NewString()}), "missing_ec": bare, "zero_ec": executioncontext.WithExecutionContext(bare, executioncontext.ExecutionContext{}), "system_over_human": permission.SystemContext(ctx, "Test"), "permission_disagreement": permission.UserContext(ctx, f.user.String(), permission.RoleUser)} {
		t.Run(name, func(t *testing.T) {
			p := newDeleteAllAudit(c, nil, []assignment.RawTarget{{Type: assignment.TargetTypeUserOverride}})
			a := p.nextAttempt()
			require.Equal(t, "unknown", a.uoBase.ActorKind)
			b := sd7Before()
			a.collectUO(override.DeleteResult{Targets: []uoaudit.Before{b}, Receipts: []uoaudit.Before{b}})
			require.Error(t, a.uoSuccesses[0].Validate())
		})
	}
}
