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
	"github.com/target/goalert/organization"
	"github.com/target/goalert/permission"
	"github.com/target/goalert/retry"
	sraudit "github.com/target/goalert/schedule/deleteaudit"
)

// The same controller fault model with a typed SR storage adapter. Real FK,
// migration and atomicity claims are checked separately against PostgreSQL.
type sd6Connector struct{ s *sd2State }

func (c sd6Connector) Connect(context.Context) (driver.Conn, error) {
	return &sd6Conn{&sd2Conn{s: c.s}}, nil
}
func (sd6Connector) Driver() driver.Driver { return sd2Driver{} }

type sd6Conn struct{ *sd2Conn }

func (c *sd6Conn) ExecContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Result, error) {
	q = strings.ReplaceAll(q, "schedule_rotation_delete_audit_events", "escalation_policy_delete_audit_events")
	return c.sd2Conn.ExecContext(ctx, q, args)
}
func (c *sd6Conn) QueryContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Rows, error) {
	if strings.Contains(q, "FROM schedule_rotation_delete_audit_events") {
		return &sd3Rows{[]string{"roots", "units", "bytes"}, [][]driver.Value{{int64(c.tx.eps), int64(0), int64(c.tx.eps * 6)}}}, nil
	}
	return c.sd2Conn.QueryContext(ctx, q, args)
}
func sd6Plan(t *testing.T, s *sd2State) *deleteAllAudit {
	t.Helper()
	db := sql.OpenDB(sd6Connector{s})
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { require.NoError(t, db.Close()) })
	return newDeleteAllAudit(sd3InternalSystemContext(), db, []assignment.RawTarget{{Type: assignment.TargetTypeSchedule}, {Type: assignment.TargetTypeRotation}})
}
func sd6Target(a *deleteAllAttempt, typ string) sraudit.Event {
	e := a.srBase[typ]
	e.RootID, e.TargetOrganizationID, e.TargetOrgResolution = uuid.New(), uuid.New(), "known_normal"
	return e
}
func sd6Attempt(t *testing.T, p *deleteAllAudit) error {
	t.Helper()
	a := p.nextAttempt()
	tx, err := a.begin(t.Context())
	if err != nil {
		return a.finish(err)
	}
	a.groupsStarted = true
	_, err = tx.ExecContext(t.Context(), "SD2 synthetic delete")
	if err == nil {
		for _, typ := range []string{sraudit.Rotation, sraudit.Schedule} {
			e := sd6Target(a, typ)
			a.srTargets = append(a.srTargets, e)
			e.RecordKind, e.Outcome, e.Reason, e.Provenance, e.DeletionMechanism, e.Cause = "success_witness", "committed", "deleted", "EXPLICIT", "explicit_sql", "explicit_target"
			a.srSuccesses = append(a.srSuccesses, e)
		}
		err = a.commit(t.Context())
	}
	return a.finish(err)
}
func TestSRDeleteControllerLifecycle(t *testing.T) {
	for _, mode := range []string{"success", "reject:23514", "reject:40001", "reject:40P01", "unknown:40003", "unknown:08006", "commit_then_error", "rollback_then_error", "rollback_unconfirmed", "audit_failed", "temporary", "exhaust", "failure_begin", "failure_append", "failure_commit", "failure_commit_after"} {
		t.Run(mode, func(t *testing.T) {
			s := &sd2State{mode: mode}
			p := sd6Plan(t, s)
			err := retry.DoTemporaryError(func(int) error { return sd6Attempt(t, p) }, retry.Limit(5))
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
				require.Equal(t, 2, s.witnesses)
			} else {
				require.Error(t, err)
				require.NotContains(t, err.Error(), "SYNTHETIC_")
			}
			if mode == "commit_then_error" || strings.HasPrefix(mode, "unknown:") {
				require.Equal(t, 2, s.witnesses)
				require.Equal(t, 2, s.observations)
			}
			for _, ids := range s.correlations {
				require.Equal(t, p.identity.RequestID.String(), ids[0])
				require.Equal(t, p.identity.ExecutionID.String(), ids[1])
			}
		})
	}
}
func TestSRDeleteUncertainty(t *testing.T) {
	for _, mode := range []string{"failure_release", "failure_begin_gated", "failure_append_gated", "failure_commit_gated", "gated"} {
		t.Run(mode, func(t *testing.T) {
			s := &sd2State{mode: mode, gate: make(chan struct{}), completed: make(chan struct{})}
			p := sd6Plan(t, s)
			start := time.Now()
			err := sd6Attempt(t, p)
			close(s.gate)
			require.Eventually(t, func() bool { return p.db.Stats().InUse == 0 }, 3*time.Second, 10*time.Millisecond)
			require.Error(t, err)
			require.False(t, retry.IsTemporaryError(err))
			require.Less(t, time.Since(start), 8*time.Second)
			require.Equal(t, 1, s.deletes)
		})
	}
}
func TestSRReceiptAndStrictAuthority(t *testing.T) {
	a := sd6Plan(t, &sd2State{}).nextAttempt()
	e := sd6Target(a, sraudit.Schedule)
	targets := []sraudit.Event{e}
	r := sraudit.Receipt{ID: e.RootID, OrganizationID: e.TargetOrganizationID}
	require.NoError(t, validateSRReceipts(targets, []sraudit.Receipt{r}))
	for _, rs := range [][]sraudit.Receipt{nil, {r, r}, {{ID: r.ID, OrganizationID: uuid.New()}}, {{ID: uuid.New(), OrganizationID: r.OrganizationID}}} {
		require.ErrorIs(t, validateSRReceipts(targets, rs), sraudit.ErrInvalid)
	}
	require.Error(t, a.srCaptureError(sraudit.ErrInvalid))
	require.True(t, a.auditFailed)
	ctx, _, _ := ikAuthorityContext(t, organization.OrganizationRoleAdmin, true)
	for _, forged := range []context.Context{context.Background(), permission.SystemContext(ctx, "Test"), permission.SystemContext(permission.UserContext(context.Background(), uuid.NewString(), permission.RoleAdmin), "Test"), permission.SourceContext(sd3InternalSystemContext(), &permission.SourceInfo{Type: permission.SourceTypeGQLAPIKey, ID: uuid.NewString()})} {
		p := newDeleteAllAudit(forged, nil, []assignment.RawTarget{{Type: assignment.TargetTypeSchedule}, {Type: assignment.TargetTypeRotation}})
		for _, e := range p.nextAttempt().srBase {
			require.NotEqual(t, "internal_system", e.ActorKind)
		}
	}
}
func TestSRFailureCapacity350(t *testing.T) {
	s := &sd2State{}
	p := sd6Plan(t, s)
	base := sd2Plan(t, &sd2State{}, true)
	p.identity, p.service = base.identity, base.service
	p.service.db = p.db
	p.hasCM, p.hasNR, p.hasKey, p.hasEP = true, true, true, true
	a := p.nextAttempt()
	for i := 0; i < 50; i++ {
		e := a.service.event
		e.ServiceID, e.TargetOrganizationID = uuid.New(), uuid.New()
		a.service.targets = append(a.service.targets, e)
		a.keyTargets = append(a.keyTargets, sd4Target(a))
		a.epTargets = append(a.epTargets, sd5Target(a))
		for _, typ := range []string{sraudit.Rotation, sraudit.Schedule} {
			a.srTargets = append(a.srTargets, sd6Target(a, typ))
		}
	}
	for i := 0; i < 100; i++ {
		e := a.event
		e.RootID, e.RootOwnerUserID, e.TargetOrganizationID, e.TargetOrgResolution = uuid.New(), e.ActorID, uuid.New(), "known_normal"
		e.RootType, e.Operation = "contact_method", "contact_method.delete"
		if i >= 50 {
			e.RootType, e.Operation, e.ParentCMID = "notification_rule", "notification_rule.delete", uuid.New()
		}
		a.targets = append(a.targets, e)
	}
	a.groupsStarted = true
	sv, cm, keys, eps := a.failureEvents("tx_failed", "write_failed")
	sr := a.srFailureEvents("tx_failed", "write_failed")
	persisted, released := recordDeleteAllFailureBatch(p.db, sv, cm, keys, eps, sr)
	require.True(t, persisted)
	require.True(t, released)
	require.Equal(t, 350, s.observations)
	require.Equal(t, 1, s.begins)
	for _, sizes := range [][6]int{{50, 100, 50, 50, 50, 51}, {50, 100, 50, 50, 51, 50}, {51, 100, 50, 50, 50, 49}, {0, 0, 0, 0, 0, 0}, {0, 0, 0, 0, -1, 1}} {
		require.False(t, deleteAllFailureCapacity(sizes[0], sizes[1], sizes[2], sizes[3], sizes[4], sizes[5]))
	}
	persisted, released = recordDeleteAllFailureBatch(p.db, sv, cm, keys, eps, append(sr, sr[0]))
	require.False(t, persisted)
	require.True(t, released)
	require.Equal(t, 1, s.begins)
}
