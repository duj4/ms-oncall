package graphqlapp

import (
	"context"
	"database/sql"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/assignment"
	"github.com/target/goalert/escalation"
	epaudit "github.com/target/goalert/escalation/deleteaudit"
	"github.com/target/goalert/organization"
	"github.com/target/goalert/permission"
	"github.com/target/goalert/retry"
)

func sd5Plan(t *testing.T, s *sd2State) *deleteAllAudit {
	t.Helper()
	db := sql.OpenDB(sd2Connector{s})
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { require.NoError(t, db.Close()) })
	return newDeleteAllAudit(sd3InternalSystemContext(), db, []assignment.RawTarget{{Type: assignment.TargetTypeEscalationPolicy, ID: uuid.NewString()}})
}
func sd5Target(a *deleteAllAttempt) epaudit.Event {
	e := a.epEvent
	e.RootID, e.TargetOrganizationID, e.TargetOrgResolution = uuid.New(), uuid.New(), "known_normal"
	return e
}
func sd5Attempt(t *testing.T, p *deleteAllAudit) error {
	t.Helper()
	a := p.nextAttempt()
	tx, err := a.begin(t.Context())
	if err != nil {
		return a.finish(err)
	}
	a.groupsStarted = true
	_, err = tx.ExecContext(t.Context(), "SD2 synthetic delete")
	if err == nil {
		e := sd5Target(a)
		a.epTargets = []epaudit.Event{e}
		e.RecordKind, e.Outcome, e.Reason, e.Provenance, e.DeletionMechanism, e.Cause = "success_witness", "committed", "deleted", "EXPLICIT", "explicit_sql", "explicit_target"
		a.epSuccesses = []epaudit.Event{e}
		err = a.commit(t.Context())
	}
	return a.finish(err)
}
func TestEscalationPolicyDeleteControllerLifecycle(t *testing.T) {
	for _, mode := range []string{"success", "reject:23514", "reject:40001", "reject:40P01", "unknown:40003", "unknown:08006", "commit_then_error", "rollback_then_error", "rollback_unconfirmed", "audit_failed", "temporary", "exhaust", "failure_begin", "failure_append", "failure_commit", "failure_commit_after"} {
		t.Run(mode, func(t *testing.T) {
			s := &sd2State{mode: mode}
			p := sd5Plan(t, s)
			err := retry.DoTemporaryError(func(int) error { return sd5Attempt(t, p) }, retry.Limit(5))
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
				require.Equal(t, 1, s.commits)
				require.Equal(t, 1, s.witnesses)
			} else {
				require.Error(t, err)
				require.NotContains(t, err.Error(), "SYNTHETIC_")
			}
			if mode == "commit_then_error" || strings.HasPrefix(mode, "unknown:") {
				require.Equal(t, 1, s.witnesses)
				require.Greater(t, s.observations, 0)
			}
			for _, ids := range s.correlations {
				require.Equal(t, p.identity.RequestID.String(), ids[0])
				require.Equal(t, p.identity.ExecutionID.String(), ids[1])
			}
		})
	}
}
func TestEscalationPolicyDeleteUncertainty(t *testing.T) {
	for _, mode := range []string{"failure_release", "failure_begin_gated", "failure_append_gated", "failure_commit_gated", "gated"} {
		t.Run(mode, func(t *testing.T) {
			s := &sd2State{mode: mode, gate: make(chan struct{}), completed: make(chan struct{})}
			p := sd5Plan(t, s)
			start := time.Now()
			err := sd5Attempt(t, p)
			close(s.gate)
			require.Eventually(t, func() bool { return p.db.Stats().InUse == 0 }, 3*time.Second, 10*time.Millisecond)
			require.Error(t, err)
			require.False(t, retry.IsTemporaryError(err))
			require.Less(t, time.Since(start), 8*time.Second)
			require.Equal(t, 1, s.deletes)
		})
	}
}
func TestEscalationPolicyDeleteReceiptIntegrity(t *testing.T) {
	for _, mode := range []string{"correct", "missing", "extra", "duplicate", "wrong_org"} {
		t.Run(mode, func(t *testing.T) {
			a := sd5Plan(t, &sd2State{}).nextAttempt()
			e := sd5Target(a)
			a.epTargets = []epaudit.Event{e}
			r := []escalation.DeleteReceipt{{ID: e.RootID, OrganizationID: e.TargetOrganizationID}}
			switch mode {
			case "missing":
				r = nil
			case "extra":
				r = append(r, escalation.DeleteReceipt{ID: uuid.New(), OrganizationID: e.TargetOrganizationID})
			case "duplicate":
				r = append(r, r[0])
			case "wrong_org":
				r[0].OrganizationID = uuid.New()
			}
			err := a.collectEPReceipts(r)
			if mode == "correct" {
				require.NoError(t, err)
			} else {
				require.ErrorIs(t, err, epaudit.ErrInvalid)
			}
		})
	}
	a := sd5Plan(t, &sd2State{}).nextAttempt()
	require.Error(t, a.epCaptureError(epaudit.ErrInvalid))
	require.Error(t, a.epCaptureError(&pgconn.PgError{Code: "40001"}))
	require.True(t, a.auditFailed)
	require.Len(t, a.epFailureEvents("denied", "authority_denied"), 1)
	a.epInUse = true
	require.Equal(t, "target_in_use", a.epFailureEvents("validation_failed", "invalid_fields")[0].Reason)
	require.Equal(t, "commit_unconfirmed", a.epFailureEvents("commit_unknown", "commit_unconfirmed")[0].Reason)
}
func TestEscalationPolicyDeleteFailureCapacity250(t *testing.T) {
	s := &sd2State{}
	p := sd2Plan(t, s, true)
	p.hasKey, p.hasEP = true, true
	a := p.nextAttempt()
	a.epEvent = sd5Plan(t, &sd2State{}).nextAttempt().epEvent
	a.epEvent.RequestID, a.epEvent.ExecutionID, a.epEvent.AttemptID = a.event.RequestID, a.event.ExecutionID, a.event.AttemptID
	for i := 0; i < 50; i++ {
		e := a.service.event
		e.ServiceID, e.TargetOrganizationID = uuid.New(), uuid.New()
		a.service.targets = append(a.service.targets, e)
		a.keyTargets = append(a.keyTargets, sd4Target(a))
		a.epTargets = append(a.epTargets, sd5Target(a))
	}
	// Build CM/NR through the existing collector identity projection.
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
	require.Len(t, sv, 50)
	require.Len(t, cm, 100)
	require.Len(t, keys, 50)
	require.Len(t, eps, 50)
	persisted, released := recordDeleteAllFailureBatch(p.db, sv, cm, keys, eps)
	require.True(t, persisted)
	require.True(t, released)
	require.Equal(t, 250, s.observations)
	require.Equal(t, 1, s.begins)
	for _, n := range [][4]int{{51, 100, 50, 50}, {50, 101, 50, 50}, {50, 100, 51, 50}, {50, 100, 50, 51}, {0, 0, 0, 251}, {0, 0, 0, 0}} {
		require.False(t, deleteAllFailureCapacity(n[0], n[1], n[2], n[3]))
	}
	persisted, released = recordDeleteAllFailureBatch(p.db, sv, cm, keys, append(eps, eps[0]))
	require.False(t, persisted)
	require.True(t, released)
	require.Equal(t, 250, s.observations)
}
func TestEscalationPolicyDeleteStrictSystemAndRoutes(t *testing.T) {
	for _, typ := range []assignment.TargetType{assignment.TargetTypeEscalationPolicy, assignment.TargetTypeService, assignment.TargetTypeIntegrationKey, assignment.TargetTypeContactMethod, assignment.TargetTypeNotificationRule, assignment.TargetTypeSchedule, assignment.TargetTypeRotation} {
		require.NotNil(t, newDeleteAllAudit(context.Background(), nil, []assignment.RawTarget{{Type: typ}}))
	}
	for _, typ := range []assignment.TargetType{assignment.TargetTypeUserSession} {
		require.Nil(t, newDeleteAllAudit(context.Background(), nil, []assignment.RawTarget{{Type: typ}}))
	}
	e := sd5Plan(t, &sd2State{}).nextAttempt().epEvent
	require.Equal(t, "internal_system", e.ActorKind)
	ctx, _, _ := ikAuthorityContext(t, organization.OrganizationRoleAdmin, true)
	for _, forged := range []context.Context{permission.SystemContext(ctx, "Test"), permission.SourceContext(sd3InternalSystemContext(), &permission.SourceInfo{Type: permission.SourceTypeGQLAPIKey, ID: uuid.NewString()}), permission.SystemContext(permission.UserContext(context.Background(), uuid.NewString(), permission.RoleAdmin), "Test")} {
		p := newDeleteAllAudit(forged, nil, []assignment.RawTarget{{Type: assignment.TargetTypeEscalationPolicy}})
		require.NotEqual(t, "internal_system", p.nextAttempt().epEvent.ActorKind)
	}
}

func TestEscalationPolicyDeleteConfirmedCommitAndStickyFailure(t *testing.T) {
	t.Run("single Commit and confirmed cleanup fault", func(t *testing.T) {
		s := &sd2State{}
		p := sd5Plan(t, s)
		a := p.nextAttempt()
		tx, err := a.begin(t.Context())
		require.NoError(t, err)
		_, err = tx.ExecContext(t.Context(), "SD2 synthetic delete")
		require.NoError(t, err)
		e := sd5Target(a)
		a.epTargets = []epaudit.Event{e}
		e.RecordKind, e.Outcome, e.Reason, e.Provenance, e.DeletionMechanism, e.Cause = "success_witness", "committed", "deleted", "EXPLICIT", "explicit_sql", "explicit_target"
		a.epSuccesses = []epaudit.Event{e}
		require.NoError(t, a.commit(t.Context()))
		require.Error(t, a.commit(t.Context()))
		gate, entered, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
		go func() { defer close(done); _ = a.conn.Raw(func(any) error { close(entered); <-gate; return nil }) }()
		<-entered
		require.NoError(t, a.finish(nil))
		require.Error(t, a.finish(nil))
		close(gate)
		<-done
		require.Eventually(t, func() bool { return p.db.Stats().InUse == 0 }, 3*time.Second, 10*time.Millisecond)
		require.Equal(t, 1, s.begins)
		require.Equal(t, 1, s.witnesses)
		require.Zero(t, s.observations)
	})
	t.Run("integrity remains sticky across later SQL abort", func(t *testing.T) {
		s := &sd2State{mode: "temporary"}
		p := sd5Plan(t, s)
		a := p.nextAttempt()
		tx, err := a.begin(t.Context())
		require.NoError(t, err)
		_, err = tx.ExecContext(t.Context(), "SD2 synthetic delete")
		require.Error(t, err)
		require.Error(t, a.epCaptureError(epaudit.ErrInvalid))
		err = a.finish(err)
		require.Error(t, err)
		require.False(t, retry.IsTemporaryError(err))
		require.Equal(t, 1, s.deletes)
	})
}
