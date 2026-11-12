package graphqlapp

import (
	"bytes"
	"context"
	"database/sql"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/assignment"
	"github.com/target/goalert/integrationkey"
	keyaudit "github.com/target/goalert/integrationkey/deleteaudit"
	"github.com/target/goalert/permission"
	"github.com/target/goalert/retry"
	"github.com/target/goalert/service/deleteaudit"
	audit "github.com/target/goalert/user/cmnrdeleteaudit"
	"github.com/target/goalert/util/log"
)

func sd4Plan(t *testing.T, s *sd2State) *deleteAllAudit {
	t.Helper()
	db := sql.OpenDB(sd2Connector{s})
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { require.NoError(t, db.Close()) })
	return newDeleteAllAudit(sd3InternalSystemContext(), db, []assignment.RawTarget{{Type: assignment.TargetTypeIntegrationKey, ID: uuid.NewString()}})
}
func sd3InternalSystemContext() context.Context {
	return permission.SystemContext(context.Background(), "Engine")
}
func sd4Target(a *deleteAllAttempt) keyaudit.Event {
	e := a.keyEvent
	e.ResourceID, e.ParentServiceID, e.TargetOrganizationID, e.TargetOrgResolution = uuid.New(), uuid.New(), uuid.New(), "known_normal"
	return e
}
func sd4Attempt(t *testing.T, p *deleteAllAudit) error {
	t.Helper()
	a := p.nextAttempt()
	tx, err := a.begin(t.Context())
	if err != nil {
		return a.finish(err)
	}
	a.groupsStarted = true
	_, err = tx.ExecContext(t.Context(), "SD2 synthetic delete")
	if err == nil {
		e := sd4Target(a)
		a.keyTargets = []keyaudit.Event{e}
		err = a.collectKeyReceipts([]serviceKeyReceipt{{e.ResourceID, e.ParentServiceID, e.TargetOrganizationID}}, []integrationkey.DeleteReceipt{{ResourceID: e.ResourceID, ServiceID: e.ParentServiceID}})
	}
	if err == nil {
		err = a.commit(t.Context())
	}
	return a.finish(err)
}
func TestIntegrationKeyDeleteControllerLifecycle(t *testing.T) {
	for _, mode := range []string{"success", "reject:23514", "reject:40001", "reject:40P01", "unknown:40003", "commit_then_error", "rollback_then_error", "rollback_unconfirmed", "audit_failed", "temporary", "exhaust", "failure_begin", "failure_append", "failure_commit", "failure_commit_after"} {
		t.Run(mode, func(t *testing.T) {
			s := &sd2State{mode: mode}
			p := sd4Plan(t, s)
			err := retry.DoTemporaryError(func(int) error { return sd4Attempt(t, p) }, retry.Limit(5))
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
func TestIntegrationKeyDeletePartitionAndContradictions(t *testing.T) {
	for _, mode := range []string{"key_only", "actual_parent", "unrelated", "suppressed_parent", "missing_effect", "wrong_org", "wrong_provenance", "duplicate_receipt", "unknown_receipt", "wrong_parent", "duplicate_target"} {
		t.Run(mode, func(t *testing.T) {
			a := sd4Plan(t, &sd2State{}).nextAttempt()
			e := sd4Target(a)
			r := serviceKeyReceipt{e.ResourceID, e.ParentServiceID, e.TargetOrganizationID}
			a.keyTargets = []keyaudit.Event{e}
			result := []integrationkey.DeleteReceipt{{ResourceID: r.resource, ServiceID: r.root}}
			if mode == "unknown_receipt" {
				result[0].ResourceID = uuid.New()
			}
			if mode == "wrong_parent" {
				result[0].ServiceID = uuid.New()
			}
			if mode == "duplicate_receipt" {
				result = append(result, result[0])
			}
			err := a.collectKeyReceipts([]serviceKeyReceipt{r}, result)
			if mode == "unknown_receipt" || mode == "wrong_parent" || mode == "duplicate_receipt" {
				require.ErrorIs(t, err, keyaudit.ErrInvalid)
				return
			}
			require.NoError(t, err)
			if mode != "key_only" {
				root, org := r.root, r.org
				if mode == "unrelated" {
					root = uuid.New()
				}
				if mode == "wrong_org" {
					org = uuid.New()
				}
				se := deleteaudit.Event{ServiceID: root, TargetOrganizationID: org}
				if mode != "missing_effect" && mode != "unrelated" {
					id := r.resource
					se.Effects = []deleteaudit.Effect{{ResourceType: deleteaudit.IntegrationKey, ResourceUUID: &id, TargetOrganizationID: org, Provenance: "EXPLICIT", DeletionMechanism: "explicit_sql", Cause: "explicit_target"}}
				}
				if mode == "wrong_provenance" {
					se.Effects[0].Provenance = "CASCADE"
				}
				a.service = &serviceDeleteAttempt{}
				if mode != "suppressed_parent" {
					a.service.successes = []deleteaudit.Event{se}
				}
			}
			if mode == "duplicate_target" {
				a.keyTargets = append(a.keyTargets, e)
			}
			events, err := a.partitionKeys()
			switch mode {
			case "missing_effect", "wrong_org", "wrong_provenance", "duplicate_target":
				require.ErrorIs(t, err, keyaudit.ErrInvalid)
			default:
				require.NoError(t, err)
				want := 1
				if mode == "actual_parent" {
					want = 0
				}
				require.Len(t, events, want)
			}
		})
	}
}
func TestIntegrationKeyDeleteStickyIntegrityAndRouting(t *testing.T) {
	a := sd4Plan(t, &sd2State{}).nextAttempt()
	require.Error(t, a.keyCaptureError(keyaudit.ErrInvalid))
	require.Error(t, a.keyCaptureError(&pgconn.PgError{Code: "40001"}))
	require.True(t, a.auditFailed)
	for _, typ := range []assignment.TargetType{assignment.TargetTypeEscalationPolicy, assignment.TargetTypeIntegrationKey, assignment.TargetTypeService, assignment.TargetTypeContactMethod, assignment.TargetTypeNotificationRule} {
		require.NotNil(t, newDeleteAllAudit(t.Context(), nil, []assignment.RawTarget{{Type: typ}}))
	}
	for _, typ := range []assignment.TargetType{assignment.TargetTypeSchedule, assignment.TargetTypeRotation, assignment.TargetTypeUserOverride, assignment.TargetTypeUser} {
		require.NotNil(t, newDeleteAllAudit(t.Context(), nil, []assignment.RawTarget{{Type: typ}}))
	}
	for _, typ := range []assignment.TargetType{assignment.TargetTypeUserSession} {
		require.Nil(t, newDeleteAllAudit(t.Context(), nil, []assignment.RawTarget{{Type: typ}}))
		require.NotNil(t, newDeleteAllAudit(t.Context(), nil, []assignment.RawTarget{{Type: typ}, {Type: assignment.TargetTypeIntegrationKey}}))
	}
}
func TestIntegrationKeyDeleteFailureCapacity(t *testing.T) {
	s := &sd2State{}
	p := sd2Plan(t, s, true)
	p.hasKey = true
	// Reuse a strictly classified Key identity while retaining shared correlation.
	a := p.nextAttempt()
	a.keyEvent = sd4Plan(t, &sd2State{}).nextAttempt().keyEvent
	a.keyEvent.RequestID, a.keyEvent.ExecutionID, a.keyEvent.AttemptID = a.event.RequestID, a.event.ExecutionID, a.event.AttemptID
	for i := 0; i < 50; i++ {
		e := a.service.event
		e.ServiceID, e.TargetOrganizationID = uuid.New(), uuid.New()
		a.service.targets = append(a.service.targets, e)
		a.keyTargets = append(a.keyTargets, sd4Target(a))
	}
	for _, typ := range []string{audit.ContactMethod, audit.NotificationRule} {
		for i := 0; i < 50; i++ {
			target := audit.Target{ID: uuid.New(), OwnerID: a.event.ActorID, OrganizationID: uuid.New(), OrgResolution: "known_normal"}
			if typ == audit.NotificationRule {
				target.ParentCMID = uuid.New()
			}
			a.targets = append(a.targets, a.target(target, typ))
		}
	}
	a.groupsStarted = true
	services, cmnr, keys, eps := a.failureEvents("tx_failed", "write_failed")
	require.Len(t, keys, 50)
	require.Len(t, cmnr, 100)
	persisted, released := recordDeleteAllFailureBatch(p.db, services, cmnr, keys, eps)
	require.True(t, persisted)
	require.True(t, released)
	require.Equal(t, 200, s.observations)
	for _, sizes := range [][3]int{{50, 100, 51}, {51, 100, 50}, {50, 101, 50}} {
		sv, cm, ks := append([]deleteaudit.Event{}, services...), append([]audit.Event{}, cmnr...), append([]keyaudit.Event{}, keys...)
		for len(sv) < sizes[0] {
			sv = append(sv, services[0])
		}
		for len(cm) < sizes[1] {
			cm = append(cm, cmnr[0])
		}
		for len(ks) < sizes[2] {
			ks = append(ks, keys[0])
		}
		persisted, released = recordDeleteAllFailureBatch(p.db, sv, cm, ks, nil)
		require.False(t, persisted)
		require.True(t, released)
		require.Equal(t, 200, s.observations)
	}
}
func TestIntegrationKeyDeleteUncertainReleaseAndLateWriter(t *testing.T) {
	for _, mode := range []string{"failure_release", "failure_begin_gated", "failure_append_gated", "failure_commit_gated", "gated"} {
		t.Run(mode, func(t *testing.T) {
			s := &sd2State{mode: mode, gate: make(chan struct{}), completed: make(chan struct{})}
			p := sd4Plan(t, s)
			start := time.Now()
			err := sd4Attempt(t, p)
			close(s.gate)
			require.Eventually(t, func() bool { return p.db.Stats().InUse == 0 }, 3*time.Second, 10*time.Millisecond)
			require.Error(t, err)
			require.False(t, retry.IsTemporaryError(err))
			require.Less(t, time.Since(start), 8*time.Second)
			require.Equal(t, 1, s.deletes)
		})
	}
}
func TestIntegrationKeyDeleteDiagnostics(t *testing.T) {
	var out bytes.Buffer
	logger := log.NewLogger()
	logger.EnableDebug()
	logger.SetOutput(&out)
	p := sd4Plan(t, &sd2State{mode: "temporary"})
	p.ctx = log.WithField(log.WithLogger(p.ctx, logger), "Authorization", "SYNTHETIC_PARENT_SECRET")
	require.NoError(t, retry.DoTemporaryError(func(int) error { return sd4Attempt(t, p) }, retry.Log(p.retryContext()), retry.Limit(5)))
	require.NotContains(t, out.String(), "SYNTHETIC_")
	require.Contains(t, out.String(), p.identity.ExecutionID.String())
}

func TestIntegrationKeyDeleteStickyFailureAndSingleOwner(t *testing.T) {
	t.Run("sticky integrity blocks later temporary business error", func(t *testing.T) {
		s := &sd2State{mode: "temporary"}
		p := sd4Plan(t, s)
		a := p.nextAttempt()
		tx, err := a.begin(t.Context())
		require.NoError(t, err)
		_, err = tx.ExecContext(t.Context(), "SD2 synthetic delete")
		require.Error(t, err)
		require.Error(t, a.keyCaptureError(keyaudit.ErrInvalid))
		err = a.finish(err)
		require.Error(t, err)
		require.False(t, retry.IsTemporaryError(err))
		require.Equal(t, 1, s.deletes)
		require.Equal(t, 1, s.observations)
	})
	t.Run("confirmed Key commit survives release uncertainty", func(t *testing.T) {
		s := &sd2State{}
		p := sd4Plan(t, s)
		a := p.nextAttempt()
		tx, err := a.begin(t.Context())
		require.NoError(t, err)
		_, err = tx.ExecContext(t.Context(), "SD2 synthetic delete")
		require.NoError(t, err)
		e := sd4Target(a)
		a.keyTargets = []keyaudit.Event{e}
		require.NoError(t, a.collectKeyReceipts([]serviceKeyReceipt{{e.ResourceID, e.ParentServiceID, e.TargetOrganizationID}}, []integrationkey.DeleteReceipt{{ResourceID: e.ResourceID, ServiceID: e.ParentServiceID}}))
		require.NoError(t, a.commit(t.Context()))
		require.Error(t, a.commit(t.Context()))
		require.Equal(t, 1, s.commits)
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
}
