package graphqlapp

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/assignment"
	"github.com/target/goalert/permission"
	"github.com/target/goalert/retry"
	cmnr "github.com/target/goalert/user/cmnrdeleteaudit"
	audit "github.com/target/goalert/user/deleteaudit"
)

func sd8Plan(t *testing.T, s *sd2State) *deleteAllAudit {
	db := sql.OpenDB(sd2Connector{s})
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { require.NoError(t, db.Close()) })
	return newDeleteAllAudit(permission.SystemContext(t.Context(), "Engine"), db, []assignment.RawTarget{{Type: assignment.TargetTypeUser, ID: uuid.NewString()}})
}

type sd8NoConnect struct{ calls atomic.Int64 }

func (c *sd8NoConnect) Connect(context.Context) (driver.Conn, error) {
	c.calls.Add(1)
	return nil, errors.New("unexpected connection")
}
func (*sd8NoConnect) Driver() driver.Driver { return sd2Driver{} }

type sd8LateConnect struct {
	state                  *sd2State
	calls                  atomic.Int64
	entered, release, done chan struct{}
}

func (c *sd8LateConnect) Connect(context.Context) (driver.Conn, error) {
	if c.calls.Add(1) == 2 {
		close(c.entered)
		<-c.release // deliberately ignores cancellation
		defer close(c.done)
	}
	return &sd2Conn{s: c.state}, nil
}
func (*sd8LateConnect) Driver() driver.Driver { return sd2Driver{} }

func TestUserDeleteAuditLateConnectOwnership(t *testing.T) {
	state := &sd2State{mode: "failure_connect_gated"}
	c := &sd8LateConnect{state: state, entered: make(chan struct{}), release: make(chan struct{}), done: make(chan struct{})}
	db := sql.OpenDB(c)
	db.SetMaxIdleConns(0)
	defer db.Close()
	p := newDeleteAllAudit(permission.SystemContext(t.Context(), "Engine"), db, []assignment.RawTarget{{Type: assignment.TargetTypeUser}})
	start := time.Now()
	require.Error(t, sd8Attempt(t, p))
	require.GreaterOrEqual(t, time.Since(start), 1900*time.Millisecond)
	select {
	case <-c.entered:
	default:
		t.Fatal("native Connect was not entered")
	}
	require.EqualValues(t, 2, c.calls.Load())
	close(c.release)
	<-c.done
	require.Eventually(t, func() bool { return db.Stats().OpenConnections == 0 }, time.Second, time.Millisecond)
	require.EqualValues(t, 2, c.calls.Load(), "no replacement worker")
	state.mu.Lock()
	defer state.mu.Unlock()
	require.Equal(t, 1, state.deletes, "no business replay")
	for _, correlation := range state.correlations {
		require.NotEmpty(t, correlation[0])
	}
}

func TestUserDeleteAuditCommitReleaseOwnership(t *testing.T) {
	state := &sd2State{mode: "gated", gate: make(chan struct{}), completed: make(chan struct{})}
	p := sd8Plan(t, state)
	err := sd8Attempt(t, p)
	require.Error(t, err)
	require.False(t, retry.IsTemporaryError(err))
	require.Equal(t, 1, p.db.Stats().InUse)
	close(state.gate)
	<-state.completed
	require.Eventually(t, func() bool { return p.db.Stats().InUse == 0 }, 3*time.Second, time.Millisecond)
	state.mu.Lock()
	defer state.mu.Unlock()
	require.Equal(t, 1, state.deletes)
	require.Equal(t, 1, state.begins, "unconfirmed release must not start failure writer")
	require.Equal(t, 1, state.commits)
	require.Zero(t, state.observations)
}

func TestUserDeleteAuditFailurePreconnectAndFallback(t *testing.T) {
	connector := new(sd8NoConnect)
	db := sql.OpenDB(connector)
	defer db.Close()
	for _, sizes := range [][4]int{{50, 50, 50, 101}, {51, 50, 50, 0}, {50, 51, 50, 0}, {50, 50, 51, 0}} {
		persisted, released := SD8FailureBatchForTest(db, sizes[0], sizes[1], sizes[2], sizes[3])
		require.False(t, persisted)
		require.True(t, released)
	}
	p := newDeleteAllAudit(permission.SystemContext(t.Context(), "Engine"), db, []assignment.RawTarget{{Type: assignment.TargetTypeUser}, {Type: assignment.TargetTypeContactMethod}, {Type: assignment.TargetTypeNotificationRule}})
	a := p.nextAttempt()
	a.groupsStarted = true
	_, cmnrEvents, _, _ := a.failureEvents("tx_failed", "write_failed")
	for _, typ := range []string{cmnr.ContactMethod, cmnr.NotificationRule} {
		var events []cmnr.Event
		for _, e := range cmnrEvents {
			if e.Operation != typ+".delete" {
				continue
			}
			e.RootType, e.RootID, e.RootOwnerUserID = typ, uuid.New(), uuid.New()
			if typ == cmnr.NotificationRule {
				e.ParentCMID = uuid.New()
			}
			for range 51 {
				copy := e
				copy.EventID = uuid.New()
				require.NoError(t, copy.Canonical().Validate())
				events = append(events, copy)
			}
		}
		require.Len(t, events, 51)
		persisted, released := recordDeleteAllFailureBatchWithUser(db, nil, events, nil, nil, nil, nil)
		require.False(t, persisted)
		require.True(t, released)
	}
	fallback := a.userFailureEvents("tx_failed", "write_failed")
	require.Len(t, fallback, 1)
	require.Nil(t, fallback[0].RootID)
	require.NoError(t, fallback[0].Validate())
	a.userTargets = make([]audit.Event, 100)
	for i := range a.userTargets {
		a.userTargets[i] = a.userBase
		a.userTargets[i].RootID = audit.ID(uuid.New())
	}
	require.Len(t, a.userFailureEvents("tx_failed", "write_failed"), 100, "fallback must not create event 101")
	require.Zero(t, connector.calls.Load())
}
func sd8Attempt(t *testing.T, p *deleteAllAudit) error {
	a := p.nextAttempt()
	tx, err := a.begin(t.Context())
	if err != nil {
		return a.finish(err)
	}
	a.groupsStarted = true
	_, err = tx.ExecContext(t.Context(), "SD2 synthetic delete")
	if err == nil {
		e := a.userBase
		root := uuid.New()
		ordinal := 0
		e.RootID = &root
		e.RootOrdinal = &ordinal
		e.BeforeContext = &audit.Before{Version: 1, UserID: root, UserRole: "user", RowVersion: 1, TargetOrgResolution: "unknown", OrganizationRole: "unknown"}
		e.RecordKind, e.Outcome, e.Reason = "success_witness", "committed", "deleted"
		e.Provenance, e.DeletionMechanism, e.Cause = "EXPLICIT", "explicit_sql", "explicit_target"
		a.userTargets = []audit.Event{e}
		a.userReceipts = []audit.Receipt{{Event: e, DeletedUserID: root, DeletedRole: "user", DeletedRowVersion: 1}}
		err = a.commit(t.Context())
	}
	return a.finish(err)
}

func TestUserDeleteAuditControllerLifecycle(t *testing.T) {
	for _, mode := range []string{"success", "temporary", "commit_then_error", "rollback_then_error", "unknown:08006", "unknown:40003", "reject:23514", "audit_failed", "failure_append", "failure_commit"} {
		t.Run(mode, func(t *testing.T) {
			state := &sd2State{mode: mode}
			p := sd8Plan(t, state)
			err := retry.DoTemporaryError(func(int) error { return sd8Attempt(t, p) }, retry.Limit(5))
			if mode == "success" || mode == "temporary" {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
			state.mu.Lock()
			deletes, begins, success, observations := state.deletes, state.begins, state.witnesses, state.observations
			state.mu.Unlock()
			want := 1
			if mode == "temporary" {
				want = 3
			}
			require.Equal(t, want, deletes, "unknown/sticky must never replay")
			if mode == "commit_then_error" || mode == "unknown:08006" || mode == "unknown:40003" {
				require.Equal(t, 1, success)
				require.Equal(t, 1, observations)
				require.Equal(t, 2, begins)
			}
			if mode == "rollback_then_error" || mode == "reject:23514" || mode == "audit_failed" {
				require.Zero(t, success)
			}
		})
	}
}

func TestUserDeleteAuditFailureCapacity500(t *testing.T) {
	require.True(t, deleteAllFailureCapacityWithUser(50, 100, 50, 50, 50, 50, 50, 100))
	for _, sizes := range [][8]int{{50, 100, 50, 50, 50, 50, 50, 101}, {51, 100, 50, 50, 50, 50, 50, 100}, {50, 101, 50, 50, 50, 50, 50, 99}, {50, 100, 51, 50, 50, 50, 50, 99}, {50, 100, 50, 51, 50, 50, 50, 99}, {50, 100, 50, 50, 51, 50, 50, 99}, {50, 100, 50, 50, 50, 51, 50, 99}, {50, 100, 50, 50, 50, 50, 51, 99}, {0, 0, 0, 0, 0, 0, 0, -1}} {
		require.False(t, deleteAllFailureCapacityWithUser(sizes[0], sizes[1], sizes[2], sizes[3], sizes[4], sizes[5], sizes[6], sizes[7]))
	}
}

func TestUserDeleteAuditLateFailureWriter(t *testing.T) {
	for _, mode := range []string{"failure_begin_gated", "failure_append_gated", "failure_commit_gated"} {
		t.Run(mode, func(t *testing.T) {
			state := &sd2State{mode: mode, gate: make(chan struct{}), completed: make(chan struct{})}
			p := sd8Plan(t, state)
			start := time.Now()
			err := sd8Attempt(t, p)
			require.Error(t, err)
			require.GreaterOrEqual(t, time.Since(start), 1900*time.Millisecond)
			require.Less(t, time.Since(start), 3*time.Second)
			select {
			case <-state.completed:
			default:
				t.Fatal("native writer not entered")
			}
			state.mu.Lock()
			require.Equal(t, 1, state.deletes)
			require.Equal(t, 2, state.begins)
			state.mu.Unlock()
			close(state.gate)
			require.Eventually(t, func() bool { return p.db.Stats().InUse == 0 }, time.Second, 5*time.Millisecond)
			state.mu.Lock()
			require.Equal(t, 1, state.deletes)
			require.Equal(t, 2, state.begins)
			state.mu.Unlock()
		})
	}
}
