package graphqlapp

import (
	"bytes"
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/assignment"
	"github.com/target/goalert/organization"
	"github.com/target/goalert/retry"
	"github.com/target/goalert/service/deleteaudit"
	audit "github.com/target/goalert/user/cmnrdeleteaudit"
	"github.com/target/goalert/util/log"
)

// Deterministic database/sql lifecycle simulation; this is not native PG
// network/crash evidence. The smoke suite independently checks real PG state.
type sd2State struct {
	mu                       sync.Mutex
	mode                     string
	deletes, begins, commits int
	witnesses, observations  int
	correlations             [][3]string
	gate, completed          chan struct{}
	cascadeRoot, cascadeOrg  uuid.UUID
}
type sd2Connector struct{ state *sd2State }

func (c sd2Connector) Connect(context.Context) (driver.Conn, error) { return &sd2Conn{s: c.state}, nil }
func (sd2Connector) Driver() driver.Driver                          { return sd2Driver{} }

type sd2Driver struct{}

func (sd2Driver) Open(string) (driver.Conn, error) { return nil, errors.New("connector required") }

type sd2Conn struct {
	s  *sd2State
	tx *sd2Tx
}

func (*sd2Conn) Prepare(string) (driver.Stmt, error) { return nil, errors.New("unexpected prepare") }
func (*sd2Conn) Close() error                        { return nil }
func (c *sd2Conn) Begin() (driver.Tx, error) {
	c.s.mu.Lock()
	c.s.begins++
	n := c.s.begins
	c.s.mu.Unlock()
	if c.s.mode == "failure_begin" && n == 2 {
		return nil, errors.New("SYNTHETIC_BEGIN_SECRET")
	}
	if strings.HasPrefix(c.s.mode, "failure_begin_pg:") && n == 2 {
		return nil, &pgconn.PgError{Code: strings.TrimPrefix(c.s.mode, "failure_begin_pg:"), Message: "SYNTHETIC_SECRET"}
	}
	if c.s.mode == "failure_begin_gated" && n == 2 {
		close(c.s.completed)
		<-c.s.gate
	}
	c.tx = &sd2Tx{s: c.s}
	return c.tx, nil
}
func (c *sd2Conn) ExecContext(_ context.Context, q string, args []driver.NamedValue) (driver.Result, error) {
	if q == `SELECT pg_advisory_xact_lock(1297305411::integer,1396979713::integer)` || strings.HasPrefix(q, "LOCK TABLE ") {
		return driver.RowsAffected(0), nil
	}
	if q == "SD2 synthetic delete" {
		c.s.mu.Lock()
		c.s.deletes++
		n := c.s.deletes
		c.s.mu.Unlock()
		c.tx.business = true
		if c.s.mode == "temporary" && n <= 2 || c.s.mode == "exhaust" || c.s.mode == "rollback_unconfirmed" || strings.HasPrefix(c.s.mode, "failure_") {
			return nil, &pgconn.PgError{Code: "40001", Message: "SYNTHETIC_BUSINESS_SECRET"}
		}
		return driver.RowsAffected(1), nil
	}
	success := false
	var request, attempt, execution string
	if strings.Contains(q, "INSERT INTO user_delete_audit_events") {
		var event struct {
			RecordKind  string `json:"record_kind"`
			RequestID   string `json:"request_id"`
			ExecutionID string `json:"execution_id"`
			AttemptID   string `json:"attempt_id"`
		}
		if json.Unmarshal([]byte(args[0].Value.(string)), &event) != nil {
			return nil, errors.New("invalid synthetic user header")
		}
		success = event.RecordKind == "success_witness"
		request, execution, attempt = event.RequestID, event.ExecutionID, event.AttemptID
	} else if strings.Contains(q, "INSERT INTO user_cmnr_delete_audit_events") {
		success = args[4].Value == "success_witness"
		request, execution, attempt = args[1].Value.(string), args[2].Value.(string), args[3].Value.(string)
	} else if strings.Contains(q, "INSERT INTO service_delete_audit_events") {
		success = args[11].Value == "committed"
		if success {
			c.tx.services++
		}
		execution = args[14].Value.(string)
		request, attempt = args[2].Value.(string), args[1].Value.(string)
	} else if strings.Contains(q, "INSERT INTO escalation_policy_delete_audit_events") {
		success = args[5].Value == "success_witness"
		if success {
			c.tx.eps++
		}
		request, execution, attempt = args[2].Value.(string), args[3].Value.(string), args[4].Value.(string)
	} else if strings.Contains(q, "INSERT INTO integration_key_delete_audit_events") {
		success = args[5].Value == "success_witness"
		request, execution, attempt = args[2].Value.(string), args[3].Value.(string), args[4].Value.(string)
	} else {
		return nil, errors.New("unexpected write")
	}
	if success && c.s.mode == "audit_failed" || !success && c.s.mode == "failure_append" {
		return nil, errors.New("SYNTHETIC_AUDIT_SECRET")
	}
	if success && strings.HasPrefix(c.s.mode, "cascade:append:") {
		return nil, &pgconn.PgError{Code: strings.Split(c.s.mode, ":")[2], Message: "SYNTHETIC_AUDIT_SECRET"}
	}
	if !success && strings.HasPrefix(c.s.mode, "failure_append_pg:") {
		return nil, &pgconn.PgError{Code: strings.TrimPrefix(c.s.mode, "failure_append_pg:"), Message: "SYNTHETIC_SECRET"}
	}
	if !success && c.s.mode == "failure_append_gated" {
		select {
		case <-c.s.completed:
		default:
			close(c.s.completed)
		}
		<-c.s.gate
	}
	if success {
		c.tx.witnesses++
	} else {
		c.tx.observations++
	}
	c.tx.ids = append(c.tx.ids, [3]string{request, execution, attempt})
	return driver.RowsAffected(1), nil
}

func (c *sd2Conn) IsValid() bool {
	if c.s.mode == "failure_release" && c.tx != nil && !c.tx.business {
		<-c.s.gate
	}
	return true
}

type sd2Tx struct {
	s                       *sd2State
	business                bool
	witnesses, observations int
	services                int
	eps                     int
	ids                     [][3]string
}

func (tx *sd2Tx) Commit() error {
	mode := tx.s.mode
	if !tx.business && mode == "failure_commit_gated" {
		close(tx.s.completed)
		<-tx.s.gate
	}
	if tx.business && strings.HasPrefix(mode, "reject:") {
		return &pgconn.PgError{Code: strings.TrimPrefix(mode, "reject:")}
	}
	if tx.business && mode == "rollback_then_error" {
		return errors.New("SYNTHETIC_ACK_SECRET")
	}
	if !tx.business && mode == "failure_commit" {
		return errors.New("SYNTHETIC_FAILURE_ACK_SECRET")
	}
	if !tx.business && strings.HasPrefix(mode, "failure_commit_pg:") {
		return &pgconn.PgError{Code: strings.TrimPrefix(mode, "failure_commit_pg:"), Message: "SYNTHETIC_SECRET"}
	}
	if tx.business && mode == "gated" {
		<-tx.s.gate
	}
	tx.s.mu.Lock()
	if tx.business {
		tx.s.commits++
	}
	tx.s.witnesses += tx.witnesses
	tx.s.observations += tx.observations
	tx.s.correlations = append(tx.s.correlations, tx.ids...)
	tx.s.mu.Unlock()
	if !tx.business && mode == "failure_commit_after" {
		return errors.New("SYNTHETIC_FAILURE_ACK_SECRET")
	}
	if tx.business && mode == "gated" {
		close(tx.s.completed)
	}
	if tx.business && mode == "commit_then_error" {
		return errors.New("SYNTHETIC_ACK_SECRET")
	}
	if tx.business && strings.HasPrefix(mode, "unknown:") {
		return &pgconn.PgError{Code: strings.TrimPrefix(mode, "unknown:")}
	}
	return nil
}
func (tx *sd2Tx) Rollback() error {
	if tx.s.mode == "rollback_unconfirmed" {
		return errors.New("SYNTHETIC_ROLLBACK_SECRET")
	}
	return nil
}

func sd2Plan(t *testing.T, s *sd2State, mixed bool) *deleteAllAudit {
	t.Helper()
	db := sql.OpenDB(sd2Connector{s})
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { require.NoError(t, db.Close()) })
	input := []assignment.RawTarget{{Type: assignment.TargetTypeContactMethod, ID: uuid.NewString()}, {Type: assignment.TargetTypeNotificationRule, ID: uuid.NewString()}}
	if mixed {
		input = append(input, assignment.RawTarget{Type: assignment.TargetTypeService, ID: uuid.NewString()})
	}
	p := newDeleteAllAudit(t.Context(), db, input)
	owner, home := uuid.New(), uuid.New()
	p.identity.ActorKind, p.identity.ActorID, p.identity.HomeOrganizationID = "human", owner, home
	p.identity.AuthoritySource, p.identity.AuthorityRole, p.identity.OrganizationRole = "current_local_user_organization_at_admission", "platform_admin", "ORG_MEMBER"
	if p.service != nil {
		p.service.identity = deleteaudit.Event{RequestID: p.identity.RequestID, ActorKind: "human", ActorID: owner, HomeOrganizationID: home, AuthoritySource: p.identity.AuthoritySource, AuthorityRole: "platform_admin", OrganizationRole: "ORG_MEMBER"}
	}
	return p
}
func sd2Attempt(t *testing.T, p *deleteAllAudit) error {
	t.Helper()
	a := p.nextAttempt()
	tx, err := a.begin(t.Context())
	if err != nil {
		return a.finish(err)
	}
	a.groupsStarted = true
	_, err = tx.ExecContext(t.Context(), "SD2 synthetic delete")
	if err == nil {
		a.collect(audit.DeleteResult{Targets: []audit.Target{{ID: uuid.New(), OwnerID: a.event.ActorID, OrganizationID: uuid.New(), OrgResolution: "known_normal", Deleted: true}}}, audit.ContactMethod)
		if a.service != nil {
			e := a.service.event
			e.ServiceID, e.TargetOrganizationID, e.Outcome, e.Reason = uuid.New(), uuid.New(), "committed", "deleted"
			a.service.targets = []deleteaudit.Event{e}
			a.service.successes = []deleteaudit.Event{e}
			err = deleteaudit.Append(t.Context(), tx, e)
		}
	}
	if err == nil {
		err = a.commit(t.Context())
	}
	return a.finish(err)
}

func TestDeleteAllAuditControllerSimulation(t *testing.T) {
	for _, mixed := range []bool{false, true} {
		for _, mode := range []string{"success", "reject:23514", "reject:40001", "reject:40P01", "reject:P0001", "unknown:40003", "unknown:08006", "commit_then_error", "rollback_then_error", "rollback_unconfirmed", "audit_failed", "temporary", "exhaust", "failure_begin", "failure_append", "failure_commit", "failure_commit_after"} {
			t.Run(mode+map[bool]string{false: "/CMNR", true: "/Mixed"}[mixed], func(t *testing.T) {
				s := &sd2State{mode: mode}
				p := sd2Plan(t, s, mixed)
				err := retry.DoTemporaryError(func(int) error { return sd2Attempt(t, p) }, retry.Limit(5))
				s.mu.Lock()
				defer s.mu.Unlock()
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
				} else {
					require.Error(t, err)
					require.NotContains(t, err.Error(), "SYNTHETIC_")
					if want == 1 {
						require.False(t, retry.IsTemporaryError(err))
					}
				}
				if strings.HasPrefix(mode, "unknown:") || mode == "commit_then_error" {
					require.Equal(t, 1, s.commits)
					require.Greater(t, s.observations, 0)
				}
				if mode == "rollback_then_error" || mode == "audit_failed" {
					require.Zero(t, s.commits)
				}
				if strings.HasPrefix(mode, "failure_") {
					require.Equal(t, 2, s.begins)
					require.Contains(t, err.Error(), "audit persistence unavailable")
				}
				for _, ids := range s.correlations {
					require.Equal(t, p.identity.RequestID.String(), ids[0])
					if ids[1] != "" {
						require.Equal(t, p.identity.ExecutionID.String(), ids[1])
					}
				}
			})
		}
	}
}

func TestDeleteAllAuditFailureReleaseAndErrTxDoneGates(t *testing.T) {
	t.Run("failure persisted release unconfirmed", func(t *testing.T) {
		s := &sd2State{mode: "failure_release", gate: make(chan struct{})}
		p := sd2Plan(t, s, true)
		err := sd2Attempt(t, p)
		require.Error(t, err)
		require.False(t, retry.IsTemporaryError(err))
		require.Contains(t, err.Error(), "audit persistence unavailable")
		s.mu.Lock()
		begins, observations := s.begins, s.observations
		s.mu.Unlock()
		require.Equal(t, 2, begins)
		require.Greater(t, observations, 0, "failure observations are already durable despite unconfirmed release")
		close(s.gate)
		require.Eventually(t, func() bool { return p.db.Stats().InUse == 0 }, 3*time.Second, 10*time.Millisecond)
	})
	t.Run("ErrTxDone is insufficient rollback evidence", func(t *testing.T) {
		s := &sd2State{}
		p := sd2Plan(t, s, false)
		a := p.nextAttempt()
		tx, err := a.begin(t.Context())
		require.NoError(t, err)
		require.NoError(t, tx.Rollback())
		err = a.finish(&pgconn.PgError{Code: "40001"})
		require.Error(t, err)
		require.False(t, retry.IsTemporaryError(err))
		require.Equal(t, 2, s.begins)
		n := s.observations
		require.Error(t, a.finish(err))
		require.Equal(t, n, s.observations, "duplicate finish cannot append another failure")
	})
}

func TestDeleteAllAuditFailureNativeCallsIgnoringCancellation(t *testing.T) {
	for _, mode := range []string{"failure_begin_gated", "failure_append_gated", "failure_commit_gated"} {
		t.Run(mode, func(t *testing.T) {
			s := &sd2State{mode: mode, gate: make(chan struct{}), completed: make(chan struct{})}
			p := sd2Plan(t, s, true)
			start := time.Now()
			err := sd2Attempt(t, p)
			elapsed := time.Since(start)
			// Release and join cleanup before any assertion can terminate the test.
			select {
			case <-s.completed:
			default:
				close(s.gate)
				t.Fatal("native failure-writer gate was not reached")
			}
			close(s.gate)
			require.Eventually(t, func() bool { return p.db.Stats().InUse == 0 }, 3*time.Second, 10*time.Millisecond)
			require.Error(t, err)
			require.False(t, retry.IsTemporaryError(err))
			require.Less(t, elapsed, 3*time.Second)
			require.Contains(t, err.Error(), "audit persistence unavailable")
			s.mu.Lock()
			defer s.mu.Unlock()
			require.Equal(t, 2, s.begins)
			require.Equal(t, 1, s.deletes)
			if mode == "failure_commit_gated" {
				require.Greater(t, s.observations, 0, "a late native Commit can persist observations after an unavailable response")
			}
		})
	}
}

func TestDeleteAllAuditAtomicFailureBatchCapacity(t *testing.T) {
	s := &sd2State{}
	p := sd2Plan(t, s, true)
	a := p.nextAttempt()
	a.groupsStarted = true
	for i := 0; i < 50; i++ {
		e := a.service.event
		e.ServiceID, e.TargetOrganizationID = uuid.New(), uuid.New()
		a.service.targets = append(a.service.targets, e)
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
	services, events, keys, eps := a.failureEvents("tx_failed", "write_failed")
	require.Len(t, services, 50)
	require.Len(t, events, 100)
	persisted, released := recordDeleteAllFailureBatch(p.db, services, events, keys, eps)
	require.True(t, persisted)
	require.True(t, released)
	require.Equal(t, 1, s.begins)
	require.Equal(t, 150, s.observations)
}

func TestDeleteAllAuditDiagnosticsDiscardParentFields(t *testing.T) {
	var out bytes.Buffer
	logger := log.NewLogger()
	logger.EnableDebug()
	logger.SetOutput(&out)
	p := sd2Plan(t, &sd2State{mode: "temporary"}, true)
	p.ctx = log.WithField(log.WithLogger(t.Context(), logger), "Authorization", "SYNTHETIC_PARENT_SECRET")
	require.NoError(t, retry.DoTemporaryError(func(int) error { return sd2Attempt(t, p) }, retry.Log(p.retryContext()), retry.Limit(5)))
	require.Contains(t, out.String(), p.identity.RequestID.String())
	require.NotContains(t, out.String(), "SYNTHETIC_")
	require.NotContains(t, out.String(), "Authorization")
}

func TestDeleteAllAuditSharedIdentityAndOverlap(t *testing.T) {
	ctx, _, _ := ikAuthorityContext(t, organization.OrganizationRoleMember, false)
	ctx = log.SetRequestID(ctx)
	input := []assignment.RawTarget{{Type: assignment.TargetTypeContactMethod, ID: uuid.NewString()}}
	first, second := newDeleteAllAudit(ctx, nil, input), newDeleteAllAudit(ctx, nil, input)
	require.Equal(t, first.identity.RequestID, second.identity.RequestID)
	require.NotEqual(t, first.identity.ExecutionID, second.identity.ExecutionID, "separate resolver fields in the same request are distinct executions")
	p := sd2Plan(t, &sd2State{}, true)
	a, b := p.nextAttempt(), p.nextAttempt()
	require.Equal(t, a.event.RequestID, b.event.RequestID)
	require.Equal(t, a.event.ExecutionID, b.event.ExecutionID)
	require.NotEqual(t, a.event.AttemptID, b.event.AttemptID)
	require.Equal(t, a.event.AttemptID, a.service.event.AttemptID)
	cm, nr, implicit, late := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	p.explicitNR[nr], p.explicitNR[late] = true, true
	target := audit.Target{ID: nr, OwnerID: a.event.ActorID, ParentCMID: cm, OrganizationID: a.event.HomeOrganizationID, OrgResolution: "known_normal", Deleted: true}
	a.collect(audit.DeleteResult{Targets: []audit.Target{target}}, audit.NotificationRule)
	target.ID = cm
	target.ParentCMID = uuid.Nil
	child := audit.Target{ID: implicit, OwnerID: a.event.ActorID, ParentCMID: cm, OrganizationID: a.event.HomeOrganizationID, OrgResolution: "known_normal", Deleted: true}
	lateChild := child
	lateChild.ID = late
	a.collect(audit.DeleteResult{Targets: []audit.Target{target}, CascadeRules: []audit.Target{child, lateChild}}, audit.ContactMethod)
	require.Len(t, a.successes, 3)
	require.Len(t, a.successes[1].Effects, 1)
	require.Equal(t, implicit, *a.successes[1].Effects[0].ResourceUUID)
	require.Equal(t, "fk_cascade", a.successes[2].DeletionMechanism)
	require.Equal(t, a.successes[1].EventID, a.successes[2].CauseEventID)
	for _, e := range a.successes {
		require.NoError(t, e.Validate())
	}
}

func TestDeleteAllAuditDelayedCommitAndConfirmedReleaseFault(t *testing.T) {
	t.Run("CommitUnknown", func(t *testing.T) {
		s := &sd2State{mode: "gated", gate: make(chan struct{}), completed: make(chan struct{})}
		p := sd2Plan(t, s, true)
		start := time.Now()
		err := sd2Attempt(t, p)
		require.Error(t, err)
		require.False(t, retry.IsTemporaryError(err))
		require.Less(t, time.Since(start), 7*time.Second)
		require.Equal(t, 1, p.db.Stats().InUse)
		close(s.gate)
		<-s.completed
		require.Eventually(t, func() bool { return p.db.Stats().InUse == 0 }, 3*time.Second, 10*time.Millisecond)
		require.Equal(t, 1, s.commits)
		require.Zero(t, s.observations)
	})
	t.Run("CommitConfirmed", func(t *testing.T) {
		s := &sd2State{}
		p := sd2Plan(t, s, false)
		a := p.nextAttempt()
		tx, err := a.begin(t.Context())
		require.NoError(t, err)
		_, err = tx.ExecContext(t.Context(), "SD2 synthetic delete")
		require.NoError(t, err)
		require.NoError(t, a.commit(t.Context()))
		gate, entered, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
		go func() { defer close(done); _ = a.conn.Raw(func(any) error { close(entered); <-gate; return nil }) }()
		<-entered
		require.NoError(t, a.finish(nil), "confirmed success survives release uncertainty")
		require.Equal(t, 1, s.begins)
		close(gate)
		<-done
		require.Eventually(t, func() bool { return p.db.Stats().InUse == 0 }, 3*time.Second, 10*time.Millisecond)
	})
}
