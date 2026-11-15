package graphqlapp

import (
	"bytes"
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/target/goalert/organization"
	"github.com/target/goalert/permission"
	"github.com/target/goalert/util/log"
	"github.com/vektah/gqlparser/v2/ast"
	"github.com/vektah/gqlparser/v2/gqlerror"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	sraudit "github.com/target/goalert/schedule/deleteaudit"
	"github.com/target/goalert/schedule/rule"
	"github.com/target/goalert/validation"
)

func scheduleTargetUpdateTestEvent(ctx context.Context) sraudit.Event {
	e := scheduleTargetUpdateAuditEvent(ctx)
	e.RootID, e.TargetOrganizationID, e.TargetOrgResolution = uuid.New(), uuid.New(), "known_normal"
	return e
}

func scheduleTargetUpdateTestEffect(t *testing.T, e sraudit.Event) sraudit.Effect {
	t.Helper()
	f, err := scheduleTargetRuleEffect(e, rule.DeleteReceipt{ID: uuid.New(), ScheduleID: e.RootID, TargetKind: "user", TargetID: uuid.New()})
	require.NoError(t, err)
	return f
}

// These are deterministic database/sql fault simulations, not PostgreSQL FK,
// native connection loss or concurrency evidence.
func TestScheduleTargetUpdateLifecycle(t *testing.T) {
	for _, mode := range []string{"success", "reject:23514", "reject:40001", "reject:40P01", "unknown:40003", "unknown:08006", "commit_then_error", "rollback_then_error", "rollback_unconfirmed", "audit_failed", "temporary", "exhaust", "failure_begin", "failure_append", "failure_commit", "failure_commit_after", "validation"} {
		t.Run(mode, func(t *testing.T) {
			s := &sd2State{mode: mode}
			db := sql.OpenDB(scheduleTargetLifecycleConnector{s})
			db.SetMaxOpenConns(1)
			t.Cleanup(func() { require.NoError(t, db.Close()) })
			ctx := sd3InternalSystemContext()
			e := scheduleTargetUpdateTestEvent(ctx)
			err := withScheduleTargetUpdateAuditTx(ctx, db, &e, func(ctx context.Context, tx *sql.Tx) error {
				e.Effects = []sraudit.Effect{scheduleTargetUpdateTestEffect(t, e)}
				_, err := tx.ExecContext(ctx, "SD2 synthetic delete")
				if mode == "validation" {
					return validation.NewFieldError("ID", "does not exist")
				}
				return err
			})
			require.Equal(t, 1, s.deletes, "no blind replay, including serialization/deadlock and Commit Unknown")
			if mode == "success" {
				require.NoError(t, err)
				require.Equal(t, 1, s.witnesses)
				require.Equal(t, 1, s.commits)
				require.Zero(t, s.observations)
			} else {
				require.Error(t, err)
				require.NotContains(t, err.Error(), "SYNTHETIC")
				committed := strings.HasPrefix(mode, "unknown:") || mode == "commit_then_error"
				if committed {
					require.Equal(t, 1, s.witnesses)
				} else {
					require.Zero(t, s.witnesses)
				}
				if !strings.HasPrefix(mode, "failure_") {
					require.Equal(t, 1, s.observations)
				}
			}
			for _, ids := range s.correlations {
				require.Equal(t, e.RequestID.String(), ids[0])
				require.Equal(t, e.ExecutionID.String(), ids[1])
				require.Equal(t, e.AttemptID.String(), ids[2])
			}
			require.Zero(t, db.Stats().InUse)
		})
	}
}

func TestScheduleTargetUpdateNoDeletionAndInheritedOwner(t *testing.T) {
	for _, mode := range []string{"no_deletion", "outer_commit", "outer_rollback", "outer_validation"} {
		t.Run(mode, func(t *testing.T) {
			s := &sd2State{}
			db := sql.OpenDB(scheduleTargetLifecycleConnector{s})
			db.SetMaxOpenConns(1)
			defer db.Close()
			ctx := sd3InternalSystemContext()
			e := scheduleTargetUpdateTestEvent(ctx)
			var outer *sql.Tx
			if mode != "no_deletion" {
				var err error
				outer, err = db.BeginTx(ctx, nil)
				require.NoError(t, err)
				defer outer.Rollback()
				ctx = context.WithValue(ctx, txKey, outer)
			}
			err := withScheduleTargetUpdateAuditTx(ctx, db, &e, func(ctx context.Context, tx *sql.Tx) error {
				if outer != nil {
					require.Same(t, outer, tx)
					_, err := tx.ExecContext(ctx, "SD2 synthetic delete")
					require.NoError(t, err)
					e.Effects = []sraudit.Effect{scheduleTargetUpdateTestEffect(t, e)}
				}
				if mode == "outer_validation" {
					return validation.NewFieldError("ID", "does not exist")
				}
				return nil
			})
			if mode == "outer_validation" {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			require.Equal(t, 1, s.begins)
			require.Zero(t, s.witnesses)
			require.Zero(t, s.observations)
			if mode == "outer_commit" {
				require.NoError(t, outer.Commit())
				require.Equal(t, 1, s.witnesses)
			} else if outer != nil {
				require.NoError(t, outer.Rollback())
			}
		})
	}
}

func TestScheduleTargetUpdateCommitUnknownReleaseBarrier(t *testing.T) {
	s := &sd2State{mode: "gated", gate: make(chan struct{}), completed: make(chan struct{})}
	db := sql.OpenDB(scheduleTargetLifecycleConnector{s})
	db.SetMaxOpenConns(1)
	defer db.Close()
	ctx := sd3InternalSystemContext()
	e := scheduleTargetUpdateTestEvent(ctx)
	err := withScheduleTargetUpdateAuditTx(ctx, db, &e, func(ctx context.Context, tx *sql.Tx) error {
		e.Effects = []sraudit.Effect{scheduleTargetUpdateTestEffect(t, e)}
		_, err := tx.ExecContext(ctx, "SD2 synthetic delete")
		return err
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "audit persistence unavailable")
	require.Equal(t, 1, s.begins, "no independent failure writer before business release")
	close(s.gate)
	<-s.completed
	require.Eventually(t, func() bool { return db.Stats().InUse == 0 }, 3*time.Second, 10*time.Millisecond)
	require.Equal(t, 1, s.deletes)
	require.Equal(t, 1, s.witnesses, "late commit cannot be claimed rolled back")
}

func TestScheduleTargetUpdateConfirmedCommitCleanupAndPanic(t *testing.T) {
	t.Run("confirmed_commit_cleanup", func(t *testing.T) {
		s := &sd2State{}
		db := sql.OpenDB(scheduleTargetLifecycleConnector{s})
		db.SetMaxOpenConns(1)
		defer db.Close()
		ctx := sd3InternalSystemContext()
		e := scheduleTargetUpdateTestEvent(ctx)
		e.Effects = []sraudit.Effect{scheduleTargetUpdateTestEffect(t, e)}
		e.RecordKind, e.Outcome, e.Reason = "success_witness", "committed", "children_deleted"
		e.Provenance, e.DeletionMechanism, e.Cause = "EXPLICIT", "explicit_sql", "update_induced"
		conn, err := db.Conn(ctx)
		require.NoError(t, err)
		tx, err := conn.BeginTx(ctx, nil)
		require.NoError(t, err)
		_, err = tx.ExecContext(ctx, "SD2 synthetic delete")
		require.NoError(t, err)
		require.NoError(t, sraudit.Append(ctx, tx, e))
		err, finalized := commitServiceUpdate(ctx, tx)
		require.NoError(t, err)
		gate, entered, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
		go func() { defer close(done); _ = conn.Raw(func(any) error { close(entered); <-gate; return nil }) }()
		<-entered
		require.NoError(t, finishScheduleTargetUpdateAudit(ctx, db, conn, tx, true, finalized, e, nil))
		require.Equal(t, 1, s.witnesses)
		require.Zero(t, s.observations)
		close(gate)
		<-done
		require.Eventually(t, func() bool { return db.Stats().InUse == 0 }, 3*time.Second, 10*time.Millisecond)
	})
	t.Run("panic_rolls_back", func(t *testing.T) {
		s := &sd2State{}
		db := sql.OpenDB(scheduleTargetLifecycleConnector{s})
		defer db.Close()
		ctx := sd3InternalSystemContext()
		e := scheduleTargetUpdateTestEvent(ctx)
		require.Panics(t, func() {
			_ = withScheduleTargetUpdateAuditTx(ctx, db, &e, func(ctx context.Context, tx *sql.Tx) error {
				_, err := tx.ExecContext(ctx, "SD2 synthetic delete")
				require.NoError(t, err)
				e.Effects = []sraudit.Effect{scheduleTargetUpdateTestEffect(t, e)}
				panic("synthetic interruption")
			})
		})
		require.Zero(t, s.witnesses)
		require.Equal(t, 1, s.observations)
		require.Zero(t, db.Stats().InUse)
	})
}

// Reuse the established deterministic fault driver with the identical leading
// event column layout. This adapter changes only its recognized table name.
type scheduleTargetLifecycleConnector struct{ state *sd2State }

func (c scheduleTargetLifecycleConnector) Driver() driver.Driver { return sd2Driver{} }
func (c scheduleTargetLifecycleConnector) Connect(context.Context) (driver.Conn, error) {
	return &scheduleTargetLifecycleConn{sd2Conn: &sd2Conn{s: c.state}}, nil
}

type scheduleTargetLifecycleConn struct{ *sd2Conn }

func (c *scheduleTargetLifecycleConn) ExecContext(ctx context.Context, q string, args []driver.NamedValue) (driver.Result, error) {
	return c.sd2Conn.ExecContext(ctx, strings.ReplaceAll(q, "schedule_rotation_delete_audit_events", "escalation_policy_delete_audit_events"), args)
}

func TestScheduleTargetUpdateTrustedAttributionAndAuthority(t *testing.T) {
	for _, role := range []organization.OrganizationRole{organization.OrganizationRoleAdmin, organization.OrganizationRoleMember} {
		for _, pa := range []bool{false, true} {
			ctx, _, f := ikAuthorityContext(t, role, pa)
			ctx = log.SetRequestID(ctx)
			first, second := scheduleTargetUpdateAuditEvent(ctx), scheduleTargetUpdateAuditEvent(ctx)
			require.Equal(t, "human", first.ActorKind)
			require.Equal(t, f.user, first.ActorID)
			require.Equal(t, f.home, first.HomeOrganizationID)
			require.Equal(t, first.RequestID, second.RequestID)
			require.NotEqual(t, first.AttemptID, second.AttemptID)
			require.NotEqual(t, first.ExecutionID, second.ExecutionID)
			require.NotEqual(t, first.EventID, second.EventID)
			require.Equal(t, uuid.Nil, first.RootID)
			require.Equal(t, uuid.Nil, first.TargetOrganizationID)
			_, err := scheduleRotationManagementAuthority(ctx, scheduleRotationManagementUpdate)
			if role == organization.OrganizationRoleMember && !pa {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			require.Equal(t, "unknown", scheduleTargetUpdateAuditEvent(permission.SystemContext(ctx, "forged")).ActorKind)
		}
	}
}

func TestScheduleTargetUpdateClosedDiagnosticsAndErrors(t *testing.T) {
	for _, query := range []string{
		`mutation { PRIVATE_ALIAS:updateScheduleTarget other:sendSignal }`,
		`mutation { other:sendSignal ...SR } fragment SR on Mutation { PRIVATE_ALIAS:updateScheduleTarget }`,
	} {
		ctx := asOperationContext(t, query, "", "sendSignal")
		logger := log.NewLogger()
		logger.EnableJSON()
		var out bytes.Buffer
		logger.SetOutput(&out)
		ctx = log.WithLogger(log.WithField(ctx, "Cookie", "SYNTHETIC_COOKIE"), logger)
		original := &gqlerror.Error{Message: "SYNTHETIC_MESSAGE", Path: ast.Path{ast.PathName("PRIVATE_ALIAS")}, Err: &pgconn.PgError{Code: "P0001", Detail: "SYNTHETIC_SQL_DETAIL"}}
		before, err := json.Marshal(original)
		require.NoError(t, err)
		log.Log(scheduleTargetUpdateDiagnosticContext(ctx), scheduleTargetUpdateDiagnosticError(ctx, original))
		require.NotContains(t, out.String(), "SYNTHETIC")
		require.NotContains(t, out.String(), "PRIVATE_ALIAS")
		after, err := json.Marshal(original)
		require.NoError(t, err)
		require.Equal(t, string(before), string(after))
	}
	ctx := asOperationContext(t, `mutation { updateScheduleTarget:sendSignal }`, "", "sendSignal")
	require.False(t, scheduleTargetUpdateDiagnosticsSelected(ctx))
	for _, constraint := range []string{"schedule_rules_tgt_user_id_fkey", "schedule_rules_tgt_rotation_id_fkey"} {
		err := scheduleTargetUpdateSafeError(&pgconn.PgError{Code: "23503", ConstraintName: constraint, Detail: "SYNTHETIC_DETAIL"})
		require.True(t, validation.IsClientError(err))
		require.NotContains(t, err.Error(), "SYNTHETIC")
	}
	for _, err := range []error{&pgconn.PgError{Code: "23514", Hint: "SYNTHETIC_HINT"}, errors.New("SYNTHETIC_SECRET")} {
		require.NotContains(t, scheduleTargetUpdateSafeError(err).Error(), "SYNTHETIC")
	}
}
