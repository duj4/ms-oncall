package graphqlapp

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/99designs/gqlgen/graphql"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/lib/pq"
	epaudit "github.com/target/goalert/escalation/deleteaudit"
	"github.com/target/goalert/gadb"
	"github.com/target/goalert/graphql2"
	"github.com/target/goalert/permission"
	"github.com/target/goalert/util/errutil"
	"github.com/target/goalert/util/log"
	"github.com/target/goalert/validation"
)

func epUpdateAuditEvent(ctx context.Context, operation string) epaudit.Event {
	// Reuse the accepted admission projection, without any requested business data.
	p := scheduleUpdateAuditEvent(ctx, graphql2.UpdateScheduleInput{})
	return epaudit.Event{SchemaVersion: 2, EffectsVersion: 2, Operation: operation,
		EventID: p.EventID, RequestID: p.RequestID, ExecutionID: uuid.New(), AttemptID: p.AttemptID,
		ActorKind: p.ActorKind, ActorID: p.ActorID, HomeOrganizationID: p.HomeOrganizationID,
		AuthoritySource: p.AuthoritySource, AuthorityRole: p.AuthorityRole, OrganizationRole: p.OrganizationRole,
		OccurredAt: p.OccurredAt, TargetOrgResolution: "unknown", RecordKind: "attempt_observation",
		Outcome: "denied", Reason: "authority_denied"}
}

// Diagnostic selection uses schema names and the parsed enclosing operation,
// including fragments and mixed mutations. Neither aliases nor client values
// are diagnostics. The real authorization and protocol contexts are untouched.
func epUpdateDiagnosticsSelected(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	selected := func(name string) bool { return name == epaudit.PolicyUpdate || name == epaudit.StepUpdate }
	if f := graphql.GetFieldContext(ctx); f != nil && f.Object == "Mutation" && selected(f.Field.Name) {
		return true
	}
	if graphql.HasOperationContext(ctx) {
		op := graphql.GetOperationContext(ctx)
		if op.Operation != nil {
			for _, f := range graphql.CollectFields(op, op.Operation.SelectionSet, []string{"Mutation"}) {
				if selected(f.Name) {
					return true
				}
			}
		}
	}
	return false
}

func epUpdateDiagnosticContext(ctx context.Context) context.Context {
	if !epUpdateDiagnosticsSelected(ctx) {
		return ctx
	}
	clean := log.FromContext(ctx).BackgroundContext()
	clean = log.WithField(clean, "DiagnosticPolicy", "graphql_closed_projection")
	if id, err := uuid.Parse(log.RequestID(ctx)); err == nil && id != uuid.Nil {
		clean = log.WithField(clean, "RequestID", id.String())
	}
	return clean
}

func epUpdateDiagnosticError(ctx context.Context, err error) error {
	if err != nil && epUpdateDiagnosticsSelected(ctx) {
		return errors.New("GraphQL operation failed")
	}
	return err
}

func epUpdateSafeError(err error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return sql.ErrNoRows
	}
	var pg *pgconn.PgError
	if errors.As(err, &pg) {
		switch pg.ConstraintName {
		case "escalation_policies_name", "escalation_policies_name_key", "epa_no_duplicate_users", "epa_no_duplicate_schedules", "epa_no_duplicate_rotations", "epa_no_duplicate_channels", "ep_actions_per_step_limit", "ep_steps_per_policy_limit":
			mapped := errutil.MapDBError(err)
			if validation.IsClientError(mapped) || errutil.IsLimitError(mapped) {
				return mapped
			}
		}
		return errors.New("escalation policy update transaction failed")
	}
	if permission.IsPermissionError(err) || validation.IsClientError(err) || errutil.IsLimitError(err) {
		return err
	}
	return errors.New("escalation policy update transaction failed")
}

func epUpdateAuditFault(ctx context.Context, e epaudit.Event, fault, outcome string) {
	clean := context.Background()
	if ctx != nil {
		clean = log.FromContext(ctx).BackgroundContext()
	}
	clean = log.WithFields(clean, log.Fields{"AuditOperation": e.Operation, "AuditFault": fault, "AuditOutcome": outcome,
		"AuditEventID": e.EventID.String(), "AuditRequestID": e.RequestID.String(), "AuditExecutionID": e.ExecutionID.String(), "AuditAttemptID": e.AttemptID.String()})
	log.Logf(clean, "Escalation policy update audit finalization.")
}

func finishEPUpdateAudit(ctx context.Context, db *sql.DB, conn *sql.Conn, tx *sql.Tx, attempted, finalized bool, e epaudit.Event, operationErr error) error {
	rb, released := releaseServiceUpdate(conn, tx, finalized)
	if operationErr == nil {
		if !released {
			epUpdateAuditFault(ctx, e, "resource_release_unconfirmed", "committed")
		}
		return nil
	}
	if attempted {
		e.Outcome, e.Reason = serviceUpdateCommitOutcome(operationErr)
	} else if tx != nil && rb != nil {
		e.Outcome, e.Reason = "rollback_unconfirmed", "rollback_unconfirmed"
	} else if e.Outcome == "validation_failed" {
		safe := epUpdateSafeError(operationErr)
		if !validation.IsClientError(safe) && !errutil.IsLimitError(safe) && !errors.Is(safe, sql.ErrNoRows) {
			e.Outcome, e.Reason = "tx_failed", "write_failed"
		}
	}
	e.EventID, e.OccurredAt = uuid.New(), time.Now()
	e.RecordKind, e.Effects = "attempt_observation", nil
	e.Provenance, e.DeletionMechanism, e.Cause = "", "", ""
	safe := epUpdateSafeError(operationErr)
	if !released {
		epUpdateAuditFault(ctx, e, "resource_release_unconfirmed", e.Outcome)
		return fmt.Errorf("%w; escalation policy update audit persistence unavailable", safe)
	}
	// Existing bounded failure writer, after the business connection's release
	// barrier. A timeout never starts another writer or replays the Update.
	persisted, failureReleased := recordDeleteAllFailureBatch(db, nil, nil, nil, []epaudit.Event{e})
	if !persisted || !failureReleased {
		epUpdateAuditFault(ctx, e, "persistence_unavailable", e.Outcome)
		return fmt.Errorf("%w; escalation policy update audit persistence unavailable", safe)
	}
	return safe
}

// This owner is bounded to U01/U02. The Store, capture and appender never Commit.
// An inherited transaction stages its witness on the outer owner's Tx; failures
// cannot open a second writer before that owner's release barrier.
func withEPUpdateAuditTx(ctx context.Context, db *sql.DB, event *epaudit.Event, update func(context.Context, *sql.Tx) error) (err error) {
	run := func(ctx context.Context, tx *sql.Tx) error {
		event.Outcome, event.Reason = "validation_failed", "invalid_fields"
		if err := update(ctx, tx); err != nil {
			return err
		}
		if len(event.Effects) == 0 {
			return nil
		}
		event.RecordKind, event.Outcome, event.Reason = "success_witness", "committed", "children_deleted"
		event.Provenance, event.DeletionMechanism, event.Cause = "EXPLICIT", "explicit_sql", "update_induced"
		if err := epaudit.Append(ctx, tx, *event); err != nil {
			event.Outcome, event.Reason = "tx_failed", "audit_write_failed"
			return err
		}
		return nil
	}
	if hasInheritedContextTx(ctx) {
		err = withContextTx(ctx, db, run)
		if err != nil {
			return epUpdateSafeError(err)
		}
		return nil
	}
	var conn *sql.Conn
	var tx *sql.Tx
	var attempted, finalized, completed bool
	defer func() {
		if !completed && err == nil {
			err = errors.New("escalation policy update interrupted")
		}
		err = finishEPUpdateAudit(ctx, db, conn, tx, attempted, finalized, *event, err)
	}()
	event.Outcome, event.Reason = "tx_failed", "begin_failed"
	conn, err = db.Conn(ctx)
	if err != nil {
		return err
	}
	tx, err = conn.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if err = run(context.WithValue(ctx, txKey, tx), tx); err != nil {
		return err
	}
	attempted = true
	err, finalized = commitServiceUpdate(ctx, tx)
	completed = true
	return err
}

// captureEPUpdateActions follows SD5's Root -> sorted Step -> sorted Action
// hierarchy. Parent FOR UPDATE blocks incoming FK membership; Action locks
// block removals/retargeting. Fresh statements after waits recheck membership.
// Existing trigger locks, including Step's table lock, remain unchanged.
func captureEPUpdateActions(ctx context.Context, tx *sql.Tx, e epaudit.Event, steps []uuid.UUID) ([]epaudit.Effect, error) {
	if len(steps) == 0 {
		return nil, nil
	}
	if len(steps) > epaudit.MaxEffects {
		return nil, epaudit.ErrCapacity
	}
	rows, err := tx.QueryContext(ctx, `SELECT id FROM escalation_policy_steps WHERE id=ANY($1::uuid[]) AND escalation_policy_id=$2 ORDER BY id FOR UPDATE`, pq.Array(steps), e.RootID)
	if err != nil {
		return nil, err
	}
	n := 0
	for rows.Next() {
		var id uuid.UUID
		if err = rows.Scan(&id); err != nil {
			break
		}
		n++
	}
	if err == nil {
		err = rows.Err()
	}
	_ = rows.Close()
	if err != nil {
		return nil, err
	}
	if n != len(steps) {
		return nil, epaudit.ErrInvalid
	}
	if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM escalation_policy_steps WHERE id=ANY($1::uuid[]) AND escalation_policy_id=$2`, pq.Array(steps), e.RootID).Scan(&n); err != nil {
		return nil, err
	}
	if n != len(steps) {
		return nil, epaudit.ErrInvalid
	}
	rows, err = tx.QueryContext(ctx, `SELECT id FROM escalation_policy_actions WHERE escalation_policy_step_id=ANY($1::uuid[]) ORDER BY id LIMIT $2 FOR UPDATE`, pq.Array(steps), epaudit.MaxEffects-len(steps)+1)
	if err != nil {
		return nil, err
	}
	ids := []uuid.UUID{}
	for rows.Next() {
		var id uuid.UUID
		if err = rows.Scan(&id); err != nil {
			break
		}
		ids = append(ids, id)
		if len(ids)+len(steps) > epaudit.MaxEffects {
			err = epaudit.ErrCapacity
			break
		}
	}
	if err == nil {
		err = rows.Err()
	}
	_ = rows.Close()
	if err != nil {
		return nil, err
	}
	rows, err = tx.QueryContext(ctx, `SELECT id,escalation_policy_step_id,user_id,schedule_id,rotation_id,channel_id FROM escalation_policy_actions WHERE id=ANY($1::uuid[]) AND escalation_policy_step_id=ANY($2::uuid[]) ORDER BY id`, pq.Array(ids), pq.Array(steps))
	if err != nil {
		return nil, err
	}
	effects := []epaudit.Effect{}
	for rows.Next() {
		var r gadb.EPStepActionsDeleteReceiptRow
		if err = rows.Scan(&r.ID, &r.EscalationPolicyStepID, &r.UserID, &r.ScheduleID, &r.RotationID, &r.ChannelID); err != nil {
			break
		}
		f, ferr := epUpdateActionEffect(e, r, true)
		if ferr != nil {
			err = ferr
			break
		}
		effects = append(effects, f)
	}
	if err == nil {
		err = rows.Err()
	}
	_ = rows.Close()
	if err != nil {
		return nil, err
	}
	if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM escalation_policy_actions WHERE escalation_policy_step_id=ANY($1::uuid[])`, pq.Array(steps)).Scan(&n); err != nil {
		return nil, err
	}
	if len(effects) != len(ids) || n != len(ids) {
		return nil, epaudit.ErrInvalid
	}
	return effects, nil
}

func epUpdateActionEffect(e epaudit.Event, r gadb.EPStepActionsDeleteReceiptRow, cascade bool) (epaudit.Effect, error) {
	if r.ID == uuid.Nil || r.EscalationPolicyStepID == uuid.Nil {
		return epaudit.Effect{}, epaudit.ErrInvalid
	}
	f := epaudit.Effect{EffectID: uuid.New(), ResourceType: epaudit.Action, RootID: e.RootID, TargetOrganizationID: e.TargetOrganizationID,
		ResourceUUID: &r.ID, ParentStepID: &r.EscalationPolicyStepID, Relation: "escalation_policy.step.action", Change: "deleted",
		Provenance: "EXPLICIT", DeletionMechanism: "explicit_sql", Cause: "update_induced"}
	n := 0
	for _, target := range []struct {
		kind string
		id   uuid.NullUUID
	}{{"user", r.UserID}, {"schedule", r.ScheduleID}, {"rotation", r.RotationID}, {"notification_channel", r.ChannelID}} {
		if !target.id.Valid {
			continue
		}
		id := target.id.UUID
		if id == uuid.Nil {
			return f, epaudit.ErrInvalid
		}
		f.TargetKind, f.TargetID = target.kind, &id
		n++
	}
	if n != 1 {
		return f, epaudit.ErrInvalid
	}
	if cascade {
		f.Provenance, f.DeletionMechanism, f.Cause = "CASCADE", "fk_cascade", "step_delete"
	}
	return f, nil
}

func verifyEPUpdateDeleted(ctx context.Context, tx *sql.Tx, e epaudit.Event) error {
	steps, actions := []uuid.UUID{}, []uuid.UUID{}
	for _, f := range e.Effects {
		if f.ResourceUUID == nil {
			return epaudit.ErrInvalid
		}
		if f.ResourceType == epaudit.Step {
			steps = append(steps, *f.ResourceUUID)
		} else {
			actions = append(actions, *f.ResourceUUID)
		}
	}
	var remains bool
	err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT FROM escalation_policy_steps WHERE id=ANY($1::uuid[])) OR EXISTS(SELECT FROM escalation_policy_actions WHERE id=ANY($2::uuid[]) OR escalation_policy_step_id=ANY($1::uuid[]))`, pq.Array(steps), pq.Array(actions)).Scan(&remains)
	if err != nil {
		return err
	}
	if remains {
		return epaudit.ErrInvalid
	}
	return nil
}
