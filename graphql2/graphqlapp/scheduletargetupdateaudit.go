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
	"github.com/target/goalert/graphql2"
	"github.com/target/goalert/permission"
	sraudit "github.com/target/goalert/schedule/deleteaudit"
	"github.com/target/goalert/schedule/rule"
	"github.com/target/goalert/util/errutil"
	"github.com/target/goalert/util/log"
	"github.com/target/goalert/validation"
)

func scheduleTargetUpdateAuditEvent(ctx context.Context) sraudit.Event {
	// Reuse the accepted admission projection, without any requested business data.
	p := scheduleUpdateAuditEvent(ctx, graphql2.UpdateScheduleInput{})
	return sraudit.Event{SchemaVersion: 2, EffectsVersion: 2, Operation: sraudit.ScheduleTargetUpdate, RootType: sraudit.Schedule,
		EventID: p.EventID, RequestID: p.RequestID, ExecutionID: uuid.New(), AttemptID: p.AttemptID,
		ActorKind: p.ActorKind, ActorID: p.ActorID, HomeOrganizationID: p.HomeOrganizationID,
		AuthoritySource: p.AuthoritySource, AuthorityRole: p.AuthorityRole, OrganizationRole: p.OrganizationRole,
		OccurredAt: p.OccurredAt, TargetOrgResolution: "unknown", RecordKind: "attempt_observation",
		Outcome: "denied", Reason: "authority_denied"}
}

// Diagnostic selection uses schema names and the parsed enclosing operation,
// including fragments and mixed mutations. Neither aliases nor client values
// are diagnostics. The real authorization and protocol contexts are untouched.
func scheduleTargetUpdateDiagnosticsSelected(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	selected := func(name string) bool { return name == sraudit.ScheduleTargetUpdate }
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

func scheduleTargetUpdateDiagnosticContext(ctx context.Context) context.Context {
	if !scheduleTargetUpdateDiagnosticsSelected(ctx) {
		return ctx
	}
	clean := log.FromContext(ctx).BackgroundContext()
	clean = log.WithField(clean, "DiagnosticPolicy", "graphql_closed_projection")
	if id, err := uuid.Parse(log.RequestID(ctx)); err == nil && id != uuid.Nil {
		clean = log.WithField(clean, "RequestID", id.String())
	}
	return clean
}

func scheduleTargetUpdateDiagnosticError(ctx context.Context, err error) error {
	if err != nil && scheduleTargetUpdateDiagnosticsSelected(ctx) {
		return errors.New("GraphQL operation failed")
	}
	return err
}

func scheduleTargetUpdateSafeError(err error) error {
	if typed, ok := deletionSafetyError(err); ok {
		return typed
	}
	if errors.Is(err, sql.ErrNoRows) {
		return sql.ErrNoRows
	}
	var pg *pgconn.PgError
	if errors.As(err, &pg) {
		switch pg.ConstraintName {
		case "schedule_rules_tgt_user_id_fkey", "schedule_rules_tgt_rotation_id_fkey", "rules_per_schedule_limit", "targets_per_schedule_limit":
			mapped := errutil.MapDBError(err)
			if validation.IsClientError(mapped) || errutil.IsLimitError(mapped) {
				return mapped
			}
		}
		return errors.New("schedule target update transaction failed")
	}
	if permission.IsPermissionError(err) || validation.IsClientError(err) || errutil.IsLimitError(err) {
		return err
	}
	return errors.New("schedule target update transaction failed")
}

func scheduleTargetUpdateAuditFault(ctx context.Context, e sraudit.Event, fault, outcome string) {
	clean := context.Background()
	if ctx != nil {
		clean = log.FromContext(ctx).BackgroundContext()
	}
	clean = log.WithFields(clean, log.Fields{"AuditOperation": e.Operation, "AuditFault": fault, "AuditOutcome": outcome,
		"AuditEventID": e.EventID.String(), "AuditRequestID": e.RequestID.String(), "AuditExecutionID": e.ExecutionID.String(), "AuditAttemptID": e.AttemptID.String()})
	log.Logf(clean, "Schedule target update audit finalization.")
}

func finishScheduleTargetUpdateAudit(ctx context.Context, db *sql.DB, conn *sql.Conn, tx *sql.Tx, attempted, finalized bool, e sraudit.Event, operationErr error) error {
	rb, released := releaseServiceUpdate(conn, tx, finalized)
	if operationErr == nil {
		if !released {
			scheduleTargetUpdateAuditFault(ctx, e, "resource_release_unconfirmed", "committed")
		}
		return nil
	}
	if attempted {
		e.Outcome, e.Reason = serviceUpdateCommitOutcome(operationErr)
	} else if tx != nil && rb != nil {
		e.Outcome, e.Reason = "rollback_unconfirmed", "rollback_unconfirmed"
	} else if e.Outcome == "validation_failed" {
		safe := scheduleTargetUpdateSafeError(operationErr)
		if _, safetyRefusal := deletionSafetyError(safe); !safetyRefusal && !validation.IsClientError(safe) && !errutil.IsLimitError(safe) && !errors.Is(safe, sql.ErrNoRows) {
			e.Outcome, e.Reason = "tx_failed", "write_failed"
		}
	}
	e.EventID, e.OccurredAt = uuid.New(), time.Now()
	e.RecordKind, e.Effects = "attempt_observation", nil
	e.Provenance, e.DeletionMechanism, e.Cause = "", "", ""
	safe := scheduleTargetUpdateSafeError(operationErr)
	if !released {
		scheduleTargetUpdateAuditFault(ctx, e, "resource_release_unconfirmed", e.Outcome)
		return fmt.Errorf("%w; schedule target update audit persistence unavailable", safe)
	}
	// Existing bounded failure writer, after the business connection's release
	// barrier. A timeout never starts another writer or replays the Update.
	persisted, failureReleased := recordDeleteAllFailureBatch(db, nil, nil, nil, nil, []sraudit.Event{e})
	if !persisted || !failureReleased {
		scheduleTargetUpdateAuditFault(ctx, e, "persistence_unavailable", e.Outcome)
		return fmt.Errorf("%w; schedule target update audit persistence unavailable", safe)
	}
	return safe
}

// This owner is bounded to authorized UpdateScheduleTarget calls. The Store, capture and appender never Commit.
// An inherited transaction stages its witness on the outer owner's Tx; failures
// cannot open a second writer before that owner's release barrier.
func withScheduleTargetUpdateAuditTx(ctx context.Context, db *sql.DB, event *sraudit.Event, update func(context.Context, *sql.Tx) error) (err error) {
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
		if err := sraudit.Append(ctx, tx, *event); err != nil {
			event.Outcome, event.Reason = "tx_failed", "audit_write_failed"
			return err
		}
		return nil
	}
	if hasInheritedContextTx(ctx) {
		err = withContextTx(ctx, db, run)
		if err != nil {
			return scheduleTargetUpdateSafeError(err)
		}
		return nil
	}
	var conn *sql.Conn
	var tx *sql.Tx
	var attempted, finalized, completed bool
	defer func() {
		if !completed && err == nil {
			err = errors.New("schedule target update interrupted")
		}
		err = finishScheduleTargetUpdateAudit(ctx, db, conn, tx, attempted, finalized, *event, err)
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

// Receipt fields come exclusively from DELETE RETURNING. Target is a surviving
// reference; neither it nor the Schedule is an affected deleted resource.
func scheduleTargetRuleEffect(e sraudit.Event, r rule.DeleteReceipt) (sraudit.Effect, error) {
	if r.ID == uuid.Nil || r.ScheduleID != e.RootID || r.TargetID == uuid.Nil || (r.TargetKind != "user" && r.TargetKind != "rotation") {
		return sraudit.Effect{}, sraudit.ErrInvalid
	}
	id := r.ID
	return sraudit.Effect{EffectID: uuid.New(), ResourceType: sraudit.Rule, RootID: e.RootID, TargetOrganizationID: e.TargetOrganizationID,
		Relation: "schedule.schedule_rule", Change: "deleted", Provenance: "EXPLICIT", DeletionMechanism: "explicit_sql", Cause: "update_induced", ResourceUUID: &id,
		RuleDeletion: &sraudit.RuleDeleteDetail{ScheduleID: r.ScheduleID, TargetKind: r.TargetKind, TargetID: r.TargetID}}, nil
}
