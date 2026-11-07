package graphqlapp

import (
	"context"
	"database/sql"
	"slices"

	"github.com/google/uuid"
	"github.com/target/goalert/assignment"
	"github.com/target/goalert/executioncontext"
	"github.com/target/goalert/organization"
	"github.com/target/goalert/permission"
	"github.com/target/goalert/validation/validate"
)

// existingRootManagementAuthority retains Home admission separately from the
// target. Only the bounded existing-root callers below may resolve a global
// target; Create, temporary schedules and notification rules keep Home scope.
func existingRootManagementAuthority(ctx context.Context, typ assignment.TargetType) (*uuid.UUID, error) {
	switch typ {
	case assignment.TargetTypeEscalationPolicy:
		return epManagementAuthority(ctx, epManagementUpdate)
	case assignment.TargetTypeSchedule, assignment.TargetTypeRotation:
		return scheduleRotationManagementAuthority(ctx, scheduleRotationManagementUpdate)
	default:
		return nil, permission.NewAccessDenied("existing root management authority is required")
	}
}

func existingRootTargetOrganization(ctx context.Context, tx *sql.Tx, typ assignment.TargetType, id string) (*uuid.UUID, error) {
	return existingRootTargetOrganizationTx(ctx, tx, typ, id, true)
}

func existingRootTargetOrganizationTx(ctx context.Context, tx *sql.Tx, typ assignment.TargetType, id string, exclusive bool) (*uuid.UUID, error) {
	home, err := existingRootManagementAuthority(ctx, typ)
	if err != nil || home == nil {
		return home, err // Only the existing, explicitly trusted System path is nil.
	}
	if !executioncontext.ExecutionContextFromContext(ctx).Privileges().PlatformAdmin() {
		return home, nil
	}
	if tx == nil {
		return nil, permission.NewAccessDenied("existing root management requires a transaction")
	}
	var field, table string
	switch typ {
	case assignment.TargetTypeEscalationPolicy:
		field, table = "EscalationPolicyID", "escalation_policies"
	case assignment.TargetTypeSchedule:
		field, table = "ScheduleID", "schedules"
	case assignment.TargetTypeRotation:
		field, table = "RotationID", "rotations"
	}
	if err := validate.UUID(field, id); err != nil {
		return nil, err
	}
	if typ == assignment.TargetTypeRotation {
		// Match RotationStore and DeleteAll: participant/state tables before Root.
		if _, err := tx.ExecContext(ctx, `LOCK rotation_participants, rotation_state IN EXCLUSIVE MODE`); err != nil {
			return nil, err
		}
	}
	lock := " FOR SHARE"
	if exclusive {
		lock = " FOR UPDATE"
	}
	var target uuid.UUID
	// Lock the actual row before following its Organization in a new statement.
	// A joined locking read can retain an obsolete parent after a lock wait.
	if err := tx.QueryRowContext(ctx, `SELECT organization_id FROM `+table+` WHERE id=$1`+lock, id).Scan(&target); err != nil {
		return nil, err
	}
	var normal uuid.UUID
	err = tx.QueryRowContext(ctx, `SELECT o.id FROM organizations o
		JOIN normal_organizations n ON n.organization_id=o.id
			AND n.organization_classification=o.classification
		WHERE o.id=$1 AND o.classification='NORMAL' AND o.id<>$2 AND o.id<>$3
		FOR SHARE OF o, n`, target, organization.DefaultOrganizationID, uuid.Nil).Scan(&normal)
	if err != nil {
		return nil, err
	}
	return &target, nil
}

func existingStepTargetOrganization(ctx context.Context, tx *sql.Tx, id string) (*uuid.UUID, error) {
	home, err := epManagementAuthority(ctx, epManagementUpdate)
	if err != nil || home == nil {
		return home, err
	}
	if !executioncontext.ExecutionContextFromContext(ctx).Privileges().PlatformAdmin() {
		return home, nil
	}
	if err := validate.UUID("EscalationPolicyStepID", id); err != nil {
		return nil, err
	}
	var parent string
	if err := tx.QueryRowContext(ctx, `SELECT escalation_policy_id FROM escalation_policy_steps WHERE id=$1 FOR UPDATE`, id).Scan(&parent); err != nil {
		return nil, err
	}
	return existingRootTargetOrganizationTx(ctx, tx, assignment.TargetTypeEscalationPolicy, parent, false)
}

// Each call resolves exactly one Root group. It never borrows another group's
// scope or grants a same-type batch spanning multiple Normal Organizations.
func existingRootDeleteTargetOrganization(ctx context.Context, tx *sql.Tx, typ assignment.TargetType, ids []string) (*uuid.UUID, error) {
	home, err := existingRootManagementAuthority(ctx, typ)
	if err != nil || home == nil {
		return home, err
	}
	if !executioncontext.ExecutionContextFromContext(ctx).Privileges().PlatformAdmin() {
		return home, nil
	}
	field := map[assignment.TargetType]string{
		assignment.TargetTypeEscalationPolicy: "EscalationPolicyID",
		assignment.TargetTypeSchedule:         "ScheduleID",
		assignment.TargetTypeRotation:         "RotationID",
	}[typ]
	parsed, err := validate.ParseManyUUID(field, ids, 50)
	if err != nil {
		return nil, err
	}
	ids = make([]string, len(parsed))
	for i, id := range parsed {
		ids[i] = id.String()
	}
	slices.Sort(ids)
	ids = slices.Compact(ids)
	var target *uuid.UUID
	for _, id := range ids {
		org, err := existingRootTargetOrganization(ctx, tx, typ, id)
		if err != nil {
			return nil, err
		}
		if target != nil && *target != *org {
			return nil, sql.ErrNoRows
		}
		target = org
	}
	if target == nil {
		return home, nil
	}
	return target, nil
}
