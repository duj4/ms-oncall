package graphqlapp

import (
	"context"
	"database/sql"
	"slices"

	"github.com/google/uuid"
	"github.com/target/goalert/assignment"
	"github.com/target/goalert/util/sqlutil"
	"github.com/target/goalert/validation/validate"
)

// validateScheduleRotationDeleteTx protects dependent configuration affected by
// root deletion. Each group has its own explicitly resolved target scope;
// trusted nil-scope callers retain their existing behavior. All locks belong
// to DeleteAll's business transaction.
func validateScheduleRotationDeleteTx(ctx context.Context, tx *sql.Tx, targets map[assignment.TargetType][]string, rotationOrg, scheduleOrg *uuid.UUID) error {
	if rotationOrg == nil && scheduleOrg == nil {
		return nil
	}
	var rotationIDs, scheduleIDs []string
	for _, root := range []struct {
		typ            assignment.TargetType
		field, table   string
		ids            *[]string
		organizationID *uuid.UUID
	}{
		{assignment.TargetTypeRotation, "RotationID", "rotations", &rotationIDs, rotationOrg},
		{assignment.TargetTypeSchedule, "ScheduleID", "schedules", &scheduleIDs, scheduleOrg},
	} {
		ids := targets[root.typ]
		if len(ids) == 0 || root.organizationID == nil {
			continue
		}
		parsed, err := validate.ParseManyUUID(root.field, ids, 50)
		if err != nil {
			return err
		}
		ids = make([]string, len(parsed))
		for i, id := range parsed {
			ids[i] = id.String()
		}
		slices.Sort(ids)
		ids = slices.Compact(ids)
		if root.typ == assignment.TargetTypeRotation {
			// Match RotationStore's existing table-before-root lock order. This
			// is also the existing DeleteAll Rotation-before-Schedule ordering.
			if _, err := tx.ExecContext(ctx, `LOCK rotation_participants, rotation_state IN EXCLUSIVE MODE`); err != nil {
				return err
			}
		}
		// FOR UPDATE conflicts with the FK's KEY SHARE, preventing a new or
		// retargeted dependent Action from entering after this root is checked.
		locked, err := lockDeleteCascadeIDs(ctx, tx, `SELECT id FROM `+root.table+`
			WHERE id=ANY($1::uuid[]) AND organization_id=$2 ORDER BY id FOR UPDATE`, sqlutil.UUIDArray(ids), *root.organizationID)
		if err != nil {
			return err
		}
		if len(locked) != len(ids) {
			return sql.ErrNoRows
		}
		*root.ids = locked
	}
	if len(rotationIDs)+len(scheduleIDs) == 0 {
		return nil
	}

	// Lock each relation separately, then follow its current parent in the next
	// statement. A single locking join can miss a concurrently reparented row
	// when PostgreSQL rechecks a stale joined tuple after waiting for its lock.
	if len(rotationIDs) > 0 {
		if err := validateRotationRuleDeleteTx(ctx, tx, rotationIDs, *rotationOrg); err != nil {
			return err
		}
	}

	actions, err := lockDeleteCascadeIDs(ctx, tx, `SELECT id FROM escalation_policy_actions
		WHERE rotation_id=ANY($1::uuid[]) OR schedule_id=ANY($2::uuid[])
		ORDER BY id FOR UPDATE`, sqlutil.UUIDArray(rotationIDs), sqlutil.UUIDArray(scheduleIDs))
	if err != nil || len(actions) == 0 {
		return err
	}
	steps, err := lockDeleteCascadeIDs(ctx, tx, `SELECT id FROM escalation_policy_steps
		WHERE id IN (SELECT escalation_policy_step_id FROM escalation_policy_actions WHERE id=ANY($1::uuid[]))
		ORDER BY id FOR SHARE`, sqlutil.UUIDArray(actions))
	if err != nil {
		return err
	}
	policies, err := lockDeleteCascadeIDs(ctx, tx, `SELECT id FROM escalation_policies
		WHERE id IN (SELECT escalation_policy_id FROM escalation_policy_steps WHERE id=ANY($1::uuid[]))
		ORDER BY id FOR SHARE`, sqlutil.UUIDArray(steps))
	if err != nil {
		return err
	}
	var foreign bool
	// Compare each dependent Action to its own referenced Root's scope. Having
	// authority over both groups cannot legitimize a cross-Org relationship.
	err = tx.QueryRowContext(ctx, `SELECT EXISTS (
		SELECT 1 FROM escalation_policy_actions a
		JOIN escalation_policy_steps s ON s.id=a.escalation_policy_step_id
		JOIN escalation_policies p ON p.id=s.escalation_policy_id
		WHERE p.id=ANY($1::uuid[]) AND a.id=ANY($2::uuid[]) AND (
			(a.rotation_id=ANY($3::uuid[]) AND p.organization_id<>$4) OR
			(a.schedule_id=ANY($5::uuid[]) AND p.organization_id<>$6))
	)`, sqlutil.UUIDArray(policies), sqlutil.UUIDArray(actions),
		sqlutil.UUIDArray(rotationIDs), rotationOrg, sqlutil.UUIDArray(scheduleIDs), scheduleOrg).Scan(&foreign)
	if err != nil {
		return err
	}
	if foreign {
		// Match unavailable-root behavior without exposing foreign identities.
		return sql.ErrNoRows
	}
	return nil
}

func validateRotationRuleDeleteTx(ctx context.Context, tx *sql.Tx, rotationIDs []string, organizationID uuid.UUID) error {
	if len(rotationIDs) == 0 {
		return nil
	}
	// The already-held Rotation FOR UPDATE locks fence new references via the
	// FK's KEY SHARE lock. Lock existing Rules before reading their parents:
	// READ COMMITTED must observe any reparenting committed while we waited.
	rules, err := lockDeleteCascadeIDs(ctx, tx, `SELECT id FROM schedule_rules
		WHERE tgt_rotation_id=ANY($1::uuid[]) ORDER BY id FOR UPDATE`, sqlutil.UUIDArray(rotationIDs))
	if err != nil || len(rules) == 0 {
		return err
	}
	// FOR SHARE also fences a non-key Organization update to the real Schedule.
	// Rule locks keep schedule_id stable while we follow and check that parent.
	schedules, err := lockDeleteCascadeIDs(ctx, tx, `SELECT id FROM schedules
		WHERE id IN (SELECT schedule_id FROM schedule_rules WHERE id=ANY($1::uuid[]))
		ORDER BY id FOR SHARE`, sqlutil.UUIDArray(rules))
	if err != nil {
		return err
	}
	var foreign bool
	err = tx.QueryRowContext(ctx, `SELECT EXISTS (
		SELECT 1 FROM schedules WHERE id=ANY($1::uuid[]) AND organization_id<>$2
	)`, sqlutil.UUIDArray(schedules), organizationID).Scan(&foreign)
	if err != nil {
		return err
	}
	if foreign {
		return sql.ErrNoRows
	}
	return nil
}

func lockDeleteCascadeIDs(ctx context.Context, tx *sql.Tx, query string, args ...any) ([]string, error) {
	rows, err := tx.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}
