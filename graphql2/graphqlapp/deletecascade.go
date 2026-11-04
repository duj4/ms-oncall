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

// validateScheduleRotationDeleteTx protects EP configuration affected by root
// deletion. The existing management authority supplies a concrete Home scope
// for every Human, including PlatformAdmin; trusted nil-scope callers retain
// their existing behavior. All locks belong to DeleteAll's business transaction.
func validateScheduleRotationDeleteTx(ctx context.Context, tx *sql.Tx, targets map[assignment.TargetType][]string, organizationID *uuid.UUID) error {
	if organizationID == nil {
		return nil
	}
	var rotationIDs, scheduleIDs []string
	for _, root := range []struct {
		typ          assignment.TargetType
		field, table string
		ids          *[]string
	}{
		{assignment.TargetTypeRotation, "RotationID", "rotations", &rotationIDs},
		{assignment.TargetTypeSchedule, "ScheduleID", "schedules", &scheduleIDs},
	} {
		ids := targets[root.typ]
		if len(ids) == 0 {
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
			WHERE id=ANY($1::uuid[]) AND organization_id=$2 ORDER BY id FOR UPDATE`, sqlutil.UUIDArray(ids), *organizationID)
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
	err = tx.QueryRowContext(ctx, `SELECT EXISTS (
		SELECT 1 FROM escalation_policies WHERE id=ANY($1::uuid[]) AND organization_id<>$2
	)`, sqlutil.UUIDArray(policies), *organizationID).Scan(&foreign)
	if err != nil {
		return err
	}
	if foreign {
		// Match unavailable-root behavior without exposing foreign identities.
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
