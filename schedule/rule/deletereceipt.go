package rule

import (
	"context"
	"database/sql"
	"errors"

	"github.com/google/uuid"
	"github.com/target/goalert/assignment"
	"github.com/target/goalert/permission"
	"github.com/target/goalert/util/sqlutil"
	"github.com/target/goalert/validation/validate"
)

// DeleteReceipt contains only identities returned by a successful SQL DELETE.
// It does not contain Rule configuration or any referenced object's deletion.
type DeleteReceipt struct {
	ID, ScheduleID uuid.UUID
	TargetKind     string
	TargetID       uuid.UUID
}

// LockScheduleRulesTx follows the caller's Schedule FOR UPDATE lock. Lock all
// existing children in UUID order, including other targets: a target-only
// retarget does not acquire a new Schedule FK lock. The caller must read the
// selected collection again in a fresh statement after this wait. The root's
// FK fence blocks incoming INSERT/reparent; these locks fence UPDATE/DELETE.
// This method neither locks another ancestor nor owns the transaction.
func (s *Store) LockScheduleRulesTx(ctx context.Context, tx *sql.Tx, scheduleID string) error {
	if err := permission.LimitCheckAny(ctx, permission.All); err != nil {
		return err
	}
	if err := validate.UUID("ScheduleID", scheduleID); err != nil {
		return err
	}
	if tx == nil {
		return errors.New("schedule rule locking requires transaction")
	}
	rows, err := tx.QueryContext(ctx, `SELECT id FROM schedule_rules WHERE schedule_id=$1 ORDER BY id FOR UPDATE`, scheduleID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return err
		}
	}
	return rows.Err()
}

const deleteManyReceiptSQL = `DELETE FROM schedule_rules
 WHERE id=ANY($1::uuid[]) AND schedule_id=$2 AND (tgt_user_id=$3 OR tgt_rotation_id=$4)
 RETURNING id,schedule_id,tgt_user_id,tgt_rotation_id`

// DeleteManyReceiptTx preserves the legacy method for unrelated callers. Its
// additional predicates prevent stale selectors from deleting a different
// collection. Only actual RETURNING rows are evidence, never the requested IDs.
// The caller retains the Schedule/child locks and sole Commit ownership.
func (s *Store) DeleteManyReceiptTx(ctx context.Context, tx *sql.Tx, scheduleID string, target assignment.Target, ids []string) ([]DeleteReceipt, error) {
	if err := permission.LimitCheckAny(ctx, permission.All); err != nil {
		return nil, err
	}
	if tx == nil {
		return nil, errors.New("schedule rule receipt requires transaction")
	}
	if err := validate.Many(validate.UUID("ScheduleID", scheduleID),
		validate.OneOf("TargetType", target.TargetType(), assignment.TargetTypeUser, assignment.TargetTypeRotation),
		validate.UUID("TargetID", target.TargetID()), validate.ManyUUID("RuleIDs", ids, 50)); err != nil {
		return nil, err
	}
	if len(ids) == 0 {
		return nil, nil
	}
	var user, rotation sql.NullString
	wantKind := "rotation"
	if target.TargetType() == assignment.TargetTypeUser {
		wantKind = "user"
		user = sql.NullString{String: target.TargetID(), Valid: true}
	} else {
		rotation = sql.NullString{String: target.TargetID(), Valid: true}
	}
	rows, err := tx.QueryContext(ctx, deleteManyReceiptSQL, sqlutil.UUIDArray(ids), scheduleID, user, rotation)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []DeleteReceipt
	for rows.Next() {
		var r DeleteReceipt
		var u, rot uuid.NullUUID
		if err := rows.Scan(&r.ID, &r.ScheduleID, &u, &rot); err != nil {
			return nil, err
		}
		if r.ID == uuid.Nil || r.ScheduleID == uuid.Nil || u.Valid == rot.Valid {
			return nil, errors.New("invalid schedule rule deletion receipt")
		}
		if u.Valid {
			r.TargetKind, r.TargetID = "user", u.UUID
		} else {
			r.TargetKind, r.TargetID = "rotation", rot.UUID
		}
		if r.TargetID == uuid.Nil || r.ScheduleID != uuid.MustParse(scheduleID) || r.TargetKind != wantKind || r.TargetID != uuid.MustParse(target.TargetID()) {
			return nil, errors.New("mismatched schedule rule deletion receipt")
		}
		result = append(result, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return result, nil
}
