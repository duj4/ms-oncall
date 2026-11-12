package rotation

import (
	"context"
	"database/sql"

	"github.com/google/uuid"
	"github.com/target/goalert/permission"
	sraudit "github.com/target/goalert/schedule/deleteaudit"
	"github.com/target/goalert/util/sqlutil"
	"github.com/target/goalert/validation"
	"github.com/target/goalert/validation/validate"
)

// DeleteReceipt is evidence from the actual root DELETE, not requested IDs.
type DeleteReceipt = sraudit.Receipt

// DeleteManyForAuditTx preserves DeleteManyTx's scoped SQL,
// complete-set, raw input limit and System no-op semantics. The caller owns Tx.
func (s *Store) DeleteManyForAuditTx(ctx context.Context, tx *sql.Tx, ids []string, organizationID *uuid.UUID) ([]DeleteReceipt, error) {
	if err := permission.LimitCheckAny(ctx, permission.Admin, permission.User); err != nil {
		return nil, err
	}
	parsed, err := validate.ParseManyUUID("RotationID", ids, 50)
	if err != nil {
		return nil, err
	}
	if tx == nil {
		return nil, validation.NewFieldError("Transaction", "must be specified")
	}
	if len(ids) == 0 {
		return nil, nil
	}
	want := map[uuid.UUID]bool{}
	for _, id := range parsed {
		want[id] = true
	}
	if _, err := tx.ExecContext(ctx, `LOCK rotation_participants, rotation_state IN EXCLUSIVE MODE`); err != nil {
		return nil, err
	}
	q := `DELETE FROM rotations pol WHERE pol.id=any($1)`
	args := []any{sqlutil.UUIDArray(ids)}
	if organizationID != nil {
		if *organizationID == uuid.Nil {
			return nil, validation.NewFieldError("OrganizationID", "must be specified")
		}
		q += ` AND pol.organization_id=$2 AND
		 (SELECT count(*) FROM (SELECT DISTINCT requested_id FROM unnest($1::uuid[]) AS requested(requested_id)) requested)
		 = (SELECT count(*) FROM rotations matched WHERE matched.id=any($1) AND matched.organization_id=$2)`
		args = append(args, *organizationID)
	}
	rows, err := tx.QueryContext(ctx, q+` RETURNING pol.id,pol.organization_id`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []DeleteReceipt
	for rows.Next() {
		var r DeleteReceipt
		if err := rows.Scan(&r.ID, &r.OrganizationID); err != nil {
			return nil, err
		}
		result = append(result, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if organizationID != nil && len(result) != len(want) {
		return result, sql.ErrNoRows
	}
	return result, nil
}
