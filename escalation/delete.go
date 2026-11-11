package escalation

import (
	"context"
	"database/sql"

	"github.com/google/uuid"
	"github.com/target/goalert/permission"
	"github.com/target/goalert/util/sqlutil"
	"github.com/target/goalert/validation"
	"github.com/target/goalert/validation/validate"
)

// DeleteReceipt is evidence from the actual root DELETE, not requested IDs.
type DeleteReceipt struct{ ID, OrganizationID uuid.UUID }

// DeleteManyPoliciesForAuditTx preserves DeleteManyPoliciesTx's scoped SQL,
// complete-set, raw input limit and System no-op semantics. The caller owns Tx.
func (s *Store) DeleteManyPoliciesForAuditTx(ctx context.Context, tx *sql.Tx, ids []string, organizationID *uuid.UUID) ([]DeleteReceipt, error) {
	if err := permission.LimitCheckAny(ctx, permission.Admin, permission.User); err != nil {
		return nil, err
	}
	parsed, err := validate.ParseManyUUID("EscalationPolicyID", ids, 50)
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
	q := `DELETE FROM escalation_policies pol WHERE pol.id=any($1)`
	args := []any{sqlutil.UUIDArray(ids)}
	if organizationID != nil {
		if *organizationID == uuid.Nil {
			return nil, validation.NewFieldError("OrganizationID", "must be specified")
		}
		q += ` AND pol.organization_id=$2 AND
		 (SELECT count(*) FROM (SELECT DISTINCT requested_id FROM unnest($1::uuid[]) AS requested(requested_id)) requested)
		 = (SELECT count(*) FROM escalation_policies matched WHERE matched.id=any($1) AND matched.organization_id=$2)`
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
