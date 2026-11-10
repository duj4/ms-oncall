package integrationkey

import (
	"context"
	"database/sql"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/target/goalert/permission"
	"github.com/target/goalert/validation"
	"github.com/target/goalert/validation/validate"
)

// DeleteReceipt deliberately excludes the credential UUID and key contents.
type DeleteReceipt struct{ ResourceID, ServiceID uuid.UUID }

// DeleteManyForAuditTx uses the existing delete predicates and a safe explicit
// RETURNING projection. The caller locks/authorizes the keys and their parents,
// and owns the transaction. The controller partitions these receipts into independent Key roots or SD3 effects.
func (s *Store) DeleteManyForAuditTx(ctx context.Context, tx *sql.Tx, ids []string, org *uuid.UUID) ([]DeleteReceipt, error) {
	if err := permission.LimitCheckAny(ctx, permission.Admin, permission.User); err != nil {
		return nil, err
	}
	uids, err := validate.ParseManyUUID("IntegrationKeyID", ids, 50)
	if err != nil {
		return nil, err
	}
	if tx == nil {
		return nil, sql.ErrTxDone
	}
	q := `DELETE FROM integration_keys k WHERE k.id=ANY($1::uuid[])`
	args := []any{pq.Array(uids)}
	if org != nil {
		if *org == uuid.Nil {
			return nil, validation.NewFieldError("OrganizationID", "must be specified")
		}
		q = `DELETE FROM integration_keys k USING services s
		WHERE k.id=ANY($1::uuid[]) AND s.id=k.service_id AND s.organization_id=$2
		AND (SELECT count(DISTINCT requested_id) FROM unnest($1::uuid[]) AS requested(requested_id)) = (
		SELECT count(*) FROM integration_keys matched JOIN services parent ON parent.id=matched.service_id
		WHERE matched.id=ANY($1::uuid[]) AND parent.organization_id=$2)`
		args = append(args, *org)
	}
	rows, err := tx.QueryContext(ctx, q+` RETURNING k.audit_resource_id,k.service_id`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []DeleteReceipt
	for rows.Next() {
		var r DeleteReceipt
		if err := rows.Scan(&r.ResourceID, &r.ServiceID); err != nil {
			return nil, err
		}
		result = append(result, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	want := make(map[uuid.UUID]bool)
	for _, id := range uids {
		want[id] = true
	}
	if org != nil && len(result) != len(want) {
		return nil, sql.ErrNoRows
	}
	return result, nil
}
