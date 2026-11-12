package override

import (
	"context"
	"database/sql"
	"slices"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/target/goalert/override/deleteaudit"
	"github.com/target/goalert/permission"
	"github.com/target/goalert/validation/validate"
)

// DeleteResult carries the locked safe inventory and actual DELETE RETURNING
// identities. It neither grants authority nor claims a committed outcome.
type DeleteResult struct {
	Targets, Receipts []deleteaudit.Before
}

// DeleteUserOverrideForAuditTx uses the supplied Controller transaction only.
// The legacy public operations retain their existing behavior and signatures.
// Never lock the parent Schedule here: Schedule deletion locks its parent row
// before taking the user_overrides table lock during its FK cascade.
func (s *Store) DeleteUserOverrideForAuditTx(ctx context.Context, tx *sql.Tx, ids []string, organizationID *uuid.UUID) (result DeleteResult, err error) {
	if tx == nil {
		return result, deleteaudit.ErrUnavailable
	}
	if err = permission.LimitCheckAny(ctx, permission.User, permission.Admin); err != nil {
		return result, err
	}
	if len(ids) == 0 {
		return result, nil
	}
	parsed, err := validate.ParseManyUUID("UserOverrideID", ids, 50)
	if err != nil {
		return result, err
	}
	slices.SortFunc(parsed, func(a, b uuid.UUID) int { return slices.Compare(a[:], b[:]) })
	parsed = slices.Compact(parsed)
	scope, err := organizationScope(organizationID)
	if err != nil {
		return result, err
	}
	err = s.withTx(ctx, tx, func(tx *sql.Tx) error {
		// withTx has already acquired the existing EXCLUSIVE table lock. A new
		// READ COMMITTED statement observes any update that completed while waiting.
		const fields = `o.id,o.tgt_schedule_id,s.organization_id,o.add_user_id,o.remove_user_id,o.start_time,o.end_time,o.xmin::text::bigint`
		args := []any{pq.Array(parsed), scope}
		rows, err := tx.QueryContext(ctx, `SELECT `+fields+` FROM user_overrides o JOIN schedules s ON s.id=o.tgt_schedule_id WHERE o.id=ANY($1::uuid[]) AND ($2::uuid IS NULL OR s.organization_id=$2) ORDER BY o.id`, args...)
		if err != nil {
			return err
		}
		result.Targets, err = readDeleteBefore(rows)
		if err != nil {
			return err
		}
		if scope.Valid && len(result.Targets) != len(parsed) {
			return sql.ErrNoRows
		}
		for _, b := range result.Targets {
			if err := b.Validate(); err != nil {
				return err
			}
		}
		// Use a fresh statement again: neither client input nor a previously
		// joined parent snapshot can substitute for actual deletion identity.
		rows, err = tx.QueryContext(ctx, `DELETE FROM user_overrides o USING schedules s WHERE s.id=o.tgt_schedule_id AND o.id=ANY($1::uuid[]) AND ($2::uuid IS NULL OR s.organization_id=$2) RETURNING `+fields, args...)
		if err != nil {
			return err
		}
		result.Receipts, err = readDeleteBefore(rows)
		if err != nil {
			return err
		}
		if err = deleteaudit.ValidateReceipts(result.Targets, result.Receipts); err != nil {
			return err
		}
		var remains bool
		if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT FROM user_overrides WHERE id=ANY($1::uuid[]))`, pq.Array(parsed)).Scan(&remains); err != nil {
			return err
		}
		if remains {
			return deleteaudit.ErrInvalid
		}
		// A delete trigger or concurrent parent change must not leave a different
		// attribution behind a seemingly matching joined RETURNING snapshot.
		parents, orgs := make([]uuid.UUID, 0, len(result.Targets)), make([]uuid.UUID, 0, len(result.Targets))
		for _, b := range result.Targets {
			parents = append(parents, b.ParentScheduleID)
			orgs = append(orgs, b.TargetOrganizationID)
		}
		var matched int
		if err = tx.QueryRowContext(ctx, `SELECT count(*) FROM unnest($1::uuid[],$2::uuid[]) expected(id,org) JOIN schedules s ON s.id=expected.id AND s.organization_id=expected.org`, pq.Array(parents), pq.Array(orgs)).Scan(&matched); err != nil {
			return err
		}
		if matched != len(result.Targets) {
			return deleteaudit.ErrInvalid
		}
		return nil
	})
	return result, err
}

func readDeleteBefore(rows *sql.Rows) ([]deleteaudit.Before, error) {
	defer rows.Close()
	var result []deleteaudit.Before
	for rows.Next() {
		b := deleteaudit.Before{Version: 1}
		var add, remove uuid.NullUUID
		if err := rows.Scan(&b.RootID, &b.ParentScheduleID, &b.TargetOrganizationID, &add, &remove, &b.Start, &b.End, &b.RowVersion); err != nil {
			return nil, err
		}
		if add.Valid {
			b.AddUserID = &add.UUID
		}
		if remove.Valid {
			b.RemoveUserID = &remove.UUID
		}
		result = append(result, b)
		if len(result) > deleteaudit.MaxRoots {
			return nil, deleteaudit.ErrCapacity
		}
	}
	return result, rows.Err()
}
