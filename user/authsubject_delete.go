package user

import (
	"context"
	"database/sql"
	"errors"

	"github.com/google/uuid"
	audit "github.com/target/goalert/user/authsubjectdeleteaudit"
	"github.com/target/goalert/user/deleteaudit"
)

type AuthSubjectDeleteResult struct {
	DeletedCount int
	Receipt      *audit.Receipt
}

// readAuthSubjectRows consumes the complete closed projection and checks both
// iteration and close errors. A second row is an integrity error, never a
// reason to keep the first identity. No authentication predicates are retained.
func readAuthSubjectRows(rows *sql.Rows) (*audit.Before, error) {
	var result *audit.Before
	var failure error
	for rows.Next() {
		var b audit.Before
		var owner, cm uuid.NullUUID
		b.Version = 1
		if err := rows.Scan(&b.ID, &owner, &cm, &b.RowVersion); err != nil {
			failure = err
			break
		}
		if !owner.Valid {
			failure = audit.ErrInvalid
			break
		}
		b.UserID = owner.UUID
		if result != nil {
			failure = audit.ErrInvalid
			break
		}
		if cm.Valid {
			b.CMID = &cm.UUID
		}
		result = &b
	}
	if err := rows.Err(); failure == nil {
		failure = err
	}
	if err := rows.Close(); failure == nil {
		failure = err
	}
	if failure != nil {
		return nil, failure
	}
	return result, nil
}

func (s *Store) deleteAuthSubjectForAudit(ctx context.Context, tx *sql.Tx, n *AuthSubject, e audit.Event) (AuthSubjectDeleteResult, error) {
	var result AuthSubjectDeleteResult
	if tx == nil {
		return result, audit.ErrInvalid
	}
	owner, err := uuid.Parse(n.UserID)
	if err != nil {
		return result, audit.ErrInvalid
	}
	org, err := deleteaudit.SnapshotOrganization(ctx, tx, owner)
	if err != nil {
		return result, audit.ErrCapture
	}
	e.TargetOrganizationID = audit.ID(org.ID)
	e.TargetOrgResolution = org.Resolution
	rows, err := tx.QueryContext(ctx, `SELECT id,user_id,cm_id,xmin::text::bigint FROM auth_subjects WHERE user_id=$1 AND provider_id=$2 AND subject_id=$3 FOR UPDATE`, owner, n.ProviderID, n.SubjectID)
	if err != nil {
		return result, audit.ErrCapture
	}
	before, err := readAuthSubjectRows(rows)
	if err != nil {
		if errors.Is(err, audit.ErrInvalid) {
			return result, audit.ErrInvalid
		}
		return result, audit.ErrCapture
	}
	rows, err = withTx(ctx, tx, s.deleteUserAuthSubject).QueryContext(ctx, owner, n.ProviderID, n.SubjectID)
	if err != nil {
		return result, audit.ErrDelete
	}
	returned, err := readAuthSubjectRows(rows)
	if err != nil {
		if errors.Is(err, audit.ErrInvalid) {
			return result, audit.ErrInvalid
		}
		return result, audit.ErrDelete
	}
	if returned == nil {
		return result, nil
	}
	if before == nil {
		return result, audit.ErrInvalid
	}
	var absent bool
	if err = tx.QueryRowContext(ctx, `SELECT NOT EXISTS(SELECT FROM auth_subjects WHERE id=$1)`, int64(returned.ID)).Scan(&absent); err != nil {
		return result, audit.ErrPostcheck
	}
	if !absent {
		return result, audit.ErrPostcheck
	}
	result.Receipt, err = audit.NewReceipt(tx, e, *before, *returned, owner, absent)
	if err != nil {
		return AuthSubjectDeleteResult{}, err
	}
	result.DeletedCount = 1
	return result, nil
}
