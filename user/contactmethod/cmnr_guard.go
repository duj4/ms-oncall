package contactmethod

import (
	"context"
	"database/sql"
	"slices"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/target/goalert/executioncontext"
)

// LockCMNRContactMethods locks existing CM rows in UUID order for CM Delete
// and NR Create/Delete. No raw destination is read. FOR UPDATE also conflicts
// with the FK KEY SHARE used by concurrent NR insertion/reparenting.
func LockCMNRContactMethods(ctx context.Context, tx *sql.Tx, ids []uuid.UUID) (map[uuid.UUID]uuid.UUID, error) {
	rows, err := tx.QueryContext(ctx, `SELECT id,user_id FROM user_contact_methods
		WHERE id=ANY($1::uuid[]) ORDER BY id FOR UPDATE`, pq.Array(ids))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	owners := make(map[uuid.UUID]uuid.UUID)
	for rows.Next() {
		var id, owner uuid.UUID
		if err := rows.Scan(&id, &owner); err != nil {
			return nil, err
		}
		owners[id] = owner
	}
	return owners, rows.Err()
}

// AuthorizeCMNROwners visits locked CM owners in UUID order, acquiring current
// User/Normal assignment locks before either Store writes. It is deliberately
// limited to the three approved CMNR mutations.
func AuthorizeCMNROwners(ctx context.Context, tx *sql.Tx, authority executioncontext.CMNRMutationAuthority, cms map[uuid.UUID]uuid.UUID) error {
	owners := make([]uuid.UUID, 0, len(cms))
	for _, owner := range cms {
		owners = append(owners, owner)
	}
	slices.SortFunc(owners, func(a, b uuid.UUID) int { return slices.Compare(a[:], b[:]) })
	for _, owner := range slices.Compact(owners) {
		if err := authority.AuthorizeUser(ctx, tx, owner); err != nil {
			return err
		}
	}
	return nil
}

func deleteCMNRTargets(ctx context.Context, tx *sql.Tx, authority executioncontext.CMNRMutationAuthority, ids []uuid.UUID) error {
	_, err := deleteCMNRTargetsResult(ctx, tx, authority, ids, false)
	return err
}
