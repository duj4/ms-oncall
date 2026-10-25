package contactmethod

import (
	"context"
	"database/sql"
	"slices"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/target/goalert/executioncontext"
	"github.com/target/goalert/permission"
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
	cms, err := LockCMNRContactMethods(ctx, tx, ids)
	if err != nil {
		return err
	}
	lockedIDs := make([]uuid.UUID, 0, len(cms))
	for id := range cms {
		lockedIDs = append(lockedIDs, id)
	}
	// Validate the complete cascade before deleting anything. CM locks fence
	// new references; NR locks fence concurrent child owner/parent changes.
	rows, err := tx.QueryContext(ctx, `SELECT user_id,contact_method_id FROM user_notification_rules
		WHERE contact_method_id=ANY($1::uuid[]) ORDER BY id FOR UPDATE`, pq.Array(lockedIDs))
	if err != nil {
		return err
	}
	for rows.Next() {
		var owner, cm uuid.UUID
		if err := rows.Scan(&owner, &cm); err != nil {
			_ = rows.Close()
			return err
		}
		if cms[cm] != owner {
			_ = rows.Close()
			return permission.NewAccessDenied("")
		}
	}
	err = rows.Err()
	_ = rows.Close()
	if err != nil {
		return err
	}
	if err := AuthorizeCMNROwners(ctx, tx, authority, cms); err != nil {
		return err
	}
	// Delete only locked existing rows, never an ID first inserted after the
	// locking read. Missing IDs retain their S0A no-op behavior.
	_, err = tx.ExecContext(ctx, `DELETE FROM user_contact_methods WHERE id=ANY($1::uuid[])`, pq.Array(lockedIDs))
	return err
}
