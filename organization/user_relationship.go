package organization

import (
	"context"
	"database/sql"

	"github.com/google/uuid"
)

// ValidateUserOrganizationTx checks a staffing reference against the persisted
// parent's Organization in the business transaction. It deliberately grants no
// exception for a target User's platform role and adds no assignment locks or
// in-flight transfer fence. Unavailable and foreign affiliations are both absent.
func (s *Store) ValidateUserOrganizationTx(ctx context.Context, tx *sql.Tx, userID, parentOrganizationID uuid.UUID) error {
	if userID == uuid.Nil || parentOrganizationID == uuid.Nil {
		return ErrNotFound
	}
	target, err := s.FindCurrentUserOrganizationTx(ctx, tx, userID)
	if err != nil {
		return err
	}
	if target.OrganizationID != parentOrganizationID {
		return ErrNotFound
	}
	return nil
}
