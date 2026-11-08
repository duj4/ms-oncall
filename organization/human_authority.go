package organization

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/target/goalert/permission"
)

// CurrentHumanOrganization is request-admission identity, not OnCall affiliation.
// Default assignments are included only when their complete persisted relation
// is valid. Operational consumers continue to use CurrentUserOrganizationsQuery.
type CurrentHumanOrganization struct {
	UserID         uuid.UUID
	UserRole       permission.Role
	OrganizationID uuid.UUID
	Classification Classification
	Role           OrganizationRole
}

const currentHumanOrganizationQuery = `
 SELECT u.id, u.role, o.id, o.classification, a.organization_role
 FROM public.users u
 JOIN public.user_organization_assignments a ON a.user_id=u.id
 JOIN public.organizations o ON o.id=a.effective_organization_id
   AND o.classification=a.effective_organization_classification
 LEFT JOIN public.normal_organizations n ON n.organization_id=o.id
 WHERE u.id=$1 AND u.role IN ('user','admin') AND (
   (o.classification='NORMAL' AND o.id<>'` + DefaultOrganizationID + `'
    AND n.organization_id=a.effective_normal_organization_id
    AND n.organization_id=o.id AND n.organization_classification=o.classification
    AND a.organization_role IN ('ORG_ADMIN','ORG_MEMBER')
    AND a.mapping_outcome='EXACTLY_ONE' AND a.matched_count=1)
   OR
   (o.classification='DEFAULT' AND o.id='` + DefaultOrganizationID + `'
    AND o.canonical_name='` + DefaultOrganizationCanonicalName + `'
    AND n.organization_id IS NULL AND a.effective_normal_organization_id IS NULL
    AND a.organization_role='NONE'
    AND ((a.mapping_outcome='ZERO' AND a.matched_count=0)
      OR (a.mapping_outcome='MULTIPLE' AND a.matched_count>1)))
 )`

// FindCurrentHumanOrganization observes current user role and the complete Home
// assignment in one statement. Absence and contradictions grant no authority.
func (s *Store) FindCurrentHumanOrganization(ctx context.Context, id uuid.UUID) (*CurrentHumanOrganization, error) {
	if id == uuid.Nil {
		return nil, ErrInvalidInput
	}
	var value CurrentHumanOrganization
	err := s.db.QueryRowContext(ctx, currentHumanOrganizationQuery, id).Scan(&value.UserID, &value.UserRole, &value.OrganizationID, &value.Classification, &value.Role)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("read current Human authority: %w", err)
	}
	if value.UserID != id {
		return nil, ErrInvariantViolation
	}
	return &value, nil
}
