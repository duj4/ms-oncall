package deleteaudit

import (
	"context"
	"database/sql"
	"errors"
	"github.com/google/uuid"
	"github.com/target/goalert/organization"
)

// OrganizationSnapshot is historical attribution only, never a capability.
type OrganizationSnapshot struct {
	ID         uuid.UUID
	Resolution string
}

// SnapshotOrganization retains the existing attribution-only JOIN semantics.
// It lives below User to avoid importing authentication back into User Store.
func SnapshotOrganization(ctx context.Context, tx *sql.Tx, owner uuid.UUID) (OrganizationSnapshot, error) {
	unknown := OrganizationSnapshot{Resolution: "unknown"}
	var id uuid.UUID
	err := tx.QueryRowContext(ctx, `SELECT a.user_id FROM public.users u
	 JOIN public.user_organization_assignments a ON a.user_id=u.id
	 WHERE u.id=$1 FOR SHARE OF u,a`, owner).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return unknown, nil
	}
	if err != nil {
		return unknown, err
	}
	var resolution string
	err = tx.QueryRowContext(ctx, `SELECT o.id, CASE WHEN o.classification='NORMAL' THEN 'known_normal' ELSE 'known_default' END
	 FROM public.users u JOIN public.user_organization_assignments a ON a.user_id=u.id
	 JOIN public.organizations o ON o.id=a.effective_organization_id AND o.classification=a.effective_organization_classification
	 WHERE u.id=$1 AND u.role IN ('user','admin') AND (
	 (o.classification='NORMAL' AND o.id<>$2 AND a.mapping_outcome='EXACTLY_ONE' AND a.matched_count=1
	 AND a.effective_normal_organization_id=o.id AND a.organization_role IN ('ORG_MEMBER','ORG_ADMIN'))
	 OR (o.classification='DEFAULT' AND o.id=$2 AND a.effective_normal_organization_id IS NULL AND a.organization_role='NONE'))
	 FOR SHARE OF u,a,o`, owner, organization.DefaultOrganizationID).Scan(&id, &resolution)
	if errors.Is(err, sql.ErrNoRows) {
		return unknown, nil
	}
	if err != nil {
		return unknown, err
	}
	if resolution == "known_normal" {
		var normal uuid.UUID
		err = tx.QueryRowContext(ctx, `SELECT organization_id FROM public.normal_organizations WHERE organization_id=$1 AND organization_classification='NORMAL' FOR SHARE`, id).Scan(&normal)
		if errors.Is(err, sql.ErrNoRows) {
			return unknown, nil
		}
		if err != nil {
			return unknown, err
		}
	}
	return OrganizationSnapshot{ID: id, Resolution: resolution}, nil
}
