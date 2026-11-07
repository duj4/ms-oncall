package graphqlapp

import (
	"context"
	"database/sql"
	"errors"

	"github.com/google/uuid"
	"github.com/target/goalert/organization"
	"github.com/target/goalert/permission"
	"github.com/target/goalert/validation/validate"
)

// contactMethodTargetOrganization is only for CM Create and metadata Update.
// Human Home/PA comes from current-PG admission; the target comes from locked
// persistent User/Assignment/Normal rows in the business transaction.
func contactMethodTargetOrganization(ctx context.Context, tx *sql.Tx, userID string, home *uuid.UUID, pa bool) (*uuid.UUID, error) {
	if home == nil {
		return nil, nil // Existing non-Human Store authorization still applies.
	}
	deny := permission.NewAccessDenied("Contact Method target authority is required")
	if !pa && userID != permission.UserID(ctx) {
		return nil, deny
	}
	if err := validate.UUID("UserID", userID); err != nil {
		return nil, err
	}
	var owner uuid.UUID
	// Lock identity/assignment before resolving the mutable parent in a new
	// READ COMMITTED statement, following the existing CMNR lock boundary.
	err := tx.QueryRowContext(ctx, `SELECT a.user_id FROM users u
		JOIN user_organization_assignments a ON a.user_id=u.id
		WHERE u.id=$1 FOR SHARE OF u,a`, userID).Scan(&owner)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, deny
	}
	if err != nil {
		return nil, err
	}
	var target uuid.UUID
	err = tx.QueryRowContext(ctx, `SELECT a.effective_organization_id
		FROM users u JOIN user_organization_assignments a ON a.user_id=u.id
		JOIN organizations o ON o.id=a.effective_organization_id
			AND o.classification=a.effective_organization_classification
		JOIN normal_organizations n ON n.organization_id=o.id
			AND n.organization_classification=o.classification
			AND n.organization_id=a.effective_normal_organization_id
		WHERE u.id=$1 AND u.role IN ('user','admin')
			AND a.mapping_outcome='EXACTLY_ONE' AND a.matched_count=1
			AND a.effective_organization_classification='NORMAL'
			AND a.effective_organization_id<>$2
			AND a.effective_normal_organization_id=a.effective_organization_id
			AND a.organization_role IN ('ORG_MEMBER','ORG_ADMIN')
		FOR SHARE OF u,a,o,n`, owner, organization.DefaultOrganizationID).Scan(&target)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && !pa && target != *home) {
		return nil, deny
	}
	if err != nil {
		return nil, err
	}
	return &target, nil
}
