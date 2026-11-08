package graphqlapp

import (
	"context"
	"database/sql"

	"github.com/google/uuid"
	"github.com/target/goalert/auth"
	"github.com/target/goalert/executioncontext"
	"github.com/target/goalert/organization"
	"github.com/target/goalert/permission"
	"github.com/target/goalert/validation/validate"
)

type serviceManagementOperation uint8

const (
	serviceManagementCreate serviceManagementOperation = iota
	serviceManagementUpdate
	serviceManagementDelete
)

// serviceManagementAuthority authorizes only Service mutations. Human role and
// Home come from canonical current-PG request admission. This returns a Home
// constraint; Update and Delete subsequently resolve their PlatformAdmin targets.
// It does not authorize credential issuance or refresh in-flight authority.
func serviceManagementAuthority(ctx context.Context, operation serviceManagementOperation) (*uuid.UUID, error) {
	deny := permission.NewAccessDenied("Service management authority is required")
	if ctx == nil || operation > serviceManagementDelete {
		return nil, deny
	}
	home, err := rootManagementHome(ctx)
	if err != nil {
		return nil, err
	}
	ec := executioncontext.ExecutionContextFromContext(ctx)
	if home == nil {
		// Preserve the demonstrated trusted internal Update/Delete boundary.
		// Create still requires Human authority. Nil scope alone grants nothing.
		if operation != serviceManagementCreate && permission.System(ctx) &&
			permission.UserID(ctx) == "" && !permission.Service(ctx) &&
			auth.RequesterFromContext(ctx) == nil && ec == nil && permission.Source(ctx) == nil {
			return nil, nil
		}
		return nil, deny
	}
	if permission.System(ctx) || permission.Service(ctx) || !permission.User(ctx) || ec == nil || ec.Privileges() == nil {
		return nil, deny
	}
	p := ec.Privileges()
	if p.PlatformAdmin() != permission.Admin(ctx) ||
		(p.OrganizationRole() != organization.OrganizationRoleAdmin && !p.PlatformAdmin()) {
		return nil, deny
	}
	return home, nil
}

// serviceUpdateTargetOrganization is limited to updating an existing Service.
// Recheck the admission carrier before any privileged target lookup; this is
// not a new authority read or an expansion of generic nil-scope Store access.
func serviceUpdateTargetOrganization(ctx context.Context, tx *sql.Tx, id string) (*uuid.UUID, error) {
	home, err := serviceManagementAuthority(ctx, serviceManagementUpdate)
	if err != nil || home == nil {
		return home, err // Only the explicit trusted System path can return nil.
	}
	ec := executioncontext.ExecutionContextFromContext(ctx)
	if !ec.Privileges().PlatformAdmin() {
		return home, nil
	}
	if err := validate.UUID("ServiceID", id); err != nil {
		return nil, err
	}
	var target uuid.UUID
	err = tx.QueryRowContext(ctx, `
		SELECT s.organization_id FROM services s
		JOIN organizations o ON o.id = s.organization_id AND o.classification = 'NORMAL'
		JOIN normal_organizations n ON n.organization_id = o.id
			AND n.organization_classification = o.classification
		JOIN escalation_policies p ON p.id = s.escalation_policy_id
			AND p.organization_id = s.organization_id
		WHERE s.id = $1 AND s.organization_id <> $2 AND s.organization_id <> $3
		FOR UPDATE OF s FOR SHARE OF o, n, p
	`, id, organization.DefaultOrganizationID, uuid.Nil).Scan(&target)
	if err != nil {
		return nil, err
	}
	return &target, nil
}

// lockServiceUpdatePolicy corroborates and locks the replacement EP's actual
// Organization after normal Store validation, without changing the EP itself.
func lockServiceUpdatePolicy(ctx context.Context, tx *sql.Tx, id string, organizationID uuid.UUID) error {
	var policyID string
	return tx.QueryRowContext(ctx, `SELECT id FROM escalation_policies
		WHERE id = $1 AND organization_id = $2 FOR SHARE`, id, organizationID).Scan(&policyID)
}
