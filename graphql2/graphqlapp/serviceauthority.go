package graphqlapp

import (
	"context"

	"github.com/google/uuid"
	"github.com/target/goalert/auth"
	"github.com/target/goalert/executioncontext"
	"github.com/target/goalert/organization"
	"github.com/target/goalert/permission"
)

type serviceManagementOperation uint8

const (
	serviceManagementCreate serviceManagementOperation = iota
	serviceManagementUpdate
	serviceManagementDelete
)

// serviceManagementAuthority authorizes only Service mutations. Human role and
// Home come from canonical current-PG request admission; every Human receives
// a concrete Home Store constraint, including PlatformAdmin. This does not
// authorize credential issuance or refresh authority during an in-flight request.
func serviceManagementAuthority(ctx context.Context, operation serviceManagementOperation) (*uuid.UUID, error) {
	deny := permission.NewAccessDenied("Service management authority is required")
	if ctx == nil || operation > serviceManagementDelete {
		return nil, deny
	}
	home, err := rootStoreOrganizationID(ctx)
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
