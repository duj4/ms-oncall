package graphqlapp

import (
	"context"

	"github.com/google/uuid"
	"github.com/target/goalert/auth"
	"github.com/target/goalert/executioncontext"
	"github.com/target/goalert/organization"
	"github.com/target/goalert/permission"
)

type scheduleRotationManagementOperation uint8

const (
	scheduleRotationManagementCreate scheduleRotationManagementOperation = iota
	scheduleRotationManagementUpdate
)

// scheduleRotationManagementAuthority uses current-PG Human admission and always
// constrains Human management to Home, including PlatformAdmin. Internal updates
// retain trusted System compatibility; nil scope alone grants no authority.
func scheduleRotationManagementAuthority(ctx context.Context, operation scheduleRotationManagementOperation) (*uuid.UUID, error) {
	deny := permission.NewAccessDenied("Schedule/Rotation management authority is required")
	if ctx == nil || operation > scheduleRotationManagementUpdate {
		return nil, deny
	}
	home, err := rootManagementHome(ctx)
	if err != nil {
		return nil, err
	}
	ec := executioncontext.ExecutionContextFromContext(ctx)
	if home == nil {
		if operation == scheduleRotationManagementUpdate && permission.System(ctx) &&
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
