package executioncontext

import (
	"context"

	"github.com/target/goalert/auth"
	"github.com/target/goalert/permission"
)

// CheckHumanAuthority corroborates immutable admission evidence with canonical
// request identity. It grants no operation, target, field or Store permission.
func CheckHumanAuthority(ctx context.Context) (*ExecutionContext, error) {
	deny := permission.NewAccessDenied("current Human authority is required")
	if ctx == nil || permission.System(ctx) || permission.Service(ctx) || !permission.User(ctx) {
		return nil, deny
	}
	r := auth.RequesterFromContext(ctx)
	c := ExecutionContextFromContext(ctx)
	s := permission.Source(ctx)
	if r == nil || !r.Valid() || c == nil || !c.Valid() || s == nil ||
		c.PrincipalKind() != PrincipalKindHuman || c.PrincipalID() != r.UserID().String() || c.ActualActorID() != r.UserID().String() ||
		permission.UserID(ctx) != r.UserID().String() || s.Type != permission.SourceTypeAuthProvider || s.ID != r.SessionID().String() ||
		c.AuthenticationSource().Type() != s.Type.String() || c.AuthenticationSource().ID() != s.ID ||
		c.Privileges().PlatformAdmin() != permission.Admin(ctx) {
		return nil, deny
	}
	if _, ok := c.HomeOrganizationID(); !ok {
		return nil, deny
	}
	return c, nil
}
