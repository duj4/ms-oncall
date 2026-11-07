package graphqlapp

import (
	"context"

	"github.com/google/uuid"
	"github.com/target/goalert/executioncontext"
	"github.com/target/goalert/permission"
)

// userProfileScope is restricted to GraphQL User profiles. Current-PG Human
// admission establishes Home and PA independently; other root reads keep their
// existing scopes. A nil Home retains the existing non-Human compatibility path.
func userProfileScope(ctx context.Context) (home *uuid.UUID, platformAdmin bool, err error) {
	home, err = rootStoreOrganizationID(ctx)
	if err != nil || home == nil {
		return home, false, err
	}
	ec := executioncontext.ExecutionContextFromContext(ctx)
	if permission.System(ctx) || permission.Service(ctx) || !permission.User(ctx) ||
		ec == nil || ec.Privileges() == nil ||
		ec.Privileges().PlatformAdmin() != permission.Admin(ctx) {
		return nil, false, permission.NewAccessDenied("User authority is required")
	}
	return home, ec.Privileges().PlatformAdmin(), nil
}
