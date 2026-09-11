package graphqlapp

import (
	"context"

	"github.com/google/uuid"
	"github.com/target/goalert/auth"
	"github.com/target/goalert/executioncontext"
	"github.com/target/goalert/permission"
)

// rootStoreOrganizationID classifies the current GraphQL principal at the
// application boundary. A non-nil result is the server-controlled effective
// Organization for an ordinary authenticated-human request. A nil result is
// the existing non-human compatibility path.
func rootStoreOrganizationID(ctx context.Context) (*uuid.UUID, error) {
	source := permission.Source(ctx)
	requester := auth.RequesterFromContext(ctx)

	if source == nil || source.Type != permission.SourceTypeAuthProvider {
		if requester != nil {
			return nil, permission.NewAccessDenied("authenticated-human Requester and permission source are inconsistent")
		}
		return nil, nil
	}

	if requester == nil || !requester.Valid() {
		return nil, permission.NewAccessDenied("authenticated-human Requester is required")
	}
	if permission.UserID(ctx) != requester.UserID().String() || source.ID != requester.SessionID().String() {
		return nil, permission.NewAccessDenied("authenticated-human Requester and permission source are inconsistent")
	}

	authority := executioncontext.ExecutionContextFromContext(ctx)
	if authority == nil || !authority.Valid() ||
		authority.PrincipalKind() != executioncontext.PrincipalKindHuman ||
		authority.PrincipalID() != requester.UserID().String() ||
		authority.ActualActorID() != requester.UserID().String() ||
		authority.AuthorityMode() != executioncontext.AuthorityModeOrganizationScoped {
		return nil, permission.NewAccessDenied("normal Organization scoped authority is required")
	}

	authenticationSource := authority.AuthenticationSource()
	if authenticationSource == nil ||
		authenticationSource.Type() != permission.SourceTypeAuthProvider.String() ||
		authenticationSource.ID() != requester.SessionID().String() {
		return nil, permission.NewAccessDenied("authenticated-human authority and permission source are inconsistent")
	}

	organizationID, present := authority.EffectiveOrganizationID()
	if !present || !executioncontext.EligibleForOrganizationBusinessScope(authority, organizationID) {
		return nil, permission.NewAccessDenied("normal Organization scoped authority is required")
	}

	return &organizationID, nil
}
