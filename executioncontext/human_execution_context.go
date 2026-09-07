package executioncontext

import (
	"context"
	"errors"
	"fmt"
	"reflect"

	"github.com/google/uuid"
	"github.com/target/goalert/auth"
	"github.com/target/goalert/organization"
	"github.com/target/goalert/permission"
	"github.com/target/goalert/user"
)

var (
	// ErrInvalidHumanExecutionContextConstructor indicates that the
	// request-admission component is absent or lacks a canonical durable reader.
	ErrInvalidHumanExecutionContextConstructor = errors.New("invalid human execution context constructor")
	// ErrHumanExecutionContextUnavailable is returned whenever current local
	// durable state cannot establish ordinary Organization-scoped human
	// authority. Callers must not repair or default this failure into authority.
	ErrHumanExecutionContextUnavailable = errors.New("human execution context unavailable")
)

type humanExecutionContextUserReader interface {
	FindOne(context.Context, string) (*user.User, error)
}

type humanExecutionContextOrganizationReader interface {
	FindUserOrganizationAssignment(context.Context, uuid.UUID) (*organization.UserOrganizationAssignment, error)
	FindNormalByID(context.Context, uuid.UUID) (*organization.NormalOrganization, error)
}

// HumanExecutionContextConstructor reconstructs ordinary human authority from
// current local durable state at request admission. It retains no result and
// does not reread the Session already resolved by canonical authentication.
type HumanExecutionContextConstructor struct {
	users         humanExecutionContextUserReader
	organizations humanExecutionContextOrganizationReader
}

// NewHumanExecutionContextConstructor composes request-admission authority
// construction from the canonical User and Organization stores.
func NewHumanExecutionContextConstructor(
	users *user.Store,
	organizations *organization.Store,
) (*HumanExecutionContextConstructor, error) {
	return newHumanExecutionContextConstructor(users, organizations)
}

func newHumanExecutionContextConstructor(
	users humanExecutionContextUserReader,
	organizations humanExecutionContextOrganizationReader,
) (*HumanExecutionContextConstructor, error) {
	if nilHumanExecutionContextDependency(users) || nilHumanExecutionContextDependency(organizations) {
		return nil, ErrInvalidHumanExecutionContextConstructor
	}
	return &HumanExecutionContextConstructor{users: users, organizations: organizations}, nil
}

// Construct consumes the identity-only authenticated-human Requester and
// returns the single downstream authority carrier. Every call re-reads the
// current User, assignment, and effective NormalOrganization. Mapping audit
// provenance is deliberately not an admission credential.
func (c *HumanExecutionContextConstructor) Construct(ctx context.Context) (ExecutionContext, error) {
	var zero ExecutionContext
	if c == nil || nilHumanExecutionContextDependency(c.users) || nilHumanExecutionContextDependency(c.organizations) {
		return zero, ErrInvalidHumanExecutionContextConstructor
	}
	if ctx == nil {
		return zero, humanExecutionContextFailure("operation context is required")
	}
	if err := ctx.Err(); err != nil {
		return zero, humanExecutionContextLookupFailure("operation context is not current", err)
	}

	requester := auth.RequesterFromContext(ctx)
	if requester == nil || !requester.Valid() {
		return zero, humanExecutionContextFailure("authenticated-human Requester is required")
	}
	authenticatedUserID := requester.UserID()
	sessionID := requester.SessionID()

	// Legacy permission metadata remains installed for existing GoAlert Stores,
	// logging, and compatibility. It corroborates the typed identity but is not
	// the semantic source of human identity or Organization authority.
	source := permission.Source(ctx)
	if permission.UserID(ctx) != authenticatedUserID.String() || source == nil ||
		source.Type != permission.SourceTypeAuthProvider || source.ID != sessionID.String() {
		return zero, humanExecutionContextFailure("legacy authentication metadata is inconsistent with Requester")
	}

	currentUser, err := c.users.FindOne(ctx, authenticatedUserID.String())
	if err != nil {
		return zero, humanExecutionContextLookupFailure("read current global User", err)
	}
	if currentUser == nil {
		return zero, humanExecutionContextFailure("current global User is missing")
	}
	loadedUserID, ok := parseCanonicalAuthorityUUID(currentUser.ID)
	if !ok || loadedUserID != authenticatedUserID {
		return zero, humanExecutionContextFailure("current global User state is inconsistent")
	}
	if _, err := currentUser.Normalize(); err != nil {
		return zero, humanExecutionContextLookupFailure("validate current global User", err)
	}
	if currentUser.Role != permission.RoleUser && currentUser.Role != permission.RoleAdmin {
		return zero, humanExecutionContextFailure("current global User role is invalid")
	}
	if permission.Admin(ctx) != (currentUser.Role == permission.RoleAdmin) {
		return zero, humanExecutionContextFailure("legacy and current global User roles are inconsistent")
	}

	assignment, err := c.organizations.FindUserOrganizationAssignment(ctx, authenticatedUserID)
	if err != nil {
		return zero, humanExecutionContextLookupFailure("read current UserOrganizationAssignment", err)
	}
	if !validCurrentOrdinaryAssignment(assignment, authenticatedUserID) {
		return zero, humanExecutionContextFailure("current UserOrganizationAssignment is not Organization-operational")
	}

	normal, err := c.organizations.FindNormalByID(ctx, assignment.EffectiveOrganizationID)
	if err != nil {
		return zero, humanExecutionContextLookupFailure("read current effective NormalOrganization", err)
	}
	if !validCurrentNormalOrganization(normal, assignment.EffectiveOrganizationID) ||
		assignment.EffectiveOrganizationClassification != normal.Classification {
		return zero, humanExecutionContextFailure("current assignment and Organization state is inconsistent")
	}

	effectiveOrganizationID := assignment.EffectiveOrganizationID
	typedContext, err := newExecutionContext(executionContextSpec{
		principalKind:            PrincipalKindHuman,
		principalID:              currentUser.ID,
		actualActorID:            currentUser.ID,
		authenticationSourceType: permission.SourceTypeAuthProvider.String(),
		authenticationSourceID:   sessionID.String(),
		organizationRole:         assignment.Role,
		platformAdmin:            false,
		authorityMode:            AuthorityModeOrganizationScoped,
		effectiveOrganizationID:  &effectiveOrganizationID,
	})
	if err != nil || !EligibleForOrganizationBusinessScope(&typedContext, effectiveOrganizationID) {
		if err == nil {
			err = errInvalidExecutionContext
		}
		return zero, humanExecutionContextLookupFailure("construct typed ExecutionContext", err)
	}
	return typedContext, nil
}

func validCurrentOrdinaryAssignment(value *organization.UserOrganizationAssignment, userID uuid.UUID) bool {
	return value != nil && userID != uuid.Nil && value.UserID == userID &&
		value.MappingOutcome == organization.MappingOutcomeExactlyOne &&
		value.EffectiveOrganizationID != uuid.Nil &&
		value.EffectiveOrganizationClassification == organization.ClassificationNormal &&
		(value.Role == organization.OrganizationRoleMember || value.Role == organization.OrganizationRoleAdmin) &&
		value.Evaluation.MatchedCount == 1
}

func validCurrentNormalOrganization(value *organization.NormalOrganization, expectedID uuid.UUID) bool {
	return value != nil && expectedID != uuid.Nil && value.ID == expectedID &&
		value.ID.String() != organization.DefaultOrganizationID &&
		value.Classification == organization.ClassificationNormal
}

func parseCanonicalAuthorityUUID(value string) (uuid.UUID, bool) {
	id, err := uuid.Parse(value)
	return id, err == nil && id != uuid.Nil && id.String() == value
}

func nilHumanExecutionContextDependency(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Ptr, reflect.Slice, reflect.UnsafePointer:
		return reflected.IsNil()
	default:
		return false
	}
}

func humanExecutionContextFailure(reason string) error {
	return fmt.Errorf("%w: %s", ErrHumanExecutionContextUnavailable, reason)
}

func humanExecutionContextLookupFailure(operation string, err error) error {
	if err == nil {
		return humanExecutionContextFailure(operation)
	}
	return fmt.Errorf("%w: %s: %w", ErrHumanExecutionContextUnavailable, operation, err)
}

var (
	_ humanExecutionContextUserReader         = (*user.Store)(nil)
	_ humanExecutionContextOrganizationReader = (*organization.Store)(nil)
)
