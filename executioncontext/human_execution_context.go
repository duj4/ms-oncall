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

type humanExecutionContextReader interface {
	FindCurrentUserOrganization(context.Context, uuid.UUID) (*organization.CurrentUserOrganization, error)
}

// HumanExecutionContextConstructor reconstructs ordinary human authority from
// current local durable state at request admission. It retains no result and
// does not reread the Session already resolved by canonical authentication.
type HumanExecutionContextConstructor struct {
	organizations humanExecutionContextReader
}

// NewHumanExecutionContextConstructor composes request-admission authority
// construction from the canonical Organization store.
func NewHumanExecutionContextConstructor(
	organizations *organization.Store,
) (*HumanExecutionContextConstructor, error) {
	return newHumanExecutionContextConstructor(organizations)
}

func newHumanExecutionContextConstructor(
	organizations humanExecutionContextReader,
) (*HumanExecutionContextConstructor, error) {
	if nilHumanExecutionContextDependency(organizations) {
		return nil, ErrInvalidHumanExecutionContextConstructor
	}
	return &HumanExecutionContextConstructor{organizations: organizations}, nil
}

// Construct consumes the identity-only authenticated-human Requester and
// returns the single downstream authority carrier. Every call observes the
// current User, assignment, base Organization, and NormalOrganization in one
// SQL statement. Mapping audit provenance is deliberately not an admission
// credential.
func (c *HumanExecutionContextConstructor) Construct(ctx context.Context) (ExecutionContext, error) {
	var zero ExecutionContext
	if c == nil || nilHumanExecutionContextDependency(c.organizations) {
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

	current, err := c.organizations.FindCurrentUserOrganization(ctx, authenticatedUserID)
	if err != nil {
		return zero, humanExecutionContextLookupFailure("read current User Organization", err)
	}
	if current == nil {
		return zero, humanExecutionContextFailure("current User Organization is missing")
	}
	if current.UserID != authenticatedUserID {
		return zero, humanExecutionContextFailure("current global User state is inconsistent")
	}
	if current.UserRole != permission.RoleUser && current.UserRole != permission.RoleAdmin {
		return zero, humanExecutionContextFailure("current global User role is invalid")
	}
	if permission.Admin(ctx) != (current.UserRole == permission.RoleAdmin) {
		return zero, humanExecutionContextFailure("legacy and current global User roles are inconsistent")
	}
	if current.OrganizationID == uuid.Nil || current.OrganizationID.String() == organization.DefaultOrganizationID ||
		(current.Role != organization.OrganizationRoleMember && current.Role != organization.OrganizationRoleAdmin) {
		return zero, humanExecutionContextFailure("current User Organization is not operational")
	}

	effectiveOrganizationID := current.OrganizationID
	typedContext, err := newExecutionContext(executionContextSpec{
		principalKind:            PrincipalKindHuman,
		principalID:              current.UserID.String(),
		actualActorID:            current.UserID.String(),
		authenticationSourceType: permission.SourceTypeAuthProvider.String(),
		authenticationSourceID:   sessionID.String(),
		organizationRole:         current.Role,
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

var _ humanExecutionContextReader = (*organization.Store)(nil)
