package executioncontext

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/target/goalert/auth"
	"github.com/target/goalert/organization"
	"github.com/target/goalert/permission"
	coretimezone "github.com/target/goalert/timezone"
	"github.com/target/goalert/user"
)

var (
	// ErrInvalidCurrentHumanAuthorityConstructor indicates that the trusted
	// current-authority component is absent or was not composed from all of its
	// canonical durable readers.
	ErrInvalidCurrentHumanAuthorityConstructor = errors.New("invalid current human authority constructor")
	// ErrCurrentHumanAuthorityUnavailable is returned whenever current durable
	// state cannot establish ordinary Organization-operational human authority.
	// Callers must not repair, default, or otherwise turn this error into
	// authority.
	ErrCurrentHumanAuthorityUnavailable = errors.New("current human authority unavailable")
)

type currentHumanSessionReader interface {
	FindCurrentUserSession(context.Context, uuid.UUID) (*auth.CurrentUserSession, error)
}

type currentHumanUserReader interface {
	FindOne(context.Context, string) (*user.User, error)
}

type currentHumanOrganizationReader interface {
	FindUserOrganizationAssignment(context.Context, uuid.UUID) (*organization.UserOrganizationAssignment, error)
	FindNormalByID(context.Context, uuid.UUID) (*organization.NormalOrganization, error)
}

// CurrentHumanAuthorityConstructor constructs ordinary human authority from
// current durable state for one operation. It retains no result or
// session-lifetime Organization authority between calls.
//
// Its zero value is invalid. The public constructor accepts only the canonical
// Core stores; the interface-backed seam remains package-private for focused
// tests and prevents arbitrary packages from supplying authority assertions.
type CurrentHumanAuthorityConstructor struct {
	sessions      currentHumanSessionReader
	users         currentHumanUserReader
	organizations currentHumanOrganizationReader
}

// NewCurrentHumanAuthorityConstructor composes current ordinary-human
// authority construction from the canonical Auth, User, and Organization
// stores. It performs no durable lookup until Construct is called.
func NewCurrentHumanAuthorityConstructor(
	sessions *auth.Handler,
	users *user.Store,
	organizations *organization.Store,
) (*CurrentHumanAuthorityConstructor, error) {
	return newCurrentHumanAuthorityConstructor(sessions, users, organizations)
}

func newCurrentHumanAuthorityConstructor(
	sessions currentHumanSessionReader,
	users currentHumanUserReader,
	organizations currentHumanOrganizationReader,
) (*CurrentHumanAuthorityConstructor, error) {
	if nilCurrentAuthorityDependency(sessions) || nilCurrentAuthorityDependency(users) || nilCurrentAuthorityDependency(organizations) {
		return nil, ErrInvalidCurrentHumanAuthorityConstructor
	}
	return &CurrentHumanAuthorityConstructor{
		sessions:      sessions,
		users:         users,
		organizations: organizations,
	}, nil
}

// CurrentHumanAuthority is one immutable accepted Stage-1 result. It combines
// the typed ExecutionContext with the current durable facts observed for this
// operation. The zero value is invalid and conveys no authority.
type CurrentHumanAuthority struct {
	valid       bool
	context     ExecutionContext
	observation CurrentHumanAuthorityObservation
}

// Valid reports whether both parts of the Stage-1 result were completely
// constructed from accepted current durable state.
func (a *CurrentHumanAuthority) Valid() bool {
	return a != nil && a.valid && a.context.Valid() && a.observation.Valid()
}

// ExecutionContext returns a copy of the accepted typed context. Invalid
// results return nil.
func (a *CurrentHumanAuthority) ExecutionContext() *ExecutionContext {
	if !a.Valid() {
		return nil
	}
	value := a.context
	return &value
}

// Observation returns a copy of the operation-local current-authority
// evidence. Invalid results return nil.
func (a *CurrentHumanAuthority) Observation() *CurrentHumanAuthorityObservation {
	if !a.Valid() {
		return nil
	}
	value := a.observation
	return &value
}

// CurrentHumanAuthorityObservation is immutable operation-local evidence of
// the durable facts used to construct ordinary Organization authority. It is
// neither persistent session authority nor a concurrency guard. Stage 2 must
// independently and atomically validate every material mutable predicate at a
// protected access or effect boundary.
type CurrentHumanAuthorityObservation struct {
	valid                      bool
	sessionCurrent             bool
	sessionID                  uuid.UUID
	userID                     uuid.UUID
	globalUserRole             permission.Role
	assignmentUserID           uuid.UUID
	assignmentState            organization.AssignmentState
	mappingOutcome             organization.MappingOutcome
	effectiveOrganizationID    uuid.UUID
	organizationRole           organization.OrganizationRole
	assignmentGeneration       int64
	organizationClassification organization.Classification
	organizationLifecycle      organization.Lifecycle
}

// Valid reports whether this complete observation was produced as part of an
// accepted current-authority construction.
func (o *CurrentHumanAuthorityObservation) Valid() bool {
	return o != nil && o.valid && o.sessionCurrent
}

// SessionCurrent reports that the canonical session row and its global User
// relationship existed when Stage 1 performed this operation's lookup. It
// does not promise that the session remains current after construction.
func (o *CurrentHumanAuthorityObservation) SessionCurrent() bool { return o.Valid() }

// SessionID returns the currently observed authenticated session identity, or
// uuid.Nil for an invalid observation.
func (o *CurrentHumanAuthorityObservation) SessionID() uuid.UUID {
	if !o.Valid() {
		return uuid.Nil
	}
	return o.sessionID
}

// UserID returns the currently observed stable global User identity, or
// uuid.Nil for an invalid observation.
func (o *CurrentHumanAuthorityObservation) UserID() uuid.UUID {
	if !o.Valid() {
		return uuid.Nil
	}
	return o.userID
}

// GlobalUserRole returns the current legacy global User role observed during
// construction. It is identity-state evidence only and is not interpreted as
// a PlatformAdmin grant or an Organization role.
func (o *CurrentHumanAuthorityObservation) GlobalUserRole() permission.Role {
	if !o.Valid() {
		return ""
	}
	return o.globalUserRole
}

// AssignmentUserID returns the stable identity of the observed assignment
// row. UserOrganizationAssignment is keyed by global User identity.
func (o *CurrentHumanAuthorityObservation) AssignmentUserID() uuid.UUID {
	if !o.Valid() {
		return uuid.Nil
	}
	return o.assignmentUserID
}

// AssignmentState returns the currently observed assignment state.
func (o *CurrentHumanAuthorityObservation) AssignmentState() organization.AssignmentState {
	if !o.Valid() {
		return ""
	}
	return o.assignmentState
}

// MappingOutcome returns the currently observed deterministic assignment
// resolution outcome.
func (o *CurrentHumanAuthorityObservation) MappingOutcome() organization.MappingOutcome {
	if !o.Valid() {
		return ""
	}
	return o.mappingOutcome
}

// EffectiveOrganizationID returns the current effective normal Organization
// identity used for this construction.
func (o *CurrentHumanAuthorityObservation) EffectiveOrganizationID() uuid.UUID {
	if !o.Valid() {
		return uuid.Nil
	}
	return o.effectiveOrganizationID
}

// OrganizationRole returns the currently observed ordinary Organization role.
func (o *CurrentHumanAuthorityObservation) OrganizationRole() organization.OrganizationRole {
	if !o.Valid() {
		return ""
	}
	return o.organizationRole
}

// AssignmentGeneration returns the positive current assignment generation.
func (o *CurrentHumanAuthorityObservation) AssignmentGeneration() int64 {
	if !o.Valid() {
		return 0
	}
	return o.assignmentGeneration
}

// OrganizationClassification returns the classification observed from the
// current NormalOrganization record.
func (o *CurrentHumanAuthorityObservation) OrganizationClassification() organization.Classification {
	if !o.Valid() {
		return ""
	}
	return o.organizationClassification
}

// OrganizationLifecycle returns the lifecycle observed from the current
// NormalOrganization record.
func (o *CurrentHumanAuthorityObservation) OrganizationLifecycle() organization.Lifecycle {
	if !o.Valid() {
		return ""
	}
	return o.organizationLifecycle
}

// Construct loads current durable state for the authenticated human in ctx and
// constructs ordinary Organization-operational authority. Every call performs
// fresh session, User, assignment, and NormalOrganization reads. It neither
// caches results nor implements the later Complete Operation Guard.
func (c *CurrentHumanAuthorityConstructor) Construct(ctx context.Context) (CurrentHumanAuthority, error) {
	var zero CurrentHumanAuthority
	if c == nil || nilCurrentAuthorityDependency(c.sessions) || nilCurrentAuthorityDependency(c.users) || nilCurrentAuthorityDependency(c.organizations) {
		return zero, ErrInvalidCurrentHumanAuthorityConstructor
	}
	if ctx == nil {
		return zero, currentHumanAuthorityFailure("operation context is required")
	}
	if err := ctx.Err(); err != nil {
		return zero, currentHumanAuthorityLookupFailure("operation context is not current", err)
	}

	source := permission.Source(ctx)
	if source == nil || source.Type != permission.SourceTypeAuthProvider {
		return zero, currentHumanAuthorityFailure("authenticated human session source is required")
	}
	sessionID, ok := parseCanonicalAuthorityUUID(source.ID)
	if !ok {
		return zero, currentHumanAuthorityFailure("authenticated session identity is invalid")
	}
	authenticatedUserID, ok := parseCanonicalAuthorityUUID(permission.UserID(ctx))
	if !ok {
		return zero, currentHumanAuthorityFailure("authenticated global User identity is invalid")
	}

	session, err := c.sessions.FindCurrentUserSession(ctx, sessionID)
	if err != nil {
		return zero, currentHumanAuthorityLookupFailure("read current authenticated session", err)
	}
	if session == nil || session.ID != sessionID || session.UserID == uuid.Nil || session.UserID != authenticatedUserID {
		return zero, currentHumanAuthorityFailure("current session state is inconsistent")
	}

	currentUser, err := c.users.FindOne(ctx, authenticatedUserID.String())
	if err != nil {
		return zero, currentHumanAuthorityLookupFailure("read current global User", err)
	}
	if currentUser == nil {
		return zero, currentHumanAuthorityFailure("current global User is missing")
	}
	loadedUserID, ok := parseCanonicalAuthorityUUID(currentUser.ID)
	if !ok || loadedUserID != authenticatedUserID {
		return zero, currentHumanAuthorityFailure("current global User state is inconsistent")
	}
	if _, err := currentUser.Normalize(); err != nil {
		return zero, currentHumanAuthorityLookupFailure("validate current global User", err)
	}
	if currentUser.Role != session.UserRole {
		return zero, currentHumanAuthorityFailure("current session and global User roles are inconsistent")
	}
	if currentUser.Role != permission.RoleUser && currentUser.Role != permission.RoleAdmin {
		return zero, currentHumanAuthorityFailure("current global User role is invalid")
	}

	assignment, err := c.organizations.FindUserOrganizationAssignment(ctx, authenticatedUserID)
	if err != nil {
		return zero, currentHumanAuthorityLookupFailure("read current UserOrganizationAssignment", err)
	}
	if !validCurrentOrdinaryAssignment(assignment, authenticatedUserID) {
		return zero, currentHumanAuthorityFailure("current UserOrganizationAssignment is not Organization-operational")
	}

	normal, err := c.organizations.FindNormalByID(ctx, assignment.EffectiveOrganizationID)
	if err != nil {
		return zero, currentHumanAuthorityLookupFailure("read current effective NormalOrganization", err)
	}
	if !validCurrentNormalOrganization(normal, assignment.EffectiveOrganizationID) ||
		assignment.EffectiveOrganizationClassification != normal.Classification {
		return zero, currentHumanAuthorityFailure("current assignment and Organization state is inconsistent")
	}

	generation := assignment.AssignmentGeneration
	effectiveOrganizationID := assignment.EffectiveOrganizationID
	typedContext, err := newExecutionContext(executionContextSpec{
		principalKind:            PrincipalKindHuman,
		principalID:              currentUser.ID,
		actualActorID:            currentUser.ID,
		authenticationSourceType: source.Type.String(),
		authenticationSourceID:   source.ID,
		organizationRole:         assignment.Role,
		platformAdmin:            false,
		authorityMode:            AuthorityModeOrganizationScoped,
		effectiveOrganizationID:  &effectiveOrganizationID,
		assignmentGeneration:     &generation,
	})
	if err != nil || !EligibleForOrganizationBusinessScope(&typedContext, effectiveOrganizationID) {
		if err == nil {
			err = errInvalidExecutionContext
		}
		return zero, currentHumanAuthorityLookupFailure("construct typed ExecutionContext", err)
	}

	observation := CurrentHumanAuthorityObservation{
		valid:                      true,
		sessionCurrent:             true,
		sessionID:                  sessionID,
		userID:                     authenticatedUserID,
		globalUserRole:             currentUser.Role,
		assignmentUserID:           assignment.UserID,
		assignmentState:            assignment.State,
		mappingOutcome:             assignment.MappingOutcome,
		effectiveOrganizationID:    assignment.EffectiveOrganizationID,
		organizationRole:           assignment.Role,
		assignmentGeneration:       assignment.AssignmentGeneration,
		organizationClassification: normal.Classification,
		organizationLifecycle:      normal.Lifecycle,
	}
	result := CurrentHumanAuthority{
		valid:       true,
		context:     typedContext,
		observation: observation,
	}
	if !result.Valid() {
		return zero, currentHumanAuthorityFailure("constructed authority is incomplete")
	}
	return result, nil
}

func validCurrentOrdinaryAssignment(value *organization.UserOrganizationAssignment, userID uuid.UUID) bool {
	if value == nil || userID == uuid.Nil || value.UserID != userID || value.AssignmentGeneration <= 0 ||
		value.State != organization.AssignmentStateActive ||
		value.MappingOutcome != organization.MappingOutcomeExactlyOne ||
		value.EffectiveOrganizationID == uuid.Nil ||
		value.EffectiveOrganizationID.String() == organization.DefaultOrganizationID ||
		value.EffectiveOrganizationClassification != organization.ClassificationNormal ||
		(value.Role != organization.OrganizationRoleMember && value.Role != organization.OrganizationRoleAdmin) ||
		value.Evaluation.MatchedCount != 1 || value.Evaluation.AuthoritativeEvaluatedAt.IsZero() ||
		!validAuthorityEvidenceIdentity(value.Evaluation.SourceConfigVersion) ||
		value.Evaluation.EvidenceDigest == (organization.EvidenceDigest{}) ||
		value.PendingTransferID != nil {
		return false
	}
	return true
}

func validCurrentNormalOrganization(value *organization.NormalOrganization, expectedID uuid.UUID) bool {
	if value == nil || expectedID == uuid.Nil || value.ID != expectedID ||
		value.ID.String() == organization.DefaultOrganizationID ||
		value.Classification != organization.ClassificationNormal ||
		value.Lifecycle != organization.LifecycleActive ||
		strings.TrimSpace(value.DisplayName) == "" ||
		!validAuthorityEvidenceIdentity(value.CanonicalName) ||
		!validAuthorityEvidenceIdentity(value.CorporateMappingKey) ||
		strings.TrimSpace(value.TimeZone) == "" || coretimezone.CanonicalZone(value.TimeZone) != value.TimeZone ||
		value.CreatedAt.IsZero() || value.UpdatedAt.IsZero() || value.UpdatedAt.Before(value.CreatedAt) {
		return false
	}
	return true
}

func validAuthorityEvidenceIdentity(value string) bool {
	return value != "" && utf8.ValidString(value) && strings.IndexByte(value, 0) < 0 && strings.TrimSpace(value) == value
}

func parseCanonicalAuthorityUUID(value string) (uuid.UUID, bool) {
	id, err := uuid.Parse(value)
	return id, err == nil && id != uuid.Nil && id.String() == value
}

func nilCurrentAuthorityDependency(value any) bool {
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

func currentHumanAuthorityFailure(reason string) error {
	return fmt.Errorf("%w: %s", ErrCurrentHumanAuthorityUnavailable, reason)
}

func currentHumanAuthorityLookupFailure(operation string, err error) error {
	if err == nil {
		return currentHumanAuthorityFailure(operation)
	}
	return fmt.Errorf("%w: %s: %w", ErrCurrentHumanAuthorityUnavailable, operation, err)
}

var (
	_ currentHumanSessionReader      = (*auth.Handler)(nil)
	_ currentHumanUserReader         = (*user.Store)(nil)
	_ currentHumanOrganizationReader = (*organization.Store)(nil)
)
