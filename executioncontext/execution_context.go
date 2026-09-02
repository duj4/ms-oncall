// Package executioncontext defines the inert, immutable trust-context value
// contract used by later, separately authorized identity foundations.
//
// This package does not authenticate, authorize, install values in a
// context.Context, or provide any runtime construction path.
package executioncontext

import (
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/target/goalert/organization"
)

var errInvalidExecutionContext = errors.New("invalid ExecutionContext")

// PrincipalKind identifies the kind of authenticated principal represented by
// an ExecutionContext. Its zero value and unknown values are invalid.
type PrincipalKind string

const (
	// PrincipalKindHuman identifies a human principal.
	PrincipalKindHuman PrincipalKind = "HUMAN"
	// PrincipalKindIntegration identifies an integration principal.
	PrincipalKindIntegration PrincipalKind = "INTEGRATION"
	// PrincipalKindOrganizationSystem identifies an Organization-local system principal.
	PrincipalKindOrganizationSystem PrincipalKind = "ORG_SYSTEM"
	// PrincipalKindMachine identifies a machine principal.
	PrincipalKindMachine PrincipalKind = "MACHINE"
	// PrincipalKindPlatformSystem identifies a platform system principal.
	PrincipalKindPlatformSystem PrincipalKind = "PLATFORM_SYSTEM"
)

// AuthorityMode identifies the structural authority scope represented by an
// ExecutionContext. Its zero value and unknown values are invalid.
type AuthorityMode string

const (
	// AuthorityModeOrganizationScoped requires one non-Default effective Organization.
	AuthorityModeOrganizationScoped AuthorityMode = "ORG_SCOPED"
	// AuthorityModeDefaultRestricted carries no effective Organization authority.
	AuthorityModeDefaultRestricted AuthorityMode = "DEFAULT_RESTRICTED"
	// AuthorityModePlatformGlobal carries no effective Organization identity.
	AuthorityModePlatformGlobal AuthorityMode = "PLATFORM_GLOBAL"
)

// AuthenticationSource is immutable structural evidence identifying the kind
// and stable identity of the authentication source. It does not validate a
// credential or authenticate a request.
type AuthenticationSource struct {
	sourceType string
	sourceID   string
}

// Type returns the authentication-source type exactly as supplied by the
// private trusted construction seam. The zero value returns an empty string.
func (s AuthenticationSource) Type() string { return s.sourceType }

// ID returns the authentication-source identity exactly as supplied by the
// private trusted construction seam. The zero value returns an empty string.
func (s AuthenticationSource) ID() string { return s.sourceID }

// PrivilegeMetadata is immutable coarse privilege evidence. It deliberately
// provides no capability catalog, evaluator, or authorization decision.
type PrivilegeMetadata struct {
	organizationRole organization.OrganizationRole
	platformAdmin    bool
}

// OrganizationRole returns the accepted coarse Organization role metadata.
// The zero value returns the zero, invalid Organization role.
func (p PrivilegeMetadata) OrganizationRole() organization.OrganizationRole {
	return p.organizationRole
}

// PlatformAdmin reports the structural PlatformAdmin privilege marker. It
// makes no authorization decision and grants no behavior.
func (p PrivilegeMetadata) PlatformAdmin() bool { return p.platformAdmin }

// ExecutionContext is an immutable value carrying validated identity and
// authority-mode evidence. All trust-bearing fields are private, the zero value
// is invalid, and this checkpoint intentionally exposes no public constructor.
type ExecutionContext struct {
	valid                      bool
	principalKind              PrincipalKind
	principalID                string
	actualActorID              string
	authenticationSource       AuthenticationSource
	privileges                 PrivilegeMetadata
	authorityMode              AuthorityMode
	effectiveOrganizationID    uuid.UUID
	hasEffectiveOrganization   bool
	assignmentGeneration       int64
	hasAssignmentGeneration    bool
	platformAdminAssumptionID  string
	hasPlatformAdminAssumption bool
}

// Valid reports whether the value was completely validated by the private
// trusted construction seam. The zero value is invalid and carries no trusted
// authority.
func (c ExecutionContext) Valid() bool { return c.valid }

// PrincipalKind returns the validated principal kind, or its invalid zero
// value when the ExecutionContext is invalid.
func (c ExecutionContext) PrincipalKind() PrincipalKind {
	if !c.valid {
		return ""
	}
	return c.principalKind
}

// PrincipalID returns the stable principal identity exactly as supplied, or an
// empty string when the ExecutionContext is invalid.
func (c ExecutionContext) PrincipalID() string {
	if !c.valid {
		return ""
	}
	return c.principalID
}

// ActualActorID returns the stable actual-actor identity exactly as supplied,
// or an empty string when the ExecutionContext is invalid.
func (c ExecutionContext) ActualActorID() string {
	if !c.valid {
		return ""
	}
	return c.actualActorID
}

// AuthenticationSource returns immutable authentication-source evidence. An
// invalid ExecutionContext returns the zero AuthenticationSource.
func (c ExecutionContext) AuthenticationSource() AuthenticationSource {
	if !c.valid {
		return AuthenticationSource{}
	}
	return c.authenticationSource
}

// Privileges returns immutable coarse privilege metadata. An invalid
// ExecutionContext returns the zero PrivilegeMetadata.
func (c ExecutionContext) Privileges() PrivilegeMetadata {
	if !c.valid {
		return PrivilegeMetadata{}
	}
	return c.privileges
}

// AuthorityMode returns the validated authority mode, or its invalid zero
// value when the ExecutionContext is invalid.
func (c ExecutionContext) AuthorityMode() AuthorityMode {
	if !c.valid {
		return ""
	}
	return c.authorityMode
}

// EffectiveOrganizationID returns the effective Organization identity and
// true only for a valid ORG_SCOPED ExecutionContext.
func (c ExecutionContext) EffectiveOrganizationID() (uuid.UUID, bool) {
	if !c.valid || !c.hasEffectiveOrganization {
		return uuid.Nil, false
	}
	return c.effectiveOrganizationID, true
}

// AssignmentGeneration returns optional positive assignment-generation
// evidence. It does not load, compare, or enforce generation state.
func (c ExecutionContext) AssignmentGeneration() (int64, bool) {
	if !c.valid || !c.hasAssignmentGeneration {
		return 0, false
	}
	return c.assignmentGeneration, true
}

// PlatformAdminAssumptionID returns optional structurally validated assumption
// identity evidence. It does not create, validate, activate, or revoke an
// assumption.
func (c ExecutionContext) PlatformAdminAssumptionID() (string, bool) {
	if !c.valid || !c.hasPlatformAdminAssumption {
		return "", false
	}
	return c.platformAdminAssumptionID, true
}

// executionContextSpec is private because its fields carry trust declarations.
// Later checkpoints may add narrowly scoped trusted factories; this checkpoint
// deliberately provides no runtime producer.
type executionContextSpec struct {
	principalKind             PrincipalKind
	principalID               string
	actualActorID             string
	authenticationSourceType  string
	authenticationSourceID    string
	organizationRole          organization.OrganizationRole
	platformAdmin             bool
	authorityMode             AuthorityMode
	effectiveOrganizationID   *uuid.UUID
	assignmentGeneration      *int64
	platformAdminAssumptionID *string
}

// newExecutionContext is the package-private validation seam used by contract
// tests only. It returns the invalid zero value on every validation failure.
func newExecutionContext(spec executionContextSpec) (ExecutionContext, error) {
	var zero ExecutionContext

	if !validPrincipalKind(spec.principalKind) {
		return zero, invalidContextError("principal kind")
	}
	if err := validateStableIdentity(spec.principalID); err != nil {
		return zero, invalidContextError("principal identity")
	}
	if err := validateStableIdentity(spec.actualActorID); err != nil {
		return zero, invalidContextError("actual-actor identity")
	}
	if err := validateStableIdentity(spec.authenticationSourceType); err != nil {
		return zero, invalidContextError("authentication-source type")
	}
	if err := validateStableIdentity(spec.authenticationSourceID); err != nil {
		return zero, invalidContextError("authentication-source identity")
	}
	if !validOrganizationRole(spec.organizationRole) {
		return zero, invalidContextError("Organization role metadata")
	}
	if !validAuthorityMode(spec.authorityMode) {
		return zero, invalidContextError("authority mode")
	}

	var effectiveOrganizationID uuid.UUID
	hasEffectiveOrganization := spec.effectiveOrganizationID != nil
	if hasEffectiveOrganization {
		effectiveOrganizationID = *spec.effectiveOrganizationID
		if effectiveOrganizationID == uuid.Nil {
			return zero, invalidContextError("effective Organization identity")
		}
	}
	defaultOrganizationID, err := uuid.Parse(organization.DefaultOrganizationID)
	if err != nil || defaultOrganizationID == uuid.Nil {
		return zero, invalidContextError("distinguished Default Organization contract")
	}
	switch spec.authorityMode {
	case AuthorityModeOrganizationScoped:
		if !hasEffectiveOrganization || effectiveOrganizationID == defaultOrganizationID {
			return zero, invalidContextError("ORG_SCOPED effective Organization")
		}
	case AuthorityModeDefaultRestricted, AuthorityModePlatformGlobal:
		if hasEffectiveOrganization {
			return zero, invalidContextError("effective Organization is incompatible with authority mode")
		}
	}

	var assignmentGeneration int64
	hasAssignmentGeneration := spec.assignmentGeneration != nil
	if hasAssignmentGeneration {
		assignmentGeneration = *spec.assignmentGeneration
		if assignmentGeneration <= 0 {
			return zero, invalidContextError("assignment generation")
		}
	}

	var platformAdminAssumptionID string
	hasPlatformAdminAssumption := spec.platformAdminAssumptionID != nil
	if hasPlatformAdminAssumption {
		platformAdminAssumptionID = *spec.platformAdminAssumptionID
		if err := validateStableIdentity(platformAdminAssumptionID); err != nil {
			return zero, invalidContextError("PlatformAdmin assumption identity")
		}
	}

	return ExecutionContext{
		valid:         true,
		principalKind: spec.principalKind,
		principalID:   spec.principalID,
		actualActorID: spec.actualActorID,
		authenticationSource: AuthenticationSource{
			sourceType: spec.authenticationSourceType,
			sourceID:   spec.authenticationSourceID,
		},
		privileges: PrivilegeMetadata{
			organizationRole: spec.organizationRole,
			platformAdmin:    spec.platformAdmin,
		},
		authorityMode:              spec.authorityMode,
		effectiveOrganizationID:    effectiveOrganizationID,
		hasEffectiveOrganization:   hasEffectiveOrganization,
		assignmentGeneration:       assignmentGeneration,
		hasAssignmentGeneration:    hasAssignmentGeneration,
		platformAdminAssumptionID:  platformAdminAssumptionID,
		hasPlatformAdminAssumption: hasPlatformAdminAssumption,
	}, nil
}

func validPrincipalKind(value PrincipalKind) bool {
	switch value {
	case PrincipalKindHuman,
		PrincipalKindIntegration,
		PrincipalKindOrganizationSystem,
		PrincipalKindMachine,
		PrincipalKindPlatformSystem:
		return true
	default:
		return false
	}
}

func validAuthorityMode(value AuthorityMode) bool {
	switch value {
	case AuthorityModeOrganizationScoped,
		AuthorityModeDefaultRestricted,
		AuthorityModePlatformGlobal:
		return true
	default:
		return false
	}
}

func validOrganizationRole(value organization.OrganizationRole) bool {
	switch value {
	case organization.OrganizationRoleMember,
		organization.OrganizationRoleAdmin,
		organization.OrganizationRoleNone:
		return true
	default:
		return false
	}
}

func validateStableIdentity(value string) error {
	if value == "" {
		return errors.New("identity is empty")
	}
	if !utf8.ValidString(value) {
		return errors.New("identity is not valid UTF-8")
	}
	if strings.IndexByte(value, 0) >= 0 {
		return errors.New("identity contains U+0000")
	}
	return nil
}

func invalidContextError(field string) error {
	return fmt.Errorf("%w: invalid %s", errInvalidExecutionContext, field)
}
