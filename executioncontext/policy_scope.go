package executioncontext

import (
	"github.com/google/uuid"
	"github.com/target/goalert/organization"
)

// EligibleForOrganizationBusinessScope reports whether context structurally
// satisfies the policy-scope preconditions for evaluating a target normal
// Organization. A true result is not an authorization decision and grants no
// business capability.
func EligibleForOrganizationBusinessScope(context *ExecutionContext, targetOrganizationID uuid.UUID) bool {
	if !context.Valid() || context.AuthorityMode() != AuthorityModeOrganizationScoped || targetOrganizationID == uuid.Nil {
		return false
	}

	defaultOrganizationID, err := uuid.Parse(organization.DefaultOrganizationID)
	if err != nil || defaultOrganizationID == uuid.Nil || targetOrganizationID == defaultOrganizationID {
		return false
	}

	effectiveOrganizationID, present := context.EffectiveOrganizationID()
	return present &&
		effectiveOrganizationID != uuid.Nil &&
		effectiveOrganizationID != defaultOrganizationID &&
		effectiveOrganizationID == targetOrganizationID
}

// EligibleForPlatformGlobalScope reports whether context structurally
// satisfies the policy-scope precondition for the platform-global evaluation
// domain. A true result is not an authorization decision and grants no
// platform-global capability.
func EligibleForPlatformGlobalScope(context *ExecutionContext) bool {
	return context.Valid() && context.AuthorityMode() == AuthorityModePlatformGlobal
}
