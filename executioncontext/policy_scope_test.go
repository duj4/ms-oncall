package executioncontext

import (
	"testing"

	"github.com/google/uuid"
	"github.com/target/goalert/organization"
)

var (
	policyTestOrganizationID      = uuid.MustParse("1cfe9987-4003-47cc-8862-c8235912e7af")
	policyTestOtherOrganizationID = uuid.MustParse("43a00ee2-c251-49af-a742-9bf22a723936")
)

func TestPolicyScopeEligibilityFailsClosed(t *testing.T) {
	for _, context := range []*ExecutionContext{nil, {}} {
		if EligibleForOrganizationBusinessScope(context, policyTestOrganizationID) || EligibleForPlatformGlobalScope(context) {
			t.Fatalf("invalid context is policy-scope eligible: %#v", context)
		}
	}
}

func TestOrganizationBusinessScopeEligibilityRequiresExactNormalTarget(t *testing.T) {
	context := mustPolicyTestContext(t, organizationScopedTestSpec(
		PrincipalKindHuman,
		organization.OrganizationRoleMember,
		false,
		policyTestOrganizationID,
	))
	defaultID := uuid.MustParse(organization.DefaultOrganizationID)
	tests := []struct {
		name   string
		target uuid.UUID
		want   bool
	}{
		{name: "exact normal scope match", target: policyTestOrganizationID, want: true},
		{name: "scope mismatch", target: policyTestOtherOrganizationID},
		{name: "zero target", target: uuid.Nil},
		{name: "distinguished Default target", target: defaultID},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := EligibleForOrganizationBusinessScope(context, test.target); got != test.want {
				t.Fatalf("EligibleForOrganizationBusinessScope = %t, want %t", got, test.want)
			}
		})
	}
	if EligibleForPlatformGlobalScope(context) {
		t.Fatal("ORG_SCOPED context is eligible for platform-global scope")
	}
}

func TestPolicyScopeEligibilitySeparatesAuthorityModes(t *testing.T) {
	organizationContext := mustPolicyTestContext(t, organizationScopedTestSpec(
		PrincipalKindIntegration,
		organization.OrganizationRoleNone,
		false,
		policyTestOrganizationID,
	))
	defaultContext := mustPolicyTestContext(t, structuralTestSpec(
		PrincipalKindHuman,
		AuthorityModeDefaultRestricted,
		organization.OrganizationRoleNone,
		false,
	))
	platformContext := mustPolicyTestContext(t, structuralTestSpec(
		PrincipalKindHuman,
		AuthorityModePlatformGlobal,
		organization.OrganizationRoleNone,
		true,
	))

	if !EligibleForOrganizationBusinessScope(organizationContext, policyTestOrganizationID) || EligibleForPlatformGlobalScope(organizationContext) {
		t.Fatal("Organization-scoped context has incorrect policy eligibility")
	}
	if EligibleForOrganizationBusinessScope(defaultContext, policyTestOrganizationID) || EligibleForPlatformGlobalScope(defaultContext) {
		t.Fatal("Default-restricted context has policy eligibility")
	}
	if EligibleForOrganizationBusinessScope(platformContext, policyTestOrganizationID) || !EligibleForPlatformGlobalScope(platformContext) {
		t.Fatal("platform-global context has incorrect policy eligibility")
	}
}

func mustPolicyTestContext(t *testing.T, spec executionContextSpec) *ExecutionContext {
	t.Helper()
	context, err := newExecutionContext(spec)
	if err != nil {
		t.Fatalf("newExecutionContext: %v", err)
	}
	return &context
}
