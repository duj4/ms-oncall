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
	invalidSpec := structuralTestSpec(
		PrincipalKindHuman,
		AuthorityModeOrganizationScoped,
		organization.OrganizationRoleMember,
		false,
		false,
	)
	invalidSpec.effectiveOrganizationID = pointerTo(uuid.Nil)
	invalidContext, err := newExecutionContext(invalidSpec)
	if err == nil {
		t.Fatal("newExecutionContext error = nil, want invalid context")
	}

	tests := []struct {
		name    string
		context *ExecutionContext
	}{
		{name: "nil", context: nil},
		{name: "zero", context: &ExecutionContext{}},
		{name: "rejected construction", context: &invalidContext},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			defer func() {
				if recovered := recover(); recovered != nil {
					t.Fatalf("scope eligibility panicked: %v", recovered)
				}
			}()
			if EligibleForOrganizationBusinessScope(test.context, policyTestOrganizationID) {
				t.Fatal("invalid context is eligible for Organization-business scope")
			}
			if EligibleForPlatformGlobalScope(test.context) {
				t.Fatal("invalid context is eligible for platform-global scope")
			}
		})
	}
}

func TestOrganizationBusinessScopeEligibilityRequiresExactNormalTarget(t *testing.T) {
	context := mustPolicyTestContext(t, organizationScopedPolicyTestSpec(
		PrincipalKindHuman,
		organization.OrganizationRoleMember,
		false,
		false,
		policyTestOrganizationID,
	))
	defaultOrganizationID := uuid.MustParse(organization.DefaultOrganizationID)

	tests := []struct {
		name   string
		target uuid.UUID
		want   bool
	}{
		{name: "exact normal scope match", target: policyTestOrganizationID, want: true},
		{name: "scope mismatch", target: policyTestOtherOrganizationID},
		{name: "zero target", target: uuid.Nil},
		{name: "distinguished Default target", target: defaultOrganizationID},
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
	tests := []struct {
		name                     string
		spec                     executionContextSpec
		wantOrganizationBusiness bool
		wantPlatformGlobal       bool
	}{
		{
			name: "Organization scoped",
			spec: organizationScopedPolicyTestSpec(
				PrincipalKindHuman,
				organization.OrganizationRoleMember,
				false,
				false,
				policyTestOrganizationID,
			),
			wantOrganizationBusiness: true,
		},
		{
			name: "Default restricted",
			spec: structuralTestSpec(
				PrincipalKindHuman,
				AuthorityModeDefaultRestricted,
				organization.OrganizationRoleNone,
				false,
				false,
			),
		},
		{
			name: "Default restricted with inert PlatformAdmin metadata",
			spec: structuralTestSpec(
				PrincipalKindHuman,
				AuthorityModeDefaultRestricted,
				organization.OrganizationRoleNone,
				true,
				false,
			),
		},
		{
			name: "Platform global human",
			spec: structuralTestSpec(
				PrincipalKindHuman,
				AuthorityModePlatformGlobal,
				organization.OrganizationRoleNone,
				true,
				false,
			),
			wantPlatformGlobal: true,
		},
		{
			name: "Platform global system",
			spec: structuralTestSpec(
				PrincipalKindPlatformSystem,
				AuthorityModePlatformGlobal,
				organization.OrganizationRoleNone,
				false,
				false,
			),
			wantPlatformGlobal: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			context := mustPolicyTestContext(t, test.spec)
			if got := EligibleForOrganizationBusinessScope(context, policyTestOrganizationID); got != test.wantOrganizationBusiness {
				t.Fatalf("Organization-business eligibility = %t, want %t", got, test.wantOrganizationBusiness)
			}
			if got := EligibleForPlatformGlobalScope(context); got != test.wantPlatformGlobal {
				t.Fatalf("platform-global eligibility = %t, want %t", got, test.wantPlatformGlobal)
			}
		})
	}
}

func TestPlatformAdminMetadataDoesNotBypassOrganizationScope(t *testing.T) {
	globalContext := mustPolicyTestContext(t, structuralTestSpec(
		PrincipalKindHuman,
		AuthorityModePlatformGlobal,
		organization.OrganizationRoleNone,
		true,
		false,
	))
	if EligibleForOrganizationBusinessScope(globalContext, policyTestOrganizationID) {
		t.Fatal("PLATFORM_GLOBAL PlatformAdmin context bypassed Organization scope")
	}
	if !EligibleForPlatformGlobalScope(globalContext) {
		t.Fatal("valid PLATFORM_GLOBAL context is not eligible for its evaluation domain")
	}

	assumedContext := mustPolicyTestContext(t, organizationScopedPolicyTestSpec(
		PrincipalKindHuman,
		organization.OrganizationRoleNone,
		true,
		true,
		policyTestOrganizationID,
	))
	if !EligibleForOrganizationBusinessScope(assumedContext, policyTestOrganizationID) {
		t.Fatal("assumed ORG_SCOPED context is not eligible for its exact Organization scope")
	}
	if EligibleForOrganizationBusinessScope(assumedContext, policyTestOtherOrganizationID) {
		t.Fatal("PlatformAdmin assumption evidence bypassed an Organization scope mismatch")
	}
	if EligibleForPlatformGlobalScope(assumedContext) {
		t.Fatal("ORG_SCOPED assumption evidence created platform-global eligibility")
	}
}

func TestOrganizationScopeEligibilityIsRoleAndPrincipalIndependent(t *testing.T) {
	tests := []struct {
		name          string
		principalKind PrincipalKind
		role          organization.OrganizationRole
		platformAdmin bool
		assumption    bool
	}{
		{name: "human member", principalKind: PrincipalKindHuman, role: organization.OrganizationRoleMember},
		{name: "human admin", principalKind: PrincipalKindHuman, role: organization.OrganizationRoleAdmin},
		{name: "human PlatformAdmin assumption", principalKind: PrincipalKindHuman, role: organization.OrganizationRoleNone, platformAdmin: true, assumption: true},
		{name: "integration role none", principalKind: PrincipalKindIntegration, role: organization.OrganizationRoleNone},
		{name: "Organization system role none", principalKind: PrincipalKindOrganizationSystem, role: organization.OrganizationRoleNone},
		{name: "machine role none", principalKind: PrincipalKindMachine, role: organization.OrganizationRoleNone},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			context := mustPolicyTestContext(t, organizationScopedPolicyTestSpec(
				test.principalKind,
				test.role,
				test.platformAdmin,
				test.assumption,
				policyTestOrganizationID,
			))
			if !EligibleForOrganizationBusinessScope(context, policyTestOrganizationID) {
				t.Fatal("exact Organization scope is ineligible because of role or principal metadata")
			}
			if EligibleForOrganizationBusinessScope(context, policyTestOtherOrganizationID) {
				t.Fatal("role or principal metadata bypassed an Organization scope mismatch")
			}
			if EligibleForPlatformGlobalScope(context) {
				t.Fatal("ORG_SCOPED principal is eligible for platform-global scope")
			}
		})
	}
}

func TestPolicyScopeEligibilityTreatsGenerationAndAssumptionEvidenceAsInert(t *testing.T) {
	withoutGeneration := organizationScopedPolicyTestSpec(
		PrincipalKindHuman,
		organization.OrganizationRoleMember,
		false,
		false,
		policyTestOrganizationID,
	)
	withGeneration := withoutGeneration
	withGeneration.assignmentGeneration = pointerTo(int64(37))

	for _, spec := range []executionContextSpec{withoutGeneration, withGeneration} {
		context := mustPolicyTestContext(t, spec)
		if !EligibleForOrganizationBusinessScope(context, policyTestOrganizationID) {
			t.Fatal("assignment-generation evidence changed exact-match eligibility")
		}
		if EligibleForOrganizationBusinessScope(context, policyTestOtherOrganizationID) {
			t.Fatal("assignment-generation evidence created a cross-Organization match")
		}
		if EligibleForPlatformGlobalScope(context) {
			t.Fatal("assignment-generation evidence created platform-global eligibility")
		}
	}

	defaultRestrictedWithGeneration := structuralTestSpec(
		PrincipalKindHuman,
		AuthorityModeDefaultRestricted,
		organization.OrganizationRoleNone,
		false,
		false,
	)
	defaultRestrictedWithGeneration.assignmentGeneration = pointerTo(int64(41))
	defaultRestrictedContext := mustPolicyTestContext(t, defaultRestrictedWithGeneration)
	if EligibleForOrganizationBusinessScope(defaultRestrictedContext, policyTestOrganizationID) {
		t.Fatal("assignment-generation evidence created Organization-business eligibility")
	}
	if EligibleForPlatformGlobalScope(defaultRestrictedContext) {
		t.Fatal("assignment-generation evidence created platform-global eligibility")
	}

	assumedContext := mustPolicyTestContext(t, organizationScopedPolicyTestSpec(
		PrincipalKindHuman,
		organization.OrganizationRoleNone,
		true,
		true,
		policyTestOrganizationID,
	))
	if EligibleForOrganizationBusinessScope(assumedContext, policyTestOtherOrganizationID) {
		t.Fatal("assumption evidence created a cross-Organization match")
	}
}

func organizationScopedPolicyTestSpec(
	principalKind PrincipalKind,
	role organization.OrganizationRole,
	platformAdmin bool,
	assumption bool,
	organizationID uuid.UUID,
) executionContextSpec {
	spec := structuralTestSpec(
		principalKind,
		AuthorityModeOrganizationScoped,
		role,
		platformAdmin,
		assumption,
	)
	spec.effectiveOrganizationID = pointerTo(organizationID)
	return spec
}

func mustPolicyTestContext(t *testing.T, spec executionContextSpec) *ExecutionContext {
	t.Helper()
	context, err := newExecutionContext(spec)
	if err != nil {
		t.Fatalf("newExecutionContext: %v", err)
	}
	return &context
}
