package executioncontext

import (
	"errors"
	"reflect"
	"testing"

	"github.com/google/uuid"
	"github.com/target/goalert/organization"
)

func structuralTestSpec(kind PrincipalKind, mode AuthorityMode, role organization.OrganizationRole, platformAdmin bool) executionContextSpec {
	return executionContextSpec{
		principalKind:            kind,
		principalID:              "principal:stable",
		actualActorID:            "actor:stable",
		authenticationSourceType: "source-type:stable",
		authenticationSourceID:   "source-id:stable",
		organizationRole:         role,
		platformAdmin:            platformAdmin,
		authorityMode:            mode,
	}
}

func organizationScopedTestSpec(kind PrincipalKind, role organization.OrganizationRole, platformAdmin bool, id uuid.UUID) executionContextSpec {
	spec := structuralTestSpec(kind, AuthorityModeOrganizationScoped, role, platformAdmin)
	spec.effectiveOrganizationID = pointerTo(id)
	return spec
}

func TestExecutionContextAcceptsStructuralPrincipalMatrix(t *testing.T) {
	normalID := uuid.MustParse("d0142ff4-8d87-45ce-bce7-e12a8e814d38")
	tests := []struct {
		name string
		spec executionContextSpec
	}{
		{name: "human member", spec: organizationScopedTestSpec(PrincipalKindHuman, organization.OrganizationRoleMember, false, normalID)},
		{name: "human Organization admin", spec: organizationScopedTestSpec(PrincipalKindHuman, organization.OrganizationRoleAdmin, false, normalID)},
		{name: "human Default restricted", spec: structuralTestSpec(PrincipalKindHuman, AuthorityModeDefaultRestricted, organization.OrganizationRoleNone, false)},
		{name: "human platform global", spec: structuralTestSpec(PrincipalKindHuman, AuthorityModePlatformGlobal, organization.OrganizationRoleNone, true)},
		{name: "integration", spec: organizationScopedTestSpec(PrincipalKindIntegration, organization.OrganizationRoleNone, false, normalID)},
		{name: "Organization system", spec: organizationScopedTestSpec(PrincipalKindOrganizationSystem, organization.OrganizationRoleNone, false, normalID)},
		{name: "Organization machine", spec: organizationScopedTestSpec(PrincipalKindMachine, organization.OrganizationRoleNone, false, normalID)},
		{name: "platform machine", spec: structuralTestSpec(PrincipalKindMachine, AuthorityModePlatformGlobal, organization.OrganizationRoleNone, false)},
		{name: "platform system", spec: structuralTestSpec(PrincipalKindPlatformSystem, AuthorityModePlatformGlobal, organization.OrganizationRoleNone, false)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := newExecutionContext(test.spec)
			if err != nil || !got.Valid() {
				t.Fatalf("newExecutionContext = (%#v, %v), want valid", got, err)
			}
			if got.PrincipalKind() != test.spec.principalKind || got.PrincipalID() != test.spec.principalID ||
				got.ActualActorID() != test.spec.actualActorID || got.AuthorityMode() != test.spec.authorityMode {
				t.Fatalf("unexpected ExecutionContext accessors: %#v", got)
			}
			if source := got.AuthenticationSource(); source == nil || source.Type() != test.spec.authenticationSourceType || source.ID() != test.spec.authenticationSourceID {
				t.Fatalf("AuthenticationSource = %#v", source)
			}
			if privileges := got.Privileges(); privileges == nil || privileges.OrganizationRole() != test.spec.organizationRole || privileges.PlatformAdmin() != test.spec.platformAdmin {
				t.Fatalf("Privileges = %#v", privileges)
			}
			organizationID, present := got.EffectiveOrganizationID()
			if test.spec.authorityMode == AuthorityModeOrganizationScoped {
				if !present || organizationID != normalID {
					t.Fatalf("EffectiveOrganizationID = (%s, %t), want (%s, true)", organizationID, present, normalID)
				}
			} else if present || organizationID != uuid.Nil {
				t.Fatalf("EffectiveOrganizationID = (%s, %t), want absent", organizationID, present)
			}
		})
	}
}

func TestExecutionContextRejectsContradictoryStructure(t *testing.T) {
	normalID := uuid.MustParse("88a2a739-cd62-4278-b520-2d98f67631d5")
	defaultID := uuid.MustParse(organization.DefaultOrganizationID)
	valid := organizationScopedTestSpec(PrincipalKindHuman, organization.OrganizationRoleMember, false, normalID)
	tests := []struct {
		name   string
		mutate func(*executionContextSpec)
	}{
		{name: "unknown principal", mutate: func(v *executionContextSpec) { v.principalKind = "UNKNOWN" }},
		{name: "empty principal ID", mutate: func(v *executionContextSpec) { v.principalID = "" }},
		{name: "invalid actor UTF-8", mutate: func(v *executionContextSpec) { v.actualActorID = string([]byte{0xff}) }},
		{name: "source contains NUL", mutate: func(v *executionContextSpec) { v.authenticationSourceID = "bad\x00source" }},
		{name: "unknown role", mutate: func(v *executionContextSpec) { v.organizationRole = "OWNER" }},
		{name: "unknown authority mode", mutate: func(v *executionContextSpec) { v.authorityMode = "UNKNOWN" }},
		{name: "missing Organization scope", mutate: func(v *executionContextSpec) { v.effectiveOrganizationID = nil }},
		{name: "nil Organization scope", mutate: func(v *executionContextSpec) { v.effectiveOrganizationID = pointerTo(uuid.Nil) }},
		{name: "Default used as Organization scope", mutate: func(v *executionContextSpec) { v.effectiveOrganizationID = &defaultID }},
		{name: "human NONE role Organization scope", mutate: func(v *executionContextSpec) { v.organizationRole = organization.OrganizationRoleNone }},
		{name: "human PlatformAdmin Organization scope", mutate: func(v *executionContextSpec) { v.platformAdmin = true }},
		{name: "effective Organization in Default mode", mutate: func(v *executionContextSpec) { v.authorityMode = AuthorityModeDefaultRestricted }},
		{name: "effective Organization in platform mode", mutate: func(v *executionContextSpec) {
			v.authorityMode = AuthorityModePlatformGlobal
			v.organizationRole = organization.OrganizationRoleNone
			v.platformAdmin = true
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			spec := valid
			test.mutate(&spec)
			got, err := newExecutionContext(spec)
			if !errors.Is(err, errInvalidExecutionContext) || got.Valid() {
				t.Fatalf("newExecutionContext = (%#v, %v), want invalid", got, err)
			}
		})
	}

	invalidCombinations := []executionContextSpec{
		structuralTestSpec(PrincipalKindHuman, AuthorityModePlatformGlobal, organization.OrganizationRoleNone, false),
		structuralTestSpec(PrincipalKindIntegration, AuthorityModePlatformGlobal, organization.OrganizationRoleNone, false),
		structuralTestSpec(PrincipalKindPlatformSystem, AuthorityModeDefaultRestricted, organization.OrganizationRoleNone, false),
		organizationScopedTestSpec(PrincipalKindMachine, organization.OrganizationRoleMember, false, normalID),
		organizationScopedTestSpec(PrincipalKindIntegration, organization.OrganizationRoleNone, true, normalID),
	}
	for index, spec := range invalidCombinations {
		got, err := newExecutionContext(spec)
		if !errors.Is(err, errInvalidExecutionContext) || got.Valid() {
			t.Fatalf("invalid combination %d = (%#v, %v), want invalid", index, got, err)
		}
	}
}

func TestExecutionContextZeroAndNilValuesExposeNoAuthority(t *testing.T) {
	for _, context := range []*ExecutionContext{nil, {}} {
		if context.Valid() || context.PrincipalKind() != "" || context.PrincipalID() != "" || context.ActualActorID() != "" ||
			context.AuthenticationSource() != nil || context.Privileges() != nil || context.AuthorityMode() != "" {
			t.Fatalf("invalid context exposed authority: %#v", context)
		}
		if id, present := context.EffectiveOrganizationID(); present || id != uuid.Nil {
			t.Fatalf("invalid context Organization = (%s, %t)", id, present)
		}
	}
	var source *AuthenticationSource
	var privileges *PrivilegeMetadata
	if source.Type() != "" || source.ID() != "" || privileges.OrganizationRole() != "" || privileges.PlatformAdmin() {
		t.Fatal("nil evidence values exposed metadata")
	}
}

func TestExecutionContextIsImmutableByValue(t *testing.T) {
	organizationID := uuid.MustParse("0e6cbaef-7f9a-4bf5-bcae-c0c1363204b1")
	spec := organizationScopedTestSpec(PrincipalKindHuman, organization.OrganizationRoleMember, false, organizationID)
	spec.authenticationSourceID = "source:original"
	got, err := newExecutionContext(spec)
	if err != nil {
		t.Fatal(err)
	}
	original := got
	organizationID = uuid.New()
	spec.principalID = "principal:changed"
	spec.authenticationSourceID = "source:changed"
	if !reflect.DeepEqual(got, original) {
		t.Fatalf("ExecutionContext changed after input mutation: %#v", got)
	}
	returnedSource := got.AuthenticationSource()
	returnedPrivileges := got.Privileges()
	returnedSource.sourceID = "source:returned-copy-changed"
	returnedPrivileges.organizationRole = organization.OrganizationRoleAdmin
	if got.AuthenticationSource().ID() != "source:original" || got.Privileges().OrganizationRole() != organization.OrganizationRoleMember {
		t.Fatal("returned metadata copy mutated ExecutionContext")
	}
}

func pointerTo[T any](value T) *T { return &value }
