package executioncontext

import (
	"bytes"
	"encoding/gob"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/google/uuid"
	"github.com/target/goalert/organization"
)

func validTestSpec() executionContextSpec {
	return executionContextSpec{
		principalKind:            PrincipalKindHuman,
		principalID:              "principal:Case-Sensitive",
		actualActorID:            "actor:distinct",
		authenticationSourceType: "session",
		authenticationSourceID:   "session:stable",
		organizationRole:         organization.OrganizationRoleNone,
		authorityMode:            AuthorityModeDefaultRestricted,
	}
}

func structuralTestSpec(kind PrincipalKind, mode AuthorityMode, role organization.OrganizationRole, platformAdmin, assumption bool) executionContextSpec {
	spec := validTestSpec()
	spec.principalKind = kind
	spec.authorityMode = mode
	spec.organizationRole = role
	spec.platformAdmin = platformAdmin
	if mode == AuthorityModeOrganizationScoped {
		spec.effectiveOrganizationID = pointerTo(uuid.MustParse("e0ff2a3f-a9f8-4cd5-904f-e6599965110e"))
	}
	if assumption {
		spec.platformAdminAssumptionID = pointerTo("assumption:structural")
	}
	return spec
}

func validTestSpecForPrincipal(kind PrincipalKind) executionContextSpec {
	switch kind {
	case PrincipalKindHuman:
		return structuralTestSpec(kind, AuthorityModeDefaultRestricted, organization.OrganizationRoleNone, false, false)
	case PrincipalKindIntegration, PrincipalKindOrganizationSystem, PrincipalKindMachine:
		return structuralTestSpec(kind, AuthorityModeOrganizationScoped, organization.OrganizationRoleNone, false, false)
	case PrincipalKindPlatformSystem:
		return structuralTestSpec(kind, AuthorityModePlatformGlobal, organization.OrganizationRoleNone, false, false)
	default:
		spec := validTestSpec()
		spec.principalKind = kind
		return spec
	}
}

func requireInvalidContext(t *testing.T, spec executionContextSpec) {
	t.Helper()
	got, err := newExecutionContext(spec)
	if err == nil {
		t.Fatal("newExecutionContext error = nil, want validation failure")
	}
	assertNoAuthority(t, got)
}

func assertNoAuthority(t *testing.T, got ExecutionContext) {
	t.Helper()
	assertNoAuthorityPointer(t, &got)
}

func assertNoAuthorityPointer(t *testing.T, got *ExecutionContext) {
	t.Helper()
	if got.Valid() {
		t.Fatal("ExecutionContext.Valid = true, want false")
	}
	if got.PrincipalKind() != "" || got.PrincipalID() != "" || got.ActualActorID() != "" {
		t.Fatalf("invalid ExecutionContext exposed principal evidence: kind=%q principal=%q actor=%q", got.PrincipalKind(), got.PrincipalID(), got.ActualActorID())
	}
	if source := got.AuthenticationSource(); source != nil {
		t.Fatalf("invalid ExecutionContext authentication source = %#v, want absent", source)
	}
	if privileges := got.Privileges(); privileges != nil {
		t.Fatalf("invalid ExecutionContext privileges = %#v, want absent", privileges)
	}
	if got.AuthorityMode() != "" {
		t.Fatalf("invalid ExecutionContext authority mode = %q, want zero", got.AuthorityMode())
	}
	if value, ok := got.EffectiveOrganizationID(); ok || value != uuid.Nil {
		t.Fatalf("invalid ExecutionContext effective Organization = (%s, %t), want absent", value, ok)
	}
	if value, ok := got.AssignmentGeneration(); ok || value != 0 {
		t.Fatalf("invalid ExecutionContext assignment generation = (%d, %t), want absent", value, ok)
	}
	if value, ok := got.PlatformAdminAssumptionID(); ok || value != "" {
		t.Fatalf("invalid ExecutionContext assumption identity = (%q, %t), want absent", value, ok)
	}
}

func TestZeroExecutionContextFailsClosed(t *testing.T) {
	assertNoAuthority(t, ExecutionContext{})
}

func TestPrincipalKindValidation(t *testing.T) {
	validKinds := []PrincipalKind{
		PrincipalKindHuman,
		PrincipalKindIntegration,
		PrincipalKindOrganizationSystem,
		PrincipalKindMachine,
		PrincipalKindPlatformSystem,
	}
	for _, kind := range validKinds {
		t.Run(string(kind), func(t *testing.T) {
			spec := validTestSpecForPrincipal(kind)
			got, err := newExecutionContext(spec)
			if err != nil {
				t.Fatalf("newExecutionContext: %v", err)
			}
			if got.PrincipalKind() != kind {
				t.Fatalf("PrincipalKind = %q, want %q", got.PrincipalKind(), kind)
			}
		})
	}

	for _, kind := range []PrincipalKind{"", "UNKNOWN", "human", "255"} {
		t.Run("reject_"+string(kind), func(t *testing.T) {
			spec := validTestSpec()
			spec.principalKind = kind
			requireInvalidContext(t, spec)
		})
	}
}

func TestAuthorityModeOrganizationMatrix(t *testing.T) {
	normalID := uuid.MustParse("e0ff2a3f-a9f8-4cd5-904f-e6599965110e")
	defaultID := uuid.MustParse(organization.DefaultOrganizationID)

	tests := []struct {
		name    string
		mode    AuthorityMode
		orgID   *uuid.UUID
		wantErr bool
	}{
		{name: "ORG_SCOPED normal", mode: AuthorityModeOrganizationScoped, orgID: &normalID},
		{name: "ORG_SCOPED missing", mode: AuthorityModeOrganizationScoped, wantErr: true},
		{name: "ORG_SCOPED zero", mode: AuthorityModeOrganizationScoped, orgID: pointerTo(uuid.Nil), wantErr: true},
		{name: "ORG_SCOPED Default", mode: AuthorityModeOrganizationScoped, orgID: &defaultID, wantErr: true},
		{name: "DEFAULT_RESTRICTED absent", mode: AuthorityModeDefaultRestricted},
		{name: "DEFAULT_RESTRICTED normal", mode: AuthorityModeDefaultRestricted, orgID: &normalID, wantErr: true},
		{name: "DEFAULT_RESTRICTED Default", mode: AuthorityModeDefaultRestricted, orgID: &defaultID, wantErr: true},
		{name: "PLATFORM_GLOBAL absent", mode: AuthorityModePlatformGlobal},
		{name: "PLATFORM_GLOBAL normal", mode: AuthorityModePlatformGlobal, orgID: &normalID, wantErr: true},
		{name: "PLATFORM_GLOBAL Default", mode: AuthorityModePlatformGlobal, orgID: &defaultID, wantErr: true},
		{name: "zero mode", mode: "", wantErr: true},
		{name: "unknown mode", mode: "UNKNOWN", wantErr: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			spec := validTestSpec()
			spec.authorityMode = test.mode
			spec.effectiveOrganizationID = test.orgID
			switch test.mode {
			case AuthorityModeOrganizationScoped:
				spec.organizationRole = organization.OrganizationRoleMember
			case AuthorityModePlatformGlobal:
				spec.platformAdmin = true
			}
			got, err := newExecutionContext(spec)
			if test.wantErr {
				if err == nil {
					t.Fatal("newExecutionContext error = nil, want validation failure")
				}
				assertNoAuthority(t, got)
				return
			}
			if err != nil {
				t.Fatalf("newExecutionContext: %v", err)
			}
			if !got.Valid() || got.AuthorityMode() != test.mode {
				t.Fatalf("valid/mode = (%t, %q), want (true, %q)", got.Valid(), got.AuthorityMode(), test.mode)
			}
			value, present := got.EffectiveOrganizationID()
			if test.mode == AuthorityModeOrganizationScoped {
				if !present || value != normalID {
					t.Fatalf("EffectiveOrganizationID = (%s, %t), want (%s, true)", value, present, normalID)
				}
			} else if present || value != uuid.Nil {
				t.Fatalf("EffectiveOrganizationID = (%s, %t), want absent", value, present)
			}
		})
	}
}

func TestStableIdentityIntegrity(t *testing.T) {
	spec := validTestSpec()
	spec.principalID = "Principal:ABC-Ä"
	spec.actualActorID = "550e8400-e29b-41d4-a716-446655440000"
	spec.authenticationSourceType = "来源:Session"
	spec.authenticationSourceID = "Source:Case-SENSITIVE"

	got, err := newExecutionContext(spec)
	if err != nil {
		t.Fatalf("newExecutionContext: %v", err)
	}
	if got.PrincipalID() != spec.principalID || got.ActualActorID() != spec.actualActorID {
		t.Fatalf("principal/actual actor = (%q, %q), want exact (%q, %q)", got.PrincipalID(), got.ActualActorID(), spec.principalID, spec.actualActorID)
	}
	if got.PrincipalID() == got.ActualActorID() {
		t.Fatal("principal identity and actual actor were not preserved distinctly")
	}
	source := got.AuthenticationSource()
	if source.Type() != spec.authenticationSourceType || source.ID() != spec.authenticationSourceID {
		t.Fatalf("authentication source = (%q, %q), want exact (%q, %q)", source.Type(), source.ID(), spec.authenticationSourceType, spec.authenticationSourceID)
	}

	invalidIdentities := []string{"", "contains\x00nul", string([]byte{0xff, 0xfe})}
	for _, invalid := range invalidIdentities {
		for _, field := range []string{"principal", "actual actor", "source type", "source identity"} {
			t.Run(field+"_invalid", func(t *testing.T) {
				candidate := validTestSpec()
				switch field {
				case "principal":
					candidate.principalID = invalid
				case "actual actor":
					candidate.actualActorID = invalid
				case "source type":
					candidate.authenticationSourceType = invalid
				case "source identity":
					candidate.authenticationSourceID = invalid
				}
				requireInvalidContext(t, candidate)
			})
		}
	}
}

func TestAssignmentGenerationEvidence(t *testing.T) {
	t.Run("absent", func(t *testing.T) {
		got, err := newExecutionContext(validTestSpec())
		if err != nil {
			t.Fatalf("newExecutionContext: %v", err)
		}
		if value, present := got.AssignmentGeneration(); present || value != 0 {
			t.Fatalf("AssignmentGeneration = (%d, %t), want absent", value, present)
		}
	})

	for _, value := range []int64{1, 17} {
		t.Run("positive", func(t *testing.T) {
			spec := validTestSpec()
			spec.assignmentGeneration = &value
			got, err := newExecutionContext(spec)
			if err != nil {
				t.Fatalf("newExecutionContext: %v", err)
			}
			if generation, present := got.AssignmentGeneration(); !present || generation != value {
				t.Fatalf("AssignmentGeneration = (%d, %t), want (%d, true)", generation, present, value)
			}
		})
	}

	for _, value := range []int64{0, -1} {
		t.Run("non_positive", func(t *testing.T) {
			spec := validTestSpec()
			spec.assignmentGeneration = &value
			requireInvalidContext(t, spec)
		})
	}

	for _, kind := range []PrincipalKind{
		PrincipalKindIntegration,
		PrincipalKindOrganizationSystem,
		PrincipalKindMachine,
		PrincipalKindPlatformSystem,
	} {
		t.Run("reject_non_human_"+string(kind), func(t *testing.T) {
			spec := validTestSpecForPrincipal(kind)
			spec.assignmentGeneration = pointerTo(int64(1))
			requireInvalidContext(t, spec)
		})
	}
}

func TestPlatformAdminAssumptionEvidence(t *testing.T) {
	t.Run("absent", func(t *testing.T) {
		got, err := newExecutionContext(validTestSpec())
		if err != nil {
			t.Fatalf("newExecutionContext: %v", err)
		}
		if value, present := got.PlatformAdminAssumptionID(); present || value != "" {
			t.Fatalf("PlatformAdminAssumptionID = (%q, %t), want absent", value, present)
		}
	})

	for _, value := range []string{"assumption:Case-Ä", "550e8400-e29b-41d4-a716-446655440000"} {
		t.Run("valid", func(t *testing.T) {
			spec := structuralTestSpec(PrincipalKindHuman, AuthorityModeOrganizationScoped, organization.OrganizationRoleNone, true, true)
			spec.platformAdminAssumptionID = &value
			got, err := newExecutionContext(spec)
			if err != nil {
				t.Fatalf("newExecutionContext: %v", err)
			}
			if assumptionID, present := got.PlatformAdminAssumptionID(); !present || assumptionID != value {
				t.Fatalf("PlatformAdminAssumptionID = (%q, %t), want (%q, true)", assumptionID, present, value)
			}
		})
	}

	for _, value := range []string{"", "bad\x00assumption", string([]byte{0xff})} {
		t.Run("invalid", func(t *testing.T) {
			spec := structuralTestSpec(PrincipalKindHuman, AuthorityModeOrganizationScoped, organization.OrganizationRoleNone, true, true)
			spec.platformAdminAssumptionID = &value
			requireInvalidContext(t, spec)
		})
	}
}

func TestHumanPrincipalPrivilegeAuthorityMatrix(t *testing.T) {
	tests := []struct {
		name          string
		mode          AuthorityMode
		role          organization.OrganizationRole
		platformAdmin bool
		assumption    bool
		wantValid     bool
	}{
		{name: "ORG_SCOPED member ordinary", mode: AuthorityModeOrganizationScoped, role: organization.OrganizationRoleMember, wantValid: true},
		{name: "ORG_SCOPED admin ordinary", mode: AuthorityModeOrganizationScoped, role: organization.OrganizationRoleAdmin, wantValid: true},
		{name: "ORG_SCOPED none ordinary", mode: AuthorityModeOrganizationScoped, role: organization.OrganizationRoleNone},
		{name: "ORG_SCOPED PlatformAdmin assumed", mode: AuthorityModeOrganizationScoped, role: organization.OrganizationRoleNone, platformAdmin: true, assumption: true, wantValid: true},
		{name: "ORG_SCOPED PlatformAdmin without assumption", mode: AuthorityModeOrganizationScoped, role: organization.OrganizationRoleNone, platformAdmin: true},
		{name: "ORG_SCOPED assumption without PlatformAdmin", mode: AuthorityModeOrganizationScoped, role: organization.OrganizationRoleNone, assumption: true},
		{name: "ORG_SCOPED assumed member", mode: AuthorityModeOrganizationScoped, role: organization.OrganizationRoleMember, platformAdmin: true, assumption: true},
		{name: "ORG_SCOPED assumed admin", mode: AuthorityModeOrganizationScoped, role: organization.OrganizationRoleAdmin, platformAdmin: true, assumption: true},
		{name: "DEFAULT_RESTRICTED none", mode: AuthorityModeDefaultRestricted, role: organization.OrganizationRoleNone, wantValid: true},
		{name: "DEFAULT_RESTRICTED PlatformAdmin inert", mode: AuthorityModeDefaultRestricted, role: organization.OrganizationRoleNone, platformAdmin: true, wantValid: true},
		{name: "DEFAULT_RESTRICTED member", mode: AuthorityModeDefaultRestricted, role: organization.OrganizationRoleMember},
		{name: "DEFAULT_RESTRICTED admin", mode: AuthorityModeDefaultRestricted, role: organization.OrganizationRoleAdmin},
		{name: "DEFAULT_RESTRICTED assumption", mode: AuthorityModeDefaultRestricted, role: organization.OrganizationRoleNone, platformAdmin: true, assumption: true},
		{name: "PLATFORM_GLOBAL PlatformAdmin", mode: AuthorityModePlatformGlobal, role: organization.OrganizationRoleNone, platformAdmin: true, wantValid: true},
		{name: "PLATFORM_GLOBAL non PlatformAdmin", mode: AuthorityModePlatformGlobal, role: organization.OrganizationRoleNone},
		{name: "PLATFORM_GLOBAL member", mode: AuthorityModePlatformGlobal, role: organization.OrganizationRoleMember, platformAdmin: true},
		{name: "PLATFORM_GLOBAL admin", mode: AuthorityModePlatformGlobal, role: organization.OrganizationRoleAdmin, platformAdmin: true},
		{name: "PLATFORM_GLOBAL assumption", mode: AuthorityModePlatformGlobal, role: organization.OrganizationRoleNone, platformAdmin: true, assumption: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			spec := structuralTestSpec(PrincipalKindHuman, test.mode, test.role, test.platformAdmin, test.assumption)
			got, err := newExecutionContext(spec)
			if !test.wantValid {
				if err == nil {
					t.Fatal("newExecutionContext error = nil, want structural rejection")
				}
				assertNoAuthority(t, got)
				return
			}
			if err != nil {
				t.Fatalf("newExecutionContext: %v", err)
			}
			if !got.Valid() {
				t.Fatal("ExecutionContext.Valid = false, want true")
			}
			privileges := got.Privileges()
			if privileges.OrganizationRole() != test.role || privileges.PlatformAdmin() != test.platformAdmin {
				t.Fatalf("Privileges = (%q, %t), want (%q, %t)", privileges.OrganizationRole(), privileges.PlatformAdmin(), test.role, test.platformAdmin)
			}
		})
	}
}

func TestNonHumanPrincipalPrivilegeAuthorityMatrix(t *testing.T) {
	tests := []struct {
		name          string
		kind          PrincipalKind
		mode          AuthorityMode
		role          organization.OrganizationRole
		platformAdmin bool
		assumption    bool
		wantValid     bool
	}{
		{name: "INTEGRATION ORG_SCOPED", kind: PrincipalKindIntegration, mode: AuthorityModeOrganizationScoped, role: organization.OrganizationRoleNone, wantValid: true},
		{name: "INTEGRATION role", kind: PrincipalKindIntegration, mode: AuthorityModeOrganizationScoped, role: organization.OrganizationRoleMember},
		{name: "INTEGRATION PlatformAdmin", kind: PrincipalKindIntegration, mode: AuthorityModeOrganizationScoped, role: organization.OrganizationRoleNone, platformAdmin: true},
		{name: "INTEGRATION assumption", kind: PrincipalKindIntegration, mode: AuthorityModeOrganizationScoped, role: organization.OrganizationRoleNone, assumption: true},
		{name: "INTEGRATION DEFAULT_RESTRICTED", kind: PrincipalKindIntegration, mode: AuthorityModeDefaultRestricted, role: organization.OrganizationRoleNone},
		{name: "INTEGRATION PLATFORM_GLOBAL", kind: PrincipalKindIntegration, mode: AuthorityModePlatformGlobal, role: organization.OrganizationRoleNone},
		{name: "ORG_SYSTEM ORG_SCOPED", kind: PrincipalKindOrganizationSystem, mode: AuthorityModeOrganizationScoped, role: organization.OrganizationRoleNone, wantValid: true},
		{name: "ORG_SYSTEM DEFAULT_RESTRICTED", kind: PrincipalKindOrganizationSystem, mode: AuthorityModeDefaultRestricted, role: organization.OrganizationRoleNone},
		{name: "ORG_SYSTEM PLATFORM_GLOBAL", kind: PrincipalKindOrganizationSystem, mode: AuthorityModePlatformGlobal, role: organization.OrganizationRoleNone},
		{name: "ORG_SYSTEM role", kind: PrincipalKindOrganizationSystem, mode: AuthorityModeOrganizationScoped, role: organization.OrganizationRoleAdmin},
		{name: "ORG_SYSTEM PlatformAdmin", kind: PrincipalKindOrganizationSystem, mode: AuthorityModeOrganizationScoped, role: organization.OrganizationRoleNone, platformAdmin: true},
		{name: "ORG_SYSTEM assumption", kind: PrincipalKindOrganizationSystem, mode: AuthorityModeOrganizationScoped, role: organization.OrganizationRoleNone, assumption: true},
		{name: "PLATFORM_SYSTEM PLATFORM_GLOBAL", kind: PrincipalKindPlatformSystem, mode: AuthorityModePlatformGlobal, role: organization.OrganizationRoleNone, wantValid: true},
		{name: "PLATFORM_SYSTEM ORG_SCOPED", kind: PrincipalKindPlatformSystem, mode: AuthorityModeOrganizationScoped, role: organization.OrganizationRoleNone},
		{name: "PLATFORM_SYSTEM DEFAULT_RESTRICTED", kind: PrincipalKindPlatformSystem, mode: AuthorityModeDefaultRestricted, role: organization.OrganizationRoleNone},
		{name: "PLATFORM_SYSTEM role", kind: PrincipalKindPlatformSystem, mode: AuthorityModePlatformGlobal, role: organization.OrganizationRoleMember},
		{name: "PLATFORM_SYSTEM PlatformAdmin", kind: PrincipalKindPlatformSystem, mode: AuthorityModePlatformGlobal, role: organization.OrganizationRoleNone, platformAdmin: true},
		{name: "PLATFORM_SYSTEM assumption", kind: PrincipalKindPlatformSystem, mode: AuthorityModePlatformGlobal, role: organization.OrganizationRoleNone, assumption: true},
		{name: "MACHINE ORG_SCOPED", kind: PrincipalKindMachine, mode: AuthorityModeOrganizationScoped, role: organization.OrganizationRoleNone, wantValid: true},
		{name: "MACHINE PLATFORM_GLOBAL", kind: PrincipalKindMachine, mode: AuthorityModePlatformGlobal, role: organization.OrganizationRoleNone, wantValid: true},
		{name: "MACHINE DEFAULT_RESTRICTED", kind: PrincipalKindMachine, mode: AuthorityModeDefaultRestricted, role: organization.OrganizationRoleNone},
		{name: "MACHINE role", kind: PrincipalKindMachine, mode: AuthorityModeOrganizationScoped, role: organization.OrganizationRoleAdmin},
		{name: "MACHINE PlatformAdmin", kind: PrincipalKindMachine, mode: AuthorityModePlatformGlobal, role: organization.OrganizationRoleNone, platformAdmin: true},
		{name: "MACHINE assumption", kind: PrincipalKindMachine, mode: AuthorityModeOrganizationScoped, role: organization.OrganizationRoleNone, assumption: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			spec := structuralTestSpec(test.kind, test.mode, test.role, test.platformAdmin, test.assumption)
			got, err := newExecutionContext(spec)
			if !test.wantValid {
				if err == nil {
					t.Fatal("newExecutionContext error = nil, want structural rejection")
				}
				assertNoAuthority(t, got)
				return
			}
			if err != nil {
				t.Fatalf("newExecutionContext: %v", err)
			}
			if !got.Valid() {
				t.Fatal("ExecutionContext.Valid = false, want true")
			}
		})
	}

	spec := validTestSpec()
	spec.organizationRole = organization.OrganizationRole("UNKNOWN")
	requireInvalidContext(t, spec)
}

func TestAccessorFailClosedMatrix(t *testing.T) {
	var nilContext *ExecutionContext
	var nilSource *AuthenticationSource
	var nilPrivileges *PrivilegeMetadata

	nilCalls := []struct {
		name string
		call func()
	}{
		{name: "ExecutionContext.Valid", call: func() { _ = nilContext.Valid() }},
		{name: "ExecutionContext.PrincipalKind", call: func() { _ = nilContext.PrincipalKind() }},
		{name: "ExecutionContext.PrincipalID", call: func() { _ = nilContext.PrincipalID() }},
		{name: "ExecutionContext.ActualActorID", call: func() { _ = nilContext.ActualActorID() }},
		{name: "ExecutionContext.AuthenticationSource", call: func() { _ = nilContext.AuthenticationSource() }},
		{name: "ExecutionContext.Privileges", call: func() { _ = nilContext.Privileges() }},
		{name: "ExecutionContext.AuthorityMode", call: func() { _ = nilContext.AuthorityMode() }},
		{name: "ExecutionContext.EffectiveOrganizationID", call: func() { _, _ = nilContext.EffectiveOrganizationID() }},
		{name: "ExecutionContext.AssignmentGeneration", call: func() { _, _ = nilContext.AssignmentGeneration() }},
		{name: "ExecutionContext.PlatformAdminAssumptionID", call: func() { _, _ = nilContext.PlatformAdminAssumptionID() }},
		{name: "AuthenticationSource.Type", call: func() { _ = nilSource.Type() }},
		{name: "AuthenticationSource.ID", call: func() { _ = nilSource.ID() }},
		{name: "PrivilegeMetadata.OrganizationRole", call: func() { _ = nilPrivileges.OrganizationRole() }},
		{name: "PrivilegeMetadata.PlatformAdmin", call: func() { _ = nilPrivileges.PlatformAdmin() }},
	}
	for _, test := range nilCalls {
		t.Run("nil_"+test.name, func(t *testing.T) {
			defer func() {
				if recovered := recover(); recovered != nil {
					t.Fatalf("nil-pointer accessor panicked: %v", recovered)
				}
			}()
			test.call()
		})
	}

	assertNoAuthorityPointer(t, nilContext)
	zeroContext := ExecutionContext{}
	assertNoAuthorityPointer(t, &zeroContext)
	zeroSource := AuthenticationSource{}
	if zeroSource.Type() != "" || zeroSource.ID() != "" || nilSource.Type() != "" || nilSource.ID() != "" {
		t.Fatal("nil or zero AuthenticationSource exposed evidence")
	}
	zeroPrivileges := PrivilegeMetadata{}
	if zeroPrivileges.OrganizationRole() != "" || zeroPrivileges.PlatformAdmin() || nilPrivileges.OrganizationRole() != "" || nilPrivileges.PlatformAdmin() {
		t.Fatal("nil or zero PrivilegeMetadata exposed evidence")
	}

	spec := structuralTestSpec(PrincipalKindHuman, AuthorityModeOrganizationScoped, organization.OrganizationRoleMember, false, false)
	spec.assignmentGeneration = pointerTo(int64(23))
	validContext, err := newExecutionContext(spec)
	if err != nil {
		t.Fatalf("newExecutionContext: %v", err)
	}
	if !validContext.Valid() || validContext.PrincipalKind() != PrincipalKindHuman || validContext.PrincipalID() != spec.principalID ||
		validContext.ActualActorID() != spec.actualActorID || validContext.AuthorityMode() != AuthorityModeOrganizationScoped {
		t.Fatal("valid ExecutionContext accessors did not return accepted evidence")
	}
	if source := validContext.AuthenticationSource(); source == nil || source.Type() != spec.authenticationSourceType || source.ID() != spec.authenticationSourceID {
		t.Fatalf("AuthenticationSource = %#v, want accepted evidence", source)
	}
	if privileges := validContext.Privileges(); privileges == nil || privileges.OrganizationRole() != organization.OrganizationRoleMember || privileges.PlatformAdmin() {
		t.Fatalf("Privileges = %#v, want ordinary member evidence", privileges)
	}
	if organizationID, present := validContext.EffectiveOrganizationID(); !present || organizationID != *spec.effectiveOrganizationID {
		t.Fatalf("EffectiveOrganizationID = (%s, %t), want (%s, true)", organizationID, present, *spec.effectiveOrganizationID)
	}
	if generation, present := validContext.AssignmentGeneration(); !present || generation != 23 {
		t.Fatalf("AssignmentGeneration = (%d, %t), want (23, true)", generation, present)
	}
	if assumptionID, present := validContext.PlatformAdminAssumptionID(); present || assumptionID != "" {
		t.Fatalf("PlatformAdminAssumptionID = (%q, %t), want absent", assumptionID, present)
	}

	assumedSpec := structuralTestSpec(PrincipalKindHuman, AuthorityModeOrganizationScoped, organization.OrganizationRoleNone, true, true)
	assumedContext, err := newExecutionContext(assumedSpec)
	if err != nil {
		t.Fatalf("newExecutionContext assumed: %v", err)
	}
	if assumptionID, present := assumedContext.PlatformAdminAssumptionID(); !present || assumptionID != *assumedSpec.platformAdminAssumptionID {
		t.Fatalf("PlatformAdminAssumptionID = (%q, %t), want (%q, true)", assumptionID, present, *assumedSpec.platformAdminAssumptionID)
	}
}

func TestExecutionContextIsImmutableByValue(t *testing.T) {
	organizationID := uuid.MustParse("0e6cbaef-7f9a-4bf5-bcae-c0c1363204b1")
	generation := int64(29)
	assumptionID := "assumption:original"
	spec := validTestSpec()
	spec.authorityMode = AuthorityModeOrganizationScoped
	spec.effectiveOrganizationID = &organizationID
	spec.assignmentGeneration = &generation
	spec.platformAdminAssumptionID = &assumptionID
	spec.platformAdmin = true
	spec.authenticationSourceID = "source:original"

	got, err := newExecutionContext(spec)
	if err != nil {
		t.Fatalf("newExecutionContext: %v", err)
	}
	original := got

	organizationID = uuid.MustParse("80c5ed3c-7d5d-4d93-a26d-aa68e33a78fa")
	generation = 30
	assumptionID = "assumption:changed"
	spec.principalID = "principal:changed"
	spec.authenticationSourceID = "source:changed"
	spec.organizationRole = organization.OrganizationRoleAdmin

	if !reflect.DeepEqual(got, original) {
		t.Fatalf("ExecutionContext changed after construction-spec mutation: got %#v, want %#v", got, original)
	}
	copyOfContext := got
	if !reflect.DeepEqual(copyOfContext, got) {
		t.Fatalf("copied ExecutionContext = %#v, want %#v", copyOfContext, got)
	}
	if value, present := got.EffectiveOrganizationID(); !present || value != uuid.MustParse("0e6cbaef-7f9a-4bf5-bcae-c0c1363204b1") {
		t.Fatalf("effective Organization changed to (%s, %t)", value, present)
	}
	if value, present := got.AssignmentGeneration(); !present || value != 29 {
		t.Fatalf("assignment generation changed to (%d, %t)", value, present)
	}
	if value, present := got.PlatformAdminAssumptionID(); !present || value != "assumption:original" {
		t.Fatalf("assumption identity changed to (%q, %t)", value, present)
	}
	if got.AuthenticationSource().ID() != "source:original" {
		t.Fatalf("authentication source identity changed to %q", got.AuthenticationSource().ID())
	}
	returnedSource := got.AuthenticationSource()
	returnedPrivileges := got.Privileges()
	returnedSource.sourceID = "source:returned-copy-changed"
	returnedPrivileges.organizationRole = organization.OrganizationRoleAdmin
	returnedPrivileges.platformAdmin = false
	if got.AuthenticationSource().ID() != "source:original" {
		t.Fatalf("returned AuthenticationSource mutated internal identity to %q", got.AuthenticationSource().ID())
	}
	if got.Privileges().OrganizationRole() != organization.OrganizationRoleNone || !got.Privileges().PlatformAdmin() {
		t.Fatalf("returned PrivilegeMetadata mutated internal evidence to (%q, %t)", got.Privileges().OrganizationRole(), got.Privileges().PlatformAdmin())
	}
	if !reflect.DeepEqual(got, original) {
		t.Fatalf("ExecutionContext changed after returned-copy mutation: got %#v, want %#v", got, original)
	}
}

func TestSerializationCannotMintAuthority(t *testing.T) {
	valid, err := newExecutionContext(structuralTestSpec(PrincipalKindHuman, AuthorityModeOrganizationScoped, organization.OrganizationRoleMember, false, false))
	if err != nil {
		t.Fatalf("newExecutionContext: %v", err)
	}

	encodedJSON, err := json.Marshal(valid) //nolint:staticcheck // The test proves private trust state is not serialized.
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	var restoredFromJSON ExecutionContext
	if err := json.Unmarshal(encodedJSON, &restoredFromJSON); err != nil { //nolint:staticcheck // The test proves no authority is restored.
		t.Fatalf("json.Unmarshal: %v", err)
	}
	assertNoAuthority(t, restoredFromJSON)
	forgedJSON := []byte(`{"valid":true,"principalKind":"HUMAN","authorityMode":"PLATFORM_GLOBAL"}`)
	if err := json.Unmarshal(forgedJSON, &restoredFromJSON); err != nil { //nolint:staticcheck // The test exercises an intentionally opaque type.
		t.Fatalf("json.Unmarshal forged payload: %v", err)
	}
	assertNoAuthority(t, restoredFromJSON)

	var encodedGob bytes.Buffer
	if err := gob.NewEncoder(&encodedGob).Encode(valid); err == nil {
		t.Fatal("gob encoded an ExecutionContext with only private trust-bearing state")
	}
}

func TestMalformedSpecsNeverReturnAuthority(t *testing.T) {
	normalID := uuid.MustParse("b311bd8e-c456-4e26-91e9-f0ac2b8b12e7")
	invalidSpecs := []executionContextSpec{
		{},
		func() executionContextSpec { v := validTestSpec(); v.principalKind = "UNKNOWN"; return v }(),
		func() executionContextSpec { v := validTestSpec(); v.principalID = ""; return v }(),
		func() executionContextSpec { v := validTestSpec(); v.actualActorID = "bad\x00actor"; return v }(),
		func() executionContextSpec { v := validTestSpec(); v.authenticationSourceType = ""; return v }(),
		func() executionContextSpec { v := validTestSpec(); v.authenticationSourceID = ""; return v }(),
		func() executionContextSpec { v := validTestSpec(); v.organizationRole = "UNKNOWN"; return v }(),
		func() executionContextSpec { v := validTestSpec(); v.authorityMode = "UNKNOWN"; return v }(),
		func() executionContextSpec {
			v := validTestSpec()
			v.authorityMode = AuthorityModeOrganizationScoped
			return v
		}(),
		func() executionContextSpec { v := validTestSpec(); v.effectiveOrganizationID = &normalID; return v }(),
	}
	for i, spec := range invalidSpecs {
		t.Run(string(rune('A'+i)), func(t *testing.T) {
			requireInvalidContext(t, spec)
		})
	}
}

func pointerTo[T any](value T) *T { return &value }
