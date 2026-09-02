package executioncontext

import (
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
	if got.Valid() {
		t.Fatal("ExecutionContext.Valid = true, want false")
	}
	if got.PrincipalKind() != "" || got.PrincipalID() != "" || got.ActualActorID() != "" {
		t.Fatalf("invalid ExecutionContext exposed principal evidence: kind=%q principal=%q actor=%q", got.PrincipalKind(), got.PrincipalID(), got.ActualActorID())
	}
	if source := got.AuthenticationSource(); source != (AuthenticationSource{}) || source.Type() != "" || source.ID() != "" {
		t.Fatalf("invalid ExecutionContext authentication source = %#v, want zero", source)
	}
	if privileges := got.Privileges(); privileges != (PrivilegeMetadata{}) || privileges.OrganizationRole() != "" || privileges.PlatformAdmin() {
		t.Fatalf("invalid ExecutionContext privileges = %#v, want zero", privileges)
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
			spec := validTestSpec()
			spec.principalKind = kind
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
			spec := validTestSpec()
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
			spec := validTestSpec()
			spec.platformAdminAssumptionID = &value
			requireInvalidContext(t, spec)
		})
	}
}

func TestPrivilegeMetadataIsBoundedAndNotInferred(t *testing.T) {
	roles := []organization.OrganizationRole{
		organization.OrganizationRoleMember,
		organization.OrganizationRoleAdmin,
		organization.OrganizationRoleNone,
	}
	for _, role := range roles {
		t.Run(string(role), func(t *testing.T) {
			spec := validTestSpec()
			spec.organizationRole = role
			spec.platformAdmin = role == organization.OrganizationRoleNone
			got, err := newExecutionContext(spec)
			if err != nil {
				t.Fatalf("newExecutionContext: %v", err)
			}
			privileges := got.Privileges()
			if privileges.OrganizationRole() != role || privileges.PlatformAdmin() != spec.platformAdmin {
				t.Fatalf("Privileges = (%q, %t), want (%q, %t)", privileges.OrganizationRole(), privileges.PlatformAdmin(), role, spec.platformAdmin)
			}
		})
	}

	normalID := uuid.MustParse("cc93a9e6-31d0-411b-a78f-ddf471c9231d")
	spec := validTestSpec()
	spec.authorityMode = AuthorityModeOrganizationScoped
	spec.effectiveOrganizationID = &normalID
	spec.organizationRole = organization.OrganizationRoleNone
	got, err := newExecutionContext(spec)
	if err != nil {
		t.Fatalf("newExecutionContext with explicit NONE role: %v", err)
	}
	if got.Privileges().OrganizationRole() != organization.OrganizationRoleNone {
		t.Fatalf("ORG_SCOPED role = %q, want explicit NONE without inference", got.Privileges().OrganizationRole())
	}

	spec = validTestSpec()
	spec.organizationRole = organization.OrganizationRole("UNKNOWN")
	requireInvalidContext(t, spec)
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
