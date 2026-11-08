package executioncontext

import (
	"testing"

	"github.com/google/uuid"
	"github.com/target/goalert/auth"
	"github.com/target/goalert/organization"
	"github.com/target/goalert/permission"
)

func TestDefaultHumanAuthorityDoesNotGrantOperationalMembership(t *testing.T) {
	for _, pa := range []bool{false, true} {
		t.Run(map[bool]string{false: "ordinary Default", true: "Default PA"}[pa], func(t *testing.T) {
			f := newHumanExecutionContextFixture(t)
			f.reader.value.OrganizationID = uuid.MustParse(organization.DefaultOrganizationID)
			f.reader.value.Classification = organization.ClassificationDefault
			f.reader.value.Role = organization.OrganizationRoleNone
			role := permission.RoleUser
			if pa {
				role = permission.RoleAdmin
			}
			f.reader.value.UserRole = role
			f.setLegacyRole(role)
			value, err := f.constructor(t).Construct(f.ctx)
			if err != nil {
				t.Fatal(err)
			}
			if home, ok := value.HomeOrganizationID(); !ok || home.String() != organization.DefaultOrganizationID {
				t.Fatalf("Home = %s %t", home, ok)
			}
			if _, ok := value.EffectiveOrganizationID(); ok {
				t.Fatal("Default acquired operational affiliation")
			}
			if EligibleForOrganizationBusinessScope(&value, f.orgID) {
				t.Fatal("Default acquired Normal business scope")
			}
			want := AuthorityModeDefaultRestricted
			if pa {
				want = AuthorityModePlatformGlobal
			}
			if value.AuthorityMode() != want {
				t.Fatalf("mode = %s", value.AuthorityMode())
			}
			ctx := WithExecutionContext(f.ctx, value)
			got, err := CheckHumanAuthority(ctx)
			if err != nil || got.Privileges().PlatformAdmin() != pa {
				t.Fatalf("authority = %v, %v", got, err)
			}
			requester, _ := auth.NewRequester(f.userID.String(), uuid.NewString())
			if _, err := CheckHumanAuthority(auth.WithRequester(ctx, requester)); !permission.IsPermissionError(err) {
				t.Fatal("Session mismatch accepted")
			}
		})
	}
}

func TestHumanAuthorityClassificationContradictionsFailClosed(t *testing.T) {
	for _, tc := range []struct {
		name  string
		class organization.Classification
		id    uuid.UUID
		role  organization.OrganizationRole
	}{
		{"Normal with Default ID", organization.ClassificationNormal, uuid.MustParse(organization.DefaultOrganizationID), organization.OrganizationRoleMember},
		{"Default with Normal ID", organization.ClassificationDefault, uuid.New(), organization.OrganizationRoleNone},
		{"Default with Member role", organization.ClassificationDefault, uuid.MustParse(organization.DefaultOrganizationID), organization.OrganizationRoleMember},
		{"unknown classification", "INVALID", uuid.New(), organization.OrganizationRoleMember},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newHumanExecutionContextFixture(t)
			f.reader.value.OrganizationID = tc.id
			f.reader.value.Classification = tc.class
			f.reader.value.Role = tc.role
			v, err := f.constructor(t).Construct(f.ctx)
			if err == nil || v.Valid() {
				t.Fatal("contradictory persisted identity accepted")
			}
		})
	}
}
