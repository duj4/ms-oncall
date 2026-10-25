package executioncontext

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/target/goalert/auth"
	"github.com/target/goalert/organization"
	"github.com/target/goalert/permission"
)

func TestCMNRHumanAuthorityBinding(t *testing.T) {
	for _, test := range []struct {
		name    string
		role    permission.Role
		orgRole organization.OrganizationRole
	}{
		{"OrgMember", permission.RoleUser, organization.OrganizationRoleMember},
		{"OrgAdmin", permission.RoleUser, organization.OrganizationRoleAdmin},
		{"PlatformAdmin Home member", permission.RoleAdmin, organization.OrganizationRoleMember},
		{"PlatformAdmin Home admin", permission.RoleAdmin, organization.OrganizationRoleAdmin},
	} {
		f := newHumanExecutionContextFixture(t)
		admin := test.role == permission.RoleAdmin
		f.reader.value.UserRole = test.role
		f.reader.value.Role = test.orgRole
		f.setLegacyRole(test.role)
		value, err := f.constructor(t).Construct(f.ctx)
		if err != nil {
			t.Fatal(err)
		}
		ctx := WithExecutionContext(f.ctx, value)
		for name, mutate := range map[string]func(context.Context) context.Context{
			"valid":                    func(c context.Context) context.Context { return c },
			"missing ExecutionContext": func(context.Context) context.Context { return f.ctx },
			"missing Requester": func(context.Context) context.Context {
				return WithExecutionContext(permission.UserSourceContext(context.Background(), f.userID.String(), f.reader.value.UserRole,
					&permission.SourceInfo{Type: permission.SourceTypeAuthProvider, ID: f.sessionID.String()}), value)
			},
			"missing Source": func(context.Context) context.Context {
				return WithExecutionContext(auth.WithRequester(
					permission.UserContext(context.Background(), f.userID.String(), test.role),
					*auth.RequesterFromContext(f.ctx)), value)
			},
			"different Requester User": func(c context.Context) context.Context {
				r, err := auth.NewRequester(uuid.NewString(), f.sessionID.String())
				if err != nil {
					t.Fatal(err)
				}
				return auth.WithRequester(c, r)
			},
			"different Requester Session": func(c context.Context) context.Context {
				r, err := auth.NewRequester(f.userID.String(), uuid.NewString())
				if err != nil {
					t.Fatal(err)
				}
				return auth.WithRequester(c, r)
			},
			"different legacy User": func(c context.Context) context.Context {
				return permission.UserContext(c, uuid.NewString(), f.reader.value.UserRole)
			},
			"different legacy role": func(c context.Context) context.Context {
				role := permission.RoleAdmin
				if admin {
					role = permission.RoleUser
				}
				return permission.UserContext(c, f.userID.String(), role)
			},
			"different source Session": func(c context.Context) context.Context {
				return permission.SourceContext(c, &permission.SourceInfo{Type: permission.SourceTypeAuthProvider, ID: uuid.NewString()})
			},
			"different source type": func(c context.Context) context.Context {
				return permission.SourceContext(c, &permission.SourceInfo{Type: permission.SourceTypeGQLAPIKey, ID: f.sessionID.String()})
			},
			"different actual actor": func(c context.Context) context.Context {
				changed := value
				changed.actualActorID = uuid.NewString()
				return WithExecutionContext(c, changed)
			},
			"different principal": func(c context.Context) context.Context {
				changed := value
				changed.principalID = uuid.NewString()
				return WithExecutionContext(c, changed)
			},
			"nonhuman": func(c context.Context) context.Context {
				changed := value
				changed.principalKind = PrincipalKindMachine
				return WithExecutionContext(c, changed)
			},
		} {
			t.Run(test.name+"/"+name, func(t *testing.T) {
				got, err := CheckCMNRMutationAuthority(mutate(ctx))
				if name != "valid" {
					if !permission.IsPermissionError(err) || permission.IsUnauthorized(err) || got != (CMNRMutationAuthority{}) {
						t.Fatal("inconsistent Human authority was accepted")
					}
					return
				}
				if err != nil || !got.valid || got.system || got.owner != f.userID || got.home != f.orgID || got.platformAdmin != admin {
					t.Fatal("valid Human lost authenticated identity, Home or current global role")
				}
				if value.Privileges().OrganizationRole() != test.orgRole {
					t.Fatal("Human authority lost Home Organization role")
				}
			})
		}
	}
}

func TestCMNRExplicitNonHumanSourceDenied(t *testing.T) {
	owner := uuid.New()
	for _, sourceType := range []permission.SourceType{
		permission.SourceTypeGQLAPIKey,
		permission.SourceTypeUIK,
		permission.SourceTypeContactMethod,
		permission.SourceType(999),
	} {
		for _, role := range []permission.Role{permission.RoleUser, permission.RoleAdmin} {
			t.Run(sourceType.String()+"/"+string(role), func(t *testing.T) {
				ctx := permission.UserSourceContext(context.Background(), owner.String(), role,
					&permission.SourceInfo{Type: sourceType, ID: "test-source"})
				got, err := CheckCMNRMutationAuthority(ctx)
				if !permission.IsPermissionError(err) || permission.IsUnauthorized(err) {
					t.Fatalf("explicit non-Human source: error = %v, want access denied", err)
				}
				if got != (CMNRMutationAuthority{}) {
					t.Fatal("rejected source retained authority")
				}
			})
		}
	}
}

func TestCMNRAuthProviderWithoutAdmissionDenied(t *testing.T) {
	for _, role := range []permission.Role{permission.RoleUser, permission.RoleAdmin} {
		t.Run(string(role), func(t *testing.T) {
			ctx := permission.UserSourceContext(context.Background(), uuid.NewString(), role,
				&permission.SourceInfo{Type: permission.SourceTypeAuthProvider, ID: uuid.NewString()})
			got, err := CheckCMNRMutationAuthority(ctx)
			if !permission.IsPermissionError(err) || permission.IsUnauthorized(err) || got != (CMNRMutationAuthority{}) {
				t.Fatal("AuthProvider source replaced trusted Human admission")
			}
		})
	}
}

func TestCMNRSyntheticAdminAndSystemAreDistinct(t *testing.T) {
	owner := uuid.New()
	for _, role := range []permission.Role{permission.RoleUser, permission.RoleAdmin} {
		value, err := CheckCMNRMutationAuthority(permission.UserContext(context.Background(), owner.String(), role))
		if err != nil || value != (CMNRMutationAuthority{valid: true, owner: owner}) {
			t.Fatal("legacy UserContext did not retain strictly owner-only authority")
		}
	}
	value, err := CheckCMNRMutationAuthority(permission.SystemContext(context.Background(), "Test"))
	if err != nil || !value.valid || !value.system || value.platformAdmin || value.owner != uuid.Nil {
		t.Fatal("System authority was confused with Human PlatformAdmin")
	}
	// Explicit sources and incomplete Human metadata must not move the
	// independently trusted System/Sudo branch behind Human classification.
	sourced := permission.UserSourceContext(context.Background(), "invalid", permission.RoleAdmin,
		&permission.SourceInfo{Type: permission.SourceType(999), ID: "test-source"})
	checkSystem := func(ctx context.Context) {
		t.Helper()
		got, err := CheckCMNRMutationAuthority(ctx)
		if err != nil || got != (CMNRMutationAuthority{valid: true, system: true}) {
			t.Fatal("System/Sudo lost precedence over source or legacy UserID checks")
		}
	}
	checkSystem(permission.SystemContext(sourced, "Test"))
	permission.SudoContext(sourced, checkSystem)
	for _, ctx := range []context.Context{nil, context.Background(), permission.UserContext(context.Background(), "invalid", permission.RoleAdmin)} {
		value, err := CheckCMNRMutationAuthority(ctx)
		if !permission.IsPermissionError(err) || value.valid {
			t.Fatal("missing principal was accepted")
		}
	}
}

func TestCMNRCurrentRoleObservedOnNextAdmission(t *testing.T) {
	f := newHumanExecutionContextFixture(t)
	f.reader.value.UserRole = permission.RoleAdmin
	f.setLegacyRole(permission.RoleAdmin)
	c := f.constructor(t)
	first, err := c.Construct(f.ctx)
	if err != nil || !first.Privileges().PlatformAdmin() {
		t.Fatal("current Admin not observed")
	}
	f.reader.value.UserRole = permission.RoleUser
	if _, err := c.Construct(f.ctx); err == nil {
		t.Fatal("stale legacy role accepted at admission")
	}
	f.setLegacyRole(permission.RoleUser)
	second, err := c.Construct(f.ctx)
	if err != nil || second.Privileges().PlatformAdmin() || !first.Privileges().PlatformAdmin() {
		t.Fatal("downgrade did not affect next admission or mutated in-flight evidence")
	}
}
