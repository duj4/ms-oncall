package executioncontext

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/target/goalert/auth"
	"github.com/target/goalert/permission"
)

func TestCMNRHumanAuthorityBinding(t *testing.T) {
	for _, admin := range []bool{false, true} {
		f := newHumanExecutionContextFixture(t)
		if admin {
			f.reader.value.UserRole = permission.RoleAdmin
			f.setLegacyRole(permission.RoleAdmin)
		}
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
			t.Run(name+"/role="+string(f.reader.value.UserRole), func(t *testing.T) {
				got, err := CheckCMNRMutationAuthority(mutate(ctx))
				if name != "valid" {
					if !permission.IsPermissionError(err) || got.valid {
						t.Fatal("inconsistent Human authority was accepted")
					}
					return
				}
				if err != nil || !got.valid || got.system || got.owner != f.userID || got.home != f.orgID || got.platformAdmin != admin {
					t.Fatal("valid Human lost authenticated identity, Home or current global role")
				}
			})
		}
	}
}

func TestCMNRSyntheticAdminAndSystemAreDistinct(t *testing.T) {
	owner := uuid.New()
	for _, role := range []permission.Role{permission.RoleUser, permission.RoleAdmin} {
		value, err := CheckCMNRMutationAuthority(permission.UserContext(context.Background(), owner.String(), role))
		if err != nil || !value.valid || value.system || value.platformAdmin || value.owner != owner {
			t.Fatal("legacy UserContext did not retain strictly owner-only authority")
		}
	}
	value, err := CheckCMNRMutationAuthority(permission.SystemContext(context.Background(), "Test"))
	if err != nil || !value.valid || !value.system || value.platformAdmin || value.owner != uuid.Nil {
		t.Fatal("System authority was confused with Human PlatformAdmin")
	}
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
