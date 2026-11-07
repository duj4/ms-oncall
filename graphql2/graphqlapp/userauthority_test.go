package graphqlapp

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/target/goalert/organization"
	"github.com/target/goalert/permission"
)

func TestUserProfileAuthority(t *testing.T) {
	for _, role := range []organization.OrganizationRole{organization.OrganizationRoleMember, organization.OrganizationRoleAdmin} {
		for _, pa := range []bool{false, true} {
			ctx, _, f := ikAuthorityContext(t, role, pa)
			home, global, err := userProfileScope(ctx)
			require.NoError(t, err)
			require.Equal(t, &f.home, home)
			require.Equal(t, pa, global)
			conflictingRole := permission.RoleAdmin
			if pa {
				conflictingRole = permission.RoleUser
			}
			for _, invalid := range []context.Context{
				permission.SystemContext(ctx, "Test"),
				permission.ServiceContext(ctx, f.home.String()),
				permission.UserSourceContext(ctx, f.user.String(), conflictingRole,
					&permission.SourceInfo{Type: permission.SourceTypeAuthProvider, ID: f.session.String()}),
			} {
				_, _, err := userProfileScope(invalid)
				require.True(t, permission.IsPermissionError(err))
			}
		}
	}
	require.False(t, userRelationshipSelection(context.Background()))
}
