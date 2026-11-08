package graphqlapp

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/auth"
	"github.com/target/goalert/executioncontext"
	"github.com/target/goalert/organization"
	"github.com/target/goalert/permission"
	"github.com/target/goalert/user"
)

func TestHumanOperationAdmissionRejectsInvalidAuthority(t *testing.T) {
	ctx, _, f := ikAuthorityContext(t, organization.OrganizationRoleAdmin, true)
	requester := *auth.RequesterFromContext(ctx)
	legacy := permission.UserSourceContext(context.Background(), f.user.String(), permission.RoleAdmin,
		&permission.SourceInfo{Type: permission.SourceTypeAuthProvider, ID: f.session.String()})
	other, err := auth.NewRequester(uuid.NewString(), uuid.NewString())
	require.NoError(t, err)
	for name, invalid := range map[string]context.Context{
		"missing authority":    auth.WithRequester(legacy, requester),
		"missing Requester":    legacy,
		"bare Admin":           permission.UserContext(context.Background(), f.user.String(), permission.RoleAdmin),
		"mismatched Requester": auth.WithRequester(ctx, other),
		"mismatched Session":   permission.SourceContext(ctx, &permission.SourceInfo{Type: permission.SourceTypeAuthProvider, ID: uuid.NewString()}),
		"mismatched PA":        permission.UserContext(ctx, f.user.String(), permission.RoleUser),
		"System over Human":    permission.SystemContext(ctx, "Test"),
		"Machine over Human":   permission.ServiceContext(ctx, uuid.NewString()),
		"unknown source":       permission.SourceContext(legacy, &permission.SourceInfo{Type: permission.SourceType(255), ID: uuid.NewString()}),
	} {
		t.Run(name, func(t *testing.T) {
			state, err := humanOperationAdmission(invalid)
			require.Equal(t, invalidHumanAuthority, state)
			require.True(t, permission.IsPermissionError(err))
			for _, object := range []string{"Query", "Mutation", "Subscription"} {
				require.True(t, permission.IsPermissionError(defaultHumanOperation(invalid, object, "updateUser", nil)))
			}
			require.True(t, permission.IsPermissionError(authorizeDefaultUserTarget(invalid, nil, f.user.String())))
			// These legacy branches must reject even when called directly, before
			// any transaction or Store access (the App deliberately has neither).
			a := new(App).Mutation()
			_, err = a.AddAuthSubject(invalid, user.AuthSubject{UserID: f.user.String()})
			require.True(t, permission.IsPermissionError(err))
			_, err = a.DeleteAuthSubject(invalid, user.AuthSubject{UserID: f.user.String()})
			require.True(t, permission.IsPermissionError(err))
			_, err = a.DeleteAll(invalid, nil)
			require.True(t, permission.IsPermissionError(err))
		})
	}
}

func TestHumanOperationAdmissionNormalDefaultAndNonHuman(t *testing.T) {
	for _, pa := range []bool{false, true} {
		ctx, db, f := ikAuthorityContext(t, organization.OrganizationRoleMember, pa)
		state, err := humanOperationAdmission(ctx)
		require.NoError(t, err)
		require.Equal(t, validNormalHuman, state)
		require.NoError(t, defaultHumanOperation(ctx, "Mutation", "updateUser", nil))
		// Reconstruct an actual typed Default authority via the canonical reader.
		f.home = uuid.MustParse(organization.DefaultOrganizationID)
		f.role = organization.OrganizationRoleNone
		constructor, err := executioncontext.NewHumanExecutionContextConstructor(organization.NewStore(db))
		require.NoError(t, err)
		ec, err := constructor.Construct(ctx)
		require.NoError(t, err)
		ctx = executioncontext.WithExecutionContext(ctx, ec)
		state, err = humanOperationAdmission(ctx)
		require.NoError(t, err)
		require.Equal(t, validDefaultHuman, state)
		require.NoError(t, defaultHumanOperation(ctx, "Query", "currentOrganizationContext", nil))
		err = defaultHumanOperation(ctx, "Mutation", "updateUser", nil)
		if pa {
			require.NoError(t, err)
		} else {
			require.True(t, permission.IsPermissionError(err))
		}
		require.True(t, permission.IsPermissionError(defaultHumanOperation(ctx, "Mutation", "endAllAuthSessionsByCurrentUser", nil)))
	}
	for name, ctx := range map[string]context.Context{
		"anonymous":            context.Background(),
		"System":               permission.SystemContext(context.Background(), "Engine"),
		"IntegrationPrincipal": permission.ServiceSourceContext(context.Background(), uuid.NewString(), &permission.SourceInfo{Type: permission.SourceTypeIntegrationKey, ID: uuid.NewString()}),
		"GraphQL Machine":      permission.UserSourceContext(context.Background(), uuid.NewString(), permission.RoleUser, &permission.SourceInfo{Type: permission.SourceTypeGQLAPIKey, ID: uuid.NewString()}),
	} {
		t.Run(name, func(t *testing.T) {
			state, err := humanOperationAdmission(ctx)
			require.NoError(t, err)
			require.Equal(t, nonHumanAdmission, state)
			require.NoError(t, defaultHumanOperation(ctx, "Mutation", "updateUser", nil), "the resolver retains its own authorization")
		})
	}
}
