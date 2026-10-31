package graphqlapp

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/assignment"
	"github.com/target/goalert/auth"
	"github.com/target/goalert/executioncontext"
	"github.com/target/goalert/graphql2"
	"github.com/target/goalert/organization"
	"github.com/target/goalert/permission"
)

func TestServiceManagementAuthorityRoles(t *testing.T) {
	for _, role := range []organization.OrganizationRole{organization.OrganizationRoleMember, organization.OrganizationRoleAdmin} {
		for _, pa := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/PA=%t", role, pa), func(t *testing.T) {
				// Reuse only the canonical-admission SQL-driver fixture, not IK authority.
				ctx, _, f := ikAuthorityContext(t, role, pa)
				for _, op := range []serviceManagementOperation{serviceManagementCreate, serviceManagementUpdate, serviceManagementDelete} {
					home, err := serviceManagementAuthority(ctx, op)
					if pa || role == organization.OrganizationRoleAdmin {
						require.NoError(t, err)
						require.NotNil(t, home, "PA must also receive a concrete Home constraint")
						require.Equal(t, f.home, *home)
					} else {
						require.Nil(t, home)
						require.True(t, permission.IsPermissionError(err))
					}
				}
				require.Equal(t, 1, f.queries, "no additional authority queries after admission")
				require.Zero(t, f.begins)
			})
		}
	}
}

func TestServiceManagementRejectsBeforeBusinessWork(t *testing.T) {
	ctx, _, f := ikAuthorityContext(t, organization.OrganizationRoleMember, false)
	app := new(App) // A store access, signing call or BeginTx would panic.
	id := uuid.NewString()
	for name, input := range map[string]graphql2.CreateServiceInput{
		"plain":       {Name: "Denied"},
		"nested EP":   {Name: "Denied", NewEscalationPolicy: &graphql2.CreateEscalationPolicyInput{Name: "Nested"}},
		"credentials": {Name: "Denied", NewIntegrationKeys: []graphql2.CreateIntegrationKeyInput{{Type: graphql2.IntegrationKeyTypeGeneric}}},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := app.Mutation().CreateService(ctx, input)
			require.True(t, permission.IsPermissionError(err))
		})
	}
	_, err := app.Mutation().UpdateService(ctx, graphql2.UpdateServiceInput{ID: id})
	require.True(t, permission.IsPermissionError(err))
	for _, ids := range [][]assignment.RawTarget{
		{{Type: assignment.TargetTypeService, ID: id}},
		{{Type: assignment.TargetTypeService, ID: id}, {Type: assignment.TargetTypeService, ID: "missing"}},
		{{Type: assignment.TargetTypeRotation, ID: id}, {Type: assignment.TargetTypeService, ID: id}},
		{{Type: assignment.TargetTypeIntegrationKey, ID: id}, {Type: assignment.TargetTypeService, ID: id}},
	} {
		_, err = app.Mutation().DeleteAll(ctx, ids)
		require.True(t, permission.IsPermissionError(err))
		require.NotContains(t, err.Error(), id, "denial must not expose target existence")
	}
	require.Equal(t, 1, f.queries)
	require.Zero(t, f.begins)
}

func TestServiceManagementIdentityAndSystemBoundary(t *testing.T) {
	ctx, _, f := ikAuthorityContext(t, organization.OrganizationRoleAdmin, true)
	other, err := auth.NewRequester(uuid.NewString(), uuid.NewString())
	require.NoError(t, err)
	missingEC := auth.WithRequester(permission.UserSourceContext(context.Background(), f.user.String(), permission.RoleAdmin,
		&permission.SourceInfo{Type: permission.SourceTypeAuthProvider, ID: f.session.String()}), *auth.RequesterFromContext(ctx))
	contexts := map[string]context.Context{
		"nil": nil, "unauthenticated": context.Background(),
		"legacy User":        permission.UserContext(context.Background(), f.user.String(), permission.RoleUser),
		"legacy Admin":       permission.UserContext(context.Background(), f.user.String(), permission.RoleAdmin),
		"missing EC":         missingEC,
		"zero EC":            executioncontext.WithExecutionContext(missingEC, executioncontext.ExecutionContext{}),
		"forged requester":   auth.WithRequester(ctx, other),
		"session mismatch":   permission.SourceContext(ctx, &permission.SourceInfo{Type: permission.SourceTypeAuthProvider, ID: uuid.NewString()}),
		"PA disagreement":    permission.UserContext(ctx, f.user.String(), permission.RoleUser),
		"System over Human":  permission.SystemContext(ctx, "Test"),
		"Machine over Human": permission.ServiceContext(ctx, uuid.NewString()),
		"legacy GraphQL Key": permission.UserSourceContext(context.Background(), f.user.String(), permission.RoleAdmin,
			&permission.SourceInfo{Type: permission.SourceTypeGQLAPIKey, ID: uuid.NewString()}),
		"Integration": permission.ServiceSourceContext(context.Background(), uuid.NewString(),
			&permission.SourceInfo{Type: permission.SourceTypeIntegrationKey, ID: uuid.NewString()}),
	}
	for name, c := range contexts {
		t.Run(name, func(t *testing.T) {
			for _, op := range []serviceManagementOperation{serviceManagementCreate, serviceManagementUpdate, serviceManagementDelete} {
				home, err := serviceManagementAuthority(c, op)
				require.Nil(t, home)
				require.True(t, permission.IsPermissionError(err))
			}
		})
	}
	sys := permission.SystemContext(context.Background(), "Engine")
	for _, op := range []serviceManagementOperation{serviceManagementUpdate, serviceManagementDelete} {
		home, err := serviceManagementAuthority(sys, op)
		require.NoError(t, err)
		require.Nil(t, home)
	}
	_, err = serviceManagementAuthority(sys, serviceManagementCreate)
	require.True(t, permission.IsPermissionError(err))
	_, err = serviceManagementAuthority(ctx, serviceManagementOperation(255))
	require.True(t, permission.IsPermissionError(err))
}
