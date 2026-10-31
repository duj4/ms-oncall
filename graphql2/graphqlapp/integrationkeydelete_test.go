package graphqlapp

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/assignment"
	"github.com/target/goalert/auth"
	"github.com/target/goalert/executioncontext"
	"github.com/target/goalert/organization"
	"github.com/target/goalert/permission"
)

func TestIntegrationKeyDeleteEarlyDenial(t *testing.T) {
	member, _, memberFixture := ikAuthorityContext(t, organization.OrganizationRoleMember, false)
	admin, _, f := ikAuthorityContext(t, organization.OrganizationRoleAdmin, true)
	source := &permission.SourceInfo{Type: permission.SourceTypeAuthProvider, ID: f.session.String()}
	legacy := permission.UserSourceContext(context.Background(), f.user.String(), permission.RoleAdmin, source)
	requester := *auth.RequesterFromContext(admin)
	other, err := auth.NewRequester(uuid.NewString(), uuid.NewString())
	require.NoError(t, err)
	contexts := map[string]context.Context{
		"member":                  member,
		"forged legacy admin":     permission.UserContext(member, memberFixture.user.String(), permission.RoleAdmin),
		"unauthenticated":         context.Background(),
		"bare admin":              permission.UserContext(context.Background(), f.user.String(), permission.RoleAdmin),
		"missing Requester":       executioncontext.WithExecutionContext(legacy, *executioncontext.ExecutionContextFromContext(admin)),
		"missing EC":              auth.WithRequester(legacy, requester),
		"invalid EC":              executioncontext.WithExecutionContext(auth.WithRequester(legacy, requester), executioncontext.ExecutionContext{}),
		"missing source":          executioncontext.WithExecutionContext(auth.WithRequester(permission.UserContext(context.Background(), f.user.String(), permission.RoleAdmin), requester), *executioncontext.ExecutionContextFromContext(admin)),
		"inconsistent Requester":  auth.WithRequester(admin, other),
		"inconsistent source":     permission.SourceContext(admin, &permission.SourceInfo{Type: permission.SourceTypeAuthProvider, ID: uuid.NewString()}),
		"PA disagreement":         permission.UserContext(admin, f.user.String(), permission.RoleUser),
		"Human System escalation": permission.SystemContext(admin, "Engine"),
		"retired Machine key":     permission.UserSourceContext(context.Background(), f.user.String(), permission.RoleAdmin, &permission.SourceInfo{Type: permission.SourceTypeGQLAPIKey, ID: uuid.NewString()}),
		"integration":             permission.ServiceSourceContext(context.Background(), uuid.NewString(), &permission.SourceInfo{Type: permission.SourceTypeIntegrationKey, ID: uuid.NewString()}),
	}
	app := new(App) // No DB or Stores: denial must precede Begin and all writes.
	for name, ctx := range contexts {
		t.Run(name, func(t *testing.T) {
			for _, id := range []string{uuid.NewString(), "invalid"} {
				ok, err := app.Mutation().DeleteAll(ctx, []assignment.RawTarget{
					{Type: assignment.TargetTypeSchedule, ID: uuid.NewString()},
					{Type: assignment.TargetTypeIntegrationKey, ID: id},
				})
				require.False(t, ok)
				require.True(t, permission.IsPermissionError(err))
				require.NotContains(t, err.Error(), id)
			}
		})
	}
	require.Equal(t, 1, f.queries)
	require.Equal(t, 1, memberFixture.queries)
	require.Zero(t, f.begins)
	require.Zero(t, memberFixture.begins)
}
