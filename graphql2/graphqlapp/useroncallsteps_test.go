package graphqlapp

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/auth"
	"github.com/target/goalert/executioncontext"
	"github.com/target/goalert/permission"
	"github.com/target/goalert/user"
)

func TestUserOnCallStepsAuthorityBeforeStore(t *testing.T) {
	id, session := uuid.NewString(), uuid.NewString()
	requester, err := auth.NewRequester(id, session)
	require.NoError(t, err)
	for _, role := range []permission.Role{permission.RoleUser, permission.RoleAdmin} {
		t.Run(string(role), func(t *testing.T) {
			legacy := permission.UserSourceContext(context.Background(), id, role,
				&permission.SourceInfo{Type: permission.SourceTypeAuthProvider, ID: session})
			for name, ctx := range map[string]context.Context{
				"missing requester": legacy,
				"missing authority": auth.WithRequester(legacy, requester),
				"zero authority": executioncontext.WithExecutionContext(auth.WithRequester(legacy, requester),
					executioncontext.ExecutionContext{}),
				"inconsistent source": auth.WithRequester(permission.UserSourceContext(context.Background(), id, role,
					&permission.SourceInfo{Type: permission.SourceTypeGQLAPIKey, ID: session}), requester),
				"inconsistent session": auth.WithRequester(permission.UserSourceContext(context.Background(), id, role,
					&permission.SourceInfo{Type: permission.SourceTypeAuthProvider, ID: uuid.NewString()}), requester),
			} {
				t.Run(name, func(t *testing.T) {
					// No Store or database: authority must fail before materialization.
					for _, target := range []string{id, uuid.NewString(), "bad"} {
						steps, err := new(App).User().OnCallSteps(ctx, &user.User{ID: target})
						require.Nil(t, steps)
						require.True(t, permission.IsPermissionError(err))
					}
				})
			}
		})
	}
}
