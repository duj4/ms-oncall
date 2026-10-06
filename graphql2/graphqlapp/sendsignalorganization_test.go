package graphqlapp

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/auth"
	"github.com/target/goalert/executioncontext"
	"github.com/target/goalert/expflag"
	"github.com/target/goalert/graphql2"
	"github.com/target/goalert/permission"
	"github.com/target/goalert/validation"
)

func TestSendSignalHumanAuthorityBeforeStores(t *testing.T) {
	userID, sessionID := uuid.NewString(), uuid.NewString()
	source := &permission.SourceInfo{Type: permission.SourceTypeAuthProvider, ID: sessionID}
	human := permission.UserSourceContext(context.Background(), userID, permission.RoleUser, source)
	requester, err := auth.NewRequester(userID, sessionID)
	require.NoError(t, err)
	withRequester := auth.WithRequester(human, requester)

	contexts := map[string]context.Context{
		"missing Requester":        human,
		"invalid Requester":        auth.WithRequester(human, auth.Requester{}),
		"missing ExecutionContext": withRequester,
		"invalid ExecutionContext": executioncontext.WithExecutionContext(withRequester, executioncontext.ExecutionContext{}),
		"permission User mismatch": auth.WithRequester(permission.UserSourceContext(context.Background(), uuid.NewString(), permission.RoleUser, source), requester),
		"permission Session mismatch": auth.WithRequester(permission.UserSourceContext(context.Background(), userID, permission.RoleUser,
			&permission.SourceInfo{Type: permission.SourceTypeAuthProvider, ID: uuid.NewString()}), requester),
		"Requester with API key source": auth.WithRequester(permission.UserSourceContext(context.Background(), userID, permission.RoleUser,
			&permission.SourceInfo{Type: permission.SourceTypeGQLAPIKey, ID: uuid.NewString()}), requester),
		"Requester without source": auth.WithRequester(permission.UserContext(context.Background(), userID, permission.RoleUser), requester),
	}
	for name, ctx := range contexts {
		t.Run(name, func(t *testing.T) {
			ctx = expflag.Context(ctx, expflag.FlagSet{expflag.UnivKeys})
			// Nil Stores and destination: denial must precede either Store and
			// even dereferencing the destination, without a recover fallback.
			ok, err := new(App).Mutation().SendSignal(ctx, graphql2.SendSignalInput{ServiceID: uuid.NewString()})
			require.False(t, ok)
			require.True(t, permission.IsPermissionError(err), "%v", err)
		})
	}
}

func TestSendSignalValidationBeforeHumanAuthority(t *testing.T) {
	app := new(App)
	input := graphql2.SendSignalInput{ServiceID: "invalid-service-id"}
	ok, err := app.Mutation().SendSignal(expflag.Context(context.Background(), expflag.FlagSet{expflag.UnivKeys}), input)
	require.False(t, ok)
	require.True(t, permission.IsPermissionError(err))

	// An AuthProvider source without Requester would fail classification, but
	// the pre-existing feature and UUID validations still precede it.
	ctx := permission.UserSourceContext(context.Background(), uuid.NewString(), permission.RoleUser,
		&permission.SourceInfo{Type: permission.SourceTypeAuthProvider, ID: uuid.NewString()})
	ok, err = app.Mutation().SendSignal(ctx, input)
	require.False(t, ok)
	require.EqualError(t, err, "feature not enabled")

	ok, err = app.Mutation().SendSignal(expflag.Context(ctx, expflag.FlagSet{expflag.UnivKeys}), input)
	require.False(t, ok)
	var fieldErr validation.FieldError
	require.ErrorAs(t, err, &fieldErr)
	require.Equal(t, "ServiceID", fieldErr.Field())
}
