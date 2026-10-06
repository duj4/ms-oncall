package graphqlapp

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/auth"
	"github.com/target/goalert/executioncontext"
	"github.com/target/goalert/graphql2"
	"github.com/target/goalert/permission"
)

func TestMultiAckHumanAuthorityBeforeTransaction(t *testing.T) {
	userID, sessionID := uuid.NewString(), uuid.NewString()
	source := &permission.SourceInfo{Type: permission.SourceTypeAuthProvider, ID: sessionID}
	human := permission.UserSourceContext(context.Background(), userID, permission.RoleUser, source)
	requester, err := auth.NewRequester(userID, sessionID)
	require.NoError(t, err)
	withRequester := auth.WithRequester(human, requester)
	legacyAdmin := permission.UserSourceContext(context.Background(), userID, permission.RoleAdmin, source)
	contexts := map[string]context.Context{
		"legacy Admin missing Requester":        legacyAdmin,
		"legacy Admin missing ExecutionContext": auth.WithRequester(legacyAdmin, requester),
		"missing Requester":                     human,
		"invalid Requester":                     auth.WithRequester(human, auth.Requester{}),
		"missing ExecutionContext":              withRequester,
		"invalid ExecutionContext":              executioncontext.WithExecutionContext(withRequester, executioncontext.ExecutionContext{}),
		"permission User mismatch":              auth.WithRequester(permission.UserSourceContext(context.Background(), uuid.NewString(), permission.RoleUser, source), requester),
		"permission Session mismatch": auth.WithRequester(permission.UserSourceContext(context.Background(), userID, permission.RoleUser,
			&permission.SourceInfo{Type: permission.SourceTypeAuthProvider, ID: uuid.NewString()}), requester),
		"Requester with API key source": auth.WithRequester(permission.UserSourceContext(context.Background(), userID, permission.RoleUser,
			&permission.SourceInfo{Type: permission.SourceTypeGQLAPIKey, ID: uuid.NewString()}), requester),
		"Requester without source": auth.WithRequester(permission.UserContext(context.Background(), userID, permission.RoleUser), requester),
	}
	for name, ctx := range contexts {
		t.Run(name, func(t *testing.T) {
			for _, enabled := range []bool{false, true} {
				// Nil DB and Stores: invalid authority must fail before even
				// beginning a transaction, for either MultiAck value.
				policyID := uuid.NewString()
				step, err := new(App).Mutation().CreateEscalationPolicyStep(ctx, graphql2.CreateEscalationPolicyStepInput{
					EscalationPolicyID: &policyID, DelayMinutes: 60, MultiAck: &enabled,
				})
				require.Nil(t, step)
				require.True(t, permission.IsPermissionError(err), "%v", err)
				ok, err := new(App).Mutation().UpdateEscalationPolicyStep(ctx, graphql2.UpdateEscalationPolicyStepInput{ID: uuid.NewString(), MultiAck: &enabled})
				require.False(t, ok)
				require.True(t, permission.IsPermissionError(err), "%v", err)
			}
		})
	}
}
