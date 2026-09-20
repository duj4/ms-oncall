package graphqlapp

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/graphql2"
)

func TestCalendarUpdateProductPolicyBeforeStoreAndTransaction(t *testing.T) {
	// A missing Store/database proves rejection precedes both the transaction
	// and FindOneForUpdate, independently of the Store's own product guard.
	for _, id := range []string{uuid.NewString(), uuid.NewString(), "malformed"} {
		ok, err := new(App).Mutation().UpdateUserCalendarSubscription(context.Background(), graphql2.UpdateUserCalendarSubscriptionInput{ID: id})
		require.False(t, ok)
		require.EqualError(t, err, "disabled by administrator")
	}
}
