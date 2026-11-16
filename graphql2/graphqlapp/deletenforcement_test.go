package graphqlapp

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	ds "github.com/target/goalert/deletionsafety"
	"github.com/target/goalert/graphql2"
)

func TestDeletionEnforcementSafeErrorChain(t *testing.T) {
	for _, code := range []ds.ErrorCode{ds.DeletionBlocked, ds.DeletionConfirmationRequired, ds.DeletionDependencyChanged, ds.DeletionUnavailable, ds.DeletionPreviewLimitExceeded} {
		raw := errors.Join(errors.New("SYNTHETIC_PRIVATE_SQL_DETAIL"), &ds.DeletionSafetyError{Code: code})
		a := &deleteAllAttempt{plan: &deleteAllAudit{}}
		safe := a.safeError(raw)
		typed, ok := deletionSafetyError(safe)
		require.True(t, ok)
		require.Equal(t, code, typed.Code)
		out := deletionPreviewGraphQLError(context.Background(), safe)
		require.Equal(t, graphql2.ErrorCode(code), out.Extensions["code"])
		require.NotContains(t, out.Message, "SYNTHETIC_PRIVATE")
		// Audit/Commit failures must retain their original finalization contract.
		a.commitAttempted = true
		require.NotEqual(t, typed, a.safeError(errors.New("SYNTHETIC_PRIVATE_AUDIT")))
	}
}
