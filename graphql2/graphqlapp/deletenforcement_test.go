package graphqlapp

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/target/goalert/assignment"
	ds "github.com/target/goalert/deletionsafety"
	"github.com/target/goalert/graphql2"
)

func TestDeletionEnforcementSessionCompatibility(t *testing.T) {
	ctx := context.Background()
	session := assignment.RawTarget{Type: assignment.TargetTypeUserSession, ID: "synthetic-session-selector"}
	for _, input := range [][]assignment.RawTarget{{session}, {session, session}} {
		bound, err := enforceDeleteAll(ctx, nil, input, nil)
		require.NoError(t, err)
		require.Equal(t, ctx, bound, "SD9 must receive the original authority context")
	}
	// Both orders must fail before accessing a transaction, even when a caller
	// supplies confirmation. No mixed batch can enter the compatibility path.
	for _, typ := range []assignment.TargetType{
		assignment.TargetTypeUser, assignment.TargetTypeService,
		assignment.TargetTypeEscalationPolicy, assignment.TargetTypeSchedule,
		assignment.TargetTypeRotation, assignment.TargetTypeContactMethod,
		assignment.TargetTypeNotificationRule, assignment.TargetTypeIntegrationKey,
		assignment.TargetTypeUserOverride, assignment.TargetTypeCalendarSubscription,
		assignment.TargetTypeHeartbeatMonitor, assignment.TargetType(-1),
	} {
		t.Run(typ.String(), func(t *testing.T) {
			other := assignment.RawTarget{Type: typ, ID: "synthetic-other-selector"}
			for _, input := range [][]assignment.RawTarget{{session, other}, {other, session}} {
				_, err := enforceDeleteAll(ctx, nil, input, &graphql2.DeletionSafetyConfirmationInput{ExpectedImpactVersion: "guessed", AcknowledgeImpacts: true})
				typed, ok := deletionSafetyError(err)
				require.True(t, ok)
				require.Equal(t, ds.DeletionUnavailable, typed.Code)
			}
		})
	}
	require.Len(t, deleteTargetKinds, 9)
	_, generalRoot := deleteTargetKinds[assignment.TargetTypeUserSession]
	require.False(t, generalRoot)
}

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
