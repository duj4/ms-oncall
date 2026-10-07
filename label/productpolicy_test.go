package label

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/assignment"
	"github.com/target/goalert/permission"
)

func TestLabelProductPolicyBeforeDatabase(t *testing.T) {
	// No DB, DBTX, or transaction exists: any attempted SQL would panic.
	s := new(Store)
	userID := uuid.NewString()
	contexts := []context.Context{
		context.Background(),
		permission.UserContext(context.Background(), userID, permission.RoleUser),
		permission.UserContext(context.Background(), userID, permission.RoleAdmin),
		permission.SystemContext(context.Background(), "test"),
		permission.UserSourceContext(context.Background(), userID, permission.RoleAdmin, &permission.SourceInfo{Type: permission.SourceTypeGQLAPIKey}),
	}
	zero, org := uuid.Nil, uuid.New()
	targets := []assignment.Target{assignment.ServiceTarget(uuid.NewString()), assignment.ScheduleTarget(uuid.NewString()), assignment.RotationTarget(uuid.NewString()), assignment.EscalationPolicyTarget(uuid.NewString())}
	for _, ctx := range contexts {
		for _, scope := range []*uuid.UUID{nil, &zero, &org} {
			for _, tgt := range targets {
				for _, value := range []string{"create", "update", "same-value", ""} {
					require.ErrorIs(t, s.SetTx(ctx, nil, &Label{Target: tgt, Key: "policy/key", Value: value}, scope), ErrDisabled)
				}
				rows, err := s.FindAllByTarget(ctx, nil, tgt)
				require.Nil(t, rows)
				require.ErrorIs(t, err, ErrDisabled)
			}
			_, err := s.FindAllByService(ctx, nil, uuid.NewString(), scope)
			require.ErrorIs(t, err, ErrDisabled)
			_, err = s.UniqueKeysTx(ctx, nil, scope)
			require.ErrorIs(t, err, ErrDisabled)
			for _, after := range []string{"", "policy/key", "malformed"} {
				_, err = s.SearchKeys(ctx, &KeySearchOptions{After: after}, scope)
				require.ErrorIs(t, err, ErrDisabled)
				_, err = s.SearchValues(ctx, &ValueSearchOptions{Key: "policy/key", KeySearchOptions: KeySearchOptions{After: after}}, scope)
				require.ErrorIs(t, err, ErrDisabled)
			}
		}
		require.ErrorIs(t, s.SetTx(ctx, nil, nil, nil), ErrDisabled)
	}
}
