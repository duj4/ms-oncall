package override

import (
	"context"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/override/deleteaudit"
	"github.com/target/goalert/permission"
	"testing"
)

func TestAuditedDeleteRequiresSuppliedTransaction(t *testing.T) {
	s := &Store{}
	result, err := s.DeleteUserOverrideForAuditTx(permission.SystemContext(context.Background(), "Test"), nil, []string{uuid.NewString()}, nil)
	require.ErrorIs(t, err, deleteaudit.ErrUnavailable)
	require.Empty(t, result.Targets)
	require.Empty(t, result.Receipts)
}
