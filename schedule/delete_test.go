package schedule

import (
	"context"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/permission"
	"github.com/target/goalert/validation"
	"testing"
)

func TestDeleteManyForAuditTxRequiresTransactionAndRawLimit(t *testing.T) {
	s := &Store{}
	ctx := permission.SystemContext(context.Background(), "Test")
	_, err := s.DeleteManyForAuditTx(ctx, nil, []string{uuid.NewString()}, nil)
	require.True(t, validation.IsValidationError(err))
	ids := make([]string, 51)
	for i := range ids {
		ids[i] = uuid.NewString()
	}
	_, err = s.DeleteManyForAuditTx(ctx, nil, ids, nil)
	require.Error(t, err)
	_, err = s.DeleteManyForAuditTx(context.Background(), nil, ids, nil)
	require.True(t, permission.IsPermissionError(err))
}
