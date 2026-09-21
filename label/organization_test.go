package label

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/assignment"
	"github.com/target/goalert/permission"
)

func TestStoreScopeValidationBeforeSQL(t *testing.T) {
	s := &Store{}
	ctx := permission.SystemContext(context.Background(), "test")
	zero := uuid.Nil
	const scopeError = "invalid value for 'OrganizationID': must be specified"
	l := &Label{Target: assignment.ServiceTarget("00000000-0000-0000-0000-000000000003"), Key: "own/key", Value: "value"}
	require.EqualError(t, s.SetTx(ctx, nil, l, &zero), scopeError)
	_, err := s.FindAllByService(ctx, nil, l.Target.TargetID(), &zero)
	require.EqualError(t, err, scopeError)
	_, err = s.UniqueKeysTx(ctx, nil, &zero)
	require.EqualError(t, err, scopeError)
	_, err = s.SearchKeys(ctx, nil, &zero)
	require.EqualError(t, err, scopeError)
	_, err = s.SearchValues(ctx, nil, &zero)
	require.EqualError(t, err, scopeError)

	l.Key = "bad"
	require.EqualError(t, s.SetTx(ctx, nil, l, &zero), "invalid value for 'Key': prefix and suffix must be separated by `/`")
	_, err = s.SearchKeys(ctx, &KeySearchOptions{Omit: []string{"bad"}}, &zero)
	require.EqualError(t, err, "invalid value for 'Omit[0]': prefix and suffix must be separated by `/`")
	_, err = s.SearchValues(ctx, &ValueSearchOptions{KeySearchOptions: KeySearchOptions{Limit: -1}}, &zero)
	require.EqualError(t, err, "invalid value for 'Limit': must not be negative")
	require.True(t, permission.IsPermissionError(s.SetTx(context.Background(), nil, l, &zero)))
}
