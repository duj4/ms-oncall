package postgres

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	ds "github.com/target/goalert/deletionsafety"
)

func TestUserBatchScopeFactsAreCanonical(t *testing.T) {
	user := ds.Resource{Kind: ds.ResourceUser, ID: "00000000-0000-4000-8000-000000000001"}
	a, b := strings.Repeat("a", 64), strings.Repeat("b", 64)
	one, err := BatchScopeFingerprint([]ds.Resource{user}, []string{a})
	require.NoError(t, err)
	require.Equal(t, a, one)
	forward, err := BatchScopeFingerprint([]ds.Resource{user, user}, []string{a, b})
	require.NoError(t, err)
	reverse, err := BatchScopeFingerprint([]ds.Resource{user, user}, []string{b, a})
	require.NoError(t, err)
	require.Equal(t, forward, reverse)
	require.NotEqual(t, a, forward)
	_, err = BatchScopeFingerprint([]ds.Resource{user}, []string{"invalid"})
	require.Error(t, err)
	_, err = BatchScopeFingerprint(nil, nil)
	require.Error(t, err)
	service := ds.Resource{Kind: ds.ResourceService, ID: user.ID}
	_, err = BatchScopeFingerprint([]ds.Resource{service, service}, []string{a, b})
	require.Error(t, err)
	legacy, err := BatchScopeFingerprint([]ds.Resource{service, service}, []string{a, a})
	require.NoError(t, err)
	require.Equal(t, a, legacy)
}
