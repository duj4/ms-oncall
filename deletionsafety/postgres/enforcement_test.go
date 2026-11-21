package postgres

import (
	"context"
	"database/sql"
	"testing"

	"github.com/stretchr/testify/require"
	ds "github.com/target/goalert/deletionsafety"
	guard "github.com/target/goalert/internal/deletionguard"
)

func TestNativeProfileRequiresRealStability(t *testing.T) {
	root := ds.Resource{Kind: ds.ResourceNotificationRule, ID: "00000000-0000-4000-8000-000000000001"}
	require.False(t, guard.StableNR(context.Background(), new(sql.Tx), root))
	require.False(t, guard.StableNR(context.Background(), nil, root))
	require.Error(t, guard.RequireDelete(context.Background(), new(sql.Tx), root.Kind, []string{root.ID}))
	// No other root can consume a carrier, even under a System-like marker.
	for kind := ds.ResourceService; kind <= ds.ResourceScheduleTarget; kind++ {
		if kind == ds.ResourceNotificationRule {
			continue
		}
		require.Error(t, guard.RequireDelete(context.Background(), new(sql.Tx), kind, []string{root.ID}))
	}
}
