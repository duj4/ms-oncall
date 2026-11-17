package updateguard

import (
	"context"
	"database/sql"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
	ds "github.com/target/goalert/deletionsafety"
)

func TestTransactionAndReceiptConfinement(t *testing.T) {
	ctx := context.Background()
	tx, foreign := new(sql.Tx), new(sql.Tx)
	a := ds.Resource{Kind: ds.ResourceEscalationPolicyAction, ID: "synthetic-action"}
	b := ds.Resource{Kind: ds.ResourceScheduleRule, ID: "synthetic-rule"}
	require.Error(t, Require(ctx, tx))
	bound, err := Bind(ctx, tx, []ds.Resource{a})
	require.NoError(t, err)
	require.Error(t, Require(bound, foreign))
	require.Error(t, Complete(bound, tx))
	require.Error(t, Consume(bound, tx, b))
	require.Error(t, Consume(bound, tx, a, a))
	require.NoError(t, Consume(bound, tx, a))
	require.Error(t, Consume(bound, tx, a))
	require.NoError(t, Complete(bound, tx))
	_, err = Bind(ctx, tx, []ds.Resource{{Kind: ds.ResourceUser, ID: "not-an-update-child"}})
	require.Error(t, err)
}

func TestConcurrentCapabilityCannotConsumeTwice(t *testing.T) {
	tx := new(sql.Tx)
	a := ds.Resource{Kind: ds.ResourceScheduleRule, ID: "synthetic-rule"}
	ctx, err := Bind(context.Background(), tx, []ds.Resource{a})
	require.NoError(t, err)
	var successes atomic.Int64
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			if Consume(ctx, tx, a) == nil {
				successes.Add(1)
			}
		})
	}
	wg.Wait()
	require.EqualValues(t, 1, successes.Load())
	require.NoError(t, Complete(ctx, tx))
}
