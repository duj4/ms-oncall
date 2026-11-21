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

func TestRotationRequestedAndReturnedIdentities(t *testing.T) {
	tx := new(sql.Tx)
	part := ds.Resource{Kind: ds.ResourceRotationParticipant, ID: "participant"}
	state := ds.Resource{Kind: ds.ResourceRotationState, ID: "42"}
	ctx, err := Bind(context.Background(), tx, []ds.Resource{part, state})
	require.NoError(t, err)
	require.Error(t, Check(ctx, new(sql.Tx), part))
	require.Error(t, Check(ctx, tx, part, part))
	require.Error(t, Check(ctx, tx, ds.Resource{Kind: part.Kind, ID: "unconfirmed"}))
	require.NoError(t, Check(ctx, tx, part, state))
	require.NoError(t, Consume(ctx, tx, state))
	require.Error(t, Check(ctx, tx, state))
	require.Error(t, Complete(ctx, tx))
	require.NoError(t, Consume(ctx, tx, part))
	require.NoError(t, Complete(ctx, tx))
}
