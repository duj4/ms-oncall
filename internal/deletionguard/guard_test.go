package guard

import (
	"context"
	"database/sql"
	"testing"

	"github.com/stretchr/testify/require"
	ds "github.com/target/goalert/deletionsafety"
)

func TestUncertifiedAndWrongProfileCannotDelete(t *testing.T) {
	ctx := context.Background()
	tx := new(sql.Tx)
	for kind := ds.ResourceService; kind <= ds.ResourceScheduleTarget; kind++ {
		require.Error(t, RequireDelete(ctx, tx, kind, []string{"00000000-0000-4000-8000-000000000001"}))
	}
	_, err := ConsumeNR(ctx, tx, []string{"00000000-0000-4000-8000-000000000001"})
	require.Error(t, err)
	// Even an internal marker cannot authorize a fabricated zero stability proof.
	fake := context.WithValue(ctx, stabilityKey{}, &stability{})
	require.False(t, StableNR(fake, tx, ds.Resource{Kind: ds.ResourceNotificationRule, ID: "00000000-0000-4000-8000-000000000001"}))
}

func TestCertificationEpochCannotBeRestored(t *testing.T) {
	tx := new(sql.Tx)
	first, old := nextEpoch(tx)
	second, newer := nextEpoch(tx)
	require.Same(t, first, second)
	require.Greater(t, newer, old)
	// An old generation is permanently invalid without querying an uninitialized
	// SQL transaction. SQL witness rollback alone cannot reactivate this token.
	oldToken := &stability{tx: tx, epoch: first, generation: old}
	require.False(t, oldToken.witness(context.Background(), tx, "certified"))
	other, otherGen := nextEpoch(new(sql.Tx))
	require.NotSame(t, first, other)
	require.EqualValues(t, 1, otherGen)
}

func TestNRStabilityRejectsUnsupportedAndRawOverflow(t *testing.T) {
	for _, raw := range [][]Selector{{{Kind: ds.ResourceService, ID: "00000000-0000-4000-8000-000000000001"}}, make([]Selector, 51)} {
		_, _, err := StabilizeNR(context.Background(), new(sql.Tx), raw)
		require.Error(t, err)
	}
}

func TestCMStabilityRejectsOtherRootsAndRawOverflow(t *testing.T) {
	for _, raw := range [][]Selector{{{Kind: ds.ResourceNotificationRule, ID: "00000000-0000-4000-8000-000000000001"}}, {{Kind: ds.ResourceContactMethod, ID: "invalid"}}, make([]Selector, 51)} {
		_, _, err := StabilizeCM(context.Background(), new(sql.Tx), raw)
		require.Error(t, err)
	}
	_, err := ConsumeCM(context.Background(), new(sql.Tx), []string{"00000000-0000-4000-8000-000000000001"})
	require.Error(t, err)
	require.False(t, StableCM(context.Background(), new(sql.Tx), ds.Resource{Kind: ds.ResourceContactMethod, ID: "00000000-0000-4000-8000-000000000001"}))
}

func TestServiceStabilityRejectsOtherRootsAndRawOverflow(t *testing.T) {
	for _, raw := range [][]Selector{{{Kind: ds.ResourceContactMethod, ID: "00000000-0000-4000-8000-000000000001"}}, {{Kind: ds.ResourceService, ID: "invalid"}}, make([]Selector, 51)} {
		_, _, err := StabilizeService(context.Background(), new(sql.Tx), raw)
		require.Error(t, err)
	}
	_, err := ConsumeService(context.Background(), new(sql.Tx), []string{"00000000-0000-4000-8000-000000000001"})
	require.Error(t, err)
	_, err = ServiceTargets(context.Background(), new(sql.Tx), []string{"00000000-0000-4000-8000-000000000001"})
	require.Error(t, err)
	require.False(t, StableService(context.Background(), new(sql.Tx), ds.Resource{Kind: ds.ResourceService, ID: "00000000-0000-4000-8000-000000000001"}))
}

func TestEPStabilityRejectsOtherRootsAndRawOverflow(t *testing.T) {
	ctx, tx := context.Background(), new(sql.Tx)
	for _, raw := range [][]Selector{{{Kind: ds.ResourceService, ID: "00000000-0000-4000-8000-000000000001"}}, {{Kind: ds.ResourceEscalationPolicy, ID: "invalid"}}, make([]Selector, 51)} {
		_, _, err := StabilizeEP(ctx, tx, raw)
		require.Error(t, err)
	}
	_, err := ConsumeEP(ctx, tx, []string{"00000000-0000-4000-8000-000000000001"})
	require.Error(t, err)
	_, err = EPTargets(ctx, tx, []string{"00000000-0000-4000-8000-000000000001"})
	require.Error(t, err)
	require.False(t, StableEP(ctx, tx, ds.Resource{Kind: ds.ResourceEscalationPolicy, ID: "00000000-0000-4000-8000-000000000001"}))
}

func TestScheduleStabilityRejectsOtherRootsAndRawOverflow(t *testing.T) {
	ctx, tx := context.Background(), new(sql.Tx)
	for _, raw := range [][]Selector{{{Kind: ds.ResourceEscalationPolicy, ID: "00000000-0000-4000-8000-000000000001"}}, {{Kind: ds.ResourceSchedule, ID: "invalid"}}, make([]Selector, 51)} {
		_, _, err := StabilizeSchedule(ctx, tx, raw)
		require.Error(t, err)
	}
	_, err := ConsumeSchedule(ctx, tx, []string{"00000000-0000-4000-8000-000000000001"})
	require.Error(t, err)
	_, err = ScheduleTargets(ctx, tx, []string{"00000000-0000-4000-8000-000000000001"})
	require.Error(t, err)
	require.False(t, StableSchedule(ctx, tx, ds.Resource{Kind: ds.ResourceSchedule, ID: "00000000-0000-4000-8000-000000000001"}))
}

func TestRotationStabilityRejectsOtherRootsAndRawOverflow(t *testing.T) {
	ctx, tx := context.Background(), new(sql.Tx)
	for _, raw := range [][]Selector{{{Kind: ds.ResourceSchedule, ID: "00000000-0000-4000-8000-000000000001"}}, {{Kind: ds.ResourceRotation, ID: "invalid"}}, make([]Selector, 51)} {
		_, _, err := StabilizeRotation(ctx, tx, raw)
		require.Error(t, err)
	}
	_, err := ConsumeRotation(ctx, tx, []string{"00000000-0000-4000-8000-000000000001"})
	require.Error(t, err)
	_, err = RotationTargets(ctx, tx, []string{"00000000-0000-4000-8000-000000000001"})
	require.Error(t, err)
	require.False(t, StableRotation(ctx, tx, ds.Resource{Kind: ds.ResourceRotation, ID: "00000000-0000-4000-8000-000000000001"}))
}
