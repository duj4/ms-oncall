package schedulejsonguard

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	audit "github.com/target/goalert/schedule/jsonupdateaudit"
)

func TestExactTransactionAndImmutableCoverageCapability(t *testing.T) {
	before := []audit.Coverage{{Kind: "temporary", Start: "0", End: "100"}}
	after := []audit.Coverage{{Kind: "temporary", Start: "0", End: "30"}, {Kind: "temporary", Start: "70", End: "100"}}
	effects, err := audit.Diff(before, after)
	require.NoError(t, err)
	e := audit.Event{Version: 1, EventID: uuid.New(), AttemptID: uuid.New(), RequestID: uuid.New(), ActorKind: "internal_system", AuthoritySource: "trusted_internal_system", AuthorityRole: "internal_system", OrganizationRole: "unknown", ScheduleID: uuid.New(), OrganizationID: uuid.New(), EnvelopeID: 1, Operation: audit.Clear, Mode: "clear", OccurredAt: time.Now(), Before: before, After: after, Effects: effects}
	ctx := context.Background()
	tx := new(sql.Tx)
	require.Error(t, Authorize(ctx, tx, e.ScheduleID, 1, e.Operation, e.Mode, before, after))
	bound, err := Bind(ctx, tx, e)
	require.NoError(t, err)
	require.True(t, Bound(bound, tx))
	require.NoError(t, Authorize(bound, tx, e.ScheduleID, 1, e.Operation, e.Mode, before, after))
	for _, bad := range []struct {
		tx       *sql.Tx
		id       uuid.UUID
		envelope int64
		op, mode string
	}{
		{new(sql.Tx), e.ScheduleID, 1, e.Operation, e.Mode}, {tx, uuid.New(), 1, e.Operation, e.Mode}, {tx, e.ScheduleID, 2, e.Operation, e.Mode}, {tx, e.ScheduleID, 1, audit.Set, "set"},
	} {
		require.Error(t, Authorize(bound, bad.tx, bad.id, bad.envelope, bad.op, bad.mode, before, after))
	}
	e.Before[0].End = "90" // caller's slices cannot mutate the bound grant
	require.Error(t, Authorize(bound, tx, e.ScheduleID, 1, e.Operation, e.Mode, e.Before, after))
	original := []audit.Coverage{{Kind: "temporary", Start: "0", End: "100"}}
	require.NoError(t, Authorize(bound, tx, e.ScheduleID, 1, e.Operation, e.Mode, original, after))
	g := bound.Value(key{}).(*grant)
	g.used.Store(true)
	require.False(t, Bound(bound, tx))
	require.Error(t, Authorize(bound, tx, e.ScheduleID, 1, e.Operation, e.Mode, original, after))
}
