package oncalljsonguard

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	audit "github.com/target/goalert/schedule/oncallupdateaudit"
)

func TestExactCapability(t *testing.T) {
	id := uuid.New()
	b := []audit.Rule{{ID: id.String() + ":0", Channel: uuid.NewString()}}
	a := []audit.Rule{}
	f, err := audit.Diff(id, b, a)
	require.NoError(t, err)
	e := audit.Event{Version: 1, EventID: uuid.New(), RequestID: uuid.New(), AttemptID: uuid.New(), ActorKind: "internal_system", AuthoritySource: "trusted_internal_system", AuthorityRole: "internal_system", OrganizationRole: "unknown", ScheduleID: id, OrganizationID: uuid.New(), EnvelopeID: 12, Operation: audit.Operation, OccurredAt: time.Now(), Before: b, After: a, Effects: f}
	tx, other := new(sql.Tx), new(sql.Tx)
	base := context.Background()
	require.Error(t, Authorize(base, tx, id, e.OrganizationID, 12, b, a))
	ctx, err := Bind(base, tx, e)
	require.NoError(t, err)
	require.NoError(t, Authorize(ctx, tx, id, e.OrganizationID, 12, b, a))
	require.Error(t, Authorize(ctx, other, id, e.OrganizationID, 12, b, a))
	require.Error(t, Authorize(ctx, tx, uuid.New(), e.OrganizationID, 12, b, a))
	require.Error(t, Authorize(ctx, tx, id, e.OrganizationID, 13, b, a))
	require.Error(t, Authorize(ctx, tx, id, e.OrganizationID, 12, a, b))
	original := b[0].Channel
	e.Before[0].Channel = uuid.NewString()
	require.NoError(t, Authorize(ctx, tx, id, e.OrganizationID, 12, []audit.Rule{{ID: id.String() + ":0", Channel: original}}, a))
	g := ctx.Value(key{}).(*grant)
	g.used.Store(true)
	require.Error(t, Authorize(ctx, tx, id, e.OrganizationID, 12, b, a))
}
