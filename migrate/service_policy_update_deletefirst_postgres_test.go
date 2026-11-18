package migrate

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/graphql2"
	"github.com/target/goalert/permission"
)

func TestPostgresServicePolicyUpdateServiceDeleteFirst(t *testing.T) {
	base, uri, db := boundedAuditDB(t, len(Names()))
	ctx, cancel := context.WithTimeout(permission.SystemContext(base, "ServicePolicyUpdateTest"), 12*time.Second)
	defer cancel()
	app := updateNativeApp(t, ctx, db)
	f := newServicePolicyFixture(t, ctx, db, "none")
	input := f.input()
	confirmation := enforcementPreview(t, ctx, app, graphql2.DeletionResourceInput{Type: graphql2.DeletionTargetTypeService, ID: f.service.String()})
	barrier := &updateNativeBarrier{prefix: "delete from services", ready: make(chan uint32, 1), release: make(chan struct{})}
	cfg, err := pgx.ParseConfig(uri)
	require.NoError(t, err)
	cfg.Tracer = barrier
	ownerDB := stdlib.OpenDB(*cfg)
	defer func() { require.NoError(t, ownerDB.Close()) }()
	owner := updateNativeApp(t, ctx, ownerDB)
	var once sync.Once
	release := func() { once.Do(func() { close(barrier.release) }) }
	defer release()
	done := make(chan error, 1)
	barrier.armed.Store(true)
	go func() {
		_, err := owner.Mutation().DeleteAll(ctx, serviceProfileInput(f.service), confirmation)
		done <- err
	}()
	var pid uint32
	select {
	case pid = <-barrier.ready:
	case err := <-done:
		require.FailNow(t, "delete did not reach DML", "%v", err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	waiter := make(chan error, 1)
	go func() { _, err := app.Mutation().UpdateService(ctx, input); waiter <- err }()
	rotationUpdateBlocked(t, ctx, db, pid, waiter)
	release()
	require.NoError(t, <-done)
	require.Error(t, <-waiter)
	require.Equal(t, 0, enforcementCount(t, ctx, db, `SELECT count(*) FROM services WHERE id=$1`, f.service))
	require.Equal(t, 2, enforcementCount(t, ctx, db, `SELECT count(*) FROM escalation_policies WHERE id IN ($1,$2)`, f.policy, f.next))
	require.Zero(t, enforcementCount(t, ctx, db, `SELECT count(*) FROM service_update_audit_events WHERE service_id=$1 AND outcome='committed'`, f.service))
}
