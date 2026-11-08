package graphqlapp

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/rootcreateaudit"
)

type unknownCommitGatedConnector struct {
	state           *createFaultState
	gate, completed chan struct{}
}

func (c unknownCommitGatedConnector) Connect(context.Context) (driver.Conn, error) {
	return &unknownCommitGatedConn{createFaultConn: &createFaultConn{state: c.state}, gate: c.gate, completed: c.completed}, nil
}
func (unknownCommitGatedConnector) Driver() driver.Driver { return createFaultDriver{} }

type unknownCommitGatedConn struct {
	*createFaultConn
	gate, completed chan struct{}
}

func (c *unknownCommitGatedConn) Begin() (driver.Tx, error) {
	tx, err := c.createFaultConn.Begin()
	return unknownCommitGatedTx{Tx: tx, gate: c.gate, completed: c.completed}, err
}

type unknownCommitGatedTx struct {
	driver.Tx
	gate, completed chan struct{}
}

func (tx unknownCommitGatedTx) Commit() error {
	<-tx.gate
	err := tx.Tx.Commit()
	close(tx.completed)
	return err
}

func TestRootCreateDelayedCommitUnknownAndEventualRelease(t *testing.T) {
	state := &createFaultState{mode: "success"}
	gate, completed := make(chan struct{}), make(chan struct{})
	db := sql.OpenDB(unknownCommitGatedConnector{state, gate, completed})
	gateClosed := false
	defer func() {
		if !gateClosed {
			close(gate)
		}
		db.Close()
	}()
	id, target := uuid.New(), uuid.New()
	event := rootcreateaudit.Event{EventID: uuid.New(), AttemptID: uuid.New(), RequestID: uuid.New(), ActorID: uuid.New(), HomeOrganizationID: uuid.New(), OrganizationRole: "ORG_MEMBER", RootType: "service", TargetOrganizationID: target, Outcome: "validation_failed", Reason: "invalid_fields", OccurredAt: time.Now()}
	plan := &rootCreatePlan{ctx: t.Context(), db: db, target: target, audited: true, event: event}
	started := time.Now()
	err := plan.withTx(t.Context(), func(ctx context.Context, tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, "A12 synthetic root create")
		return err
	}, func() string { return id.String() })
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.True(t, plan.attempted)
	require.False(t, plan.committed)
	require.False(t, plan.finalized)
	err = plan.finish(err)
	require.Error(t, err)
	require.Less(t, time.Since(started), 8*time.Second)
	require.Equal(t, "commit_unknown", plan.event.Outcome)
	require.Equal(t, "commit_unconfirmed", plan.event.Reason)
	require.Equal(t, 1, state.creates)
	require.Empty(t, state.events, "no independent failure append before release barrier")
	require.Equal(t, 1, db.Stats().InUse)
	close(gate)
	gateClosed = true
	select {
	case <-completed:
	case <-time.After(3 * time.Second):
		t.Fatal("controlled Commit did not finish")
	}
	require.Eventually(t, func() bool { return db.Stats().InUse == 0 }, 3*time.Second, 10*time.Millisecond)
	require.Equal(t, 1, state.committedRoots)
	require.Len(t, state.events, 1)
	require.Equal(t, "committed", state.events[0][9].Value)
	require.Equal(t, "created", state.events[0][10].Value)
	require.Equal(t, id.String(), state.events[0][7].Value)
	require.Equal(t, target.String(), state.events[0][8].Value)
	require.Equal(t, event.AttemptID.String(), state.events[0][1].Value)
	require.Equal(t, event.RequestID.String(), state.events[0][2].Value)
	require.Equal(t, 1, state.creates, "timeout and release must never replay Create")
	t.Log("controlled driver wait: bounded unknown response, no false rollback/independent append/replay, eventual connection release")
}
