package smoke

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/assignment"
	"github.com/target/goalert/label"
	"github.com/target/goalert/permission"
	"github.com/target/goalert/test/smoke/harness"
)

func TestServiceLabelForeignLockRejection(t *testing.T) {
	h := serviceLabelHarness(t)
	app := serviceLabelApp(h)
	for _, value := range []string{"updated", ""} {
		t.Run("foreign/value="+value, func(t *testing.T) {
			before := serviceLabelSnapshot(t, h, "b")
			ctx, cancel := context.WithTimeout(serviceLabelHuman(t, h, "user-a"), 2*time.Second)
			defer cancel()
			blocker, err := h.App().DB().BeginTx(t.Context(), nil)
			require.NoError(t, err)
			defer blocker.Rollback()
			var key string
			require.NoError(t, blocker.QueryRow(`SELECT key FROM labels WHERE tgt_service_id=$1 AND key='org/shared' FOR UPDATE`, serviceLabelID("b")).Scan(&key))
			ok, err := app.Mutation().SetLabel(ctx, serviceLabelInput("b", key, value))
			// The blocker is still held. A lock wait would time out, not return
			// the scoped rejection, and no release is used to let it proceed.
			require.False(t, ok)
			require.ErrorIs(t, err, sql.ErrNoRows)
			require.NoError(t, ctx.Err())
			require.Equal(t, before, serviceLabelSnapshot(t, h, "b"))
			require.NoError(t, blocker.Rollback())
			require.Equal(t, before, serviceLabelSnapshot(t, h, "b"))
		})
	}
	t.Run("same organization retains label locking", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(serviceLabelHuman(t, h, "user-a"), 5*time.Second)
		defer cancel()
		blocker, err := h.App().DB().BeginTx(t.Context(), nil)
		require.NoError(t, err)
		defer blocker.Rollback()
		var key string
		require.NoError(t, blocker.QueryRow(`SELECT key FROM labels WHERE tgt_service_id=$1 AND key='org/shared' FOR UPDATE`, serviceLabelID("a")).Scan(&key))
		done := make(chan error, 1)
		go func() {
			_, err := app.Mutation().SetLabel(ctx, serviceLabelInput("a", key, "updated"))
			done <- err
		}()
		// Observe an actual PostgreSQL wait instead of assuming a goroutine
		// has reached the database after an arbitrary sleep.
		require.Eventually(t, func() bool {
			var waiting bool
			err := h.App().DB().QueryRowContext(ctx, `SELECT EXISTS (
			 SELECT 1 FROM pg_stat_activity WHERE datname=current_database()
			 AND wait_event_type='Lock' AND query LIKE '%INSERT INTO labels%')`).Scan(&waiting)
			return err == nil && waiting
		}, 2*time.Second, 10*time.Millisecond)
		require.NoError(t, blocker.Rollback())
		require.NoError(t, <-done)
		var value string
		require.NoError(t, h.App().DB().QueryRow(`SELECT value FROM labels WHERE tgt_service_id=$1 AND key=$2`, serviceLabelID("a"), key).Scan(&value))
		require.Equal(t, "updated", value)
	})
}

func TestServiceLabelStoreTransactionScope(t *testing.T) {
	h := serviceLabelHarness(t)
	s := h.App().LabelStore
	ctx := permission.SystemContext(t.Context(), "Smoketest")
	org := uuid.MustParse(harness.SmokeOrganizationID)
	for _, target := range []string{"a", "b"} {
		t.Run(target, func(t *testing.T) {
			before := serviceLabelSnapshot(t, h, target)
			tx, err := h.App().DB().BeginTx(ctx, nil)
			require.NoError(t, err)
			defer tx.Rollback()
			err = s.SetTx(ctx, tx, &label.Label{Target: assignment.ServiceTarget(serviceLabelID(target)), Key: "new/transaction", Value: "value"}, &org)
			if target == "b" {
				require.ErrorIs(t, err, sql.ErrNoRows)
			} else {
				require.NoError(t, err)
				keys, err := s.UniqueKeysTx(ctx, tx, &org)
				require.NoError(t, err)
				require.Contains(t, keys, "new/transaction")
				keys, err = s.UniqueKeysTx(ctx, h.App().DB(), &org)
				require.NoError(t, err)
				require.NotContains(t, keys, "new/transaction")
			}
			// Rejection must leave a caller-owned transaction usable.
			var one int
			require.NoError(t, tx.QueryRow(`SELECT 1`).Scan(&one))
			require.NoError(t, tx.Rollback())
			require.Equal(t, before, serviceLabelSnapshot(t, h, target))
		})
	}
	t.Run("parent lookup uses caller transaction and adds no parent lock", func(t *testing.T) {
		tx, err := h.App().DB().BeginTx(ctx, nil)
		require.NoError(t, err)
		defer tx.Rollback()
		_, err = tx.Exec(`INSERT INTO services(id,organization_id,name,escalation_policy_id) VALUES($1,$2,'transaction service',$3)`, serviceLabelID("uncommitted"), org, serviceLabelID("policy-a"))
		require.NoError(t, err)
		err = s.SetTx(ctx, tx, &label.Label{Target: assignment.ServiceTarget(serviceLabelID("uncommitted")), Key: "new/transaction", Value: "value"}, &org)
		require.NoError(t, err)
		err = s.SetTx(ctx, tx, &label.Label{Target: assignment.ServiceTarget(serviceLabelID("a")), Key: "org/shared", Value: ""}, &org)
		require.NoError(t, err)
		other, err := h.App().DB().BeginTx(ctx, nil)
		require.NoError(t, err)
		defer other.Rollback()
		var id string
		require.NoError(t, other.QueryRow(`SELECT id FROM services WHERE id=$1 FOR UPDATE NOWAIT`, serviceLabelID("a")).Scan(&id))
	})
	for _, scope := range []*uuid.UUID{nil, &org} {
		keys, err := s.UniqueKeysTx(ctx, h.App().DB(), scope)
		require.NoError(t, err)
		rows, err := s.FindAllByService(ctx, h.App().DB(), serviceLabelID("b"), scope)
		require.NoError(t, err)
		if scope == nil {
			require.Contains(t, keys, "bbb/foreign")
			require.Len(t, rows, 3)
		} else {
			require.NotContains(t, keys, "bbb/foreign")
			require.Empty(t, rows)
		}
	}
}
