package migrate

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/assignment"
	ds "github.com/target/goalert/deletionsafety"
	"github.com/target/goalert/graphql2"
	"github.com/target/goalert/permission"
)

func TestPostgresServicePolicyUpdateConcurrency(t *testing.T) {
	base, uri, db := boundedAuditDB(t, len(Names()))
	db.SetMaxOpenConns(16)
	for _, mode := range []string{"same_update", "service_delete", "ep_delete", "relation_writer", "policy_writer", "step_writer", "action_writer", "state_writer", "alert_writer", "incoming_alert", "incoming_step", "incoming_action", "organization", "authority"} {
		t.Run(mode, func(t *testing.T) {
			base, cancel := context.WithTimeout(base, 12*time.Second)
			defer cancel()
			ctx := permission.SystemContext(base, "ServicePolicyUpdateTest")
			app := updateNativeApp(t, ctx, db)
			status := "triggered"
			if mode == "service_delete" {
				status = "none"
			}
			f := newServicePolicyFixture(t, ctx, db, status)
			human := previewAdmit(t, base, db, f.actor)
			input := f.input()
			p, err := app.Query().PreviewUpdateService(human, input)
			require.NoError(t, err)
			input.Confirmation = updateNativeConfirmation(p)
			var deletion *graphql2.DeletionSafetyConfirmationInput
			if mode == "service_delete" {
				deletion = enforcementPreview(t, human, app, graphql2.DeletionResourceInput{Type: graphql2.DeletionTargetTypeService, ID: f.service.String()})
			}
			if mode == "ep_delete" {
				deletion = enforcementPreview(t, human, app, graphql2.DeletionResourceInput{Type: graphql2.DeletionTargetTypeEscalationPolicy, ID: f.next.String()})
			}
			barrier := &updateNativeBarrier{prefix: "update services set name", ready: make(chan uint32, 1), release: make(chan struct{})}
			cfg, err := pgx.ParseConfig(uri)
			require.NoError(t, err)
			cfg.Tracer = barrier
			ownerDB := stdlib.OpenDB(*cfg)
			t.Cleanup(func() { require.NoError(t, ownerDB.Close()) })
			owner := updateNativeApp(t, ctx, ownerDB)
			var once sync.Once
			release := func() { once.Do(func() { close(barrier.release) }) }
			t.Cleanup(release)
			done := make(chan error, 1)
			barrier.armed.Store(true)
			go func() { _, err := owner.Mutation().UpdateService(human, input); done <- err }()
			var pid uint32
			select {
			case pid = <-barrier.ready:
			case err := <-done:
				require.FailNow(t, "did not reach protected DML", "%v", err)
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			switch mode {
			case "service_delete", "ep_delete":
				target := assignment.RawTarget{Type: assignment.TargetTypeService, ID: f.service.String()}
				if mode == "ep_delete" {
					target = assignment.RawTarget{Type: assignment.TargetTypeEscalationPolicy, ID: f.next.String()}
				}
				_, err := app.Mutation().DeleteAll(human, []assignment.RawTarget{target}, deletion)
				require.Error(t, err)
			case "same_update":
				second := make(chan error, 1)
				go func() { _, err := app.Mutation().UpdateService(human, input); second <- err }()
				rotationUpdateBlocked(t, ctx, db, pid, second)
				release()
				require.NoError(t, <-done)
				enforceCode(t, <-second, ds.DeletionDependencyChanged)
				return
			default:
				writer, err := db.BeginTx(ctx, nil)
				require.NoError(t, err)
				defer func() { _ = writer.Rollback() }()
				query := `UPDATE services SET escalation_policy_id=escalation_policy_id WHERE id=$1`
				id := f.service
				switch mode {
				case "policy_writer":
					query = `UPDATE escalation_policies SET repeat=repeat WHERE id=$1`
					id = f.next
				case "step_writer":
					query = `UPDATE escalation_policy_steps SET delay=delay WHERE id=$1`
					id = f.step
				case "action_writer":
					query = `UPDATE escalation_policy_actions SET user_id=user_id WHERE escalation_policy_step_id=$1`
					id = f.step
				case "state_writer":
					query = `UPDATE escalation_policy_state SET loop_count=loop_count WHERE service_id=$1`
				case "alert_writer":
					query = `UPDATE alerts SET summary=summary WHERE service_id=$1`
				case "incoming_alert":
					query = `INSERT INTO alerts(service_id,summary,dedup_key) VALUES($1,'Synthetic concurrent Alert',gen_random_uuid()::text)`
				case "incoming_step":
					query = `INSERT INTO escalation_policy_steps(escalation_policy_id,step_number) VALUES($1,1)`
					id = f.policy
				case "incoming_action":
					query = `INSERT INTO escalation_policy_actions(escalation_policy_step_id,user_id) VALUES($1,'` + f.actor.String() + `')`
					id = f.step
				case "organization":
					query = `UPDATE organizations SET display_name=display_name WHERE id=$1`
					id = f.org
				case "authority":
					query = `UPDATE user_organization_assignments SET organization_role=organization_role WHERE user_id=$1`
					id = f.actor
				}
				waiting := serviceProfileWait(t, ctx, db, writer, func() error { _, err := writer.ExecContext(ctx, query, id); return err })
				rotationUpdateBlocked(t, ctx, db, pid, waiting)
				release()
				require.NoError(t, <-done)
				require.NoError(t, <-waiting)
				require.NoError(t, writer.Rollback())
				return
			}
			release()
			require.NoError(t, <-done)
			if mode == "ep_delete" {
				// Once committed, the newly referenced EP must BLOCK under the
				// unchanged Root contract. The old EP remains an independent object.
				p, err := app.Query().DeletionPreview(human, graphql2.DeletionPlanInput{Operation: graphql2.DeletionOperationDeleteResources, Targets: []graphql2.DeletionResourceInput{{Type: graphql2.DeletionTargetTypeEscalationPolicy, ID: f.next.String()}}}, nil, nil)
				require.NoError(t, err)
				require.False(t, p.CanProceed)
				require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM escalation_policies WHERE id=$1`, f.policy))
			}
		})
	}
}

func TestPostgresServicePolicyUpdateWriterFirstRecheck(t *testing.T) {
	base, _, db := boundedAuditDB(t, len(Names()))
	db.SetMaxOpenConns(16)
	for _, mode := range []string{"service_wait", "policy", "state", "alert", "organization", "authority"} {
		t.Run(mode, func(t *testing.T) {
			base, cancel := context.WithTimeout(base, 12*time.Second)
			defer cancel()
			ctx := permission.SystemContext(base, "ServicePolicyUpdateTest")
			app := updateNativeApp(t, ctx, db)
			f := newServicePolicyFixture(t, ctx, db, "triggered")
			human := previewAdmit(t, base, db, f.actor)
			input := f.input()
			p, err := app.Query().PreviewUpdateService(human, input)
			require.NoError(t, err)
			input.Confirmation = updateNativeConfirmation(p)
			writer, err := db.BeginTx(ctx, nil)
			require.NoError(t, err)
			defer func() { _ = writer.Rollback() }()
			query := `UPDATE services SET description='Synthetic waited state' WHERE id=$1`
			id := f.service
			switch mode {
			case "policy":
				query = `UPDATE escalation_policies SET repeat=repeat+1 WHERE id=$1`
				id = f.next
			case "state":
				query = `UPDATE escalation_policy_state SET loop_count=loop_count+1 WHERE service_id=$1`
			case "alert":
				query = `UPDATE alerts SET summary=summary WHERE service_id=$1`
			case "organization":
				query = `UPDATE organizations SET display_name=display_name WHERE id=$1`
				id = f.org
			case "authority":
				query = `UPDATE user_organization_assignments SET organization_role='ORG_MEMBER' WHERE user_id=$1`
				id = f.actor
			}
			_, err = writer.ExecContext(ctx, query, id)
			require.NoError(t, err)
			var pid uint32
			require.NoError(t, writer.QueryRowContext(ctx, `SELECT pg_backend_pid()`).Scan(&pid))
			done := make(chan error, 1)
			go func() { _, err := app.Mutation().UpdateService(human, input); done <- err }()
			if mode == "service_wait" {
				rotationUpdateBlocked(t, ctx, db, pid, done)
				require.NoError(t, writer.Commit())
				enforceCode(t, <-done, ds.DeletionDependencyChanged)
			} else {
				require.Error(t, <-done, "NOWAIT must refuse rather than invert the root/runtime lock order")
				require.NoError(t, writer.Commit())
				if mode == "policy" || mode == "state" {
					_, err = app.Mutation().UpdateService(human, input)
					enforceCode(t, err, ds.DeletionDependencyChanged)
				}
				if mode == "authority" {
					_, err = app.Mutation().UpdateService(human, input)
					enforceCode(t, err, ds.DeletionUnavailable)
				}
			}
			require.Equal(t, 0, enforcementCount(t, ctx, db, `SELECT count(*) FROM service_update_audit_events WHERE service_id=$1 AND outcome='committed'`, f.service))
			if mode == "policy" || mode == "state" || mode == "alert" || mode == "organization" {
				fresh, err := app.Query().PreviewUpdateService(human, input)
				require.NoError(t, err)
				input.Confirmation = updateNativeConfirmation(fresh)
				ok, err := app.Mutation().UpdateService(human, input)
				require.NoError(t, err)
				require.True(t, ok, "a fresh authorized retry succeeds after contention is released")
			}
		})
	}
}

// A real DeleteAll owns the target EP before Service Update tries to attach it.
func TestPostgresServicePolicyUpdateEPDeleteFirst(t *testing.T) {
	base, uri, db := boundedAuditDB(t, len(Names()))
	ctx, cancel := context.WithTimeout(permission.SystemContext(base, "ServicePolicyUpdateTest"), 12*time.Second)
	defer cancel()
	app := updateNativeApp(t, ctx, db)
	f := newServicePolicyFixture(t, ctx, db, "none")
	input := f.input()
	confirmation := enforcementPreview(t, ctx, app, graphql2.DeletionResourceInput{Type: graphql2.DeletionTargetTypeEscalationPolicy, ID: f.next.String()})
	barrier := &updateNativeBarrier{prefix: "delete from escalation_policies", ready: make(chan uint32, 1), release: make(chan struct{})}
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
		_, err := owner.Mutation().DeleteAll(ctx, []assignment.RawTarget{{Type: assignment.TargetTypeEscalationPolicy, ID: f.next.String()}}, confirmation)
		done <- err
	}()
	select {
	case <-barrier.ready:
	case err := <-done:
		require.FailNow(t, "delete did not reach DML", "%v", err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	_, err = app.Mutation().UpdateService(ctx, input)
	require.Error(t, err)
	release()
	require.NoError(t, <-done)
	_, err = app.Mutation().UpdateService(ctx, input)
	require.Error(t, err)
	require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM services WHERE id=$1 AND escalation_policy_id=$2`, f.service, f.policy))
}
