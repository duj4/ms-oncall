package migrate

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/alert"
	"github.com/target/goalert/alert/alertlog"
	ds "github.com/target/goalert/deletionsafety"
	collector "github.com/target/goalert/deletionsafety/postgres"
	"github.com/target/goalert/integrationkey"
	guard "github.com/target/goalert/internal/deletionguard"
	"github.com/target/goalert/permission"
)

func TestPostgresDeletionEnforcementIntegrationKeyWriters(t *testing.T) {
	base, uri, db := boundedAuditDB(t, len(Names()))
	ctx := permission.SystemContext(base, "KeyProfileTest")
	for _, first := range []string{"writer", "delete"} {
		for _, kind := range []string{"key_update", "key_delete", "key_reparent", "service_update", "service_delete", "service_scope", "config_insert", "log_many", "log_service", "log_ep", "alert_status", "actor", "assignment", "organization", "normal_organization"} {
			t.Run(first+"_"+kind, func(t *testing.T) {
				f := keyProfileFixtureFor(t, ctx, db, integrationkey.TypeGeneric)
				other := newServiceProfileFixture(t, ctx, db)
				human := previewAdmit(t, base, db, f.actor)
				aid := serviceProfileAlert(t, ctx, db, f.service, "triggered")
				logs, err := alertlog.NewStore(ctx, db, nil)
				require.NoError(t, err)
				keyCtx := permission.ServiceSourceContext(ctx, f.service.String(), &permission.SourceInfo{Type: permission.SourceTypeIntegrationKey, ID: f.credential.String()})
				require.NoError(t, logs.LogTx(keyCtx, nil, int(aid), alertlog.TypeCreated, nil))
				writer := epProfileWriter(t, ctx, db)
				var pid int
				require.NoError(t, writer.QueryRowContext(ctx, `SELECT pg_backend_pid()`).Scan(&pid))
				writerCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
				defer cancel()
				run := func() error {
					q := `UPDATE integration_keys SET name=name WHERE audit_resource_id=$1`
					args := []any{f.safe}
					switch kind {
					case "key_delete":
						q = `DELETE FROM integration_keys WHERE audit_resource_id=$1`
					case "key_reparent":
						q = `UPDATE integration_keys SET service_id=$2 WHERE audit_resource_id=$1`
						args = append(args, other.service)
					case "service_update":
						q = `UPDATE services SET name=name WHERE id=$1`
						args = []any{f.service}
					case "service_delete":
						q = `DELETE FROM services WHERE id=$1`
						args = []any{f.service}
					case "service_scope":
						q = `UPDATE services SET organization_id=$2 WHERE id=$1`
						args = []any{f.service, other.org}
					case "config_insert":
						q = `INSERT INTO uik_config(id,config) VALUES($1,'{"Version":1,"V1":{}}')`
						args = []any{f.credential}
					case "log_many":
						return logs.LogManyTx(keyCtx, writer, []int{int(aid)}, alertlog.TypeCreated, nil)
					case "log_service":
						return logs.LogServiceTx(keyCtx, writer, f.service.String(), alertlog.TypeAcknowledged, nil)
					case "log_ep":
						return logs.LogEPTx(keyCtx, writer, f.policy.String(), alertlog.TypeEscalated, &alertlog.EscalationMetaData{})
					case "alert_status":
						return serviceProfileAlertStore(t, ctx, db).UpdateStatusTx(writerCtx, writer, int(aid), alert.StatusClosed)
					case "actor":
						q = `UPDATE users SET name=name WHERE id=$1`
						args = []any{f.actor}
					case "assignment":
						q = `UPDATE user_organization_assignments SET organization_role=organization_role WHERE user_id=$1`
						args = []any{f.actor}
					case "organization":
						q = `UPDATE organizations SET display_name=display_name WHERE id=$1`
						args = []any{f.org}
					case "normal_organization":
						q = `UPDATE normal_organizations SET iana_time_zone=iana_time_zone WHERE organization_id=$1`
						args = []any{f.org}
					}
					_, err := writer.ExecContext(writerCtx, q, args...)
					return err
				}
				app := enforcementApp(t, ctx, db)
				confirm := enforcementPreview(t, human, app, keyProfilePreview(f.safe)...)
				if first == "writer" {
					require.NoError(t, run())
					_, err = app.Mutation().DeleteAll(human, keyProfileInput(f.credential), confirm)
					enforceCode(t, err, ds.DeletionUnavailable)
					require.Zero(t, enforcementCount(t, ctx, db, `SELECT count(*) FROM integration_key_delete_audit_events WHERE root_resource_id=$1 AND outcome='committed'`, f.safe))
					require.NoError(t, writer.Commit())
					_, err = app.Mutation().DeleteAll(human, keyProfileInput(f.credential), confirm)
					switch kind {
					case "key_delete", "service_delete", "log_many", "log_service", "log_ep":
						enforceCode(t, err, ds.DeletionDependencyChanged)
					case "key_reparent", "service_scope", "config_insert":
						enforceCode(t, err, ds.DeletionUnavailable)
					default:
						require.NoError(t, err)
					}
					if kind == "log_many" || kind == "log_service" || kind == "log_ep" {
						fresh := enforcementPreview(t, human, app, keyProfilePreview(f.safe)...)
						_, err = app.Mutation().DeleteAll(human, keyProfileInput(f.credential), fresh)
						require.NoError(t, err)
					}
				} else {
					traced, barrier := overrideProfileTraced(t, uri, "VALUES($1,'certified'")
					controller := enforcementApp(t, ctx, traced)
					deleted := make(chan error, 1)
					go func() {
						_, err := controller.Mutation().DeleteAll(human, keyProfileInput(f.credential), confirm)
						deleted <- err
					}()
					select {
					case <-barrier.arrived:
					case <-ctx.Done():
						t.Fatal(ctx.Err())
					}
					done := make(chan error, 1)
					go func() { done <- run() }()
					overrideWait(t, writerCtx, db, pid, done)
					close(barrier.resume)
					require.NoError(t, <-deleted)
					writerErr := <-done
					if kind == "config_insert" {
						require.Error(t, writerErr)
						require.NoError(t, writer.Rollback())
					} else {
						require.NoError(t, writerErr)
						require.NoError(t, writer.Commit())
					}
					require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM integration_key_delete_audit_events WHERE root_resource_id=$1 AND outcome='committed'`, f.safe))
				}
			})
		}
	}
}

func TestPostgresDeletionEnforcementIntegrationKeyIndependent(t *testing.T) {
	ctx, uri, db := boundedAuditDB(t, len(Names()))
	ctx = permission.SystemContext(ctx, "KeyProfileTest")
	for _, first := range []string{"writer", "delete"} {
		for _, kind := range []string{"key_create", "sibling_key", "foreign_service", "foreign_org", "notification_rule", "contact_method", "rotation", "schedule", "ep", "override"} {
			t.Run(first+"_"+kind, func(t *testing.T) {
				f := keyProfileFixtureFor(t, ctx, db, integrationkey.TypeGeneric)
				g := newDeletionFixture(t, ctx, db)
				o := overrideProfileFixture(t, ctx, db)
				sibling, safe := keyProfileCreate(t, ctx, db, f.service, f.org, integrationkey.TypeEmail)
				_ = sibling
				app := enforcementApp(t, ctx, db)
				writer := epProfileWriter(t, ctx, db)
				_, err := writer.ExecContext(ctx, `SET LOCAL lock_timeout='500ms'`)
				require.NoError(t, err)
				run := func() error {
					q := `UPDATE integration_keys SET name=name WHERE audit_resource_id=$1`
					args := []any{safe}
					switch kind {
					case "key_create":
						_, err := app.IntKeyStore.Create(ctx, writer, &integrationkey.IntegrationKey{Name: "sibling-" + uuid.NewString(), ServiceID: f.service.String(), Type: integrationkey.TypeGeneric}, &f.org)
						return err
					case "foreign_service":
						q = `UPDATE services SET name=name WHERE id=$1`
						args = []any{g.service}
					case "foreign_org":
						q = `UPDATE organizations SET display_name=display_name WHERE id=$1`
						args = []any{o.org}
					case "notification_rule":
						q = `UPDATE user_notification_rules SET delay_minutes=delay_minutes WHERE id=$1`
						args = []any{g.nr}
					case "contact_method":
						q = `UPDATE user_contact_methods SET name=name WHERE id=$1`
						args = []any{g.cm}
					case "rotation":
						q = `UPDATE rotations SET name=name WHERE id=$1`
						args = []any{f.rotation}
					case "schedule":
						q = `UPDATE schedules SET name=name WHERE id=$1`
						args = []any{f.schedule}
					case "ep":
						q = `UPDATE escalation_policies SET name=name WHERE id=$1`
						args = []any{f.policy}
					case "override":
						q = `UPDATE user_overrides SET end_time=end_time WHERE id=$1`
						args = []any{o.override}
					}
					res, err := writer.ExecContext(ctx, q, args...)
					if err != nil {
						return err
					}
					n, err := res.RowsAffected()
					require.NoError(t, err)
					require.EqualValues(t, 1, n)
					return nil
				}
				confirm := enforcementPreview(t, ctx, app, keyProfilePreview(f.safe)...)
				if first == "writer" {
					require.NoError(t, run())
					_, err = app.Mutation().DeleteAll(ctx, keyProfileInput(f.credential), confirm)
					require.NoError(t, err)
					require.NoError(t, writer.Commit())
				} else {
					traced, barrier := overrideProfileTraced(t, uri, "VALUES($1,'certified'")
					controller := enforcementApp(t, ctx, traced)
					done := make(chan error, 1)
					go func() {
						_, err := controller.Mutation().DeleteAll(ctx, keyProfileInput(f.credential), confirm)
						done <- err
					}()
					<-barrier.arrived
					require.NoError(t, run())
					require.NoError(t, writer.Commit())
					close(barrier.resume)
					require.NoError(t, <-done)
				}
			})
		}
	}
	f := keyProfileFixtureFor(t, ctx, db, integrationkey.TypeGeneric)
	tx := nrBegin(t, ctx, db)
	_ = keyProfileEnforce(t, ctx, tx, f, keyProfileVersion(t, ctx, db, f.safe))
	var n int
	require.NoError(t, tx.QueryRowContext(ctx, `SELECT count(*) FROM pg_locks l JOIN pg_class c ON c.oid=l.relation JOIN pg_namespace ns ON ns.oid=c.relnamespace WHERE l.pid=pg_backend_pid() AND ns.nspname='public' AND l.mode IN ('ShareLock','ShareRowExclusiveLock','ExclusiveLock','AccessExclusiveLock')`).Scan(&n))
	require.Zero(t, n)
	require.NoError(t, tx.Rollback())
}

func TestPostgresDeletionEnforcementIntegrationKeyWitnessAndBudget(t *testing.T) {
	ctx, _, db := boundedAuditDB(t, len(Names()))
	ctx = permission.SystemContext(ctx, "KeyProfileTest")
	f := keyProfileFixtureFor(t, ctx, db, integrationkey.TypeGeneric)
	version := keyProfileVersion(t, ctx, db, f.safe)
	for _, q := range []string{`UPDATE pg_temp.d09_nr_deletion_witness SET nonce=gen_random_uuid() WHERE phase='certified'`, `UPDATE pg_temp.d09_nr_deletion_witness SET xid='0' WHERE phase='certified'`, `UPDATE pg_temp.d09_nr_deletion_witness SET profile='service-only-v1' WHERE phase='certified'`, `UPDATE pg_temp.d09_nr_deletion_witness SET raw_hash='\x00' WHERE phase='certified'`, `UPDATE pg_temp.d09_nr_deletion_witness SET effective_hash='\x00' WHERE phase='certified'`} {
		tx := nrBegin(t, ctx, db)
		bound := keyProfileEnforce(t, ctx, tx, f, version)
		_, err := tx.ExecContext(ctx, q)
		require.NoError(t, err)
		_, err = guard.ConsumeIntegrationKey(bound, tx, []string{f.credential.String()})
		enforceCode(t, err, ds.DeletionUnavailable)
		require.NoError(t, tx.Rollback())
	}
	limits := collector.DefaultLimits()
	limits.MaxQueries = 1
	result, err := collectDeletion(t, ctx, db, keyProfileRoot(f.safe), limits)
	enforceCode(t, err, ds.DeletionPreviewLimitExceeded)
	require.NotEqual(t, ds.DependenciesComplete, result.Collection.Completeness)
	keyProfileNoSuccess(t, ctx, db)
	// Inspect the actual migrated FK catalog. Only Config points to the Key;
	// AlertLog's subject reference is deliberately non-FK.
	require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM pg_constraint WHERE contype='f' AND confrelid='integration_keys'::regclass AND conrelid='uik_config'::regclass AND confdeltype='c'`))
	require.Zero(t, enforcementCount(t, ctx, db, `SELECT count(*) FROM pg_constraint WHERE contype='f' AND confrelid='integration_keys'::regclass AND conrelid<>'uik_config'::regclass`))
	require.Zero(t, enforcementCount(t, ctx, db, `SELECT count(*) FROM pg_constraint WHERE contype='f' AND conrelid='alert_logs'::regclass AND confrelid='integration_keys'::regclass`))
}
