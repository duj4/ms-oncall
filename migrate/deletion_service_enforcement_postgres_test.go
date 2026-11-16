package migrate

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/lib/pq"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/alert"
	"github.com/target/goalert/alert/alertlog"
	"github.com/target/goalert/assignment"
	ds "github.com/target/goalert/deletionsafety"
	collector "github.com/target/goalert/deletionsafety/postgres"
	"github.com/target/goalert/gadb"
	"github.com/target/goalert/graphql2"
	guard "github.com/target/goalert/internal/deletionguard"
	"github.com/target/goalert/organization"
	"github.com/target/goalert/permission"
	"github.com/target/goalert/util/sqlutil"
)

type serviceProfileContextKey struct{}

type serviceProfileFixture struct {
	boundedFixture
	service, policy, step uuid.UUID
}

// Construct only the requested shape. Never delete an existing fixture's
// historical messages/logs/alerts in order to make enforcement succeed.
func newServiceProfileFixture(t *testing.T, ctx context.Context, db *sql.DB) serviceProfileFixture {
	t.Helper()
	f := serviceProfileFixture{boundedFixture: newBoundedFixture(t, ctx, db), service: uuid.New(), policy: uuid.New(), step: uuid.New()}
	for _, u := range []uuid.UUID{f.actor, f.user} {
		enforcementExec(t, ctx, db, `UPDATE users SET role='user' WHERE id=$1`, u)
		_, err := organization.NewStore(db).CreateUserOrganizationAssignment(ctx, organization.CreateUserOrganizationAssignmentInput{UserID: u, UserOrganizationAssignmentValues: organization.UserOrganizationAssignmentValues{
			EffectiveOrganizationID: f.org, EffectiveOrganizationClassification: organization.ClassificationNormal, Role: organization.OrganizationRoleAdmin, MappingOutcome: organization.MappingOutcomeExactlyOne,
			Evaluation: organization.AssignmentEvaluation{AuthoritativeEvaluatedAt: time.Now(), SourceConfigVersion: "synthetic-service-profile", MatchedCount: 1}}})
		require.NoError(t, err)
	}
	enforcementExec(t, ctx, db, `INSERT INTO escalation_policies(id,organization_id,name) VALUES($1,$2,($1::uuid)::text)`, f.policy, f.org)
	enforcementExec(t, ctx, db, `INSERT INTO escalation_policy_steps(id,escalation_policy_id,step_number) VALUES($1,$2,0)`, f.step, f.policy)
	enforcementExec(t, ctx, db, `INSERT INTO escalation_policy_actions(escalation_policy_step_id,user_id) VALUES($1,$2)`, f.step, f.user)
	serviceProfileInsert(t, ctx, db, f.service, f.org, f.policy)
	return f
}

func serviceProfileInsert(t *testing.T, ctx context.Context, db *sql.DB, id, org, policy uuid.UUID) {
	t.Helper()
	enforcementExec(t, ctx, db, `INSERT INTO services(id,organization_id,name,escalation_policy_id) VALUES($1,$2,($1::uuid)::text,$3)`, id, org, policy)
}
func serviceProfileRoot(id uuid.UUID) ds.Resource {
	return ds.Resource{Kind: ds.ResourceService, ID: id.String()}
}
func serviceProfileSelectors(ids ...uuid.UUID) []collector.Selector {
	var raw []collector.Selector
	for _, id := range ids {
		raw = append(raw, collector.Selector{Kind: ds.ResourceService, ID: id.String()})
	}
	return raw
}
func serviceProfileInput(ids ...uuid.UUID) []assignment.RawTarget {
	var raw []assignment.RawTarget
	for _, id := range ids {
		raw = append(raw, assignment.RawTarget{Type: assignment.TargetTypeService, ID: id.String()})
	}
	return raw
}
func serviceProfileVersion(t *testing.T, ctx context.Context, db *sql.DB, id uuid.UUID) string {
	t.Helper()
	facts, err := collectDeletion(t, ctx, db, serviceProfileRoot(id), collector.Limits{})
	require.NoError(t, err)
	return deletionPlan(t, serviceProfileRoot(id), facts).ImpactVersion()
}
func serviceProfileEnforce(t *testing.T, ctx context.Context, tx *sql.Tx, id uuid.UUID, version string) context.Context {
	t.Helper()
	bound, err := collector.Enforce(ctx, tx, serviceProfileSelectors(id), version, true, authorizeDeletionFixture(serviceProfileRoot(id)))
	require.NoError(t, err)
	return bound
}
func serviceProfileAlert(t *testing.T, ctx context.Context, db *sql.DB, service uuid.UUID, status string) int64 {
	t.Helper()
	var id int64
	require.NoError(t, db.QueryRowContext(ctx, `INSERT INTO alerts(service_id,status,summary,dedup_key) VALUES($1,$2::enum_alert_status,'SYNTHETIC_PRIVATE_ALERT',CASE WHEN $2::enum_alert_status='closed' THEN NULL ELSE ($3::uuid)::text END) RETURNING id`, service, status, uuid.New()).Scan(&id))
	return id
}
func serviceProfileNoSuccess(t *testing.T, ctx context.Context, db *sql.DB) {
	t.Helper()
	require.Zero(t, enforcementCount(t, ctx, db, `SELECT count(*) FROM service_delete_audit_events WHERE outcome='committed'`))
}

func TestPostgresDeletionEnforcementServiceBusiness(t *testing.T) {
	ctx, _, db := boundedAuditDB(t, len(Names()))
	ctx = permission.SystemContext(ctx, "ServiceProfileTest")
	app := enforcementApp(t, ctx, db)
	for _, status := range []string{"none", "triggered", "active", "closed"} {
		t.Run(status, func(t *testing.T) {
			f := newServiceProfileFixture(t, ctx, db)
			var aid int64
			if status != "none" {
				aid = serviceProfileAlert(t, ctx, db, f.service, status)
			}
			confirm := enforcementPreview(t, ctx, app, graphql2.DeletionResourceInput{Type: graphql2.DeletionTargetTypeService, ID: f.service.String()})
			ok, err := app.Mutation().DeleteAll(ctx, serviceProfileInput(f.service), confirm)
			if status == "active" || status == "triggered" {
				require.False(t, ok)
				enforceCode(t, err, ds.DeletionBlocked)
				require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM alerts WHERE id=$1`, aid))
				return
			}
			require.NoError(t, err)
			require.True(t, ok)
			require.Zero(t, enforcementCount(t, ctx, db, `SELECT count(*) FROM services WHERE id=$1`, f.service))
			require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM escalation_policies WHERE id=$1`, f.policy))
			require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM escalation_policy_steps WHERE id=$1`, f.step))
			require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM users WHERE id=$1`, f.user))
			require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM service_delete_audit_events WHERE outcome='committed' AND service_id=$1 AND operation='service.delete'`, f.service))
			if status == "closed" {
				require.Zero(t, enforcementCount(t, ctx, db, `SELECT count(*) FROM alerts WHERE id=$1`, aid))
				require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM service_delete_audit_events a CROSS JOIN LATERAL jsonb_array_elements(a.effects) e WHERE a.service_id=$1 AND e->>'resource_type'='alert' AND e->>'provenance'='CASCADE' AND e->>'cause'='service_delete'`, f.service))
			}
		})
	}
	// Duplicate raw selectors and missing IDs remain legal; each actual root
	// produces exactly one DELETE RETURNING receipt and one audit event.
	f, other := newServiceProfileFixture(t, ctx, db), newServiceProfileFixture(t, ctx, db)
	confirm := enforcementPreview(t, ctx, app, graphql2.DeletionResourceInput{Type: graphql2.DeletionTargetTypeService, ID: f.service.String()}, graphql2.DeletionResourceInput{Type: graphql2.DeletionTargetTypeService, ID: other.service.String()})
	ok, err := app.Mutation().DeleteAll(ctx, serviceProfileInput(f.service, f.service, other.service, uuid.New()), confirm)
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, 2, enforcementCount(t, ctx, db, `SELECT count(*) FROM service_delete_audit_events WHERE outcome='committed' AND service_id=ANY($1::uuid[])`, pq.Array([]uuid.UUID{f.service, other.service})))
	ok, err = app.Mutation().DeleteAll(ctx, serviceProfileInput(uuid.Nil), nil)
	require.NoError(t, err)
	require.True(t, ok)
	_, err = app.Mutation().DeleteAll(ctx, serviceProfileInput(f.service), confirm)
	enforceCode(t, err, ds.DeletionDependencyChanged)
	_, err = app.Mutation().DeleteAll(ctx, serviceProfileInput(slicesRepeatService(f.service, 51)...), nil)
	require.Error(t, err)
	require.NotEqual(t, string(ds.DeletionUnavailable), err.Error())
}
func slicesRepeatService(id uuid.UUID, n int) []uuid.UUID {
	out := make([]uuid.UUID, n)
	for i := range out {
		out[i] = id
	}
	return out
}

func TestPostgresDeletionEnforcementServiceClosureAudit(t *testing.T) {
	ctx, _, db := boundedAuditDB(t, len(Names()))
	ctx = permission.SystemContext(ctx, "ServiceProfileTest")
	f := newServiceProfileFixture(t, ctx, db)
	app := enforcementApp(t, ctx, db)
	aid := serviceProfileAlert(t, ctx, db, f.service, "closed")
	key := uuid.New()
	var safe uuid.UUID
	require.NoError(t, db.QueryRowContext(ctx, `INSERT INTO integration_keys(id,service_id,name,type) VALUES($1,$2,'synthetic','generic') RETURNING audit_resource_id`, key, f.service).Scan(&safe))
	enforcementExec(t, ctx, db, `INSERT INTO user_favorites(user_id,tgt_service_id) VALUES($1,$2)`, f.user, f.service)
	enforcementExec(t, ctx, db, `INSERT INTO alert_data(alert_id,metadata) VALUES($1,'{}')`, aid)
	enforcementExec(t, ctx, db, `INSERT INTO alert_feedback(alert_id,noise_reason) VALUES($1,'synthetic')`, aid)
	enforcementExec(t, ctx, db, `INSERT INTO alert_metrics(alert_id,service_id,closed_at) VALUES($1,$2,now())`, aid, f.service)
	enforcementExec(t, ctx, db, `INSERT INTO notification_policy_cycles(user_id,alert_id) VALUES($1,$2)`, f.user, aid)
	logStore, err := alertlog.NewStore(ctx, db, nil)
	require.NoError(t, err)
	require.NoError(t, logStore.LogTx(ctx, nil, int(aid), alertlog.TypeClosed, nil))
	// Integration log historical subject uses a SQL-internal credential
	// predicate; neither this ID nor any destination enters plan or error text.
	enforcementExec(t, ctx, db, `UPDATE alert_logs SET sub_integration_key_id=$2 WHERE alert_id=$1`, aid, key)
	confirm := enforcementPreview(t, ctx, app, graphql2.DeletionResourceInput{Type: graphql2.DeletionTargetTypeService, ID: f.service.String()})
	require.NotContains(t, confirm.ExpectedImpactVersion, key.String())
	_, err = app.Mutation().DeleteAll(ctx, serviceProfileInput(f.service), nil)
	enforceCode(t, err, ds.DeletionConfirmationRequired)
	stale := *confirm
	stale.ExpectedImpactVersion = "stale"
	_, err = app.Mutation().DeleteAll(ctx, serviceProfileInput(f.service), &stale)
	enforceCode(t, err, ds.DeletionDependencyChanged)
	serviceProfileNoSuccess(t, ctx, db)
	ok, err := app.Mutation().DeleteAll(ctx, serviceProfileInput(f.service), confirm)
	require.NoError(t, err)
	require.True(t, ok)
	for _, table := range []string{"alert_data", "alert_feedback", "alert_metrics", "notification_policy_cycles"} {
		require.Zero(t, enforcementCount(t, ctx, db, `SELECT count(*) FROM `+table+` WHERE alert_id=$1`, aid))
	}
	require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM alert_logs WHERE alert_id=$1`, aid), "historical non-FK logs are preserved")
	require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM users WHERE id=$1`, f.user))
	var effects string
	require.NoError(t, db.QueryRowContext(ctx, `SELECT effects::text FROM service_delete_audit_events WHERE outcome='committed' AND service_id=$1`, f.service).Scan(&effects))
	require.Contains(t, effects, safe.String())
	require.NotContains(t, effects, key.String())
	var decoded []map[string]any
	require.NoError(t, json.Unmarshal([]byte(effects), &decoded))
	require.Len(t, decoded, 3)
}

func TestPostgresDeletionEnforcementServiceUnsupported(t *testing.T) {
	ctx, _, db := boundedAuditDB(t, len(Names()))
	ctx = permission.SystemContext(ctx, "ServiceProfileTest")
	app := enforcementApp(t, ctx, db)
	for _, shape := range []string{"signal", "pending_message", "historical_message", "key_config", "label", "external_status_bundle"} {
		t.Run(shape, func(t *testing.T) {
			f, good := newServiceProfileFixture(t, ctx, db), newServiceProfileFixture(t, ctx, db)
			channel := uuid.New()
			enforcementExec(t, ctx, db, `INSERT INTO notification_channels(id,name,type,value,dest) VALUES($1,($1::uuid)::text,'WEBHOOK',($1::uuid)::text,jsonb_build_object('type','synthetic','id',($1::uuid)::text))`, channel)
			switch shape {
			case "signal":
				enforcementExec(t, ctx, db, `INSERT INTO pending_signals(service_id,dest_id,params) VALUES($1,$2,'{}')`, f.service, channel)
			case "pending_message":
				enforcementExec(t, ctx, db, `INSERT INTO outgoing_messages(service_id,channel_id,message_type) VALUES($1,$2,'test_notification')`, f.service, channel)
			case "historical_message":
				enforcementExec(t, ctx, db, `INSERT INTO outgoing_messages(service_id,channel_id,message_type,last_status,sent_at) VALUES($1,$2,'test_notification','sent',now())`, f.service, channel)
			case "key_config":
				enforcementExec(t, ctx, db, `WITH k AS (INSERT INTO integration_keys(service_id,name,type) VALUES($1,'synthetic','generic') RETURNING id) INSERT INTO uik_config(id,config) SELECT id,'{}' FROM k`, f.service)
			case "label":
				enforcementExec(t, ctx, db, `INSERT INTO labels(tgt_service_id,key,value) VALUES($1,'synthetic','synthetic')`, f.service)
			case "external_status_bundle":
				aid := serviceProfileAlert(t, ctx, db, f.service, "closed")
				enforcementExec(t, ctx, db, `INSERT INTO outgoing_messages(channel_id,message_type,last_status,status_alert_ids) VALUES($1,'alert_status_update_bundle','failed',ARRAY[$2::bigint])`, channel, aid)
			}
			ok, err := app.Mutation().DeleteAll(ctx, serviceProfileInput(good.service, f.service), nil)
			require.False(t, ok)
			enforceCode(t, err, ds.DeletionUnavailable)
			require.Equal(t, 2, enforcementCount(t, ctx, db, `SELECT count(*) FROM services WHERE id=ANY($1::uuid[])`, pq.Array([]uuid.UUID{good.service, f.service})))
			serviceProfileNoSuccess(t, ctx, db)
		})
	}
	f := newServiceProfileFixture(t, ctx, db)
	for _, kind := range []assignment.TargetType{assignment.TargetTypeEscalationPolicy, assignment.TargetTypeIntegrationKey, assignment.TargetTypeContactMethod, assignment.TargetTypeNotificationRule, assignment.TargetTypeRotation, assignment.TargetTypeUser} {
		_, err := app.Mutation().DeleteAll(ctx, append(serviceProfileInput(f.service), assignment.RawTarget{Type: kind, ID: uuid.NewString()}), nil)
		enforceCode(t, err, ds.DeletionUnavailable)
	}
}

func TestPostgresDeletionEnforcementServiceAuditFailure(t *testing.T) {
	ctx, _, db := boundedAuditDB(t, len(Names()))
	ctx = permission.SystemContext(ctx, "ServiceProfileTest")
	f := newServiceProfileFixture(t, ctx, db)
	app := enforcementApp(t, ctx, db)
	aid := serviceProfileAlert(t, ctx, db, f.service, "closed")
	confirm := enforcementPreview(t, ctx, app, graphql2.DeletionResourceInput{Type: graphql2.DeletionTargetTypeService, ID: f.service.String()})
	enforcementExec(t, ctx, db, `CREATE FUNCTION service_profile_reject_audit() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'synthetic audit failure'; END$$; CREATE TRIGGER service_profile_reject BEFORE INSERT ON service_delete_audit_events FOR EACH ROW EXECUTE FUNCTION service_profile_reject_audit()`)
	ok, err := app.Mutation().DeleteAll(ctx, serviceProfileInput(f.service), confirm)
	require.False(t, ok)
	require.Error(t, err)
	require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM services WHERE id=$1`, f.service))
	require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM alerts WHERE id=$1`, aid))
	serviceProfileNoSuccess(t, ctx, db)
	enforcementExec(t, ctx, db, `DROP TRIGGER service_profile_reject ON service_delete_audit_events`)
	ok, err = app.Mutation().DeleteAll(ctx, serviceProfileInput(f.service), confirm)
	require.NoError(t, err)
	require.True(t, ok)
}

func serviceProfileAlertStore(t *testing.T, ctx context.Context, db *sql.DB) *alert.Store {
	t.Helper()
	logs, err := alertlog.NewStore(ctx, db, nil)
	require.NoError(t, err)
	store, err := alert.NewStore(ctx, db, logs)
	require.NoError(t, err)
	return store
}

func serviceProfileWait(t *testing.T, ctx context.Context, db *sql.DB, tx *sql.Tx, fn func() error) <-chan error {
	t.Helper()
	var pid int
	require.NoError(t, tx.QueryRowContext(ctx, `SELECT pg_backend_pid()`).Scan(&pid))
	done := make(chan error, 1)
	go func() { done <- fn() }()
	for {
		var waiting bool
		require.NoError(t, db.QueryRowContext(ctx, `SELECT cardinality(pg_blocking_pids($1))>0`, pid).Scan(&waiting))
		if waiting {
			return done
		}
		select {
		case err := <-done:
			require.FailNow(t, "writer did not reach lock barrier", "%v", err)
		default:
		}
		require.NoError(t, ctx.Err())
	}
}

func TestPostgresDeletionEnforcementServiceAlertCreate(t *testing.T) {
	ctx, _, db := boundedAuditDB(t, len(Names()))
	ctx = permission.SystemContext(ctx, "ServiceProfileTest")
	app := enforcementApp(t, ctx, db)
	store := serviceProfileAlertStore(t, ctx, db)
	for _, mode := range []string{"create", "upsert", "raw_fk"} {
		for _, first := range []string{"delete", "writer"} {
			t.Run(mode+"_"+first, func(t *testing.T) {
				f := newServiceProfileFixture(t, ctx, db)
				version := serviceProfileVersion(t, ctx, db, f.service)
				writer, err := db.BeginTx(ctx, nil)
				require.NoError(t, err)
				defer func() { _ = writer.Rollback() }()
				writeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
				defer cancel()
				run := func() error {
					a := &alert.Alert{ServiceID: f.service.String(), Summary: "synthetic", Status: alert.StatusTriggered, Source: alert.SourceManual}
					switch mode {
					case "create":
						_, err := store.CreateTxScoped(writeCtx, writer, a, nil)
						return err
					case "upsert":
						_, _, err := store.CreateOrUpdateTxScoped(writeCtx, writer, a, nil)
						return err
					default:
						_, err := writer.ExecContext(writeCtx, `INSERT INTO alerts(service_id,status,summary,dedup_key) VALUES($1,'triggered','synthetic',$2)`, f.service, uuid.NewString())
						return err
					}
				}
				if first == "writer" {
					require.NoError(t, run()) // completed statement, transaction still open
					tx := nrBegin(t, ctx, db)
					_, err := collector.Enforce(ctx, tx, serviceProfileSelectors(f.service), version, true, authorizeDeletionFixture(serviceProfileRoot(f.service)))
					enforceCode(t, err, ds.DeletionUnavailable)
					require.NoError(t, tx.Rollback())
					require.NoError(t, writer.Commit())
					tx = nrBegin(t, ctx, db)
					_, err = collector.Enforce(ctx, tx, serviceProfileSelectors(f.service), version, true, authorizeDeletionFixture(serviceProfileRoot(f.service)))
					enforceCode(t, err, ds.DeletionBlocked)
					require.NoError(t, tx.Rollback())
				} else {
					tx := nrBegin(t, ctx, db)
					bound := serviceProfileEnforce(t, ctx, tx, f.service, version)
					done := serviceProfileWait(t, writeCtx, db, writer, run)
					receipts, err := app.ServiceStore.DeleteManyForAuditTx(bound, tx, []string{f.service.String()}, nil)
					require.NoError(t, err)
					require.Len(t, receipts, 1)
					require.NoError(t, tx.Commit())
					err = <-done
					require.Error(t, err)
					require.NotContains(t, err.Error(), "SYNTHETIC_PRIVATE")
					require.NoError(t, writer.Rollback())
					require.Zero(t, enforcementCount(t, ctx, db, `SELECT count(*) FROM alerts WHERE service_id=$1`, f.service))
				}
			})
		}
	}
	serviceProfileNoSuccess(t, ctx, db)
}

func TestPostgresDeletionEnforcementServiceAlertStatusCleanup(t *testing.T) {
	ctx, _, db := boundedAuditDB(t, len(Names()))
	ctx = permission.SystemContext(ctx, "ServiceProfileTest")
	store := serviceProfileAlertStore(t, ctx, db)
	app := enforcementApp(t, ctx, db)
	f := newServiceProfileFixture(t, ctx, db)
	aid := serviceProfileAlert(t, ctx, db, f.service, "active")
	version := serviceProfileVersion(t, ctx, db, f.service)
	writer, err := db.BeginTx(ctx, nil)
	require.NoError(t, err)
	defer func() { _ = writer.Rollback() }()
	require.NoError(t, store.UpdateStatusTx(ctx, writer, int(aid), alert.StatusClosed))
	tx := nrBegin(t, ctx, db)
	_, err = collector.Enforce(ctx, tx, serviceProfileSelectors(f.service), version, true, authorizeDeletionFixture(serviceProfileRoot(f.service)))
	enforceCode(t, err, ds.DeletionUnavailable)
	require.NoError(t, tx.Rollback())
	require.NoError(t, writer.Commit())
	tx = nrBegin(t, ctx, db)
	_, err = collector.Enforce(ctx, tx, serviceProfileSelectors(f.service), version, true, authorizeDeletionFixture(serviceProfileRoot(f.service)))
	enforceCode(t, err, ds.DeletionDependencyChanged)
	require.NoError(t, tx.Rollback())
	// Both SQL and public Store reject reopening a closed alert. Even a no-op
	// status assignment is forbidden by the existing PostgreSQL trigger.
	_, err = db.ExecContext(ctx, `UPDATE alerts SET status='active',dedup_key='synthetic' WHERE id=$1`, aid)
	require.Error(t, err)
	require.Error(t, store.UpdateStatus(ctx, int(aid), alert.StatusTriggered))
	// Exercise the real scoped batch and by-Service paths on separate Services.
	for _, kind := range []string{"many", "service"} {
		g := newServiceProfileFixture(t, ctx, db)
		id := serviceProfileAlert(t, ctx, db, g.service, "triggered")
		if kind == "many" {
			_, err = store.UpdateManyAlertStatusScoped(ctx, alert.StatusClosed, []int{int(id)}, nil, nil)
		} else {
			err = store.UpdateStatusByServiceScoped(ctx, g.service.String(), alert.StatusClosed, nil)
		}
		require.NoError(t, err)
		require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM alerts WHERE id=$1 AND status='closed'`, id))
	}
	// Cleanup uses its original SKIP LOCKED query: Delete-first is nonblocking
	// with zero rows; Writer-first is refused and a new attempt re-collects.
	enforcementExec(t, ctx, db, `UPDATE alerts SET created_at=now()-'100 days'::interval WHERE id=$1`, aid)
	version = serviceProfileVersion(t, ctx, db, f.service)
	tx = nrBegin(t, ctx, db)
	bound := serviceProfileEnforce(t, ctx, tx, f.service, version)
	cleanup, err := db.BeginTx(ctx, nil)
	require.NoError(t, err)
	defer func() { _ = cleanup.Rollback() }()
	n, err := gadb.New(cleanup).CleanupMgrDeleteOldAlerts(ctx, 30)
	require.NoError(t, err)
	require.Zero(t, n)
	require.NoError(t, cleanup.Commit())
	receipts, err := app.ServiceStore.DeleteManyForAuditTx(bound, tx, []string{f.service.String()}, nil)
	require.NoError(t, err)
	require.Len(t, receipts, 1)
	require.NoError(t, tx.Commit())
	g := newServiceProfileFixture(t, ctx, db)
	id := serviceProfileAlert(t, ctx, db, g.service, "closed")
	enforcementExec(t, ctx, db, `UPDATE alerts SET created_at=now()-'100 days'::interval WHERE id=$1`, id)
	version = serviceProfileVersion(t, ctx, db, g.service)
	cleanup, err = db.BeginTx(ctx, nil)
	require.NoError(t, err)
	n, err = gadb.New(cleanup).CleanupMgrDeleteOldAlerts(ctx, 30)
	require.NoError(t, err)
	require.EqualValues(t, 1, n)
	tx = nrBegin(t, ctx, db)
	_, err = collector.Enforce(ctx, tx, serviceProfileSelectors(g.service), version, true, authorizeDeletionFixture(serviceProfileRoot(g.service)))
	enforceCode(t, err, ds.DeletionUnavailable)
	require.NoError(t, tx.Rollback())
	require.NoError(t, cleanup.Commit())
	tx = nrBegin(t, ctx, db)
	_, err = collector.Enforce(ctx, tx, serviceProfileSelectors(g.service), version, true, authorizeDeletionFixture(serviceProfileRoot(g.service)))
	enforceCode(t, err, ds.DeletionDependencyChanged)
	require.NoError(t, tx.Rollback())
}

func TestPostgresDeletionEnforcementServiceMissingWindow(t *testing.T) {
	ctx, _, db := boundedAuditDB(t, len(Names()))
	ctx = permission.SystemContext(ctx, "ServiceProfileTest")
	app := enforcementApp(t, ctx, db)
	f := newServiceProfileFixture(t, ctx, db)
	for _, legacy := range []bool{false, true} {
		absent := uuid.New()
		tx := nrBegin(t, ctx, db)
		bound, err := collector.Enforce(ctx, tx, serviceProfileSelectors(absent), "", false, authorizeDeletionFixture(serviceProfileRoot(absent)))
		require.NoError(t, err)
		serviceProfileInsert(t, ctx, db, absent, f.org, f.policy)
		if legacy {
			require.NoError(t, app.ServiceStore.DeleteManyTx(bound, tx, []string{absent.String()}, nil))
		} else {
			receipts, err := app.ServiceStore.DeleteManyForAuditTx(bound, tx, []string{absent.String()}, nil)
			require.NoError(t, err)
			require.Empty(t, receipts)
		}
		require.NoError(t, tx.Commit())
		require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM services WHERE id=$1`, absent))
	}
	absent := uuid.New()
	version := serviceProfileVersion(t, ctx, db, f.service)
	tx := nrBegin(t, ctx, db)
	bound, err := collector.Enforce(ctx, tx, serviceProfileSelectors(f.service, absent), version, true, authorizeDeletionFixture(serviceProfileRoot(f.service)))
	require.NoError(t, err)
	// Use another Policy: this fixture insertion is independent of the selected
	// root's intentionally locked, retained Policy.
	other := uuid.New()
	enforcementExec(t, ctx, db, `INSERT INTO escalation_policies(id,organization_id,name) VALUES($1,$2,($1::uuid)::text)`, other, f.org)
	serviceProfileInsert(t, ctx, db, absent, f.org, other)
	receipts, err := app.ServiceStore.DeleteManyForAuditTx(bound, tx, []string{f.service.String(), absent.String()}, nil)
	require.NoError(t, err)
	require.Len(t, receipts, 1)
	require.Equal(t, f.service, receipts[0].ID)
	require.NoError(t, tx.Commit())
	require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM services WHERE id=$1`, absent))
	serviceProfileNoSuccess(t, ctx, db)
}

func TestPostgresDeletionEnforcementServiceGuardLifecycle(t *testing.T) {
	ctx, _, db := boundedAuditDB(t, len(Names()))
	ctx = permission.SystemContext(ctx, "ServiceProfileTest")
	f := newServiceProfileFixture(t, ctx, db)
	app := enforcementApp(t, ctx, db)
	version := serviceProfileVersion(t, ctx, db, f.service)
	raw := serviceProfileSelectors(f.service)
	for _, phase := range []string{"before_locks", "after_locks", "after_witness"} {
		t.Run(phase, func(t *testing.T) {
			tx := nrBegin(t, ctx, db)
			if phase == "before_locks" {
				_, err := tx.ExecContext(ctx, `SAVEPOINT checkpoint`)
				require.NoError(t, err)
			}
			checked, _, err := guard.StabilizeService(ctx, tx, raw)
			require.NoError(t, err)
			if phase == "after_locks" {
				_, err = tx.ExecContext(ctx, `SAVEPOINT checkpoint`)
				require.NoError(t, err)
			}
			facts, err := collector.Collect(checked, tx, serviceProfileRoot(f.service), collector.Recheck, collector.Limits{}, authorizeDeletionFixture(serviceProfileRoot(f.service)))
			require.NoError(t, err)
			plan := deletionPlan(t, serviceProfileRoot(f.service), facts)
			_, err = guard.Bind(ctx, tx, checked, append(raw, raw...), plan, version, true)
			enforceCode(t, err, ds.DeletionUnavailable)
			_, err = guard.Bind(ctx, tx, checked, raw, ds.DeletionPlan{}, version, true)
			enforceCode(t, err, ds.DeletionUnavailable)
			bound, err := guard.Bind(ctx, tx, checked, raw, plan, version, true)
			require.NoError(t, err)
			if phase == "after_witness" {
				_, err = tx.ExecContext(ctx, `SAVEPOINT checkpoint`)
				require.NoError(t, err)
			}
			_, err = tx.ExecContext(ctx, `ROLLBACK TO checkpoint`)
			require.NoError(t, err)
			if phase != "after_witness" {
				_, err = app.ServiceStore.DeleteManyForAuditTx(bound, tx, []string{f.service.String()}, nil)
				enforceCode(t, err, ds.DeletionUnavailable)
				_, err = guard.Bind(ctx, tx, checked, raw, plan, version, true)
				enforceCode(t, err, ds.DeletionUnavailable)
				bound = serviceProfileEnforce(t, ctx, tx, f.service, version)
			}
			receipts, err := app.ServiceStore.DeleteManyForAuditTx(bound, tx, []string{f.service.String()}, nil)
			require.NoError(t, err)
			require.Len(t, receipts, 1)
			_, err = app.ServiceStore.DeleteManyForAuditTx(bound, tx, []string{f.service.String()}, nil)
			enforceCode(t, err, ds.DeletionUnavailable)
			require.NoError(t, tx.Rollback())
		})
	}
	tx := nrBegin(t, ctx, db)
	old := serviceProfileEnforce(t, ctx, tx, f.service, version)
	_, err := tx.ExecContext(ctx, `SAVEPOINT old_generation`)
	require.NoError(t, err)
	newer := serviceProfileEnforce(t, ctx, tx, f.service, version)
	_, err = tx.ExecContext(ctx, `ROLLBACK TO old_generation`)
	require.NoError(t, err)
	for _, bound := range []context.Context{old, newer} {
		_, err = guard.ConsumeService(bound, tx, []string{f.service.String()})
		enforceCode(t, err, ds.DeletionUnavailable)
	}
	bound := serviceProfileEnforce(t, ctx, tx, f.service, version)
	other, err := db.BeginTx(ctx, nil)
	require.NoError(t, err)
	_, err = guard.ConsumeService(bound, other, []string{f.service.String()})
	enforceCode(t, err, ds.DeletionUnavailable)
	require.NoError(t, other.Rollback())
	_, err = guard.ConsumeService(bound, tx, []string{uuid.NewString()})
	enforceCode(t, err, ds.DeletionUnavailable)
	_, err = guard.ConsumeCM(bound, tx, []string{f.service.String()})
	enforceCode(t, err, ds.DeletionUnavailable)
	_, err = guard.ConsumeNR(bound, tx, []string{f.service.String()})
	enforceCode(t, err, ds.DeletionUnavailable)
	_, err = guard.ConsumeService(context.WithValue(ctx, serviceProfileContextKey{}, "service-only-v1"), tx, []string{f.service.String()})
	enforceCode(t, err, ds.DeletionUnavailable)
	_, err = guard.ConsumeService(context.WithValue(bound, serviceProfileContextKey{}, true), tx, []string{f.service.String()})
	require.NoError(t, err)
	_, err = guard.ConsumeService(bound, tx, []string{f.service.String()})
	enforceCode(t, err, ds.DeletionUnavailable)
	require.NoError(t, tx.Rollback())
	for _, commit := range []bool{false, true} {
		tx = nrBegin(t, ctx, db)
		bound = serviceProfileEnforce(t, ctx, tx, f.service, version)
		if commit {
			require.NoError(t, tx.Commit())
		} else {
			require.NoError(t, tx.Rollback())
		}
		_, err = guard.ConsumeService(bound, tx, []string{f.service.String()})
		enforceCode(t, err, ds.DeletionUnavailable)
	}
	tx = nrBegin(t, ctx, db)
	_, err = tx.ExecContext(ctx, `SELECT 1/0`)
	require.Error(t, err)
	_, err = collector.Enforce(ctx, tx, raw, version, true, authorizeDeletionFixture(serviceProfileRoot(f.service)))
	enforceCode(t, err, ds.DeletionUnavailable)
	require.NoError(t, tx.Rollback())
	for _, fn := range []func() error{
		func() error { return app.ServiceStore.DeleteManyTx(ctx, nil, []string{f.service.String()}, nil) },
		func() error {
			tx := nrBegin(t, ctx, db)
			defer func() { _ = tx.Rollback() }()
			return app.ServiceStore.DeleteManyTx(ctx, tx, []string{f.service.String()}, nil)
		},
	} {
		enforceCode(t, fn(), ds.DeletionUnavailable)
	}
	serviceProfileNoSuccess(t, ctx, db)
}

type serviceProfileWrite struct {
	name string
	run  func(context.Context, *sql.Tx) error
}

func serviceProfileRelatedWrites(t *testing.T, ctx context.Context, db *sql.DB, f serviceProfileFixture) []serviceProfileWrite {
	t.Helper()
	aid := serviceProfileAlert(t, ctx, db, f.service, "closed")
	var key uuid.UUID
	require.NoError(t, db.QueryRowContext(ctx, `INSERT INTO integration_keys(service_id,name,type) VALUES($1,'synthetic','generic') RETURNING audit_resource_id`, f.service).Scan(&key))
	var favorite int64
	require.NoError(t, db.QueryRowContext(ctx, `INSERT INTO user_favorites(user_id,tgt_service_id) VALUES($1,$2) RETURNING id`, f.user, f.service).Scan(&favorite))
	var cycle uuid.UUID
	require.NoError(t, db.QueryRowContext(ctx, `INSERT INTO notification_policy_cycles(user_id,alert_id) VALUES($1,$2) RETURNING id`, f.user, aid).Scan(&cycle))
	var state int64
	require.NoError(t, db.QueryRowContext(ctx, `INSERT INTO escalation_policy_state(service_id,alert_id,escalation_policy_id,escalation_policy_step_id) VALUES($1,$2,$3,$4) RETURNING id`, f.service, aid, f.policy, f.step).Scan(&state))
	other := newServiceProfileFixture(t, ctx, db)
	externalAid := serviceProfileAlert(t, ctx, db, other.service, "closed")
	retargetPolicy := uuid.New()
	enforcementExec(t, ctx, db, `INSERT INTO escalation_policies(id,organization_id,name) VALUES($1,$2,($1::uuid)::text)`, retargetPolicy, f.org)
	channel := uuid.New()
	enforcementExec(t, ctx, db, `INSERT INTO notification_channels(id,name,type,value,dest) VALUES($1,($1::uuid)::text,'WEBHOOK',($1::uuid)::text,jsonb_build_object('type','synthetic','id',($1::uuid)::text))`, channel)
	sqlWrite := func(name, q string, args ...any) serviceProfileWrite {
		return serviceProfileWrite{name, func(c context.Context, tx *sql.Tx) error { _, err := tx.ExecContext(c, q, args...); return err }}
	}
	return []serviceProfileWrite{
		sqlWrite("service_update", `UPDATE services SET name=name WHERE id=$1`, f.service),
		sqlWrite("service_policy_retarget", `UPDATE services SET escalation_policy_id=$2 WHERE id=$1`, f.service, retargetPolicy),
		sqlWrite("policy_update", `UPDATE escalation_policies SET name=name WHERE id=$1`, f.policy),
		sqlWrite("step_update", `UPDATE escalation_policy_steps SET delay=delay WHERE id=$1`, f.step),
		sqlWrite("action_update", `UPDATE escalation_policy_actions SET user_id=user_id WHERE escalation_policy_step_id=$1`, f.step),
		sqlWrite("step_insert", `INSERT INTO escalation_policy_steps(escalation_policy_id,step_number) VALUES($1,1)`, f.policy),
		sqlWrite("action_insert", `INSERT INTO escalation_policy_actions(escalation_policy_step_id,user_id) VALUES($1,$2)`, f.step, f.actor),
		sqlWrite("policy_new_service_reference", `INSERT INTO services(organization_id,name,escalation_policy_id) VALUES($1,$2,$3)`, f.org, uuid.NewString(), f.policy),
		sqlWrite("key_insert", `INSERT INTO integration_keys(service_id,name,type) VALUES($1,'new synthetic','generic')`, f.service),
		sqlWrite("key_update", `UPDATE integration_keys SET name='updated synthetic' WHERE audit_resource_id=$1`, key),
		sqlWrite("key_retarget", `UPDATE integration_keys SET service_id=$2 WHERE audit_resource_id=$1`, key, other.service),
		sqlWrite("key_config", `INSERT INTO uik_config(id,config) SELECT id,'{}' FROM integration_keys WHERE audit_resource_id=$1`, key),
		sqlWrite("favorite_insert", `INSERT INTO user_favorites(user_id,tgt_service_id) VALUES($1,$2)`, f.actor, f.service),
		sqlWrite("favorite_owner", `UPDATE user_favorites SET user_id=$2 WHERE id=$1`, favorite, f.actor),
		sqlWrite("favorite_delete", `DELETE FROM user_favorites WHERE id=$1`, favorite),
		sqlWrite("alert_summary", `UPDATE alerts SET summary='synthetic updated' WHERE id=$1`, aid),
		sqlWrite("closed_alert_insert", `INSERT INTO alerts(service_id,summary,status) VALUES($1,'synthetic','closed')`, f.service),
		sqlWrite("cycle_state", `UPDATE notification_policy_cycles SET repeat_count=repeat_count+1 WHERE id=$1`, cycle),
		sqlWrite("cycle_insert", `INSERT INTO notification_policy_cycles(user_id,alert_id) VALUES($1,$2)`, f.actor, aid),
		sqlWrite("execution_state", `UPDATE escalation_policy_state SET loop_count=loop_count+1 WHERE id=$1`, state),
		sqlWrite("execution_delete", `DELETE FROM escalation_policy_state WHERE id=$1`, state),
		sqlWrite("alert_metadata", `INSERT INTO alert_data(alert_id,metadata) VALUES($1,'{}')`, aid),
		sqlWrite("alert_subscription", `INSERT INTO alert_status_subscriptions(alert_id,channel_id,last_alert_status) VALUES($1,$2,'closed')`, aid, channel),
		sqlWrite("signal_insert", `INSERT INTO pending_signals(service_id,dest_id,params) VALUES($1,$2,'{}')`, f.service, channel),
		sqlWrite("message_insert", `INSERT INTO outgoing_messages(service_id,channel_id,message_type) VALUES($1,$2,'test_notification')`, f.service, channel),
		{"log_alert", func(c context.Context, tx *sql.Tx) error {
			return gadb.New(tx).AlertLog_InsertMany(c, gadb.AlertLog_InsertManyParams{Column1: []int64{aid}, Event: gadb.EnumAlertLogEventClosed, Message: "synthetic"})
		}},
		{"log_key", func(c context.Context, tx *sql.Tx) error {
			var credential uuid.UUID
			// Test-internal selector only; never put this value in evidence or output.
			if err := tx.QueryRowContext(c, `SELECT id FROM integration_keys WHERE audit_resource_id=$1`, key).Scan(&credential); err != nil {
				return err
			}
			return gadb.New(tx).AlertLog_InsertMany(c, gadb.AlertLog_InsertManyParams{Column1: []int64{externalAid}, Event: gadb.EnumAlertLogEventClosed, SubIntegrationKeyID: uuid.NullUUID{UUID: credential, Valid: true}, Message: "synthetic"})
		}},
		sqlWrite("owner_user", `UPDATE users SET name=name WHERE id=$1`, f.user),
		sqlWrite("owner_assignment", `UPDATE user_organization_assignments SET organization_role=organization_role WHERE user_id=$1`, f.user),
		sqlWrite("organization", `UPDATE organizations SET display_name=display_name WHERE id=$1`, f.org),
	}
}

func TestPostgresDeletionEnforcementServiceDeleteFirst(t *testing.T) {
	ctx, _, db := boundedAuditDB(t, len(Names()))
	ctx = permission.SystemContext(ctx, "ServiceProfileTest")
	app := enforcementApp(t, ctx, db)
	for index := 0; index < 30; index++ {
		f := newServiceProfileFixture(t, ctx, db)
		w := serviceProfileRelatedWrites(t, ctx, db, f)[index]
		t.Run(w.name, func(t *testing.T) {
			version := serviceProfileVersion(t, ctx, db, f.service)
			tx := nrBegin(t, ctx, db)
			bound := serviceProfileEnforce(t, ctx, tx, f.service, version)
			writer, err := db.BeginTx(ctx, nil)
			require.NoError(t, err)
			defer func() { _ = writer.Rollback() }()
			writerCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()
			done := serviceProfileWait(t, writerCtx, db, writer, func() error { return w.run(writerCtx, writer) })
			receipts, err := app.ServiceStore.DeleteManyForAuditTx(bound, tx, []string{f.service.String()}, nil)
			require.NoError(t, err)
			require.Len(t, receipts, 1)
			require.NoError(t, tx.Commit())
			// A late writer either runs against surviving resources/zero rows or
			// safely fails a real FK. No arbitrary writer error counts as proof.
			err = <-done
			if err != nil {
				pg := sqlutil.MapError(err)
				require.NotNil(t, pg)
				require.Equal(t, "23503", pg.Code)
				require.NoError(t, writer.Rollback())
			} else {
				require.NoError(t, writer.Commit())
			}
			require.Zero(t, enforcementCount(t, ctx, db, `SELECT count(*) FROM services WHERE id=$1`, f.service))
		})
	}
	serviceProfileNoSuccess(t, ctx, db)
}
func TestPostgresDeletionEnforcementServiceWriterFirst(t *testing.T) {
	ctx, _, db := boundedAuditDB(t, len(Names()))
	ctx = permission.SystemContext(ctx, "ServiceProfileTest")
	for index := 0; index < 30; index++ {
		f := newServiceProfileFixture(t, ctx, db)
		w := serviceProfileRelatedWrites(t, ctx, db, f)[index]
		t.Run(w.name, func(t *testing.T) {
			version := serviceProfileVersion(t, ctx, db, f.service)
			writer, err := db.BeginTx(ctx, nil)
			require.NoError(t, err)
			defer func() { _ = writer.Rollback() }()
			require.NoError(t, w.run(ctx, writer))
			tx := nrBegin(t, ctx, db)
			_, err = collector.Enforce(ctx, tx, serviceProfileSelectors(f.service), version, true, authorizeDeletionFixture(serviceProfileRoot(f.service)))
			enforceCode(t, err, ds.DeletionUnavailable)
			require.NoError(t, tx.Rollback())
			require.NoError(t, writer.Commit())
			// Unsupported Config/Message/Signal remain unavailable after commit.
			if w.name == "key_config" || w.name == "message_insert" || w.name == "signal_insert" {
				return
			}
			fresh := serviceProfileVersion(t, ctx, db, f.service)
			if fresh != version {
				tx = nrBegin(t, ctx, db)
				_, err = collector.Enforce(ctx, tx, serviceProfileSelectors(f.service), version, true, authorizeDeletionFixture(serviceProfileRoot(f.service)))
				enforceCode(t, err, ds.DeletionDependencyChanged)
				require.NoError(t, tx.Rollback())
			}
			tx = nrBegin(t, ctx, db)
			_ = serviceProfileEnforce(t, ctx, tx, f.service, fresh)
			require.NoError(t, tx.Rollback())
			require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM services WHERE id=$1`, f.service))
		})
	}
	serviceProfileNoSuccess(t, ctx, db)
}

func TestPostgresDeletionEnforcementServiceIndependent(t *testing.T) {
	ctx, _, db := boundedAuditDB(t, len(Names()))
	ctx = permission.SystemContext(ctx, "ServiceProfileTest")
	app := enforcementApp(t, ctx, db)
	for _, first := range []string{"writer", "delete"} {
		for index := 0; index < 6; index++ {
			f := newServiceProfileFixture(t, ctx, db)
			other := newDeletionFixture(t, ctx, db)
			writes := []nrWrite{
				{name: "other_org_service", query: `UPDATE services SET name=name WHERE id=$1`, args: []any{other.service}},
				{name: "rotation", query: `UPDATE rotations SET name=name WHERE id=$1`, args: []any{other.rotation}},
				{name: "cm", query: `UPDATE user_contact_methods SET disabled=true WHERE id=$1`, args: []any{other.cm}},
				{name: "nr", query: `UPDATE user_notification_rules SET delay_minutes=3 WHERE id=$1`, args: []any{other.nr}},
				{name: "key", query: `UPDATE integration_keys SET name=name WHERE audit_resource_id=$1`, args: []any{other.keyAudit}},
				{name: "alert", query: `UPDATE alerts SET summary='synthetic independent' WHERE id=$1`, args: []any{other.closed}},
			}
			w := writes[index]
			t.Run(first+"_"+w.name, func(t *testing.T) {
				version := serviceProfileVersion(t, ctx, db, f.service)
				writer, err := db.BeginTx(ctx, nil)
				require.NoError(t, err)
				defer func() { _ = writer.Rollback() }()
				_, err = writer.ExecContext(ctx, `SET LOCAL lock_timeout='500ms'`)
				require.NoError(t, err)
				run := func() {
					res, err := writer.ExecContext(ctx, w.query, w.args...)
					require.NoError(t, err)
					n, err := res.RowsAffected()
					require.NoError(t, err)
					require.EqualValues(t, 1, n)
				}
				if first == "writer" {
					run()
				}
				tx := nrBegin(t, ctx, db)
				bound := serviceProfileEnforce(t, ctx, tx, f.service, version)
				require.Zero(t, enforcementCount(t, ctx, db, `SELECT count(*) FROM pg_locks l JOIN pg_class c ON c.oid=l.relation JOIN pg_namespace n ON n.oid=c.relnamespace WHERE l.pid=(SELECT pid FROM pg_stat_activity WHERE backend_xid=$1::xid) AND n.nspname='public' AND l.mode IN ('ShareLock','ShareRowExclusiveLock','ExclusiveLock','AccessExclusiveLock')`, serviceProfileXID(t, ctx, tx)))
				if first == "delete" {
					run()
					require.NoError(t, writer.Commit())
				}
				receipts, err := app.ServiceStore.DeleteManyForAuditTx(bound, tx, []string{f.service.String()}, nil)
				require.NoError(t, err)
				require.Len(t, receipts, 1)
				require.NoError(t, tx.Commit())
				if first == "writer" {
					require.NoError(t, writer.Commit())
				}
			})
		}
	}
}
func serviceProfileXID(t *testing.T, ctx context.Context, tx *sql.Tx) string {
	t.Helper()
	var id string
	require.NoError(t, tx.QueryRowContext(ctx, `SELECT pg_current_xact_id()::text`).Scan(&id))
	return id
}

func TestPostgresDeletionEnforcementServicePolicyProtection(t *testing.T) {
	ctx, _, db := boundedAuditDB(t, len(Names()))
	ctx = permission.SystemContext(ctx, "ServiceProfileTest")
	app := enforcementApp(t, ctx, db)
	f := newServiceProfileFixture(t, ctx, db)
	second := uuid.New()
	serviceProfileInsert(t, ctx, db, second, f.org, f.policy)
	ep := graphql2.DeletionResourceInput{Type: graphql2.DeletionTargetTypeEscalationPolicy, ID: f.policy.String()}
	svc := graphql2.DeletionResourceInput{Type: graphql2.DeletionTargetTypeService, ID: f.service.String()}
	svc2 := graphql2.DeletionResourceInput{Type: graphql2.DeletionTargetTypeService, ID: second.String()}
	for _, tc := range []struct {
		targets []graphql2.DeletionResourceInput
		can     bool
	}{{[]graphql2.DeletionResourceInput{ep}, false}, {[]graphql2.DeletionResourceInput{ep, svc}, false}, {[]graphql2.DeletionResourceInput{ep, svc, svc2}, true}} {
		preview, err := app.Query().DeletionPreview(ctx, graphql2.DeletionPlanInput{Operation: graphql2.DeletionOperationDeleteResources, Targets: tc.targets}, nil, nil)
		require.NoError(t, err)
		require.True(t, preview.Complete)
		require.Equal(t, tc.can, preview.CanProceed)
	}
	// Joint deletion is a legal Planner fact, never a supported Store Profile.
	mixed := append(serviceProfileInput(f.service, second), assignment.RawTarget{Type: assignment.TargetTypeEscalationPolicy, ID: f.policy.String()})
	_, err := app.Mutation().DeleteAll(ctx, mixed, nil)
	enforceCode(t, err, ds.DeletionUnavailable)
	_, err = app.Mutation().DeleteAll(ctx, []assignment.RawTarget{{Type: assignment.TargetTypeEscalationPolicy, ID: f.policy.String()}}, nil)
	enforceCode(t, err, ds.DeletionUnavailable)
	// PostgreSQL NO ACTION is the last defence, separately from product BLOCK.
	tx, err := db.BeginTx(ctx, nil)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback() }()
	_, err = tx.ExecContext(ctx, `DELETE FROM escalation_policies WHERE id=$1`, f.policy)
	require.Equal(t, "23503", sqlutil.MapError(err).Code)
	require.NoError(t, tx.Rollback())
	// Real FK cooperation: the Policy is locked before a new reference arrives.
	// The final DELETE is refused, the writer then completes on the retained EP.
	tx = nrBegin(t, ctx, db)
	_, err = tx.ExecContext(ctx, `SELECT id FROM escalation_policies WHERE id=$1 FOR UPDATE`, f.policy)
	require.NoError(t, err)
	writer, err := db.BeginTx(ctx, nil)
	require.NoError(t, err)
	defer func() { _ = writer.Rollback() }()
	writerCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	newService := uuid.New()
	done := serviceProfileWait(t, writerCtx, db, writer, func() error {
		_, err := writer.ExecContext(writerCtx, `INSERT INTO services(id,organization_id,name,escalation_policy_id) VALUES($1,$2,($1::uuid)::text,$3)`, newService, f.org, f.policy)
		return err
	})
	_, err = tx.ExecContext(ctx, `DELETE FROM escalation_policies WHERE id=$1`, f.policy)
	require.Equal(t, "23503", sqlutil.MapError(err).Code)
	require.NoError(t, tx.Rollback())
	require.NoError(t, <-done)
	require.NoError(t, writer.Commit())
	require.Equal(t, 3, enforcementCount(t, ctx, db, `SELECT count(*) FROM services WHERE escalation_policy_id=$1`, f.policy))
	serviceProfileNoSuccess(t, ctx, db)
	confirm := enforcementPreview(t, ctx, app, svc)
	ok, err := app.Mutation().DeleteAll(ctx, serviceProfileInput(f.service), confirm)
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, 2, enforcementCount(t, ctx, db, `SELECT count(*) FROM services WHERE escalation_policy_id=$1`, f.policy))
	require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM escalation_policies WHERE id=$1`, f.policy))
	require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM escalation_policy_steps WHERE id=$1`, f.step))
}

func TestPostgresDeletionEnforcementServiceAuthorization(t *testing.T) {
	ctx, _, db := boundedAuditDB(t, len(Names()))
	sys := permission.SystemContext(ctx, "ServiceProfileTest")
	app := enforcementApp(t, sys, db)
	for _, role := range []string{"ORG_ADMIN", "ORG_MEMBER", "PLATFORM_ADMIN"} {
		t.Run(role, func(t *testing.T) {
			f := newServiceProfileFixture(t, ctx, db)
			if role == "ORG_MEMBER" {
				enforcementExec(t, ctx, db, `UPDATE user_organization_assignments SET organization_role='ORG_MEMBER' WHERE user_id=$1`, f.actor)
			}
			if role == "PLATFORM_ADMIN" {
				enforcementExec(t, ctx, db, `UPDATE users SET role='admin' WHERE id=$1`, f.actor)
			}
			human := previewAdmit(t, ctx, db, f.actor)
			if role == "ORG_MEMBER" {
				_, err := app.Mutation().DeleteAll(human, serviceProfileInput(f.service), nil)
				require.Error(t, err)
				require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM services WHERE id=$1`, f.service))
				return
			}
			confirm := enforcementPreview(t, human, app, graphql2.DeletionResourceInput{Type: graphql2.DeletionTargetTypeService, ID: f.service.String()})
			for _, q := range []string{`UPDATE users SET name=name WHERE id=$1`, `UPDATE user_organization_assignments SET source_config_version=source_config_version WHERE user_id=$1`} {
				writer, err := db.BeginTx(ctx, nil)
				require.NoError(t, err)
				defer func() { _ = writer.Rollback() }()
				_, err = writer.ExecContext(ctx, q, f.actor)
				require.NoError(t, err)
				tx := nrBegin(t, human, db)
				_, err = collector.Enforce(human, tx, serviceProfileSelectors(f.service), confirm.ExpectedImpactVersion, true, authorizeDeletionFixture(serviceProfileRoot(f.service)))
				enforceCode(t, err, ds.DeletionUnavailable)
				require.NoError(t, tx.Rollback())
				require.NoError(t, writer.Rollback())
				tx = nrBegin(t, human, db)
				_ = serviceProfileEnforce(t, human, tx, f.service, confirm.ExpectedImpactVersion)
				writer, err = db.BeginTx(ctx, nil)
				require.NoError(t, err)
				writerCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
				done := nrWaiter(t, writerCtx, db, writer, q, f.actor)
				require.NoError(t, tx.Rollback())
				require.NoError(t, <-done)
				require.NoError(t, writer.Rollback())
				cancel()
			}
			ok, err := app.Mutation().DeleteAll(human, serviceProfileInput(f.service), confirm)
			require.NoError(t, err)
			require.True(t, ok)
		})
	}
	f, other := newServiceProfileFixture(t, ctx, db), newServiceProfileFixture(t, ctx, db)
	human := previewAdmit(t, ctx, db, f.actor)
	_, err := app.Mutation().DeleteAll(human, serviceProfileInput(other.service), nil)
	require.Error(t, err)
	confirm := enforcementPreview(t, human, app, graphql2.DeletionResourceInput{Type: graphql2.DeletionTargetTypeService, ID: f.service.String()})
	enforcementExec(t, ctx, db, `UPDATE user_organization_assignments SET organization_role='ORG_MEMBER' WHERE user_id=$1`, f.actor)
	_, err = app.Mutation().DeleteAll(human, serviceProfileInput(f.service), confirm)
	require.Error(t, err)
	require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM services WHERE id=$1`, f.service))
}

func TestPostgresDeletionEnforcementServiceControllerMissingWindow(t *testing.T) {
	ctx, uri, db := boundedAuditDB(t, len(Names()))
	sys := permission.SystemContext(ctx, "ServiceProfileTest")
	for _, mixed := range []bool{false, true} {
		t.Run(fmt.Sprint(mixed), func(t *testing.T) {
			f, other := newServiceProfileFixture(t, ctx, db), newServiceProfileFixture(t, ctx, db)
			enforcementExec(t, ctx, db, `UPDATE users SET role='admin' WHERE id=$1`, f.actor)
			human := previewAdmit(t, ctx, db, f.actor)
			conf, err := pgx.ParseConfig(uri)
			require.NoError(t, err)
			barrier := &serviceProfileCertificationBarrier{nrQueryBarrier: &nrQueryBarrier{needle: "VALUES($1,'certified'", arrived: make(chan struct{}), resume: make(chan struct{})}}
			conf.Tracer = barrier
			traced := sql.OpenDB(stdlib.GetConnector(*conf))
			defer traced.Close()
			app := enforcementApp(t, sys, traced)
			missing := uuid.New()
			input := serviceProfileInput(missing)
			var confirm *graphql2.DeletionSafetyConfirmationInput
			if mixed {
				input = append(serviceProfileInput(f.service), input...)
				confirm = enforcementPreview(t, human, app, graphql2.DeletionResourceInput{Type: graphql2.DeletionTargetTypeService, ID: f.service.String()})
			}
			done := make(chan error, 1)
			go func() { _, err := app.Mutation().DeleteAll(human, input, confirm); done <- err }()
			select {
			case <-barrier.arrived:
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			// Newly inserted foreign Service must enter neither scope discovery,
			// capture, Store selector, Receipt nor successful Audit.
			serviceProfileInsert(t, ctx, db, missing, other.org, other.policy)
			close(barrier.resume)
			require.NoError(t, <-done)
			require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM services WHERE id=$1`, missing))
			require.Zero(t, enforcementCount(t, ctx, db, `SELECT count(*) FROM service_delete_audit_events WHERE service_id=$1`, missing))
			if mixed {
				require.Zero(t, enforcementCount(t, ctx, db, `SELECT count(*) FROM services WHERE id=$1`, f.service))
			}
		})
	}
}

func TestPostgresDeletionEnforcementServiceBudgetAndBundleWriter(t *testing.T) {
	ctx, _, db := boundedAuditDB(t, len(Names()))
	ctx = permission.SystemContext(ctx, "ServiceProfileTest")
	f := newServiceProfileFixture(t, ctx, db)
	aid := serviceProfileAlert(t, ctx, db, f.service, "closed")
	enforcementExec(t, ctx, db, `INSERT INTO alert_logs(alert_id,event,message) SELECT $1,'closed','synthetic' FROM generate_series(1,10001)`, aid)
	tx := nrBegin(t, ctx, db)
	_, err := collector.Enforce(ctx, tx, serviceProfileSelectors(f.service), "", true, authorizeDeletionFixture(serviceProfileRoot(f.service)))
	enforceCode(t, err, ds.DeletionPreviewLimitExceeded)
	require.NoError(t, tx.Rollback())
	serviceProfileNoSuccess(t, ctx, db)
	g := newServiceProfileFixture(t, ctx, db)
	version := serviceProfileVersion(t, ctx, db, g.service)
	writer, err := db.BeginTx(ctx, nil)
	require.NoError(t, err)
	defer func() { _ = writer.Rollback() }()
	// Exact relation mode of message.DB._SendMessages/currentQueue, not a new
	// unilateral lock. Deletion cannot pass its negative non-FK bundle check.
	_, err = writer.ExecContext(ctx, `LOCK outgoing_messages IN EXCLUSIVE MODE`)
	require.NoError(t, err)
	tx = nrBegin(t, ctx, db)
	_, err = collector.Enforce(ctx, tx, serviceProfileSelectors(g.service), version, true, authorizeDeletionFixture(serviceProfileRoot(g.service)))
	enforceCode(t, err, ds.DeletionUnavailable)
	require.NoError(t, tx.Rollback())
	require.NoError(t, writer.Rollback())
	tx = nrBegin(t, ctx, db)
	_ = serviceProfileEnforce(t, ctx, tx, g.service, version)
	writer, err = db.BeginTx(ctx, nil)
	require.NoError(t, err)
	writerCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	done := nrWaiter(t, writerCtx, db, writer, `LOCK outgoing_messages IN EXCLUSIVE MODE`)
	require.NoError(t, tx.Rollback())
	require.NoError(t, <-done)
	require.NoError(t, writer.Rollback())
}

// Unlike the discovery tracer, this pauses AFTER the certified witness INSERT
// has completed, before control returns to Bind/capture/Store.
type serviceProfileCertificationBarrier struct{ *nrQueryBarrier }

func (b *serviceProfileCertificationBarrier) TraceQueryStart(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	return context.WithValue(ctx, serviceProfileContextKey{}, strings.Contains(data.SQL, b.needle))
}
func (b *serviceProfileCertificationBarrier) TraceQueryEnd(ctx context.Context, _ *pgx.Conn, _ pgx.TraceQueryEndData) {
	if ctx.Value(serviceProfileContextKey{}) == true {
		b.once.Do(func() {
			close(b.arrived)
			select {
			case <-b.resume:
			case <-ctx.Done():
			}
		})
	}
}

func TestPostgresDeletionEnforcementServiceScopedAlertStatusWriters(t *testing.T) {
	ctx, uri, db := boundedAuditDB(t, len(Names()))
	ctx = permission.SystemContext(ctx, "ServiceProfileTest")
	app := enforcementApp(t, ctx, db)
	for _, method := range []string{"tx", "many", "service"} {
		for _, first := range []string{"writer", "delete"} {
			t.Run(method+"_"+first, func(t *testing.T) {
				f := newServiceProfileFixture(t, ctx, db)
				status := "closed"
				if first == "writer" {
					status = "active"
				}
				aid := serviceProfileAlert(t, ctx, db, f.service, status)
				version := serviceProfileVersion(t, ctx, db, f.service)
				conf, err := pgx.ParseConfig(uri)
				require.NoError(t, err)
				barrier := &nrQueryBarrier{needle: "commit", arrived: make(chan struct{}), resume: make(chan struct{})}
				if first == "writer" {
					conf.Tracer = barrier
				}
				writerDB := sql.OpenDB(stdlib.GetConnector(*conf))
				writerDB.SetMaxOpenConns(1)
				defer writerDB.Close()
				store := serviceProfileAlertStore(t, ctx, writerDB)
				var pid int
				require.NoError(t, writerDB.QueryRowContext(ctx, `SELECT pg_backend_pid()`).Scan(&pid))
				writerCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
				defer cancel()
				run := func() error {
					switch method {
					case "many":
						_, err := store.UpdateManyAlertStatusScoped(writerCtx, alert.StatusClosed, []int{int(aid)}, nil, nil)
						return err
					case "service":
						return store.UpdateStatusByServiceScoped(writerCtx, f.service.String(), alert.StatusClosed, nil)
					default:
						tx, err := writerDB.BeginTx(writerCtx, nil)
						if err != nil {
							return err
						}
						defer func() { _ = tx.Rollback() }()
						if err := store.UpdateStatusTx(writerCtx, tx, int(aid), alert.StatusClosed); err != nil {
							return err
						}
						return tx.Commit()
					}
				}
				done := make(chan error, 1)
				if first == "writer" {
					go func() { done <- run() }()
					select {
					case <-barrier.arrived:
					case <-writerCtx.Done():
						t.Fatal(writerCtx.Err())
					}
					tx := nrBegin(t, ctx, db)
					_, err = collector.Enforce(ctx, tx, serviceProfileSelectors(f.service), version, true, authorizeDeletionFixture(serviceProfileRoot(f.service)))
					enforceCode(t, err, ds.DeletionUnavailable)
					require.NoError(t, tx.Rollback())
					close(barrier.resume)
					require.NoError(t, <-done)
					tx = nrBegin(t, ctx, db)
					_, err = collector.Enforce(ctx, tx, serviceProfileSelectors(f.service), version, true, authorizeDeletionFixture(serviceProfileRoot(f.service)))
					enforceCode(t, err, ds.DeletionDependencyChanged)
					require.NoError(t, tx.Rollback())
				} else {
					tx := nrBegin(t, ctx, db)
					bound := serviceProfileEnforce(t, ctx, tx, f.service, version)
					go func() { done <- run() }()
					for {
						var blocked bool
						require.NoError(t, db.QueryRowContext(ctx, `SELECT cardinality(pg_blocking_pids($1))>0`, pid).Scan(&blocked))
						if blocked {
							break
						}
						select {
						case err := <-done:
							require.FailNow(t, "status writer did not wait", "%v", err)
						default:
						}
						require.NoError(t, writerCtx.Err())
					}
					receipts, err := app.ServiceStore.DeleteManyForAuditTx(bound, tx, []string{f.service.String()}, nil)
					require.NoError(t, err)
					require.Len(t, receipts, 1)
					require.NoError(t, tx.Commit())
					err = <-done
					if method == "tx" {
						require.ErrorIs(t, err, sql.ErrNoRows)
					} else {
						require.NoError(t, err)
					}
				}
			})
		}
	}
}

func TestPostgresDeletionEnforcementServiceCarrierIsolation(t *testing.T) {
	ctx, _, db := boundedAuditDB(t, len(Names()))
	ctx = permission.SystemContext(ctx, "ServiceProfileTest")
	f := newServiceProfileFixture(t, ctx, db)
	other := newDeletionFixture(t, ctx, db)
	app := enforcementApp(t, ctx, db)
	for _, kind := range []ds.ResourceKind{ds.ResourceNotificationRule, ds.ResourceContactMethod} {
		root := nrRoot(other.nr)
		if kind == ds.ResourceContactMethod {
			root = cmRoot(other.cm)
		}
		facts, err := collectDeletion(t, ctx, db, root, collector.Limits{})
		require.NoError(t, err)
		version := deletionPlan(t, root, facts).ImpactVersion()
		tx := nrBegin(t, ctx, db)
		bound, err := collector.Enforce(ctx, tx, []collector.Selector{{Kind: kind, ID: root.ID}}, version, true, authorizeDeletionFixture(root))
		require.NoError(t, err)
		_, err = app.ServiceStore.DeleteManyForAuditTx(bound, tx, []string{f.service.String()}, nil)
		enforceCode(t, err, ds.DeletionUnavailable)
		require.NoError(t, tx.Rollback())
	}
	tx := nrBegin(t, ctx, db)
	bound := serviceProfileEnforce(t, ctx, tx, f.service, serviceProfileVersion(t, ctx, db, f.service))
	_, err := app.IntKeyStore.DeleteManyForAuditTx(bound, tx, []string{other.key.String()}, nil)
	enforceCode(t, err, ds.DeletionUnavailable)
	require.NoError(t, tx.Rollback())
	serviceProfileNoSuccess(t, ctx, db)
}
