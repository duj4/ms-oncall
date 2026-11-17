package migrate

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/lib/pq"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/alert/alertlog"
	"github.com/target/goalert/assignment"
	ds "github.com/target/goalert/deletionsafety"
	collector "github.com/target/goalert/deletionsafety/postgres"
	"github.com/target/goalert/escalation"
	"github.com/target/goalert/gadb"
	"github.com/target/goalert/graphql2"
	guard "github.com/target/goalert/internal/deletionguard"
	"github.com/target/goalert/organization"
	"github.com/target/goalert/permission"
	"github.com/target/goalert/service"
	"github.com/target/goalert/util/sqlutil"
)

type epProfileFixture struct {
	boundedFixture
	policy, step, action uuid.UUID
}

func epProfileInsert(t *testing.T, ctx context.Context, db *sql.DB, id, org uuid.UUID) {
	t.Helper()
	enforcementExec(t, ctx, db, `INSERT INTO escalation_policies(id,organization_id,name) VALUES($1,$2,($1::uuid)::text)`, id, org)
}

func newEPProfileFixture(t *testing.T, ctx context.Context, db *sql.DB, steps bool) epProfileFixture {
	t.Helper()
	f := epProfileFixture{boundedFixture: newBoundedFixture(t, ctx, db), policy: uuid.New(), step: uuid.New(), action: uuid.New()}
	for _, u := range []uuid.UUID{f.actor, f.user} {
		enforcementExec(t, ctx, db, `UPDATE users SET role='user' WHERE id=$1`, u)
		_, err := organization.NewStore(db).CreateUserOrganizationAssignment(ctx, organization.CreateUserOrganizationAssignmentInput{UserID: u, UserOrganizationAssignmentValues: organization.UserOrganizationAssignmentValues{
			EffectiveOrganizationID: f.org, EffectiveOrganizationClassification: organization.ClassificationNormal, Role: organization.OrganizationRoleAdmin, MappingOutcome: organization.MappingOutcomeExactlyOne,
			Evaluation: organization.AssignmentEvaluation{AuthoritativeEvaluatedAt: time.Now(), SourceConfigVersion: "synthetic-ep-profile", MatchedCount: 1}}})
		require.NoError(t, err)
	}
	epProfileInsert(t, ctx, db, f.policy, f.org)
	if steps {
		enforcementExec(t, ctx, db, `INSERT INTO escalation_policy_steps(id,escalation_policy_id) VALUES($1,$2)`, f.step, f.policy)
		enforcementExec(t, ctx, db, `INSERT INTO escalation_policy_actions(id,escalation_policy_step_id,user_id) VALUES($1,$2,$3)`, f.action, f.step, f.user)
	}
	return f
}

func epProfileRoot(id uuid.UUID) ds.Resource {
	return ds.Resource{Kind: ds.ResourceEscalationPolicy, ID: id.String()}
}
func epProfileSelectors(ids ...uuid.UUID) []collector.Selector {
	var raw []collector.Selector
	for _, id := range ids {
		raw = append(raw, collector.Selector{Kind: ds.ResourceEscalationPolicy, ID: id.String()})
	}
	return raw
}
func epProfileInput(ids ...uuid.UUID) []assignment.RawTarget {
	var raw []assignment.RawTarget
	for _, id := range ids {
		raw = append(raw, assignment.RawTarget{Type: assignment.TargetTypeEscalationPolicy, ID: id.String()})
	}
	return raw
}
func epProfilePreviewInput(ids ...uuid.UUID) []graphql2.DeletionResourceInput {
	var raw []graphql2.DeletionResourceInput
	for _, id := range ids {
		raw = append(raw, graphql2.DeletionResourceInput{Type: graphql2.DeletionTargetTypeEscalationPolicy, ID: id.String()})
	}
	return raw
}
func epProfileVersion(t *testing.T, ctx context.Context, db *sql.DB, id uuid.UUID) string {
	t.Helper()
	facts, err := collectDeletion(t, ctx, db, epProfileRoot(id), collector.Limits{})
	require.NoError(t, err)
	return deletionPlan(t, epProfileRoot(id), facts).ImpactVersion()
}
func epProfileEnforce(t *testing.T, ctx context.Context, tx *sql.Tx, id uuid.UUID, version string) context.Context {
	t.Helper()
	bound, err := collector.Enforce(ctx, tx, epProfileSelectors(id), version, true, authorizeDeletionFixture(epProfileRoot(id)))
	require.NoError(t, err)
	return bound
}
func epProfileNoSuccess(t *testing.T, ctx context.Context, db *sql.DB) {
	t.Helper()
	require.Zero(t, enforcementCount(t, ctx, db, `SELECT count(*) FROM escalation_policy_delete_audit_events WHERE outcome='committed'`))
}

func TestPostgresDeletionEnforcementEPBusiness(t *testing.T) {
	ctx, _, db := boundedAuditDB(t, len(Names()))
	ctx = permission.SystemContext(ctx, "EPProfileTest")
	app := enforcementApp(t, ctx, db)
	for _, steps := range []bool{false, true} {
		t.Run(fmt.Sprint(steps), func(t *testing.T) {
			f := newEPProfileFixture(t, ctx, db, steps)
			confirm := enforcementPreview(t, ctx, app, epProfilePreviewInput(f.policy)...)
			if steps {
				_, err := app.Mutation().DeleteAll(ctx, epProfileInput(f.policy), nil)
				enforceCode(t, err, ds.DeletionConfirmationRequired)
				stale := *confirm
				stale.ExpectedImpactVersion = "stale"
				_, err = app.Mutation().DeleteAll(ctx, epProfileInput(f.policy), &stale)
				enforceCode(t, err, ds.DeletionDependencyChanged)
			}
			ok, err := app.Mutation().DeleteAll(ctx, epProfileInput(f.policy, f.policy, uuid.New()), confirm)
			require.NoError(t, err)
			require.True(t, ok)
			require.Zero(t, enforcementCount(t, ctx, db, `SELECT count(*) FROM escalation_policies WHERE id=$1`, f.policy))
			require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM escalation_policy_delete_audit_events WHERE root_id=$1 AND outcome='committed' AND operation='escalation_policy.delete' AND provenance='EXPLICIT'`, f.policy))
		})
	}
	f, g := newEPProfileFixture(t, ctx, db, true), newEPProfileFixture(t, ctx, db, true)
	confirm := enforcementPreview(t, ctx, app, epProfilePreviewInput(f.policy, g.policy)...)
	ok, err := app.Mutation().DeleteAll(ctx, epProfileInput(f.policy, g.policy, f.policy), confirm)
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, 2, enforcementCount(t, ctx, db, `SELECT count(*) FROM escalation_policy_delete_audit_events WHERE outcome='committed' AND root_id=ANY($1::uuid[])`, pq.Array([]uuid.UUID{f.policy, g.policy})))
	ok, err = app.Mutation().DeleteAll(ctx, epProfileInput(uuid.Nil), nil)
	require.NoError(t, err)
	require.True(t, ok)
	_, err = app.Mutation().DeleteAll(ctx, epProfileInput(f.policy), confirm)
	enforceCode(t, err, ds.DeletionDependencyChanged)
	_, err = app.Mutation().DeleteAll(ctx, epProfileInput(slicesRepeatService(f.policy, 51)...), nil)
	require.Error(t, err)
	require.NotEqual(t, string(ds.DeletionUnavailable), err.Error())
}

func TestPostgresDeletionEnforcementEPClosureAudit(t *testing.T) {
	ctx, _, db := boundedAuditDB(t, len(Names()))
	ctx = permission.SystemContext(ctx, "EPProfileTest")
	f := newEPProfileFixture(t, ctx, db, true)
	app := enforcementApp(t, ctx, db)
	second := uuid.New()
	enforcementExec(t, ctx, db, `INSERT INTO escalation_policy_steps(id,escalation_policy_id) VALUES($1,$2)`, second, f.policy)
	for _, target := range []struct {
		column string
		id     uuid.UUID
	}{{"schedule_id", f.schedule}, {"rotation_id", f.rotation}, {"user_id", f.user}} {
		enforcementExec(t, ctx, db, `INSERT INTO escalation_policy_actions(escalation_policy_step_id,`+target.column+`) VALUES($1,$2)`, second, target.id)
	}
	enforcementExec(t, ctx, db, `INSERT INTO user_favorites(user_id,tgt_escalation_policy_id) VALUES($1,$2)`, f.user, f.policy)
	confirm := enforcementPreview(t, ctx, app, epProfilePreviewInput(f.policy)...)
	ok, err := app.Mutation().DeleteAll(ctx, epProfileInput(f.policy), confirm)
	require.NoError(t, err)
	require.True(t, ok)
	for _, target := range []struct {
		table string
		id    uuid.UUID
	}{{"users", f.user}, {"schedules", f.schedule}, {"rotations", f.rotation}} {
		require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM `+target.table+` WHERE id=$1`, target.id))
	}
	require.Zero(t, enforcementCount(t, ctx, db, `SELECT count(*) FROM escalation_policy_steps WHERE escalation_policy_id=$1`, f.policy))
	require.Zero(t, enforcementCount(t, ctx, db, `SELECT count(*) FROM escalation_policy_actions WHERE escalation_policy_step_id=ANY($1::uuid[])`, pq.Array([]uuid.UUID{f.step, second})))
	var raw []byte
	require.NoError(t, db.QueryRowContext(ctx, `SELECT effects FROM escalation_policy_delete_audit_events WHERE root_id=$1 AND outcome='committed'`, f.policy).Scan(&raw))
	var effects []map[string]any
	require.NoError(t, json.Unmarshal(raw, &effects))
	require.Len(t, effects, 7) // 2 Steps, 4 Actions, 1 Favorite
	for _, e := range effects {
		require.Contains(t, []string{"escalation_policy_step", "escalation_policy_action", "escalation_policy_favorite"}, e["resource_type"])
		require.Equal(t, "CASCADE", e["provenance"])
		require.Equal(t, "fk_cascade", e["deletion_mechanism"])
		require.Equal(t, "escalation_policy_delete", e["cause"])
	}
}

func TestPostgresDeletionEnforcementEPServiceBlock(t *testing.T) {
	ctx, _, db := boundedAuditDB(t, len(Names()))
	ctx = permission.SystemContext(ctx, "EPProfileTest")
	app := enforcementApp(t, ctx, db)
	for _, n := range []int{1, 2} {
		for _, status := range []string{"none", "active", "triggered", "closed"} {
			t.Run(fmt.Sprintf("%d_%s", n, status), func(t *testing.T) {
				f := newEPProfileFixture(t, ctx, db, true)
				var services []uuid.UUID
				for range n {
					id := uuid.New()
					serviceProfileInsert(t, ctx, db, id, f.org, f.policy)
					services = append(services, id)
					if status != "none" {
						serviceProfileAlert(t, ctx, db, id, status)
					}
				}
				confirm := enforcementPreview(t, ctx, app, epProfilePreviewInput(f.policy)...)
				_, err := app.Mutation().DeleteAll(ctx, epProfileInput(f.policy), confirm)
				enforceCode(t, err, ds.DeletionBlocked)
				require.Equal(t, n, enforcementCount(t, ctx, db, `SELECT count(*) FROM services WHERE escalation_policy_id=$1`, f.policy))
				if n == 2 && status == "none" {
					conf := enforcementPreview(t, ctx, app, graphql2.DeletionResourceInput{Type: graphql2.DeletionTargetTypeService, ID: services[0].String()})
					ok, err := app.Mutation().DeleteAll(ctx, serviceProfileInput(services[0]), conf)
					require.NoError(t, err)
					require.True(t, ok)
					_, err = app.Mutation().DeleteAll(ctx, epProfileInput(f.policy), confirm)
					enforceCode(t, err, ds.DeletionBlocked)
					require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM services WHERE escalation_policy_id=$1`, f.policy))
				}
			})
		}
	}
	epProfileNoSuccess(t, ctx, db)
}

func TestPostgresDeletionEnforcementEPAuditFailure(t *testing.T) {
	ctx, _, db := boundedAuditDB(t, len(Names()))
	ctx = permission.SystemContext(ctx, "EPProfileTest")
	f := newEPProfileFixture(t, ctx, db, true)
	app := enforcementApp(t, ctx, db)
	confirm := enforcementPreview(t, ctx, app, epProfilePreviewInput(f.policy)...)
	enforcementExec(t, ctx, db, `CREATE FUNCTION synthetic_ep_sink_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.outcome='committed' THEN RAISE EXCEPTION 'synthetic audit failure'; END IF; RETURN NEW; END $$`)
	enforcementExec(t, ctx, db, `CREATE TRIGGER synthetic_ep_sink_failure BEFORE INSERT ON escalation_policy_delete_audit_events FOR EACH ROW EXECUTE FUNCTION synthetic_ep_sink_failure()`)
	_, err := app.Mutation().DeleteAll(ctx, epProfileInput(f.policy), confirm)
	require.Error(t, err)
	for _, row := range []struct {
		table string
		id    uuid.UUID
	}{{"escalation_policies", f.policy}, {"escalation_policy_steps", f.step}, {"escalation_policy_actions", f.action}} {
		require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM `+row.table+` WHERE id=$1`, row.id))
	}
	epProfileNoSuccess(t, ctx, db)
	enforcementExec(t, ctx, db, `DROP TRIGGER synthetic_ep_sink_failure ON escalation_policy_delete_audit_events`)
	ok, err := app.Mutation().DeleteAll(ctx, epProfileInput(f.policy), confirm)
	require.NoError(t, err)
	require.True(t, ok)
}

func TestPostgresDeletionEnforcementEPGuardLifecycle(t *testing.T) {
	ctx, _, db := boundedAuditDB(t, len(Names()))
	ctx = permission.SystemContext(ctx, "EPProfileTest")
	f := newEPProfileFixture(t, ctx, db, true)
	app := enforcementApp(t, ctx, db)
	version := epProfileVersion(t, ctx, db, f.policy)
	raw := epProfileSelectors(f.policy)
	for _, phase := range []string{"before_locks", "after_locks", "after_witness"} {
		t.Run(phase, func(t *testing.T) {
			tx := nrBegin(t, ctx, db)
			if phase == "before_locks" {
				_, err := tx.ExecContext(ctx, `SAVEPOINT checkpoint`)
				require.NoError(t, err)
			}
			checked, _, err := guard.StabilizeEP(ctx, tx, raw)
			require.NoError(t, err)
			if phase == "after_locks" {
				_, err = tx.ExecContext(ctx, `SAVEPOINT checkpoint`)
				require.NoError(t, err)
			}
			facts, err := collector.Collect(checked, tx, epProfileRoot(f.policy), collector.Recheck, collector.Limits{}, authorizeDeletionFixture(epProfileRoot(f.policy)))
			require.NoError(t, err)
			plan := deletionPlan(t, epProfileRoot(f.policy), facts)
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
				_, err = app.PolicyStore.DeleteManyPoliciesForAuditTx(bound, tx, []string{f.policy.String()}, nil)
				enforceCode(t, err, ds.DeletionUnavailable)
				_, err = guard.Bind(ctx, tx, checked, raw, plan, version, true)
				enforceCode(t, err, ds.DeletionUnavailable)
				bound = epProfileEnforce(t, ctx, tx, f.policy, version)
			}
			receipts, err := app.PolicyStore.DeleteManyPoliciesForAuditTx(bound, tx, []string{f.policy.String()}, nil)
			require.NoError(t, err)
			require.Len(t, receipts, 1)
			_, err = app.PolicyStore.DeleteManyPoliciesForAuditTx(bound, tx, []string{f.policy.String()}, nil)
			enforceCode(t, err, ds.DeletionUnavailable)
			require.NoError(t, tx.Rollback())
		})
	}
	tx := nrBegin(t, ctx, db)
	old := epProfileEnforce(t, ctx, tx, f.policy, version)
	_, err := tx.ExecContext(ctx, `SAVEPOINT old_generation`)
	require.NoError(t, err)
	newer := epProfileEnforce(t, ctx, tx, f.policy, version)
	_, err = tx.ExecContext(ctx, `ROLLBACK TO old_generation`)
	require.NoError(t, err)
	for _, bound := range []context.Context{old, newer} {
		_, err = guard.ConsumeEP(bound, tx, []string{f.policy.String()})
		enforceCode(t, err, ds.DeletionUnavailable)
	}
	bound := epProfileEnforce(t, ctx, tx, f.policy, version)
	other, err := db.BeginTx(ctx, nil)
	require.NoError(t, err)
	_, err = guard.ConsumeEP(bound, other, []string{f.policy.String()})
	enforceCode(t, err, ds.DeletionUnavailable)
	require.NoError(t, other.Rollback())
	_, err = guard.ConsumeEP(bound, tx, []string{uuid.NewString()})
	enforceCode(t, err, ds.DeletionUnavailable)
	_, err = guard.ConsumeCM(bound, tx, []string{f.policy.String()})
	enforceCode(t, err, ds.DeletionUnavailable)
	_, err = guard.ConsumeNR(bound, tx, []string{f.policy.String()})
	enforceCode(t, err, ds.DeletionUnavailable)
	_, err = guard.ConsumeEP(context.WithValue(ctx, serviceProfileContextKey{}, "escalation-policy-only-v1"), tx, []string{f.policy.String()})
	enforceCode(t, err, ds.DeletionUnavailable)
	_, err = guard.ConsumeEP(context.WithValue(bound, serviceProfileContextKey{}, true), tx, []string{f.policy.String()})
	require.NoError(t, err)
	_, err = guard.ConsumeEP(bound, tx, []string{f.policy.String()})
	enforceCode(t, err, ds.DeletionUnavailable)
	require.NoError(t, tx.Rollback())
	for _, commit := range []bool{false, true} {
		tx = nrBegin(t, ctx, db)
		bound = epProfileEnforce(t, ctx, tx, f.policy, version)
		if commit {
			require.NoError(t, tx.Commit())
		} else {
			require.NoError(t, tx.Rollback())
		}
		_, err = guard.ConsumeEP(bound, tx, []string{f.policy.String()})
		enforceCode(t, err, ds.DeletionUnavailable)
	}
	tx = nrBegin(t, ctx, db)
	_, err = tx.ExecContext(ctx, `SELECT 1/0`)
	require.Error(t, err)
	_, err = collector.Enforce(ctx, tx, raw, version, true, authorizeDeletionFixture(epProfileRoot(f.policy)))
	enforceCode(t, err, ds.DeletionUnavailable)
	require.NoError(t, tx.Rollback())
	for _, fn := range []func() error{
		func() error { return app.PolicyStore.DeleteManyPoliciesTx(ctx, nil, []string{f.policy.String()}, nil) },
		func() error {
			tx := nrBegin(t, ctx, db)
			defer func() { _ = tx.Rollback() }()
			return app.PolicyStore.DeleteManyPoliciesTx(ctx, tx, []string{f.policy.String()}, nil)
		},
	} {
		enforceCode(t, fn(), ds.DeletionUnavailable)
	}
	epProfileNoSuccess(t, ctx, db)
}

func TestPostgresDeletionEnforcementEPMissingWindow(t *testing.T) {
	ctx, _, db := boundedAuditDB(t, len(Names()))
	ctx = permission.SystemContext(ctx, "EPProfileTest")
	f := newEPProfileFixture(t, ctx, db, true)
	app := enforcementApp(t, ctx, db)
	for _, legacy := range []bool{false, true} {
		absent := uuid.New()
		tx := nrBegin(t, ctx, db)
		bound, err := collector.Enforce(ctx, tx, epProfileSelectors(absent), "", false, authorizeDeletionFixture(epProfileRoot(absent)))
		require.NoError(t, err)
		epProfileInsert(t, ctx, db, absent, f.org)
		if legacy {
			require.NoError(t, app.PolicyStore.DeleteManyPoliciesTx(bound, tx, []string{absent.String()}, nil))
		} else {
			receipts, err := app.PolicyStore.DeleteManyPoliciesForAuditTx(bound, tx, []string{absent.String()}, nil)
			require.NoError(t, err)
			require.Empty(t, receipts)
		}
		require.NoError(t, tx.Commit())
		require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM escalation_policies WHERE id=$1`, absent))
	}
	absent := uuid.New()
	tx := nrBegin(t, ctx, db)
	version := epProfileVersion(t, ctx, db, f.policy)
	bound, err := collector.Enforce(ctx, tx, epProfileSelectors(f.policy, absent), version, true, authorizeDeletionFixture(epProfileRoot(f.policy)))
	require.NoError(t, err)
	epProfileInsert(t, ctx, db, absent, f.org)
	receipts, err := app.PolicyStore.DeleteManyPoliciesForAuditTx(bound, tx, []string{f.policy.String(), absent.String()}, nil)
	require.NoError(t, err)
	require.Len(t, receipts, 1)
	require.Equal(t, f.policy, receipts[0].ID)
	require.NoError(t, tx.Commit())
	require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM escalation_policies WHERE id=$1`, absent))
	epProfileNoSuccess(t, ctx, db)
}

func TestPostgresDeletionEnforcementEPControllerMissingWindow(t *testing.T) {
	ctx, uri, db := boundedAuditDB(t, len(Names()))
	sys := permission.SystemContext(ctx, "EPProfileTest")
	for _, mixed := range []bool{false, true} {
		t.Run(fmt.Sprint(mixed), func(t *testing.T) {
			f, other := newEPProfileFixture(t, ctx, db, true), newEPProfileFixture(t, ctx, db, true)
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
			input := epProfileInput(missing)
			var confirm *graphql2.DeletionSafetyConfirmationInput
			if mixed {
				input = append(epProfileInput(f.policy), input...)
				confirm = enforcementPreview(t, human, app, epProfilePreviewInput(f.policy)...)
			}
			done := make(chan error, 1)
			go func() { _, err := app.Mutation().DeleteAll(human, input, confirm); done <- err }()
			select {
			case <-barrier.arrived:
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			epProfileInsert(t, ctx, db, missing, other.org)
			close(barrier.resume)
			require.NoError(t, <-done)
			require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM escalation_policies WHERE id=$1`, missing))
			require.Zero(t, enforcementCount(t, ctx, db, `SELECT count(*) FROM escalation_policy_delete_audit_events WHERE root_id=$1`, missing))
			if mixed {
				require.Zero(t, enforcementCount(t, ctx, db, `SELECT count(*) FROM escalation_policies WHERE id=$1`, f.policy))
			}
		})
	}
}

func TestPostgresDeletionEnforcementEPUnsupported(t *testing.T) {
	ctx, _, db := boundedAuditDB(t, len(Names()))
	ctx = permission.SystemContext(ctx, "EPProfileTest")
	app := enforcementApp(t, ctx, db)
	for _, shape := range []string{"open_history", "closed_history", "message", "channel", "label", "active_state", "closed_state", "foreign_step_state"} {
		t.Run(shape, func(t *testing.T) {
			f, good := newEPProfileFixture(t, ctx, db, true), newEPProfileFixture(t, ctx, db, true)
			switch shape {
			case "open_history", "closed_history":
				end := "NULL"
				if shape == "closed_history" {
					end = "now()"
				}
				enforcementExec(t, ctx, db, `INSERT INTO ep_step_on_call_users(ep_step_id,user_id,end_time) VALUES($1,$2,`+end+`)`, f.step, f.user)
			case "message", "channel":
				channel := uuid.New()
				enforcementExec(t, ctx, db, `INSERT INTO notification_channels(id,name,type,value,dest) VALUES($1,($1::uuid)::text,'WEBHOOK',($1::uuid)::text,jsonb_build_object('type','unknown','id',($1::uuid)::text))`, channel)
				if shape == "message" {
					enforcementExec(t, ctx, db, `INSERT INTO outgoing_messages(escalation_policy_id,channel_id,message_type) VALUES($1,$2,'test_notification')`, f.policy, channel)
				} else {
					enforcementExec(t, ctx, db, `INSERT INTO escalation_policy_actions(escalation_policy_step_id,channel_id) VALUES($1,$2)`, f.step, channel)
				}
			case "label":
				enforcementExec(t, ctx, db, `INSERT INTO labels(key,value,tgt_ep_id) VALUES('synthetic','unsupported',$1)`, f.policy)
			default:
				svc := uuid.New()
				serviceProfileInsert(t, ctx, db, svc, f.org, f.policy)
				status := "closed"
				if shape == "active_state" {
					status = "active"
				}
				aid := serviceProfileAlert(t, ctx, db, svc, status)
				step := f.step
				if shape == "foreign_step_state" {
					step = good.step
				}
				enforcementExec(t, ctx, db, `INSERT INTO escalation_policy_state(service_id,alert_id,escalation_policy_id,escalation_policy_step_id) VALUES($1,$2,$3,$4) ON CONFLICT(alert_id) DO UPDATE SET escalation_policy_step_id=excluded.escalation_policy_step_id`, svc, aid, f.policy, step)
			}
			if shape == "open_history" || shape == "closed_history" || shape == "message" || shape == "channel" || shape == "label" {
				previewRejected(t, previewHTTP(t, ctx, app, previewInput(graphql2.DeletionTargetTypeEscalationPolicy, f.policy), 1, nil), string(ds.DeletionUnavailable))
			}
			_, err := app.Mutation().DeleteAll(ctx, epProfileInput(good.policy, f.policy), &graphql2.DeletionSafetyConfirmationInput{ExpectedImpactVersion: "guessed", AcknowledgeImpacts: true})
			code := ds.DeletionUnavailable
			if shape == "active_state" || shape == "closed_state" {
				code = ds.DeletionBlocked
			}
			enforceCode(t, err, code)
			require.Equal(t, 2, enforcementCount(t, ctx, db, `SELECT count(*) FROM escalation_policies WHERE id=ANY($1::uuid[])`, pq.Array([]uuid.UUID{good.policy, f.policy})))
		})
	}
	f := newEPProfileFixture(t, ctx, db, true)
	for _, kind := range []assignment.TargetType{assignment.TargetTypeService, assignment.TargetTypeUser, assignment.TargetTypeSchedule, assignment.TargetTypeRotation, assignment.TargetTypeIntegrationKey, assignment.TargetTypeContactMethod, assignment.TargetTypeNotificationRule} {
		_, err := app.Mutation().DeleteAll(ctx, append(epProfileInput(f.policy), assignment.RawTarget{Type: kind, ID: uuid.NewString()}), nil)
		enforceCode(t, err, ds.DeletionUnavailable)
	}
	epProfileNoSuccess(t, ctx, db)
}

func epProfileRelatedWrites(t *testing.T, ctx context.Context, db *sql.DB, f epProfileFixture) []serviceProfileWrite {
	t.Helper()
	otherPolicy, otherStep, svc := uuid.New(), uuid.New(), uuid.New()
	epProfileInsert(t, ctx, db, otherPolicy, f.org)
	enforcementExec(t, ctx, db, `INSERT INTO escalation_policy_steps(id,escalation_policy_id) VALUES($1,$2)`, otherStep, otherPolicy)
	serviceProfileInsert(t, ctx, db, svc, f.org, otherPolicy)
	var favorite int64
	require.NoError(t, db.QueryRowContext(ctx, `INSERT INTO user_favorites(user_id,tgt_escalation_policy_id) VALUES($1,$2) RETURNING id`, f.user, f.policy).Scan(&favorite))
	logs, err := alertlog.NewStore(ctx, db, nil)
	require.NoError(t, err)
	store, err := escalation.NewStore(ctx, db, escalation.Config{LogStore: logs})
	require.NoError(t, err)
	svcStore, err := service.NewStore(ctx, db)
	require.NoError(t, err)
	sqlWrite := func(name, q string, args ...any) serviceProfileWrite {
		return serviceProfileWrite{name, func(c context.Context, tx *sql.Tx) error { _, err := tx.ExecContext(c, q, args...); return err }}
	}
	return []serviceProfileWrite{
		{"step_insert_store", func(c context.Context, tx *sql.Tx) error {
			_, err := store.CreateStepTx(c, tx, &escalation.Step{PolicyID: f.policy.String(), DelayMinutes: 1})
			return err
		}},
		{"step_delete_store", func(c context.Context, tx *sql.Tx) error {
			_, err := store.DeleteStepReceiptTx(c, tx, f.step)
			if err == sql.ErrNoRows {
				return nil
			}
			return err
		}},
		{"step_number_store", func(c context.Context, tx *sql.Tx) error { return store.UpdateStepNumberTx(c, tx, f.step, 0) }},
		{"step_delay_store", func(c context.Context, tx *sql.Tx) error { return store.UpdateStepDelayTx(c, tx, f.step, 2) }},
		sqlWrite("step_move", `UPDATE escalation_policy_steps SET escalation_policy_id=$2,step_number=1 WHERE id=$1`, f.step, otherPolicy),
		{"action_insert_gadb", func(c context.Context, tx *sql.Tx) error {
			return gadb.New(tx).EPStepActionsAddAction(c, gadb.EPStepActionsAddActionParams{EscalationPolicyStepID: f.step, UserID: uuid.NullUUID{UUID: f.actor, Valid: true}})
		}},
		sqlWrite("action_delete", `DELETE FROM escalation_policy_actions WHERE id=$1`, f.action),
		sqlWrite("action_retarget", `UPDATE escalation_policy_actions SET user_id=$2 WHERE id=$1`, f.action, f.actor),
		sqlWrite("action_move", `UPDATE escalation_policy_actions SET escalation_policy_step_id=$2 WHERE id=$1`, f.action, otherStep),
		sqlWrite("policy_update", `UPDATE escalation_policies SET repeat=repeat+1 WHERE id=$1`, f.policy),
		{"service_create_store", func(c context.Context, tx *sql.Tx) error {
			_, err := svcStore.CreateServiceTx(c, tx, &service.Service{Name: "synthetic-" + uuid.NewString(), Description: "synthetic", OrganizationID: f.org, EscalationPolicyID: f.policy.String()})
			return err
		}},
		{"service_retarget_store", func(c context.Context, tx *sql.Tx) error {
			return svcStore.UpdateTx(c, tx, &service.Service{ID: svc.String(), Name: "synthetic-" + svc.String(), Description: "synthetic", OrganizationID: f.org, EscalationPolicyID: f.policy.String()}, nil)
		}},
		sqlWrite("favorite_insert", `INSERT INTO user_favorites(user_id,tgt_escalation_policy_id) VALUES($1,$2)`, f.actor, f.policy),
		sqlWrite("favorite_owner", `UPDATE user_favorites SET user_id=$2 WHERE id=$1`, favorite, f.actor),
		sqlWrite("favorite_delete", `DELETE FROM user_favorites WHERE id=$1`, favorite),
		sqlWrite("user_target", `UPDATE users SET name=name WHERE id=$1`, f.user),
		sqlWrite("target_assignment", `UPDATE user_organization_assignments SET organization_role=organization_role WHERE user_id=$1`, f.user),
		sqlWrite("schedule_target", `UPDATE schedules SET name=name WHERE id=$1`, f.schedule),
		sqlWrite("rotation_target", `UPDATE rotations SET name=name WHERE id=$1`, f.rotation),
		sqlWrite("organization", `UPDATE organizations SET display_name=display_name WHERE id=$1`, f.org),
		{"other_ep_step_insert", func(c context.Context, tx *sql.Tx) error {
			_, err := store.CreateStepTx(c, tx, &escalation.Step{PolicyID: otherPolicy.String(), DelayMinutes: 1})
			return err
		}},
		sqlWrite("history_insert", `INSERT INTO ep_step_on_call_users(ep_step_id,user_id) VALUES($1,$2)`, f.step, f.user),
	}
}

func TestPostgresDeletionEnforcementEPDeleteFirst(t *testing.T) {
	ctx, uri, db := boundedAuditDB(t, len(Names()))
	ctx = permission.SystemContext(ctx, "EPProfileTest")
	for index := 0; index < 22; index++ {
		f := newEPProfileFixture(t, ctx, db, true)
		// Cover all retained target kinds on the selected EP.
		enforcementExec(t, ctx, db, `INSERT INTO escalation_policy_actions(escalation_policy_step_id,schedule_id) VALUES($1,$2)`, f.step, f.schedule)
		enforcementExec(t, ctx, db, `INSERT INTO escalation_policy_actions(escalation_policy_step_id,rotation_id) VALUES($1,$2)`, f.step, f.rotation)
		w := epProfileRelatedWrites(t, ctx, db, f)[index]
		t.Run(w.name, func(t *testing.T) {
			conf, err := pgx.ParseConfig(uri)
			require.NoError(t, err)
			barrier := &serviceProfileCertificationBarrier{nrQueryBarrier: &nrQueryBarrier{needle: "VALUES($1,'certified'", arrived: make(chan struct{}), resume: make(chan struct{})}}
			conf.Tracer = barrier
			traced := sql.OpenDB(stdlib.GetConnector(*conf))
			defer traced.Close()
			app := enforcementApp(t, ctx, traced)
			confirm := enforcementPreview(t, ctx, app, epProfilePreviewInput(f.policy)...)
			deleted := make(chan error, 1)
			go func() { _, err := app.Mutation().DeleteAll(ctx, epProfileInput(f.policy), confirm); deleted <- err }()
			select {
			case <-barrier.arrived:
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			writer := epProfileWriter(t, ctx, db)
			writerCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()
			done := serviceProfileWait(t, writerCtx, db, writer, func() error { return w.run(writerCtx, writer) })
			close(barrier.resume)
			require.NoError(t, <-deleted)
			err = <-done
			if err != nil {
				pg := sqlutil.MapError(err)
				require.NotNil(t, pg)
				require.Equal(t, "23503", pg.Code)
				require.NoError(t, writer.Rollback())
			} else {
				require.NoError(t, writer.Commit())
			}
			require.Zero(t, enforcementCount(t, ctx, db, `SELECT count(*) FROM escalation_policies WHERE id=$1`, f.policy))
			require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM escalation_policy_delete_audit_events WHERE root_id=$1 AND outcome='committed'`, f.policy))
			for _, target := range []struct {
				table string
				id    uuid.UUID
			}{{"users", f.user}, {"schedules", f.schedule}, {"rotations", f.rotation}} {
				require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM `+target.table+` WHERE id=$1`, target.id))
			}
		})
	}
}

func TestPostgresDeletionEnforcementEPWriterFirst(t *testing.T) {
	ctx, _, db := boundedAuditDB(t, len(Names()))
	ctx = permission.SystemContext(ctx, "EPProfileTest")
	app := enforcementApp(t, ctx, db)
	for index := 0; index < 22; index++ {
		f := newEPProfileFixture(t, ctx, db, true)
		enforcementExec(t, ctx, db, `INSERT INTO escalation_policy_actions(escalation_policy_step_id,schedule_id) VALUES($1,$2)`, f.step, f.schedule)
		enforcementExec(t, ctx, db, `INSERT INTO escalation_policy_actions(escalation_policy_step_id,rotation_id) VALUES($1,$2)`, f.step, f.rotation)
		w := epProfileRelatedWrites(t, ctx, db, f)[index]
		t.Run(w.name, func(t *testing.T) {
			version := epProfileVersion(t, ctx, db, f.policy)
			writer := epProfileWriter(t, ctx, db)
			writeErr := w.run(ctx, writer)
			require.NoError(t, writeErr)
			_, err := app.Mutation().DeleteAll(ctx, epProfileInput(f.policy), &graphql2.DeletionSafetyConfirmationInput{ExpectedImpactVersion: version, AcknowledgeImpacts: true})
			enforceCode(t, err, ds.DeletionUnavailable)
			commitErr := writer.Commit()
			if w.name == "step_move" {
				var pg *pgconn.PgError
				require.ErrorAs(t, commitErr, &pg)
				require.Equal(t, "P0001", pg.Code)
				require.Contains(t, commitErr.Error(), "must not change escalation_policy_id")
				require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM escalation_policy_steps WHERE id=$1 AND escalation_policy_id=$2`, f.step, f.policy))
			} else {
				require.NoError(t, commitErr)
			}
			require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM escalation_policies WHERE id=$1`, f.policy))
			require.Zero(t, enforcementCount(t, ctx, db, `SELECT count(*) FROM escalation_policy_delete_audit_events WHERE root_id=$1 AND outcome='committed'`, f.policy))
			if w.name == "history_insert" {
				return
			}
			fresh := epProfileVersion(t, ctx, db, f.policy)
			tx := nrBegin(t, ctx, db)
			_, err = collector.Enforce(ctx, tx, epProfileSelectors(f.policy), fresh, true, authorizeDeletionFixture(epProfileRoot(f.policy)))
			if w.name == "service_create_store" || w.name == "service_retarget_store" {
				enforceCode(t, err, ds.DeletionBlocked)
			} else {
				require.NoError(t, err)
			}
			require.NoError(t, tx.Rollback())
			if fresh != version && w.name != "service_create_store" && w.name != "service_retarget_store" {
				tx = nrBegin(t, ctx, db)
				_, err = collector.Enforce(ctx, tx, epProfileSelectors(f.policy), version, true, authorizeDeletionFixture(epProfileRoot(f.policy)))
				enforceCode(t, err, ds.DeletionDependencyChanged)
				require.NoError(t, tx.Rollback())
			}
		})
	}
	epProfileNoSuccess(t, ctx, db)
}

func epProfileWriter(t *testing.T, ctx context.Context, db *sql.DB) *sql.Tx {
	t.Helper()
	tx, err := db.BeginTx(ctx, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = tx.Rollback() })
	return tx
}

func TestPostgresDeletionEnforcementEPIndependent(t *testing.T) {
	ctx, uri, db := boundedAuditDB(t, len(Names()))
	ctx = permission.SystemContext(ctx, "EPProfileTest")
	for _, first := range []string{"writer", "delete"} {
		for index := 0; index < 7; index++ {
			f := newEPProfileFixture(t, ctx, db, true)
			other := newDeletionFixture(t, ctx, db)
			writes := []nrWrite{
				{name: "organization", query: `UPDATE organizations SET display_name=display_name WHERE id=$1`, args: []any{other.org}},
				{name: "service", query: `UPDATE services SET name=name WHERE id=$1`, args: []any{other.service}},
				{name: "rotation", query: `UPDATE rotations SET name=name WHERE id=$1`, args: []any{other.rotation}},
				{name: "cm", query: `UPDATE user_contact_methods SET disabled=true WHERE id=$1`, args: []any{other.cm}},
				{name: "nr", query: `UPDATE user_notification_rules SET delay_minutes=3 WHERE id=$1`, args: []any{other.nr}},
				{name: "key", query: `UPDATE integration_keys SET name=name WHERE audit_resource_id=$1`, args: []any{other.keyAudit}},
				{name: "schedule", query: `UPDATE schedules SET name=name WHERE id=$1`, args: []any{other.schedule}},
			}
			w := writes[index]
			t.Run(first+"_"+w.name, func(t *testing.T) {
				writer := epProfileWriter(t, ctx, db)
				_, err := writer.ExecContext(ctx, `SET LOCAL lock_timeout='500ms'`)
				require.NoError(t, err)
				run := func() {
					res, err := writer.ExecContext(ctx, w.query, w.args...)
					require.NoError(t, err)
					n, err := res.RowsAffected()
					require.NoError(t, err)
					require.EqualValues(t, 1, n)
				}
				conf, err := pgx.ParseConfig(uri)
				require.NoError(t, err)
				barrier := &serviceProfileCertificationBarrier{nrQueryBarrier: &nrQueryBarrier{needle: "VALUES($1,'certified'", arrived: make(chan struct{}), resume: make(chan struct{})}}
				if first == "delete" {
					conf.Tracer = barrier
				}
				traced := sql.OpenDB(stdlib.GetConnector(*conf))
				defer traced.Close()
				app := enforcementApp(t, ctx, traced)
				confirm := enforcementPreview(t, ctx, app, epProfilePreviewInput(f.policy)...)
				if first == "writer" {
					run()
					ok, err := app.Mutation().DeleteAll(ctx, epProfileInput(f.policy), confirm)
					require.NoError(t, err)
					require.True(t, ok)
					require.NoError(t, writer.Commit())
				} else {
					done := make(chan error, 1)
					go func() { _, err := app.Mutation().DeleteAll(ctx, epProfileInput(f.policy), confirm); done <- err }()
					select {
					case <-barrier.arrived:
					case <-ctx.Done():
						t.Fatal(ctx.Err())
					}
					// The sole strong public relation lock is the frozen Step trigger
					// mode. Ordinary writes to these unrelated resources still commit.
					require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM pg_locks l JOIN pg_class c ON c.oid=l.relation JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND l.mode IN ('ShareLock','ShareRowExclusiveLock','ExclusiveLock','AccessExclusiveLock') AND l.granted`))
					run()
					require.NoError(t, writer.Commit())
					close(barrier.resume)
					require.NoError(t, <-done)
				}
				require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM escalation_policy_delete_audit_events WHERE root_id=$1 AND outcome='committed'`, f.policy))
			})
		}
	}
}

func TestPostgresDeletionEnforcementEPBudgetAndTriggerOrder(t *testing.T) {
	ctx, _, db := boundedAuditDB(t, len(Names()))
	ctx = permission.SystemContext(ctx, "EPProfileTest")
	f := newEPProfileFixture(t, ctx, db, true)
	// Verify the actual migrated definitions, not a copied trigger assumption.
	for _, function := range []string{"fn_inc_ep_step_number_on_insert", "fn_decr_ep_step_number_on_delete"} {
		var definition string
		require.NoError(t, db.QueryRowContext(ctx, `SELECT pg_get_functiondef(oid) FROM pg_proc WHERE proname=$1`, function).Scan(&definition))
		require.Contains(t, definition, "LOCK escalation_policy_steps IN EXCLUSIVE MODE")
	}
	version := epProfileVersion(t, ctx, db, f.policy)
	for _, q := range []string{`SELECT id FROM escalation_policies WHERE id=$1 FOR UPDATE`, `LOCK escalation_policy_steps IN ROW EXCLUSIVE MODE`, `LOCK escalation_policy_steps IN SHARE MODE`} {
		writer := epProfileWriter(t, ctx, db)
		if q == `SELECT id FROM escalation_policies WHERE id=$1 FOR UPDATE` {
			_, err := writer.ExecContext(ctx, q, f.policy)
			require.NoError(t, err)
		} else {
			_, err := writer.ExecContext(ctx, q)
			require.NoError(t, err)
		}
		tx := nrBegin(t, ctx, db)
		_, err := collector.Enforce(ctx, tx, epProfileSelectors(f.policy), version, true, authorizeDeletionFixture(epProfileRoot(f.policy)))
		enforceCode(t, err, ds.DeletionUnavailable)
		require.NoError(t, tx.Rollback())
		require.NoError(t, writer.Rollback())
	}
	// Favorites have no per-EP config limit. One extra actual identity must
	// reject, not truncate the stable set and certify a partial capture.
	enforcementExec(t, ctx, db, `WITH u AS (INSERT INTO users(id,name) SELECT gen_random_uuid(),'synthetic budget' FROM generate_series(1,10001) RETURNING id) INSERT INTO user_favorites(user_id,tgt_escalation_policy_id) SELECT id,$1 FROM u`, f.policy)
	tx := nrBegin(t, ctx, db)
	_, err := collector.Enforce(ctx, tx, epProfileSelectors(f.policy), "", true, authorizeDeletionFixture(epProfileRoot(f.policy)))
	enforceCode(t, err, ds.DeletionPreviewLimitExceeded)
	require.NoError(t, tx.Rollback())
	epProfileNoSuccess(t, ctx, db)
}

func TestPostgresDeletionEnforcementEPCarrierIsolation(t *testing.T) {
	ctx, _, db := boundedAuditDB(t, len(Names()))
	ctx = permission.SystemContext(ctx, "EPProfileTest")
	f := newEPProfileFixture(t, ctx, db, true)
	other := newServiceProfileFixture(t, ctx, db)
	nr := newDeletionFixture(t, ctx, db)
	app := enforcementApp(t, ctx, db)
	for _, root := range []ds.Resource{nrRoot(nr.nr), cmRoot(nr.cm), serviceProfileRoot(other.service)} {
		facts, err := collectDeletion(t, ctx, db, root, collector.Limits{})
		require.NoError(t, err)
		tx := nrBegin(t, ctx, db)
		bound, err := collector.Enforce(ctx, tx, []collector.Selector{{Kind: root.Kind, ID: root.ID}}, deletionPlan(t, root, facts).ImpactVersion(), true, authorizeDeletionFixture(root))
		require.NoError(t, err)
		_, err = app.PolicyStore.DeleteManyPoliciesForAuditTx(bound, tx, []string{f.policy.String()}, nil)
		enforceCode(t, err, ds.DeletionUnavailable)
		require.NoError(t, tx.Rollback())
	}
	tx := nrBegin(t, ctx, db)
	bound := epProfileEnforce(t, ctx, tx, f.policy, epProfileVersion(t, ctx, db, f.policy))
	for _, fn := range []func() error{
		func() error {
			_, err := app.ServiceStore.DeleteManyForAuditTx(bound, tx, []string{other.service.String()}, nil)
			return err
		},
		func() error { _, err := guard.ConsumeCM(bound, tx, []string{nr.cm.String()}); return err },
		func() error { _, err := guard.ConsumeNR(bound, tx, []string{nr.nr.String()}); return err },
		func() error {
			_, err := app.IntKeyStore.DeleteManyForAuditTx(bound, tx, []string{nr.key.String()}, nil)
			return err
		},
	} {
		enforceCode(t, fn(), ds.DeletionUnavailable)
	}
	require.NoError(t, tx.Rollback())
	epProfileNoSuccess(t, ctx, db)
}

func TestPostgresDeletionEnforcementEPReferenceRetarget(t *testing.T) {
	ctx, _, db := boundedAuditDB(t, len(Names()))
	ctx = permission.SystemContext(ctx, "EPProfileTest")
	app := enforcementApp(t, ctx, db)
	for _, first := range []string{"writer", "delete"} {
		f := newEPProfileFixture(t, ctx, db, true)
		other, svc := uuid.New(), uuid.New()
		epProfileInsert(t, ctx, db, other, f.org)
		serviceProfileInsert(t, ctx, db, svc, f.org, f.policy)
		old := epProfileVersion(t, ctx, db, f.policy)
		writer := epProfileWriter(t, ctx, db)
		run := func(c context.Context) error {
			return app.ServiceStore.UpdateTx(c, writer, &service.Service{ID: svc.String(), Name: "synthetic-" + svc.String(), Description: "synthetic", OrganizationID: f.org, EscalationPolicyID: other.String()}, nil)
		}
		if first == "writer" {
			require.NoError(t, run(ctx))
			tx := nrBegin(t, ctx, db)
			_, _, err := guard.StabilizeEP(ctx, tx, epProfileSelectors(f.policy))
			enforceCode(t, err, ds.DeletionUnavailable)
			require.NoError(t, tx.Rollback())
		} else {
			tx := nrBegin(t, ctx, db)
			_, _, err := guard.StabilizeEP(ctx, tx, epProfileSelectors(f.policy))
			require.NoError(t, err)
			writerCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
			done := serviceProfileWait(t, writerCtx, db, writer, func() error { return run(writerCtx) })
			require.NoError(t, tx.Rollback())
			require.NoError(t, <-done)
			cancel()
		}
		require.NoError(t, writer.Commit())
		_, err := app.Mutation().DeleteAll(ctx, epProfileInput(f.policy), &graphql2.DeletionSafetyConfirmationInput{ExpectedImpactVersion: old, AcknowledgeImpacts: true})
		enforceCode(t, err, ds.DeletionDependencyChanged)
		confirm := enforcementPreview(t, ctx, app, epProfilePreviewInput(f.policy)...)
		ok, err := app.Mutation().DeleteAll(ctx, epProfileInput(f.policy), confirm)
		require.NoError(t, err)
		require.True(t, ok)
		require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM services WHERE id=$1 AND escalation_policy_id=$2`, svc, other))
	}
}

func TestPostgresDeletionEnforcementEPAuthorization(t *testing.T) {
	ctx, _, db := boundedAuditDB(t, len(Names()))
	sys := permission.SystemContext(ctx, "EPProfileTest")
	app := enforcementApp(t, sys, db)
	for _, role := range []string{"ORG_ADMIN", "ORG_MEMBER", "PLATFORM_ADMIN"} {
		t.Run(role, func(t *testing.T) {
			f := newEPProfileFixture(t, ctx, db, true)
			if role == "ORG_MEMBER" {
				enforcementExec(t, ctx, db, `UPDATE user_organization_assignments SET organization_role='ORG_MEMBER' WHERE user_id=$1`, f.actor)
			}
			if role == "PLATFORM_ADMIN" {
				enforcementExec(t, ctx, db, `UPDATE users SET role='admin' WHERE id=$1`, f.actor)
			}
			human := previewAdmit(t, ctx, db, f.actor)
			if role == "ORG_MEMBER" {
				_, err := app.Mutation().DeleteAll(human, epProfileInput(f.policy), nil)
				require.Error(t, err)
				require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM escalation_policies WHERE id=$1`, f.policy))
				return
			}
			confirm := enforcementPreview(t, human, app, graphql2.DeletionResourceInput{Type: graphql2.DeletionTargetTypeEscalationPolicy, ID: f.policy.String()})
			for _, q := range []string{`UPDATE users SET name=name WHERE id=$1`, `UPDATE user_organization_assignments SET source_config_version=source_config_version WHERE user_id=$1`} {
				writer, err := db.BeginTx(ctx, nil)
				require.NoError(t, err)
				defer func() { _ = writer.Rollback() }()
				_, err = writer.ExecContext(ctx, q, f.actor)
				require.NoError(t, err)
				tx := nrBegin(t, human, db)
				_, err = collector.Enforce(human, tx, epProfileSelectors(f.policy), confirm.ExpectedImpactVersion, true, authorizeDeletionFixture(epProfileRoot(f.policy)))
				enforceCode(t, err, ds.DeletionUnavailable)
				require.NoError(t, tx.Rollback())
				require.NoError(t, writer.Rollback())
				tx = nrBegin(t, human, db)
				_ = epProfileEnforce(t, human, tx, f.policy, confirm.ExpectedImpactVersion)
				writer, err = db.BeginTx(ctx, nil)
				require.NoError(t, err)
				writerCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
				done := nrWaiter(t, writerCtx, db, writer, q, f.actor)
				require.NoError(t, tx.Rollback())
				require.NoError(t, <-done)
				require.NoError(t, writer.Rollback())
				cancel()
			}
			ok, err := app.Mutation().DeleteAll(human, epProfileInput(f.policy), confirm)
			require.NoError(t, err)
			require.True(t, ok)
		})
	}
	f, other := newEPProfileFixture(t, ctx, db, true), newEPProfileFixture(t, ctx, db, true)
	human := previewAdmit(t, ctx, db, f.actor)
	_, err := app.Mutation().DeleteAll(human, epProfileInput(other.policy), nil)
	require.Error(t, err)
	confirm := enforcementPreview(t, human, app, graphql2.DeletionResourceInput{Type: graphql2.DeletionTargetTypeEscalationPolicy, ID: f.policy.String()})
	enforcementExec(t, ctx, db, `UPDATE user_organization_assignments SET organization_role='ORG_MEMBER' WHERE user_id=$1`, f.actor)
	_, err = app.Mutation().DeleteAll(human, epProfileInput(f.policy), confirm)
	require.Error(t, err)
	require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM escalation_policies WHERE id=$1`, f.policy))
}

func TestPostgresDeletionEnforcementEPReverseOrderWriter(t *testing.T) {
	ctx, uri, db := boundedAuditDB(t, len(Names()))
	ctx = permission.SystemContext(ctx, "EPProfileTest")
	f := newEPProfileFixture(t, ctx, db, true)
	version := epProfileVersion(t, ctx, db, f.policy)
	logs, err := alertlog.NewStore(ctx, db, nil)
	require.NoError(t, err)
	store, err := escalation.NewStore(ctx, db, escalation.Config{LogStore: logs})
	require.NoError(t, err)
	writer := epProfileWriter(t, ctx, db)
	_, err = writer.ExecContext(ctx, `SELECT id FROM escalation_policies WHERE id=$1 FOR UPDATE`, f.policy)
	require.NoError(t, err)
	conf, err := pgx.ParseConfig(uri)
	require.NoError(t, err)
	barrier := &serviceProfileCertificationBarrier{nrQueryBarrier: &nrQueryBarrier{needle: "LOCK TABLE public.escalation_policy_steps IN EXCLUSIVE", arrived: make(chan struct{}), resume: make(chan struct{})}}
	conf.Tracer = barrier
	traced := sql.OpenDB(stdlib.GetConnector(*conf))
	defer traced.Close()
	tx := nrBegin(t, ctx, traced)
	defer func() { _ = tx.Rollback() }()
	checked := make(chan error, 1)
	go func() {
		_, err := collector.Enforce(ctx, tx, epProfileSelectors(f.policy), version, true, authorizeDeletionFixture(epProfileRoot(f.policy)))
		checked <- err
	}()
	select {
	case <-barrier.arrived:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	writerCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	done := serviceProfileWait(t, writerCtx, db, writer, func() error {
		_, err := store.CreateStepTx(writerCtx, writer, &escalation.Step{PolicyID: f.policy.String(), DelayMinutes: 1})
		return err
	})
	// Writer owns EP and waits for Step EXCLUSIVE. Deletion owns Step EXCLUSIVE,
	// but must refuse EP NOWAIT, never wait back on that writer to form a cycle.
	close(barrier.resume)
	enforceCode(t, <-checked, ds.DeletionUnavailable)
	require.NoError(t, tx.Rollback())
	require.NoError(t, <-done)
	require.NoError(t, writer.Commit())
	require.Equal(t, 2, enforcementCount(t, ctx, db, `SELECT step_count FROM escalation_policies WHERE id=$1`, f.policy))
	require.Equal(t, 2, enforcementCount(t, ctx, db, `SELECT count(*) FROM escalation_policy_steps WHERE escalation_policy_id=$1 AND step_number IN (0,1)`, f.policy))
	epProfileNoSuccess(t, ctx, db)
}

func TestPostgresDeletionEnforcementEPOrganizationAndTargetScope(t *testing.T) {
	ctx, _, db := boundedAuditDB(t, len(Names()))
	sys := permission.SystemContext(ctx, "EPProfileTest")
	app := enforcementApp(t, sys, db)
	for _, first := range []string{"writer", "delete"} {
		f, other := newEPProfileFixture(t, ctx, db, true), newEPProfileFixture(t, ctx, db, true)
		human := previewAdmit(t, ctx, db, f.actor)
		writer := epProfileWriter(t, sys, db)
		q := `UPDATE escalation_policies SET organization_id=$2 WHERE id=$1`
		if first == "writer" {
			_, err := writer.ExecContext(sys, q, f.policy, other.org)
			require.NoError(t, err)
			tx := nrBegin(t, sys, db)
			_, _, err = guard.StabilizeEP(sys, tx, epProfileSelectors(f.policy))
			enforceCode(t, err, ds.DeletionUnavailable)
			require.NoError(t, tx.Rollback())
		} else {
			tx := nrBegin(t, sys, db)
			_, _, err := guard.StabilizeEP(sys, tx, epProfileSelectors(f.policy))
			require.NoError(t, err)
			writerCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
			done := nrWaiter(t, writerCtx, db, writer, q, f.policy, other.org)
			require.NoError(t, tx.Rollback())
			require.NoError(t, <-done)
			cancel()
		}
		require.NoError(t, writer.Commit())
		_, err := app.Mutation().DeleteAll(human, epProfileInput(f.policy), nil)
		require.Error(t, err)
		require.Equal(t, 1, enforcementCount(t, sys, db, `SELECT count(*) FROM escalation_policies WHERE id=$1 AND organization_id=$2`, f.policy, other.org))
	}
	// A retained Action target in another organization is unavailable to this
	// actor even though the actor can manage the EP itself.
	f, foreign := newEPProfileFixture(t, ctx, db, true), newEPProfileFixture(t, ctx, db, true)
	enforcementExec(t, ctx, db, `UPDATE escalation_policy_actions SET user_id=$2 WHERE id=$1`, f.action, foreign.user)
	human := previewAdmit(t, ctx, db, f.actor)
	_, err := app.Mutation().DeleteAll(human, epProfileInput(f.policy), nil)
	enforceCode(t, err, ds.DeletionUnavailable)
	// Missing authoritative assignment must not be replaced with a guessed scope.
	enforcementExec(t, ctx, db, `DELETE FROM user_organization_assignments WHERE user_id=$1`, foreign.user)
	_, err = app.Mutation().DeleteAll(sys, epProfileInput(f.policy), nil)
	enforceCode(t, err, ds.DeletionUnavailable)
	epProfileNoSuccess(t, sys, db)
}
