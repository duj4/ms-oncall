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
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/assignment"
	ds "github.com/target/goalert/deletionsafety"
	collector "github.com/target/goalert/deletionsafety/postgres"
	"github.com/target/goalert/gadb"
	"github.com/target/goalert/graphql2"
	guard "github.com/target/goalert/internal/deletionguard"
	"github.com/target/goalert/override"
	uoaudit "github.com/target/goalert/override/deleteaudit"
	"github.com/target/goalert/permission"
)

func overrideProfileRoot(id uuid.UUID) ds.Resource {
	return ds.Resource{Kind: ds.ResourceUserOverride, ID: id.String()}
}
func overrideProfileSelectors(ids ...uuid.UUID) []collector.Selector {
	var out []collector.Selector
	for _, id := range ids {
		out = append(out, collector.Selector{Kind: ds.ResourceUserOverride, ID: id.String()})
	}
	return out
}
func overrideProfileInput(ids ...uuid.UUID) []assignment.RawTarget {
	var out []assignment.RawTarget
	for _, id := range ids {
		out = append(out, assignment.RawTarget{Type: assignment.TargetTypeUserOverride, ID: id.String()})
	}
	return out
}
func overrideProfilePreviewInput(ids ...uuid.UUID) []graphql2.DeletionResourceInput {
	var out []graphql2.DeletionResourceInput
	for _, id := range ids {
		out = append(out, graphql2.DeletionResourceInput{Type: graphql2.DeletionTargetTypeUserOverride, ID: id.String()})
	}
	return out
}
func overrideProfileVersion(t *testing.T, ctx context.Context, db *sql.DB, id uuid.UUID) string {
	t.Helper()
	facts, err := collectDeletion(t, ctx, db, overrideProfileRoot(id), collector.Limits{})
	require.NoError(t, err)
	return deletionPlan(t, overrideProfileRoot(id), facts).ImpactVersion()
}
func overrideProfileEnforce(t *testing.T, ctx context.Context, tx *sql.Tx, id uuid.UUID, version string) context.Context {
	t.Helper()
	bound, err := collector.Enforce(ctx, tx, overrideProfileSelectors(id), version, true, authorizeDeletionFixture(overrideProfileRoot(id)))
	require.NoError(t, err)
	return bound
}
func overrideProfileNoSuccess(t *testing.T, ctx context.Context, db *sql.DB) {
	t.Helper()
	require.Zero(t, enforcementCount(t, ctx, db, `SELECT count(*) FROM user_override_delete_audit_events WHERE outcome='committed'`))
}
func overrideProfileFixture(t *testing.T, ctx context.Context, db *sql.DB) scheduleProfileFixture {
	t.Helper()
	return newScheduleProfileFixture(t, ctx, db, true)
}
func overrideProfileRetained(t *testing.T, ctx context.Context, db *sql.DB, f scheduleProfileFixture) {
	t.Helper()
	for _, v := range []struct {
		table string
		id    uuid.UUID
	}{{"schedules", f.schedule}, {"schedules", f.otherSchedule}, {"users", f.user}, {"users", f.actor}, {"rotations", f.rotation}, {"escalation_policies", f.policy}, {"schedule_rules", f.rule}} {
		require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM `+v.table+` WHERE id=$1`, v.id))
	}
	require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM rotation_participants WHERE rotation_id=$1`, f.rotation))
	require.Zero(t, enforcementCount(t, ctx, db, `SELECT count(*) FROM schedule_rotation_delete_audit_events WHERE outcome='committed'`))
	require.Zero(t, enforcementCount(t, ctx, db, `SELECT count(*) FROM user_delete_audit_events WHERE outcome='committed'`))
}

func TestPostgresDeletionEnforcementOverrideBusiness(t *testing.T) {
	ctx, _, db := boundedAuditDB(t, len(Names()))
	ctx = permission.SystemContext(ctx, "OverrideProfileTest")
	app := enforcementApp(t, ctx, db)
	for _, state := range []string{"active", "future", "ended", "add_only", "remove_only"} {
		t.Run(state, func(t *testing.T) {
			f := overrideProfileFixture(t, ctx, db)
			if state != "ended" {
				enforcementExec(t, ctx, db, `UPDATE user_overrides SET start_time=$2,end_time=$3 WHERE id=$1`, f.override, f.now.Add(-time.Hour), f.now.Add(time.Hour))
			}
			if state == "future" {
				enforcementExec(t, ctx, db, `UPDATE user_overrides SET start_time=$2,end_time=$3 WHERE id=$1`, f.override, f.now.Add(time.Hour), f.now.Add(2*time.Hour))
			}
			if state == "add_only" {
				enforcementExec(t, ctx, db, `UPDATE user_overrides SET remove_user_id=NULL WHERE id=$1`, f.override)
			}
			if state == "remove_only" {
				enforcementExec(t, ctx, db, `UPDATE user_overrides SET add_user_id=NULL WHERE id=$1`, f.override)
			}
			facts, err := collectDeletion(t, ctx, db, overrideProfileRoot(f.override), collector.Limits{})
			require.NoError(t, err)
			plan := deletionPlan(t, overrideProfileRoot(f.override), facts)
			require.True(t, plan.CanProceed())
			require.Equal(t, state != "ended", plan.RequiresConfirmation())
			var before uoaudit.Before
			require.NoError(t, db.QueryRowContext(ctx, `SELECT jsonb_build_object('version',1,'root_id',o.id,'parent_schedule_id',o.tgt_schedule_id,'target_organization_id',s.organization_id,'add_user_id',o.add_user_id,'remove_user_id',o.remove_user_id,'start',o.start_time,'end',o.end_time,'row_version',o.xmin::text::bigint) FROM user_overrides o JOIN schedules s ON s.id=o.tgt_schedule_id WHERE o.id=$1`, f.override).Scan(jsonScanner{&before}))
			other := uuid.New()
			enforcementExec(t, ctx, db, `INSERT INTO user_overrides(id,tgt_schedule_id,add_user_id,start_time,end_time) VALUES($1,$2,$3,$4,$5)`, other, f.schedule, f.user, f.now.Add(4*time.Hour), f.now.Add(5*time.Hour))
			if state != "ended" {
				require.Contains(t, enforcementHTTP(t, ctx, app, overrideProfileInput(f.override), nil, true), string(ds.DeletionConfirmationRequired))
				_, err = app.Mutation().DeleteAll(ctx, overrideProfileInput(f.override), nil)
				enforceCode(t, err, ds.DeletionConfirmationRequired)
			}
			confirm := enforcementPreview(t, ctx, app, overrideProfilePreviewInput(f.override)...)
			_, err = app.Mutation().DeleteAll(ctx, overrideProfileInput(f.override, f.override, uuid.New(), uuid.Nil), confirm)
			require.NoError(t, err)
			require.Zero(t, enforcementCount(t, ctx, db, `SELECT count(*) FROM user_overrides WHERE id=$1`, f.override))
			require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM user_overrides WHERE id=$1`, other))
			var got uoaudit.Before
			require.NoError(t, db.QueryRowContext(ctx, `SELECT before_context FROM user_override_delete_audit_events WHERE root_id=$1 AND outcome='committed' AND provenance='EXPLICIT' AND deletion_mechanism='explicit_sql' AND cause='explicit_target' AND effects='[]'::jsonb`, f.override).Scan(jsonScanner{&got}))
			before.Start, before.End = before.Start.UTC(), before.End.UTC()
			require.Equal(t, before, got)
			var event uoaudit.Event
			require.NoError(t, db.QueryRowContext(ctx, `SELECT to_jsonb(e) FROM user_override_delete_audit_events e WHERE root_id=$1 AND outcome='committed'`, f.override).Scan(jsonScanner{&event}))
			require.NoError(t, event.Validate())
			overrideProfileRetained(t, ctx, db, f)
			_, err = app.Mutation().DeleteAll(ctx, overrideProfileInput(f.override), confirm)
			enforceCode(t, err, ds.DeletionDependencyChanged)
		})
	}
	f, g := overrideProfileFixture(t, ctx, db), overrideProfileFixture(t, ctx, db)
	confirm := enforcementPreview(t, ctx, app, overrideProfilePreviewInput(f.override, g.override)...)
	_, err := app.Mutation().DeleteAll(ctx, overrideProfileInput(f.override, g.override, f.override), confirm)
	require.NoError(t, err)
	require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM (SELECT request_id,execution_id,attempt_id FROM user_override_delete_audit_events WHERE root_id IN ($1,$2) AND outcome='committed' GROUP BY 1,2,3 HAVING count(*)=2) x`, f.override, g.override))
	_, err = app.Mutation().DeleteAll(ctx, overrideProfileInput(uuid.Nil), nil)
	require.NoError(t, err)
	_, err = app.Mutation().DeleteAll(ctx, overrideProfileInput(slicesRepeatService(uuid.New(), 51)...), nil)
	require.Error(t, err)
}

type jsonScanner struct{ target any }

func (s jsonScanner) Scan(v any) error {
	data, ok := v.([]byte)
	if !ok {
		return fmt.Errorf("expected json bytes")
	}
	return json.Unmarshal(data, s.target)
}

func TestPostgresDeletionEnforcementOverrideAuditFailure(t *testing.T) {
	ctx, _, db := boundedAuditDB(t, len(Names()))
	ctx = permission.SystemContext(ctx, "OverrideProfileTest")
	app := enforcementApp(t, ctx, db)
	f, g := overrideProfileFixture(t, ctx, db), overrideProfileFixture(t, ctx, db)
	confirm := enforcementPreview(t, ctx, app, overrideProfilePreviewInput(f.override, g.override)...)
	enforcementExec(t, ctx, db, `CREATE SEQUENCE override_failure_seen; CREATE FUNCTION override_audit_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.outcome='committed' THEN IF EXISTS(SELECT FROM user_overrides WHERE id=NEW.root_id) THEN RAISE EXCEPTION 'delete not reached'; END IF; PERFORM nextval('override_failure_seen'); RAISE EXCEPTION 'synthetic append failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER override_audit_failure BEFORE INSERT ON user_override_delete_audit_events FOR EACH ROW EXECUTE FUNCTION override_audit_failure()`)
	_, err := app.Mutation().DeleteAll(ctx, overrideProfileInput(f.override, g.override), confirm)
	require.Error(t, err)
	var seen bool
	require.NoError(t, db.QueryRowContext(ctx, `SELECT is_called FROM override_failure_seen`).Scan(&seen))
	require.True(t, seen)
	for _, id := range []uuid.UUID{f.override, g.override} {
		require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM user_overrides WHERE id=$1`, id))
	}
	overrideProfileNoSuccess(t, ctx, db)
	enforcementExec(t, ctx, db, `DROP TRIGGER override_audit_failure ON user_override_delete_audit_events`)
	_, err = app.Mutation().DeleteAll(ctx, overrideProfileInput(f.override, g.override), confirm)
	require.NoError(t, err)
	require.Equal(t, 2, enforcementCount(t, ctx, db, `SELECT count(*) FROM user_override_delete_audit_events WHERE outcome='committed'`))
	overrideProfileRetained(t, ctx, db, f)
	overrideProfileRetained(t, ctx, db, g)
}

func TestPostgresDeletionEnforcementOverrideMissing(t *testing.T) {
	ctx, _, db := boundedAuditDB(t, len(Names()))
	ctx = permission.SystemContext(ctx, "OverrideProfileTest")
	app := enforcementApp(t, ctx, db)
	for _, audited := range []bool{false, true} {
		f := overrideProfileFixture(t, ctx, db)
		missing := uuid.New()
		version := overrideProfileVersion(t, ctx, db, f.override)
		tx := nrBegin(t, ctx, db)
		bound, err := collector.Enforce(ctx, tx, overrideProfileSelectors(f.override, missing), version, true, authorizeDeletionFixture(overrideProfileRoot(f.override)))
		require.NoError(t, err)
		// The table lock prevents external insertion. A same-transaction late insert
		// still proves both Store implementations use only the certified subset.
		_, err = tx.ExecContext(ctx, `INSERT INTO user_overrides(id,tgt_schedule_id,add_user_id,start_time,end_time) VALUES($1,$2,$3,$4,$5)`, missing, f.schedule, f.user, f.now.Add(4*time.Hour), f.now.Add(5*time.Hour))
		require.NoError(t, err)
		if audited {
			result, err := app.OverrideStore.DeleteUserOverrideForAuditTx(bound, tx, []string{f.override.String(), missing.String()}, &f.org)
			require.NoError(t, err)
			require.Len(t, result.Receipts, 1)
		} else {
			require.NoError(t, app.OverrideStore.DeleteUserOverrideTxScoped(bound, tx, []string{f.override.String(), missing.String()}, &f.org))
		}
		var n int
		require.NoError(t, tx.QueryRowContext(ctx, `SELECT count(*) FROM user_overrides WHERE id=$1`, missing).Scan(&n))
		require.Equal(t, 1, n)
		require.NoError(t, tx.Rollback())
	}
	overrideProfileNoSuccess(t, ctx, db)
}

func TestPostgresDeletionEnforcementOverrideCleanup(t *testing.T) {
	ctx, _, db := boundedAuditDB(t, len(Names()))
	ctx = permission.SystemContext(ctx, "OverrideProfileTest")
	app := enforcementApp(t, ctx, db)
	// Exactly the generated production CleanupManager SQL, without a Store bypass.
	for _, first := range []string{"cleanup", "delete"} {
		t.Run(first, func(t *testing.T) {
			f := overrideProfileFixture(t, ctx, db)
			enforcementExec(t, ctx, db, `UPDATE user_overrides SET start_time=$2,end_time=$3 WHERE id=$1`, f.override, f.now.Add(-49*time.Hour), f.now.Add(-48*time.Hour))
			confirm := enforcementPreview(t, ctx, app, overrideProfilePreviewInput(f.override)...)
			tx := epProfileWriter(t, ctx, db)
			if first == "cleanup" {
				n, err := gadb.New(tx).CleanupMgrDeleteOldOverrides(ctx, 1)
				require.NoError(t, err)
				require.Positive(t, n)
				_, err = app.Mutation().DeleteAll(ctx, overrideProfileInput(f.override), confirm)
				enforceCode(t, err, ds.DeletionUnavailable)
				require.NoError(t, tx.Commit())
				_, err = app.Mutation().DeleteAll(ctx, overrideProfileInput(f.override), confirm)
				enforceCode(t, err, ds.DeletionDependencyChanged)
				_, err = app.Mutation().DeleteAll(ctx, overrideProfileInput(f.override), nil)
				require.NoError(t, err)
				require.Zero(t, enforcementCount(t, ctx, db, `SELECT count(*) FROM user_override_delete_audit_events WHERE root_id=$1 AND outcome='committed'`, f.override))
			} else {
				bound := overrideProfileEnforce(t, ctx, tx, f.override, confirm.ExpectedImpactVersion)
				writer := epProfileWriter(t, ctx, db)
				done := nrWaiter(t, ctx, db, writer, `DELETE FROM user_overrides WHERE id=ANY(SELECT id FROM user_overrides WHERE end_time<now()-'1 day'::interval LIMIT 100 FOR UPDATE SKIP LOCKED)`)
				result, err := app.OverrideStore.DeleteUserOverrideForAuditTx(bound, tx, []string{f.override.String()}, nil)
				require.NoError(t, err)
				require.Len(t, result.Receipts, 1)
				// Controller commit/audit coexistence is covered by the traced Writer suite.
				require.NoError(t, tx.Commit())
				require.NoError(t, <-done)
				require.NoError(t, writer.Commit())
			}
			overrideProfileRetained(t, ctx, db, f)
		})
	}
}

// A deterministic SQL blocking barrier, from the existing native profile suites.
func overrideProfileTraced(t *testing.T, uri string, needle string) (*sql.DB, *serviceProfileCertificationBarrier) {
	t.Helper()
	conf, err := pgx.ParseConfig(uri)
	require.NoError(t, err)
	b := &serviceProfileCertificationBarrier{nrQueryBarrier: &nrQueryBarrier{needle: needle, arrived: make(chan struct{}), resume: make(chan struct{})}}
	conf.Tracer = b
	db := sql.OpenDB(stdlib.GetConnector(*conf))
	t.Cleanup(func() {
		select {
		case <-b.resume:
		default:
			close(b.resume)
		}
		require.NoError(t, db.Close())
	})
	return db, b
}

func TestPostgresDeletionEnforcementOverrideGuardLifecycle(t *testing.T) {
	ctx, _, db := boundedAuditDB(t, len(Names()))
	ctx = permission.SystemContext(ctx, "OverrideProfileTest")
	f := overrideProfileFixture(t, ctx, db)
	app := enforcementApp(t, ctx, db)
	version := overrideProfileVersion(t, ctx, db, f.override)
	raw := overrideProfileSelectors(f.override)
	for _, phase := range []string{"before_locks", "after_locks", "after_witness"} {
		t.Run(phase, func(t *testing.T) {
			tx := nrBegin(t, ctx, db)
			if phase == "before_locks" {
				_, err := tx.ExecContext(ctx, `SAVEPOINT checkpoint`)
				require.NoError(t, err)
			}
			checked, _, err := guard.StabilizeUserOverride(ctx, tx, raw)
			require.NoError(t, err)
			if phase == "after_locks" {
				_, err = tx.ExecContext(ctx, `SAVEPOINT checkpoint`)
				require.NoError(t, err)
			}
			facts, err := collector.Collect(checked, tx, overrideProfileRoot(f.override), collector.Recheck, collector.Limits{}, authorizeDeletionFixture(overrideProfileRoot(f.override)))
			require.NoError(t, err)
			plan := deletionPlan(t, overrideProfileRoot(f.override), facts)
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
				_, err = app.OverrideStore.DeleteUserOverrideForAuditTx(bound, tx, []string{f.override.String()}, nil)
				enforceCode(t, err, ds.DeletionUnavailable)
				_, err = guard.Bind(ctx, tx, checked, raw, plan, version, true)
				enforceCode(t, err, ds.DeletionUnavailable)
				bound = overrideProfileEnforce(t, ctx, tx, f.override, version)
			}
			receipts, err := app.OverrideStore.DeleteUserOverrideForAuditTx(bound, tx, []string{f.override.String()}, nil)
			require.NoError(t, err)
			require.Len(t, receipts.Receipts, 1)
			_, err = app.OverrideStore.DeleteUserOverrideForAuditTx(bound, tx, []string{f.override.String()}, nil)
			enforceCode(t, err, ds.DeletionUnavailable)
			require.NoError(t, tx.Rollback())
		})
	}
	tx := nrBegin(t, ctx, db)
	old := overrideProfileEnforce(t, ctx, tx, f.override, version)
	_, err := tx.ExecContext(ctx, `SAVEPOINT old_generation`)
	require.NoError(t, err)
	newer := overrideProfileEnforce(t, ctx, tx, f.override, version)
	_, err = tx.ExecContext(ctx, `ROLLBACK TO old_generation`)
	require.NoError(t, err)
	for _, bound := range []context.Context{old, newer} {
		_, err = guard.ConsumeUserOverride(bound, tx, []string{f.override.String()})
		enforceCode(t, err, ds.DeletionUnavailable)
	}
	bound := overrideProfileEnforce(t, ctx, tx, f.override, version)
	other, err := db.BeginTx(ctx, nil)
	require.NoError(t, err)
	_, err = guard.ConsumeUserOverride(bound, other, []string{f.override.String()})
	enforceCode(t, err, ds.DeletionUnavailable)
	require.NoError(t, other.Rollback())
	_, err = guard.ConsumeUserOverride(bound, tx, []string{uuid.NewString()})
	enforceCode(t, err, ds.DeletionUnavailable)
	_, err = guard.ConsumeCM(bound, tx, []string{f.override.String()})
	enforceCode(t, err, ds.DeletionUnavailable)
	_, err = guard.ConsumeNR(bound, tx, []string{f.override.String()})
	enforceCode(t, err, ds.DeletionUnavailable)
	_, err = guard.ConsumeUserOverride(context.WithValue(ctx, serviceProfileContextKey{}, "rotation-only-v1"), tx, []string{f.override.String()})
	enforceCode(t, err, ds.DeletionUnavailable)
	_, err = guard.ConsumeUserOverride(context.WithValue(bound, serviceProfileContextKey{}, true), tx, []string{f.override.String()})
	require.NoError(t, err)
	_, err = guard.ConsumeUserOverride(bound, tx, []string{f.override.String()})
	enforceCode(t, err, ds.DeletionUnavailable)
	require.NoError(t, tx.Rollback())
	for _, commit := range []bool{false, true} {
		tx = nrBegin(t, ctx, db)
		bound = overrideProfileEnforce(t, ctx, tx, f.override, version)
		if commit {
			require.NoError(t, tx.Commit())
		} else {
			require.NoError(t, tx.Rollback())
		}
		_, err = guard.ConsumeUserOverride(bound, tx, []string{f.override.String()})
		enforceCode(t, err, ds.DeletionUnavailable)
	}
	tx = nrBegin(t, ctx, db)
	_, err = tx.ExecContext(ctx, `SELECT 1/0`)
	require.Error(t, err)
	_, err = collector.Enforce(ctx, tx, raw, version, true, authorizeDeletionFixture(overrideProfileRoot(f.override)))
	enforceCode(t, err, ds.DeletionUnavailable)
	require.NoError(t, tx.Rollback())
	for _, fn := range []func() error{
		func() error { return app.OverrideStore.DeleteUserOverrideTx(ctx, nil, f.override.String()) },
		func() error {
			tx := nrBegin(t, ctx, db)
			defer func() { _ = tx.Rollback() }()
			return app.OverrideStore.DeleteUserOverrideTx(ctx, tx, f.override.String())
		},
	} {
		enforceCode(t, fn(), ds.DeletionUnavailable)
	}
	overrideProfileNoSuccess(t, ctx, db)
}

func TestPostgresDeletionEnforcementOverrideAuthorization(t *testing.T) {
	ctx, _, db := boundedAuditDB(t, len(Names()))
	sys := permission.SystemContext(ctx, "OverrideProfileTest")
	app := enforcementApp(t, sys, db)
	for _, role := range []string{"ORG_ADMIN", "ORG_MEMBER", "PLATFORM_ADMIN"} {
		t.Run(role, func(t *testing.T) {
			f := overrideProfileFixture(t, ctx, db)
			if role == "ORG_MEMBER" {
				enforcementExec(t, ctx, db, `UPDATE user_organization_assignments SET organization_role='ORG_MEMBER' WHERE user_id=$1`, f.actor)
			}
			if role == "PLATFORM_ADMIN" {
				enforcementExec(t, ctx, db, `UPDATE users SET role='admin' WHERE id=$1`, f.actor)
			}
			human := previewAdmit(t, ctx, db, f.actor)

			confirm := enforcementPreview(t, human, app, graphql2.DeletionResourceInput{Type: graphql2.DeletionTargetTypeUserOverride, ID: f.override.String()})
			for _, q := range []string{`UPDATE users SET name=name WHERE id=$1`, `UPDATE user_organization_assignments SET source_config_version=source_config_version WHERE user_id=$1`} {
				writer, err := db.BeginTx(ctx, nil)
				require.NoError(t, err)
				defer func() { _ = writer.Rollback() }()
				_, err = writer.ExecContext(ctx, q, f.actor)
				require.NoError(t, err)
				tx := nrBegin(t, human, db)
				_, err = collector.Enforce(human, tx, overrideProfileSelectors(f.override), confirm.ExpectedImpactVersion, true, authorizeDeletionFixture(overrideProfileRoot(f.override)))
				enforceCode(t, err, ds.DeletionUnavailable)
				require.NoError(t, tx.Rollback())
				require.NoError(t, writer.Rollback())
				tx = nrBegin(t, human, db)
				_ = overrideProfileEnforce(t, human, tx, f.override, confirm.ExpectedImpactVersion)
				writer, err = db.BeginTx(ctx, nil)
				require.NoError(t, err)
				writerCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
				done := nrWaiter(t, writerCtx, db, writer, q, f.actor)
				require.NoError(t, tx.Rollback())
				require.NoError(t, <-done)
				require.NoError(t, writer.Rollback())
				cancel()
			}
			ok, err := app.Mutation().DeleteAll(human, overrideProfileInput(f.override), confirm)
			require.NoError(t, err)
			require.True(t, ok)
		})
	}
	f, other := overrideProfileFixture(t, ctx, db), overrideProfileFixture(t, ctx, db)
	human := previewAdmit(t, ctx, db, f.actor)
	_, err := app.Mutation().DeleteAll(human, overrideProfileInput(other.override), nil)
	require.Error(t, err)
	confirm := enforcementPreview(t, human, app, graphql2.DeletionResourceInput{Type: graphql2.DeletionTargetTypeUserOverride, ID: f.override.String()})
	enforcementExec(t, ctx, db, `UPDATE user_organization_assignments SET organization_role='ORG_MEMBER' WHERE user_id=$1`, f.actor)
	_, err = app.Mutation().DeleteAll(human, overrideProfileInput(f.override), confirm)
	require.Error(t, err)
	require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM user_overrides WHERE id=$1`, f.override))
}

func TestPostgresDeletionEnforcementOverrideIndependent(t *testing.T) {
	ctx, uri, db := boundedAuditDB(t, len(Names()))
	ctx = permission.SystemContext(ctx, "OverrideProfileTest")
	for _, first := range []string{"writer", "delete"} {
		for index := 0; index < 9; index++ {
			f := overrideProfileFixture(t, ctx, db)
			other := newDeletionFixture(t, ctx, db)
			writes := []nrWrite{
				{name: "organization", query: `UPDATE organizations SET display_name=display_name WHERE id=$1`, args: []any{other.org}},
				{name: "service", query: `UPDATE services SET name=name WHERE id=$1`, args: []any{other.service}},
				{name: "rotation", query: `UPDATE rotations SET name=name WHERE id=$1`, args: []any{other.rotation}},
				{name: "cm", query: `UPDATE user_contact_methods SET disabled=true WHERE id=$1`, args: []any{other.cm}},
				{name: "nr", query: `UPDATE user_notification_rules SET delay_minutes=3 WHERE id=$1`, args: []any{other.nr}},
				{name: "key", query: `UPDATE integration_keys SET name=name WHERE audit_resource_id=$1`, args: []any{other.keyAudit}},
				{name: "user", query: `UPDATE users SET name=name WHERE id=$1`, args: []any{other.user}},
				{name: "ep", query: `UPDATE escalation_policies SET name=name WHERE id=$1`, args: []any{other.policy}},
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
				confirm := enforcementPreview(t, ctx, app, overrideProfilePreviewInput(f.override)...)
				if first == "writer" {
					run()
					ok, err := app.Mutation().DeleteAll(ctx, overrideProfileInput(f.override), confirm)
					require.NoError(t, err)
					require.True(t, ok)
					require.NoError(t, writer.Commit())
				} else {
					done := make(chan error, 1)
					go func() {
						_, err := app.Mutation().DeleteAll(ctx, overrideProfileInput(f.override), confirm)
						done <- err
					}()
					select {
					case <-barrier.arrived:
					case <-ctx.Done():
						t.Fatal(ctx.Err())
					}
					// Only the existing Override table lock; unrelated business updates still commit.
					require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM pg_locks l JOIN pg_class c ON c.oid=l.relation JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND l.mode IN ('ShareLock','ShareRowExclusiveLock','ExclusiveLock','AccessExclusiveLock') AND l.granted`))
					run()
					require.NoError(t, writer.Commit())
					close(barrier.resume)
					require.NoError(t, <-done)
				}
				require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM user_override_delete_audit_events WHERE root_id=$1 AND outcome='committed'`, f.override))
			})
		}
	}
}

func TestPostgresDeletionEnforcementOverrideHumanBatch(t *testing.T) {
	base, _, db := boundedAuditDB(t, len(Names()))
	sys := permission.SystemContext(base, "OverrideProfileTest")
	f := overrideProfileFixture(t, sys, db)
	app := enforcementApp(t, sys, db)
	human := previewAdmit(t, base, db, f.actor)
	ids := []uuid.UUID{f.override}
	for i, parent := range []uuid.UUID{f.schedule, f.otherSchedule} {
		o, err := app.OverrideStore.CreateUserOverrideTxScoped(human, nil, &override.UserOverride{Target: assignment.ScheduleTarget(parent.String()), AddUserID: f.user.String(), RemoveUserID: f.actor.String(), Start: f.now.Add(time.Duration(i+4) * time.Hour), End: f.now.Add(time.Duration(i+5) * time.Hour)}, &f.org)
		require.NoError(t, err)
		ids = append(ids, uuid.MustParse(o.ID))
	}
	confirm := enforcementPreview(t, human, app, overrideProfilePreviewInput(ids...)...)
	_, err := app.Mutation().DeleteAll(human, overrideProfileInput(append(ids, f.override, uuid.New(), uuid.Nil)...), confirm)
	require.NoError(t, err)
	rows, err := db.QueryContext(base, `SELECT to_jsonb(e) FROM user_override_delete_audit_events e WHERE outcome='committed' ORDER BY root_id`)
	require.NoError(t, err)
	var events []uoaudit.Event
	for rows.Next() {
		var event uoaudit.Event
		require.NoError(t, rows.Scan(jsonScanner{&event}))
		require.NoError(t, event.Validate())
		events = append(events, event)
	}
	require.NoError(t, rows.Err())
	rows.Close()
	require.Len(t, events, 3)
	require.NoError(t, uoaudit.ValidateBatch(events))
	for _, event := range events {
		require.Equal(t, f.org, event.TargetOrganizationID)
		require.Equal(t, f.actor, event.ActorID)
		require.Equal(t, events[0].RequestID, event.RequestID)
		require.Equal(t, events[0].ExecutionID, event.ExecutionID)
		require.Equal(t, events[0].AttemptID, event.AttemptID)
	}
	overrideProfileRetained(t, base, db, f)
}
