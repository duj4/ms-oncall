package migrate

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/assignment"
	ds "github.com/target/goalert/deletionsafety"
	collector "github.com/target/goalert/deletionsafety/postgres"
	"github.com/target/goalert/escalation"
	"github.com/target/goalert/gadb"
	"github.com/target/goalert/graphql2"
	guard "github.com/target/goalert/internal/deletionguard"
	"github.com/target/goalert/notification/nfydest"
	"github.com/target/goalert/permission"
	sraudit "github.com/target/goalert/schedule/deleteaudit"
	"github.com/target/goalert/schedule/rotation"
	"github.com/target/goalert/schedule/rule"
	"github.com/target/goalert/util/sqlutil"
)

// root is the newly created empty Rotation; the embedded rotation is a
// separate populated Rotation whose Participants and State must be retained.
type rotationProfileFixture struct {
	scheduleProfileFixture
	root uuid.UUID
}

func rotationProfileInsert(t *testing.T, ctx context.Context, db *sql.DB, id, org uuid.UUID) {
	t.Helper()
	enforcementExec(t, ctx, db, `INSERT INTO rotations(id,organization_id,name,type,time_zone) VALUES($1,$2,($1::uuid)::text,'daily','UTC')`, id, org)
}
func newRotationProfileFixture(t *testing.T, ctx context.Context, db *sql.DB) rotationProfileFixture {
	t.Helper()
	f := rotationProfileFixture{scheduleProfileFixture: newScheduleProfileFixture(t, ctx, db, false)}
	// Use the actual Store creation lifecycle, with every normal Trigger enabled.
	store, err := rotation.NewStore(ctx, db)
	require.NoError(t, err)
	r, err := store.CreateRotationTx(permission.SystemContext(ctx, "RotationProfileFixture"), nil, &rotation.Rotation{OrganizationID: f.org, Name: "rotation-" + uuid.NewString(), Type: rotation.TypeDaily, Start: time.Now().UTC(), ShiftLength: 1})
	require.NoError(t, err)
	f.root = uuid.MustParse(r.ID)
	require.Zero(t, enforcementCount(t, ctx, db, `SELECT count(*) FROM rotation_state WHERE rotation_id=$1`, f.root))
	return f
}
func rotationProfileRoot(id uuid.UUID) ds.Resource {
	return ds.Resource{Kind: ds.ResourceRotation, ID: id.String()}
}
func rotationProfileSelectors(ids ...uuid.UUID) []collector.Selector {
	var raw []collector.Selector
	for _, id := range ids {
		raw = append(raw, collector.Selector{Kind: ds.ResourceRotation, ID: id.String()})
	}
	return raw
}
func rotationProfileInput(ids ...uuid.UUID) []assignment.RawTarget {
	var raw []assignment.RawTarget
	for _, id := range ids {
		raw = append(raw, assignment.RawTarget{Type: assignment.TargetTypeRotation, ID: id.String()})
	}
	return raw
}
func rotationProfilePreviewInput(ids ...uuid.UUID) []graphql2.DeletionResourceInput {
	var raw []graphql2.DeletionResourceInput
	for _, id := range ids {
		raw = append(raw, graphql2.DeletionResourceInput{Type: graphql2.DeletionTargetTypeRotation, ID: id.String()})
	}
	return raw
}
func rotationProfileVersion(t *testing.T, ctx context.Context, db *sql.DB, id uuid.UUID) string {
	t.Helper()
	facts, err := collectDeletion(t, ctx, db, rotationProfileRoot(id), collector.Limits{})
	require.NoError(t, err)
	return deletionPlan(t, rotationProfileRoot(id), facts).ImpactVersion()
}
func rotationProfileEnforce(t *testing.T, ctx context.Context, tx *sql.Tx, id uuid.UUID, version string) context.Context {
	t.Helper()
	bound, err := collector.Enforce(ctx, tx, rotationProfileSelectors(id), version, true, authorizeDeletionFixture(rotationProfileRoot(id)))
	require.NoError(t, err)
	return bound
}
func rotationProfileNoSuccess(t *testing.T, ctx context.Context, db *sql.DB) {
	t.Helper()
	scheduleProfileNoSuccess(t, ctx, db)
}

func TestPostgresDeletionEnforcementRotationBusiness(t *testing.T) {
	ctx, _, db := boundedAuditDB(t, len(Names()))
	ctx = permission.SystemContext(ctx, "RotationProfileTest")
	app := enforcementApp(t, ctx, db)
	for _, favorite := range []bool{false, true} {
		f := newRotationProfileFixture(t, ctx, db)
		if favorite {
			enforcementExec(t, ctx, db, `INSERT INTO user_favorites(user_id,tgt_rotation_id) VALUES($1,$2)`, f.user, f.root)
		}
		confirm := enforcementPreview(t, ctx, app, rotationProfilePreviewInput(f.root)...)
		ok, err := app.Mutation().DeleteAll(ctx, rotationProfileInput(f.root, f.root, uuid.New(), uuid.Nil), confirm)
		require.NoError(t, err)
		require.True(t, ok)
		require.Zero(t, enforcementCount(t, ctx, db, `SELECT count(*) FROM rotations WHERE id=$1`, f.root))
		require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM schedule_rotation_delete_audit_events WHERE root_id=$1 AND outcome='committed' AND operation='rotation.delete' AND provenance='EXPLICIT'`, f.root))
		var raw []byte
		require.NoError(t, db.QueryRowContext(ctx, `SELECT effects FROM schedule_rotation_delete_audit_events WHERE root_id=$1 AND outcome='committed'`, f.root).Scan(&raw))
		var effects []sraudit.Effect
		require.NoError(t, json.Unmarshal(raw, &effects))
		if favorite {
			require.Len(t, effects, 1)
			require.Equal(t, sraudit.Favorite, effects[0].ResourceType)
		} else {
			require.Empty(t, effects)
		}
		for _, r := range []struct {
			table string
			id    uuid.UUID
		}{{"users", f.user}, {"rotations", f.rotation}, {"schedules", f.schedule}, {"escalation_policies", f.policy}} {
			require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM `+r.table+` WHERE id=$1`, r.id))
		}
		require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM rotation_participants WHERE rotation_id=$1`, f.rotation))
	}
	f, g := newRotationProfileFixture(t, ctx, db), newRotationProfileFixture(t, ctx, db)
	confirm := enforcementPreview(t, ctx, app, rotationProfilePreviewInput(f.root, g.root)...)
	_, err := app.Mutation().DeleteAll(ctx, rotationProfileInput(f.root, g.root, f.root), confirm)
	require.NoError(t, err)
	_, err = app.Mutation().DeleteAll(ctx, rotationProfileInput(uuid.Nil), nil)
	require.NoError(t, err)
	_, err = app.Mutation().DeleteAll(ctx, rotationProfileInput(f.root), confirm)
	enforceCode(t, err, ds.DeletionDependencyChanged)
	_, err = app.Mutation().DeleteAll(ctx, rotationProfileInput(slicesRepeatService(g.root, 51)...), nil)
	require.Error(t, err)
}

func TestPostgresDeletionEnforcementRotationLifecycleBoundary(t *testing.T) {
	ctx, _, db := boundedAuditDB(t, len(Names()))
	ctx = permission.SystemContext(ctx, "RotationProfileTest")
	app := enforcementApp(t, ctx, db)
	for _, count := range []int{1, 3} {
		f := newRotationProfileFixture(t, ctx, db)
		old := rotationProfileVersion(t, ctx, db, f.root)
		users := []string{}
		for range count {
			users = append(users, f.user.String())
		}
		require.NoError(t, app.RotationStore.AddRotationUsersTx(ctx, nil, f.root.String(), users))
		require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM rotation_state WHERE rotation_id=$1`, f.root))
		facts, err := collectDeletion(t, ctx, db, rotationProfileRoot(f.root), collector.Limits{})
		require.NoError(t, err)
		require.Equal(t, ds.DependenciesComplete, facts.Collection.Completeness)
		_, err = app.Mutation().DeleteAll(ctx, rotationProfileInput(f.root), nil)
		enforceCode(t, err, ds.DeletionConfirmationRequired)
		_, err = app.Mutation().DeleteAll(ctx, rotationProfileInput(f.root), &graphql2.DeletionSafetyConfirmationInput{ExpectedImpactVersion: old, AcknowledgeImpacts: true})
		enforceCode(t, err, ds.DeletionDependencyChanged)
		empty := newRotationProfileFixture(t, ctx, db)
		_, err = app.Mutation().DeleteAll(ctx, rotationProfileInput(empty.root, f.root), nil)
		enforceCode(t, err, ds.DeletionConfirmationRequired)
		require.Equal(t, 2, enforcementCount(t, ctx, db, `SELECT count(*) FROM rotations WHERE id IN ($1,$2)`, empty.root, f.root))
		require.Equal(t, count, enforcementCount(t, ctx, db, `SELECT count(*) FROM rotation_participants WHERE rotation_id=$1`, f.root))
		var ids []string
		rows, err := db.QueryContext(ctx, `SELECT id::text FROM rotation_participants WHERE rotation_id=$1 ORDER BY position`, f.root)
		require.NoError(t, err)
		for rows.Next() {
			var id string
			require.NoError(t, rows.Scan(&id))
			ids = append(ids, id)
		}
		require.NoError(t, rows.Err())
		rows.Close()
		// This separate member-edit operation exercises the normal last-member
		// Trigger. It is never cleanup by the deletion enforcer or a CASCADE proof.
		require.NoError(t, app.RotationStore.DeleteRotationParticipantsTx(ctx, nil, ids))
		require.Zero(t, enforcementCount(t, ctx, db, `SELECT count(*) FROM rotation_state WHERE rotation_id=$1`, f.root))
		require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM users WHERE id=$1`, f.user))
	}
}

func TestPostgresDeletionEnforcementRotationReferenceBlock(t *testing.T) {
	ctx, _, db := boundedAuditDB(t, len(Names()))
	ctx = permission.SystemContext(ctx, "RotationProfileTest")
	app := enforcementApp(t, ctx, db)
	for _, kind := range []string{"rule", "action"} {
		f := rotationPopulated(t, ctx, db, 5, 2)
		for range 2 {
			if kind == "rule" {
				id := uuid.New()
				scheduleProfileInsert(t, ctx, db, id, f.org)
				enforcementExec(t, ctx, db, `INSERT INTO schedule_rules(schedule_id,tgt_rotation_id) VALUES($1,$2)`, id, f.root)
			} else {
				policy := uuid.New()
				epProfileInsert(t, ctx, db, policy, f.org)
				for range 4 {
					step := uuid.New()
					enforcementExec(t, ctx, db, `INSERT INTO escalation_policy_steps(id,escalation_policy_id) VALUES($1,$2)`, step, policy)
					enforcementExec(t, ctx, db, `INSERT INTO escalation_policy_actions(escalation_policy_step_id,rotation_id) VALUES($1,$2)`, step, f.root)
				}
			}
		}
		facts, err := collectDeletion(t, ctx, db, rotationProfileRoot(f.root), collector.Limits{})
		require.NoError(t, err)
		relation := ds.RelationshipRuleTarget
		n := 2
		if kind == "action" {
			relation = ds.RelationshipActionTarget
			n = 8
		}
		require.Len(t, slices.DeleteFunc(facts.Collection.Dependencies, func(d ds.Dependency) bool { return d.Relationship != relation }), n)
		confirm := enforcementPreview(t, ctx, app, rotationProfilePreviewInput(f.root)...)
		for _, c := range []*graphql2.DeletionSafetyConfirmationInput{nil, confirm, {ExpectedImpactVersion: confirm.ExpectedImpactVersion, AcknowledgeImpacts: true}} {
			_, err = app.Mutation().DeleteAll(ctx, rotationProfileInput(f.root), c)
			enforceCode(t, err, ds.DeletionBlocked)
		}
		require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM rotations WHERE id=$1`, f.root))
	}
	rotationProfileNoSuccess(t, ctx, db)
}

func TestPostgresDeletionEnforcementRotationAuditFailure(t *testing.T) {
	ctx, _, db := boundedAuditDB(t, len(Names()))
	ctx = permission.SystemContext(ctx, "RotationProfileTest")
	app := enforcementApp(t, ctx, db)
	f, g := newRotationProfileFixture(t, ctx, db), newRotationProfileFixture(t, ctx, db)
	enforcementExec(t, ctx, db, `INSERT INTO user_favorites(user_id,tgt_rotation_id) VALUES($1,$2)`, f.user, f.root)
	confirm := enforcementPreview(t, ctx, app, rotationProfilePreviewInput(f.root, g.root)...)
	enforcementExec(t, ctx, db, `CREATE FUNCTION synthetic_rotation_sink_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.outcome='committed' THEN IF EXISTS(SELECT FROM rotations WHERE id=NEW.root_id) THEN RAISE EXCEPTION 'delete did not run'; END IF; RAISE EXCEPTION 'synthetic audit failure after delete'; END IF; RETURN NEW; END $$`)
	enforcementExec(t, ctx, db, `CREATE TRIGGER synthetic_rotation_sink_failure BEFORE INSERT ON schedule_rotation_delete_audit_events FOR EACH ROW EXECUTE FUNCTION synthetic_rotation_sink_failure()`)
	_, err := app.Mutation().DeleteAll(ctx, rotationProfileInput(f.root, g.root), confirm)
	require.Error(t, err)
	require.Equal(t, 2, enforcementCount(t, ctx, db, `SELECT count(*) FROM rotations WHERE id IN ($1,$2)`, f.root, g.root))
	require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM user_favorites WHERE tgt_rotation_id=$1`, f.root))
	rotationProfileNoSuccess(t, ctx, db)
	enforcementExec(t, ctx, db, `DROP TRIGGER synthetic_rotation_sink_failure ON schedule_rotation_delete_audit_events`)
	_, err = app.Mutation().DeleteAll(ctx, rotationProfileInput(f.root, g.root), confirm)
	require.NoError(t, err)
}

func TestPostgresDeletionEnforcementRotationGuardLifecycle(t *testing.T) {
	ctx, _, db := boundedAuditDB(t, len(Names()))
	ctx = permission.SystemContext(ctx, "RotationProfileTest")
	f := rotationPopulated(t, ctx, db, 5, 2)
	app := enforcementApp(t, ctx, db)
	version := rotationProfileVersion(t, ctx, db, f.root)
	raw := rotationProfileSelectors(f.root)
	for _, phase := range []string{"before_locks", "after_locks", "after_witness"} {
		t.Run(phase, func(t *testing.T) {
			tx := nrBegin(t, ctx, db)
			if phase == "before_locks" {
				_, err := tx.ExecContext(ctx, `SAVEPOINT checkpoint`)
				require.NoError(t, err)
			}
			checked, _, err := guard.StabilizeRotation(ctx, tx, raw)
			require.NoError(t, err)
			if phase == "after_locks" {
				_, err = tx.ExecContext(ctx, `SAVEPOINT checkpoint`)
				require.NoError(t, err)
			}
			facts, err := collector.Collect(checked, tx, rotationProfileRoot(f.root), collector.Recheck, collector.Limits{}, authorizeDeletionFixture(rotationProfileRoot(f.root)))
			require.NoError(t, err)
			plan := deletionPlan(t, rotationProfileRoot(f.root), facts)
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
				_, err = app.RotationStore.DeleteManyForAuditTx(bound, tx, []string{f.root.String()}, nil)
				enforceCode(t, err, ds.DeletionUnavailable)
				_, err = guard.Bind(ctx, tx, checked, raw, plan, version, true)
				enforceCode(t, err, ds.DeletionUnavailable)
				bound = rotationProfileEnforce(t, ctx, tx, f.root, version)
			}
			receipts, err := app.RotationStore.DeleteManyForAuditTx(bound, tx, []string{f.root.String()}, nil)
			require.NoError(t, err)
			require.Len(t, receipts, 1)
			_, err = app.RotationStore.DeleteManyForAuditTx(bound, tx, []string{f.root.String()}, nil)
			enforceCode(t, err, ds.DeletionUnavailable)
			require.NoError(t, tx.Rollback())
		})
	}
	tx := nrBegin(t, ctx, db)
	old := rotationProfileEnforce(t, ctx, tx, f.root, version)
	_, err := tx.ExecContext(ctx, `SAVEPOINT old_generation`)
	require.NoError(t, err)
	newer := rotationProfileEnforce(t, ctx, tx, f.root, version)
	_, err = tx.ExecContext(ctx, `ROLLBACK TO old_generation`)
	require.NoError(t, err)
	for _, bound := range []context.Context{old, newer} {
		_, err = guard.ConsumeRotation(bound, tx, []string{f.root.String()})
		enforceCode(t, err, ds.DeletionUnavailable)
	}
	bound := rotationProfileEnforce(t, ctx, tx, f.root, version)
	other, err := db.BeginTx(ctx, nil)
	require.NoError(t, err)
	_, err = guard.ConsumeRotation(bound, other, []string{f.root.String()})
	enforceCode(t, err, ds.DeletionUnavailable)
	require.NoError(t, other.Rollback())
	_, err = guard.ConsumeRotation(bound, tx, []string{uuid.NewString()})
	enforceCode(t, err, ds.DeletionUnavailable)
	_, err = guard.ConsumeCM(bound, tx, []string{f.root.String()})
	enforceCode(t, err, ds.DeletionUnavailable)
	_, err = guard.ConsumeNR(bound, tx, []string{f.root.String()})
	enforceCode(t, err, ds.DeletionUnavailable)
	_, err = guard.ConsumeRotation(context.WithValue(ctx, serviceProfileContextKey{}, "rotation-only-v1"), tx, []string{f.root.String()})
	enforceCode(t, err, ds.DeletionUnavailable)
	_, err = guard.ConsumeRotation(context.WithValue(bound, serviceProfileContextKey{}, true), tx, []string{f.root.String()})
	require.NoError(t, err)
	_, err = guard.ConsumeRotation(bound, tx, []string{f.root.String()})
	enforceCode(t, err, ds.DeletionUnavailable)
	require.NoError(t, tx.Rollback())
	for _, commit := range []bool{false, true} {
		tx = nrBegin(t, ctx, db)
		bound = rotationProfileEnforce(t, ctx, tx, f.root, version)
		if commit {
			require.NoError(t, tx.Commit())
		} else {
			require.NoError(t, tx.Rollback())
		}
		_, err = guard.ConsumeRotation(bound, tx, []string{f.root.String()})
		enforceCode(t, err, ds.DeletionUnavailable)
	}
	tx = nrBegin(t, ctx, db)
	_, err = tx.ExecContext(ctx, `SELECT 1/0`)
	require.Error(t, err)
	_, err = collector.Enforce(ctx, tx, raw, version, true, authorizeDeletionFixture(rotationProfileRoot(f.root)))
	enforceCode(t, err, ds.DeletionUnavailable)
	require.NoError(t, tx.Rollback())
	for _, fn := range []func() error{
		func() error { return app.RotationStore.DeleteManyTx(ctx, nil, []string{f.root.String()}, nil) },
		func() error {
			tx := nrBegin(t, ctx, db)
			defer func() { _ = tx.Rollback() }()
			return app.RotationStore.DeleteManyTx(ctx, tx, []string{f.root.String()}, nil)
		},
	} {
		enforceCode(t, fn(), ds.DeletionUnavailable)
	}
	rotationProfileNoSuccess(t, ctx, db)
}

func TestPostgresDeletionEnforcementRotationAuthorization(t *testing.T) {
	ctx, _, db := boundedAuditDB(t, len(Names()))
	sys := permission.SystemContext(ctx, "RotationProfileTest")
	app := enforcementApp(t, sys, db)
	for _, role := range []string{"ORG_ADMIN", "ORG_MEMBER", "PLATFORM_ADMIN"} {
		t.Run(role, func(t *testing.T) {
			f := rotationPopulated(t, ctx, db, 5, 2)
			if role == "ORG_MEMBER" {
				enforcementExec(t, ctx, db, `UPDATE user_organization_assignments SET organization_role='ORG_MEMBER' WHERE user_id=$1`, f.actor)
			}
			if role == "PLATFORM_ADMIN" {
				enforcementExec(t, ctx, db, `UPDATE users SET role='admin' WHERE id=$1`, f.actor)
			}
			human := previewAdmit(t, ctx, db, f.actor)
			if role == "ORG_MEMBER" {
				_, err := app.Mutation().DeleteAll(human, rotationProfileInput(f.root), nil)
				require.Error(t, err)
				require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM rotations WHERE id=$1`, f.root))
				return
			}
			confirm := enforcementPreview(t, human, app, graphql2.DeletionResourceInput{Type: graphql2.DeletionTargetTypeRotation, ID: f.root.String()})
			for _, q := range []string{`UPDATE users SET name=name WHERE id=$1`, `UPDATE user_organization_assignments SET source_config_version=source_config_version WHERE user_id=$1`} {
				writer, err := db.BeginTx(ctx, nil)
				require.NoError(t, err)
				defer func() { _ = writer.Rollback() }()
				_, err = writer.ExecContext(ctx, q, f.actor)
				require.NoError(t, err)
				tx := nrBegin(t, human, db)
				_, err = collector.Enforce(human, tx, rotationProfileSelectors(f.root), confirm.ExpectedImpactVersion, true, authorizeDeletionFixture(rotationProfileRoot(f.root)))
				enforceCode(t, err, ds.DeletionUnavailable)
				require.NoError(t, tx.Rollback())
				require.NoError(t, writer.Rollback())
				tx = nrBegin(t, human, db)
				_ = rotationProfileEnforce(t, human, tx, f.root, confirm.ExpectedImpactVersion)
				writer, err = db.BeginTx(ctx, nil)
				require.NoError(t, err)
				writerCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
				done := nrWaiter(t, writerCtx, db, writer, q, f.actor)
				require.NoError(t, tx.Rollback())
				require.NoError(t, <-done)
				require.NoError(t, writer.Rollback())
				cancel()
			}
			ok, err := app.Mutation().DeleteAll(human, rotationProfileInput(f.root), confirm)
			require.NoError(t, err)
			require.True(t, ok)
		})
	}
	f, other := newRotationProfileFixture(t, ctx, db), newRotationProfileFixture(t, ctx, db)
	human := previewAdmit(t, ctx, db, f.actor)
	_, err := app.Mutation().DeleteAll(human, rotationProfileInput(other.root), nil)
	require.Error(t, err)
	confirm := enforcementPreview(t, human, app, graphql2.DeletionResourceInput{Type: graphql2.DeletionTargetTypeRotation, ID: f.root.String()})
	enforcementExec(t, ctx, db, `UPDATE user_organization_assignments SET organization_role='ORG_MEMBER' WHERE user_id=$1`, f.actor)
	_, err = app.Mutation().DeleteAll(human, rotationProfileInput(f.root), confirm)
	require.Error(t, err)
	require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM rotations WHERE id=$1`, f.root))
}

func TestPostgresDeletionEnforcementRotationCarrierIsolation(t *testing.T) {
	ctx, _, db := boundedAuditDB(t, len(Names()))
	ctx = permission.SystemContext(ctx, "RotationProfileTest")
	f := rotationPopulated(t, ctx, db, 5, 2)
	other := newServiceProfileFixture(t, ctx, db)
	nr := newDeletionFixture(t, ctx, db)
	app := enforcementApp(t, ctx, db)
	for _, root := range []ds.Resource{nrRoot(nr.nr), cmRoot(nr.cm), serviceProfileRoot(other.service), epProfileRoot(f.policy), scheduleProfileRoot(f.schedule)} {
		facts, err := collectDeletion(t, ctx, db, root, collector.Limits{})
		require.NoError(t, err)
		tx := nrBegin(t, ctx, db)
		bound, err := collector.Enforce(ctx, tx, []collector.Selector{{Kind: root.Kind, ID: root.ID}}, deletionPlan(t, root, facts).ImpactVersion(), true, authorizeDeletionFixture(root))
		require.NoError(t, err)
		_, err = app.RotationStore.DeleteManyForAuditTx(bound, tx, []string{f.root.String()}, nil)
		enforceCode(t, err, ds.DeletionUnavailable)
		require.NoError(t, tx.Rollback())
	}
	tx := nrBegin(t, ctx, db)
	bound := rotationProfileEnforce(t, ctx, tx, f.root, rotationProfileVersion(t, ctx, db, f.root))
	for _, fn := range []func() error{
		func() error {
			_, err := app.ServiceStore.DeleteManyForAuditTx(bound, tx, []string{other.service.String()}, nil)
			return err
		},
		func() error { _, err := guard.ConsumeEP(bound, tx, []string{f.policy.String()}); return err },
		func() error { _, err := guard.ConsumeSchedule(bound, tx, []string{f.schedule.String()}); return err },
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
	rotationProfileNoSuccess(t, ctx, db)
}

func TestPostgresDeletionEnforcementRotationWitnessTamper(t *testing.T) {
	ctx, _, db := boundedAuditDB(t, len(Names()))
	ctx = permission.SystemContext(ctx, "RotationProfileTest")
	f := rotationPopulated(t, ctx, db, 5, 2)
	version := rotationProfileVersion(t, ctx, db, f.root)
	for _, change := range []string{`nonce=gen_random_uuid()`, `profile='service-only-v1'`, `xid='foreign'`, `raw_hash=decode('00','hex')`, `effective_hash=decode('00','hex')`} {
		tx := nrBegin(t, ctx, db)
		bound := rotationProfileEnforce(t, ctx, tx, f.root, version)
		_, err := tx.ExecContext(ctx, `SAVEPOINT original_witness`)
		require.NoError(t, err)
		_, err = tx.ExecContext(ctx, `UPDATE pg_temp.d09_nr_deletion_witness SET `+change+` WHERE phase='certified'`)
		require.NoError(t, err)
		_, err = guard.ConsumeRotation(bound, tx, []string{f.root.String()})
		enforceCode(t, err, ds.DeletionUnavailable)
		_, err = tx.ExecContext(ctx, `ROLLBACK TO original_witness`)
		require.NoError(t, err)
		_, err = guard.ConsumeRotation(bound, tx, []string{f.root.String()})
		enforceCode(t, err, ds.DeletionUnavailable)
		require.NoError(t, tx.Rollback())
	}
	// A Rotation carrier never becomes a child-root/retained-root capability.
	app := enforcementApp(t, ctx, db)
	tx := nrBegin(t, ctx, db)
	bound := rotationProfileEnforce(t, ctx, tx, f.root, version)
	for _, call := range []func() error{func() error { return app.OverrideStore.DeleteUserOverrideTx(bound, tx, f.override.String()) }, func() error { return app.UserStore.DeleteManyTx(bound, tx, []string{f.user.String()}) }, func() error { return app.RotationStore.DeleteManyTx(bound, tx, []string{f.rotation.String()}, nil) }} {
		enforceCode(t, call(), ds.DeletionUnavailable)
	}
	require.NoError(t, tx.Rollback())
	rotationProfileNoSuccess(t, ctx, db)
}

func TestPostgresDeletionEnforcementRotationIndependent(t *testing.T) {
	ctx, uri, db := boundedAuditDB(t, len(Names()))
	ctx = permission.SystemContext(ctx, "RotationProfileTest")
	for _, first := range []string{"writer", "delete"} {
		for index := 0; index < 9; index++ {
			f := rotationPopulated(t, ctx, db, 5, 2)
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
				confirm := enforcementPreview(t, ctx, app, rotationProfilePreviewInput(f.root)...)
				if first == "writer" {
					run()
					ok, err := app.Mutation().DeleteAll(ctx, rotationProfileInput(f.root), confirm)
					require.NoError(t, err)
					require.True(t, ok)
					require.NoError(t, writer.Commit())
				} else {
					done := make(chan error, 1)
					go func() {
						_, err := app.Mutation().DeleteAll(ctx, rotationProfileInput(f.root), confirm)
						done <- err
					}()
					select {
					case <-barrier.arrived:
					case <-ctx.Done():
						t.Fatal(ctx.Err())
					}
					// Exactly the two pre-existing Rotation table locks; unrelated business updates still commit.
					require.Equal(t, 2, enforcementCount(t, ctx, db, `SELECT count(*) FROM pg_locks l JOIN pg_class c ON c.oid=l.relation JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND l.mode IN ('ShareLock','ShareRowExclusiveLock','ExclusiveLock','AccessExclusiveLock') AND l.granted`))
					run()
					require.NoError(t, writer.Commit())
					close(barrier.resume)
					require.NoError(t, <-done)
				}
				require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM schedule_rotation_delete_audit_events WHERE root_id=$1 AND outcome='committed'`, f.root))
			})
		}
	}
}

func TestPostgresDeletionEnforcementRotationReferenceWriters(t *testing.T) {
	ctx, _, db := boundedAuditDB(t, len(Names()))
	ctx = permission.SystemContext(ctx, "RotationProfileTest")
	for _, first := range []string{"delete", "writer"} {
		for _, kind := range []string{"rule_create", "rule_to", "rule_away", "rule_delete", "rule_reparent", "rule_update", "schedule_scope", "action_create", "action_to", "action_away", "action_delete", "action_reparent", "ep_scope"} {
			t.Run(first+"_"+kind, func(t *testing.T) {
				f := rotationPopulated(t, ctx, db, 5, 2)
				app := enforcementApp(t, ctx, db)
				rules, err := rule.NewStore(ctx, db)
				require.NoError(t, err)
				registry := nfydest.NewRegistry()
				registry.RegisterProvider(ctx, app.RotationStore)
				ep, err := escalation.NewStore(ctx, db, escalation.Config{Registry: registry})
				require.NoError(t, err)
				incoming := kind != "rule_create" && kind != "rule_to" && kind != "action_create" && kind != "action_to"
				target := f.rotation
				if incoming {
					target = f.root
				}
				isRule := kind[:4] == "rule" || kind == "schedule_scope"
				if isRule {
					enforcementExec(t, ctx, db, `INSERT INTO schedule_rules(id,schedule_id,tgt_rotation_id) VALUES($1,$2,$3)`, f.rule, f.schedule, target)
				} else {
					enforcementExec(t, ctx, db, `INSERT INTO escalation_policy_steps(id,escalation_policy_id) VALUES($1,$2)`, f.step, f.policy)
					enforcementExec(t, ctx, db, `INSERT INTO escalation_policy_actions(id,escalation_policy_step_id,rotation_id) VALUES($1,$2,$3)`, f.action, f.step, target)
				}
				newPolicy, newStep := uuid.New(), uuid.New()
				epProfileInsert(t, ctx, db, newPolicy, f.org)
				enforcementExec(t, ctx, db, `INSERT INTO escalation_policy_steps(id,escalation_policy_id) VALUES($1,$2)`, newStep, newPolicy)
				other := newRotationProfileFixture(t, ctx, db)
				version := rotationProfileVersion(t, ctx, db, f.root)
				writer := epProfileWriter(t, ctx, db)
				run := func() error {
					switch kind {
					case "rule_create":
						_, err := rules.CreateRuleTx(ctx, writer, rule.NewAlwaysActive(f.otherSchedule.String(), assignment.RotationTarget(f.root.String())))
						return err
					case "rule_delete":
						return rules.DeleteManyTx(ctx, writer, []string{f.rule.String()})
					case "rule_to", "rule_away", "rule_reparent", "rule_update":
						dest, parent := f.root, f.schedule
						if kind == "rule_away" {
							dest = f.rotation
						}
						if kind == "rule_reparent" {
							parent = f.otherSchedule
						}
						r := rule.NewAlwaysActive(parent.String(), assignment.RotationTarget(dest.String()))
						r.ID = f.rule.String()
						r.WeekdayFilter[1] = 0
						return rules.UpdateTx(ctx, writer, r)
					case "schedule_scope":
						_, err := writer.ExecContext(ctx, `UPDATE schedules SET organization_id=$2 WHERE id=$1`, f.schedule, other.org)
						return err
					case "action_create":
						return ep.AddStepActionTx(ctx, writer, newStep, rotation.DestFromID(f.root.String()))
					case "action_delete":
						return ep.DeleteStepActionTx(ctx, writer, f.step, rotation.DestFromID(f.root.String()))
					case "action_to", "action_away":
						dest := f.root
						if kind == "action_away" {
							dest = f.rotation
						}
						_, err := writer.ExecContext(ctx, `UPDATE escalation_policy_actions SET rotation_id=$2 WHERE id=$1`, f.action, dest)
						return err
					case "action_reparent":
						_, err := writer.ExecContext(ctx, `UPDATE escalation_policy_actions SET escalation_policy_step_id=$2 WHERE id=$1`, f.action, newStep)
						return err
					default:
						_, err := writer.ExecContext(ctx, `UPDATE escalation_policies SET organization_id=$2 WHERE id=$1`, f.policy, other.org)
						return err
					}
				}
				if first == "writer" {
					require.NoError(t, run())
					tx := nrBegin(t, ctx, db)
					_, err = collector.Enforce(ctx, tx, rotationProfileSelectors(f.root), version, true, authorizeDeletionFixture(rotationProfileRoot(f.root)))
					enforceCode(t, err, ds.DeletionUnavailable)
					require.NoError(t, tx.Rollback())
					require.NoError(t, writer.Commit())
					fresh := rotationProfileVersion(t, ctx, db, f.root)
					tx = nrBegin(t, ctx, db)
					_, err = collector.Enforce(ctx, tx, rotationProfileSelectors(f.root), fresh, true, authorizeDeletionFixture(rotationProfileRoot(f.root)))
					removed := kind == "rule_away" || kind == "rule_delete" || kind == "action_away" || kind == "action_delete"
					if removed {
						require.NoError(t, err)
					} else {
						enforceCode(t, err, ds.DeletionBlocked)
					}
					require.NoError(t, tx.Rollback())
					if removed {
						tx = nrBegin(t, ctx, db)
						_, err = collector.Enforce(ctx, tx, rotationProfileSelectors(f.root), version, true, authorizeDeletionFixture(rotationProfileRoot(f.root)))
						enforceCode(t, err, ds.DeletionDependencyChanged)
						require.NoError(t, tx.Rollback())
					}
				} else {
					tx := nrBegin(t, ctx, db)
					if incoming {
						_, _, err = guard.StabilizeRotation(ctx, tx, rotationProfileSelectors(f.root))
						require.NoError(t, err)
						done := serviceProfileWait(t, ctx, db, writer, run)
						require.NoError(t, tx.Rollback())
						require.NoError(t, <-done)
						require.NoError(t, writer.Commit())
					} else {
						bound := rotationProfileEnforce(t, ctx, tx, f.root, version)
						done := serviceProfileWait(t, ctx, db, writer, run)
						receipts, err := app.RotationStore.DeleteManyForAuditTx(bound, tx, []string{f.root.String()}, nil)
						require.NoError(t, err)
						require.Len(t, receipts, 1)
						require.NoError(t, tx.Commit())
						err = <-done
						require.Error(t, err)
						require.Equal(t, "23503", sqlutil.MapError(err).Code)
						require.NoError(t, writer.Rollback())
					}
				}
				require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM schedules WHERE id=$1`, f.schedule))
				require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM escalation_policies WHERE id=$1`, f.policy))
			})
		}
	}
	rotationProfileNoSuccess(t, ctx, db)
}

func TestPostgresDeletionEnforcementRotationStateWriters(t *testing.T) {
	ctx, _, db := boundedAuditDB(t, len(Names()))
	ctx = permission.SystemContext(ctx, "RotationProfileTest")
	app := enforcementApp(t, ctx, db)
	for _, first := range []string{"delete", "writer"} {
		for _, kind := range []string{"insert", "delete", "user", "reorder", "active", "engine_update", "state_update", "root_then_tables"} {
			t.Run(first+"_"+kind, func(t *testing.T) {
				f := newRotationProfileFixture(t, ctx, db)
				require.NoError(t, app.RotationStore.AddRotationUsersTx(ctx, nil, f.root.String(), []string{f.user.String(), f.actor.String(), f.user.String()}))
				parts, err := app.RotationStore.FindAllParticipants(ctx, f.root.String())
				require.NoError(t, err)
				require.Len(t, parts, 3)
				writer := epProfileWriter(t, ctx, db)
				run := func() error {
					switch kind {
					case "insert":
						return app.RotationStore.AddRotationUsersTx(ctx, writer, f.root.String(), []string{f.user.String()})
					case "delete":
						return app.RotationStore.DeleteRotationParticipantsTx(ctx, writer, []string{parts[0].ID})
					case "user":
						return app.RotationStore.UpdateParticipantUserIDTx(ctx, writer, parts[0].ID, f.actor.String())
					case "reorder":
						if _, err := writer.ExecContext(ctx, `LOCK rotation_participants,rotation_state IN EXCLUSIVE MODE`); err != nil {
							return err
						}
						_, err := writer.ExecContext(ctx, `SELECT move_rotation_position($1,2)`, parts[0].ID)
						return err
					case "active":
						return app.RotationStore.SetActiveIndexTx(ctx, writer, f.root.String(), 1)
					case "engine_update":
						return gadb.New(writer).RotMgrUpdate(ctx, gadb.RotMgrUpdateParams{RotationID: f.root, Position: 1, RotationParticipantID: uuid.MustParse(parts[1].ID)})
					case "root_then_tables":
						if _, err := writer.ExecContext(ctx, `UPDATE rotations SET name=name WHERE id=$1`, f.root); err != nil {
							return err
						}
						_, err := writer.ExecContext(ctx, `LOCK rotation_state,rotation_participants IN EXCLUSIVE MODE`)
						return err
					default:
						_, err := writer.ExecContext(ctx, `UPDATE rotation_state SET shift_start=shift_start+interval '1 second' WHERE rotation_id=$1`, f.root)
						return err
					}
				}
				if first == "writer" {
					require.NoError(t, run())
					tx := nrBegin(t, ctx, db)
					_, err = collector.Enforce(ctx, tx, rotationProfileSelectors(f.root), "", false, authorizeDeletionFixture(rotationProfileRoot(f.root)))
					enforceCode(t, err, ds.DeletionUnavailable)
					require.NoError(t, tx.Rollback())
					require.NoError(t, writer.Commit())
				} else {
					tx := nrBegin(t, ctx, db)
					checked, _, err := guard.StabilizeRotation(ctx, tx, rotationProfileSelectors(f.root))
					require.NoError(t, err)
					facts, err := collector.Collect(checked, tx, rotationProfileRoot(f.root), collector.Recheck, collector.Limits{}, authorizeDeletionFixture(rotationProfileRoot(f.root)))
					require.NoError(t, err)
					require.Equal(t, ds.DependenciesComplete, facts.Collection.Completeness)
					done := serviceProfileWait(t, ctx, db, writer, run)
					require.NoError(t, tx.Rollback())
					require.NoError(t, <-done)
					require.NoError(t, writer.Commit())
				}
				tx := nrBegin(t, ctx, db)
				_, err = collector.Enforce(ctx, tx, rotationProfileSelectors(f.root), "", false, authorizeDeletionFixture(rotationProfileRoot(f.root)))
				enforceCode(t, err, ds.DeletionConfirmationRequired)
				require.NoError(t, tx.Rollback())
				require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM rotations WHERE id=$1`, f.root))
				require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM users WHERE id=$1`, f.user))
				require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM rotation_state WHERE rotation_id=$1`, f.root))
			})
		}
	}
	rotationProfileNoSuccess(t, ctx, db)
}

func TestPostgresDeletionEnforcementRotationMissingWindow(t *testing.T) {
	ctx, _, db := boundedAuditDB(t, len(Names()))
	ctx = permission.SystemContext(ctx, "RotationProfileTest")
	app := enforcementApp(t, ctx, db)
	for _, legacy := range []bool{false, true} {
		for _, existing := range []bool{false, true} {
			t.Run(fmt.Sprintf("legacy=%v/existing=%v", legacy, existing), func(t *testing.T) {
				f := rotationPopulated(t, ctx, db, 5, 2)
				missing := uuid.New()
				ids := []uuid.UUID{missing}
				version := ""
				if existing {
					ids = append(ids, f.root)
					version = rotationProfileVersion(t, ctx, db, f.root)
				}
				tx := nrBegin(t, ctx, db)
				bound, err := collector.Enforce(ctx, tx, rotationProfileSelectors(ids...), version, true, authorizeDeletionFixture(rotationProfileRoot(f.root)))
				require.NoError(t, err)
				rotationProfileInsert(t, ctx, db, missing, f.org)
				enforcementExec(t, ctx, db, `INSERT INTO schedule_rules(schedule_id,tgt_rotation_id) VALUES($1,$2)`, f.schedule, missing)
				raw := []string{}
				for _, id := range ids {
					raw = append(raw, id.String())
				}
				if legacy {
					require.NoError(t, app.RotationStore.DeleteManyTx(bound, tx, raw, nil))
				} else {
					receipts, err := app.RotationStore.DeleteManyForAuditTx(bound, tx, raw, nil)
					require.NoError(t, err)
					n := 0
					if existing {
						n = 1
					}
					require.Len(t, receipts, n)
				}
				require.NoError(t, tx.Commit())
				require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM rotations WHERE id=$1`, missing))
				require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM schedule_rules WHERE tgt_rotation_id=$1`, missing))
			})
		}
	}
	rotationProfileNoSuccess(t, ctx, db)
}

func TestPostgresDeletionEnforcementRotationControllerMissingWindow(t *testing.T) {
	ctx, uri, db := boundedAuditDB(t, len(Names()))
	sys := permission.SystemContext(ctx, "RotationProfileTest")
	for _, existing := range []bool{false, true} {
		f, other := rotationPopulated(t, sys, db, 5, 2), newRotationProfileFixture(t, sys, db)
		enforcementExec(t, ctx, db, `UPDATE users SET role='admin' WHERE id=$1`, f.actor)
		human := previewAdmit(t, ctx, db, f.actor)
		conf, err := pgx.ParseConfig(uri)
		require.NoError(t, err)
		barrier := &serviceProfileCertificationBarrier{nrQueryBarrier: &nrQueryBarrier{needle: "VALUES($1,'certified'", arrived: make(chan struct{}), resume: make(chan struct{})}}
		conf.Tracer = barrier
		traced := sql.OpenDB(stdlib.GetConnector(*conf))
		app := enforcementApp(t, sys, traced)
		missing := uuid.New()
		input := rotationProfileInput(missing)
		var confirmation *graphql2.DeletionSafetyConfirmationInput
		if existing {
			input = append(input, rotationProfileInput(f.root)...)
			confirmation = enforcementPreview(t, human, app, rotationProfilePreviewInput(f.root)...)
		}
		done := make(chan error, 1)
		go func() { _, err := app.Mutation().DeleteAll(human, input, confirmation); done <- err }()
		select {
		case <-barrier.arrived:
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
		rotationProfileInsert(t, sys, db, missing, other.org)
		enforcementExec(t, sys, db, `INSERT INTO schedule_rules(schedule_id,tgt_rotation_id) VALUES($1,$2)`, other.schedule, missing)
		close(barrier.resume)
		require.NoError(t, <-done)
		traced.Close()
		require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM rotations WHERE id=$1`, missing))
		require.Zero(t, enforcementCount(t, ctx, db, `SELECT count(*) FROM schedule_rotation_delete_audit_events WHERE root_id=$1`, missing))
		require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM schedule_rules WHERE tgt_rotation_id=$1`, missing))
		if existing {
			require.Zero(t, enforcementCount(t, ctx, db, `SELECT count(*) FROM rotations WHERE id=$1`, f.root))
		}
	}
}

func TestPostgresDeletionEnforcementRotationFailClosed(t *testing.T) {
	ctx, _, db := boundedAuditDB(t, len(Names()))
	ctx = permission.SystemContext(ctx, "RotationProfileTest")
	app := enforcementApp(t, ctx, db)
	f := newRotationProfileFixture(t, ctx, db)
	for _, kind := range []assignment.TargetType{assignment.TargetTypeUser, assignment.TargetTypeSchedule, assignment.TargetTypeEscalationPolicy, assignment.TargetTypeService, assignment.TargetTypeContactMethod, assignment.TargetTypeNotificationRule, assignment.TargetTypeIntegrationKey, assignment.TargetTypeUserOverride, assignment.TargetTypeUserSession, assignment.TargetTypeCalendarSubscription} {
		_, err := app.Mutation().DeleteAll(ctx, append(rotationProfileInput(f.root), assignment.RawTarget{Type: kind, ID: uuid.NewString()}), nil)
		require.Error(t, err)
	}
	for _, kind := range []assignment.TargetType{assignment.TargetTypeUser, assignment.TargetTypeIntegrationKey, assignment.TargetTypeUserSession, assignment.TargetTypeCalendarSubscription} {
		_, err := app.Mutation().DeleteAll(ctx, []assignment.RawTarget{{Type: kind, ID: uuid.NewString()}}, nil)
		require.Error(t, err)
	}
	// Labels and cross-organization references remain unsupported/unauthorized.
	enforcementExec(t, ctx, db, `INSERT INTO labels(tgt_rotation_id,key,value) VALUES($1,'synthetic','value')`, f.root)
	_, err := app.Mutation().DeleteAll(ctx, rotationProfileInput(f.root), nil)
	enforceCode(t, err, ds.DeletionUnavailable)
	require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM rotations WHERE id=$1`, f.root))
	rotationProfileNoSuccess(t, ctx, db)
}

func TestPostgresDeletionEnforcementRotationTableProtocol(t *testing.T) {
	ctx, _, db := boundedAuditDB(t, len(Names()))
	ctx = permission.SystemContext(ctx, "RotationProfileTest")
	app := enforcementApp(t, ctx, db)
	for _, table := range []string{"rotation_participants", "rotation_state"} {
		f := rotationPopulated(t, ctx, db, 5, 2)
		writer := epProfileWriter(t, ctx, db)
		_, err := writer.ExecContext(ctx, `LOCK TABLE `+table+` IN ROW EXCLUSIVE MODE`)
		require.NoError(t, err)
		tx := nrBegin(t, ctx, db)
		_, err = collector.Enforce(ctx, tx, rotationProfileSelectors(f.root), "", false, authorizeDeletionFixture(rotationProfileRoot(f.root)))
		enforceCode(t, err, ds.DeletionUnavailable)
		require.NoError(t, tx.Rollback())
		require.NoError(t, writer.Rollback())
		// Delete-first also contends with another Rotation's writes, by design.
		tx = nrBegin(t, ctx, db)
		_ = rotationProfileEnforce(t, ctx, tx, f.root, rotationProfileVersion(t, ctx, db, f.root))
		writer = epProfileWriter(t, ctx, db)
		_, err = writer.ExecContext(ctx, `SET LOCAL lock_timeout='100ms'`)
		require.NoError(t, err)
		if table == "rotation_participants" {
			err = app.RotationStore.AddRotationUsersTx(ctx, writer, f.rotation.String(), []string{f.user.String()})
		} else {
			err = app.RotationStore.SetActiveIndexTx(ctx, writer, f.rotation.String(), 0)
		}
		require.Error(t, err)
		require.Equal(t, "55P03", sqlutil.MapError(err).Code)
		require.NoError(t, writer.Rollback())
		require.NoError(t, tx.Rollback())
	}
	// A reverse writer holds the root, then waits for the two-table protocol.
	// Native deletion rejects that root NOWAIT and releases its early tables.
	f := rotationPopulated(t, ctx, db, 5, 2)
	writer := epProfileWriter(t, ctx, db)
	_, err := writer.ExecContext(ctx, `UPDATE rotations SET name=name WHERE id=$1`, f.root)
	require.NoError(t, err)
	tx := nrBegin(t, ctx, db)
	_, err = collector.Enforce(ctx, tx, rotationProfileSelectors(f.root), "", false, authorizeDeletionFixture(rotationProfileRoot(f.root)))
	enforceCode(t, err, ds.DeletionUnavailable)
	require.NoError(t, tx.Rollback())
	_, err = writer.ExecContext(ctx, `LOCK rotation_state,rotation_participants IN EXCLUSIVE MODE NOWAIT`)
	require.NoError(t, err)
	require.NoError(t, writer.Commit())
	rotationProfileNoSuccess(t, ctx, db)
}

func TestPostgresDeletionEnforcementRotationStepReparentDenied(t *testing.T) {
	ctx, _, db := boundedAuditDB(t, len(Names()))
	ctx = permission.SystemContext(ctx, "RotationProfileTest")
	for _, first := range []string{"writer", "delete"} {
		f := newRotationProfileFixture(t, ctx, db)
		other := uuid.New()
		epProfileInsert(t, ctx, db, other, f.org)
		enforcementExec(t, ctx, db, `INSERT INTO escalation_policy_steps(id,escalation_policy_id) VALUES($1,$2)`, f.step, f.policy)
		enforcementExec(t, ctx, db, `INSERT INTO escalation_policy_actions(escalation_policy_step_id,rotation_id) VALUES($1,$2)`, f.step, f.root)
		writer := epProfileWriter(t, ctx, db)
		run := func() error {
			_, err := writer.ExecContext(ctx, `UPDATE escalation_policy_steps SET escalation_policy_id=$2 WHERE id=$1`, f.step, other)
			return err
		}
		var err error
		if first == "delete" {
			tx := nrBegin(t, ctx, db)
			_, _, err = guard.StabilizeRotation(ctx, tx, rotationProfileSelectors(f.root))
			require.NoError(t, err)
			done := serviceProfileWait(t, ctx, db, writer, run)
			require.NoError(t, tx.Rollback())
			require.NoError(t, <-done)
		} else {
			require.NoError(t, run())
			tx := nrBegin(t, ctx, db)
			_, err = collector.Enforce(ctx, tx, rotationProfileSelectors(f.root), rotationProfileVersion(t, ctx, db, f.root), true, authorizeDeletionFixture(rotationProfileRoot(f.root)))
			enforceCode(t, err, ds.DeletionUnavailable)
			require.NoError(t, tx.Rollback())
		}
		err = writer.Commit() // the existing parent invariant is DEFERRABLE INITIALLY DEFERRED
		require.Error(t, err)
		require.Equal(t, "P0001", sqlutil.MapError(err).Code)
		require.Contains(t, err.Error(), "must not change escalation_policy_id")
		require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM escalation_policy_steps WHERE id=$1 AND escalation_policy_id=$2`, f.step, f.policy))
		tx := nrBegin(t, ctx, db)
		_, err = collector.Enforce(ctx, tx, rotationProfileSelectors(f.root), rotationProfileVersion(t, ctx, db, f.root), true, authorizeDeletionFixture(rotationProfileRoot(f.root)))
		enforceCode(t, err, ds.DeletionBlocked)
		require.NoError(t, tx.Rollback())
	}
	rotationProfileNoSuccess(t, ctx, db)
}

func TestPostgresDeletionEnforcementRotationScope(t *testing.T) {
	ctx, _, db := boundedAuditDB(t, len(Names()))
	sys := permission.SystemContext(ctx, "RotationProfileTest")
	app := enforcementApp(t, sys, db)
	for _, kind := range []string{"rule_foreign", "action_foreign", "rule_orphan", "action_orphan", "organization_missing", "favorite_owner_assignment_missing"} {
		t.Run(kind, func(t *testing.T) {
			f, other := newRotationProfileFixture(t, sys, db), newRotationProfileFixture(t, sys, db)
			switch kind {
			case "rule_foreign", "rule_orphan":
				parent := f.schedule
				if kind == "rule_foreign" {
					parent = other.schedule
				}
				enforcementExec(t, ctx, db, `INSERT INTO schedule_rules(id,schedule_id,tgt_rotation_id) VALUES($1,$2,$3)`, f.rule, parent, f.root)
				if kind == "rule_orphan" {
					corruptDeletionFixture(t, ctx, db, `UPDATE schedule_rules SET schedule_id=$2 WHERE id=$1`, f.rule, uuid.New())
				}
			case "action_foreign", "action_orphan":
				policy := f.policy
				if kind == "action_foreign" {
					policy = other.policy
				}
				enforcementExec(t, ctx, db, `INSERT INTO escalation_policy_steps(id,escalation_policy_id) VALUES($1,$2)`, f.step, policy)
				enforcementExec(t, ctx, db, `INSERT INTO escalation_policy_actions(id,escalation_policy_step_id,rotation_id) VALUES($1,$2,$3)`, f.action, f.step, f.root)
				if kind == "action_orphan" {
					corruptDeletionFixture(t, ctx, db, `UPDATE escalation_policy_actions SET escalation_policy_step_id=$2 WHERE id=$1`, f.action, uuid.New())
				}
			case "organization_missing":
				corruptDeletionFixture(t, ctx, db, `UPDATE rotations SET organization_id=$2 WHERE id=$1`, f.root, uuid.New())
			default:
				enforcementExec(t, ctx, db, `INSERT INTO user_favorites(user_id,tgt_rotation_id) VALUES($1,$2)`, f.user, f.root)
				enforcementExec(t, ctx, db, `DELETE FROM user_organization_assignments WHERE user_id=$1`, f.user)
			}
			// Trigger suppression is confined to malformed negative fixtures above;
			// every executable scenario uses the normal production lifecycle.
			human := previewAdmit(t, ctx, db, f.actor)
			if kind == "rule_foreign" || kind == "action_foreign" {
				facts, err := collectDeletion(t, human, db, rotationProfileRoot(f.root), collector.Limits{})
				require.Error(t, err)
				require.Empty(t, facts.Collection.Dependencies)
				require.Empty(t, facts.Collection.Checked)
			}
			_, err := app.Mutation().DeleteAll(human, rotationProfileInput(f.root), nil)
			require.Error(t, err)
			require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM rotations WHERE id=$1`, f.root))
		})
	}
	rotationProfileNoSuccess(t, ctx, db)
}

func TestPostgresDeletionEnforcementRotationStoreBypass(t *testing.T) {
	ctx, _, db := boundedAuditDB(t, len(Names()))
	ctx = permission.SystemContext(ctx, "RotationProfileTest")
	f := rotationPopulated(t, ctx, db, 5, 2)
	app := enforcementApp(t, ctx, db)
	for _, audited := range []bool{false, true} {
		tx := nrBegin(t, ctx, db)
		var err error
		if audited {
			_, err = app.RotationStore.DeleteManyForAuditTx(ctx, tx, []string{f.root.String()}, nil)
		} else {
			err = app.RotationStore.DeleteManyTx(ctx, tx, []string{f.root.String()}, nil)
		}
		enforceCode(t, err, ds.DeletionUnavailable)
		require.NoError(t, tx.Rollback())
	}
	require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM rotations WHERE id=$1`, f.root))
	rotationProfileNoSuccess(t, ctx, db)
}
