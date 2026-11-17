package migrate

import (
	"context"
	"database/sql"
	"errors"
	"github.com/target/goalert/notificationchannel"
	"github.com/target/goalert/schedule"
	"github.com/target/goalert/schedule/rotation"
	"github.com/target/goalert/util/timeutil"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/alert/alertlog"
	"github.com/target/goalert/assignment"
	ds "github.com/target/goalert/deletionsafety"
	"github.com/target/goalert/escalation"
	"github.com/target/goalert/gadb"
	"github.com/target/goalert/graphql2"
	"github.com/target/goalert/graphql2/graphqlapp"
	"github.com/target/goalert/notification/nfydest"
	"github.com/target/goalert/permission"
	"github.com/target/goalert/schedule/rule"
	"github.com/target/goalert/user"
)

func updateNativeApp(t *testing.T, ctx context.Context, db *sql.DB) *graphqlapp.App {
	t.Helper()
	app := enforcementApp(t, ctx, db)
	var err error
	app.RuleStore, err = rule.NewStore(ctx, db)
	require.NoError(t, err)
	registry := nfydest.NewRegistry()
	app.DestReg = registry
	registry.RegisterProvider(ctx, app.UserStore)
	registry.RegisterProvider(ctx, app.ScheduleStore)
	registry.RegisterProvider(ctx, app.RotationStore)
	logs, err := alertlog.NewStore(ctx, db, registry)
	require.NoError(t, err)
	app.PolicyStore, err = escalation.NewStore(ctx, db, escalation.Config{Registry: registry, LogStore: logs})
	require.NoError(t, err)
	return app
}

type updateNativeFixture struct {
	epProfileFixture
	kind   string
	policy graphql2.UpdateEscalationPolicyInput
	step   graphql2.UpdateEscalationPolicyStepInput
	target graphql2.ScheduleTargetInput
}

func newUpdateNativeFixture(t *testing.T, ctx context.Context, db *sql.DB, kind string) *updateNativeFixture {
	t.Helper()
	f := &updateNativeFixture{epProfileFixture: newEPProfileFixture(t, ctx, db, true), kind: kind}
	enforcementExec(t, ctx, db, `UPDATE escalation_policies SET name='Synthetic update policy '||id::text WHERE id=$1`, f.epProfileFixture.policy)
	f.policy = graphql2.UpdateEscalationPolicyInput{ID: f.epProfileFixture.policy.String(), StepIDs: []string{}}
	f.step = graphql2.UpdateEscalationPolicyStepInput{ID: f.epProfileFixture.step.String(), Actions: []gadb.DestV1{}}
	id := f.schedule.String()
	target := assignment.NewRawTarget(assignment.UserTarget(f.user.String()))
	f.target = graphql2.ScheduleTargetInput{ScheduleID: &id, Target: &target, Rules: []graphql2.ScheduleRuleInput{}}
	if kind == "U03" {
		for range 2 {
			enforcementExec(t, ctx, db, `INSERT INTO schedule_rules(id,schedule_id,tgt_user_id) VALUES($1,$2,$3)`, uuid.New(), f.schedule, f.user)
		}
		enforcementExec(t, ctx, db, `INSERT INTO schedule_rules(id,schedule_id,tgt_rotation_id) VALUES($1,$2,$3)`, uuid.New(), f.schedule, f.rotation)
	}
	return f
}

func (f *updateNativeFixture) preview(ctx context.Context, app *graphqlapp.App) (*graphql2.UpdateDeletionPreview, error) {
	switch f.kind {
	case "U01":
		return app.Query().PreviewUpdateEscalationPolicy(ctx, f.policy)
	case "U02":
		return app.Query().PreviewUpdateEscalationPolicyStep(ctx, f.step)
	default:
		return app.Query().PreviewUpdateScheduleTarget(ctx, f.target)
	}
}
func (f *updateNativeFixture) mutate(ctx context.Context, app *graphqlapp.App, c *graphql2.DeletionSafetyConfirmationInput) (bool, error) {
	switch f.kind {
	case "U01":
		i := f.policy
		i.Confirmation = c
		return app.Mutation().UpdateEscalationPolicy(ctx, i)
	case "U02":
		i := f.step
		i.Confirmation = c
		return app.Mutation().UpdateEscalationPolicyStep(ctx, i)
	default:
		i := f.target
		i.Confirmation = c
		return app.Mutation().UpdateScheduleTarget(ctx, i)
	}
}
func (f *updateNativeFixture) nondestructive() {
	switch f.kind {
	case "U01":
		f.policy.StepIDs = []string{f.epProfileFixture.step.String()}
		name := "ordinary updated policy"
		f.policy.Name = &name
	case "U02":
		f.step.Actions = []gadb.DestV1{user.DestFromID(f.user.String())}
		delay := 3
		f.step.DelayMinutes = &delay
	default:
		start := timeutil.Clock(8 * time.Hour)
		f.target.Rules = []graphql2.ScheduleRuleInput{{Start: &start}, {}}
	}
}
func updateNativeConfirmation(p *graphql2.UpdateDeletionPreview) *graphql2.DeletionSafetyConfirmationInput {
	return &graphql2.DeletionSafetyConfirmationInput{ExpectedImpactVersion: p.ImpactVersion, AcknowledgeImpacts: true}
}

func updateNativeSnapshot(t *testing.T, ctx context.Context, observer *sql.Conn) string {
	t.Helper()
	var data string
	require.NoError(t, observer.QueryRowContext(ctx, `SELECT jsonb_build_array(
      (SELECT jsonb_agg(to_jsonb(p) ORDER BY id) FROM escalation_policies p),
      (SELECT jsonb_agg(to_jsonb(s) ORDER BY id) FROM escalation_policy_steps s),
      (SELECT jsonb_agg(to_jsonb(a) ORDER BY id) FROM escalation_policy_actions a),
      (SELECT jsonb_agg(to_jsonb(r) ORDER BY id) FROM schedule_rules r),
      (SELECT count(*) FROM escalation_policy_delete_audit_events WHERE record_kind='success_witness'),
      (SELECT COALESCE(sum(jsonb_array_length(effects)),0) FROM escalation_policy_delete_audit_events WHERE record_kind='success_witness'),
      (SELECT count(*) FROM schedule_rotation_delete_audit_events WHERE record_kind='success_witness'),
      (SELECT COALESCE(sum(jsonb_array_length(effects)),0) FROM schedule_rotation_delete_audit_events WHERE record_kind='success_witness'))::text`).Scan(&data))
	return data
}

func TestPostgresUpdateInducedSafetyBusiness(t *testing.T) {
	ctx, _, db := boundedAuditDB(t, len(Names()))
	db.SetMaxOpenConns(12)
	var version string
	require.NoError(t, db.QueryRowContext(ctx, `SHOW server_version`).Scan(&version))
	require.Equal(t, "17.11", version)
	require.Equal(t, 307, enforcementCount(t, ctx, db, `SELECT count(*) FROM gorp_migrations`))
	ctx = permission.SystemContext(ctx, "UpdateInducedSafetyTest")
	app := updateNativeApp(t, ctx, db)
	observer, err := db.Conn(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, observer.Close()) })
	for _, kind := range []string{"U01", "U02", "U03"} {
		t.Run(kind, func(t *testing.T) {
			f := newUpdateNativeFixture(t, ctx, db, kind)
			// Original mutations continue to accept ordinary updates, without confirmation.
			f.nondestructive()
			p, err := f.preview(ctx, app)
			require.NoError(t, err)
			require.False(t, p.RequiresConfirmation)
			require.Empty(t, p.Removed)
			ok, err := f.mutate(ctx, app, nil)
			require.NoError(t, err)
			require.True(t, ok)
			switch kind {
			case "U01":
				var name string
				require.NoError(t, db.QueryRowContext(ctx, `SELECT name FROM escalation_policies WHERE id=$1`, f.epProfileFixture.policy).Scan(&name))
				require.Equal(t, "ordinary updated policy", name)
			case "U02":
				require.Equal(t, 3, enforcementCount(t, ctx, db, `SELECT delay FROM escalation_policy_steps WHERE id=$1`, f.epProfileFixture.step))
			case "U03":
				var first string
				require.NoError(t, db.QueryRowContext(ctx, `SELECT start_time::text FROM schedule_rules WHERE schedule_id=$1 AND tgt_user_id=$2 ORDER BY created_at,id LIMIT 1`, f.schedule, f.user).Scan(&first))
				require.Equal(t, "08:00:00", first)
			}
			auditTable, root := "escalation_policy_delete_audit_events", f.epProfileFixture.policy
			if kind == "U02" {
				root = f.epProfileFixture.step
			}
			if kind == "U03" {
				auditTable = "schedule_rotation_delete_audit_events"
				root = f.schedule
			}
			require.Zero(t, enforcementCount(t, ctx, db, `SELECT count(*) FROM `+auditTable+` WHERE root_id=$1 AND record_kind='success_witness'`, root))
			f.policy.StepIDs = []string{}
			f.step.Actions = []gadb.DestV1{}
			f.target.Rules = []graphql2.ScheduleRuleInput{}
			before := updateNativeSnapshot(t, ctx, observer)
			p, err = f.preview(ctx, app)
			require.NoError(t, err)
			require.True(t, p.CanProceed)
			require.True(t, p.RequiresConfirmation)
			for _, impact := range p.Impacts {
				require.True(t, impact.CanModifyReference)
			}
			want := 1
			if kind != "U02" {
				want = 2
			}
			require.Len(t, p.Removed, want)
			require.Equal(t, before, updateNativeSnapshot(t, ctx, observer), "Preview must be read-only")
			for _, c := range []*graphql2.DeletionSafetyConfirmationInput{nil, {ExpectedImpactVersion: p.ImpactVersion}, {ExpectedImpactVersion: "wrong", AcknowledgeImpacts: true}, {ExpectedImpactVersion: p.ImpactVersion + "tampered", AcknowledgeImpacts: true}} {
				_, err := f.mutate(ctx, app, c)
				require.Error(t, err)
				require.Equal(t, before, updateNativeSnapshot(t, ctx, observer))
			}
			// A different actual update input cannot reuse the confirmation.
			switch kind {
			case "U01":
				name := "different intent"
				f.policy.Name = &name
			case "U02":
				delay := 4
				f.step.DelayMinutes = &delay
			default:
				f.target.Rules = []graphql2.ScheduleRuleInput{{}}
			}
			_, err = f.mutate(ctx, app, updateNativeConfirmation(p))
			enforceCode(t, err, ds.DeletionDependencyChanged)
			require.Equal(t, before, updateNativeSnapshot(t, ctx, observer))
			p, err = f.preview(ctx, app)
			require.NoError(t, err)
			ok, err = f.mutate(ctx, app, updateNativeConfirmation(p))
			require.NoError(t, err)
			require.True(t, ok)
			// The audit's actual UUID set equals the confirmed, deduplicated plan.
			table := "escalation_policy_delete_audit_events"
			root = f.epProfileFixture.policy
			if kind == "U02" {
				root = f.epProfileFixture.step
			}
			if kind == "U03" {
				table = "schedule_rotation_delete_audit_events"
				root = f.schedule
			}
			rows, err := db.QueryContext(ctx, `SELECT e->>'resource_uuid',e->>'provenance' FROM `+table+` a CROSS JOIN LATERAL jsonb_array_elements(a.effects) e WHERE a.root_id=$1 AND a.record_kind='success_witness' ORDER BY e->>'resource_uuid'`, root)
			require.NoError(t, err)
			actual := map[string]string{}
			for rows.Next() {
				var id, source string
				require.NoError(t, rows.Scan(&id, &source))
				require.NotContains(t, actual, id)
				actual[id] = source
			}
			require.NoError(t, rows.Err())
			require.NoError(t, rows.Close())
			require.Len(t, actual, len(p.Removed))
			for _, r := range p.Removed {
				require.Contains(t, actual, r.ID)
			}
			if kind == "U01" {
				require.Equal(t, "EXPLICIT", actual[f.epProfileFixture.step.String()])
				require.Equal(t, "CASCADE", actual[f.action.String()])
			}
			require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM users WHERE id=$1`, f.user))
			require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM schedules WHERE id=$1`, f.schedule))
		})
	}
}

func TestPostgresUpdateInducedSafetyDrift(t *testing.T) {
	ctx, _, db := boundedAuditDB(t, len(Names()))
	ctx = permission.SystemContext(ctx, "UpdateInducedSafetyTest")
	app := updateNativeApp(t, ctx, db)
	for _, kind := range []string{"U01", "U02", "U03"} {
		for _, mode := range []string{"add", "remove", "modify"} {
			t.Run(kind+"/"+mode, func(t *testing.T) {
				f := newUpdateNativeFixture(t, ctx, db, kind)
				p, err := f.preview(ctx, app)
				require.NoError(t, err)
				switch {
				case kind == "U03" && mode == "add":
					enforcementExec(t, ctx, db, `INSERT INTO schedule_rules(id,schedule_id,tgt_user_id) VALUES($1,$2,$3)`, uuid.New(), f.schedule, f.user)
				case kind == "U03" && mode == "remove":
					enforcementExec(t, ctx, db, `DELETE FROM schedule_rules WHERE id=(SELECT id FROM schedule_rules WHERE schedule_id=$1 AND tgt_user_id=$2 ORDER BY created_at,id LIMIT 1)`, f.schedule, f.user)
				case kind == "U03":
					enforcementExec(t, ctx, db, `UPDATE schedule_rules SET start_time='01:00' WHERE schedule_id=$1 AND tgt_user_id=$2`, f.schedule, f.user)
				case mode == "add":
					enforcementExec(t, ctx, db, `INSERT INTO escalation_policy_actions(escalation_policy_step_id,schedule_id) VALUES($1,$2)`, f.epProfileFixture.step, f.schedule)
				case mode == "remove":
					enforcementExec(t, ctx, db, `DELETE FROM escalation_policy_actions WHERE id=$1`, f.action)
				default:
					enforcementExec(t, ctx, db, `UPDATE escalation_policy_actions SET user_id=NULL,schedule_id=$2 WHERE id=$1`, f.action, f.schedule)
				}
				observer, err := db.Conn(ctx)
				require.NoError(t, err)
				defer func() { require.NoError(t, observer.Close()) }()
				before := updateNativeSnapshot(t, ctx, observer)
				_, err = f.mutate(ctx, app, updateNativeConfirmation(p))
				enforceCode(t, err, ds.DeletionDependencyChanged)
				require.Equal(t, before, updateNativeSnapshot(t, ctx, observer))
			})
		}
	}
}

func updateNativeFault(t *testing.T, ctx context.Context, db *sql.DB, f *updateNativeFixture, mode string) {
	t.Helper()
	table := "escalation_policy_delete_audit_events"
	root := f.epProfileFixture.policy
	if f.kind == "U02" {
		root = f.epProfileFixture.step
	}
	if f.kind == "U03" {
		table = "schedule_rotation_delete_audit_events"
		root = f.schedule
	}
	if mode == "detail" {
		enforcementExec(t, ctx, db, `ALTER TABLE `+table+` ADD CONSTRAINT update_safety_detail CHECK(record_kind<>'success_witness' OR root_id<>'`+root.String()+`' OR jsonb_array_length(effects)=0)`)
		t.Cleanup(func() { enforcementExec(t, ctx, db, `ALTER TABLE `+table+` DROP CONSTRAINT update_safety_detail`) })
		return
	}
	timing := "BEFORE INSERT"
	deferred := ""
	condition := `NEW.record_kind='success_witness' AND NEW.root_id='` + root.String() + `'`
	if mode == "commit" {
		timing = "AFTER INSERT"
		deferred = "DEFERRABLE INITIALLY DEFERRED"
	}
	if mode == "write" {
		timing = "BEFORE DELETE"
		deferred = ""
		condition = "true"
		switch f.kind {
		case "U01":
			table = "escalation_policy_steps"
		case "U02":
			table = "escalation_policy_actions"
		default:
			table = "schedule_rules"
		}
	}
	enforcementExec(t, ctx, db, `CREATE FUNCTION update_safety_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF `+condition+` THEN RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='synthetic update safety fault'; END IF; RETURN NEW; END $$`)
	constraint := ""
	if mode == "commit" {
		constraint = "CONSTRAINT "
	}
	enforcementExec(t, ctx, db, `CREATE `+constraint+`TRIGGER update_safety_fault `+timing+` ON `+table+` `+deferred+` FOR EACH ROW EXECUTE FUNCTION update_safety_fault()`)
	t.Cleanup(func() {
		enforcementExec(t, ctx, db, `DROP TRIGGER update_safety_fault ON `+table)
		enforcementExec(t, ctx, db, `DROP FUNCTION update_safety_fault()`)
	})
}

func TestPostgresUpdateInducedSafetyAtomicity(t *testing.T) {
	ctx, _, db := boundedAuditDB(t, len(Names()))
	db.SetMaxOpenConns(12)
	ctx = permission.SystemContext(ctx, "UpdateInducedSafetyTest")
	app := updateNativeApp(t, ctx, db)
	for _, kind := range []string{"U01", "U02", "U03"} {
		for _, mode := range []string{"header", "detail", "commit", "write"} {
			t.Run(kind+"/"+mode, func(t *testing.T) {
				f := newUpdateNativeFixture(t, ctx, db, kind)
				p, err := f.preview(ctx, app)
				require.NoError(t, err)
				updateNativeFault(t, ctx, db, f, mode)
				observer, err := db.Conn(ctx)
				require.NoError(t, err)
				defer func() { require.NoError(t, observer.Close()) }()
				before := updateNativeSnapshot(t, ctx, observer)
				_, err = f.mutate(ctx, app, updateNativeConfirmation(p))
				require.Error(t, err)
				auditTable, root := "escalation_policy_delete_audit_events", f.epProfileFixture.policy
				if kind == "U02" {
					root = f.epProfileFixture.step
				}
				if kind == "U03" {
					auditTable = "schedule_rotation_delete_audit_events"
					root = f.schedule
				}
				var reason string
				require.NoError(t, db.QueryRowContext(ctx, `SELECT reason_code FROM `+auditTable+` WHERE root_id=$1 AND record_kind='attempt_observation' ORDER BY occurred_at DESC LIMIT 1`, root).Scan(&reason))
				want := "audit_write_failed"
				if mode == "commit" {
					want = "commit_rejected"
				}
				if mode == "write" {
					want = "write_failed"
				}
				require.Equal(t, want, reason, "must reach the intended native fault stage")
				require.Equal(t, before, updateNativeSnapshot(t, ctx, observer), "business rows and successful audit must both roll back")
			})
		}
	}
}

func TestPostgresUpdateInducedSafetyBlockAndUnsupported(t *testing.T) {
	ctx, _, db := boundedAuditDB(t, len(Names()))
	ctx = permission.SystemContext(ctx, "UpdateInducedSafetyTest")
	app := updateNativeApp(t, ctx, db)
	for _, mode := range []string{"active", "closed", "history"} {
		t.Run(mode, func(t *testing.T) {
			f := newUpdateNativeFixture(t, ctx, db, "U01")
			if mode == "history" {
				enforcementExec(t, ctx, db, `INSERT INTO ep_step_on_call_users(ep_step_id,user_id,start_time) VALUES($1,$2,now())`, f.epProfileFixture.step, f.user)
			} else {
				service := uuid.New()
				serviceProfileInsert(t, ctx, db, service, f.org, f.epProfileFixture.policy)
				status := "triggered"
				if mode == "closed" {
					status = "closed"
				}
				alert := serviceProfileAlert(t, ctx, db, service, status)
				enforcementExec(t, ctx, db, `INSERT INTO escalation_policy_state(service_id,alert_id,escalation_policy_id,escalation_policy_step_id) VALUES($1,$2,$3,$4) ON CONFLICT(alert_id) DO UPDATE SET escalation_policy_step_id=$4`, service, alert, f.epProfileFixture.policy, f.epProfileFixture.step)
			}
			observer, err := db.Conn(ctx)
			require.NoError(t, err)
			defer func() { require.NoError(t, observer.Close()) }()
			before := updateNativeSnapshot(t, ctx, observer)
			p, err := f.preview(ctx, app)
			if mode == "active" {
				require.NoError(t, err)
				require.False(t, p.CanProceed)
				_, err = f.mutate(ctx, app, updateNativeConfirmation(p))
				enforceCode(t, err, ds.DeletionBlocked)
			} else {
				enforceCode(t, err, ds.DeletionUnavailable)
				_, err = f.mutate(ctx, app, &graphql2.DeletionSafetyConfirmationInput{ExpectedImpactVersion: "guessed", AcknowledgeImpacts: true})
				enforceCode(t, err, ds.DeletionUnavailable)
			}
			require.Equal(t, before, updateNativeSnapshot(t, ctx, observer))
		})
	}
}

func TestPostgresUpdateInducedSafetyCanonicalDiffs(t *testing.T) {
	ctx, _, db := boundedAuditDB(t, len(Names()))
	ctx = permission.SystemContext(ctx, "UpdateInducedSafetyTest")
	app := updateNativeApp(t, ctx, db)
	t.Run("U01_reorder_then_remove", func(t *testing.T) {
		f := newUpdateNativeFixture(t, ctx, db, "U01")
		step, action := uuid.New(), uuid.New()
		enforcementExec(t, ctx, db, `INSERT INTO escalation_policy_steps(id,escalation_policy_id) VALUES($1,$2)`, step, f.epProfileFixture.policy)
		enforcementExec(t, ctx, db, `INSERT INTO escalation_policy_actions(id,escalation_policy_step_id,schedule_id) VALUES($1,$2,$3)`, action, step, f.schedule)
		f.policy.StepIDs = []string{step.String(), f.epProfileFixture.step.String()}
		p, err := f.preview(ctx, app)
		require.NoError(t, err)
		require.Empty(t, p.Removed)
		require.False(t, p.RequiresConfirmation)
		_, err = f.mutate(ctx, app, nil)
		require.NoError(t, err)
		require.Zero(t, enforcementCount(t, ctx, db, `SELECT count(*) FROM escalation_policy_delete_audit_events WHERE root_id=$1 AND record_kind='success_witness'`, f.epProfileFixture.policy))
		f.policy.StepIDs = []string{f.epProfileFixture.step.String()}
		p, err = f.preview(ctx, app)
		require.NoError(t, err)
		require.Len(t, p.Removed, 2)
		got := map[string]bool{}
		for _, r := range p.Removed {
			got[r.ID] = true
		}
		require.True(t, got[step.String()])
		require.True(t, got[action.String()])
		_, err = f.mutate(ctx, app, updateNativeConfirmation(p))
		require.NoError(t, err)
		require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM escalation_policy_actions WHERE id=$1`, f.action))
	})
	t.Run("U02_set_order_duplicates_and_addition", func(t *testing.T) {
		f := newUpdateNativeFixture(t, ctx, db, "U02")
		keep := uuid.New()
		enforcementExec(t, ctx, db, `INSERT INTO escalation_policy_actions(id,escalation_policy_step_id,schedule_id) VALUES($1,$2,$3)`, keep, f.epProfileFixture.step, f.schedule)
		sched := schedule.DestFromID(f.schedule.String())
		added := user.DestFromID(f.actor.String())
		f.step.Actions = []gadb.DestV1{added, sched, sched}
		p, err := f.preview(ctx, app)
		require.NoError(t, err)
		require.Len(t, p.Removed, 1)
		require.Equal(t, f.action.String(), p.Removed[0].ID)
		f.step.Actions = []gadb.DestV1{sched, added, sched}
		reordered, err := f.preview(ctx, app)
		require.NoError(t, err)
		require.Equal(t, p.ImpactVersion, reordered.ImpactVersion)
		_, err = f.mutate(ctx, app, updateNativeConfirmation(p))
		require.NoError(t, err)
		require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM escalation_policy_actions WHERE id=$1`, keep))
		require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM escalation_policy_actions WHERE escalation_policy_step_id=$1 AND user_id=$2`, f.epProfileFixture.step, f.actor))
		require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT jsonb_array_length(effects) FROM escalation_policy_delete_audit_events WHERE root_id=$1 AND record_kind='success_witness'`, f.epProfileFixture.step))
	})
	t.Run("U03_real_positional_ids", func(t *testing.T) {
		f := newUpdateNativeFixture(t, ctx, db, "U03")
		enforcementExec(t, ctx, db, `UPDATE schedule_rules SET created_at='2026-11-01 00:00:00+00' WHERE schedule_id=$1`, f.schedule)
		rows, err := db.QueryContext(ctx, `SELECT id::text FROM schedule_rules WHERE schedule_id=$1 AND tgt_user_id=$2 ORDER BY created_at,id`, f.schedule, f.user)
		require.NoError(t, err)
		var ids []string
		for rows.Next() {
			var id string
			require.NoError(t, rows.Scan(&id))
			ids = append(ids, id)
		}
		require.NoError(t, rows.Err())
		require.NoError(t, rows.Close())
		start := timeutil.Clock(8 * time.Hour)
		f.target.Rules = []graphql2.ScheduleRuleInput{{ID: &ids[1], Start: &start}}
		p, err := f.preview(ctx, app)
		require.NoError(t, err)
		require.Len(t, p.Removed, 1)
		require.Equal(t, ids[1], p.Removed[0].ID)
		_, err = f.mutate(ctx, app, updateNativeConfirmation(p))
		require.NoError(t, err)
		require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM schedule_rules WHERE id=$1 AND start_time='08:00'`, ids[0]))
		require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM schedule_rules WHERE schedule_id=$1 AND tgt_rotation_id=$2`, f.schedule, f.rotation))
	})
}

func TestPostgresUpdateInducedSafetyStateChangeDuringExecution(t *testing.T) {
	ctx, _, db := boundedAuditDB(t, len(Names()))
	ctx = permission.SystemContext(ctx, "UpdateInducedSafetyTest")
	app := updateNativeApp(t, ctx, db)
	for _, kind := range []string{"U01", "U02", "U03"} {
		t.Run(kind, func(t *testing.T) {
			f := newUpdateNativeFixture(t, ctx, db, kind)
			table, condition, change := "escalation_policies", `OLD.id='`+f.epProfileFixture.policy.String()+`'`, `UPDATE escalation_policy_actions SET user_id=NULL,schedule_id='`+f.schedule.String()+`' WHERE id='`+f.action.String()+`';`
			if kind == "U02" {
				table = "escalation_policy_steps"
				condition = `OLD.id='` + f.epProfileFixture.step.String() + `'`
				delay := 3
				f.step.DelayMinutes = &delay
			}
			if kind == "U03" {
				f.target.Rules = []graphql2.ScheduleRuleInput{{}}
				var first, last string
				require.NoError(t, db.QueryRowContext(ctx, `SELECT min(id::text),max(id::text) FROM schedule_rules WHERE schedule_id=$1 AND tgt_user_id=$2`, f.schedule, f.user).Scan(&first, &last))
				enforcementExec(t, ctx, db, `UPDATE schedule_rules SET created_at='2026-11-01 00:00:00+00' WHERE schedule_id=$1`, f.schedule)
				table = "schedule_rules"
				condition = `OLD.id='` + first + `'`
				change = `UPDATE schedule_rules SET tgt_user_id=NULL,tgt_rotation_id='` + f.rotation.String() + `' WHERE id='` + last + `';`
			}
			p, err := f.preview(ctx, app)
			require.NoError(t, err)
			enforcementExec(t, ctx, db, `CREATE FUNCTION update_safety_change() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN `+change+` RETURN NEW; END $$`)
			enforcementExec(t, ctx, db, `CREATE TRIGGER update_safety_change BEFORE UPDATE ON `+table+` FOR EACH ROW WHEN (`+condition+`) EXECUTE FUNCTION update_safety_change()`)
			t.Cleanup(func() {
				enforcementExec(t, ctx, db, `DROP TRIGGER update_safety_change ON `+table)
				enforcementExec(t, ctx, db, `DROP FUNCTION update_safety_change()`)
			})
			observer, err := db.Conn(ctx)
			require.NoError(t, err)
			defer func() { require.NoError(t, observer.Close()) }()
			before := updateNativeSnapshot(t, ctx, observer)
			_, err = f.mutate(ctx, app, updateNativeConfirmation(p))
			enforceCode(t, err, ds.DeletionDependencyChanged)
			require.Equal(t, before, updateNativeSnapshot(t, ctx, observer))
		})
	}
}

func TestPostgresUpdateInducedSafetyStoreBypass(t *testing.T) {
	ctx, _, db := boundedAuditDB(t, len(Names()))
	ctx = permission.SystemContext(ctx, "UpdateInducedSafetyTest")
	app := updateNativeApp(t, ctx, db)
	f := newUpdateNativeFixture(t, ctx, db, "U03")
	observer, err := db.Conn(ctx)
	require.NoError(t, err)
	defer func() { require.NoError(t, observer.Close()) }()
	before := updateNativeSnapshot(t, ctx, observer)
	var ruleID string
	require.NoError(t, db.QueryRowContext(ctx, `SELECT id::text FROM schedule_rules WHERE schedule_id=$1 AND tgt_user_id=$2 LIMIT 1`, f.schedule, f.user).Scan(&ruleID))
	for _, entry := range []struct {
		name string
		call func(*sql.Tx) error
	}{
		{"step_legacy", func(tx *sql.Tx) error {
			_, e := app.PolicyStore.DeleteStepTx(ctx, tx, f.epProfileFixture.step)
			return e
		}},
		{"step_receipt", func(tx *sql.Tx) error {
			_, e := app.PolicyStore.DeleteStepReceiptTx(ctx, tx, f.epProfileFixture.step)
			return e
		}},
		{"action_legacy", func(tx *sql.Tx) error {
			return app.PolicyStore.DeleteStepActionTx(ctx, tx, f.epProfileFixture.step, user.DestFromID(f.user.String()))
		}},
		{"action_receipt", func(tx *sql.Tx) error {
			_, e := app.PolicyStore.DeleteStepActionReceiptTx(ctx, tx, f.epProfileFixture.step, user.DestFromID(f.user.String()))
			return e
		}},
		{"rule_legacy", func(tx *sql.Tx) error { return app.RuleStore.DeleteManyTx(ctx, tx, []string{ruleID}) }},
		{"rule_receipt", func(tx *sql.Tx) error {
			_, e := app.RuleStore.DeleteManyReceiptTx(ctx, tx, f.schedule.String(), assignment.UserTarget(f.user.String()), []string{ruleID})
			return e
		}},
	} {
		t.Run(entry.name, func(t *testing.T) {
			tx, err := db.BeginTx(ctx, nil)
			require.NoError(t, err)
			enforceCode(t, entry.call(tx), ds.DeletionUnavailable)
			require.NoError(t, tx.Rollback())
			require.Equal(t, before, updateNativeSnapshot(t, ctx, observer))
		})
	}
}

func TestPostgresUpdateInducedSafetyInitialCreationCompatibility(t *testing.T) {
	ctx, _, db := boundedAuditDB(t, len(Names()))
	app := updateNativeApp(t, permission.SystemContext(ctx, "UpdateInducedSafetyTest"), db)
	f := newUpdateNativeFixture(t, ctx, db, "U03")
	enforcementExec(t, ctx, db, `UPDATE normal_organizations SET iana_time_zone='Etc/UTC' WHERE organization_id=$1`, f.org)
	human := previewAdmit(t, ctx, db, f.actor)
	target := assignment.NewRawTarget(assignment.UserTarget(f.user.String()))
	created, err := app.Mutation().CreateSchedule(human, graphql2.CreateScheduleInput{Name: "Synthetic initial target " + uuid.NewString(), TimeZone: "UTC", Targets: []graphql2.ScheduleTargetInput{
		{Target: &target, Rules: []graphql2.ScheduleRuleInput{{}}},
	}})
	require.NoError(t, err)
	require.NotNil(t, created)
	require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM schedule_rules WHERE schedule_id=$1`, created.ID))
	require.Zero(t, enforcementCount(t, ctx, db, `SELECT count(*) FROM schedule_rotation_delete_audit_events WHERE root_id=$1`, created.ID), "initial configuration must not invent an Update-induced deletion event")
}

func TestPostgresUpdateInducedSafetyTransientFailureNoReplay(t *testing.T) {
	ctx, _, db := boundedAuditDB(t, len(Names()))
	ctx = permission.SystemContext(ctx, "UpdateInducedSafetyTest")
	app := updateNativeApp(t, ctx, db)
	for _, state := range []string{"40001", "40P01"} {
		t.Run(state, func(t *testing.T) {
			f := newUpdateNativeFixture(t, ctx, db, "U02")
			p, err := f.preview(ctx, app)
			require.NoError(t, err)
			enforcementExec(t, ctx, db, `CREATE SEQUENCE update_safety_attempts`)
			enforcementExec(t, ctx, db, `CREATE FUNCTION update_safety_transient() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM nextval('update_safety_attempts'); RAISE EXCEPTION USING ERRCODE='`+state+`',MESSAGE='synthetic transient write failure'; END $$`)
			enforcementExec(t, ctx, db, `CREATE TRIGGER update_safety_transient BEFORE DELETE ON escalation_policy_actions FOR EACH ROW EXECUTE FUNCTION update_safety_transient()`)
			t.Cleanup(func() { enforcementExec(t, ctx, db, `DROP SEQUENCE update_safety_attempts`) })
			_, err = f.mutate(ctx, app, updateNativeConfirmation(p))
			require.Error(t, err)
			var safety *ds.DeletionSafetyError
			require.False(t, errors.As(err, &safety), "a transaction fault must not become a business BLOCK")
			require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT last_value FROM update_safety_attempts`), "no blind internal replay of a failed update")
			require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM escalation_policy_actions WHERE id=$1`, f.action))
			require.Zero(t, enforcementCount(t, ctx, db, `SELECT count(*) FROM escalation_policy_delete_audit_events WHERE root_id=$1 AND record_kind='success_witness'`, f.epProfileFixture.step))
			enforcementExec(t, ctx, db, `DROP TRIGGER update_safety_transient ON escalation_policy_actions`)
			enforcementExec(t, ctx, db, `DROP FUNCTION update_safety_transient()`)
			// This is a new request after the abort. It must recheck the real state;
			// the old signed consent is usable only because that state is identical.
			_, err = f.mutate(ctx, app, updateNativeConfirmation(p))
			require.NoError(t, err)
			require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM escalation_policy_delete_audit_events WHERE root_id=$1 AND record_kind='success_witness'`, f.epProfileFixture.step))
		})
	}
}

func TestPostgresUpdateInducedSafetyUnsupportedScope(t *testing.T) {
	ctx, _, db := boundedAuditDB(t, len(Names()))
	system := permission.SystemContext(ctx, "UpdateInducedSafetyTest")
	app := updateNativeApp(t, system, db)
	t.Run("U02_channel_system_and_human_boundary", func(t *testing.T) {
		f := newUpdateNativeFixture(t, ctx, db, "U02")
		channel, action := uuid.New(), uuid.New()
		dest := gadb.DestV1{Type: "synthetic-channel", Args: map[string]string{"synthetic_id": channel.String()}}
		enforcementExec(t, ctx, db, `DELETE FROM escalation_policy_actions WHERE id=$1`, f.action)
		enforcementExec(t, ctx, db, `INSERT INTO notification_channels(id,name,type,value,dest) VALUES($1,'Synthetic channel','WEBHOOK','synthetic',$2)`, channel, gadb.NullDestV1{Valid: true, DestV1: dest})
		enforcementExec(t, ctx, db, `INSERT INTO escalation_policy_actions(id,escalation_policy_step_id,channel_id) VALUES($1,$2,$3)`, action, f.epProfileFixture.step, channel)
		registry := nfydest.NewRegistry()
		nc, err := notificationchannel.NewStore(system, db, registry)
		require.NoError(t, err)
		logs, err := alertlog.NewStore(system, db, registry)
		require.NoError(t, err)
		local := *app
		local.PolicyStore, err = escalation.NewStore(system, db, escalation.Config{Registry: registry, NCStore: nc, LogStore: logs})
		require.NoError(t, err)
		human := previewAdmit(t, ctx, db, f.actor)
		_, err = f.preview(human, &local)
		enforceCode(t, err, ds.DeletionUnavailable)
		_, err = f.mutate(human, &local, &graphql2.DeletionSafetyConfirmationInput{ExpectedImpactVersion: "guessed", AcknowledgeImpacts: true})
		enforceCode(t, err, ds.DeletionUnavailable)
		require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM escalation_policy_actions WHERE id=$1`, action))
		p, err := f.preview(system, &local)
		require.NoError(t, err)
		require.Len(t, p.Removed, 1)
		_, err = f.mutate(system, &local, updateNativeConfirmation(p))
		require.NoError(t, err)
		require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM notification_channels WHERE id=$1`, channel))
	})
	t.Run("U03_foreign_historical_target", func(t *testing.T) {
		f := newUpdateNativeFixture(t, ctx, db, "U03")
		foreign := newEPProfileFixture(t, ctx, db, false)
		enforcementExec(t, ctx, db, `INSERT INTO schedule_rules(id,schedule_id,tgt_user_id) VALUES($1,$2,$3)`, uuid.New(), f.schedule, foreign.user)
		target := assignment.NewRawTarget(assignment.UserTarget(foreign.user.String()))
		f.target.Target = &target
		human := previewAdmit(t, ctx, db, f.actor)
		_, err := f.preview(human, app)
		enforceCode(t, err, ds.DeletionUnavailable)
		_, err = f.mutate(human, app, &graphql2.DeletionSafetyConfirmationInput{ExpectedImpactVersion: "guessed", AcknowledgeImpacts: true})
		enforceCode(t, err, ds.DeletionUnavailable)
		require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM schedule_rules WHERE schedule_id=$1 AND tgt_user_id=$2`, f.schedule, foreign.user))
	})
}

func TestPostgresUpdateInducedSafetyDesiredTargets(t *testing.T) {
	base, _, db := boundedAuditDB(t, len(Names()))
	ctx := permission.SystemContext(base, "UpdateInducedSafetyTest")
	app := updateNativeApp(t, ctx, db)
	for _, mode := range []string{"missing", "foreign", "unregistered", "state_changed", "valid_user", "valid_schedule", "valid_rotation"} {
		t.Run(mode, func(t *testing.T) {
			f := newUpdateNativeFixture(t, ctx, db, "U02")
			human := previewAdmit(t, base, db, f.actor)
			caller := ctx
			switch mode {
			case "missing":
				f.step.Actions = []gadb.DestV1{user.DestFromID(uuid.NewString())}
			case "foreign":
				other := newEPProfileFixture(t, ctx, db, false)
				f.step.Actions = []gadb.DestV1{user.DestFromID(other.user.String())}
				caller = human
			case "unregistered":
				f.step.Actions = []gadb.DestV1{{Type: "synthetic-unregistered", Args: map[string]string{}}}
			case "valid_user":
				f.step.Actions = []gadb.DestV1{user.DestFromID(f.actor.String())}
				caller = human
			case "valid_schedule":
				f.step.Actions = []gadb.DestV1{schedule.DestFromID(f.schedule.String())}
				caller = human
			case "valid_rotation":
				f.step.Actions = []gadb.DestV1{rotation.DestFromID(f.rotation.String())}
				caller = human
			default:
				f.step.Actions = []gadb.DestV1{user.DestFromID(f.actor.String())}
			}
			if strings.HasPrefix(mode, "valid_") {
				p, err := f.preview(caller, app)
				require.NoError(t, err)
				require.True(t, p.CanProceed)
				_, err = f.mutate(caller, app, updateNativeConfirmation(p))
				require.NoError(t, err)
				require.Zero(t, enforcementCount(t, ctx, db, `SELECT count(*) FROM escalation_policy_actions WHERE id=$1`, f.action))
				require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM escalation_policy_actions WHERE escalation_policy_step_id=$1`, f.epProfileFixture.step))
				require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM escalation_policy_delete_audit_events WHERE root_id=$1 AND record_kind='success_witness'`, f.epProfileFixture.step))
				return
			}
			if mode == "state_changed" {
				p, err := f.preview(caller, app)
				require.NoError(t, err)
				enforcementExec(t, ctx, db, `UPDATE user_organization_assignments SET organization_role='ORG_MEMBER' WHERE user_id=$1`, f.actor)
				_, err = f.mutate(caller, app, updateNativeConfirmation(p))
				enforceCode(t, err, ds.DeletionDependencyChanged)
			} else {
				_, err := f.preview(caller, app)
				enforceCode(t, err, ds.DeletionUnavailable)
				_, err = f.mutate(caller, app, nil)
				enforceCode(t, err, ds.DeletionUnavailable)
			}
			require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM escalation_policy_actions WHERE id=$1`, f.action))
			require.Zero(t, enforcementCount(t, ctx, db, `SELECT count(*) FROM escalation_policy_delete_audit_events WHERE root_id=$1 AND record_kind='success_witness'`, f.epProfileFixture.step))
		})
	}
}
