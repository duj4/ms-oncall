package migrate

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/assignment"
	"github.com/target/goalert/config"
	ds "github.com/target/goalert/deletionsafety"
	collector "github.com/target/goalert/deletionsafety/postgres"
	"github.com/target/goalert/escalation"
	"github.com/target/goalert/graphql2"
	"github.com/target/goalert/graphql2/graphqlapp"
	"github.com/target/goalert/integrationkey"
	guard "github.com/target/goalert/internal/deletionguard"
	"github.com/target/goalert/override"
	"github.com/target/goalert/permission"
	"github.com/target/goalert/schedule"
	"github.com/target/goalert/schedule/rotation"
	"github.com/target/goalert/service"
	"github.com/target/goalert/user"
	"github.com/target/goalert/user/contactmethod"
	"github.com/target/goalert/user/notificationrule"
)

func enforcementApp(t *testing.T, ctx context.Context, db *sql.DB) *graphqlapp.App {
	t.Helper()
	svc, err := service.NewStore(ctx, db)
	require.NoError(t, err)
	ep, err := escalation.NewStore(ctx, db, escalation.Config{})
	require.NoError(t, err)
	sched, err := schedule.NewStore(ctx, db, nil)
	require.NoError(t, err)
	rot, err := rotation.NewStore(ctx, db)
	require.NoError(t, err)
	uo, err := override.NewStore(ctx, db)
	require.NoError(t, err)
	nr, err := notificationrule.NewStore(ctx, db)
	require.NoError(t, err)
	return &graphqlapp.App{DB: db, PreviewSigner: previewNativeSigner{}, ServiceStore: svc, PolicyStore: ep, ScheduleStore: sched, RotationStore: rot, OverrideStore: uo, NRStore: nr, CMStore: contactmethod.NewStore(nil), IntKeyStore: integrationkey.NewStore(ctx, db, nil, nil, nil), UserStore: &user.Store{}}
}
func enforceCode(t *testing.T, err error, code ds.ErrorCode) {
	t.Helper()
	var typed *ds.DeletionSafetyError
	require.ErrorAs(t, err, &typed)
	require.Equal(t, code, typed.Code)
}
func enforcementPreview(t *testing.T, ctx context.Context, app *graphqlapp.App, targets ...graphql2.DeletionResourceInput) *graphql2.DeletionSafetyConfirmationInput {
	t.Helper()
	p, err := app.Query().DeletionPreview(ctx, graphql2.DeletionPlanInput{Operation: graphql2.DeletionOperationDeleteResources, Targets: targets}, nil, nil)
	require.NoError(t, err)
	return &graphql2.DeletionSafetyConfirmationInput{ExpectedImpactVersion: p.ImpactVersion, AcknowledgeImpacts: true}
}
func enforcementCount(t *testing.T, ctx context.Context, db *sql.DB, q string, args ...any) int {
	t.Helper()
	var n int
	require.NoError(t, db.QueryRowContext(ctx, q, args...).Scan(&n))
	return n
}
func enforcementExec(t *testing.T, ctx context.Context, db *sql.DB, q string, args ...any) {
	t.Helper()
	_, err := db.ExecContext(ctx, q, args...)
	require.NoError(t, err)
}

func enforcementHTTP(t *testing.T, ctx context.Context, app *graphqlapp.App, input []assignment.RawTarget, confirm *graphql2.DeletionSafetyConfirmationInput, legacy bool) string {
	t.Helper()
	targets := make([]map[string]any, len(input))
	for i, r := range input {
		typ, err := r.Type.MarshalText()
		require.NoError(t, err)
		targets[i] = map[string]any{"type": string(typ), "id": r.ID}
	}
	query := `mutation($input:[TargetInput!],$confirmation:DeletionSafetyConfirmationInput){deleteAll(input:$input,confirmation:$confirmation)}`
	if legacy {
		query = `mutation($input:[TargetInput!]){deleteAll(input:$input)}`
	}
	payload, err := json.Marshal(map[string]any{"query": query, "variables": map[string]any{"input": targets, "confirmation": confirm}})
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/graphql", bytes.NewReader(payload)).WithContext((config.Config{}).Context(ctx))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	app.Handler().ServeHTTP(w, req)
	require.NotContains(t, w.Body.String(), "SYNTHETIC_PRIVATE")
	return w.Body.String()
}

func nrSelectors(ids ...uuid.UUID) []collector.Selector {
	out := make([]collector.Selector, len(ids))
	for i, id := range ids {
		out[i] = collector.Selector{Kind: ds.ResourceNotificationRule, ID: id.String()}
	}
	return out
}
func nrInput(ids ...uuid.UUID) []assignment.RawTarget {
	out := make([]assignment.RawTarget, len(ids))
	for i, id := range ids {
		out[i] = assignment.RawTarget{Type: assignment.TargetTypeNotificationRule, ID: id.String()}
	}
	return out
}
func nrRoot(id uuid.UUID) ds.Resource {
	return ds.Resource{Kind: ds.ResourceNotificationRule, ID: id.String()}
}
func nrVersion(t *testing.T, ctx context.Context, db *sql.DB, id uuid.UUID) string {
	t.Helper()
	result, err := collectDeletion(t, ctx, db, nrRoot(id), collector.Limits{})
	require.NoError(t, err)
	return deletionPlan(t, nrRoot(id), result).ImpactVersion()
}
func nrBegin(t *testing.T, ctx context.Context, db *sql.DB) *sql.Tx {
	t.Helper()
	tx, err := db.BeginTx(ctx, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = tx.Rollback() })
	_, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(1297305411,1396979713)`)
	require.NoError(t, err)
	return tx
}
func nrEnforce(t *testing.T, ctx context.Context, tx *sql.Tx, id uuid.UUID, version string) context.Context {
	t.Helper()
	bound, err := collector.Enforce(ctx, tx, nrSelectors(id), version, true, authorizeDeletionFixture(nrRoot(id)))
	require.NoError(t, err)
	return bound
}
func nrSibling(t *testing.T, ctx context.Context, db *sql.DB, f deletionFixture, delay int) (uuid.UUID, uuid.UUID) {
	t.Helper()
	cm, nr := uuid.New(), uuid.New()
	enforcementExec(t, ctx, db, `INSERT INTO user_contact_methods(id,user_id,name,type,value,dest,pending) VALUES($1,$2,($1::uuid)::text,'WEBHOOK',($1::uuid)::text,jsonb_build_object('type','synthetic','id',($1::uuid)::text),false)`, cm, f.user)
	enforcementExec(t, ctx, db, `INSERT INTO user_notification_rules(id,user_id,contact_method_id,delay_minutes) VALUES($1,$2,$3,$4)`, nr, f.user, cm, delay)
	return cm, nr
}
func nrNoSuccess(t *testing.T, ctx context.Context, db *sql.DB) {
	t.Helper()
	require.Zero(t, enforcementCount(t, ctx, db, `SELECT count(*) FROM user_cmnr_delete_audit_events WHERE outcome='committed'`))
}

func TestPostgresDeletionEnforcementNRBusiness(t *testing.T) {
	ctx, _, db := boundedAuditDB(t, len(Names()))
	f := newDeletionFixture(t, ctx, db)
	ctx = permission.SystemContext(ctx, "NRProofTest")
	app := enforcementApp(t, ctx, db)
	input := nrInput(f.nr)
	require.Contains(t, enforcementHTTP(t, ctx, app, input, nil, true), string(ds.DeletionConfirmationRequired))
	confirm := enforcementPreview(t, ctx, app, graphql2.DeletionResourceInput{Type: graphql2.DeletionTargetTypeNotificationRule, ID: f.nr.String()})
	stale := *confirm
	stale.ExpectedImpactVersion = "stale"
	require.Contains(t, enforcementHTTP(t, ctx, app, input, &stale, false), string(ds.DeletionDependencyChanged))
	nrNoSuccess(t, ctx, db)
	ok, err := app.Mutation().DeleteAll(ctx, input, confirm)
	require.NoError(t, err)
	require.True(t, ok)
	require.Zero(t, enforcementCount(t, ctx, db, `SELECT count(*) FROM user_notification_rules WHERE id=$1`, f.nr))
	require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM user_contact_methods WHERE id=$1`, f.cm))
	require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM user_cmnr_delete_audit_events WHERE outcome='committed' AND provenance='EXPLICIT'`))
	// Existing Missing no-op and actual stale version semantics.
	ok, err = app.Mutation().DeleteAll(ctx, input, nil)
	require.NoError(t, err)
	require.True(t, ok)
	_, err = app.Mutation().DeleteAll(ctx, input, confirm)
	enforceCode(t, err, ds.DeletionDependencyChanged)
	require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM user_cmnr_delete_audit_events WHERE outcome='committed'`))
	// Multi-NR, duplicate raw selector and Missing ID: exactly two receipts.
	f = newDeletionFixture(t, ctx, db)
	_, second := nrSibling(t, ctx, db, f, 3)
	confirm = enforcementPreview(t, ctx, app, graphql2.DeletionResourceInput{Type: graphql2.DeletionTargetTypeNotificationRule, ID: f.nr.String()}, graphql2.DeletionResourceInput{Type: graphql2.DeletionTargetTypeNotificationRule, ID: second.String()})
	ok, err = app.Mutation().DeleteAll(ctx, nrInput(f.nr, f.nr, second, uuid.New()), confirm)
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, 3, enforcementCount(t, ctx, db, `SELECT count(*) FROM user_cmnr_delete_audit_events WHERE outcome='committed' AND provenance='EXPLICIT'`))
	// INFORMATIONAL remains executable without confirmation.
	f = newDeletionFixture(t, ctx, db)
	enforcementExec(t, ctx, db, `DELETE FROM notification_policy_cycles WHERE user_id=$1`, f.user)
	enforcementExec(t, ctx, db, `UPDATE user_notification_rules SET delay_minutes=5 WHERE id=$1`, f.nr)
	ok, err = app.Mutation().DeleteAll(ctx, nrInput(f.nr), nil)
	require.NoError(t, err)
	require.True(t, ok)
	// Duplicates count before normalization; malformed inputs keep validation errors.
	many := make([]assignment.RawTarget, 51)
	for i := range many {
		many[i] = nrInput(f.nr)[0]
	}
	_, err = app.Mutation().DeleteAll(ctx, many, nil)
	require.Error(t, err)
	require.NotEqual(t, string(ds.DeletionUnavailable), err.Error())
	_, err = app.Mutation().DeleteAll(ctx, []assignment.RawTarget{{Type: assignment.TargetTypeNotificationRule, ID: "invalid"}}, nil)
	require.Error(t, err)
}

func TestPostgresDeletionEnforcementNRFailClosed(t *testing.T) {
	ctx, _, db := boundedAuditDB(t, len(Names()))
	f := newDeletionFixture(t, ctx, db)
	ctx = permission.SystemContext(ctx, "NRProofTest")
	app := enforcementApp(t, ctx, db)
	roots := []assignment.RawTarget{
		{Type: assignment.TargetTypeUser, ID: f.user.String()},
		{Type: assignment.TargetTypeService, ID: f.service.String()},
		{Type: assignment.TargetTypeEscalationPolicy, ID: f.policy.String()},
		{Type: assignment.TargetTypeSchedule, ID: f.schedule.String()},
		{Type: assignment.TargetTypeRotation, ID: f.rotation.String()},
		{Type: assignment.TargetTypeContactMethod, ID: f.cm.String()},
		{Type: assignment.TargetTypeIntegrationKey, ID: f.key.String()},
		{Type: assignment.TargetTypeUserOverride, ID: f.override.String()},
		{Type: assignment.TargetTypeUserSession, ID: f.session.String()},
		{Type: assignment.TargetTypeCalendarSubscription, ID: uuid.NewString()},
		{Type: assignment.TargetTypeHeartbeatMonitor, ID: uuid.NewString()},
	}
	before := deletionSnapshot(t, ctx, db)
	for _, root := range roots {
		batches := [][]assignment.RawTarget{append(nrInput(f.nr), root)}
		// Pure Session revocation uses SD9; the NR + Session batch stays rejected.
		if root.Type != assignment.TargetTypeContactMethod && root.Type != assignment.TargetTypeService && root.Type != assignment.TargetTypeEscalationPolicy && root.Type != assignment.TargetTypeUserSession {
			batches = append(batches, []assignment.RawTarget{root})
		}
		for _, batch := range batches {
			ok, err := app.Mutation().DeleteAll(ctx, batch, &graphql2.DeletionSafetyConfirmationInput{ExpectedImpactVersion: "guessed", AcknowledgeImpacts: true})
			require.False(t, ok)
			expected := ds.DeletionUnavailable
			if len(batch) == 1 && root.Type == assignment.TargetTypeRotation {
				expected = ds.DeletionBlocked // Complete Rotation closure retains its real external blockers.
			}
			if len(batch) == 1 && (root.Type == assignment.TargetTypeUserOverride || root.Type == assignment.TargetTypeIntegrationKey) {
				expected = ds.DeletionDependencyChanged // Native roots reject the guessed version.
			}
			enforceCode(t, err, expected)
		}
	}
	for _, batch := range [][]assignment.RawTarget{{roots[1], roots[2]}, {roots[3], roots[4]}, {roots[0], roots[5], nrInput(f.nr)[0]}, {roots[4], roots[2]}} {
		ok, err := app.Mutation().DeleteAll(ctx, batch, nil)
		require.False(t, ok)
		enforceCode(t, err, ds.DeletionUnavailable)
	}
	// Unsupported status bundle / Universal / Calendar do not enable a root.
	enforcementExec(t, ctx, db, `INSERT INTO labels(key,value,tgt_schedule_id) VALUES('synthetic','unsupported',$1)`, f.schedule)
	_, err := app.Mutation().DeleteAll(ctx, []assignment.RawTarget{roots[3]}, nil)
	enforceCode(t, err, ds.DeletionUnavailable)
	after := deletionSnapshot(t, ctx, db)
	for table, hash := range before {
		if !strings.Contains(table, "audit") && table != "labels" {
			require.Equal(t, hash, after[table], table)
		}
	}
	nrNoSuccess(t, ctx, db)
	// All legacy and audited root Stores retain their Guard, even under System.
	tx := nrBegin(t, ctx, db)
	for name, call := range map[string]func() error{
		"service":  func() error { return app.ServiceStore.DeleteManyTx(ctx, tx, []string{f.service.String()}, nil) },
		"policy":   func() error { return app.PolicyStore.DeleteManyPoliciesTx(ctx, tx, []string{f.policy.String()}, nil) },
		"schedule": func() error { return app.ScheduleStore.DeleteManyTx(ctx, tx, []string{f.schedule.String()}, nil) },
		"rotation": func() error { return app.RotationStore.DeleteManyTx(ctx, tx, []string{f.rotation.String()}, nil) },
		"cm":       func() error { return app.CMStore.Delete(ctx, tx, f.cm.String()) },
		"nr":       func() error { return app.NRStore.DeleteTx(ctx, tx, f.nr.String()) },
		"key":      func() error { return app.IntKeyStore.DeleteMany(ctx, tx, []string{f.key.String()}, nil) },
		"override": func() error { return app.OverrideStore.DeleteUserOverrideTx(ctx, tx, f.override.String()) },
		"user":     func() error { return app.UserStore.DeleteManyTx(ctx, tx, []string{f.user.String()}) },
	} {
		t.Run(name, func(t *testing.T) { enforceCode(t, call(), ds.DeletionUnavailable) })
	}
	require.NoError(t, tx.Rollback())
	// Read-only Preview still supports non-NR roots, including an unbypassable BLOCK.
	p, err := app.Query().DeletionPreview(ctx, previewInput(graphql2.DeletionTargetTypeService, f.service), nil, nil)
	require.NoError(t, err)
	require.False(t, p.CanProceed)
}

func TestPostgresDeletionEnforcementNRGuardLifecycle(t *testing.T) {
	nativeGuardLifecycle(t, ds.ResourceNotificationRule)
}

func nativeGuardLifecycle(t *testing.T, kind ds.ResourceKind) {
	ctx, _, db := boundedAuditDB(t, len(Names()))
	f := newDeletionFixture(t, ctx, db)
	ctx = permission.SystemContext(ctx, "NRProofTest")
	id := f.nr
	stabilize := guard.StabilizeNR
	wrongKind := ds.ResourceContactMethod
	if kind == ds.ResourceContactMethod {
		id = f.cm
		stabilize = guard.StabilizeCM
		wrongKind = ds.ResourceNotificationRule
	}
	root := ds.Resource{Kind: kind, ID: id.String()}
	raw := []collector.Selector{{Kind: kind, ID: id.String()}}
	facts, err := collectDeletion(t, ctx, db, root, collector.Limits{})
	require.NoError(t, err)
	version := deletionPlan(t, root, facts).ImpactVersion()
	app := enforcementApp(t, ctx, db)
	deleteOne := app.NRStore.DeleteForAuditTx
	if kind == ds.ResourceContactMethod {
		deleteOne = app.CMStore.DeleteForAuditTx
	}
	enforce := func(tx *sql.Tx) context.Context {
		carrier, err := collector.Enforce(ctx, tx, raw, version, true, authorizeDeletionFixture(root))
		require.NoError(t, err)
		return carrier
	}
	for _, phase := range []string{"before_locks", "after_locks_before_witness", "after_witness"} {
		t.Run(phase, func(t *testing.T) {
			tx := nrBegin(t, ctx, db)
			if phase == "before_locks" {
				_, err := tx.ExecContext(ctx, `SAVEPOINT checkpoint`)
				require.NoError(t, err)
			}
			checked, targets, err := stabilize(ctx, tx, raw)
			require.NoError(t, err)
			require.Equal(t, []ds.Resource{root}, targets)
			var certified int
			require.NoError(t, tx.QueryRowContext(ctx, `SELECT count(*) FROM pg_temp.d09_nr_deletion_witness WHERE phase='certified'`).Scan(&certified))
			require.Zero(t, certified)
			if phase == "after_locks_before_witness" {
				_, err = tx.ExecContext(ctx, `SAVEPOINT checkpoint`)
				require.NoError(t, err)
			}
			facts, err := collector.Collect(checked, tx, root, collector.Recheck, collector.Limits{}, authorizeDeletionFixture(root))
			require.NoError(t, err)
			plan := deletionPlan(t, root, facts)
			carrier, err := guard.Bind(ctx, tx, checked, raw, plan, version, true)
			require.NoError(t, err)
			if phase == "after_witness" {
				_, err = tx.ExecContext(ctx, `SAVEPOINT checkpoint`)
				require.NoError(t, err)
			}
			_, err = tx.ExecContext(ctx, `ROLLBACK TO SAVEPOINT checkpoint`)
			require.NoError(t, err)
			if phase == "after_witness" {
				// Locks precede the savepoint and remain held. Witness is still valid.
				result, err := deleteOne(carrier, tx, id.String())
				require.NoError(t, err)
				require.Len(t, result.Targets, 1)
				require.True(t, result.Targets[0].Deleted)
			} else {
				_, err := deleteOne(carrier, tx, id.String())
				enforceCode(t, err, ds.DeletionUnavailable)
				// Re-binding the SAME stability/nonce is forbidden, even if SQL rollback
				// removed its final row while retaining its locked checkpoint.
				_, err = guard.Bind(ctx, tx, checked, raw, plan, version, true)
				enforceCode(t, err, ds.DeletionUnavailable)
				fresh := enforce(tx)
				_, err = deleteOne(carrier, tx, id.String())
				enforceCode(t, err, ds.DeletionUnavailable)
				result, err := deleteOne(fresh, tx, id.String())
				require.NoError(t, err)
				require.Len(t, result.Targets, 1)
			}
			require.NoError(t, tx.Rollback())
		})
	}
	tx := nrBegin(t, ctx, db)
	old := enforce(tx)
	_, err = tx.ExecContext(ctx, `SAVEPOINT old_generation`)
	require.NoError(t, err)
	newer := enforce(tx)
	_, err = tx.ExecContext(ctx, `ROLLBACK TO SAVEPOINT old_generation`)
	require.NoError(t, err)
	// The old SQL witness still exists; monotonic revocation prevents resurrection.
	enforceCode(t, guard.RequireDelete(old, tx, kind, []string{id.String()}), ds.DeletionUnavailable)
	enforceCode(t, guard.RequireDelete(newer, tx, kind, []string{id.String()}), ds.DeletionUnavailable)
	current := enforce(tx)
	other, err := db.BeginTx(ctx, nil)
	require.NoError(t, err)
	enforceCode(t, guard.RequireDelete(current, other, kind, []string{id.String()}), ds.DeletionUnavailable)
	require.NoError(t, other.Rollback())
	enforceCode(t, guard.RequireDelete(current, tx, kind, []string{uuid.NewString()}), ds.DeletionUnavailable)
	enforceCode(t, guard.RequireDelete(current, tx, wrongKind, []string{id.String()}), ds.DeletionUnavailable)
	type forgedProfile struct{}
	fake := context.WithValue(ctx, forgedProfile{}, "notification-rule-only-v1")
	enforceCode(t, guard.RequireDelete(fake, tx, kind, []string{id.String()}), ds.DeletionUnavailable)
	copyContext := context.WithValue(current, forgedProfile{}, true)
	require.NoError(t, guard.RequireDelete(copyContext, tx, kind, []string{id.String()}))
	enforceCode(t, guard.RequireDelete(current, tx, kind, []string{id.String()}), ds.DeletionUnavailable)
	require.NoError(t, tx.Rollback())
	enforceCode(t, guard.RequireDelete(current, tx, kind, []string{id.String()}), ds.DeletionUnavailable)
	// Commit invalidates an unconsumed carrier, with no reliance on Go flags.
	tx = nrBegin(t, ctx, db)
	current = enforce(tx)
	require.NoError(t, tx.Commit())
	enforceCode(t, guard.RequireDelete(current, tx, kind, []string{id.String()}), ds.DeletionUnavailable)
	nrNoSuccess(t, ctx, db)
}

type nrWrite struct {
	name, query, verify string
	args                []any
}

func nrRelatedWrites(t *testing.T, ctx context.Context, db *sql.DB, f deletionFixture) []nrWrite {
	t.Helper()
	cm, nr := nrSibling(t, ctx, db, f, 0)
	var cycle uuid.UUID
	require.NoError(t, db.QueryRowContext(ctx, `SELECT id FROM notification_policy_cycles WHERE user_id=$1 AND alert_id=$2`, f.user, f.active).Scan(&cycle))
	newCM, newNR, newCycle := uuid.New(), uuid.New(), uuid.New()
	return []nrWrite{
		{"new_nr", `INSERT INTO user_notification_rules(id,user_id,contact_method_id,delay_minutes) VALUES($1,$2,$3,6)`, `SELECT count(*) FROM user_notification_rules WHERE id=$1`, []any{newNR, f.user, cm}},
		{"new_cm", `INSERT INTO user_contact_methods(id,user_id,name,type,value,dest,pending) VALUES($1,$2,($1::uuid)::text,'WEBHOOK',($1::uuid)::text,jsonb_build_object('type','synthetic','id',($1::uuid)::text),false)`, `SELECT count(*) FROM user_contact_methods WHERE id=$1`, []any{newCM, f.user}},
		{"new_cycle", `INSERT INTO notification_policy_cycles(id,user_id,alert_id) VALUES($1,$2,$3)`, `SELECT count(*) FROM notification_policy_cycles WHERE id=$1`, []any{newCycle, f.user, f.active}},
		{"cm_disabled", `UPDATE user_contact_methods SET disabled=true WHERE id=$1`, `SELECT count(*) FROM user_contact_methods WHERE id=$1 AND disabled`, []any{cm}},
		{"cm_pending", `UPDATE user_contact_methods SET pending=true WHERE id=$1`, `SELECT count(*) FROM user_contact_methods WHERE id=$1 AND pending`, []any{cm}},
		{"nr_delay", `UPDATE user_notification_rules SET delay_minutes=7 WHERE id=$1`, `SELECT count(*) FROM user_notification_rules WHERE id=$1 AND delay_minutes=7`, []any{nr}},
		{"nr_parent", `UPDATE user_notification_rules SET contact_method_id=$2,delay_minutes=8 WHERE id=$1`, `SELECT count(*) FROM user_notification_rules WHERE id=$1 AND delay_minutes=8`, []any{nr, f.cm}},
		{"nr_delete", `DELETE FROM user_notification_rules WHERE id=$1`, `SELECT count(*) FROM user_notification_rules WHERE id<>$1 AND user_id=(SELECT user_id FROM user_contact_methods WHERE id=$2)`, []any{nr, cm}},
		{"cycle_state", `UPDATE notification_policy_cycles SET repeat_count=repeat_count+1 WHERE id=$1`, `SELECT count(*) FROM notification_policy_cycles WHERE id=$1 AND repeat_count>0`, []any{cycle}},
		{"alert_state", `UPDATE alerts SET status='closed' WHERE id=$1`, `SELECT count(*) FROM alerts WHERE id=$1 AND status='closed'`, []any{f.active}},
	}
}
func nrWaiter(t *testing.T, ctx context.Context, db *sql.DB, writer *sql.Tx, query string, args ...any) <-chan error {
	t.Helper()
	var pid int
	require.NoError(t, writer.QueryRowContext(ctx, `SELECT pg_backend_pid()`).Scan(&pid))
	done := make(chan error, 1)
	go func() { _, err := writer.ExecContext(ctx, query, args...); done <- err }()
	for {
		var waiting bool
		require.NoError(t, db.QueryRowContext(ctx, `SELECT cardinality(pg_blocking_pids($1))>0`, pid).Scan(&waiting))
		if waiting {
			break
		}
		select {
		case err := <-done:
			require.FailNow(t, "writer did not wait", "%v", err)
		default:
		}
		require.NoError(t, ctx.Err())
	}
	return done
}

func TestPostgresDeletionEnforcementNRDeleteFirst(t *testing.T) {
	ctx, _, db := boundedAuditDB(t, len(Names()))
	ctx = permission.SystemContext(ctx, "NRProofTest")
	for index := 0; index < 10; index++ {
		f := newDeletionFixture(t, ctx, db)
		writes := nrRelatedWrites(t, ctx, db, f)
		w := writes[index]
		t.Run(w.name, func(t *testing.T) {
			version := nrVersion(t, ctx, db, f.nr)
			tx := nrBegin(t, ctx, db)
			bound := nrEnforce(t, ctx, tx, f.nr, version)
			writer, err := db.BeginTx(ctx, nil)
			require.NoError(t, err)
			defer func() { _ = writer.Rollback() }()
			args := w.args
			if w.name == "nr_delete" {
				args = args[:1]
			}
			done := nrWaiter(t, ctx, db, writer, w.query, args...)
			store, err := notificationrule.NewStore(ctx, db)
			require.NoError(t, err)
			result, err := store.DeleteForAuditTx(bound, tx, f.nr.String())
			require.NoError(t, err)
			require.Len(t, result.Targets, 1)
			require.True(t, result.Targets[0].Deleted)
			require.NoError(t, tx.Commit())
			require.NoError(t, <-done)
			require.NoError(t, writer.Commit())
			require.Zero(t, enforcementCount(t, ctx, db, `SELECT count(*) FROM user_notification_rules WHERE id=$1`, f.nr))
			if w.name == "nr_delete" {
				require.Zero(t, enforcementCount(t, ctx, db, `SELECT count(*) FROM user_notification_rules WHERE id=$1`, w.args[0]))
			} else {
				require.Equal(t, 1, enforcementCount(t, ctx, db, w.verify, w.args[0]))
			}
		})
	}
}

func TestPostgresDeletionEnforcementNRWriterFirst(t *testing.T) {
	ctx, _, db := boundedAuditDB(t, len(Names()))
	ctx = permission.SystemContext(ctx, "NRProofTest")
	for index := 0; index < 10; index++ {
		f := newDeletionFixture(t, ctx, db)
		w := nrRelatedWrites(t, ctx, db, f)[index]
		t.Run(w.name, func(t *testing.T) {
			version := nrVersion(t, ctx, db, f.nr)
			writer, err := db.BeginTx(ctx, nil)
			require.NoError(t, err)
			defer func() { _ = writer.Rollback() }()
			args := w.args
			if w.name == "nr_delete" {
				args = args[:1]
			}
			_, err = writer.ExecContext(ctx, w.query, args...)
			require.NoError(t, err) // completed SQL is the barrier
			tx := nrBegin(t, ctx, db)
			_, err = collector.Enforce(ctx, tx, nrSelectors(f.nr), version, true, authorizeDeletionFixture(nrRoot(f.nr)))
			enforceCode(t, err, ds.DeletionUnavailable)
			require.NoError(t, tx.Rollback())
			require.NoError(t, writer.Commit())
			freshVersion := nrVersion(t, ctx, db, f.nr)
			if version != freshVersion {
				tx = nrBegin(t, ctx, db)
				_, err = collector.Enforce(ctx, tx, nrSelectors(f.nr), version, true, authorizeDeletionFixture(nrRoot(f.nr)))
				enforceCode(t, err, ds.DeletionDependencyChanged)
				require.NoError(t, tx.Rollback())
			}
			tx = nrBegin(t, ctx, db)
			bound := nrEnforce(t, ctx, tx, f.nr, freshVersion)
			require.NoError(t, guard.RequireDelete(bound, tx, ds.ResourceNotificationRule, []string{f.nr.String()}))
			require.NoError(t, tx.Rollback())
			require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM user_notification_rules WHERE id=$1`, f.nr))
		})
	}
	nrNoSuccess(t, ctx, db)
}

func TestPostgresDeletionEnforcementNRIndependent(t *testing.T) {
	ctx, _, db := boundedAuditDB(t, len(Names()))
	ctx = permission.SystemContext(ctx, "NRProofTest")
	f := newDeletionFixture(t, ctx, db)
	other := newDeletionFixture(t, ctx, db)
	writes := []nrWrite{
		{name: "other_owner_cm", query: `UPDATE user_contact_methods SET disabled=true WHERE id=$1`, args: []any{other.cm}},
		{name: "other_org_service", query: `UPDATE services SET name=name WHERE id=$1`, args: []any{other.service}},
		{name: "unrelated_rotation", query: `UPDATE rotations SET name=name WHERE id=$1`, args: []any{other.rotation}},
		{name: "unrelated_key", query: `UPDATE integration_keys SET name=name WHERE id=$1`, args: []any{other.key}},
		{name: "unrelated_alert", query: `UPDATE alerts SET status='closed' WHERE id=$1`, args: []any{other.active}},
	}
	version := nrVersion(t, ctx, db, f.nr)
	for _, w := range writes {
		t.Run(w.name, func(t *testing.T) {
			writer, err := db.BeginTx(ctx, nil)
			require.NoError(t, err)
			_, err = writer.ExecContext(ctx, w.query, w.args...)
			require.NoError(t, err)
			tx := nrBegin(t, ctx, db)
			nrEnforce(t, ctx, tx, f.nr, version) // writer-first must not reject NR
			require.NoError(t, tx.Rollback())
			require.NoError(t, writer.Rollback())
		})
	}
	tx := nrBegin(t, ctx, db)
	bound := nrEnforce(t, ctx, tx, f.nr, version)
	var globalLocks int
	require.NoError(t, tx.QueryRowContext(ctx, `SELECT count(*) FROM pg_locks l JOIN pg_class c ON c.oid=l.relation JOIN pg_namespace n ON n.oid=c.relnamespace WHERE l.pid=pg_backend_pid() AND n.nspname='public' AND l.mode IN ('ShareLock','ShareRowExclusiveLock','ExclusiveLock','AccessExclusiveLock')`).Scan(&globalLocks))
	require.Zero(t, globalLocks)
	for _, w := range writes {
		writer, err := db.BeginTx(ctx, nil)
		require.NoError(t, err)
		_, err = writer.ExecContext(ctx, `SET LOCAL lock_timeout='250ms'`)
		require.NoError(t, err)
		res, err := writer.ExecContext(ctx, w.query, w.args...)
		require.NoError(t, err, w.name)
		count, err := res.RowsAffected()
		require.NoError(t, err)
		require.EqualValues(t, 1, count)
		require.NoError(t, writer.Commit()) // completed while deletion still owns its locks
	}
	store, err := notificationrule.NewStore(ctx, db)
	require.NoError(t, err)
	result, err := store.DeleteForAuditTx(bound, tx, f.nr.String())
	require.NoError(t, err)
	require.Len(t, result.Targets, 1)
	require.NoError(t, tx.Commit())
	require.Zero(t, enforcementCount(t, ctx, db, `SELECT count(*) FROM user_notification_rules WHERE id=$1`, f.nr))
}

// Driver tracing pauses before the owner lock, AFTER CM/NR locks/discovery.
// This is a deterministic discovery-window barrier without a production hook.
type nrQueryBarrier struct {
	needle          string
	arrived, resume chan struct{}
	once            sync.Once
}

func (b *nrQueryBarrier) TraceQueryStart(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	if strings.Contains(data.SQL, b.needle) {
		b.once.Do(func() {
			close(b.arrived)
			select {
			case <-b.resume:
			case <-ctx.Done():
			}
		})
	}
	return ctx
}
func (*nrQueryBarrier) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}

func TestPostgresDeletionEnforcementNRMembershipWindow(t *testing.T) {
	ctx, uri, db := boundedAuditDB(t, len(Names()))
	ctx = permission.SystemContext(ctx, "NRProofTest")
	for _, kind := range []string{"cm", "nr", "cycle"} {
		t.Run(kind, func(t *testing.T) {
			f := newDeletionFixture(t, ctx, db)
			version := nrVersion(t, ctx, db, f.nr)
			conf, err := pgx.ParseConfig(uri)
			require.NoError(t, err)
			barrier := &nrQueryBarrier{needle: "SELECT id::text FROM public.users WHERE", arrived: make(chan struct{}), resume: make(chan struct{})}
			conf.Tracer = barrier
			traced := sql.OpenDB(stdlib.GetConnector(*conf))
			defer traced.Close()
			tx := nrBegin(t, ctx, traced)
			done := make(chan error, 1)
			go func() {
				_, err := collector.Enforce(ctx, tx, nrSelectors(f.nr), version, true, authorizeDeletionFixture(nrRoot(f.nr)))
				done <- err
			}()
			select {
			case <-barrier.arrived:
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			// A fresh CM does not touch any already locked sibling, and can commit
			// before the owner FK barrier. A newly committed NR must also be detected.
			newCM := uuid.New()
			if kind == "cm" || kind == "nr" {
				enforcementExec(t, ctx, db, `INSERT INTO user_contact_methods(id,user_id,name,type,value,dest,pending) VALUES($1,$2,($1::uuid)::text,'WEBHOOK',($1::uuid)::text,jsonb_build_object('type','synthetic','id',($1::uuid)::text),false)`, newCM, f.user)
				if kind == "nr" {
					enforcementExec(t, ctx, db, `INSERT INTO user_notification_rules(user_id,contact_method_id,delay_minutes) VALUES($1,$2,0)`, f.user, newCM)
				}
			} else {
				enforcementExec(t, ctx, db, `DELETE FROM notification_policy_cycles WHERE user_id=$1`, f.user)
			}
			close(barrier.resume)
			err = <-done
			if kind == "cycle" { // discovered after User lock; fresh risk invalidates version
				enforceCode(t, err, ds.DeletionDependencyChanged)
			} else {
				enforceCode(t, err, ds.DeletionUnavailable)
			}
			require.NoError(t, tx.Rollback())
			require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM user_notification_rules WHERE id=$1`, f.nr))
		})
	}
	nrNoSuccess(t, ctx, db)
}

func TestPostgresDeletionEnforcementNRMissingWindow(t *testing.T) {
	ctx, _, db := boundedAuditDB(t, len(Names()))
	f := newDeletionFixture(t, ctx, db)
	ctx = permission.SystemContext(ctx, "NRProofTest")
	store, err := notificationrule.NewStore(ctx, db)
	require.NoError(t, err)
	// The original UUID validator accepts the zero UUID; if absent it remains
	// a legal no-op, rather than gaining a stricter identity rule in this profile.
	app := enforcementApp(t, ctx, db)
	ok, err := app.Mutation().DeleteAll(ctx, nrInput(uuid.Nil), nil)
	require.NoError(t, err)
	require.True(t, ok)
	missing := uuid.New()
	tx := nrBegin(t, ctx, db)
	bound, err := collector.Enforce(ctx, tx, nrSelectors(missing), "", false, authorizeDeletionFixture(nrRoot(missing)))
	require.NoError(t, err)
	enforcementExec(t, ctx, db, `INSERT INTO user_notification_rules(id,user_id,contact_method_id,delay_minutes) VALUES($1,$2,$3,9)`, missing, f.user, f.cm)
	// Insert has COMMITTED after certification, before any Store query.
	result, err := store.DeleteForAuditTx(bound, tx, missing.String())
	require.NoError(t, err)
	require.Empty(t, result.Targets)
	require.NoError(t, tx.Commit())
	require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM user_notification_rules WHERE id=$1`, missing))
	// The legacy Store uses the same restricted effective selector.
	absent := uuid.New()
	tx = nrBegin(t, ctx, db)
	bound, err = collector.Enforce(ctx, tx, nrSelectors(absent), "", false, authorizeDeletionFixture(nrRoot(absent)))
	require.NoError(t, err)
	enforcementExec(t, ctx, db, `INSERT INTO user_notification_rules(id,user_id,contact_method_id,delay_minutes) VALUES($1,$2,$3,10)`, absent, f.user, f.cm)
	require.NoError(t, store.DeleteTx(bound, tx, absent.String()))
	require.NoError(t, tx.Commit())
	require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM user_notification_rules WHERE id=$1`, absent))
	// Mixed existing/Missing also cannot enlarge to a new, other-owner row.
	other := newDeletionFixture(t, ctx, db)
	absent = uuid.New()
	version := nrVersion(t, ctx, db, f.nr)
	tx = nrBegin(t, ctx, db)
	bound, err = collector.Enforce(ctx, tx, nrSelectors(f.nr, absent), version, true, authorizeDeletionFixture(nrRoot(f.nr)))
	require.NoError(t, err)
	enforcementExec(t, ctx, db, `INSERT INTO user_notification_rules(id,user_id,contact_method_id,delay_minutes) VALUES($1,$2,$3,11)`, absent, other.user, other.cm)
	result, err = store.DeleteForAuditTx(bound, tx, f.nr.String(), absent.String())
	require.NoError(t, err)
	require.Len(t, result.Targets, 1)
	require.Equal(t, f.nr, result.Targets[0].ID)
	require.NoError(t, tx.Commit())
	require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM user_notification_rules WHERE id=$1`, absent))
	tx = nrBegin(t, ctx, db)
	_, err = collector.Enforce(ctx, tx, nrSelectors(f.nr), version, true, authorizeDeletionFixture(nrRoot(f.nr)))
	enforceCode(t, err, ds.DeletionDependencyChanged)
	require.NoError(t, tx.Rollback())
	nrNoSuccess(t, ctx, db)
}

func TestPostgresDeletionEnforcementNRAuditFailure(t *testing.T) {
	ctx, _, db := boundedAuditDB(t, len(Names()))
	f := newDeletionFixture(t, ctx, db)
	ctx = permission.SystemContext(ctx, "NRProofTest")
	app := enforcementApp(t, ctx, db)
	confirm := enforcementPreview(t, ctx, app, graphql2.DeletionResourceInput{Type: graphql2.DeletionTargetTypeNotificationRule, ID: f.nr.String()})
	enforcementExec(t, ctx, db, `CREATE FUNCTION synthetic_nr_audit_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.outcome='committed' THEN RAISE EXCEPTION 'SYNTHETIC_PRIVATE_AUDIT'; END IF; RETURN NEW; END $$`)
	enforcementExec(t, ctx, db, `CREATE TRIGGER synthetic_nr_audit_failure BEFORE INSERT ON user_cmnr_delete_audit_events FOR EACH ROW EXECUTE FUNCTION synthetic_nr_audit_failure()`)
	ok, err := app.Mutation().DeleteAll(ctx, nrInput(f.nr), confirm)
	require.False(t, ok)
	require.Error(t, err)
	require.NotContains(t, err.Error(), "SYNTHETIC_PRIVATE")
	require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM user_notification_rules WHERE id=$1`, f.nr))
	nrNoSuccess(t, ctx, db)
	enforcementExec(t, ctx, db, `DROP TRIGGER synthetic_nr_audit_failure ON user_cmnr_delete_audit_events`)
	ok, err = app.Mutation().DeleteAll(ctx, nrInput(f.nr), confirm)
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM user_cmnr_delete_audit_events WHERE outcome='committed'`))
}

func TestPostgresDeletionEnforcementNRAuthorization(t *testing.T) {
	ctx, _, db := boundedAuditDB(t, len(Names()))
	sys := permission.SystemContext(ctx, "NRProofTest")
	for _, role := range []string{"ORG_MEMBER", "ORG_ADMIN", "PLATFORM_ADMIN"} {
		t.Run(role, func(t *testing.T) {
			f := newDeletionFixture(t, ctx, db)
			actor := f.user
			if role == "ORG_ADMIN" {
				enforcementExec(t, ctx, db, `UPDATE user_organization_assignments SET organization_role='ORG_ADMIN' WHERE user_id=$1`, actor)
			}
			if role == "PLATFORM_ADMIN" {
				actor = f.actor
				enforcementExec(t, ctx, db, `UPDATE users SET role='admin' WHERE id=$1`, actor)
			}
			human := previewAdmit(t, ctx, db, actor)
			app := enforcementApp(t, sys, db)
			confirm := enforcementPreview(t, human, app, graphql2.DeletionResourceInput{Type: graphql2.DeletionTargetTypeNotificationRule, ID: f.nr.String()})
			// Authorization is independently refreshed after persisted actor changes.
			tx := nrBegin(t, human, db)
			bound, err := collector.Enforce(human, tx, nrSelectors(f.nr), confirm.ExpectedImpactVersion, true, func(context.Context, *sql.Tx, collector.Target) error { return nil })
			require.NoError(t, err)
			for _, query := range []string{`UPDATE users SET name=name WHERE id=$1`, `UPDATE user_organization_assignments SET source_config_version=source_config_version WHERE user_id=$1`} {
				writer, err := db.BeginTx(ctx, nil)
				require.NoError(t, err)
				done := nrWaiter(t, ctx, db, writer, query, actor)
				// Avoid consuming the real Store selector just to demonstrate contention.
				require.NoError(t, tx.Rollback())
				require.NoError(t, <-done)
				require.NoError(t, writer.Rollback())
				tx = nrBegin(t, human, db)
				bound, err = collector.Enforce(human, tx, nrSelectors(f.nr), confirm.ExpectedImpactVersion, true, func(context.Context, *sql.Tx, collector.Target) error { return nil })
				require.NoError(t, err)
			}
			require.NoError(t, guard.RequireDelete(bound, tx, ds.ResourceNotificationRule, []string{f.nr.String()}))
			require.NoError(t, tx.Rollback())
			ok, err := app.Mutation().DeleteAll(human, nrInput(f.nr), confirm)
			require.NoError(t, err)
			require.True(t, ok)
			// OrgAdmin has owner-only NR capability, not blanket colleague deletion.
			if role != "PLATFORM_ADMIN" {
				colleague := f
				colleague.user = f.actor // same Organization, different owner
				_, colleagueNR := nrSibling(t, ctx, db, colleague, 0)
				_, err = app.Mutation().DeleteAll(human, nrInput(colleagueNR), nil)
				require.Error(t, err)
				require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM user_notification_rules WHERE id=$1`, colleagueNR))
			}
		})
	}
	// Stale actor role and assignment changes, both Writer-first and committed.
	for _, change := range []string{"role", "assignment"} {
		t.Run("stale_"+change, func(t *testing.T) {
			f := newDeletionFixture(t, ctx, db)
			human := previewAdmit(t, ctx, db, f.user)
			app := enforcementApp(t, sys, db)
			confirm := enforcementPreview(t, human, app, graphql2.DeletionResourceInput{Type: graphql2.DeletionTargetTypeNotificationRule, ID: f.nr.String()})
			writer, err := db.BeginTx(ctx, nil)
			require.NoError(t, err)
			query := `UPDATE users SET role='admin' WHERE id=$1`
			if change == "assignment" {
				query = `UPDATE user_organization_assignments SET organization_role='ORG_ADMIN' WHERE user_id=$1`
			}
			_, err = writer.ExecContext(ctx, query, f.user)
			require.NoError(t, err)
			tx := nrBegin(t, human, db)
			_, err = collector.Enforce(human, tx, nrSelectors(f.nr), confirm.ExpectedImpactVersion, true, func(context.Context, *sql.Tx, collector.Target) error { return nil })
			enforceCode(t, err, ds.DeletionUnavailable)
			require.NoError(t, tx.Rollback())
			require.NoError(t, writer.Commit())
			_, err = app.Mutation().DeleteAll(human, nrInput(f.nr), confirm)
			enforceCode(t, err, ds.DeletionUnavailable)
			require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM user_notification_rules WHERE id=$1`, f.nr))
		})
	}
	f := newDeletionFixture(t, ctx, db)
	app := enforcementApp(t, sys, db)
	enforcementExec(t, ctx, db, `DELETE FROM user_organization_assignments WHERE user_id=$1`, f.user)
	_, err := app.Mutation().DeleteAll(sys, nrInput(f.nr), nil)
	enforceCode(t, err, ds.DeletionUnavailable)
}

func TestPostgresDeletionEnforcementNRTimeoutCancellation(t *testing.T) {
	ctx, uri, db := boundedAuditDB(t, len(Names()))
	f := newDeletionFixture(t, ctx, db)
	ctx = permission.SystemContext(ctx, "NRProofTest")
	app := enforcementApp(t, ctx, db)
	confirm := enforcementPreview(t, ctx, app, graphql2.DeletionResourceInput{Type: graphql2.DeletionTargetTypeNotificationRule, ID: f.nr.String()})
	// Cancellation before enforcement never issues proof or mutates business.
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	_, err := app.Mutation().DeleteAll(cancelled, nrInput(f.nr), confirm)
	require.Error(t, err)
	// D09's inherited advisory lock remains a bounded lock-timeout failure. The
	// new profile itself never waits on a conflicting related row (NOWAIT).
	holder, err := db.BeginTx(ctx, nil)
	require.NoError(t, err)
	_, err = holder.ExecContext(ctx, `SELECT pg_advisory_xact_lock(1297305411,1396979713)`)
	require.NoError(t, err)
	conf, err := pgx.ParseConfig(uri)
	require.NoError(t, err)
	conf.RuntimeParams["lock_timeout"] = "100ms"
	limited := sql.OpenDB(stdlib.GetConnector(*conf))
	defer limited.Close()
	limitedApp := enforcementApp(t, ctx, limited)
	ok, err := limitedApp.Mutation().DeleteAll(ctx, nrInput(f.nr), confirm)
	require.False(t, ok)
	require.Error(t, err)
	require.NotContains(t, err.Error(), "SQLSTATE")
	require.NoError(t, holder.Rollback())
	require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM user_notification_rules WHERE id=$1`, f.nr))
	nrNoSuccess(t, ctx, db)
}

func TestPostgresDeletionEnforcementNRScopeAndIntegrity(t *testing.T) {
	ctx, _, db := boundedAuditDB(t, len(Names()))
	sys := permission.SystemContext(ctx, "NRProofTest")
	f := newDeletionFixture(t, ctx, db)
	app := enforcementApp(t, sys, db)
	enforcementExec(t, ctx, db, `UPDATE users SET role='admin' WHERE id=$1`, f.actor)
	human := previewAdmit(t, ctx, db, f.actor)
	confirm := enforcementPreview(t, human, app, graphql2.DeletionResourceInput{Type: graphql2.DeletionTargetTypeNotificationRule, ID: f.nr.String()})
	for _, w := range []nrWrite{
		{name: "actor_role", query: `UPDATE users SET name=name WHERE id=$1`, args: []any{f.actor}},
		{name: "owner_role", query: `UPDATE users SET name=name WHERE id=$1`, args: []any{f.user}},
		{name: "actor_assignment", query: `UPDATE user_organization_assignments SET source_config_version=source_config_version WHERE user_id=$1`, args: []any{f.actor}},
		{name: "owner_assignment", query: `UPDATE user_organization_assignments SET source_config_version=source_config_version WHERE user_id=$1`, args: []any{f.user}},
		{name: "organization", query: `UPDATE organizations SET display_name=display_name WHERE id=$1`, args: []any{f.org}},
		{name: "normal_organization", query: `UPDATE normal_organizations SET iana_time_zone=iana_time_zone WHERE organization_id=$1`, args: []any{f.org}},
	} {
		t.Run(w.name, func(t *testing.T) {
			tx := nrBegin(t, human, db)
			_, err := collector.Enforce(human, tx, nrSelectors(f.nr), confirm.ExpectedImpactVersion, true, func(context.Context, *sql.Tx, collector.Target) error { return nil })
			require.NoError(t, err)
			writer, err := db.BeginTx(ctx, nil)
			require.NoError(t, err)
			done := nrWaiter(t, ctx, db, writer, w.query, w.args...)
			require.NoError(t, tx.Rollback())
			require.NoError(t, <-done)
			// The same writer now owns the row. A new Delete attempt must NOWAIT fail.
			tx = nrBegin(t, human, db)
			_, err = collector.Enforce(human, tx, nrSelectors(f.nr), confirm.ExpectedImpactVersion, true, func(context.Context, *sql.Tx, collector.Target) error { return nil })
			enforceCode(t, err, ds.DeletionUnavailable)
			require.NoError(t, tx.Rollback())
			require.NoError(t, writer.Commit())
		})
	}
	// A real FK permits this legacy CM ownership edit without rewriting NR.
	// The resulting inconsistent sibling graph must not be treated as empty/safe.
	cm, _ := nrSibling(t, ctx, db, f, 4)
	enforcementExec(t, ctx, db, `UPDATE user_contact_methods SET user_id=$2 WHERE id=$1`, cm, f.actor)
	_, err := app.Mutation().DeleteAll(sys, nrInput(f.nr), confirm)
	enforceCode(t, err, ds.DeletionUnavailable)
	require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM user_notification_rules WHERE id=$1`, f.nr))
	nrNoSuccess(t, ctx, db)
}

func TestPostgresDeletionEnforcementNRParentDiscoveryWindow(t *testing.T) {
	ctx, uri, db := boundedAuditDB(t, len(Names()))
	ctx = permission.SystemContext(ctx, "NRProofTest")
	for _, kind := range []string{"parent", "owner", "sibling_identity"} {
		t.Run(kind, func(t *testing.T) {
			f := newDeletionFixture(t, ctx, db)
			other := newDeletionFixture(t, ctx, db)
			cm, sibling := nrSibling(t, ctx, db, f, 3)
			version := nrVersion(t, ctx, db, f.nr)
			conf, err := pgx.ParseConfig(uri)
			require.NoError(t, err)
			barrier := &nrQueryBarrier{needle: "SELECT id::text,user_id::text FROM public.user_contact_methods WHERE id=ANY", arrived: make(chan struct{}), resume: make(chan struct{})}
			conf.Tracer = barrier
			traced := sql.OpenDB(stdlib.GetConnector(*conf))
			defer traced.Close()
			tx := nrBegin(t, ctx, traced)
			done := make(chan error, 1)
			go func() {
				_, err := collector.Enforce(ctx, tx, nrSelectors(f.nr), version, true, authorizeDeletionFixture(nrRoot(f.nr)))
				done <- err
			}()
			select {
			case <-barrier.arrived:
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
			switch kind {
			case "parent":
				enforcementExec(t, ctx, db, `UPDATE user_notification_rules SET contact_method_id=$2 WHERE id=$1`, f.nr, cm)
			case "owner":
				enforcementExec(t, ctx, db, `UPDATE user_notification_rules SET user_id=$2,contact_method_id=$3,delay_minutes=12 WHERE id=$1`, f.nr, other.user, other.cm)
			case "sibling_identity":
				writer, err := db.BeginTx(ctx, nil)
				require.NoError(t, err)
				_, err = writer.ExecContext(ctx, `DELETE FROM user_notification_rules WHERE id=$1`, sibling)
				require.NoError(t, err)
				_, err = writer.ExecContext(ctx, `INSERT INTO user_notification_rules(user_id,contact_method_id,delay_minutes) VALUES($1,$2,3)`, f.user, cm)
				require.NoError(t, err)
				require.NoError(t, writer.Commit())
			}
			close(barrier.resume)
			enforceCode(t, <-done, ds.DeletionUnavailable)
			require.NoError(t, tx.Rollback())
			require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM user_notification_rules WHERE id=$1`, f.nr))
		})
	}
	nrNoSuccess(t, ctx, db)
}

func TestPostgresDeletionEnforcementNRStableBudget(t *testing.T) {
	ctx, _, db := boundedAuditDB(t, len(Names()))
	f := newDeletionFixture(t, ctx, db)
	ctx = permission.SystemContext(ctx, "NRProofTest")
	enforcementExec(t, ctx, db, `INSERT INTO notification_policy_cycles(user_id,alert_id) SELECT $1,$2 FROM generate_series(1,10001)`, f.user, f.active)
	tx := nrBegin(t, ctx, db)
	_, err := collector.Enforce(ctx, tx, nrSelectors(f.nr), "", false, authorizeDeletionFixture(nrRoot(f.nr)))
	enforceCode(t, err, ds.DeletionPreviewLimitExceeded)
	require.NoError(t, tx.Rollback())
	require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM user_notification_rules WHERE id=$1`, f.nr))
	nrNoSuccess(t, ctx, db)
}
