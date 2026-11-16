package migrate

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/target/goalert/config"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/assignment"
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

func TestPostgresDeletionEnforcementBusiness(t *testing.T) {
	ctx, _, db := boundedAuditDB(t, len(Names()))
	f := newDeletionFixture(t, ctx, db)
	ctx = permission.SystemContext(ctx, "DeletionEnforcementTest")
	app := enforcementApp(t, ctx, db)
	cases := []struct {
		typ assignment.TargetType
		id  uuid.UUID
	}{
		{assignment.TargetTypeEscalationPolicy, f.policy}, {assignment.TargetTypeSchedule, f.schedule}, {assignment.TargetTypeRotation, f.rotation}, {assignment.TargetTypeService, f.service}, {assignment.TargetTypeUser, f.user},
	}
	for _, tc := range cases {
		t.Run(tc.typ.String(), func(t *testing.T) {
			before := deletionSnapshot(t, ctx, db)
			ok, err := app.Mutation().DeleteAll(ctx, []assignment.RawTarget{{Type: tc.typ, ID: tc.id.String()}}, nil)
			require.False(t, ok)
			expected := ds.DeletionBlocked
			if tc.typ == assignment.TargetTypeRotation {
				expected = ds.DeletionUnavailable
			}
			enforceCode(t, err, expected)
			// Failed observations are permitted; business roots/relations and successful
			// audit assertions are checked separately below.
			after := deletionSnapshot(t, ctx, db)
			for table, hash := range before {
				if !strings.Contains(table, "audit") {
					require.Equal(t, hash, after[table], table)
				}
			}

			require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM services WHERE id=$1`, f.service))
			require.Zero(t, enforcementCount(t, ctx, db, `SELECT count(*) FROM service_delete_audit_events WHERE outcome='committed'`))
		})
	}
	// A completely empty policy requires no additional confirmation, including
	// legacy clients and duplicate selectors (raw limits are still applied).
	empty := uuid.New()
	enforcementExec(t, ctx, db, `INSERT INTO escalation_policies(id,organization_id,name) VALUES($1,$2,($1::uuid)::text)`, empty, f.org)
	ok, err := app.Mutation().DeleteAll(ctx, []assignment.RawTarget{{Type: assignment.TargetTypeEscalationPolicy, ID: empty.String()}, {Type: assignment.TargetTypeEscalationPolicy, ID: empty.String()}}, nil)
	require.NoError(t, err)
	require.True(t, ok)
	require.Zero(t, enforcementCount(t, ctx, db, `SELECT count(*) FROM escalation_policies WHERE id=$1`, empty))
	require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM escalation_policy_delete_audit_events WHERE root_id=$1 AND outcome='committed'`, empty))
	// Missing targets remain legacy no-ops without confirmation, but a supplied
	// old version cannot confirm a target graph which has disappeared.
	one := []assignment.RawTarget{{Type: assignment.TargetTypeEscalationPolicy, ID: empty.String()}}
	ok, err = app.Mutation().DeleteAll(ctx, one, nil)
	require.NoError(t, err)
	require.True(t, ok)
	_, err = app.Mutation().DeleteAll(ctx, one, &graphql2.DeletionSafetyConfirmationInput{ExpectedImpactVersion: "stale", AcknowledgeImpacts: true})
	enforceCode(t, err, ds.DeletionDependencyChanged)

}

func TestPostgresDeletionEnforcementConfirmationAndAudit(t *testing.T) {
	ctx, _, db := boundedAuditDB(t, len(Names()))
	f := newDeletionFixture(t, ctx, db)
	ctx = permission.SystemContext(ctx, "DeletionEnforcementTest")
	app := enforcementApp(t, ctx, db)
	target := []assignment.RawTarget{{Type: assignment.TargetTypeContactMethod, ID: f.cm.String()}, {Type: assignment.TargetTypeNotificationRule, ID: f.nr.String()}}
	_, err := app.Mutation().DeleteAll(ctx, target, nil)
	enforceCode(t, err, ds.DeletionConfirmationRequired)
	confirm := enforcementPreview(t, ctx, app, graphql2.DeletionResourceInput{Type: graphql2.DeletionTargetTypeContactMethod, ID: f.cm.String()}, graphql2.DeletionResourceInput{Type: graphql2.DeletionTargetTypeNotificationRule, ID: f.nr.String()})
	stale := *confirm
	stale.ExpectedImpactVersion = "stale"
	_, err = app.Mutation().DeleteAll(ctx, target, &stale)
	enforceCode(t, err, ds.DeletionDependencyChanged)
	// Same number of rules, new row identity invalidates the confirmation.
	enforcementExec(t, ctx, db, `DELETE FROM user_notification_rules WHERE id=$1`, f.nr)
	nr := uuid.New()
	enforcementExec(t, ctx, db, `INSERT INTO user_notification_rules(id,user_id,contact_method_id,delay_minutes) VALUES($1,$2,$3,0)`, nr, f.user, f.cm)
	_, err = app.Mutation().DeleteAll(ctx, target, confirm)
	enforceCode(t, err, ds.DeletionDependencyChanged)
	target[1].ID = nr.String()
	confirm = enforcementPreview(t, ctx, app, graphql2.DeletionResourceInput{Type: graphql2.DeletionTargetTypeContactMethod, ID: f.cm.String()}, graphql2.DeletionResourceInput{Type: graphql2.DeletionTargetTypeNotificationRule, ID: nr.String()})
	ok, err := app.Mutation().DeleteAll(ctx, target, confirm)
	require.NoError(t, err)
	require.True(t, ok)
	require.Zero(t, enforcementCount(t, ctx, db, `SELECT count(*) FROM user_contact_methods WHERE id=$1`, f.cm))
	require.Zero(t, enforcementCount(t, ctx, db, `SELECT count(*) FROM user_notification_rules WHERE id=$1`, nr))
	require.Equal(t, 2, enforcementCount(t, ctx, db, `SELECT count(*) FROM user_cmnr_delete_audit_events WHERE outcome='committed'`))
	// Both roots were explicitly selected; receipts keep explicit causality.
	require.Zero(t, enforcementCount(t, ctx, db, `SELECT count(*) FROM user_cmnr_delete_audit_events WHERE outcome='committed' AND provenance<>'EXPLICIT'`))
}

func TestPostgresDeletionEnforcementOwnedAndPreserved(t *testing.T) {
	ctx, _, db := boundedAuditDB(t, len(Names()))
	f := newDeletionFixture(t, ctx, db)
	ctx = permission.SystemContext(ctx, "DeletionEnforcementTest")
	app := enforcementApp(t, ctx, db)
	// Remove the external Service reference; Steps/Actions stay explicitly owned.
	enforcementExec(t, ctx, db, `DELETE FROM services WHERE id=$1`, f.service)
	input := []assignment.RawTarget{{Type: assignment.TargetTypeEscalationPolicy, ID: f.policy.String()}}
	_, err := app.Mutation().DeleteAll(ctx, input, nil)
	enforceCode(t, err, ds.DeletionConfirmationRequired)
	confirm := enforcementPreview(t, ctx, app, graphql2.DeletionResourceInput{Type: graphql2.DeletionTargetTypeEscalationPolicy, ID: f.policy.String()})
	ok, err := app.Mutation().DeleteAll(ctx, input, confirm)
	require.NoError(t, err)
	require.True(t, ok)
	require.Zero(t, enforcementCount(t, ctx, db, `SELECT count(*) FROM escalation_policy_steps WHERE id=$1`, f.step))
	require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM users WHERE id=$1`, f.user))
	require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM schedules WHERE id=$1`, f.schedule))
	// The frozen Collector deliberately cannot map real RotationState. This
	// batch must fail closed without deleting either explicit root.
	input = []assignment.RawTarget{{Type: assignment.TargetTypeSchedule, ID: f.schedule.String()}, {Type: assignment.TargetTypeRotation, ID: f.rotation.String()}}
	_, err = app.Mutation().DeleteAll(ctx, input, nil)
	enforceCode(t, err, ds.DeletionUnavailable)
	require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM schedules WHERE id=$1`, f.schedule))
	require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM rotations WHERE id=$1`, f.rotation))
	input = []assignment.RawTarget{{Type: assignment.TargetTypeSchedule, ID: f.schedule.String()}}
	confirm = enforcementPreview(t, ctx, app, graphql2.DeletionResourceInput{Type: graphql2.DeletionTargetTypeSchedule, ID: f.schedule.String()})
	ok, err = app.Mutation().DeleteAll(ctx, input, confirm)
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM rotations WHERE id=$1`, f.rotation))
	require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM users WHERE id=$1`, f.user))

	// Runtime state is explicitly unsupported. In the separate, genuinely empty
	// runtime-state case the accepted Collector can prove Participant cascades.
	enforcementExec(t, ctx, db, `DELETE FROM rotation_state WHERE rotation_id=$1`, f.rotation)
	confirm = enforcementPreview(t, ctx, app, graphql2.DeletionResourceInput{Type: graphql2.DeletionTargetTypeRotation, ID: f.rotation.String()})
	ok, err = app.Mutation().DeleteAll(ctx, []assignment.RawTarget{{Type: assignment.TargetTypeRotation, ID: f.rotation.String()}}, confirm)
	require.NoError(t, err)
	require.True(t, ok)
	require.Zero(t, enforcementCount(t, ctx, db, `SELECT count(*) FROM rotation_participants WHERE rotation_id=$1`, f.rotation))
	require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM users WHERE id=$1`, f.user))

}

func TestPostgresDeletionEnforcementUserAndUnsupported(t *testing.T) {
	ctx, _, db := boundedAuditDB(t, len(Names()))
	f := newDeletionFixture(t, ctx, db)
	ctx = permission.SystemContext(ctx, "DeletionEnforcementTest")
	app := enforcementApp(t, ctx, db)
	// Existing JSON references are visible and BLOCK. Even an otherwise empty User
	// graph remains unavailable until the separate writer protocol is implemented.
	fresh := uuid.New()
	enforcementExec(t, ctx, db, `INSERT INTO users(id,name,role) VALUES($1,'synthetic empty user','user')`, fresh)
	// Reuse the fixture's fully validated assignment shape.
	enforcementExec(t, ctx, db, `INSERT INTO user_organization_assignments(user_id,source_config_version,effective_organization_id,effective_organization_classification,effective_normal_organization_id,organization_role,mapping_outcome,matched_count,authoritative_evaluated_at) SELECT $1,source_config_version,effective_organization_id,effective_organization_classification,effective_normal_organization_id,organization_role,mapping_outcome,matched_count,authoritative_evaluated_at FROM user_organization_assignments WHERE user_id=$2`, fresh, f.user)
	_, err := app.Mutation().DeleteAll(ctx, []assignment.RawTarget{{Type: assignment.TargetTypeUser, ID: fresh.String()}}, nil)
	enforceCode(t, err, ds.DeletionUnavailable)
	enforcementExec(t, ctx, db, `INSERT INTO labels(key,value,tgt_schedule_id) VALUES('synthetic','unsupported',$1)`, f.schedule)
	_, err = app.Mutation().DeleteAll(ctx, []assignment.RawTarget{{Type: assignment.TargetTypeSchedule, ID: f.schedule.String()}}, nil)
	enforceCode(t, err, ds.DeletionUnavailable)
	require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM users WHERE id=$1`, fresh))
}

// Explicit barriers use completed SQL statements and server lock observations;
// no sleep or timing assumption is used to establish Writer/Delete order.
func TestPostgresDeletionEnforcementFencesAndCarriers(t *testing.T) {
	ctx, _, db := boundedAuditDB(t, len(Names()))
	f := newDeletionFixture(t, ctx, db)
	ctx = permission.SystemContext(ctx, "DeletionEnforcementTest")
	app := enforcementApp(t, ctx, db)
	safe := ds.Resource{Kind: ds.ResourceIntegrationKey, ID: f.keyAudit.String()}
	result, err := collectDeletion(t, ctx, db, safe, collector.Limits{})
	require.NoError(t, err)
	plan := deletionPlan(t, safe, result)
	selectors := []collector.Selector{{Kind: ds.ResourceIntegrationKey, ID: f.key.String()}}
	tx, err := db.BeginTx(ctx, nil)
	require.NoError(t, err)
	guarded, err := collector.Enforce(ctx, tx, selectors, plan.ImpactVersion(), true, authorizeDeletionFixture(safe))
	require.NoError(t, err)
	other, err := db.BeginTx(ctx, nil)
	require.NoError(t, err)
	enforceCode(t, guard.RequireDelete(guarded, other, ds.ResourceIntegrationKey, []string{f.key.String()}), ds.DeletionUnavailable)
	enforceCode(t, guard.RequireDelete(guarded, tx, ds.ResourceIntegrationKey, []string{uuid.NewString()}), ds.DeletionUnavailable)
	enforceCode(t, guard.RequireDelete(ctx, tx, ds.ResourceIntegrationKey, []string{f.key.String()}), ds.DeletionUnavailable)
	require.NoError(t, other.Rollback())
	writer, err := db.BeginTx(ctx, nil)
	require.NoError(t, err)
	var pid int
	require.NoError(t, writer.QueryRowContext(ctx, `SELECT pg_backend_pid()`).Scan(&pid))
	done := make(chan error, 1)
	go func() {
		_, e := writer.ExecContext(ctx, `UPDATE integration_keys SET service_id=$1 WHERE id=$2`, f.service, f.key)
		done <- e
	}()
	// A lock waiter is observed by PostgreSQL itself, not inferred from elapsed time.
	for {
		var waiting bool
		require.NoError(t, db.QueryRowContext(ctx, `SELECT EXISTS(SELECT FROM pg_locks WHERE pid=$1 AND NOT granted)`, pid).Scan(&waiting))
		if waiting {
			break
		}
		require.NoError(t, ctx.Err())
	}
	receipts, err := app.IntKeyStore.DeleteManyForAuditTx(guarded, tx, []string{f.key.String()}, nil)
	require.NoError(t, err)
	require.Len(t, receipts, 1)
	require.Equal(t, f.keyAudit, receipts[0].ResourceID)
	enforceCode(t, guard.RequireDelete(guarded, tx, ds.ResourceIntegrationKey, []string{f.key.String()}), ds.DeletionUnavailable)
	require.NoError(t, tx.Rollback())
	require.NoError(t, <-done)
	require.NoError(t, writer.Rollback())
	enforceCode(t, guard.RequireDelete(guarded, tx, ds.ResourceIntegrationKey, []string{f.key.String()}), ds.DeletionUnavailable)
	require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM integration_keys WHERE audit_resource_id=$1`, f.keyAudit))
	// A savepoint rollback can release locks without ending the Go transaction.
	// The old carrier must still be unusable after that release.
	tx, err = db.BeginTx(ctx, nil)
	require.NoError(t, err)
	_, err = tx.ExecContext(ctx, `SAVEPOINT before_fence`)
	require.NoError(t, err)
	guarded, err = collector.Enforce(ctx, tx, selectors, plan.ImpactVersion(), true, authorizeDeletionFixture(safe))
	require.NoError(t, err)
	_, err = tx.ExecContext(ctx, `ROLLBACK TO SAVEPOINT before_fence`)
	require.NoError(t, err)
	enforceCode(t, guard.RequireDelete(guarded, tx, ds.ResourceIntegrationKey, []string{f.key.String()}), ds.DeletionUnavailable)
	require.NoError(t, tx.Rollback())
	// Writer owns a conflicting table lock FIRST: NOWAIT fails closed and never DMLs.
	writer, err = db.BeginTx(ctx, nil)
	require.NoError(t, err)
	_, err = writer.ExecContext(ctx, `UPDATE services SET name=name WHERE id=$1`, f.service)
	require.NoError(t, err)
	tx, err = db.BeginTx(ctx, nil)
	require.NoError(t, err)
	_, err = collector.Enforce(ctx, tx, selectors, plan.ImpactVersion(), true, authorizeDeletionFixture(safe))
	enforceCode(t, err, ds.DeletionUnavailable)
	require.NoError(t, tx.Rollback())
	require.NoError(t, writer.Commit())
}

func TestPostgresDeletionEnforcementRollbackAndStoreBypass(t *testing.T) {
	ctx, _, db := boundedAuditDB(t, len(Names()))
	f := newDeletionFixture(t, ctx, db)
	ctx = permission.SystemContext(ctx, "DeletionEnforcementTest")
	app := enforcementApp(t, ctx, db)
	tx, err := db.BeginTx(ctx, nil)
	require.NoError(t, err)
	for name, call := range map[string]func() error{
		"Service":  func() error { return app.ServiceStore.DeleteManyTx(ctx, tx, []string{f.service.String()}, nil) },
		"EP":       func() error { return app.PolicyStore.DeleteManyPoliciesTx(ctx, tx, []string{f.policy.String()}, nil) },
		"Schedule": func() error { return app.ScheduleStore.DeleteManyTx(ctx, tx, []string{f.schedule.String()}, nil) },
		"Rotation": func() error { return app.RotationStore.DeleteManyTx(ctx, tx, []string{f.rotation.String()}, nil) },
		"CM":       func() error { return app.CMStore.Delete(ctx, tx, f.cm.String()) },
		"NR":       func() error { return app.NRStore.DeleteTx(ctx, tx, f.nr.String()) },
		"Key":      func() error { return app.IntKeyStore.DeleteMany(ctx, tx, []string{f.key.String()}, nil) },
		"Override": func() error { return app.OverrideStore.DeleteUserOverrideTx(ctx, tx, f.override.String()) },
		"User":     func() error { return app.UserStore.DeleteManyTx(ctx, tx, []string{f.user.String()}) },
	} {
		t.Run(name, func(t *testing.T) { enforceCode(t, call(), ds.DeletionUnavailable) })
	}
	require.NoError(t, tx.Rollback())
	// A later EP group fails after a legal earlier override DELETE. Both the
	// business mutation and its success audit must roll back atomically.
	input := []assignment.RawTarget{{Type: assignment.TargetTypeUserOverride, ID: f.override.String()}, {Type: assignment.TargetTypeIntegrationKey, ID: f.key.String()}}
	confirm := enforcementPreview(t, ctx, app, graphql2.DeletionResourceInput{Type: graphql2.DeletionTargetTypeUserOverride, ID: f.override.String()}, graphql2.DeletionResourceInput{Type: graphql2.DeletionTargetTypeIntegrationKey, ID: f.keyAudit.String()})
	enforcementExec(t, ctx, db, `CREATE FUNCTION synthetic_later_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'SYNTHETIC_PRIVATE'; END $$`)
	enforcementExec(t, ctx, db, `CREATE TRIGGER synthetic_later_failure BEFORE DELETE ON integration_keys FOR EACH ROW EXECUTE FUNCTION synthetic_later_failure()`)
	ok, err := app.Mutation().DeleteAll(ctx, input, confirm)
	require.False(t, ok)
	require.Error(t, err)
	require.NotContains(t, err.Error(), "SYNTHETIC_PRIVATE")
	require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM user_overrides WHERE id=$1`, f.override))
	require.Zero(t, enforcementCount(t, ctx, db, `SELECT count(*) FROM user_override_delete_audit_events WHERE outcome='committed'`))
}

func TestPostgresDeletionEnforcementServicePolicyAndAuditFailure(t *testing.T) {
	ctx, _, db := boundedAuditDB(t, len(Names()))
	f := newDeletionFixture(t, ctx, db)
	ctx = permission.SystemContext(ctx, "DeletionEnforcementTest")
	app := enforcementApp(t, ctx, db)
	input := []assignment.RawTarget{{Type: assignment.TargetTypeService, ID: f.service.String()}, {Type: assignment.TargetTypeEscalationPolicy, ID: f.policy.String()}}
	// BLOCK cannot be overridden by a guessed version or acknowledgement.
	_, err := app.Mutation().DeleteAll(ctx, input, &graphql2.DeletionSafetyConfirmationInput{ExpectedImpactVersion: "guessed", AcknowledgeImpacts: true})
	enforceCode(t, err, ds.DeletionBlocked)
	enforcementExec(t, ctx, db, `UPDATE alerts SET status='closed' WHERE service_id=$1 AND status<>'closed'`, f.service)
	_, err = app.Mutation().DeleteAll(ctx, input, nil)
	enforceCode(t, err, ds.DeletionConfirmationRequired)
	confirm := enforcementPreview(t, ctx, app, graphql2.DeletionResourceInput{Type: graphql2.DeletionTargetTypeService, ID: f.service.String()}, graphql2.DeletionResourceInput{Type: graphql2.DeletionTargetTypeEscalationPolicy, ID: f.policy.String()})
	// Audit append failure occurs after the actual DELETEs. It must roll every
	// business group back and must not become DEPENDENCY_CHANGED.
	enforcementExec(t, ctx, db, `CREATE FUNCTION synthetic_audit_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.outcome='committed' THEN RAISE EXCEPTION 'SYNTHETIC_PRIVATE_AUDIT'; END IF; RETURN NEW; END $$`)
	enforcementExec(t, ctx, db, `CREATE TRIGGER synthetic_audit_failure BEFORE INSERT ON service_delete_audit_events FOR EACH ROW EXECUTE FUNCTION synthetic_audit_failure()`)
	ok, err := app.Mutation().DeleteAll(ctx, input, confirm)
	require.False(t, ok)
	require.Error(t, err)
	var typed *ds.DeletionSafetyError
	require.NotErrorAs(t, err, &typed)
	require.NotContains(t, err.Error(), "SYNTHETIC_PRIVATE")
	require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM services WHERE id=$1`, f.service))
	require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM escalation_policies WHERE id=$1`, f.policy))
	require.Zero(t, enforcementCount(t, ctx, db, `SELECT count(*) FROM service_delete_audit_events WHERE outcome='committed'`))
	enforcementExec(t, ctx, db, `DROP TRIGGER synthetic_audit_failure ON service_delete_audit_events`)
	ok, err = app.Mutation().DeleteAll(ctx, input, confirm)
	require.NoError(t, err)
	require.True(t, ok)
	require.Zero(t, enforcementCount(t, ctx, db, `SELECT count(*) FROM services WHERE id=$1`, f.service))
	require.Zero(t, enforcementCount(t, ctx, db, `SELECT count(*) FROM escalation_policies WHERE id=$1`, f.policy))
	var audit string
	require.NoError(t, db.QueryRowContext(ctx, `SELECT effects::text FROM service_delete_audit_events WHERE outcome='committed'`).Scan(&audit))
	require.Contains(t, audit, f.keyAudit.String())
	require.NotContains(t, audit, f.key.String())
	require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM escalation_policy_delete_audit_events WHERE outcome='committed'`))
}

func TestPostgresDeletionEnforcementFreshWriterChanges(t *testing.T) {
	ctx, _, db := boundedAuditDB(t, len(Names()))
	f := newDeletionFixture(t, ctx, db)
	ctx = permission.SystemContext(ctx, "DeletionEnforcementTest")
	app := enforcementApp(t, ctx, db)
	// The completed writer COMMIT is the deterministic pre-delete barrier.
	fresh := uuid.New()
	enforcementExec(t, ctx, db, `INSERT INTO escalation_policies(id,organization_id,name) VALUES($1,$2,($1::uuid)::text)`, fresh, f.org)
	confirm := enforcementPreview(t, ctx, app, graphql2.DeletionResourceInput{Type: graphql2.DeletionTargetTypeEscalationPolicy, ID: fresh.String()})
	writer, err := db.BeginTx(ctx, nil)
	require.NoError(t, err)
	_, err = writer.ExecContext(ctx, `INSERT INTO services(id,organization_id,name,escalation_policy_id) VALUES($1,$2,($1::uuid)::text,$3)`, uuid.New(), f.org, fresh)
	require.NoError(t, err)
	require.NoError(t, writer.Commit())
	_, err = app.Mutation().DeleteAll(ctx, []assignment.RawTarget{{Type: assignment.TargetTypeEscalationPolicy, ID: fresh.String()}}, confirm)
	enforceCode(t, err, ds.DeletionBlocked)
	require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM escalation_policies WHERE id=$1`, fresh))
	// Parent/endpoint retarget with the SAME number of references changes version.
	input := []assignment.RawTarget{{Type: assignment.TargetTypeIntegrationKey, ID: f.key.String()}}
	confirm = enforcementPreview(t, ctx, app, graphql2.DeletionResourceInput{Type: graphql2.DeletionTargetTypeIntegrationKey, ID: f.keyAudit.String()})
	other := uuid.New()
	enforcementExec(t, ctx, db, `INSERT INTO services(id,organization_id,name,escalation_policy_id) VALUES($1,$2,($1::uuid)::text,$3)`, other, f.org, fresh)
	enforcementExec(t, ctx, db, `UPDATE integration_keys SET service_id=$1 WHERE id=$2`, other, f.key)
	_, err = app.Mutation().DeleteAll(ctx, input, confirm)
	enforceCode(t, err, ds.DeletionDependencyChanged)
	require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM integration_keys WHERE id=$1 AND service_id=$2`, f.key, other))
	// Closed preview followed by an active alert must BLOCK, even with confirmation.
	enforcementExec(t, ctx, db, `UPDATE alerts SET status='closed' WHERE service_id=$1 AND status<>'closed'`, f.service)
	confirm = enforcementPreview(t, ctx, app, graphql2.DeletionResourceInput{Type: graphql2.DeletionTargetTypeService, ID: f.service.String()})
	enforcementExec(t, ctx, db, `INSERT INTO alerts(service_id,status,dedup_key,summary) VALUES($1,'triggered',$2,'synthetic new active')`, f.service, uuid.NewString())
	_, err = app.Mutation().DeleteAll(ctx, []assignment.RawTarget{{Type: assignment.TargetTypeService, ID: f.service.String()}}, confirm)
	enforceCode(t, err, ds.DeletionBlocked)
	require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM services WHERE id=$1`, f.service))
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

func TestPostgresDeletionEnforcementGraphQLAndAuthority(t *testing.T) {
	ctx, _, db := boundedAuditDB(t, len(Names()))
	f := newDeletionFixture(t, ctx, db)
	ctx = permission.SystemContext(ctx, "DeletionEnforcementTest")
	app := enforcementApp(t, ctx, db)
	cm := []assignment.RawTarget{{Type: assignment.TargetTypeContactMethod, ID: f.cm.String()}}
	require.Contains(t, enforcementHTTP(t, ctx, app, cm, nil, true), string(ds.DeletionConfirmationRequired))
	require.Contains(t, enforcementHTTP(t, ctx, app, cm, &graphql2.DeletionSafetyConfirmationInput{ExpectedImpactVersion: "stale", AcknowledgeImpacts: true}, false), string(ds.DeletionDependencyChanged))
	require.Contains(t, enforcementHTTP(t, ctx, app, []assignment.RawTarget{{Type: assignment.TargetTypeService, ID: f.service.String()}}, nil, true), string(ds.DeletionBlocked))
	large := make([]assignment.RawTarget, 101)
	for i := range large {
		typ := assignment.TargetTypeContactMethod
		if i >= 50 {
			typ = assignment.TargetTypeNotificationRule
		}
		if i == 100 {
			typ = assignment.TargetTypeService
		}
		large[i] = assignment.RawTarget{Type: typ, ID: uuid.NewString()}
	}
	require.Contains(t, enforcementHTTP(t, ctx, app, large, nil, true), string(ds.DeletionPreviewLimitExceeded))
	enforcementExec(t, ctx, db, `INSERT INTO labels(key,value,tgt_schedule_id) VALUES('synthetic','unsupported',$1)`, f.schedule)
	require.Contains(t, enforcementHTTP(t, ctx, app, []assignment.RawTarget{{Type: assignment.TargetTypeSchedule, ID: f.schedule.String()}}, nil, true), string(ds.DeletionUnavailable))
	simple := uuid.New()
	enforcementExec(t, ctx, db, `INSERT INTO services(id,organization_id,name,escalation_policy_id) VALUES($1,$2,($1::uuid)::text,$3)`, simple, f.org, f.policy)
	enforcementExec(t, ctx, db, `INSERT INTO alerts(service_id,status,dedup_key,summary) VALUES($1,'triggered',$2,'synthetic simple alert')`, simple, uuid.NewString())
	// Existing persisted Home/capability authority is required. Confirmation never
	// grants management privileges, and a role change invalidates stale admission.
	human := previewAdmit(t, context.Background(), db, f.actor)
	for _, id := range []string{f.user.String(), uuid.NewString()} {
		_, denied := app.Mutation().DeleteAll(human, []assignment.RawTarget{{Type: assignment.TargetTypeUser, ID: id}}, nil)
		require.True(t, permission.IsPermissionError(denied))
	}

	_, err := app.Mutation().DeleteAll(human, []assignment.RawTarget{{Type: assignment.TargetTypeService, ID: simple.String()}}, nil)
	require.True(t, permission.IsPermissionError(err))
	enforcementExec(t, ctx, db, `UPDATE user_organization_assignments SET organization_role='ORG_ADMIN' WHERE user_id=$1`, f.actor)
	human = previewAdmit(t, context.Background(), db, f.actor)
	_, err = app.Mutation().DeleteAll(human, []assignment.RawTarget{{Type: assignment.TargetTypeService, ID: simple.String()}}, nil)
	enforceCode(t, err, ds.DeletionBlocked)
	enforcementExec(t, ctx, db, `UPDATE user_organization_assignments SET organization_role='ORG_MEMBER' WHERE user_id=$1`, f.actor)
	_, err = app.Mutation().DeleteAll(human, []assignment.RawTarget{{Type: assignment.TargetTypeService, ID: simple.String()}}, nil)
	enforceCode(t, err, ds.DeletionUnavailable)
	require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM services WHERE id=$1`, simple))
}

func TestPostgresDeletionEnforcementAfterRootLockWait(t *testing.T) {
	ctx, _, db := boundedAuditDB(t, len(Names()))
	f := newDeletionFixture(t, ctx, db)
	enforcementExec(t, ctx, db, `UPDATE user_organization_assignments SET organization_role='ORG_ADMIN' WHERE user_id=$1`, f.actor)
	ctx = previewAdmit(t, ctx, db, f.actor)
	app := enforcementApp(t, ctx, db)
	root := uuid.New()
	rule := uuid.New()
	enforcementExec(t, ctx, db, `INSERT INTO rotations(id,organization_id,name,type,time_zone) VALUES($1,$2,($1::uuid)::text,'daily','UTC')`, root, f.org)
	confirm := enforcementPreview(t, ctx, app, graphql2.DeletionResourceInput{Type: graphql2.DeletionTargetTypeRotation, ID: root.String()})
	writer, err := db.BeginTx(ctx, nil)
	require.NoError(t, err)
	var pid int
	require.NoError(t, writer.QueryRowContext(ctx, `SELECT pg_backend_pid()`).Scan(&pid))
	var locked uuid.UUID
	require.NoError(t, writer.QueryRowContext(ctx, `SELECT id FROM rotations WHERE id=$1 FOR UPDATE`, root).Scan(&locked))
	done := make(chan error, 1)
	go func() {
		_, e := app.Mutation().DeleteAll(ctx, []assignment.RawTarget{{Type: assignment.TargetTypeRotation, ID: root.String()}}, confirm)
		done <- e
	}()
	for {
		var waiting bool
		require.NoError(t, db.QueryRowContext(ctx, `SELECT EXISTS(SELECT FROM pg_stat_activity WHERE $1=ANY(pg_blocking_pids(pid)))`, pid).Scan(&waiting))
		if waiting {
			break
		}
		require.NoError(t, ctx.Err())
	}
	// The writer owns the original root lock and can add an FK reference. Delete
	// must re-read it after waiting and cannot use the earlier empty preview.
	_, err = writer.ExecContext(ctx, `INSERT INTO schedule_rules(id,schedule_id,tgt_rotation_id) VALUES($1,$2,$3)`, rule, f.schedule, root)
	require.NoError(t, err)
	require.NoError(t, writer.Commit())
	enforceCode(t, <-done, ds.DeletionBlocked)
	require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM rotations WHERE id=$1`, root))
	require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM schedule_rules WHERE id=$1 AND tgt_rotation_id=$2`, rule, root))
	require.Zero(t, enforcementCount(t, ctx, db, `SELECT count(*) FROM schedule_rotation_delete_audit_events WHERE root_id=$1 AND outcome='committed'`, root))
}

func TestPostgresDeletionEnforcementLockTimeoutAndDeadlock(t *testing.T) {
	ctx, uri, db := boundedAuditDB(t, len(Names()))
	f := newDeletionFixture(t, ctx, db)
	enforcementExec(t, ctx, db, `UPDATE user_organization_assignments SET organization_role='ORG_ADMIN' WHERE user_id=$1`, f.actor)
	ctx = previewAdmit(t, ctx, db, f.actor)
	app := enforcementApp(t, ctx, db)
	for _, mode := range []string{"timeout", "deadlock"} {
		t.Run(mode, func(t *testing.T) {
			root := uuid.New()
			rule := uuid.New()
			enforcementExec(t, ctx, db, `INSERT INTO rotations(id,organization_id,name,type,time_zone) VALUES($1,$2,($1::uuid)::text,'daily','UTC')`, root, f.org)
			confirm := enforcementPreview(t, ctx, app, graphql2.DeletionResourceInput{Type: graphql2.DeletionTargetTypeRotation, ID: root.String()})
			writer, err := db.BeginTx(ctx, nil)
			require.NoError(t, err)
			defer func() { _ = writer.Rollback() }()
			var pid int
			require.NoError(t, writer.QueryRowContext(ctx, `SELECT pg_backend_pid()`).Scan(&pid))
			var locked uuid.UUID
			require.NoError(t, writer.QueryRowContext(ctx, `SELECT id FROM rotations WHERE id=$1 FOR UPDATE`, root).Scan(&locked))
			if mode == "timeout" {
				conf, err := pgx.ParseConfig(uri)
				require.NoError(t, err)
				conf.RuntimeParams["lock_timeout"] = "100ms"
				limited := sql.OpenDB(stdlib.GetConnector(*conf))
				defer limited.Close()
				limitedApp := enforcementApp(t, ctx, limited)
				ok, err := limitedApp.Mutation().DeleteAll(ctx, []assignment.RawTarget{{Type: assignment.TargetTypeRotation, ID: root.String()}}, confirm)
				require.False(t, ok)
				require.Error(t, err)
				require.NotContains(t, err.Error(), "SQLSTATE")
				require.NoError(t, writer.Rollback())
				require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM rotations WHERE id=$1`, root))
				require.Zero(t, enforcementCount(t, ctx, db, `SELECT count(*) FROM schedule_rotation_delete_audit_events WHERE root_id=$1 AND outcome='committed'`, root))
				return
			}
			_, err = writer.ExecContext(ctx, `SET LOCAL deadlock_timeout='50ms'`)
			require.NoError(t, err)
			done := make(chan error, 1)
			go func() {
				_, e := app.Mutation().DeleteAll(ctx, []assignment.RawTarget{{Type: assignment.TargetTypeRotation, ID: root.String()}}, confirm)
				done <- e
			}()
			for {
				var waiting bool
				require.NoError(t, db.QueryRowContext(ctx, `SELECT EXISTS(SELECT FROM pg_stat_activity WHERE $1=ANY(pg_blocking_pids(pid)))`, pid).Scan(&waiting))
				if waiting {
					break
				}
				require.NoError(t, ctx.Err())
			}
			// Delete owns the inherited advisory lock and waits for our root. Requesting
			// that advisory lock completes a real PostgreSQL deadlock, with either victim
			// permitted. No timing assumption is used to create the dependency cycle.
			_, writerErr := writer.ExecContext(ctx, `SELECT pg_advisory_xact_lock(1297305411::integer,1396979713::integer)`)
			if writerErr == nil {
				_, err = writer.ExecContext(ctx, `INSERT INTO schedule_rules(id,schedule_id,tgt_rotation_id) VALUES($1,$2,$3)`, rule, f.schedule, root)
				require.NoError(t, err)
				require.NoError(t, writer.Commit())
			} else {
				var pg *pgconn.PgError
				require.True(t, errors.As(writerErr, &pg))
				require.Equal(t, "40P01", pg.Code)
				require.NoError(t, writer.Rollback())
			}
			deleteErr := <-done
			if writerErr == nil {
				require.Error(t, deleteErr)
				require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM schedule_rules WHERE id=$1`, rule))
				require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM rotations WHERE id=$1`, root))
				require.Zero(t, enforcementCount(t, ctx, db, `SELECT count(*) FROM schedule_rotation_delete_audit_events WHERE root_id=$1 AND outcome='committed'`, root))
			} else {
				require.NoError(t, deleteErr)
				require.Zero(t, enforcementCount(t, ctx, db, `SELECT count(*) FROM rotations WHERE id=$1`, root))
				require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM schedule_rotation_delete_audit_events WHERE root_id=$1 AND outcome='committed'`, root))
			}
		})
	}
}
