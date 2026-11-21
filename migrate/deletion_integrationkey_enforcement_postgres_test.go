package migrate

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/alert/alertlog"
	"github.com/target/goalert/assignment"
	ds "github.com/target/goalert/deletionsafety"
	collector "github.com/target/goalert/deletionsafety/postgres"
	"github.com/target/goalert/expflag"
	"github.com/target/goalert/gadb"
	"github.com/target/goalert/graphql2"
	"github.com/target/goalert/integrationkey"
	keyaudit "github.com/target/goalert/integrationkey/deleteaudit"
	guard "github.com/target/goalert/internal/deletionguard"
	"github.com/target/goalert/permission"
)

type keyProfileFixture struct {
	serviceProfileFixture
	credential, safe uuid.UUID
}

func keyProfileFixtureFor(t *testing.T, ctx context.Context, db *sql.DB, kind integrationkey.Type) keyProfileFixture {
	t.Helper()
	f := keyProfileFixture{serviceProfileFixture: newServiceProfileFixture(t, ctx, db)}
	f.credential, f.safe = keyProfileCreate(t, ctx, db, f.service, f.org, kind)
	return f
}

// Every success fixture uses the production Store, including its generated
// credential, default audit identity and type-specific configuration lifecycle.
func keyProfileCreate(t *testing.T, ctx context.Context, db *sql.DB, service, org uuid.UUID, kind integrationkey.Type) (uuid.UUID, uuid.UUID) {
	t.Helper()
	app := enforcementApp(t, ctx, db)
	ctx = expflag.Context(ctx, expflag.FlagSet{expflag.UnivKeys})
	k, err := app.IntKeyStore.Create(ctx, db, &integrationkey.IntegrationKey{Name: "key-" + uuid.NewString(), ServiceID: service.String(), Type: kind}, &org)
	require.NoError(t, err)
	id := uuid.MustParse(k.ID)
	var safe uuid.UUID
	require.NoError(t, db.QueryRowContext(ctx, `SELECT audit_resource_id FROM integration_keys WHERE id=$1`, id).Scan(&safe))
	require.True(t, safe != id && safe != uuid.Nil)
	return id, safe
}

func keyProfileRoot(id uuid.UUID) ds.Resource {
	return ds.Resource{Kind: ds.ResourceIntegrationKey, ID: id.String()}
}
func keyProfileSelectors(ids ...uuid.UUID) []collector.Selector {
	var raw []collector.Selector
	for _, id := range ids {
		raw = append(raw, collector.Selector{Kind: ds.ResourceIntegrationKey, ID: id.String()})
	}
	return raw
}
func keyProfileInput(ids ...uuid.UUID) []assignment.RawTarget {
	var raw []assignment.RawTarget
	for _, id := range ids {
		raw = append(raw, assignment.RawTarget{Type: assignment.TargetTypeIntegrationKey, ID: id.String()})
	}
	return raw
}
func keyProfilePreview(ids ...uuid.UUID) []graphql2.DeletionResourceInput {
	var raw []graphql2.DeletionResourceInput
	for _, id := range ids {
		raw = append(raw, graphql2.DeletionResourceInput{Type: graphql2.DeletionTargetTypeIntegrationKey, ID: id.String()})
	}
	return raw
}
func keyProfileVersion(t *testing.T, ctx context.Context, db *sql.DB, safe uuid.UUID) string {
	t.Helper()
	facts, err := collectDeletion(t, ctx, db, keyProfileRoot(safe), collector.Limits{})
	require.NoError(t, err)
	return deletionPlan(t, keyProfileRoot(safe), facts).ImpactVersion()
}
func keyProfileEnforce(t *testing.T, ctx context.Context, tx *sql.Tx, f keyProfileFixture, version string) context.Context {
	t.Helper()
	bound, err := collector.Enforce(ctx, tx, keyProfileSelectors(f.credential), version, true, authorizeDeletionFixture(keyProfileRoot(f.safe)))
	require.NoError(t, err)
	return bound
}
func keyProfileNoSuccess(t *testing.T, ctx context.Context, db *sql.DB) {
	t.Helper()
	require.Zero(t, enforcementCount(t, ctx, db, `SELECT count(*) FROM integration_key_delete_audit_events WHERE outcome='committed'`))
}
func keyProfileRetained(t *testing.T, ctx context.Context, db *sql.DB, f keyProfileFixture) {
	t.Helper()
	for _, q := range []struct {
		table string
		id    uuid.UUID
	}{{"services", f.service}, {"escalation_policies", f.policy}, {"schedules", f.schedule}, {"rotations", f.rotation}, {"users", f.user}} {
		require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM `+q.table+` WHERE id=$1`, q.id))
	}
	serviceProfileNoSuccess(t, ctx, db)
}

func TestPostgresDeletionEnforcementIntegrationKeyBusiness(t *testing.T) {
	base, _, db := boundedAuditDB(t, len(Names()))
	ctx := permission.SystemContext(base, "KeyProfileTest")
	app := enforcementApp(t, ctx, db)
	for _, kind := range []integrationkey.Type{integrationkey.TypeGeneric, integrationkey.TypeGrafana, integrationkey.TypeSite24x7, integrationkey.TypeEmail, integrationkey.TypePrometheusAlertmanager} {
		t.Run(string(kind), func(t *testing.T) {
			f := keyProfileFixtureFor(t, ctx, db, kind)
			other, _ := keyProfileCreate(t, ctx, db, f.service, f.org, kind)
			human := previewAdmit(t, base, db, f.actor)
			_, err := app.Mutation().DeleteAll(human, keyProfileInput(f.credential), nil)
			enforceCode(t, err, ds.DeletionConfirmationRequired)
			confirm := enforcementPreview(t, human, app, keyProfilePreview(f.safe)...)
			stale := *confirm
			stale.ExpectedImpactVersion = "stale"
			_, err = app.Mutation().DeleteAll(human, keyProfileInput(f.credential), &stale)
			enforceCode(t, err, ds.DeletionDependencyChanged)
			_, err = app.Mutation().DeleteAll(human, keyProfileInput(f.credential, f.credential, uuid.New(), uuid.Nil), confirm)
			require.NoError(t, err)
			require.Zero(t, enforcementCount(t, ctx, db, `SELECT count(*) FROM integration_keys WHERE audit_resource_id=$1`, f.safe))
			require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM integration_keys WHERE id=$1`, other))
			keyProfileRetained(t, ctx, db, f)
			var event keyaudit.Event
			require.NoError(t, db.QueryRowContext(ctx, `SELECT schema_version,event_id,request_id,execution_id,attempt_id,record_kind,root_resource_id,parent_service_id,target_organization_id,target_org_resolution,provenance,deletion_mechanism,cause,actor_kind,actor_id,home_organization_id,authority_source,authority_role,organization_role,outcome,reason_code,occurred_at FROM integration_key_delete_audit_events WHERE root_resource_id=$1 AND outcome='committed'`, f.safe).Scan(&event.SchemaVersion, &event.EventID, &event.RequestID, &event.ExecutionID, &event.AttemptID, &event.RecordKind, &event.ResourceID, &event.ParentServiceID, &event.TargetOrganizationID, &event.TargetOrgResolution, &event.Provenance, &event.DeletionMechanism, &event.Cause, &event.ActorKind, &event.ActorID, &event.HomeOrganizationID, &event.AuthoritySource, &event.AuthorityRole, &event.OrganizationRole, &event.Outcome, &event.Reason, &event.OccurredAt))
			require.NoError(t, event.Validate())
			require.Equal(t, f.safe, event.ResourceID)
			require.Equal(t, f.service, event.ParentServiceID)
			require.Equal(t, f.org, event.TargetOrganizationID)
			require.Equal(t, "EXPLICIT", event.Provenance)
			require.Equal(t, "explicit_sql", event.DeletionMechanism)
			require.Equal(t, "explicit_target", event.Cause)
			_, err = app.Mutation().DeleteAll(human, keyProfileInput(f.credential), confirm)
			enforceCode(t, err, ds.DeletionDependencyChanged)
			_, err = app.Mutation().DeleteAll(human, keyProfileInput(f.credential), nil)
			require.NoError(t, err)
		})
	}
}

func TestPostgresDeletionEnforcementIntegrationKeyHumanBatch(t *testing.T) {
	base, _, db := boundedAuditDB(t, len(Names()))
	ctx := permission.SystemContext(base, "KeyProfileTest")
	app := enforcementApp(t, ctx, db)
	f := keyProfileFixtureFor(t, ctx, db, integrationkey.TypeGeneric)
	service := uuid.New()
	serviceProfileInsert(t, ctx, db, service, f.org, f.policy)
	b, bs := keyProfileCreate(t, ctx, db, f.service, f.org, integrationkey.TypeGrafana)
	c, cs := keyProfileCreate(t, ctx, db, service, f.org, integrationkey.TypeEmail)
	human := previewAdmit(t, base, db, f.actor)
	confirm := enforcementPreview(t, human, app, keyProfilePreview(f.safe, bs, cs)...)
	_, err := app.Mutation().DeleteAll(human, keyProfileInput(f.credential, b, c, b, uuid.Nil), confirm)
	require.NoError(t, err)
	require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM (SELECT request_id,execution_id,attempt_id FROM integration_key_delete_audit_events WHERE outcome='committed' GROUP BY 1,2,3 HAVING count(*)=3) s`))
	require.Equal(t, 2, enforcementCount(t, ctx, db, `SELECT count(*) FROM services WHERE id IN ($1,$2)`, f.service, service))
}

func TestPostgresDeletionEnforcementIntegrationKeyCredentialAndHistory(t *testing.T) {
	ctx, _, db := boundedAuditDB(t, len(Names()))
	ctx = permission.SystemContext(ctx, "KeyProfileTest")
	app := enforcementApp(t, ctx, db)
	f := keyProfileFixtureFor(t, ctx, db, integrationkey.TypeGeneric)
	aid := serviceProfileAlert(t, ctx, db, f.service, "triggered")
	logs, err := alertlog.NewStore(ctx, db, nil)
	require.NoError(t, err)
	keyCtx := permission.ServiceSourceContext(ctx, f.service.String(), &permission.SourceInfo{Type: permission.SourceTypeIntegrationKey, ID: f.credential.String()})
	require.NoError(t, logs.LogTx(keyCtx, nil, int(aid), alertlog.TypeCreated, nil))
	var logID int
	require.NoError(t, db.QueryRowContext(ctx, `SELECT id FROM alert_logs WHERE alert_id=$1`, aid).Scan(&logID))
	facts, err := collectDeletion(t, ctx, db, keyProfileRoot(f.safe), collector.Limits{})
	require.NoError(t, err)
	raw, err := json.Marshal(facts.Collection)
	require.NoError(t, err)
	require.False(t, strings.Contains(string(raw), f.credential.String()), "credential in dependency projection")
	preview, err := app.Query().DeletionPreview(ctx, graphql2.DeletionPlanInput{Operation: graphql2.DeletionOperationDeleteResources, Targets: keyProfilePreview(f.safe)}, nil, nil)
	require.NoError(t, err)
	raw, err = json.Marshal(preview)
	require.NoError(t, err)
	require.False(t, strings.Contains(string(raw), f.credential.String()), "credential in preview")
	confirm := enforcementPreview(t, ctx, app, keyProfilePreview(f.safe)...)
	_, err = app.Mutation().DeleteAll(ctx, keyProfileInput(f.credential), confirm)
	require.NoError(t, err)
	require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM alerts WHERE id=$1 AND status='triggered'`, aid))
	entry, err := logs.FindOne(ctx, logID)
	require.NoError(t, err)
	require.Equal(t, int(aid), entry.AlertID())
	require.NotEmpty(t, entry.String(ctx))
	var audit string
	require.NoError(t, db.QueryRowContext(ctx, `SELECT to_jsonb(e)::text FROM integration_key_delete_audit_events e WHERE root_resource_id=$1`, f.safe).Scan(&audit))
	require.False(t, strings.Contains(audit, f.credential.String()), "credential in audit")
	// A newly started Store writer safely fails its type lookup. The original
	// generated INSERT can still finish a previously prepared historical log.
	err = logs.LogTx(keyCtx, nil, int(aid), alertlog.TypeCreated, nil)
	require.Error(t, err)
	require.False(t, strings.Contains(err.Error(), f.credential.String()))
	require.NoError(t, gadb.New(db).AlertLog_InsertMany(ctx, gadb.AlertLog_InsertManyParams{Column1: []int64{aid}, Event: gadb.EnumAlertLogEventCreated, SubIntegrationKeyID: uuid.NullUUID{UUID: f.credential, Valid: true}}))
	require.Equal(t, 2, enforcementCount(t, ctx, db, `SELECT count(*) FROM alert_logs WHERE alert_id=$1`, aid))
	keyProfileRetained(t, ctx, db, f)
}

func TestPostgresDeletionEnforcementIntegrationKeyAuditFailure(t *testing.T) {
	ctx, _, db := boundedAuditDB(t, len(Names()))
	ctx = permission.SystemContext(ctx, "KeyProfileTest")
	app := enforcementApp(t, ctx, db)
	f := keyProfileFixtureFor(t, ctx, db, integrationkey.TypeGeneric)
	other, safe := keyProfileCreate(t, ctx, db, f.service, f.org, integrationkey.TypeEmail)
	aid := serviceProfileAlert(t, ctx, db, f.service, "triggered")
	logs, err := alertlog.NewStore(ctx, db, nil)
	require.NoError(t, err)
	keyCtx := permission.ServiceSourceContext(ctx, f.service.String(), &permission.SourceInfo{Type: permission.SourceTypeIntegrationKey, ID: f.credential.String()})
	require.NoError(t, logs.LogTx(keyCtx, nil, int(aid), alertlog.TypeCreated, nil))
	confirm := enforcementPreview(t, ctx, app, keyProfilePreview(f.safe, safe)...)
	enforcementExec(t, ctx, db, `CREATE SEQUENCE key_delete_seen; CREATE FUNCTION key_append_fail() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.outcome='committed' THEN IF EXISTS(SELECT FROM integration_keys WHERE audit_resource_id=NEW.root_resource_id) THEN RAISE EXCEPTION 'delete not reached'; END IF; PERFORM nextval('key_delete_seen'); RAISE EXCEPTION 'synthetic audit fault'; END IF; RETURN NEW; END $$; CREATE TRIGGER key_append_fail BEFORE INSERT ON integration_key_delete_audit_events FOR EACH ROW EXECUTE FUNCTION key_append_fail()`)
	_, err = app.Mutation().DeleteAll(ctx, keyProfileInput(f.credential, other), confirm)
	require.Error(t, err)
	require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM key_delete_seen WHERE is_called`))
	require.Equal(t, 2, enforcementCount(t, ctx, db, `SELECT count(*) FROM integration_keys WHERE audit_resource_id IN ($1,$2)`, f.safe, safe))
	keyProfileNoSuccess(t, ctx, db)
	keyProfileRetained(t, ctx, db, f)
	require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM alerts WHERE id=$1 AND status='triggered'`, aid))
	require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM alert_logs WHERE alert_id=$1`, aid))
	enforcementExec(t, ctx, db, `DROP TRIGGER key_append_fail ON integration_key_delete_audit_events`)
	confirm = enforcementPreview(t, ctx, app, keyProfilePreview(f.safe, safe)...)
	_, err = app.Mutation().DeleteAll(ctx, keyProfileInput(f.credential, other), confirm)
	require.NoError(t, err)
	require.Equal(t, 2, enforcementCount(t, ctx, db, `SELECT count(*) FROM integration_key_delete_audit_events WHERE outcome='committed'`))
}

func TestPostgresDeletionEnforcementIntegrationKeyFailClosed(t *testing.T) {
	base, _, db := boundedAuditDB(t, len(Names()))
	ctx := permission.SystemContext(base, "KeyProfileTest")
	app := enforcementApp(t, ctx, db)
	for _, shape := range []string{"universal", "universal_missing_config", "orphan_history", "cross_org_history", "member", "foreign", "stale_actor", "mixed", "budget"} {
		t.Run(shape, func(t *testing.T) {
			kind := integrationkey.TypeGeneric
			if strings.HasPrefix(shape, "universal") {
				kind = integrationkey.TypeUniversal
			}
			f := keyProfileFixtureFor(t, ctx, db, kind)
			if shape == "universal_missing_config" {
				require.NoError(t, app.IntKeyStore.SetConfig(ctx, db, f.credential, nil))
			}
			use := ctx
			switch shape {
			case "orphan_history":
				require.NoError(t, gadb.New(db).AlertLog_InsertMany(ctx, gadb.AlertLog_InsertManyParams{Column1: []int64{99999999}, Event: gadb.EnumAlertLogEventCreated, SubIntegrationKeyID: uuid.NullUUID{UUID: f.credential, Valid: true}}))
			case "cross_org_history":
				g := newServiceProfileFixture(t, ctx, db)
				aid := serviceProfileAlert(t, ctx, db, g.service, "closed")
				require.NoError(t, gadb.New(db).AlertLog_InsertMany(ctx, gadb.AlertLog_InsertManyParams{Column1: []int64{aid}, Event: gadb.EnumAlertLogEventCreated, SubIntegrationKeyID: uuid.NullUUID{UUID: f.credential, Valid: true}}))
			case "member":
				enforcementExec(t, ctx, db, `UPDATE user_organization_assignments SET organization_role='ORG_MEMBER' WHERE user_id=$1`, f.actor)
				use = previewAdmit(t, base, db, f.actor)
			case "foreign":
				g := newServiceProfileFixture(t, ctx, db)
				use = previewAdmit(t, base, db, g.actor)
			case "stale_actor":
				use = previewAdmit(t, base, db, f.actor)
				enforcementExec(t, ctx, db, `UPDATE user_organization_assignments SET organization_role='ORG_MEMBER' WHERE user_id=$1`, f.actor)
			}
			input := keyProfileInput(f.credential)
			if shape == "mixed" {
				input = append(input, serviceProfileInput(f.service)...)
			}
			if shape == "budget" {
				input = keyProfileInput(slicesRepeatService(f.credential, 51)...)
			}
			_, err := app.Mutation().DeleteAll(use, input, &graphql2.DeletionSafetyConfirmationInput{ExpectedImpactVersion: "untrusted", AcknowledgeImpacts: true})
			require.Error(t, err)
			require.False(t, strings.Contains(err.Error(), f.credential.String()))
			require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM integration_keys WHERE audit_resource_id=$1`, f.safe))
			keyProfileNoSuccess(t, ctx, db)
		})
	}
}

func TestPostgresDeletionEnforcementIntegrationKeyGuard(t *testing.T) {
	ctx, _, db := boundedAuditDB(t, len(Names()))
	ctx = permission.SystemContext(ctx, "KeyProfileTest")
	app := enforcementApp(t, ctx, db)
	f := keyProfileFixtureFor(t, ctx, db, integrationkey.TypeGeneric)
	version := keyProfileVersion(t, ctx, db, f.safe)
	for _, phase := range []string{"before_locks", "after_locks", "after_certified"} {
		t.Run(phase, func(t *testing.T) {
			tx := nrBegin(t, ctx, db)
			if phase == "before_locks" {
				keyProfileTxExec(t, ctx, tx, `SAVEPOINT checkpoint`)
			}
			checked, roots, err := guard.StabilizeIntegrationKey(ctx, tx, keyProfileSelectors(f.credential))
			require.NoError(t, err)
			require.Equal(t, []ds.Resource{keyProfileRoot(f.safe)}, roots)
			if phase == "after_locks" {
				keyProfileTxExec(t, ctx, tx, `SAVEPOINT checkpoint`)
			}
			facts, err := collector.Collect(checked, tx, keyProfileRoot(f.safe), collector.Recheck, collector.Limits{}, authorizeDeletionFixture(keyProfileRoot(f.safe)))
			require.NoError(t, err)
			bound, err := guard.Bind(ctx, tx, checked, keyProfileSelectors(f.credential), deletionPlan(t, keyProfileRoot(f.safe), facts), version, true)
			require.NoError(t, err)
			if phase == "after_certified" {
				keyProfileTxExec(t, ctx, tx, `SAVEPOINT checkpoint`)
			}
			keyProfileTxExec(t, ctx, tx, `ROLLBACK TO checkpoint`)
			if phase != "after_certified" {
				_, err = guard.ConsumeIntegrationKey(bound, tx, []string{f.credential.String()})
				enforceCode(t, err, ds.DeletionUnavailable)
				bound = keyProfileEnforce(t, ctx, tx, f, version)
			}
			r, err := app.IntKeyStore.DeleteManyForAuditTx(bound, tx, []string{f.credential.String()}, nil)
			require.NoError(t, err)
			require.Len(t, r, 1)
			require.Equal(t, f.safe, r[0].ResourceID)
			_, err = guard.ConsumeIntegrationKey(bound, tx, []string{f.credential.String()})
			enforceCode(t, err, ds.DeletionUnavailable)
			require.NoError(t, tx.Rollback())
		})
	}
	tx := nrBegin(t, ctx, db)
	old := keyProfileEnforce(t, ctx, tx, f, version)
	keyProfileTxExec(t, ctx, tx, `SAVEPOINT generation`)
	newer := keyProfileEnforce(t, ctx, tx, f, version)
	keyProfileTxExec(t, ctx, tx, `ROLLBACK TO generation`)
	for _, bound := range []context.Context{old, newer} {
		_, err := guard.ConsumeIntegrationKey(bound, tx, []string{f.credential.String()})
		enforceCode(t, err, ds.DeletionUnavailable)
	}
	bound := keyProfileEnforce(t, ctx, tx, f, version)
	other, err := db.BeginTx(ctx, nil)
	require.NoError(t, err)
	_, err = guard.ConsumeIntegrationKey(bound, other, []string{f.credential.String()})
	enforceCode(t, err, ds.DeletionUnavailable)
	require.NoError(t, other.Rollback())
	_, err = guard.ConsumeIntegrationKey(bound, tx, []string{f.safe.String()})
	enforceCode(t, err, ds.DeletionUnavailable)
	for _, consume := range []func(context.Context, *sql.Tx, []string) ([]string, error){guard.ConsumeService, guard.ConsumeRotation, guard.ConsumeUserOverride, guard.ConsumeCM, guard.ConsumeNR, guard.ConsumeEP, guard.ConsumeSchedule} {
		_, err = consume(bound, tx, []string{f.credential.String()})
		enforceCode(t, err, ds.DeletionUnavailable)
	}
	copyCtx := context.WithValue(bound, serviceProfileContextKey{}, true)
	_, err = guard.ConsumeIntegrationKey(copyCtx, tx, []string{f.credential.String()})
	require.NoError(t, err)
	_, err = guard.ConsumeIntegrationKey(bound, tx, []string{f.credential.String()})
	enforceCode(t, err, ds.DeletionUnavailable)
	require.NoError(t, tx.Rollback())
	for _, commit := range []bool{false, true} {
		tx = nrBegin(t, ctx, db)
		bound = keyProfileEnforce(t, ctx, tx, f, version)
		if commit {
			require.NoError(t, tx.Commit())
		} else {
			require.NoError(t, tx.Rollback())
		}
		_, err = guard.ConsumeIntegrationKey(bound, tx, []string{f.credential.String()})
		enforceCode(t, err, ds.DeletionUnavailable)
	}
	tx = nrBegin(t, ctx, db)
	enforceCode(t, app.IntKeyStore.DeleteMany(ctx, tx, []string{f.credential.String()}, nil), ds.DeletionUnavailable)
	_, err = app.IntKeyStore.DeleteManyForAuditTx(ctx, tx, []string{f.credential.String()}, nil)
	enforceCode(t, err, ds.DeletionUnavailable)
	require.NoError(t, tx.Rollback())
	keyProfileNoSuccess(t, ctx, db)
	// A Service-owned Key CASCADE is not an independent Key Store capability.
	tx = nrBegin(t, ctx, db)
	serviceBound := serviceProfileEnforce(t, ctx, tx, f.service, serviceProfileVersion(t, ctx, db, f.service))
	_, err = guard.ConsumeIntegrationKey(serviceBound, tx, []string{f.credential.String()})
	enforceCode(t, err, ds.DeletionUnavailable)
	require.NoError(t, tx.Rollback())
}

func TestPostgresDeletionEnforcementIntegrationKeyMissing(t *testing.T) {
	ctx, uri, db := boundedAuditDB(t, len(Names()))
	ctx = permission.SystemContext(ctx, "KeyProfileTest")
	app := enforcementApp(t, ctx, db)
	f := keyProfileFixtureFor(t, ctx, db, integrationkey.TypeGeneric)
	for _, audited := range []bool{false, true} {
		// A normal Store-created row is temporarily invisible in the writer's
		// uncommitted transaction, then becomes visible after certification.
		writer := epProfileWriter(t, ctx, db)
		k, err := app.IntKeyStore.Create(ctx, writer, &integrationkey.IntegrationKey{Name: "key-" + uuid.NewString(), ServiceID: f.service.String(), Type: integrationkey.TypeEmail}, &f.org)
		require.NoError(t, err)
		missing := uuid.MustParse(k.ID)
		tx := nrBegin(t, ctx, db)
		bound, err := collector.Enforce(ctx, tx, keyProfileSelectors(missing, uuid.Nil), "", false, authorizeDeletionFixture(keyProfileRoot(f.safe)))
		require.NoError(t, err)
		require.NoError(t, writer.Commit())
		if audited {
			r, err := app.IntKeyStore.DeleteManyForAuditTx(bound, tx, []string{missing.String(), uuid.Nil.String()}, nil)
			require.NoError(t, err)
			require.Empty(t, r)
		} else {
			require.NoError(t, app.IntKeyStore.DeleteMany(bound, tx, []string{missing.String(), uuid.Nil.String()}, nil))
		}
		require.NoError(t, tx.Commit())
		require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM integration_keys WHERE id=$1`, missing))
	}
	// Actual Controller capture cannot enlarge its set after certification.
	traced, barrier := overrideProfileTraced(t, uri, "VALUES($1,'certified'")
	controller := enforcementApp(t, ctx, traced)
	writer := epProfileWriter(t, ctx, db)
	k, err := app.IntKeyStore.Create(ctx, writer, &integrationkey.IntegrationKey{Name: "key-" + uuid.NewString(), ServiceID: f.service.String(), Type: integrationkey.TypeEmail}, &f.org)
	require.NoError(t, err)
	done := make(chan error, 1)
	go func() {
		_, err := controller.Mutation().DeleteAll(ctx, keyProfileInput(uuid.MustParse(k.ID), uuid.Nil), nil)
		done <- err
	}()
	<-barrier.arrived
	require.NoError(t, writer.Commit())
	close(barrier.resume)
	require.NoError(t, <-done)
	keyProfileNoSuccess(t, ctx, db)
}

func keyProfileTxExec(t *testing.T, ctx context.Context, tx *sql.Tx, q string) {
	t.Helper()
	_, err := tx.ExecContext(ctx, q)
	require.NoError(t, err)
}

func TestPostgresDeletionEnforcementIntegrationKeyBoundaries(t *testing.T) {
	ctx, _, db := boundedAuditDB(t, len(Names()))
	ctx = permission.SystemContext(ctx, "KeyProfileTest")
	app := enforcementApp(t, ctx, db)
	f := keyProfileFixtureFor(t, ctx, db, integrationkey.TypeGeneric)
	// Even with a valid native certificate, an incorrect Store scope cannot
	// partially delete. Both native Store entry points retain their predicates.
	for _, audited := range []bool{false, true} {
		tx := nrBegin(t, ctx, db)
		bound := keyProfileEnforce(t, ctx, tx, f, keyProfileVersion(t, ctx, db, f.safe))
		foreign := uuid.New()
		var err error
		if audited {
			_, err = app.IntKeyStore.DeleteManyForAuditTx(bound, tx, []string{f.credential.String()}, &foreign)
		} else {
			err = app.IntKeyStore.DeleteMany(bound, tx, []string{f.credential.String()}, &foreign)
		}
		require.Error(t, err)
		require.False(t, strings.Contains(err.Error(), f.credential.String()))
		require.NoError(t, tx.Rollback())
	}
	facts, err := collectDeletion(t, ctx, db, keyProfileRoot(f.credential), collector.Limits{})
	enforceCode(t, err, ds.DeletionUnavailable)
	require.NotEqual(t, ds.DependenciesComplete, facts.Collection.Completeness)
	require.Empty(t, facts.Collection.Dependencies)
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	tx := nrBegin(t, ctx, db)
	_, err = collector.Enforce(cancelled, tx, keyProfileSelectors(f.credential), "", false, authorizeDeletionFixture(keyProfileRoot(f.safe)))
	enforceCode(t, err, ds.DeletionUnavailable)
	require.NoError(t, tx.Rollback())
	keyProfileNoSuccess(t, ctx, db)
	confirm := enforcementPreview(t, ctx, app, keyProfilePreview(f.safe)...)
	_, err = app.Mutation().DeleteAll(ctx, keyProfileInput(slicesRepeatService(f.credential, 50)...), confirm)
	require.NoError(t, err)
	require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM integration_key_delete_audit_events WHERE outcome='committed'`))
	// Schema-permitted but abnormal credential identity: a NULL UUID is not a
	// real Store lifecycle. It is a negative fixture only and must fail closed.
	var safe uuid.UUID
	require.NoError(t, db.QueryRowContext(ctx, `INSERT INTO integration_keys(id,service_id,name,type) VALUES($1,$2,'invalid-credential','generic') RETURNING audit_resource_id`, uuid.Nil, f.service).Scan(&safe))
	_, err = app.Mutation().DeleteAll(ctx, keyProfileInput(uuid.Nil), nil)
	enforceCode(t, err, ds.DeletionUnavailable)
	facts, err = collectDeletion(t, ctx, db, keyProfileRoot(safe), collector.Limits{})
	enforceCode(t, err, ds.DeletionUnavailable)
	require.NotEqual(t, ds.DependenciesComplete, facts.Collection.Completeness)
}
