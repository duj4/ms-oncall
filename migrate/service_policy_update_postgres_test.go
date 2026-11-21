package migrate

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/config"
	ds "github.com/target/goalert/deletionsafety"
	"github.com/target/goalert/graphql2"
	"github.com/target/goalert/graphql2/graphqlapp"
	"github.com/target/goalert/internal/servicepolicy"
	"github.com/target/goalert/organization"
	"github.com/target/goalert/permission"
)

type servicePolicyFixture struct {
	serviceProfileFixture
	next uuid.UUID
}

func newServicePolicyFixture(t *testing.T, ctx context.Context, db *sql.DB, status string) servicePolicyFixture {
	t.Helper()
	f := servicePolicyFixture{serviceProfileFixture: newServiceProfileFixture(t, ctx, db), next: uuid.New()}
	enforcementExec(t, ctx, db, `UPDATE services SET name='Synthetic-'||id::text WHERE id=$1`, f.service)
	enforcementExec(t, ctx, db, `INSERT INTO escalation_policies(id,organization_id,name) VALUES($1,$2,($1::uuid)::text)`, f.next, f.org)
	if status == "mixed" {
		for _, state := range []string{"triggered", "active", "closed"} {
			serviceProfileAlert(t, ctx, db, f.service, state)
		}
	} else if status != "none" {
		serviceProfileAlert(t, ctx, db, f.service, status)
	}
	enforcementExec(t, ctx, db, `UPDATE escalation_policy_state SET escalation_policy_step_id=$2,loop_count=2,last_escalation=now()-interval '1 minute',next_escalation=now()+interval '1 minute' WHERE service_id=$1`, f.service, f.step)
	return f
}

func (f servicePolicyFixture) input() graphql2.UpdateServiceInput {
	id := f.next.String()
	return graphql2.UpdateServiceInput{ID: f.service.String(), EscalationPolicyID: &id}
}

func servicePolicyInventory(t *testing.T, ctx context.Context, db *sql.DB) string {
	t.Helper()
	var result string
	require.NoError(t, db.QueryRowContext(ctx, `SELECT jsonb_build_array(
	 (SELECT jsonb_agg(to_jsonb(s) ORDER BY id) FROM services s),
	 (SELECT jsonb_agg(to_jsonb(p) ORDER BY id) FROM escalation_policies p),
	 (SELECT jsonb_agg(to_jsonb(s) ORDER BY id) FROM escalation_policy_steps s),
	 (SELECT jsonb_agg(to_jsonb(a) ORDER BY id) FROM escalation_policy_actions a),
	 (SELECT jsonb_agg(to_jsonb(s) ORDER BY id) FROM escalation_policy_state s),
	 (SELECT jsonb_agg(jsonb_build_array(id,service_id,status) ORDER BY id) FROM alerts),
	 (SELECT jsonb_agg(to_jsonb(a) ORDER BY event_id) FROM service_update_audit_events a WHERE outcome='committed'),
	 (SELECT jsonb_agg(to_jsonb(a) ORDER BY event_id) FROM service_delete_audit_events a),
	 (SELECT jsonb_agg(to_jsonb(a) ORDER BY event_id) FROM escalation_policy_delete_audit_events a))::text`).Scan(&result))
	return result
}

func servicePolicyStateIDs(t *testing.T, ctx context.Context, db *sql.DB, id uuid.UUID) string {
	t.Helper()
	var raw string
	require.NoError(t, db.QueryRowContext(ctx, `SELECT coalesce(jsonb_agg(id ORDER BY id),'[]')::text FROM escalation_policy_state WHERE service_id=$1`, id).Scan(&raw))
	return raw
}

func servicePolicyHTTP(t *testing.T, ctx context.Context, app *graphqlapp.App, wire map[string]any, mutation bool) (*graphql2.UpdateDeletionPreview, []json.RawMessage, string) {
	t.Helper()
	op, field, selection := "query", "previewUpdateService", "{impactVersion complete canProceed requiresConfirmation root{type id} removed{type id} impacts{relation change policy referencingResource{type id}}}"
	if mutation {
		op, field, selection = "mutation", "updateService", ""
	}
	payload, err := json.Marshal(map[string]any{"query": op + "($input:UpdateServiceInput!){result:" + field + "(input:$input)" + selection + "}", "variables": map[string]any{"input": wire}})
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/graphql", bytes.NewReader(payload)).WithContext((config.Config{}).Context(ctx))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	app.Handler().ServeHTTP(w, req)
	var out struct {
		Data   map[string]json.RawMessage
		Errors []json.RawMessage
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &out), w.Body.String())
	var p *graphql2.UpdateDeletionPreview
	if !mutation && len(out.Errors) == 0 {
		require.NoError(t, json.Unmarshal(out.Data["result"], &p))
	}
	return p, out.Errors, w.Body.String()
}

func TestPostgresServicePolicyUpdateBusiness(t *testing.T) {
	base, _, db := boundedAuditDB(t, len(Names()))
	ctx := permission.SystemContext(base, "ServicePolicyUpdateTest")
	app := updateNativeApp(t, ctx, db)
	var version string
	require.NoError(t, db.QueryRowContext(ctx, `SHOW server_version`).Scan(&version))
	require.True(t, strings.HasPrefix(version, "17.11"), version)
	require.Equal(t, len(Names()), enforcementCount(t, ctx, db, `SELECT count(*) FROM ms_oncall_migration_provenance`))
	for _, status := range []string{"none", "closed", "triggered", "active", "mixed"} {
		t.Run(status, func(t *testing.T) {
			f := newServicePolicyFixture(t, ctx, db, status)
			input := f.input()
			before := servicePolicyInventory(t, ctx, db)
			stateIDs := servicePolicyStateIDs(t, ctx, db, f.service)
			p, err := app.Query().PreviewUpdateService(ctx, input)
			require.NoError(t, err)
			require.Equal(t, before, servicePolicyInventory(t, ctx, db), "preview is read-only")
			require.True(t, p.Complete && p.CanProceed)
			require.Empty(t, p.Removed)
			require.Equal(t, status != "none" && status != "closed", p.RequiresConfirmation)
			require.NotEmpty(t, p.Impacts)
			for _, impact := range p.Impacts {
				require.Equal(t, "RELATION_REPLACED", impact.Change)
			}
			if p.RequiresConfirmation {
				ok, err := app.Mutation().UpdateService(ctx, input)
				require.False(t, ok)
				enforceCode(t, err, ds.DeletionConfirmationRequired)
				require.Equal(t, before, servicePolicyInventory(t, ctx, db))
				input.Confirmation = updateNativeConfirmation(p)
			}
			ok, err := app.Mutation().UpdateService(ctx, input)
			require.NoError(t, err)
			require.True(t, ok)
			require.Equal(t, stateIDs, servicePolicyStateIDs(t, ctx, db, f.service), "runtime identities survive the reset")
			wantStates := 0
			if status == "mixed" {
				wantStates = 2
			} else if status != "none" && status != "closed" {
				wantStates = 1
			}
			require.Equal(t, wantStates, enforcementCount(t, ctx, db, `SELECT count(*) FROM escalation_policy_state WHERE service_id=$1`, f.service))
			var actual uuid.UUID
			require.NoError(t, db.QueryRowContext(ctx, `SELECT escalation_policy_id FROM services WHERE id=$1`, f.service).Scan(&actual))
			require.Equal(t, f.next, actual)
			require.Equal(t, 2, enforcementCount(t, ctx, db, `SELECT count(*) FROM escalation_policies WHERE id IN ($1,$2)`, f.policy, f.next))
			require.Equal(t, 0, enforcementCount(t, ctx, db, `SELECT count(*) FROM escalation_policy_state WHERE service_id=$1 AND (escalation_policy_id<>$2 OR escalation_policy_step_id IS NOT NULL OR loop_count<>0 OR next_escalation IS NOT NULL OR force_escalation)`, f.service, f.next))
			require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM service_update_audit_events WHERE service_id=$1 AND outcome='committed' AND requested_fields=8 AND operation='service.update'`, f.service))
			require.Zero(t, enforcementCount(t, ctx, db, `SELECT count(*) FROM service_delete_audit_events`))
			require.Zero(t, enforcementCount(t, ctx, db, `SELECT count(*) FROM escalation_policy_delete_audit_events`))
		})
	}
}

func TestPostgresServicePolicyUpdateCompatibilityHTTP(t *testing.T) {
	base, _, db := boundedAuditDB(t, len(Names()))
	ctx := permission.SystemContext(base, "ServicePolicyUpdateTest")
	app := updateNativeApp(t, ctx, db)
	f := newServicePolicyFixture(t, ctx, db, "triggered")
	human := previewAdmit(t, base, db, f.actor)
	for _, mode := range []string{"omitted", "null", "same", "scalar", "empty", "collection", "missing_policy", "invalid_policy", "missing_service"} {
		t.Run(mode, func(t *testing.T) {
			wire := map[string]any{"id": f.service.String()}
			switch mode {
			case "null":
				wire["escalationPolicyID"] = nil
			case "same":
				wire["escalationPolicyID"] = f.policy.String()
			case "scalar":
				wire["description"] = "Synthetic scalar update"
			case "empty":
				wire["escalationPolicyID"] = ""
			case "collection":
				wire["escalationPolicyID"] = []string{}
			case "missing_policy":
				wire["escalationPolicyID"] = uuid.NewString()
			case "invalid_policy":
				wire["escalationPolicyID"] = "invalid"
			case "missing_service":
				wire["id"] = uuid.NewString()
			}
			good := mode == "omitted" || mode == "null" || mode == "same" || mode == "scalar"
			before := servicePolicyInventory(t, ctx, db)
			p, problems, body := servicePolicyHTTP(t, human, app, wire, false)
			if good {
				require.Empty(t, problems, body)
				require.False(t, p.RequiresConfirmation)
				require.Empty(t, p.Removed)
			} else {
				require.NotEmpty(t, problems, body)
			}
			require.Equal(t, before, servicePolicyInventory(t, ctx, db))
			_, problems, body = servicePolicyHTTP(t, human, app, wire, true)
			if good {
				require.Empty(t, problems, body)
			} else {
				require.NotEmpty(t, problems, body)
				require.Equal(t, before, servicePolicyInventory(t, ctx, db))
			}
		})
	}
}

func TestPostgresServicePolicyUpdateConfirmationAndDrift(t *testing.T) {
	base, _, db := boundedAuditDB(t, len(Names()))
	ctx := permission.SystemContext(base, "ServicePolicyUpdateTest")
	app := updateNativeApp(t, ctx, db)
	for _, mode := range []string{"missing", "unacknowledged", "missing_version", "forged", "tampered", "intent", "root", "relationship", "policy", "step", "alert", "state", "authority", "actor", "organization", "retired_signer"} {
		t.Run(mode, func(t *testing.T) {
			f := newServicePolicyFixture(t, ctx, db, "triggered")
			human := previewAdmit(t, base, db, f.actor)
			input := f.input()
			p, err := app.Query().PreviewUpdateService(human, input)
			require.NoError(t, err)
			input.Confirmation = updateNativeConfirmation(p)
			expected := ds.DeletionDependencyChanged
			switch mode {
			case "missing":
				input.Confirmation = nil
				expected = ds.DeletionConfirmationRequired
			case "unacknowledged":
				input.Confirmation.AcknowledgeImpacts = false
				expected = ds.DeletionConfirmationRequired
			case "missing_version":
				input.Confirmation.ExpectedImpactVersion = ""
				expected = ds.DeletionConfirmationRequired
			case "forged":
				input.Confirmation.ExpectedImpactVersion = "forged.signature"
			case "tampered":
				parts := strings.Split(input.Confirmation.ExpectedImpactVersion, ".")
				input.Confirmation.ExpectedImpactVersion = parts[0] + ".Zm9yZ2Vk"
			case "intent":
				text := "Synthetic changed intent"
				input.Description = &text
			case "root":
				enforcementExec(t, ctx, db, `UPDATE services SET description='Synthetic changed root' WHERE id=$1`, f.service)
			case "relationship":
				enforcementExec(t, ctx, db, `UPDATE services SET escalation_policy_id=$2 WHERE id=$1`, f.service, f.next)
			case "policy":
				enforcementExec(t, ctx, db, `UPDATE escalation_policies SET repeat=repeat+1 WHERE id=$1`, f.next)
			case "step":
				enforcementExec(t, ctx, db, `UPDATE escalation_policy_steps SET delay=delay+1 WHERE id=$1`, f.step)
			case "alert":
				enforcementExec(t, ctx, db, `UPDATE alerts SET status='active' WHERE service_id=$1`, f.service)
			case "state":
				enforcementExec(t, ctx, db, `UPDATE escalation_policy_state SET loop_count=loop_count+1 WHERE service_id=$1`, f.service)
			case "authority":
				enforcementExec(t, ctx, db, `UPDATE user_organization_assignments SET organization_role='ORG_MEMBER' WHERE user_id=$1`, f.actor)
				expected = ds.DeletionUnavailable
			case "actor":
				human = previewAdmit(t, base, db, f.user)
			case "organization":
				enforcementExec(t, ctx, db, `UPDATE escalation_policies SET organization_id=$2 WHERE id=$1`, f.next, newBoundedFixture(t, ctx, db).org)
				expected = ds.DeletionUnavailable
			case "retired_signer":
				copy := *app
				copy.PreviewSigner = nil
				app = &copy
			}
			defer func() { app.PreviewSigner = previewNativeSigner{} }()
			before := servicePolicyInventory(t, ctx, db)
			ok, err := app.Mutation().UpdateService(human, input)
			require.False(t, ok)
			enforceCode(t, err, expected)
			require.Equal(t, before, servicePolicyInventory(t, ctx, db))
		})
	}
}

func TestPostgresServicePolicyUpdateAuthorityAndStore(t *testing.T) {
	base, _, db := boundedAuditDB(t, len(Names()))
	ctx := permission.SystemContext(base, "ServicePolicyUpdateTest")
	app := updateNativeApp(t, ctx, db)
	f := newServicePolicyFixture(t, ctx, db, "triggered")
	foreign := newServicePolicyFixture(t, ctx, db, "none")
	for _, mode := range []string{"member", "foreign_actor", "foreign_policy"} {
		t.Run(mode, func(t *testing.T) {
			actor := f.actor
			wire := map[string]any{"id": f.service.String(), "escalationPolicyID": f.next.String()}
			if mode == "member" {
				enforcementExec(t, ctx, db, `UPDATE user_organization_assignments SET organization_role='ORG_MEMBER' WHERE user_id=$1`, f.user)
				actor = f.user
			}
			if mode == "foreign_actor" {
				actor = foreign.actor
			}
			if mode == "foreign_policy" {
				wire["escalationPolicyID"] = foreign.next.String()
			}
			human := previewAdmit(t, base, db, actor)
			before := servicePolicyInventory(t, ctx, db)
			for _, mutation := range []bool{false, true} {
				_, problems, body := servicePolicyHTTP(t, human, app, wire, mutation)
				require.NotEmpty(t, problems, body)
				require.NotContains(t, body, f.policy.String())
				require.Equal(t, before, servicePolicyInventory(t, ctx, db))
			}
		})
	}
	for _, owned := range []bool{false, true} {
		t.Run(map[bool]string{false: "caller_transaction", true: "store_transaction"}[owned], func(t *testing.T) {
			var tx *sql.Tx
			var err error
			if !owned {
				tx, err = db.BeginTx(ctx, nil)
				require.NoError(t, err)
				defer func() { _ = tx.Rollback() }()
			}
			svc, err := app.ServiceStore.FindOne(ctx, f.service.String(), &f.org)
			require.NoError(t, err)
			svc.EscalationPolicyID = f.next.String()
			before := servicePolicyInventory(t, ctx, db)
			err = app.ServiceStore.UpdateTx(ctx, tx, svc, &f.org)
			enforceCode(t, err, ds.DeletionUnavailable)
			if tx != nil {
				require.NoError(t, tx.Commit(), "refusal occurs before DML, even if caller catches the error")
			}
			require.Equal(t, before, servicePolicyInventory(t, ctx, db))
		})
	}
	// An internal capability is exact, transaction-bound and single-use.
	tx, err := db.BeginTx(ctx, nil)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback() }()
	facts, err := servicepolicy.Load(ctx, tx, f.service.String(), f.input().EscalationPolicyID, &f.org, true)
	require.NoError(t, err)
	bound, err := servicepolicy.Bind(ctx, tx, facts)
	require.NoError(t, err)
	other, err := db.BeginTx(ctx, nil)
	require.NoError(t, err)
	defer func() { _ = other.Rollback() }()
	enforceCode(t, servicepolicy.Consume(bound, other, facts), ds.DeletionUnavailable)
	wrong := facts
	wrong.After = uuid.New()
	enforceCode(t, servicepolicy.Consume(bound, tx, wrong), ds.DeletionUnavailable)
	require.NoError(t, servicepolicy.Consume(bound, tx, facts))
	enforceCode(t, servicepolicy.Consume(bound, tx, facts), ds.DeletionUnavailable)
}

func TestPostgresServicePolicyUpdatePlatformAdminHTTP(t *testing.T) {
	base, _, db := boundedAuditDB(t, len(Names()))
	ctx := permission.SystemContext(base, "ServicePolicyUpdateTest")
	app := updateNativeApp(t, ctx, db)
	for _, home := range []string{"org_admin", "normal", "default"} {
		t.Run(home, func(t *testing.T) {
			f := newServicePolicyFixture(t, ctx, db, "triggered")
			actor := newServicePolicyFixture(t, ctx, db, "none").actor
			role := "platform_admin"
			if home == "org_admin" {
				actor = f.actor
				role = "org_admin"
			} else {
				enforcementExec(t, ctx, db, `UPDATE users SET role='admin' WHERE id=$1`, actor)
			}
			if home == "default" {
				enforcementExec(t, ctx, db, `UPDATE user_organization_assignments SET effective_organization_id=$2,effective_organization_classification='DEFAULT',effective_normal_organization_id=NULL,organization_role='NONE',mapping_outcome='ZERO',matched_count=0 WHERE user_id=$1`, actor, organization.DefaultOrganizationID)
			}
			human := previewAdmit(t, base, db, actor)
			wire := map[string]any{"id": f.service.String(), "escalationPolicyID": f.next.String()}
			p, problems, body := servicePolicyHTTP(t, human, app, wire, false)
			require.Empty(t, problems, body)
			require.True(t, p.RequiresConfirmation)
			_, problems, body = servicePolicyHTTP(t, human, app, wire, true)
			require.NotEmpty(t, problems)
			require.Contains(t, body, "DELETION_CONFIRMATION_REQUIRED")
			wire["confirmation"] = updateNativeConfirmation(p)
			_, problems, body = servicePolicyHTTP(t, human, app, wire, true)
			require.Empty(t, problems, body)
			require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM service_update_audit_events WHERE service_id=$1 AND actor_id=$2 AND authority_role=$3 AND outcome='committed'`, f.service, actor, role))
		})
	}
}

func TestPostgresServicePolicyUpdateUnsupportedState(t *testing.T) {
	base, _, db := boundedAuditDB(t, len(Names()))
	ctx := permission.SystemContext(base, "ServicePolicyUpdateTest")
	app := updateNativeApp(t, ctx, db)
	for _, mode := range []string{"closed_state", "foreign_step", "unencodable_timestamp"} {
		t.Run(mode, func(t *testing.T) {
			status := "closed"
			if mode != "closed_state" {
				status = "triggered"
			}
			f := newServicePolicyFixture(t, ctx, db, status)
			switch mode {
			case "closed_state":
				enforcementExec(t, ctx, db, `INSERT INTO escalation_policy_state(alert_id,service_id,escalation_policy_id) SELECT id,service_id,$2 FROM alerts WHERE service_id=$1`, f.service, f.policy)
			case "foreign_step":
				step := uuid.New()
				enforcementExec(t, ctx, db, `INSERT INTO escalation_policy_steps(id,escalation_policy_id,step_number) VALUES($1,$2,0)`, step, f.next)
				enforcementExec(t, ctx, db, `UPDATE escalation_policy_state SET escalation_policy_step_id=$2 WHERE service_id=$1`, f.service, step)
			default:
				enforcementExec(t, ctx, db, `UPDATE escalation_policy_state SET next_escalation='10000-01-01 00:00:00+00'::timestamptz WHERE service_id=$1`, f.service)
			}
			before := servicePolicyInventory(t, ctx, db)
			_, err := app.Query().PreviewUpdateService(ctx, f.input())
			enforceCode(t, err, ds.DeletionUnavailable)
			_, err = app.Mutation().UpdateService(ctx, f.input())
			enforceCode(t, err, ds.DeletionUnavailable)
			require.Equal(t, before, servicePolicyInventory(t, ctx, db))
			// A scalar update does not reset this runtime relationship.
			text := "Synthetic compatible scalar"
			ok, err := app.Mutation().UpdateService(ctx, graphql2.UpdateServiceInput{ID: f.service.String(), Description: &text})
			require.NoError(t, err)
			require.True(t, ok)
		})
	}
}

func TestPostgresServicePolicyUpdateAtomicity(t *testing.T) {
	base, _, db := boundedAuditDB(t, len(Names()))
	ctx := permission.SystemContext(base, "ServicePolicyUpdateTest")
	app := updateNativeApp(t, ctx, db)
	for _, mode := range []string{"business", "audit", "audit_validation", "commit", "missing_write", "wrong_policy", "extra_state_effect", "retained_policy_graph"} {
		t.Run(mode, func(t *testing.T) {
			f := newServicePolicyFixture(t, ctx, db, "triggered")
			input := f.input()
			text := "Synthetic atomic update"
			input.Description = &text
			p, err := app.Query().PreviewUpdateService(ctx, input)
			require.NoError(t, err)
			input.Confirmation = updateNativeConfirmation(p)
			table, timing, constraint, deferred := "services", "BEFORE UPDATE", "", ""
			body := `IF NEW.id='` + f.service.String() + `' THEN RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='Synthetic service policy fault'; END IF; RETURN NEW;`
			switch mode {
			case "audit", "commit":
				table = "service_update_audit_events"
				timing = "BEFORE INSERT"
				body = `IF NEW.service_id='` + f.service.String() + `' AND NEW.outcome='committed' THEN RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='Synthetic service audit fault'; END IF; RETURN NEW;`
				if mode == "commit" {
					timing = "AFTER INSERT"
					constraint = "CONSTRAINT "
					deferred = "DEFERRABLE INITIALLY DEFERRED"
				}
			case "missing_write":
				body = `IF NEW.id='` + f.service.String() + `' THEN RETURN NULL; END IF; RETURN NEW;`
			case "wrong_policy":
				body = `IF NEW.id='` + f.service.String() + `' THEN NEW.escalation_policy_id=OLD.escalation_policy_id; END IF; RETURN NEW;`
			case "extra_state_effect":
				timing = "AFTER UPDATE"
				body = `IF NEW.id='` + f.service.String() + `' THEN DELETE FROM escalation_policy_state WHERE service_id=NEW.id; END IF; RETURN NEW;`
			case "retained_policy_graph":
				timing = "AFTER UPDATE"
				body = `IF NEW.id='` + f.service.String() + `' THEN DELETE FROM escalation_policy_actions WHERE escalation_policy_step_id='` + f.step.String() + `'; END IF; RETURN NEW;`
			}
			if mode == "audit_validation" {
				enforcementExec(t, ctx, db, `ALTER TABLE service_update_audit_events ADD CONSTRAINT service_policy_fault CHECK(outcome<>'committed' OR service_id<>'`+f.service.String()+`')`)
				t.Cleanup(func() {
					enforcementExec(t, ctx, db, `ALTER TABLE service_update_audit_events DROP CONSTRAINT service_policy_fault`)
				})
			} else {
				enforcementExec(t, ctx, db, `CREATE FUNCTION service_policy_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN `+body+` END $$`)
				enforcementExec(t, ctx, db, `CREATE `+constraint+`TRIGGER z_service_policy_fault `+timing+` ON `+table+` `+deferred+` FOR EACH ROW EXECUTE FUNCTION service_policy_fault()`)
				t.Cleanup(func() {
					enforcementExec(t, ctx, db, `DROP TRIGGER z_service_policy_fault ON `+table)
					enforcementExec(t, ctx, db, `DROP FUNCTION service_policy_fault()`)
				})
			}
			before := servicePolicyInventory(t, ctx, db)
			ok, err := app.Mutation().UpdateService(ctx, input)
			require.Error(t, err)
			require.False(t, ok)
			wantReason := "write_failed"
			if mode == "audit" || mode == "audit_validation" {
				wantReason = "audit_write_failed"
			}
			if mode == "commit" {
				wantReason = "commit_rejected"
			}
			var reason string
			require.NoError(t, db.QueryRowContext(ctx, `SELECT reason_code FROM service_update_audit_events WHERE service_id=$1 AND outcome<>'committed' ORDER BY occurred_at DESC LIMIT 1`, f.service).Scan(&reason))
			require.Equal(t, wantReason, reason, "the native fault must be reached at its intended stage")
			require.Equal(t, before, servicePolicyInventory(t, ctx, db))
			tx, err := db.BeginTx(ctx, nil)
			require.NoError(t, err)
			_, err = tx.ExecContext(ctx, `SELECT id FROM services WHERE id=$1 FOR UPDATE NOWAIT`, f.service)
			require.NoError(t, err)
			require.NoError(t, tx.Rollback())
		})
	}
}
