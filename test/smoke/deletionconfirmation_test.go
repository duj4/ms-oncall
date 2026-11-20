package smoke

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/assignment"
	ds "github.com/target/goalert/deletionsafety"
	"github.com/target/goalert/graphql2"
	"github.com/target/goalert/graphql2/graphqlapp"
	"github.com/target/goalert/test/smoke/harness"
)

// smokeDeleteAll preserves the original mutation, authority and raw selectors.
// Preview uses an independent, uninstrumented connection so legacy transaction
// fault injectors still measure only the actual mutation. It never retries a
// rejected mutation or manufactures an ImpactVersion.
func smokeDeleteAll(t *testing.T, h *harness.Harness, app *graphqlapp.App, ctx context.Context, input []assignment.RawTarget) (bool, error) {
	t.Helper()
	confirmation, err := smokeDeletionConfirmation(t, h, ctx, input)
	if err != nil {
		// A legacy fault test must not pass merely because Preview failed before
		// reaching its intended DML/COMMIT boundary.
		t.Error("legacy deletion fixture cannot reach its mutation through the current Preview contract")
		return false, err
	}
	return app.Mutation().DeleteAll(ctx, input, confirmation)
}

func smokeDeletionConfirmation(t *testing.T, h *harness.Harness, ctx context.Context, input []assignment.RawTarget) (*graphql2.DeletionSafetyConfirmationInput, error) {
	t.Helper()
	p, err := smokeDeletionPreview(t, h, ctx, input)
	if err != nil {
		return nil, err
	}
	if p == nil {
		return nil, nil // Existing System missing-target/no-op contract.
	}
	if !p.CanProceed || !p.Complete {
		return nil, fmt.Errorf("legacy fixture has blocked or incomplete deletion impacts")
	}
	if !p.RequiresConfirmation {
		return nil, nil
	}
	return &graphql2.DeletionSafetyConfirmationInput{ExpectedImpactVersion: p.ImpactVersion, AcknowledgeImpacts: true}, nil
}

// Return the real Preview even for a BLOCK. Negative controls must exercise the
// mutation's own recheck rather than turn a helper failure into a passing test.
func smokeDeletionPreview(t *testing.T, h *harness.Harness, ctx context.Context, input []assignment.RawTarget) (*graphql2.DeletionPreview, error) {
	t.Helper()
	types := map[assignment.TargetType]graphql2.DeletionTargetType{
		assignment.TargetTypeService:          graphql2.DeletionTargetTypeService,
		assignment.TargetTypeEscalationPolicy: graphql2.DeletionTargetTypeEscalationPolicy,
		assignment.TargetTypeSchedule:         graphql2.DeletionTargetTypeSchedule,
		assignment.TargetTypeRotation:         graphql2.DeletionTargetTypeRotation,
		assignment.TargetTypeUser:             graphql2.DeletionTargetTypeUser,
		assignment.TargetTypeContactMethod:    graphql2.DeletionTargetTypeContactMethod,
		assignment.TargetTypeNotificationRule: graphql2.DeletionTargetTypeNotificationRule,
		assignment.TargetTypeIntegrationKey:   graphql2.DeletionTargetTypeIntegrationKey,
		assignment.TargetTypeUserOverride:     graphql2.DeletionTargetTypeUserOverride,
	}
	queries := map[assignment.TargetType]string{
		assignment.TargetTypeService:          `SELECT id::text FROM services WHERE id=$1`,
		assignment.TargetTypeEscalationPolicy: `SELECT id::text FROM escalation_policies WHERE id=$1`,
		assignment.TargetTypeSchedule:         `SELECT id::text FROM schedules WHERE id=$1`,
		assignment.TargetTypeRotation:         `SELECT id::text FROM rotations WHERE id=$1`,
		assignment.TargetTypeUser:             `SELECT id::text FROM users WHERE id=$1`,
		assignment.TargetTypeContactMethod:    `SELECT id::text FROM user_contact_methods WHERE id=$1`,
		assignment.TargetTypeNotificationRule: `SELECT id::text FROM user_notification_rules WHERE id=$1`,
		assignment.TargetTypeIntegrationKey:   `SELECT audit_resource_id::text FROM integration_keys WHERE id=$1`,
		assignment.TargetTypeUserOverride:     `SELECT id::text FROM user_overrides WHERE id=$1`,
	}
	var targets []graphql2.DeletionResourceInput
	seen := map[string]bool{}
	for _, raw := range input {
		query, ok := queries[raw.Type]
		if !ok || raw.Type != input[0].Type {
			return nil, fmt.Errorf("legacy fixture requires unsupported root selection")
		}
		id, err := uuid.Parse(raw.ID)
		if err != nil || id == uuid.Nil || id.String() != raw.ID {
			return nil, fmt.Errorf("legacy fixture requires canonical root selectors")
		}
		if seen[raw.ID] {
			continue
		}
		seen[raw.ID] = true
		var safeID string
		err = h.App().DB().QueryRowContext(ctx, query, raw.ID).Scan(&safeID)
		if errors.Is(err, sql.ErrNoRows) {
			continue // Mutation still receives every original missing selector.
		}
		if err != nil {
			return nil, fmt.Errorf("legacy fixture root lookup failed (details withheld)")
		}
		targets = append(targets, graphql2.DeletionResourceInput{Type: types[raw.Type], ID: safeID})
	}
	if len(targets) == 0 {
		return nil, nil
	}
	q := graphqlapp.App{DB: h.App().DB(), PreviewSigner: h.App().SessionKeyring}
	return q.Query().DeletionPreview(ctx, graphql2.DeletionPlanInput{Operation: graphql2.DeletionOperationDeleteResources, Targets: targets}, nil, nil)
}

func smokeDeletionCode(t *testing.T, err error, code ds.ErrorCode) {
	t.Helper()
	var safety *ds.DeletionSafetyError
	require.ErrorAs(t, err, &safety)
	require.Equal(t, code, safety.Code)
}

func smokePlanConfirmation(t *testing.T, h *harness.Harness, ctx context.Context, input []assignment.RawTarget) *graphql2.DeletionSafetyConfirmationInput {
	t.Helper()
	p, err := smokeDeletionPreview(t, h, ctx, input)
	require.NoError(t, err)
	require.NotNil(t, p)
	require.True(t, p.Complete)
	require.NotEmpty(t, p.ImpactVersion)
	return &graphql2.DeletionSafetyConfirmationInput{ExpectedImpactVersion: p.ImpactVersion, AcknowledgeImpacts: true}
}

// The native profiles use NOWAIT while collecting their closure. A successful
// mutation can still fence a concurrent writer: pause its real DELETE trigger,
// then prove a second PostgreSQL session waits for its already acquired locks.
// Neither the Guard nor the production lock statements are replaced.
func smokeDeleteFencesWriter(t *testing.T, h *harness.Harness, app *graphqlapp.App, input []assignment.RawTarget, table, id string) {
	t.Helper()
	require.Contains(t, []string{"escalation_policies", "schedules", "rotations", "user_overrides", "user_contact_methods"}, table)
	ctx, cancel := context.WithTimeout(sd3System(), 15*time.Second)
	defer cancel()
	confirmation, err := smokeDeletionConfirmation(t, h, ctx, input)
	require.NoError(t, err, "legal Preview before the DELETE barrier")
	db := h.App().DB()
	gate, err := db.Conn(ctx)
	require.NoError(t, err)
	defer gate.Close()
	var gatePID int
	require.NoError(t, gate.QueryRowContext(ctx, `SELECT pg_backend_pid()`).Scan(&gatePID))
	_, err = gate.ExecContext(ctx, `SELECT pg_advisory_lock(990092,$1)`, gatePID)
	require.NoError(t, err)
	defer func() { _, _ = gate.ExecContext(context.Background(), `SELECT pg_advisory_unlock(990092,$1)`, gatePID) }()
	sd8Exec(t, h, fmt.Sprintf(`CREATE SEQUENCE smoke_contract2_hits;
CREATE FUNCTION smoke_contract2_gate() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
PERFORM nextval('smoke_contract2_hits'); PERFORM pg_advisory_xact_lock(990092,%d); RETURN OLD; END $$;
CREATE TRIGGER smoke_contract2_gate BEFORE DELETE ON %s FOR EACH ROW EXECUTE FUNCTION smoke_contract2_gate()`, gatePID, table))
	t.Cleanup(func() {
		sd8Exec(t, h, `DROP TRIGGER smoke_contract2_gate ON `+table+`; DROP FUNCTION smoke_contract2_gate(); DROP SEQUENCE smoke_contract2_hits`)
	})
	before := smokeDeletionSuccesses(t, h)
	done := make(chan error, 1)
	go func() {
		ok, err := app.Mutation().DeleteAll(ctx, input, confirmation)
		if err == nil && !ok {
			err = errors.New("mutation returned false at DELETE barrier")
		}
		done <- err
	}()
	sd3WaitBlocked(t, db, gatePID)
	var mutationPID int
	require.NoError(t, db.QueryRowContext(ctx, `SELECT pid FROM pg_stat_activity WHERE datname=current_database() AND $1=ANY(pg_blocking_pids(pid))`, gatePID).Scan(&mutationPID))
	require.EqualValues(t, 1, sd8Scalar(t, h, `SELECT count(*) FROM smoke_contract2_hits WHERE is_called`))
	writer := sd5ExternalDB(t, h, "")
	written := make(chan error, 1)
	go func() {
		var found string
		err := writer.QueryRowContext(ctx, `SELECT id::text FROM `+table+` WHERE id=$1 FOR UPDATE`, id).Scan(&found)
		written <- err
	}()
	sd3WaitBlocked(t, db, mutationPID)
	require.Equal(t, 1, serviceManagementCount(t, h, table, id), "uncommitted DELETE is invisible")
	require.Equal(t, before, smokeDeletionSuccesses(t, h), "no success witness visible before Commit")
	_, err = gate.ExecContext(ctx, `SELECT pg_advisory_unlock(990092,$1)`, gatePID)
	require.NoError(t, err)
	require.NoError(t, <-done)
	require.ErrorIs(t, <-written, sql.ErrNoRows, "waiting writer observes committed deletion")
	require.Zero(t, serviceManagementCount(t, h, table, id))
	t.Log("real Guard/DELETE barrier reached; independent writer waited; business and Audit became visible at Commit")
}

func smokeDeletionSuccesses(t *testing.T, h *harness.Harness) int64 {
	t.Helper()
	var total int64
	for _, table := range []string{"service_delete_audit_events", "escalation_policy_delete_audit_events", "schedule_rotation_delete_audit_events", "user_override_delete_audit_events", "user_cmnr_delete_audit_events", "integration_key_delete_audit_events", "user_delete_audit_events"} {
		predicate := `record_kind='success_witness'`
		if table == "service_delete_audit_events" {
			predicate = `outcome='committed'`
		}
		total += sd8Scalar(t, h, `SELECT count(*) FROM `+table+` WHERE `+predicate)
	}
	return total
}

// smokeOwnedUser is scoped to the CONTRACT3 fixtures. Keep the old unassigned
// helper for existing negative controls and tests outside this task.
func smokeOwnedUser(t *testing.T, h *harness.Harness) string {
	t.Helper()
	u := sd7User(t, h)
	sd8Assign(t, h, u, harness.SmokeOrganizationID)
	return u
}

// Assert the current retained-reference policy against both real Preview and
// the Mutation recheck. A refusal is never evidence of a reached audit fault.
func smokeAssertBlockedUser(t *testing.T, h *harness.Harness, app *graphqlapp.App, input []assignment.RawTarget) {
	t.Helper()
	before, successes := smokeUserBusinessState(t, h), smokeDeletionSuccesses(t, h)
	p, err := smokeDeletionPreview(t, h, sd3System(), input)
	require.NoError(t, err)
	require.NotNil(t, p)
	require.True(t, p.Complete)
	require.False(t, p.CanProceed)
	ok, err := app.Mutation().DeleteAll(sd3System(), input, &graphql2.DeletionSafetyConfirmationInput{ExpectedImpactVersion: p.ImpactVersion, AcknowledgeImpacts: true})
	smokeDeletionCode(t, err, ds.DeletionBlocked)
	require.False(t, ok)
	require.Equal(t, before, smokeUserBusinessState(t, h))
	require.Equal(t, successes, smokeDeletionSuccesses(t, h))
	t.Log("real Preview BLOCK and confirmed Mutation rejection: all 17 business snapshots and prior success Audits preserved")
}

// CONTRACT4 helpers are used only by its twelve bounded compatibility tests.
// Keep the complete business state and all previously committed witnesses,
// including effects, rather than accepting an error before the intended path.
func smokeContract4SuccessState(t *testing.T, h *harness.Harness) map[string]string {
	t.Helper()
	state := make(map[string]string)
	for _, table := range []string{"service_delete_audit_events", "escalation_policy_delete_audit_events", "integration_key_delete_audit_events", "user_cmnr_delete_audit_events"} {
		predicate := `record_kind='success_witness'`
		if table == "service_delete_audit_events" {
			predicate = `outcome='committed'`
		}
		var rows string
		require.NoError(t, h.App().DB().QueryRow(`SELECT coalesce(jsonb_agg(to_jsonb(e) ORDER BY to_jsonb(e)::text),'[]')::text FROM `+table+` e WHERE `+predicate).Scan(&rows))
		state[table] = rows
	}
	return state
}

func smokeContract4Reject(t *testing.T, h *harness.Harness, app *graphqlapp.App, ctx context.Context, input []assignment.RawTarget, confirmation *graphql2.DeletionSafetyConfirmationInput, code ds.ErrorCode) {
	t.Helper()
	before, audit := serviceManagementSnapshot(t, h), smokeContract4SuccessState(t, h)
	ok, err := app.Mutation().DeleteAll(ctx, input, confirmation)
	smokeDeletionCode(t, err, code)
	require.False(t, ok)
	require.Equal(t, before, serviceManagementSnapshot(t, h), "rejection must preserve every business row and relationship")
	require.Equal(t, audit, smokeContract4SuccessState(t, h), "rejection must preserve complete committed witnesses/effects")
	t.Logf("confirmed Mutation rejection %s; full business and successful Audit snapshots preserved", code)
}

func smokeContract4IsolationReject(t *testing.T, h *harness.Harness, app *graphqlapp.App, input []assignment.RawTarget, confirmation *graphql2.DeletionSafetyConfirmationInput) {
	t.Helper()
	var isolation string
	require.NoError(t, app.DB.QueryRow(`SHOW transaction_isolation`).Scan(&isolation))
	require.Contains(t, []string{"repeatable read", "serializable"}, isolation)
	before, audit := serviceManagementSnapshot(t, h), smokeContract4SuccessState(t, h)
	ok, err := app.Mutation().DeleteAll(sd3System(), input, confirmation)
	message := "deleteAll transaction failed"
	if input[0].Type == assignment.TargetTypeService {
		message = "service.delete transaction failed"
	}
	// The existing Audit entry rejects isolation before Enforcement and returns
	// its bounded transaction error, rather than a DeletionSafetyError.
	require.EqualError(t, err, message)
	require.False(t, ok)
	require.Equal(t, before, serviceManagementSnapshot(t, h))
	require.Equal(t, audit, smokeContract4SuccessState(t, h))
	t.Logf("actual %s refused at existing Audit transaction admission (%s); complete business and successful Audit state preserved", isolation, message)
}

func smokeContract4Blocked(t *testing.T, h *harness.Harness, app *graphqlapp.App, input []assignment.RawTarget) {
	t.Helper()
	p, err := smokeDeletionPreview(t, h, sd3System(), input)
	require.NoError(t, err)
	require.NotNil(t, p)
	require.True(t, p.Complete)
	require.False(t, p.CanProceed)
	smokeContract4Reject(t, h, app, sd3System(), input, &graphql2.DeletionSafetyConfirmationInput{ExpectedImpactVersion: p.ImpactVersion, AcknowledgeImpacts: true}, ds.DeletionBlocked)
}

func smokeContract4Service(t *testing.T, h *harness.Harness, home bool) string {
	t.Helper()
	root := uuid.NewString()
	org, policy := h.UUID("org-b"), h.UUID("policy-b")
	if home {
		org, policy = harness.SmokeOrganizationID, h.UUID("policy-a")
	}
	sd8Exec(t, h, `INSERT INTO services(id,organization_id,escalation_policy_id,name) VALUES($1::uuid,$2,$3,$1::text)`, root, org, policy)
	return root
}

func smokeContract4LockPID(t *testing.T, h *harness.Harness, tx *sql.Tx) int {
	t.Helper()
	var pid int
	require.NoError(t, tx.QueryRow(`SELECT pg_backend_pid()`).Scan(&pid))
	require.Positive(t, sd8Scalar(t, h, `SELECT count(*) FROM pg_locks WHERE pid=$1 AND granted AND locktype IN ('transactionid','virtualxid') AND mode='ExclusiveLock'`, pid), "independent writer owns a real PostgreSQL transaction lock")
	t.Logf("external PostgreSQL transaction PID=%d has granted native locks", pid)
	return pid
}

// Pause only after real Guard/Confirmation admission, at DELETE or Audit DML.
// PostgreSQL's blocking graph and a nontransactional sequence prove entry.
func smokeContract4Gate(t *testing.T, h *harness.Harness, app *graphqlapp.App, ctx context.Context, input []assignment.RawTarget, table string, auditGate bool, check func(context.Context, int), supplied ...*graphql2.DeletionSafetyConfirmationInput) {
	t.Helper()
	require.Contains(t, []string{"services", "escalation_policies", "integration_key_delete_audit_events"}, table)
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	confirmation, err := smokeDeletionConfirmation(t, h, ctx, input)
	require.NoError(t, err)
	if len(supplied) > 0 {
		require.Len(t, supplied, 1)
		confirmation = supplied[0]
	}
	db := h.App().DB()
	gate, err := sd5ExternalDB(t, h, "").Conn(ctx)
	require.NoError(t, err)
	defer gate.Close()
	var pid int
	require.NoError(t, gate.QueryRowContext(ctx, `SELECT pg_backend_pid()`).Scan(&pid))
	_, err = gate.ExecContext(ctx, `SELECT pg_advisory_lock(990096,$1)`, pid)
	require.NoError(t, err)
	dml, returned := "DELETE", "OLD"
	if auditGate {
		dml, returned = "INSERT", "NEW"
	}
	sd8Exec(t, h, fmt.Sprintf(`CREATE SEQUENCE contract4_gate_hits;
CREATE FUNCTION contract4_gate() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM nextval('contract4_gate_hits'); PERFORM pg_advisory_xact_lock(990096,%d); RETURN %s; END $$;
CREATE TRIGGER contract4_gate BEFORE %s ON %s FOR EACH ROW EXECUTE FUNCTION contract4_gate()`, pid, returned, dml, table))
	before, audit := serviceManagementSnapshot(t, h), smokeContract4SuccessState(t, h)
	done := make(chan error, 1)
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		ok, err := app.Mutation().DeleteAll(ctx, input, confirmation)
		if err == nil && !ok {
			err = errors.New("confirmed mutation returned false")
		}
		done <- err
	}()
	defer func() {
		_, _ = gate.ExecContext(context.Background(), `SELECT pg_advisory_unlock(990096,$1)`, pid)
		cancel()
		select {
		case <-finished:
		case <-time.After(5 * time.Second):
			t.Error("confirmed mutation did not finish after releasing its task gate")
		}
	}()
	sd3WaitBlocked(t, db, pid)
	var mutationPID int
	require.NoError(t, db.QueryRowContext(ctx, `SELECT pid FROM pg_stat_activity WHERE datname=current_database() AND $1=ANY(pg_blocking_pids(pid))`, pid).Scan(&mutationPID))
	require.EqualValues(t, 1, sd8Scalar(t, h, `SELECT count(*) FROM contract4_gate_hits WHERE is_called`))
	require.Equal(t, before, serviceManagementSnapshot(t, h), "uncommitted business DML is invisible")
	require.Equal(t, audit, smokeContract4SuccessState(t, h), "uncommitted success Audit is invisible")
	check(ctx, mutationPID)
	_, err = gate.ExecContext(ctx, `SELECT pg_advisory_unlock(990096,$1)`, pid)
	require.NoError(t, err)
	require.NoError(t, <-done)
	<-finished
	sd8Exec(t, h, `DROP TRIGGER contract4_gate ON `+table+`; DROP FUNCTION contract4_gate(); DROP SEQUENCE contract4_gate_hits`)
	t.Logf("real %s barrier hit once, mutation PID=%d, business and Audit invisible until Commit", dml, mutationPID)
}
