package migrate

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
	epaudit "github.com/target/goalert/escalation/deleteaudit"
)

func sd5SchemaEvent() epaudit.Event {
	return epaudit.Event{SchemaVersion: 1, EffectsVersion: 1, EventID: uuid.New(), RequestID: uuid.New(), ExecutionID: uuid.New(), AttemptID: uuid.New(), RecordKind: "success_witness", RootID: uuid.New(), TargetOrganizationID: uuid.New(), TargetOrgResolution: "known_normal", Provenance: "EXPLICIT", DeletionMechanism: "explicit_sql", Cause: "explicit_target", ActorKind: "internal_system", AuthoritySource: "trusted_internal_system", AuthorityRole: "internal_system", OrganizationRole: "unknown", Outcome: "committed", Reason: "deleted", OccurredAt: time.Now()}
}
func sd5SchemaEffect(e epaudit.Event, n int) epaudit.Effect {
	id := uuid.New()
	return epaudit.Effect{EffectID: uuid.New(), ResourceType: epaudit.Step, RootID: e.RootID, TargetOrganizationID: e.TargetOrganizationID, Relation: "escalation_policy.step", Change: "deleted", Provenance: "CASCADE", DeletionMechanism: "fk_cascade", Cause: "escalation_policy_delete", ResourceUUID: &id, StepNumber: &n}
}

func TestPostgresEscalationPolicyDeleteClosedEffects(t *testing.T) {
	ctx, _, db := boundedAuditDB(t, len(Names()))
	e := sd5SchemaEvent()
	step := sd5SchemaEffect(e, 0)
	e.Effects = []epaudit.Effect{step}
	tx, err := db.BeginTx(ctx, nil)
	require.NoError(t, err)
	require.NoError(t, epaudit.Append(ctx, tx, e))
	require.NoError(t, tx.Commit())
	var raw string
	require.NoError(t, db.QueryRowContext(ctx, `SELECT to_jsonb(e)::text FROM escalation_policy_delete_audit_events e WHERE event_id=$1`, e.EventID).Scan(&raw))
	for name, change := range map[string]func(map[string]any){
		"unknown_key": func(f map[string]any) { f["destination"] = "SYNTHETIC_DEST@example.invalid" }, "unknown_type": func(f map[string]any) { f["resource_type"] = "other" }, "null_id": func(f map[string]any) { f["resource_uuid"] = nil }, "zero_id": func(f map[string]any) { f["resource_uuid"] = uuid.Nil.String() }, "wrong_root": func(f map[string]any) { f["root_id"] = uuid.NewString() }, "wrong_target": func(f map[string]any) { f["target_organization_id"] = uuid.NewString() }, "negative_step": func(f map[string]any) { f["step_number"] = -1 }, "mixed_type_fields": func(f map[string]any) { f["target_kind"] = "user" }, "wrong_parent": func(f map[string]any) {
			delete(f, "step_number")
			f["resource_type"], f["relation"], f["parent_step_id"], f["target_kind"], f["target_id"] = "escalation_policy_action", "escalation_policy.step.action", uuid.NewString(), "user", uuid.NewString()
		},
	} {
		t.Run(name, func(t *testing.T) {
			var row map[string]any
			require.NoError(t, json.Unmarshal([]byte(raw), &row))
			row["event_id"], row["attempt_id"] = uuid.NewString(), uuid.NewString()
			f := row["effects"].([]any)[0].(map[string]any)
			change(f)
			b, err := json.Marshal(row)
			require.NoError(t, err)
			_, err = db.ExecContext(ctx, `INSERT INTO escalation_policy_delete_audit_events SELECT (jsonb_populate_record(NULL::escalation_policy_delete_audit_events,$1::jsonb)).*`, string(b))
			var pg *pgconn.PgError
			require.ErrorAs(t, err, &pg)
			require.Equal(t, "23514", pg.Code)
		})
	}
	// Duplicate effect identity must fail independently of effect_id uniqueness.
	e.EventID, e.AttemptID = uuid.New(), uuid.New()
	copyStep := step
	copyStep.EffectID = uuid.New()
	e.Effects = []epaudit.Effect{step, copyStep}
	b, err := json.Marshal(e.Effects)
	require.NoError(t, err)
	var valid bool
	require.NoError(t, db.QueryRowContext(ctx, `SELECT escalation_policy_delete_effects_valid($1::jsonb,$2,$3)`, string(b), e.RootID, e.TargetOrganizationID).Scan(&valid))
	require.False(t, valid)
	// Default PA is a valid Human success, independently enforced by SQL.
	e = sd5SchemaEvent()
	e.ActorKind, e.ActorID, e.HomeOrganizationID, e.AuthoritySource, e.AuthorityRole, e.OrganizationRole = "human", uuid.New(), uuid.MustParse("296e2656-7221-53fe-bd0a-832d24ccfd03"), "current_local_user_organization_at_admission", "platform_admin", "NONE"
	tx, err = db.BeginTx(ctx, nil)
	require.NoError(t, err)
	require.NoError(t, epaudit.Append(ctx, tx, e))
	require.NoError(t, tx.Commit())
	var publicFunction bool
	require.NoError(t, db.QueryRowContext(ctx, `SELECT EXISTS(SELECT FROM pg_proc p,LATERAL aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a WHERE p.oid='escalation_policy_delete_effects_valid(jsonb,uuid,uuid)'::regprocedure AND a.grantee=0)`).Scan(&publicFunction))
	require.False(t, publicFunction)
}

// Exercise the count boundary and PostgreSQL's distinct encoding budget with
// bounded closed fixtures. These validate the schema, not actual business deletes.
func TestPostgresEscalationPolicyDeleteEffectsBudgets(t *testing.T) {
	ctx, _, db := boundedAuditDB(t, len(Names()))
	e := sd5SchemaEvent()
	for i := 0; i < epaudit.MaxEffects; i++ {
		e.Effects = append(e.Effects, sd5SchemaEffect(e, 0))
	}
	raw, err := json.Marshal(e.Effects)
	require.NoError(t, err)
	var valid bool
	var bytes int
	require.NoError(t, db.QueryRowContext(ctx, `SELECT escalation_policy_delete_effects_valid($1::jsonb,$2,$3),octet_length($1::jsonb::text)`, string(raw), e.RootID, e.TargetOrganizationID).Scan(&valid, &bytes))
	require.True(t, valid)
	t.Logf("16384 step effects: Go=%d PG text=%d", len(raw), bytes)
	e.Effects = append(e.Effects, sd5SchemaEffect(e, 0))
	raw, err = json.Marshal(e.Effects)
	require.NoError(t, err)
	require.NoError(t, db.QueryRowContext(ctx, `SELECT escalation_policy_delete_effects_valid($1::jsonb,$2,$3)`, string(raw), e.RootID, e.TargetOrganizationID).Scan(&valid))
	require.False(t, valid)
	// All typed JSON strings have closed bounded values. JSONB text adds spaces;
	// measure the nearest reachable boundary with Favorite rows, without padding.
	e = sd5SchemaEvent()
	owner, org := uuid.New(), uuid.New()
	f := sd5SchemaEffect(e, 0)
	number := int64(1)
	f.ResourceType, f.ResourceUUID, f.StepNumber, f.ResourceNumericID, f.OwnerUserID, f.OwnerOrganizationID, f.OwnerOrgResolution, f.Relation, f.Change = epaudit.Favorite, nil, nil, &number, &owner, &org, "known_normal", "escalation_policy.favorite", "relationship_removed"
	one, _ := json.Marshal(f)
	var unit int
	require.NoError(t, db.QueryRowContext(ctx, `SELECT octet_length($1::jsonb::text)`, string(one)).Scan(&unit))
	// Fixed 5-digit row IDs make each effect equal in length. Arrays add 2 bytes
	// per member (comma+space), with brackets replacing the final delimiter.
	n := (epaudit.MaxJSONBytes) / (unit + 6)
	for i := 0; i < n+100; i++ {
		x := f
		id := int64(10000 + i)
		x.ResourceNumericID = &id
		x.EffectID = uuid.New()
		e.Effects = append(e.Effects, x)
	}
	// Find the exact last prefix accepted by effects::text's 8 MiB byte count.
	lo, hi := 0, len(e.Effects)
	for lo < hi {
		mid := (lo + hi + 1) / 2
		b, _ := json.Marshal(e.Effects[:mid])
		require.NoError(t, db.QueryRowContext(ctx, `SELECT octet_length($1::jsonb::text)`, string(b)).Scan(&bytes))
		if bytes <= epaudit.MaxJSONBytes {
			lo = mid
		} else {
			hi = mid - 1
		}
	}
	require.Less(t, lo, len(e.Effects))
	require.Less(t, lo, epaudit.MaxEffects)
	for _, count := range []int{lo, lo + 1} {
		b, _ := json.Marshal(e.Effects[:count])
		require.NoError(t, db.QueryRowContext(ctx, `SELECT escalation_policy_delete_effects_valid($1::jsonb,$2,$3),octet_length($1::jsonb::text)`, string(b), e.RootID, e.TargetOrganizationID).Scan(&valid, &bytes))
		require.Equal(t, count == lo, valid)
		t.Logf("byte boundary effects=%d Go=%d PG text=%d valid=%t", count, len(b), bytes, valid)
	}
}

func TestEscalationPolicyDeleteAudit299CanonicalHistory(t *testing.T) {
	h, err := loadEmbeddedHistory()
	require.NoError(t, err)
	require.Len(t, h.entries, 299)
	e := h.entries[298]
	require.Equal(t, "20261111121850-escalation-policy-delete-audit.sql", e.ID)
	require.Equal(t, h.entries[297].ID, e.PredecessorID)
	marker := []byte(",\n    {\n      \"id\": \"ms-oncall-escalation-policy-delete-audit-d09-sd5\",")
	i := bytes.Index(h.manifest, marker)
	require.Positive(t, i)
	prefix := append(append([]byte{}, h.manifest[:i]...), []byte("\n  ]\n}\n")...)
	require.Equal(t, "a97a0d389d796b166e726ae71c304bb634dc337bbf60fb1ef65e84e76972dcfc", fmt.Sprintf("%x", sha256.Sum256(prefix)))
}
func TestPostgresEscalationPolicyDeleteAuditSchemaAndReplay(t *testing.T) {
	for _, start := range []int{298, 299} {
		t.Run(fmt.Sprint(start), func(t *testing.T) { escalationPolicyDeleteAuditSchemaAndReplay(t, start) })
	}
}
func escalationPolicyDeleteAuditSchemaAndReplay(t *testing.T, start int) {
	ctx, uri, db := boundedAuditDB(t, start)
	var version string
	require.NoError(t, db.QueryRowContext(ctx, `SELECT current_setting('server_version')`).Scan(&version))
	t.Log("Actual PostgreSQL version:", version)
	f := newBoundedFixture(t, ctx, db)
	policy := uuid.New()
	_, err := db.ExecContext(ctx, `INSERT INTO escalation_policies(id,organization_id,name) VALUES($1,$2,'SD5 synthetic')`, policy, f.org)
	require.NoError(t, err)
	n, err := Up(ctx, uri, "")
	require.NoError(t, err)
	require.Equal(t, len(Names())-start, n)
	require.NoError(t, VerifyAll(ctx, uri))
	require.NoError(t, VerifyIsLatest(ctx, uri))
	var owner, insertOK, execOK, publicTable, publicFunction bool
	require.NoError(t, db.QueryRowContext(ctx, `SELECT pg_get_userbyid(c.relowner)=current_user,has_table_privilege(current_user,c.oid,'INSERT'),has_function_privilege(current_user,'escalation_policy_delete_append_only()','EXECUTE'),EXISTS(SELECT FROM aclexplode(coalesce(c.relacl,acldefault('r',c.relowner))) WHERE grantee=0),EXISTS(SELECT FROM pg_proc p,LATERAL aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a WHERE p.oid='escalation_policy_delete_append_only()'::regprocedure AND a.grantee=0) FROM pg_class c WHERE c.oid='escalation_policy_delete_audit_events'::regclass`).Scan(&owner, &insertOK, &execOK, &publicTable, &publicFunction))
	require.True(t, owner)
	require.True(t, insertOK)
	require.True(t, execOK)
	require.False(t, publicTable)
	require.False(t, publicFunction)
	e := epaudit.Event{SchemaVersion: 1, EffectsVersion: 1, EventID: uuid.New(), RequestID: uuid.New(), ExecutionID: uuid.New(), AttemptID: uuid.New(), RecordKind: "success_witness", RootID: policy, TargetOrganizationID: f.org, TargetOrgResolution: "known_normal", Provenance: "EXPLICIT", DeletionMechanism: "explicit_sql", Cause: "explicit_target", ActorKind: "internal_system", AuthoritySource: "trusted_internal_system", AuthorityRole: "internal_system", OrganizationRole: "unknown", Outcome: "committed", Reason: "deleted", OccurredAt: time.Now()}
	tx, err := db.BeginTx(ctx, nil)
	require.NoError(t, err)
	require.NoError(t, epaudit.Append(ctx, tx, e))
	require.NoError(t, epaudit.Append(ctx, tx, e))
	// The same migrated PostgreSQL identity stages audit INSERT and business DELETE.
	_, err = tx.ExecContext(ctx, `DELETE FROM escalation_policies WHERE id=$1`, policy)
	require.NoError(t, err)
	require.NoError(t, tx.Commit())
	var raw string
	require.NoError(t, db.QueryRowContext(ctx, `SELECT to_jsonb(e)::text FROM escalation_policy_delete_audit_events e WHERE event_id=$1`, e.EventID).Scan(&raw))
	require.NotContains(t, raw, "SYNTHETIC_")
	tx, err = db.BeginTx(ctx, nil)
	require.NoError(t, err)
	conflict := e
	conflict.TargetOrganizationID = uuid.New()
	require.ErrorIs(t, epaudit.Append(ctx, tx, conflict), epaudit.ErrConflict)
	require.NoError(t, tx.Rollback())
	tx, err = db.BeginTx(ctx, nil)
	require.NoError(t, err)
	duplicate := e
	duplicate.EventID = uuid.New()
	require.ErrorIs(t, epaudit.Append(ctx, tx, duplicate), epaudit.ErrUnavailable)
	require.NoError(t, tx.Rollback())
	// Bypass the typed writer: SQL itself rejects invalid/null closed fields.
	for field, value := range map[string]any{"root_type": "other", "cause": "SYNTHETIC_SECRET", "schema_version": 2, "operation": "other", "record_kind": "other", "root_id": nil, "effects_version": 2, "target_organization_id": nil, "target_org_resolution": "unknown", "actor_kind": "unknown", "authority_source": "caller", "provenance": "CASCADE", "deletion_mechanism": "fk_cascade", "outcome": "tx_failed", "reason_code": "SYNTHETIC_SECRET", "actor_id": uuid.NewString(), "occurred_at": "infinity"} {
		t.Run(field, func(t *testing.T) {
			var row map[string]any
			require.NoError(t, json.Unmarshal([]byte(raw), &row))
			row["event_id"], row["attempt_id"] = uuid.NewString(), uuid.NewString()
			row[field] = value
			b, err := json.Marshal(row)
			require.NoError(t, err)
			_, err = db.ExecContext(ctx, `INSERT INTO escalation_policy_delete_audit_events SELECT (jsonb_populate_record(NULL::escalation_policy_delete_audit_events,$1::jsonb)).*`, string(b))
			var pg *pgconn.PgError
			require.ErrorAs(t, err, &pg)
			require.Equal(t, "23514", pg.Code)
		})
	}
	for _, q := range []string{`UPDATE escalation_policy_delete_audit_events SET reason_code=reason_code`, `DELETE FROM escalation_policy_delete_audit_events`, `TRUNCATE escalation_policy_delete_audit_events`} {
		_, err = db.ExecContext(ctx, q)
		var pg *pgconn.PgError
		require.ErrorAs(t, err, &pg)
		require.Equal(t, "55000", pg.Code)
	}
	var fk int
	require.NoError(t, db.QueryRowContext(ctx, `SELECT count(*) FROM pg_constraint WHERE conrelid='escalation_policy_delete_audit_events'::regclass AND contype='f'`).Scan(&fk))
	require.Zero(t, fk)
	_, err = db.ExecContext(ctx, `DELETE FROM users WHERE id=$1`, f.user)
	require.NoError(t, err)
	var after string
	require.NoError(t, db.QueryRowContext(ctx, `SELECT to_jsonb(e)::text FROM escalation_policy_delete_audit_events e WHERE event_id=$1`, e.EventID).Scan(&after))
	require.Equal(t, raw, after)
	_, err = Down(ctx, uri, "integration-key-delete-audit")
	require.Error(t, err)
}
