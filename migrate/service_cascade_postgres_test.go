package migrate

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/service/deleteaudit"
	cmnraudit "github.com/target/goalert/user/cmnrdeleteaudit"
)

func TestServiceCascade297CanonicalHistory(t *testing.T) {
	h, err := loadEmbeddedHistory()
	require.NoError(t, err)
	require.Len(t, h.entries, 299)
	e := h.entries[296]
	require.EqualValues(t, 297, e.Position)
	require.Equal(t, "20261110172342-service-cascade-b2-effects.sql", e.ID)
	require.Equal(t, h.entries[295].ID, e.PredecessorID)
	for i, want := range map[int]string{294: "062dd95cde1a2880178074c2f5884c1cdd1a4da69f00090662dcd81dd917509f", 295: "5cb15dbf9926f185cad5393adc42a38a0c2a24cc85be5665551f606f968e230b"} {
		raw, err := migrationFS.ReadFile("migrations/" + h.entries[i].ID)
		require.NoError(t, err)
		require.Equal(t, want, fmt.Sprintf("%x", sha256.Sum256(raw)))
	}
}

func TestPostgresServiceCascadePG17HistoryAndPG19KeyIdentity(t *testing.T) {
	for _, start := range []int{294, 295, 296} {
		t.Run(fmt.Sprint(start), func(t *testing.T) {
			ctx, uri, db := boundedAuditDB(t, start)
			if start < 296 {
				_, err := Up(ctx, uri, "user-cmnr-delete-audit")
				require.NoError(t, err)
			}
			f := newBoundedFixture(t, ctx, db)
			policy, svc, key := uuid.New(), uuid.New(), uuid.New()
			_, err := db.ExecContext(ctx, `INSERT INTO escalation_policies(id,organization_id,name) VALUES($1,$2,'SD3 migration')`, policy, f.org)
			require.NoError(t, err)
			_, err = db.ExecContext(ctx, `INSERT INTO services(id,organization_id,name,escalation_policy_id) VALUES($1,$2,'SD3 migration',$3)`, svc, f.org, policy)
			require.NoError(t, err)
			_, err = db.ExecContext(ctx, `INSERT INTO integration_keys(id,service_id,name,type) VALUES($1,$2,'SD3 migration','generic')`, key, svc)
			require.NoError(t, err)
			old := serviceDeleteDBEvent()
			cm := cmnrDBEvent()
			tx, err := db.BeginTx(ctx, nil)
			require.NoError(t, err)
			require.NoError(t, appendLegacyServiceDelete(ctx, tx, old))
			require.NoError(t, tx.Commit())
			tx, err = db.BeginTx(ctx, nil)
			require.NoError(t, err)
			// Historical CMNR is unchanged by 297, including all its existing fields.
			require.NoError(t, cmnraudit.Append(ctx, tx, cm))
			require.NoError(t, tx.Commit())
			var before, cmBefore string
			require.NoError(t, db.QueryRowContext(ctx, `SELECT to_jsonb(e)::text FROM service_delete_audit_events e`).Scan(&before))
			require.NoError(t, db.QueryRowContext(ctx, `SELECT to_jsonb(e)::text FROM user_cmnr_delete_audit_events e`).Scan(&cmBefore))
			n, err := Up(ctx, uri, "")
			require.NoError(t, err)
			require.Equal(t, len(Names())-296, n)
			require.NoError(t, VerifyAll(ctx, uri))
			require.NoError(t, VerifyIsLatest(ctx, uri))
			var after, cmAfter string
			var historical bool
			require.NoError(t, db.QueryRowContext(ctx, `SELECT (to_jsonb(e)-ARRAY['effects_version','execution_id','effects'])::text,effects_version IS NULL AND execution_id IS NULL AND effects IS NULL FROM service_delete_audit_events e`).Scan(&after, &historical))
			require.JSONEq(t, before, after)
			require.True(t, historical)
			require.NoError(t, db.QueryRowContext(ctx, `SELECT to_jsonb(e)::text FROM user_cmnr_delete_audit_events e`).Scan(&cmAfter))
			require.Equal(t, cmBefore, cmAfter)
			var safe uuid.UUID
			require.NoError(t, db.QueryRowContext(ctx, `SELECT audit_resource_id FROM integration_keys WHERE id=$1`, key).Scan(&safe))
			require.NotEqual(t, uuid.Nil, safe)
			require.NotEqual(t, key, safe)
			_, err = db.ExecContext(ctx, `UPDATE integration_keys SET name='metadata updated',audit_resource_id=audit_resource_id WHERE id=$1`, key)
			require.NoError(t, err)
			_, err = db.ExecContext(ctx, `UPDATE integration_keys SET audit_resource_id=gen_random_uuid() WHERE id=$1`, key)
			var pg *pgconn.PgError
			require.ErrorAs(t, err, &pg)
			require.Equal(t, "55000", pg.Code)
			newKey := uuid.New()
			var newSafe uuid.UUID
			require.NoError(t, db.QueryRowContext(ctx, `INSERT INTO integration_keys(id,service_id,name,type) VALUES($1,$2,'SD3 new','generic') RETURNING audit_resource_id`, newKey, svc).Scan(&newSafe))
			require.NotEqual(t, newKey, newSafe)
			require.NotEqual(t, safe, newSafe)
			require.NotEqual(t, uuid.Nil, newSafe)
			var service uuid.UUID
			require.NoError(t, db.QueryRowContext(ctx, `SELECT service_id FROM integration_keys WHERE id=$1 AND type='generic'`, key).Scan(&service))
			require.Equal(t, svc, service)
			_, err = Down(ctx, uri, "user-cmnr-delete-audit")
			require.Error(t, err)
		})
	}
}

func TestPostgresServiceCascadePG18StrictEnvelopeAndU05Replay(t *testing.T) {
	ctx, _, db := boundedAuditDB(t, len(Names()))
	e := serviceDeleteDBEvent()
	key := uuid.New()
	n := int64(9223372036854775807)
	e.Effects = []deleteaudit.Effect{{EffectID: uuid.New(), ResourceType: deleteaudit.IntegrationKey, ResourceUUID: &key, OwnerOrgResolution: "not_applicable", TargetOrganizationID: e.TargetOrganizationID, Relation: "service.integration_key", Change: "deleted", Provenance: "EXPLICIT", DeletionMechanism: "explicit_sql", Cause: "explicit_target"}, {EffectID: uuid.New(), ResourceType: deleteaudit.Alert, ResourceNumericID: &n, OwnerOrgResolution: "not_applicable", TargetOrganizationID: e.TargetOrganizationID, Relation: "service.alert", Change: "deleted", Provenance: "CASCADE", DeletionMechanism: "fk_cascade", Cause: "service_delete"}}
	e = e.Canonical()
	tx, err := db.BeginTx(ctx, nil)
	require.NoError(t, err)
	require.NoError(t, deleteaudit.Append(ctx, tx, e))
	require.NoError(t, deleteaudit.Append(ctx, tx, e))
	for name, change := range map[string]func(*deleteaudit.Event){
		"execution": func(e *deleteaudit.Event) { e.ExecutionID = uuid.New() }, "request": func(e *deleteaudit.Event) { e.RequestID = uuid.New() }, "attempt": func(e *deleteaudit.Event) { e.AttemptID = uuid.New() },
		"time": func(e *deleteaudit.Event) { e.OccurredAt = e.OccurredAt.Add(time.Second) }, "effect": func(e *deleteaudit.Event) { e.Effects[0].EffectID = uuid.New() },
		"provenance": func(e *deleteaudit.Event) { e.Effects[0].Provenance = "EXPLICIT" }, "actor": func(e *deleteaudit.Event) { e.ActorID = uuid.New() }, "root": func(e *deleteaudit.Event) { e.ServiceID = uuid.New() },
	} {
		t.Run(name, func(t *testing.T) {
			c := e.Canonical()
			change(&c)
			require.ErrorIs(t, deleteaudit.Append(ctx, tx, c), deleteaudit.ErrConflict)
		})
	}
	require.NoError(t, tx.Commit())
	var recorded time.Time
	require.NoError(t, db.QueryRowContext(ctx, `SELECT recorded_at FROM service_delete_audit_events WHERE event_id=$1`, e.EventID).Scan(&recorded))
	for name, patch := range map[string]string{
		"legacy":  "jsonb_build_object('effects_version',NULL,'execution_id',NULL,'effects',NULL)",
		"version": "jsonb_build_object('effects_version',2)", "execution": "jsonb_build_object('execution_id','00000000-0000-0000-0000-000000000000')",
		"extra key": `jsonb_build_object('effects',jsonb_set(effects,'{0,metadata}','"SYNTHETIC_SECRET"'))`,
		"whitelist": `jsonb_build_object('effects',jsonb_set(effects,'{0,resource_type}','"heartbeat_monitor"'))`,
		"fraction":  `jsonb_build_object('effects',jsonb_set(effects,'{0,resource_numeric_id}','1.5'))`,
		"overflow":  `jsonb_build_object('effects',jsonb_set(effects,'{0,resource_numeric_id}','9223372036854775808'))`,
		"duplicate": `jsonb_build_object('effects',effects||effects)`, "order": `jsonb_build_object('effects',jsonb_build_array(effects->1,effects->0))`,
		"owner":  `jsonb_build_object('effects',jsonb_set(effects,'{0,owner_user_id}',to_jsonb(gen_random_uuid())))`,
		"target": `jsonb_build_object('effects',jsonb_set(effects,'{0,target_organization_id}',to_jsonb(gen_random_uuid())))`,
		"object": `jsonb_build_object('effects','{}'::jsonb)`, "failed nonempty": `jsonb_build_object('outcome','commit_unknown','reason_code','commit_unconfirmed')`,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := db.ExecContext(ctx, `INSERT INTO service_delete_audit_events SELECT (jsonb_populate_record(NULL::service_delete_audit_events,to_jsonb(e)||jsonb_build_object('event_id',gen_random_uuid(),'attempt_id',gen_random_uuid())||`+patch+`)).* FROM service_delete_audit_events e WHERE event_id=$1`, e.EventID)
			var pg *pgconn.PgError
			require.ErrorAs(t, err, &pg)
			require.Equal(t, "23514", pg.Code)
		})
	}
	for _, q := range []string{`UPDATE service_delete_audit_events SET effects=effects WHERE false`, `DELETE FROM service_delete_audit_events WHERE false`, `TRUNCATE service_delete_audit_events`} {
		_, err := db.ExecContext(ctx, q)
		var pg *pgconn.PgError
		require.ErrorAs(t, err, &pg)
		require.Equal(t, "55000", pg.Code)
	}
	unknown := e
	unknown.EventID = uuid.New()
	unknown.Outcome, unknown.Reason, unknown.Effects = "commit_unknown", "commit_unconfirmed", nil
	require.NoError(t, deleteaudit.RecordFailures(db, []deleteaudit.Event{unknown}))
	var count, unknownCount int
	var unchanged time.Time
	require.NoError(t, db.QueryRowContext(ctx, `SELECT count(*) FILTER(WHERE outcome='committed' AND jsonb_array_length(effects)=2),count(*) FILTER(WHERE outcome='commit_unknown' AND effects='[]'::jsonb) FROM service_delete_audit_events`).Scan(&count, &unknownCount))
	require.Equal(t, 1, count)
	require.Equal(t, 1, unknownCount)
	require.NoError(t, db.QueryRowContext(ctx, `SELECT recorded_at FROM service_delete_audit_events WHERE event_id=$1`, e.EventID).Scan(&unchanged))
	require.Equal(t, recorded, unchanged)
	var fks int
	require.NoError(t, db.QueryRowContext(ctx, `SELECT count(*) FROM pg_constraint WHERE contype='f' AND conrelid='service_delete_audit_events'::regclass`).Scan(&fks))
	require.Zero(t, fks)
	raw, err := json.Marshal(e.Effects)
	require.NoError(t, err)
	require.False(t, strings.Contains(string(raw), "SYNTHETIC_"))
}

func TestPostgresServiceCascadePG13JSONBExactByteBoundary(t *testing.T) {
	ctx, _, db := boundedAuditDB(t, len(Names()))
	e := serviceDeleteDBEvent()
	owner := uuid.New()
	org := e.TargetOrganizationID
	n := int64(1000000000000000000)
	f := deleteaudit.Effect{EffectID: uuid.New(), ResourceType: deleteaudit.ServiceFavorite, ResourceNumericID: &n, OwnerUserID: &owner, OwnerOrganizationID: &org, OwnerOrgResolution: "known_normal", TargetOrganizationID: org, Relation: "service.favorite", Change: "relationship_removed", Provenance: "CASCADE", DeletionMechanism: "fk_cascade", Cause: "service_delete"}
	raw, err := json.Marshal([]deleteaudit.Effect{f})
	require.NoError(t, err)
	var unit int
	require.NoError(t, db.QueryRowContext(ctx, `SELECT octet_length($1::jsonb::text)`, string(raw)).Scan(&unit))
	count := (deleteaudit.MaxJSONBytes + unit - 1) / unit
	reduce := count*unit - deleteaudit.MaxJSONBytes
	require.LessOrEqual(t, count, deleteaudit.MaxEffects)
	require.Less(t, reduce, count)
	require.Positive(t, reduce)
	for i := 0; i < count; i++ {
		v := int64(1000000000000000000) + int64(i)
		if i < reduce {
			v = int64(100000000000000000) + int64(i)
		}
		copy := f
		copy.EffectID = uuid.New()
		copy.ResourceNumericID = &v
		e.Effects = append(e.Effects, copy)
	}
	require.NoError(t, e.Validate())
	raw, err = json.Marshal(e.Canonical().Effects)
	require.NoError(t, err)
	require.Less(t, len(raw), deleteaudit.MaxJSONBytes)
	var size int
	require.NoError(t, db.QueryRowContext(ctx, `SELECT octet_length($1::jsonb::text)`, string(raw)).Scan(&size))
	require.Equal(t, deleteaudit.MaxJSONBytes, size)
	tx, err := db.BeginTx(ctx, nil)
	require.NoError(t, err)
	require.NoError(t, deleteaudit.Append(ctx, tx, e))
	require.NoError(t, tx.Commit())
	require.NoError(t, db.QueryRowContext(ctx, `SELECT octet_length(effects::text) FROM service_delete_audit_events WHERE event_id=$1`, e.EventID).Scan(&size))
	require.Equal(t, deleteaudit.MaxJSONBytes, size)
	over := e.Canonical()
	over.EventID, over.AttemptID = uuid.New(), uuid.New()
	larger := int64(2000000000000000000)
	over.Effects[0].ResourceNumericID = &larger
	over = over.Canonical()
	raw, err = json.Marshal(over.Effects)
	require.NoError(t, err)
	require.Less(t, len(raw), deleteaudit.MaxJSONBytes)
	require.NoError(t, over.Validate(), "compact Go bytes alone cannot enforce the JSONB-text limit")
	require.NoError(t, db.QueryRowContext(ctx, `SELECT octet_length($1::jsonb::text)`, string(raw)).Scan(&size))
	require.Equal(t, deleteaudit.MaxJSONBytes+1, size)
	tx, err = db.BeginTx(ctx, nil)
	require.NoError(t, err)
	require.ErrorIs(t, deleteaudit.Append(ctx, tx, over), deleteaudit.ErrUnavailable)
	require.NoError(t, tx.Rollback())
	t.Logf("exact JSONB boundary: %d bytes / %d effects; compact encoding %d bytes; +1 byte rejected", deleteaudit.MaxJSONBytes, count, len(raw))
}
