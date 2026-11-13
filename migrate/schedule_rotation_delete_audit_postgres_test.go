package migrate

import (
	"bytes"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
	sraudit "github.com/target/goalert/schedule/deleteaudit"
)

func sd6SchemaEvent(typ string) sraudit.Event {
	return sraudit.Event{SchemaVersion: 1, EffectsVersion: 1, RootType: typ, Operation: typ + ".delete", EventID: uuid.New(), RequestID: uuid.New(), ExecutionID: uuid.New(), AttemptID: uuid.New(), RecordKind: "success_witness", RootID: uuid.New(), TargetOrganizationID: uuid.New(), TargetOrgResolution: "known_normal", Provenance: "EXPLICIT", DeletionMechanism: "explicit_sql", Cause: "explicit_target", ActorKind: "internal_system", AuthoritySource: "trusted_internal_system", AuthorityRole: "internal_system", OrganizationRole: "unknown", Outcome: "committed", Reason: "deleted", OccurredAt: time.Now()}
}
func sd6SchemaParticipant(e sraudit.Event) sraudit.Effect {
	id := uuid.New()
	return sraudit.Effect{EffectID: uuid.New(), ResourceType: sraudit.Participant, RootID: e.RootID, TargetOrganizationID: e.TargetOrganizationID, ResourceUUID: &id, Relation: "rotation.participant", Change: "relationship_removed", Provenance: "CASCADE", DeletionMechanism: "fk_cascade", Cause: "rotation_delete", Participant: &sraudit.ParticipantDetail{UserID: uuid.New()}}
}
func TestSRDeleteAudit300CanonicalHistory(t *testing.T) {
	h, err := loadEmbeddedHistory()
	require.NoError(t, err)
	require.Len(t, h.entries, 303)
	e := h.entries[299]
	require.Equal(t, "20261112095242-schedule-rotation-delete-audit.sql", e.ID)
	require.Equal(t, h.entries[298].ID, e.PredecessorID)
	marker := []byte(",\n    {\n      \"id\": \"ms-oncall-schedule-rotation-delete-audit-d09-sd6\",")
	i := bytes.Index(h.manifest, marker)
	require.Positive(t, i)
	prefix := append(append([]byte{}, h.manifest[:i]...), []byte("\n  ]\n}\n")...)
	require.Equal(t, "e59e4433cf5dd2a3b60c613e679c1344a3f7405e7bf2f7a24af36d70fafaecfe", fmt.Sprintf("%x", sha256.Sum256(prefix)))
}

func TestPostgresSRDeleteSchemaReplayAndAtomicity(t *testing.T) {
	for _, start := range []int{299, 300} {
		t.Run(fmt.Sprint(start), func(t *testing.T) {
			ctx, uri, db := boundedAuditDB(t, start)
			n, err := Up(ctx, uri, "schedule-rotation-delete-audit")
			require.NoError(t, err)
			require.Equal(t, 300-start, n)
			_, err = Up(ctx, uri, "")
			require.NoError(t, err)
			require.NoError(t, VerifyAll(ctx, uri))
			require.NoError(t, VerifyIsLatest(ctx, uri))
			n, err = Up(ctx, uri, "")
			require.NoError(t, err)
			require.Zero(t, n)
			f := newBoundedFixture(t, ctx, db)
			app, err := sql.Open("pgx", uri)
			require.NoError(t, err)
			defer app.Close()
			var migrationSystem, appSystem string
			require.NoError(t, db.QueryRowContext(ctx, `SELECT system_identifier::text FROM pg_control_system()`).Scan(&migrationSystem))
			require.NoError(t, app.QueryRowContext(ctx, `SELECT system_identifier::text FROM pg_control_system()`).Scan(&appSystem))
			require.Equal(t, migrationSystem, appSystem)
			t.Log("Migration/Application PostgreSQL System ID:", appSystem)
			e := sd6SchemaEvent(sraudit.Schedule)
			e.RootID, e.TargetOrganizationID = f.schedule, f.org
			tx, err := app.BeginTx(ctx, nil)
			defer func() {
				if tx != nil {
					_ = tx.Rollback()
				}
			}()
			require.NoError(t, err)
			_, err = tx.ExecContext(ctx, `DELETE FROM schedules WHERE id=$1`, e.RootID)
			require.NoError(t, err)
			require.NoError(t, sraudit.Append(ctx, tx, e))
			require.NoError(t, sraudit.Append(ctx, tx, e))
			require.NoError(t, tx.Rollback())
			var nroot, naudit int
			require.NoError(t, app.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM schedules WHERE id=$1),(SELECT count(*) FROM schedule_rotation_delete_audit_events)`, e.RootID).Scan(&nroot, &naudit))
			require.Equal(t, 1, nroot)
			require.Zero(t, naudit)
			tx, err = app.BeginTx(ctx, nil)
			require.NoError(t, err)
			_, err = tx.ExecContext(ctx, `DELETE FROM schedules WHERE id=$1`, e.RootID)
			require.NoError(t, err)
			require.NoError(t, sraudit.Append(ctx, tx, e))
			require.NoError(t, tx.Commit())
			require.NoError(t, app.QueryRowContext(ctx, `SELECT count(*) FROM schedule_rotation_delete_audit_events`).Scan(&naudit))
			require.Equal(t, 1, naudit)
			for _, q := range []string{`UPDATE schedule_rotation_delete_audit_events SET outcome=outcome`, `DELETE FROM schedule_rotation_delete_audit_events`, `TRUNCATE schedule_rotation_delete_audit_events`} {
				_, err = app.ExecContext(ctx, q)
				var pg *pgconn.PgError
				require.ErrorAs(t, err, &pg)
				require.Equal(t, "55000", pg.Code)
			}
			var liveFK, publicGrant bool
			require.NoError(t, app.QueryRowContext(ctx, `SELECT EXISTS(SELECT FROM pg_constraint WHERE conrelid='schedule_rotation_delete_audit_events'::regclass AND contype='f'),EXISTS(SELECT FROM pg_class c,LATERAL aclexplode(coalesce(c.relacl,acldefault('r',c.relowner))) a WHERE c.oid='schedule_rotation_delete_audit_events'::regclass AND a.grantee=0)`).Scan(&liveFK, &publicGrant))
			require.False(t, liveFK)
			require.False(t, publicGrant)
		})
	}
}

func TestPostgresSRDeleteClosedEffects(t *testing.T) {
	ctx, _, db := boundedAuditDB(t, 300)
	e := sd6SchemaEvent(sraudit.Rotation)
	p := sd6SchemaParticipant(e)
	e.Effects = []sraudit.Effect{p}
	e.BeforeState = &sraudit.RotationState{ID: 1, ParticipantID: *p.ResourceUUID, Position: 0, Version: 2, ShiftStart: time.Now()}
	tx, err := db.BeginTx(ctx, nil)
	defer func() {
		if tx != nil {
			_ = tx.Rollback()
		}
	}()
	require.NoError(t, err)
	require.NoError(t, sraudit.Append(ctx, tx, e))
	require.NoError(t, tx.Commit())
	var raw string
	require.NoError(t, db.QueryRowContext(ctx, `SELECT to_jsonb(e)::text FROM schedule_rotation_delete_audit_events e WHERE event_id=$1`, e.EventID).Scan(&raw))
	for name, change := range map[string]func(map[string]any){"unknown_field": func(row map[string]any) { row["effects"].([]any)[0].(map[string]any)["destination"] = "SYNTHETIC_DEST" }, "unknown_detail": func(row map[string]any) {
		row["effects"].([]any)[0].(map[string]any)["participant"].(map[string]any)["name"] = "SYNTHETIC_NAME"
	}, "wrong_operation": func(row map[string]any) { row["operation"] = "schedule.delete" }, "wrong_type": func(row map[string]any) { row["root_type"] = "user" }, "zero_uuid": func(row map[string]any) {
		row["effects"].([]any)[0].(map[string]any)["resource_uuid"] = uuid.Nil.String()
	}, "state_parent": func(row map[string]any) { row["before_state"].(map[string]any)["participant_id"] = uuid.NewString() }, "state_extra": func(row map[string]any) { row["before_state"].(map[string]any)["secret"] = "SYNTHETIC_PRIVATE" }, "observation_effects": func(row map[string]any) { row["record_kind"] = "attempt_observation" }, "wrong_actor": func(row map[string]any) { row["actor_kind"] = "unknown" }} {
		t.Run(name, func(t *testing.T) {
			var row map[string]any
			require.NoError(t, json.Unmarshal([]byte(raw), &row))
			row["event_id"], row["attempt_id"] = uuid.NewString(), uuid.NewString()
			change(row)
			b, err := json.Marshal(row)
			require.NoError(t, err)
			_, err = db.ExecContext(ctx, `INSERT INTO schedule_rotation_delete_audit_events SELECT (jsonb_populate_record(NULL::schedule_rotation_delete_audit_events,$1::jsonb)).*`, string(b))
			var pg *pgconn.PgError
			require.ErrorAs(t, err, &pg)
			require.Equal(t, "23514", pg.Code)
		})
	}
}

func TestPostgresSRDeleteBudgets(t *testing.T) {
	ctx, _, db := boundedAuditDB(t, 300)
	e := sd6SchemaEvent(sraudit.Rotation)
	for i := 0; i < sraudit.MaxEffects; i++ {
		e.Effects = append(e.Effects, sd6SchemaParticipant(e))
	}
	check := func(want bool) {
		b, err := json.Marshal(e.Effects)
		require.NoError(t, err)
		s, _ := json.Marshal(e.BeforeState)
		var valid bool
		var size int
		require.NoError(t, db.QueryRowContext(ctx, `SELECT schedule_rotation_delete_effects_valid($1::jsonb,$2::jsonb,$3,$4,$5,false),octet_length($1::jsonb::text)+CASE WHEN $2::jsonb='null' THEN 0 ELSE octet_length($2::jsonb::text) END`, string(b), string(s), e.RootID, e.TargetOrganizationID, e.RootType).Scan(&valid, &size))
		t.Logf("SR budget valid=%t units=%d size=%d", valid, e.Units(), size)
		require.Equal(t, want, valid)
		t.Logf("units=%d Go=%d PG=%d accepted=%t", e.Units(), e.JSONBytes(), size, valid)
	}
	check(true)
	e.BeforeState = &sraudit.RotationState{ID: 1, ParticipantID: *e.Effects[0].ResourceUUID, Version: 2, ShiftStart: time.Now()}
	check(false)
	e.BeforeState = nil
	e.Effects = append(e.Effects, sd6SchemaParticipant(e))
	check(false)
	// The nearest reachable PostgreSQL byte boundary must be independently
	// enforced, even when compact Go JSON still fits.
	e = sd6SchemaEvent(sraudit.Schedule)
	owner, org := uuid.New(), uuid.New()
	for i := 0; i < sraudit.MaxEffects; i++ {
		id := int64(10000 + i)
		e.Effects = append(e.Effects, sraudit.Effect{EffectID: uuid.New(), ResourceType: sraudit.Favorite, RootID: e.RootID, TargetOrganizationID: e.TargetOrganizationID, Relation: "schedule.favorite", Change: "relationship_removed", Provenance: "CASCADE", DeletionMechanism: "fk_cascade", Cause: "schedule_delete", ResourceNumericID: &id, Favorite: &sraudit.FavoriteDetail{OwnerUserID: owner, OwnerOrganizationID: &org, OwnerOrgResolution: "known_normal"}})
	}
	all := e.Effects
	lo, hi := 0, len(all)
	for lo < hi {
		mid := (lo + hi + 1) / 2
		b, _ := json.Marshal(all[:mid])
		var size int
		require.NoError(t, db.QueryRowContext(ctx, `SELECT octet_length($1::jsonb::text)`, string(b)).Scan(&size))
		if size <= sraudit.MaxJSONBytes {
			lo = mid
		} else {
			hi = mid - 1
		}
	}
	require.Less(t, lo, len(all))
	e.Effects = all[:lo]
	check(true)
	e.Effects = all[:lo+1]
	check(false)
}
