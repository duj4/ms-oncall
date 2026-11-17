package migrate

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/assignment"
	"github.com/target/goalert/auth"
	"github.com/target/goalert/auth/sessionaudit"
	ds "github.com/target/goalert/deletionsafety"
	pgdump "github.com/target/goalert/devtools/pgdump-lite"
	"github.com/target/goalert/executioncontext"
	"github.com/target/goalert/organization"
	"github.com/target/goalert/permission"
	audit "github.com/target/goalert/user/deleteaudit"
)

func TestUserDeleteSession307CanonicalAppend(t *testing.T) {
	h, err := loadEmbeddedHistory()
	require.NoError(t, err)
	require.Len(t, h.entries, 307)
	marker := []byte(",\n    {\n      \"id\": \"ms-oncall-user-delete-session-audit-identity-d09-fix1\",")
	i := bytes.Index(h.manifest, marker)
	require.Positive(t, i)
	prefix := append(append([]byte{}, h.manifest[:i]...), []byte("\n  ]\n}\n")...)
	// Pins all 306 accepted SQL identities and source/provenance metadata.
	require.Equal(t, "34bc4e30bd3d95a90f47a265dbe1d6adce70d830933a4974bb66ccc75a5773c5", fmt.Sprintf("%x", sha256.Sum256(prefix)))
	tail := h.latest()
	require.Equal(t, int64(307), tail.Position)
	require.Equal(t, h.entries[305].ID, tail.PredecessorID)
	require.Equal(t, "20261117160628-user-delete-session-audit-identity-v2.sql", tail.ID)
	parsed, err := parseMigrations(h)
	require.NoError(t, err)
	require.False(t, parsed[306].Up.disableTx)
	require.False(t, parsed[306].Down.disableTx)
}

// Audit adapter harness only: never calls or bypasses the User deletion guard.
// The synthetic Root receipt does not claim successful product User deletion.
func sessionIdentitySpool(t *testing.T, ctx context.Context, tx *sql.Tx) {
	t.Helper()
	_, err := tx.ExecContext(ctx, `CREATE TEMP TABLE sd8_user_delete_witness (
 root_ordinal integer NOT NULL,resource_type text NOT NULL,resource_key text NOT NULL,
 before_value jsonb NOT NULL,after_value jsonb NOT NULL DEFAULT 'null',organization_id uuid,org_resolution text NOT NULL,
 emit boolean NOT NULL DEFAULT true,effect_id uuid NOT NULL DEFAULT gen_random_uuid(),payload jsonb,
 PRIMARY KEY(root_ordinal,resource_type,resource_key)) ON COMMIT DROP`)
	require.NoError(t, err)
}

func sessionIdentityRoot(root uuid.UUID) audit.Event {
	e := sd8SchemaEvent()
	e.RootID, e.BeforeContext.UserID = &root, root
	return e
}

func sessionIdentityFinalize(t *testing.T, ctx context.Context, tx *sql.Tx, e audit.Event) audit.Receipt {
	t.Helper()
	// Same closed Effect model and real AppendReceipt as the SD8 adapter. The
	// complete actual CaptureSessions output is used, including nonempty pages.
	_, err := tx.ExecContext(ctx, `UPDATE pg_temp.sd8_user_delete_witness SET payload=jsonb_build_object(
 'effect_id',effect_id,'resource_type',resource_type,'resource_key',resource_key,'transition_slot','row',
 'trigger_user_id',$1::uuid,'target_organization_id',organization_id,'org_resolution',org_resolution,
 'change','deleted','provenance','IMPLICIT_FK_CASCADE','deletion_mechanism','fk_cascade','before',before_value,'after',after_value)
 WHERE root_ordinal=$2`, *e.RootID, *e.RootOrdinal)
	require.NoError(t, err)
	require.NoError(t, tx.QueryRowContext(ctx, `SELECT count(*),coalesce(sum(octet_length(payload::text)),0) FROM pg_temp.sd8_user_delete_witness WHERE root_ordinal=$1`, *e.RootOrdinal).Scan(&e.EffectCount, &e.EffectJSONBytes))
	e.Manifest = map[string]int64{}
	if e.EffectCount > 0 {
		e.Manifest["user_session"] = e.EffectCount
	}
	return audit.Receipt{Event: e, DeletedUserID: *e.RootID, DeletedRole: e.BeforeContext.UserRole, DeletedRowVersion: e.BeforeContext.RowVersion}
}

func sessionIdentityCreate(t *testing.T, ctx context.Context, db *sql.DB, f userPhaseAFixture, count int) ([]uuid.UUID, []uuid.UUID) {
	t.Helper()
	h, err := auth.NewHandler(ctx, db, auth.HandlerConfig{UserStore: f.users})
	require.NoError(t, err)
	var locators, safe []uuid.UUID
	for range count {
		token, err := h.CreateSession(ctx, "synthetic-contract-fix1", f.user.String())
		require.NoError(t, err)
		var id uuid.UUID
		var matches bool
		require.NoError(t, db.QueryRowContext(ctx, `SELECT audit_resource_id,user_id=$2 FROM auth_user_sessions WHERE id=$1`, token.ID, f.user).Scan(&id, &matches))
		require.True(t, matches && id != uuid.Nil && id != token.ID)
		current, err := h.FindCurrentUserSession(ctx, token.ID)
		require.NoError(t, err)
		require.NotNil(t, current)
		locators, safe = append(locators, token.ID), append(safe, id)
	}
	return locators, safe
}

func sessionIdentityNoLeak(t *testing.T, raw []byte, locators []uuid.UUID) {
	t.Helper()
	for _, id := range locators {
		// Boolean-only assertions: never print a complete synthetic locator.
		require.False(t, bytes.Contains(raw, []byte(id.String())), "Session locator leaked")
	}
}

func TestPostgresUserDeleteSessionIdentityCaptureAndPersistence(t *testing.T) {
	base, _, db := boundedAuditDB(t, len(Names()))
	ctx := permission.SystemContext(base, "SessionContractFix1")
	other := newUserPhaseAFixture(t, ctx, db)
	_, otherSafe := sessionIdentityCreate(t, ctx, db, other, 2)
	for _, count := range []int{0, 1, 3, 257} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			f := newUserPhaseAFixture(t, ctx, db)
			require.NoError(t, f.users.SetAuthSubject(ctx, "synthetic-contract-provider", uuid.NewString(), f.user.String()))
			locators, safe := sessionIdentityCreate(t, ctx, db, f, count)
			e := sessionIdentityRoot(f.user)
			tx := userPhaseATx(t, ctx, db)
			sessionIdentitySpool(t, ctx, tx)
			org, err := audit.SnapshotOrganization(ctx, tx, f.user)
			require.NoError(t, err)
			require.NoError(t, audit.CaptureSessions(ctx, tx, f.user, 0, e.EventID, org))
			var captured int
			var exact bool
			require.NoError(t, tx.QueryRowContext(ctx, `SELECT count(*),coalesce(bool_and(
 i.audit_resource_id::text=w.resource_key AND i.user_id=$1 AND w.before_value->>'user_id'=$1::text
 AND w.before_value->>'audit_resource_id'=i.audit_resource_id::text AND w.before_value->'version'='2'
 AND NOT w.before_value ? 'id'),true) FROM pg_temp.sd8_user_delete_witness w
 FULL JOIN pg_temp.sd8_user_session_identity i ON i.audit_resource_id::text=w.resource_key`, f.user).Scan(&captured, &exact))
			require.Equal(t, count, captured)
			require.True(t, exact)
			var snapshot []byte
			require.NoError(t, tx.QueryRowContext(ctx, `SELECT coalesce(jsonb_agg(to_jsonb(w)),'[]') FROM pg_temp.sd8_user_delete_witness w`).Scan(&snapshot))
			sessionIdentityNoLeak(t, snapshot, locators)
			_, err = tx.ExecContext(ctx, `DELETE FROM auth_user_sessions WHERE user_id=$1`, f.user)
			require.NoError(t, err)
			r := sessionIdentityFinalize(t, ctx, tx, e)
			require.NoError(t, audit.AppendReceipt(ctx, tx, r))
			// Exact retry uses the same safe contract and no duplicate effects.
			require.NoError(t, audit.AppendReceipt(ctx, tx, r))
			require.NoError(t, tx.Commit())
			var persisted []byte
			var bound bool
			require.NoError(t, db.QueryRowContext(ctx, `SELECT to_jsonb(e)||jsonb_build_object('effects',coalesce((SELECT jsonb_agg(to_jsonb(f) ORDER BY effect_ordinal) FROM user_delete_audit_effects f WHERE f.event_id=e.event_id),'[]')),
 request_id=$2 AND execution_id=$3 AND attempt_id=$4 AND root_id=$5 AND operation='user.delete' AND provenance='EXPLICIT'
 FROM user_delete_audit_events e WHERE event_id=$1`, e.EventID, e.RequestID, e.ExecutionID, e.AttemptID, f.user).Scan(&persisted, &bound))
			require.True(t, bound)
			sessionIdentityNoLeak(t, persisted, locators)
			for _, id := range safe {
				require.True(t, bytes.Contains(persisted, []byte(id.String())))
			}
			require.Equal(t, count, enforcementCount(t, ctx, db, `SELECT count(*) FROM user_delete_audit_effects WHERE event_id=$1`, e.EventID))
			require.Equal(t, 2, enforcementCount(t, ctx, db, `SELECT count(*) FROM auth_user_sessions WHERE user_id=$1`, other.user))
			for _, id := range otherSafe {
				require.False(t, bytes.Contains(persisted, []byte(id.String())))
			}
			// Real User and Organization assignment retained: audit-only harness.
			require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM users WHERE id=$1`, f.user))
			require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM user_organization_assignments WHERE user_id=$1`, f.user))
			require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM auth_subjects WHERE user_id=$1`, f.user))
		})
	}
}

func TestPostgresUserDeleteSessionIdentityValidators(t *testing.T) {
	ctx, _, db := boundedAuditDB(t, len(Names()))
	root, safe, locator := uuid.New(), uuid.New(), uuid.New()
	valid := fmt.Sprintf(`{"version":2,"audit_resource_id":%q,"user_id":%q,"row_version":1}`, safe, root)
	for _, tc := range []struct {
		name, raw string
		valid     bool
	}{
		{"v2", valid, true},
		{"historical_v1", fmt.Sprintf(`{"id":%q,"user_id":%q,"row_version":1}`, locator, root), true},
		{"missing", strings.Replace(valid, `"audit_resource_id":`+fmt.Sprintf("%q", safe)+`,`, "", 1), false},
		{"raw_field", strings.Replace(valid, "audit_resource_id", "id", 1), false},
		{"wrong_type", strings.Replace(valid, fmt.Sprintf("%q", safe), "1", 1), false},
		{"zero", strings.Replace(valid, safe.String(), uuid.Nil.String(), 1), false},
		{"unknown", strings.Replace(valid, `"version":2`, `"version":3`, 1), false},
		{"string_version", strings.Replace(valid, `"version":2`, `"version":"2"`, 1), false},
		{"fraction_version", strings.Replace(valid, `"version":2`, `"version":2.0`, 1), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			key := safe.String()
			if tc.name == "historical_v1" {
				key = locator.String()
			}
			require.True(t, (audit.ValidateSnapshot("user_session", key, []byte(tc.raw)) == nil) == tc.valid)
			var validDB bool
			require.NoError(t, db.QueryRowContext(ctx, `SELECT user_delete_snapshot_valid($1::jsonb,'user_session')`, tc.raw).Scan(&validDB))
			require.Equal(t, tc.valid, validDB)
			f := audit.Effect{EffectID: uuid.New(), ResourceType: "user_session", ResourceKey: key, TransitionSlot: "row", TriggerUserID: root, OrgResolution: "unknown", Change: "deleted", Provenance: "IMPLICIT_FK_CASCADE", DeletionMechanism: "fk_cascade", Before: json.RawMessage(tc.raw), After: json.RawMessage("null")}
			raw, err := json.Marshal(f)
			require.NoError(t, err)
			require.True(t, (f.Validate(root) == nil) == tc.valid)
			require.NoError(t, db.QueryRowContext(ctx, `SELECT user_delete_effect_valid($1::jsonb)`, string(raw)).Scan(&validDB))
			require.Equal(t, tc.valid, validDB)
			// Raw database insertion must also fail for invalid snapshots. A
			// valid v2 shape without a real capture binding is refused as well.
			tx := userPhaseATx(t, ctx, db)
			_, err = tx.ExecContext(ctx, `INSERT INTO user_delete_audit_effects VALUES($1,0,1,$2,'user_session',$3,'row',$4::jsonb)`, uuid.New(), f.EffectID, key, string(raw))
			require.Error(t, err)
			require.NoError(t, tx.Rollback())
		})
	}
}

func TestPostgresUserDeleteSessionIdentityFaultAtomicity(t *testing.T) {
	base, _, db := boundedAuditDB(t, len(Names()))
	ctx := permission.SystemContext(base, "SessionContractFix1")
	f := newUserPhaseAFixture(t, ctx, db)
	locators, _ := sessionIdentityCreate(t, ctx, db, f, 2)
	for _, mode := range []string{"append_fault", "raw_identity", "wrong_parent", "missing_binding", "live_session", "invalid_snapshot", "success"} {
		t.Run(mode, func(t *testing.T) {
			e := sessionIdentityRoot(f.user)
			tx := userPhaseATx(t, ctx, db)
			sessionIdentitySpool(t, ctx, tx)
			org, err := audit.SnapshotOrganization(ctx, tx, f.user)
			require.NoError(t, err)
			require.NoError(t, audit.CaptureSessions(ctx, tx, f.user, 0, e.EventID, org))
			if mode != "live_session" {
				_, err = tx.ExecContext(ctx, `DELETE FROM auth_user_sessions WHERE user_id=$1`, f.user)
				require.NoError(t, err)
			}
			r := sessionIdentityFinalize(t, ctx, tx, e)
			switch mode {
			case "append_fault":
				_, err = tx.ExecContext(ctx, `CREATE FUNCTION pg_temp.session_audit_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic audit fault'; END $$;
 CREATE TRIGGER session_audit_fault BEFORE INSERT ON user_delete_audit_effects FOR EACH ROW EXECUTE FUNCTION pg_temp.session_audit_fault()`)
			case "raw_identity":
				_, err = tx.ExecContext(ctx, `UPDATE pg_temp.sd8_user_delete_witness SET resource_key=$1,payload=jsonb_set(jsonb_set(payload,'{resource_key}',to_jsonb($1::text)),'{before,audit_resource_id}',to_jsonb($1::text)) WHERE resource_key=(SELECT min(resource_key) FROM pg_temp.sd8_user_delete_witness)`, locators[0].String())
			case "wrong_parent":
				_, err = tx.ExecContext(ctx, `UPDATE pg_temp.sd8_user_session_identity SET user_id=$1`, uuid.New())
			case "missing_binding":
				_, err = tx.ExecContext(ctx, `DELETE FROM pg_temp.sd8_user_session_identity`)
			case "invalid_snapshot":
				_, err = tx.ExecContext(ctx, `UPDATE pg_temp.sd8_user_delete_witness SET payload=payload #- '{before,audit_resource_id}'`)
			}
			require.NoError(t, err)
			err = audit.AppendReceipt(ctx, tx, r)
			if mode == "success" {
				require.NoError(t, err)
				require.NoError(t, tx.Commit())
				require.Equal(t, 2, enforcementCount(t, ctx, db, `SELECT count(*) FROM user_delete_audit_effects WHERE event_id=$1`, e.EventID))
			} else {
				require.Error(t, err)
				sessionIdentityNoLeak(t, []byte(err.Error()), locators)
				require.NoError(t, tx.Rollback())
				require.Zero(t, enforcementCount(t, ctx, db, `SELECT count(*) FROM user_delete_audit_events WHERE event_id=$1`, e.EventID))
				require.Zero(t, enforcementCount(t, ctx, db, `SELECT count(*) FROM user_delete_audit_effects WHERE event_id=$1`, e.EventID))
				require.Equal(t, 2, enforcementCount(t, ctx, db, `SELECT count(*) FROM auth_user_sessions WHERE user_id=$1`, f.user))
			}
		})
	}
}

func TestPostgresUserDeleteSession307HistoricalCompatibility(t *testing.T) {
	ctx, uri, db := boundedAuditDB(t, 306)
	e := sd8SchemaEvent()
	locator := uuid.New()
	f := audit.Effect{EffectID: uuid.New(), ResourceType: "user_session", ResourceKey: locator.String(), TransitionSlot: "row", TriggerUserID: *e.RootID, OrgResolution: "unknown", Change: "deleted", Provenance: "IMPLICIT_FK_CASCADE", DeletionMechanism: "fk_cascade", Before: json.RawMessage(fmt.Sprintf(`{"id":%q,"user_id":%q,"row_version":1}`, locator, *e.RootID)), After: json.RawMessage("null")}
	raw, err := json.Marshal(f)
	require.NoError(t, err)
	e.EffectCount = 1
	e.Manifest = map[string]int64{"user_session": 1}
	require.NoError(t, db.QueryRowContext(ctx, `SELECT octet_length($1::jsonb::text)`, string(raw)).Scan(&e.EffectJSONBytes))
	tx := userPhaseATx(t, ctx, db)
	require.NoError(t, audit.Append(ctx, tx, e))
	insert := func(tx *sql.Tx, event uuid.UUID) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO user_delete_audit_effects VALUES($1,0,1,$2,'user_session',$3,'row',$4::jsonb)`, event, f.EffectID, f.ResourceKey, string(raw))
		return err
	}
	require.NoError(t, insert(tx, e.EventID))
	require.NoError(t, tx.Commit())
	var before, after []byte
	var xminBefore, xminAfter string
	require.NoError(t, db.QueryRowContext(ctx, `SELECT to_jsonb(f),xmin::text FROM user_delete_audit_effects f WHERE event_id=$1`, e.EventID).Scan(&before, &xminBefore))
	n, err := Up(ctx, uri, "")
	require.NoError(t, err)
	require.Equal(t, 1, n)
	require.NoError(t, VerifyAll(ctx, uri))
	require.NoError(t, VerifyIsLatest(ctx, uri))
	require.NoError(t, db.QueryRowContext(ctx, `SELECT to_jsonb(f),xmin::text FROM user_delete_audit_effects f WHERE event_id=$1`, e.EventID).Scan(&after, &xminAfter))
	require.True(t, bytes.Equal(before, after) && xminBefore == xminAfter, "historical row changed")
	var historical []byte
	require.NoError(t, db.QueryRowContext(ctx, `SELECT payload FROM user_delete_audit_effects WHERE event_id=$1`, e.EventID).Scan(&historical))
	decoded, err := audit.DecodeEffect(historical)
	require.NoError(t, err)
	require.NoError(t, decoded.Validate(*e.RootID))
	require.Error(t, decoded.ValidateForWrite(*e.RootID))
	var legacyValid bool
	require.NoError(t, db.QueryRowContext(ctx, `SELECT user_delete_effect_valid($1::jsonb)`, string(historical)).Scan(&legacyValid))
	require.True(t, legacyValid)
	tx = userPhaseATx(t, ctx, db)
	sessionIdentitySpool(t, ctx, tx)
	_, err = tx.ExecContext(ctx, `INSERT INTO pg_temp.sd8_user_delete_witness(root_ordinal,resource_type,resource_key,before_value,org_resolution,effect_id,payload) VALUES(0,'user_session',$1,$2::jsonb,'unknown',$3,$4::jsonb)`, f.ResourceKey, string(f.Before), f.EffectID, string(historical))
	require.NoError(t, err)
	r := audit.Receipt{Event: e, DeletedUserID: *e.RootID, DeletedRole: e.BeforeContext.UserRole, DeletedRowVersion: e.BeforeContext.RowVersion}
	require.NoError(t, audit.AppendReceipt(ctx, tx, r), "exact historical replay must only compare existing effects")
	require.NoError(t, tx.Commit())
	require.NoError(t, db.QueryRowContext(ctx, `SELECT to_jsonb(f),xmin::text FROM user_delete_audit_effects f WHERE event_id=$1`, e.EventID).Scan(&after, &xminAfter))
	require.True(t, bytes.Equal(before, after) && xminBefore == xminAfter)
	// A new header cannot launder that same v1 effect into a new audit record.
	tx = userPhaseATx(t, ctx, db)
	sessionIdentitySpool(t, ctx, tx)
	_, err = tx.ExecContext(ctx, `INSERT INTO pg_temp.sd8_user_delete_witness(root_ordinal,resource_type,resource_key,before_value,org_resolution,effect_id,payload) VALUES(0,'user_session',$1,$2::jsonb,'unknown',$3,$4::jsonb)`, f.ResourceKey, string(f.Before), f.EffectID, string(historical))
	require.NoError(t, err)
	r.Event.EventID = uuid.New()
	r.Event.AttemptID = uuid.New()
	require.ErrorIs(t, audit.AppendReceipt(ctx, tx, r), audit.ErrInvalid)
	require.NoError(t, tx.Rollback())
	// Replay of the historical header remains idempotent; new Session details
	// in its old format are explicitly refused, even through raw SQL.
	tx = userPhaseATx(t, ctx, db)
	require.NoError(t, audit.Append(ctx, tx, e))
	require.Error(t, insert(tx, e.EventID))
	require.NoError(t, tx.Rollback())
	n, err = Up(ctx, uri, "")
	require.NoError(t, err)
	require.Zero(t, n)
	n, err = Down(ctx, uri, Names()[305])
	require.Error(t, err)
	require.Zero(t, n)
	require.NoError(t, VerifyIsLatest(ctx, uri))
}

func TestPostgresUserDeleteSession307CanonicalSchema(t *testing.T) {
	ctx, uri, _ := boundedAuditDB(t, len(Names()))
	conn, err := pgx.Connect(ctx, uri)
	require.NoError(t, err)
	defer conn.Close(ctx)
	entries, err := migrationFS.ReadDir("migrations")
	require.NoError(t, err)
	var disk, data, applied []string
	for _, entry := range entries {
		raw, err := migrationFS.ReadFile("migrations/" + entry.Name())
		require.NoError(t, err)
		disk = append(disk, entry.Name()+"\n")
		data = append(data, fmt.Sprintf("%x  migrate/migrations/%s\n", sha256.Sum256(raw), entry.Name()))
	}
	sort.Strings(disk)
	sort.Strings(data)
	rows, err := conn.Query(ctx, `SELECT id FROM gorp_migrations ORDER BY id`)
	require.NoError(t, err)
	for rows.Next() {
		var id string
		require.NoError(t, rows.Scan(&id))
		applied = append(applied, id+"\n")
	}
	require.NoError(t, rows.Err())
	rows.Close()
	require.Equal(t, disk, applied)
	schema, err := pgdump.DumpSchema(ctx, conn)
	require.NoError(t, err)
	result := []byte(fmt.Sprintf("-- This file is auto-generated by \"make db-schema\"; DO NOT EDIT\n-- DATA=%x  -\n-- DISK=%x  -\n-- PSQL=%x  -\n--\n-- pgdump-lite database dump\n--\n\n%s", sha256.Sum256([]byte(strings.Join(data, ""))), sha256.Sum256([]byte(strings.Join(disk, ""))), sha256.Sum256([]byte(strings.Join(applied, ""))), schema.String()))
	if out := os.Getenv("USER_SESSION_AUDIT_SCHEMA"); out != "" {
		require.NoError(t, os.WriteFile(out, result, 0600))
	} else {
		canonical, err := os.ReadFile("schema.sql")
		require.NoError(t, err)
		require.True(t, bytes.Equal(canonical, result), "canonical schema differs from fresh PostgreSQL")
	}
}

func TestPostgresUserDeleteSessionIdentitySD9Agreement(t *testing.T) {
	base, _, db := boundedAuditDB(t, len(Names()))
	ctx := permission.SystemContext(base, "SessionContractFix1")
	f := newUserPhaseAFixture(t, ctx, db)
	locators, safe := sessionIdentityCreate(t, ctx, db, f, 1)
	tx := userPhaseATx(t, ctx, db)
	sessionIdentitySpool(t, ctx, tx)
	e := sessionIdentityRoot(f.user)
	org, err := audit.SnapshotOrganization(ctx, tx, f.user)
	require.NoError(t, err)
	require.NoError(t, audit.CaptureSessions(ctx, tx, f.user, 0, e.EventID, org))
	var same bool
	require.NoError(t, tx.QueryRowContext(ctx, `SELECT resource_key=$1 FROM pg_temp.sd8_user_delete_witness WHERE resource_type='user_session'`, safe[0].String()).Scan(&same))
	require.True(t, same)
	require.NoError(t, tx.Rollback())
	tx = userPhaseATx(t, ctx, db)
	binding := sessionMigrationEvent()
	r, err := sessionaudit.RevokeSelected(ctx, tx, binding, locators[0].String())
	require.NoError(t, err)
	require.NoError(t, r.Append(ctx, tx, binding))
	require.NoError(t, tx.Commit())
	require.NoError(t, db.QueryRowContext(ctx, `SELECT session_audit_id=$1 AND target_user_id=$2 FROM user_session_revoke_audit_details WHERE event_id=$3`, safe[0], f.user, binding.EventID).Scan(&same))
	require.True(t, same)
	var raw []byte
	require.NoError(t, db.QueryRowContext(ctx, `SELECT to_jsonb(d) FROM user_session_revoke_audit_details d WHERE event_id=$1`, binding.EventID).Scan(&raw))
	sessionIdentityNoLeak(t, raw, locators)
}

func TestPostgresUserDeleteSessionIdentityMissingAndConcurrent(t *testing.T) {
	base, _, db := boundedAuditDB(t, len(Names()))
	ctx := permission.SystemContext(base, "SessionContractFix1")
	f := newUserPhaseAFixture(t, ctx, db)
	locators, _ := sessionIdentityCreate(t, ctx, db, f, 1)
	writer := userPhaseATx(t, ctx, db)
	_, err := writer.ExecContext(ctx, `DELETE FROM auth_user_sessions WHERE id=$1`, locators[0])
	require.NoError(t, err)
	tx := userPhaseATx(t, ctx, db)
	sessionIdentitySpool(t, ctx, tx)
	_, err = tx.ExecContext(ctx, `SET LOCAL lock_timeout='50ms'`)
	require.NoError(t, err)
	e := sessionIdentityRoot(f.user)
	err = audit.CaptureSessions(ctx, tx, f.user, 0, e.EventID, audit.OrganizationSnapshot{Resolution: "unknown"})
	require.ErrorIs(t, err, audit.ErrInvalid)
	sessionIdentityNoLeak(t, []byte(err.Error()), locators)
	require.NoError(t, tx.Rollback())
	require.NoError(t, writer.Commit())
	tx = userPhaseATx(t, ctx, db)
	sessionIdentitySpool(t, ctx, tx)
	require.NoError(t, audit.CaptureSessions(ctx, tx, f.user, 0, e.EventID, audit.OrganizationSnapshot{Resolution: "unknown"}))
	var count int
	require.NoError(t, tx.QueryRowContext(ctx, `SELECT count(*) FROM pg_temp.sd8_user_delete_witness`).Scan(&count))
	require.Zero(t, count)
	require.NoError(t, tx.Rollback())
	tx = userPhaseATx(t, ctx, db)
	sessionIdentitySpool(t, ctx, tx)
	require.ErrorIs(t, audit.CaptureSessions(ctx, tx, uuid.New(), 0, uuid.New(), audit.OrganizationSnapshot{Resolution: "unknown"}), audit.ErrInvalid)
	require.NoError(t, tx.Rollback())
}

func TestPostgresUserDeleteSessionIdentityAnomalies(t *testing.T) {
	base, _, db := boundedAuditDB(t, len(Names()))
	ctx := permission.SystemContext(base, "SessionContractFix1")
	f := newUserPhaseAFixture(t, ctx, db)
	locators, _ := sessionIdentityCreate(t, ctx, db, f, 2)
	// Optional task-owned server log check uses exact synthetic identities and
	// Boolean-only diagnostics. Never print its contents or either locator.
	logPath := os.Getenv("SESSION_AUDIT_TEST_SERVER_LOG")
	var logOffset int
	if logPath != "" {
		raw, err := os.ReadFile(logPath)
		require.NoError(t, err)
		logOffset = len(raw)
	}
	for _, mode := range []string{"zero", "null", "locator", "other_locator", "duplicate"} {
		t.Run(mode, func(t *testing.T) {
			tx := userPhaseATx(t, ctx, db)
			sessionIdentitySpool(t, ctx, tx)
			// Deliberately corrupt ONLY this disposable transaction, then roll
			// back its schema and rows. Normal immutable identities are intact.
			_, err := tx.ExecContext(ctx, `ALTER TABLE auth_user_sessions DISABLE TRIGGER user_session_audit_identity`)
			require.NoError(t, err)
			switch mode {
			case "zero":
				_, err = tx.ExecContext(ctx, `ALTER TABLE auth_user_sessions DROP CONSTRAINT auth_user_session_audit_identity_nonzero`)
				require.NoError(t, err)
				_, err = tx.ExecContext(ctx, `UPDATE auth_user_sessions SET audit_resource_id='00000000-0000-0000-0000-000000000000' WHERE id=$1`, locators[0])
			case "null":
				_, err = tx.ExecContext(ctx, `ALTER TABLE auth_user_sessions ALTER COLUMN audit_resource_id DROP NOT NULL`)
				require.NoError(t, err)
				_, err = tx.ExecContext(ctx, `UPDATE auth_user_sessions SET audit_resource_id=NULL WHERE id=$1`, locators[0])
			case "locator":
				_, err = tx.ExecContext(ctx, `UPDATE auth_user_sessions SET audit_resource_id=id WHERE id=$1`, locators[0])
			case "other_locator":
				_, err = tx.ExecContext(ctx, `UPDATE auth_user_sessions SET audit_resource_id=$2 WHERE id=$1`, locators[0], locators[1])
			case "duplicate":
				_, err = tx.ExecContext(ctx, `ALTER TABLE auth_user_sessions DROP CONSTRAINT auth_user_session_audit_identity`)
				require.NoError(t, err)
				_, err = tx.ExecContext(ctx, `UPDATE auth_user_sessions SET audit_resource_id=(SELECT audit_resource_id FROM auth_user_sessions WHERE id=$1) WHERE user_id=$2`, locators[0], f.user)
			}
			require.NoError(t, err)
			err = audit.CaptureSessions(ctx, tx, f.user, 0, uuid.New(), audit.OrganizationSnapshot{Resolution: "unknown"})
			require.ErrorIs(t, err, audit.ErrInvalid)
			sessionIdentityNoLeak(t, []byte(err.Error()), locators)
			require.NoError(t, tx.Rollback())
		})
	}
	var intact bool
	require.NoError(t, db.QueryRowContext(ctx, `SELECT bool_and(audit_resource_id IS NOT NULL AND audit_resource_id<>id AND audit_resource_id<>'00000000-0000-0000-0000-000000000000') FROM auth_user_sessions WHERE user_id=$1`, f.user).Scan(&intact))
	require.True(t, intact)
	if logPath != "" {
		raw, err := os.ReadFile(logPath)
		require.NoError(t, err)
		require.GreaterOrEqual(t, len(raw), logOffset)
		sessionIdentityNoLeak(t, raw[logOffset:], locators)
	}
}

func TestPostgresUserDeleteSessionIdentityUserAdmission(t *testing.T) {
	base, _, db := boundedAuditDB(t, len(Names()))
	system := permission.SystemContext(base, "SessionContractFix1")
	f, actor := newUserPhaseAFixture(t, system, db), newUserPhaseAFixture(t, system, db)
	_, _ = sessionIdentityCreate(t, system, db, f, 1)
	enforcementExec(t, system, db, `UPDATE users SET role='admin' WHERE id=$1`, actor.user)
	actorSessions, _ := sessionIdentityCreate(t, system, db, actor, 1)
	human := permission.UserSourceContext(base, actor.user.String(), permission.RoleAdmin, &permission.SourceInfo{Type: permission.SourceTypeAuthProvider, ID: actorSessions[0].String()})
	requester, err := auth.NewRequester(actor.user.String(), actorSessions[0].String())
	require.NoError(t, err)
	human = auth.WithRequester(human, requester)
	constructor, err := executioncontext.NewHumanExecutionContextConstructor(organization.NewStore(db))
	require.NoError(t, err)
	ec, err := constructor.Construct(human)
	require.NoError(t, err)
	human = executioncontext.WithExecutionContext(human, ec)
	app := enforcementApp(t, system, db)
	app.UserStore = f.users
	for name, ctx := range map[string]context.Context{
		"system":      system,
		"human_admin": human,
	} {
		t.Run(name, func(t *testing.T) {
			for _, ids := range [][]uuid.UUID{{f.user}, {uuid.New()}, {f.user, f.user}} {
				var raw []assignment.RawTarget
				var targets []string
				for _, id := range ids {
					raw = append(raw, assignment.RawTarget{Type: assignment.TargetTypeUser, ID: id.String()})
					targets = append(targets, id.String())
				}
				_, err := app.Mutation().DeleteAll(ctx, raw, nil)
				if ids[0] != f.user {
					require.NoError(t, err)
				} else if name == "system" {
					enforceCode(t, err, ds.DeletionConfirmationRequired)
				} else {
					enforceCode(t, err, ds.DeletionUnavailable)
				} // Foreign Home stays denied.
				for _, audited := range []bool{false, true} {
					tx := userPhaseATx(t, ctx, db)
					if audited {
						_, err = f.users.DeleteManyForAuditTx(ctx, tx, targets, audit.Event{}, nil)
					} else {
						err = f.users.DeleteManyTx(ctx, tx, targets)
					}
					enforceCode(t, err, ds.DeletionUnavailable)
					require.NoError(t, tx.Rollback())
				}
			}
		})
	}
	require.Equal(t, 1, enforcementCount(t, system, db, `SELECT count(*) FROM users WHERE id=$1`, f.user))
	require.Equal(t, 1, enforcementCount(t, system, db, `SELECT count(*) FROM auth_user_sessions WHERE user_id=$1`, f.user))
	require.Zero(t, enforcementCount(t, system, db, `SELECT count(*) FROM user_delete_audit_events WHERE outcome='committed'`))
}
