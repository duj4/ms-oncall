package migrate

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/auth/sessionaudit"
	"github.com/target/goalert/permission"
)

func TestUserSessionRevokeCanonicalAppend(t *testing.T) {
	h, err := loadEmbeddedHistory()
	require.NoError(t, err)
	require.Len(t, h.entries, 304)
	marker := []byte(",\n    {\n      \"id\": \"ms-oncall-user-session-revoke-audit-d09-sd9\",")
	i := bytes.Index(h.manifest, marker)
	require.Positive(t, i)
	prefix := append(append([]byte{}, h.manifest[:i]...), []byte("\n  ]\n}\n")...)
	require.Equal(t, "fc86d07cf2ecea3ec1613e33e407160932cb79ba87c78feaed7f9f46e21e32c0", fmt.Sprintf("%x", sha256.Sum256(prefix)))
	require.Equal(t, h.entries[302].ID, h.entries[303].PredecessorID)
}
func TestPostgresUserSessionRevokeMigration(t *testing.T) {
	for _, start := range []int{0, 303} {
		t.Run(fmt.Sprint(start), func(t *testing.T) {
			ctx := context.Background()
			var uri string
			var db *sql.DB
			if start == 0 {
				uri = newPostgresTestDatabase(t, postgresIntegrationURL(t))
				var err error
				db, err = sql.Open("pgx", uri)
				require.NoError(t, err)
				t.Cleanup(func() { require.NoError(t, db.Close()) })
			} else {
				ctx, uri, db = boundedAuditDB(t, start)
			}
			oldID := uuid.New()
			if start == 303 {
				_, err := db.Exec(`INSERT INTO auth_user_sessions(id,user_agent,user_id) VALUES($1,'SYNTHETIC_UA',NULL)`, oldID)
				require.NoError(t, err)
				tx, err := db.BeginTx(ctx, nil)
				require.NoError(t, err)
				_, err = sessionaudit.RevokeSelected(permission.SystemContext(ctx, "Test"), tx, sessionMigrationEvent(), oldID.String())
				require.Error(t, err)
				require.NoError(t, tx.Rollback())
				var n int
				require.NoError(t, db.QueryRow(`SELECT count(*) FROM auth_user_sessions WHERE id=$1`, oldID).Scan(&n))
				require.Equal(t, 1, n)
			}
			n, err := Up(ctx, uri, "")
			require.NoError(t, err)
			require.Equal(t, 304-start, n)
			require.NoError(t, VerifyAll(ctx, uri))
			require.NoError(t, VerifyIsLatest(ctx, uri))
			if start == 303 {
				var safe uuid.UUID
				require.NoError(t, db.QueryRow(`SELECT audit_resource_id FROM auth_user_sessions WHERE id=$1`, oldID).Scan(&safe))
				require.True(t, safe != uuid.Nil && safe != oldID)
			}
			raw, provided := uuid.New(), uuid.New()
			var safe uuid.UUID
			require.NoError(t, db.QueryRow(`INSERT INTO auth_user_sessions(id,user_agent,user_id,audit_resource_id) VALUES($1,'SYNTHETIC_UA',NULL,$2) RETURNING audit_resource_id`, raw, provided).Scan(&safe))
			require.True(t, safe != provided && safe != raw && safe != uuid.Nil)
			_, err = db.Exec(`UPDATE auth_user_sessions SET audit_resource_id=$2 WHERE id=$1`, raw, uuid.New())
			require.Error(t, err)
			_, err = db.Exec(`UPDATE auth_user_sessions SET user_agent='SYNTHETIC_UA_CHANGED' WHERE id=$1`, raw)
			require.NoError(t, err)
			var stable bool
			require.NoError(t, db.QueryRow(`SELECT audit_resource_id=$2 FROM auth_user_sessions WHERE id=$1`, raw, safe).Scan(&stable))
			require.True(t, stable)
			_, err = db.Exec(`DELETE FROM auth_user_sessions WHERE id=$1`, raw)
			require.NoError(t, err)
			var next uuid.UUID
			require.NoError(t, db.QueryRow(`INSERT INTO auth_user_sessions(id,user_agent,user_id) VALUES($1,'SYNTHETIC_UA',NULL) RETURNING audit_resource_id`, raw).Scan(&next))
			require.True(t, next != safe)
			var events int
			require.NoError(t, db.QueryRow(`SELECT count(*) FROM user_session_revoke_audit_events`).Scan(&events))
			require.Zero(t, events)
		})
	}
}
func sessionMigrationEvent() sessionaudit.Event {
	now := time.Now().UTC().Truncate(time.Microsecond)
	return sessionaudit.Event{SchemaVersion: 1, EventID: uuid.New(), RequestID: uuid.New(), ExecutionID: uuid.New(), AttemptID: uuid.New(), RecordKind: "attempt_observation", Operation: "user_session.revoke", SelectionMode: "selected_sessions", ActorKind: "internal_system", InitiatorKind: "internal_system", AuthoritySource: "trusted_internal_system", AuthorityRole: "internal_system", OrganizationRole: "unknown", Outcome: "tx_failed", Reason: "begin_failed", OccurredAt: now, RecordedAt: now}
}
func TestPostgresUserSessionRevokeCompletenessAndAppendOnly(t *testing.T) {
	ctx, _, db := boundedAuditDB(t, len(Names()))
	for _, mode := range []string{"missing", "extra", "duplicate_identity", "observation_detail", "correct"} {
		t.Run(mode, func(t *testing.T) {
			e := sessionMigrationEvent()
			e.RecordKind = "success_witness"
			e.Outcome = "committed"
			e.Reason = "revoked"
			e.AffectedCount = 2
			tx, err := db.BeginTx(ctx, nil)
			require.NoError(t, err)
			_, err = tx.ExecContext(ctx, `INSERT INTO user_session_revoke_audit_events(schema_version,event_id,request_id,execution_id,attempt_id,record_kind,operation,selection_mode,actor_kind,initiator_kind,authority_source,authority_role,organization_role,affected_count,outcome,reason_code,occurred_at) VALUES(1,$1,$2,$3,$4,$5,'user_session.revoke','selected_sessions','internal_system','internal_system','trusted_internal_system','internal_system','unknown',$6,$7,$8,$9)`, e.EventID, e.RequestID, e.ExecutionID, e.AttemptID, e.RecordKind, e.AffectedCount, e.Outcome, e.Reason, e.OccurredAt)
			require.NoError(t, err)
			safe := uuid.New()
			number := 2
			if mode == "missing" {
				number = 1
			}
			if mode == "extra" {
				number = 3
			}
			for ordinal := 0; ordinal < number; ordinal++ {
				id := uuid.New()
				if mode == "duplicate_identity" {
					id = safe
				}
				_, err = tx.Exec(`INSERT INTO user_session_revoke_audit_details(event_id,effect_ordinal,session_audit_id,target_org_resolution,provenance,deletion_mechanism,cause) VALUES($1,$2,$3,'unknown','EXPLICIT','explicit_sql','explicit_target')`, e.EventID, ordinal, id)
				if err != nil {
					break
				}
			}
			if mode == "extra" || mode == "duplicate_identity" {
				require.Error(t, err)
				require.NoError(t, tx.Rollback())
				return
			}
			if mode == "observation_detail" { // an observation cannot own any detail
				require.NoError(t, tx.Rollback())
				e = sessionMigrationEvent()
				tx, err = db.BeginTx(ctx, nil)
				require.NoError(t, err)
				require.NoError(t, sessionaudit.AppendObservation(ctx, tx, e))
				_, err = tx.Exec(`INSERT INTO user_session_revoke_audit_details(event_id,effect_ordinal,session_audit_id,target_org_resolution,provenance,deletion_mechanism,cause) VALUES($1,0,$2,'unknown','EXPLICIT','explicit_sql','explicit_target')`, e.EventID, uuid.New())
				require.Error(t, err)
				require.NoError(t, tx.Rollback())
				return
			}
			err = tx.Commit()
			if mode == "missing" {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
	for _, q := range []string{`UPDATE user_session_revoke_audit_events SET reason_code=reason_code`, `DELETE FROM user_session_revoke_audit_events`, `TRUNCATE user_session_revoke_audit_details`, `DELETE FROM user_session_revoke_audit_details`} {
		_, err := db.ExecContext(context.Background(), q)
		require.Error(t, err)
	}
}
