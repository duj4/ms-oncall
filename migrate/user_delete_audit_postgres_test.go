package migrate

import (
	"context"
	"database/sql"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	audit "github.com/target/goalert/user/deleteaudit"
)

func sd8SchemaEvent() audit.Event {
	id := uuid.New()
	ordinal := 0
	return audit.Event{SchemaVersion: 1, EventID: uuid.New(), RequestID: uuid.New(), ExecutionID: uuid.New(), AttemptID: uuid.New(), RecordKind: "success_witness", Operation: "user.delete", RootType: "user", RootID: &id, RootOrdinal: &ordinal, ActorKind: "internal_system", AuthoritySource: "trusted_internal_system", AuthorityRole: "internal_system", OrganizationRole: "unknown", TargetOrgResolution: "unknown", BeforeContext: &audit.Before{Version: 1, UserID: id, UserRole: "user", RowVersion: 1, TargetOrgResolution: "unknown", OrganizationRole: "unknown"}, Provenance: "EXPLICIT", DeletionMechanism: "explicit_sql", Cause: "explicit_target", Outcome: "committed", Reason: "deleted", OccurredAt: time.Now()}
}

func TestPostgresUserDeleteMigration302(t *testing.T) {
	for _, start := range []int{0, 301} {
		t.Run(fmt.Sprint(start), func(t *testing.T) {
			var ctx context.Context
			var uri string
			var db *sql.DB
			if start > 0 {
				ctx, uri, db = boundedAuditDB(t, start)
			} else {
				ctx = context.Background()
				uri = newPostgresTestDatabase(t, postgresIntegrationURL(t))
				var err error
				db, err = sql.Open("pgx", uri)
				require.NoError(t, err)
				t.Cleanup(func() { require.NoError(t, db.Close()) })
			}
			n, err := Up(ctx, uri, "")
			require.NoError(t, err)
			require.Equal(t, 302-start, n)
			require.NoError(t, VerifyAll(ctx, uri))
			require.NoError(t, VerifyIsLatest(ctx, uri))
			n, err = Up(ctx, uri, "")
			require.NoError(t, err)
			require.Zero(t, n)
			var system string
			require.NoError(t, db.QueryRowContext(ctx, `SELECT system_identifier::text FROM pg_control_system()`).Scan(&system))
			t.Log("SystemID", system)
			tx, err := db.BeginTx(ctx, nil)
			require.NoError(t, err)
			defer func() { _ = tx.Rollback() }()
			e := sd8SchemaEvent()
			require.NoError(t, audit.Append(ctx, tx, e))
			require.NoError(t, audit.Append(ctx, tx, e))
			require.NoError(t, tx.Commit())
			observation := e
			observation.EventID = uuid.New()
			observation.RecordKind = "attempt_observation"
			observation.RootID = nil
			observation.RootOrdinal = nil
			observation.BeforeContext = nil
			observation.Provenance, observation.DeletionMechanism, observation.Cause = "", "", ""
			observation.Outcome, observation.Reason = "tx_failed", "write_failed"
			tx, err = db.BeginTx(ctx, nil)
			require.NoError(t, err)
			defer func() { _ = tx.Rollback() }()
			require.NoError(t, audit.Append(ctx, tx, observation))
			require.NoError(t, tx.Commit())
		})
	}
}
