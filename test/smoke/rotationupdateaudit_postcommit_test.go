package smoke

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/graphql2"
	"github.com/target/goalert/graphql2/graphqlapp"
	"github.com/target/goalert/schedule/rotation"
	"github.com/target/goalert/test/smoke/harness"
	"github.com/target/goalert/util/log"
)

func TestRotationUpdateAuditAcknowledgedCommitCleanup(t *testing.T) {
	for _, slow := range []bool{false, true} {
		name := "fast_close_control"
		if slow {
			name = "slow_close_after_ack"
		}
		t.Run(name, func(t *testing.T) {
			h := rotationAuditHarness(t)
			ikSetAuthority(t, h, "ORG_MEMBER", true)
			var dbName string
			require.NoError(t, h.App().DB().QueryRow(`SELECT current_database()`).Scan(&dbName))
			cfg, err := pgx.ParseConfig(harness.DBURL(dbName))
			require.NoError(t, err)
			c := &serviceAuditCloseConnector{base: stdlib.GetConnector(*cfg), started: make(chan struct{}), release: make(chan struct{}), finished: make(chan struct{})}
			db := sql.OpenDB(c)
			db.SetMaxOpenConns(1)
			t.Cleanup(func() {
				c.unblock()
				require.Eventually(t, func() bool { return db.Stats().OpenConnections == 0 }, 5*time.Second, time.Millisecond)
				require.NoError(t, db.Close())
			})
			store, err := rotation.NewStore(context.Background(), db)
			require.NoError(t, err)
			db.SetMaxIdleConns(0) // Supported pool setting forces physical Close.
			c.armed.Store(slow)
			logger := log.NewLogger()
			logger.EnableJSON()
			var captured bytes.Buffer
			logger.SetOutput(&captured)
			ctx := log.SetRequestID(log.WithLogger(servicePlatformAdminContext(t, h), logger))
			description := "SYNTHETIC_POSTCOMMIT_DESCRIPTION"
			private := log.Fields{
				"SessionID":  "SYNTHETIC_POSTCOMMIT_SESSION",
				"SourceInfo": "SYNTHETIC_POSTCOMMIT_SOURCE",
				"Token":      "SYNTHETIC_POSTCOMMIT_TOKEN",
				"SQLDetail":  "SYNTHETIC_POSTCOMMIT_SQL_DETAIL",
			}
			ctx = log.WithFields(ctx, private)
			a := graphqlapp.App{DB: db, RotationStore: store}
			start := time.Now()
			ok, operationErr := a.Mutation().UpdateRotation(ctx, graphql2.UpdateRotationInput{ID: h.UUID("rotation-a"), Description: &description})
			elapsed := time.Since(start)
			require.EqualValues(t, 1, c.commits.Load())
			require.EqualValues(t, 1, c.commitOK.Load(), "native Commit returned nil before cleanup")
			var actual string
			require.NoError(t, h.App().DB().QueryRow(`SELECT description FROM rotations WHERE id=$1`, h.UUID("rotation-a")).Scan(&actual))
			require.Equal(t, description, actual)
			var committed, failed int
			require.NoError(t, h.App().DB().QueryRow(`SELECT count(*) FILTER(WHERE outcome='committed'),count(*) FILTER(WHERE outcome<>'committed') FROM schedule_rotation_update_audit_events`).Scan(&committed, &failed))
			require.Equal(t, 1, committed)
			require.Zero(t, failed)
			require.EqualValues(t, 1, c.begins.Load(), "no replay or independent failure append")
			if slow {
				select {
				case <-c.started:
				default:
					t.Fatal("driver Close seam was not entered")
				}
				select {
				case <-c.finished:
					t.Fatal("driver Close must still be blocked at the bounded return")
				default:
				}
				require.GreaterOrEqual(t, elapsed, 2*time.Second)
				require.Less(t, elapsed, 4*time.Second)
				probe, err := h.App().DB().Begin()
				require.NoError(t, err)
				_, err = probe.Exec(`SELECT id FROM rotations WHERE id=$1 FOR UPDATE NOWAIT`, h.UUID("rotation-a"))
				require.NoError(t, err, "independent connection proves business transaction ended")
				require.NoError(t, probe.Rollback())
				// Always release the seam before asserting the API/log contract, so
				// RED runs also leave no test-owned connection or cleanup behind.
				c.unblock()
				select {
				case <-c.finished:
				case <-time.After(5 * time.Second):
					t.Fatal("test Close did not terminate")
				}
				require.Eventually(t, func() bool { return db.Stats().OpenConnections == 0 && db.Stats().InUse == 0 }, 5*time.Second, time.Millisecond)
				t.Logf("PG witness: native Commit nil=1, business update=1, committed audit=1, failure/unknown=0, begins=1; elapsed=%s; API=(%t,%v); cleanup exited and pool open/in-use=0", elapsed, ok, operationErr)
				require.NoError(t, operationErr, "acknowledged durable success must survive cleanup timeout")
				require.True(t, ok)
				var fault map[string]any
				require.NoError(t, json.Unmarshal(captured.Bytes(), &fault))
				require.Equal(t, "error", fault["level"])
				require.Equal(t, "resource_release_unconfirmed", fault["AuditFault"])
				require.Equal(t, "committed", fault["AuditOutcome"])
				require.Equal(t, "rotation.update", fault["AuditOperation"])
				require.Equal(t, "rotation.update committed; resource release unconfirmed", fault["error"])
				var eventID, attemptID, requestID string
				require.NoError(t, h.App().DB().QueryRow(`SELECT event_id,attempt_id,request_id FROM schedule_rotation_update_audit_events`).Scan(&eventID, &attemptID, &requestID))
				require.Equal(t, eventID, fault["AuditEventID"])
				require.Equal(t, attemptID, fault["AuditAttemptID"])
				require.Equal(t, requestID, fault["AuditRequestID"])
				require.Equal(t, log.RequestID(ctx), requestID)
				require.NotContains(t, captured.String(), "audit persistence unavailable")
				require.NotContains(t, captured.String(), description)
				for field, sentinel := range private {
					require.NotContains(t, fault, field)
					require.NotContains(t, captured.String(), sentinel)
				}
				t.Logf("safe cleanup fault: %s", captured.String())
			} else {
				require.NoError(t, operationErr)
				require.True(t, ok)
				require.Empty(t, captured.String())
				t.Log("CONTROL: native Commit nil=1, persisted business/committed audit=1, failure/unknown=0, API=true/nil, no cleanup fault")
			}
			require.NotContains(t, rotationAuditRows(t, h), description)
		})
	}
}
