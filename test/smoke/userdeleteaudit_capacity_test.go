package smoke

import (
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/app"
	"github.com/target/goalert/assignment"
	ds "github.com/target/goalert/deletionsafety"
	"github.com/target/goalert/limit"
	"github.com/target/goalert/permission"
	"github.com/target/goalert/test/smoke/harness"
)

func TestUserDeleteAuditCapacity(t *testing.T) {
	h := sd1Harness(t)
	s := sd6Root(t, h, "schedule", harness.SmokeOrganizationID)
	for _, n := range []int{0, 256, 257, 1024, 2048, 4095, 4096, 4097, 5000, 20000} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			u := smokeOwnedUser(t, h)
			sd8Exec(t, h, `INSERT INTO schedule_on_call_users(schedule_id,user_id,start_time,end_time) SELECT $1,$2,'2020-01-01'::timestamptz+g*interval '1 second','2020-01-01'::timestamptz+(g+1)*interval '1 second' FROM generate_series(1,$3) g`, s, u, n)
			// Full ID sets, independently read before deletion and after Commit.
			var expectedIDs, actualIDs []string
			require.NoError(t, h.App().DB().QueryRow(`SELECT coalesce(array_agg(id::text ORDER BY id::text),'{}') FROM schedule_on_call_users WHERE user_id=$1`, u).Scan(pq.Array(&expectedIDs)))
			input := []assignment.RawTarget{{Type: assignment.TargetTypeUser, ID: u}}
			if n >= 4095 {
				// Preserve every original oversized shape and all history rows.
				// The native Preview budget precedes the older streaming audit limit.
				before := smokeUserBusinessState(t, h)
				successes := smokeDeletionSuccesses(t, h)
				_, err := smokeDeletionPreview(t, h, sd3System(), input)
				smokeDeletionCode(t, err, ds.DeletionPreviewLimitExceeded)
				ok, err := sd7App(h).Mutation().DeleteAll(sd3System(), input, nil)
				require.Error(t, err)
				require.False(t, ok)
				require.Equal(t, before, smokeUserBusinessState(t, h))
				require.Equal(t, successes, smokeDeletionSuccesses(t, h))
				require.Zero(t, sd8Scalar(t, h, `SELECT count(*) FROM user_delete_audit_effects f JOIN user_delete_audit_events e USING(event_id) WHERE e.root_id=$1`, u))
				t.Logf("history=%d: original scale refused by real Preview; all business rows and prior success audits preserved", n)
				return
			}
			ok, err := smokeDeleteAll(t, h, sd7App(h), permission.SystemContext(t.Context(), "Engine"), []assignment.RawTarget{{Type: assignment.TargetTypeUser, ID: u}})
			require.NoError(t, err)
			require.True(t, ok)
			require.Zero(t, sd8Scalar(t, h, `SELECT count(*) FROM users WHERE id=$1`, u))
			require.EqualValues(t, n+1, sd8Scalar(t, h, `SELECT count(*) FROM user_delete_audit_effects f JOIN user_delete_audit_events e USING(event_id) WHERE e.root_id=$1`, u))
			require.EqualValues(t, n+1, sd8Scalar(t, h, `SELECT effect_count FROM user_delete_audit_events WHERE root_id=$1 AND record_kind='success_witness'`, u))
			require.NoError(t, h.App().DB().QueryRow(`SELECT coalesce(array_agg(resource_key ORDER BY resource_key),'{}') FROM user_delete_audit_effects JOIN user_delete_audit_events USING(event_id) WHERE root_id=$1 AND resource_type='schedule_on_call_history'`, u).Scan(pq.Array(&actualIDs)))
			require.Equal(t, expectedIDs, actualIDs)
			require.EqualValues(t, 1, sd8Scalar(t, h, `SELECT count(*) FROM user_delete_audit_effects f JOIN user_delete_audit_events e USING(event_id) WHERE e.root_id=$1 AND f.resource_type='user_organization_assignment' AND f.resource_key=$1::text`, u))
			var bytes, maxLeaf int64
			require.NoError(t, h.App().DB().QueryRow(`SELECT effect_json_bytes,coalesce((SELECT max(octet_length(payload::text)) FROM user_delete_audit_effects WHERE event_id=e.event_id),0) FROM user_delete_audit_events e WHERE root_id=$1 AND record_kind='success_witness'`, u).Scan(&bytes, &maxLeaf))
			require.LessOrEqual(t, maxLeaf, int64(4096))
			t.Logf("history=%d pages=%d persisted_bytes=%d largest_leaf=%d", n, (n+255)/256, bytes, maxLeaf)
		})
	}
}

func TestUserDeleteAuditRotationIdentity(t *testing.T) {
	// FIXTURE REPAIR: a no-Mutation control proved the legacy paused Engine
	// can recreate a deliberately missing State. Use the existing production
	// API-only mode before startup so background reconciliation cannot race
	// the complete no-mutation snapshots. Keep all seven original shapes.
	h := harness.NewStoppedHarness(t, servicePlatformAdminSQL, nil, "")
	h.StartWithAppCfgHook(func(cfg *app.Config) { cfg.APIOnly = true })
	t.Cleanup(func() {
		// The existing Harness.Close verifies real Engine cycles. Restore its
		// normal lifecycle only after every API-only preservation assertion.
		h.RestartGoAlertWithAppCfgHook(func(cfg *app.Config) { cfg.APIOnly = false })
		h.Close()
	})
	epB1Exec(t, h, `INSERT INTO schedules(id,organization_id,name,time_zone) VALUES($1,$2,'SD1 Home Schedule','UTC')`, h.UUID("schedule-a"), harness.SmokeOrganizationID)
	for _, shape := range []string{"UVW", "UUVW", "UVUW", "UUU", "U1U2", "missing_state", "large"} {
		t.Run(shape, func(t *testing.T) {
			u, v, w := smokeOwnedUser(t, h), smokeOwnedUser(t, h), smokeOwnedUser(t, h)
			users := []string{u, v, w}
			switch shape {
			case "UUVW":
				users = []string{u, u, v, w}
			case "UVUW":
				users = []string{u, v, u, w}
			case "UUU":
				users = []string{u, u, u}
			case "U1U2":
				users = []string{u, v, w}
			case "large":
				users = make([]string, 5000)
				for i := range users {
					users[i] = v
				}
				users[0] = u
			}
			if shape == "large" {
				h.SetSystemLimit(limit.ParticipantsPerRotation, -1)
			}
			rot := sd6Root(t, h, "rotation", harness.SmokeOrganizationID)
			ids := make([]string, len(users))
			for i, user := range users {
				ids[i] = uuid.NewString()
				sd8Exec(t, h, `INSERT INTO rotation_participants(id,rotation_id,user_id,position) VALUES($1,$2,$3,$4)`, ids[i], rot, user, i)
			}
			if shape == "missing_state" {
				sd8Exec(t, h, `DELETE FROM rotation_state WHERE rotation_id=$1`, rot)
				t.Cleanup(func() { sd8Exec(t, h, `DELETE FROM rotations WHERE id=$1`, rot) })
			}
			input := []assignment.RawTarget{{Type: assignment.TargetTypeUser, ID: u}}
			if shape == "U1U2" {
				input = append(input, assignment.RawTarget{Type: assignment.TargetTypeUser, ID: v})
			}
			// CONTRACT ADAPTATION: retain every original identity/scale shape.
			// A surviving Participant blocks User deletion; no participant may
			// be implicitly compacted, even with a real Preview confirmation.
			before, audits := smokeUserBusinessState(t, h), smokeDeletionSuccesses(t, h)
			preview, previewErr := smokeDeletionPreview(t, h, sd3System(), input)
			// FIXTURE REPAIR: the large shape has one reference to U and
			// 4999 to retained V. A User Preview does not charge V's references.
			// Missing Rotation State does not override the existing Participant
			// BLOCK either: every original shape has the same legal refusal.
			require.NoError(t, previewErr)
			require.True(t, preview.Complete)
			require.False(t, preview.CanProceed)
			confirmation := smokePlanConfirmation(t, h, sd3System(), input)
			ok, err := sd7App(h).Mutation().DeleteAll(sd3System(), input, confirmation)
			smokeDeletionCode(t, err, ds.DeletionBlocked)
			require.False(t, ok)

			require.Equal(t, before, smokeUserBusinessState(t, h))
			require.Equal(t, audits, smokeDeletionSuccesses(t, h))
			for i, user := range users {
				require.EqualValues(t, 1, sd8Scalar(t, h, `SELECT count(*) FROM rotation_participants WHERE id=$1 AND user_id=$2 AND position=$3`, ids[i], user, i))
			}
			require.EqualValues(t, len(users), sd8Scalar(t, h, `SELECT participant_count FROM rotations WHERE id=$1`, rot))
			require.Zero(t, sd8Scalar(t, h, `SELECT count(*) FROM user_delete_audit_effects f JOIN user_delete_audit_events e USING(event_id) WHERE e.root_id=ANY($1::uuid[])`, uuidArray(input)))
			t.Log("NEGATIVE CONTROL ONLY / NOT REACHABLE: original User-only participant identity compaction; all identities, positions, State and Audits preserved")
			if shape == "missing_state" {
				// Dispose only the task-created invalid fixture after preservation
				// checks, before the harness runs its final background Engine.
				sd8Exec(t, h, `DELETE FROM rotations WHERE id=$1`, rot)
			}

		})
	}
}

func uuidArray(input []assignment.RawTarget) any {
	ids := make([]string, len(input))
	for i, v := range input {
		ids[i] = v.ID
	}
	return pq.Array(ids)
}
