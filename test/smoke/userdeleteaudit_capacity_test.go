package smoke

import (
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/assignment"
	"github.com/target/goalert/limit"
	"github.com/target/goalert/permission"
	"github.com/target/goalert/test/smoke/harness"
)

func TestUserDeleteAuditCapacity(t *testing.T) {
	h := sd1Harness(t)
	s := sd6Root(t, h, "schedule", harness.SmokeOrganizationID)
	for _, n := range []int{0, 256, 257, 4095, 4096, 4097, 5000, 20000} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			u := sd7User(t, h)
			sd8Exec(t, h, `INSERT INTO schedule_on_call_users(schedule_id,user_id,start_time,end_time) SELECT $1,$2,'2020-01-01'::timestamptz+g*interval '1 second','2020-01-01'::timestamptz+(g+1)*interval '1 second' FROM generate_series(1,$3) g`, s, u, n)
			// Full ID sets, independently read before deletion and after Commit.
			var expectedIDs, actualIDs []string
			require.NoError(t, h.App().DB().QueryRow(`SELECT coalesce(array_agg(id::text ORDER BY id::text),'{}') FROM schedule_on_call_users WHERE user_id=$1`, u).Scan(pq.Array(&expectedIDs)))
			ok, err := sd7App(h).Mutation().DeleteAll(permission.SystemContext(t.Context(), "Engine"), []assignment.RawTarget{{Type: assignment.TargetTypeUser, ID: u}})
			require.NoError(t, err)
			require.True(t, ok)
			require.Zero(t, sd8Scalar(t, h, `SELECT count(*) FROM users WHERE id=$1`, u))
			require.EqualValues(t, n, sd8Scalar(t, h, `SELECT count(*) FROM user_delete_audit_effects f JOIN user_delete_audit_events e USING(event_id) WHERE e.root_id=$1`, u))
			require.EqualValues(t, n, sd8Scalar(t, h, `SELECT effect_count FROM user_delete_audit_events WHERE root_id=$1`, u))
			require.NoError(t, h.App().DB().QueryRow(`SELECT coalesce(array_agg(resource_key ORDER BY resource_key),'{}') FROM user_delete_audit_effects JOIN user_delete_audit_events USING(event_id) WHERE root_id=$1`, u).Scan(pq.Array(&actualIDs)))
			require.Equal(t, expectedIDs, actualIDs)
			var bytes, maxLeaf int64
			require.NoError(t, h.App().DB().QueryRow(`SELECT effect_json_bytes,coalesce((SELECT max(octet_length(payload::text)) FROM user_delete_audit_effects WHERE event_id=e.event_id),0) FROM user_delete_audit_events e WHERE root_id=$1`, u).Scan(&bytes, &maxLeaf))
			require.LessOrEqual(t, maxLeaf, int64(4096))
			if n == 20000 {
				require.Greater(t, bytes, int64(4194304))
			}
			t.Logf("history=%d pages=%d persisted_bytes=%d largest_leaf=%d", n, (n+255)/256, bytes, maxLeaf)
		})
	}
}

func TestUserDeleteAuditRotationIdentity(t *testing.T) {
	h := sd1Harness(t)
	for _, shape := range []string{"UVW", "UUVW", "UVUW", "UUU", "U1U2", "missing_state", "large"} {
		t.Run(shape, func(t *testing.T) {
			u, v, w := sd7User(t, h), sd7User(t, h), sd7User(t, h)
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
			}
			input := []assignment.RawTarget{{Type: assignment.TargetTypeUser, ID: u}}
			if shape == "U1U2" {
				input = append(input, assignment.RawTarget{Type: assignment.TargetTypeUser, ID: v})
			}
			ok, err := sd7App(h).Mutation().DeleteAll(permission.SystemContext(t.Context(), "Engine"), input)
			if shape == "missing_state" {
				require.Error(t, err)
				require.False(t, ok)
				require.EqualValues(t, len(users), sd8Scalar(t, h, `SELECT count(*) FROM rotation_participants WHERE rotation_id=$1`, rot))
				// This deliberately invalid fixture must not escape into the
				// harness's final background Engine cycles after rollback checks.
				sd8Exec(t, h, `DELETE FROM rotations WHERE id=$1`, rot)
				return
			}
			require.NoError(t, err)
			require.True(t, ok)
			expected := []string{}
			for _, user := range users {
				if user != u && (shape != "U1U2" || user != v) {
					expected = append(expected, user)
				}
			}
			rows, err := h.App().DB().Query(`SELECT id,user_id,position FROM rotation_participants WHERE rotation_id=$1 ORDER BY position`, rot)
			require.NoError(t, err)
			i := 0
			for rows.Next() {
				var id, user string
				var pos int
				require.NoError(t, rows.Scan(&id, &user, &pos))
				require.Less(t, i, len(expected))
				require.Equal(t, ids[i], id)
				require.Equal(t, expected[i], user)
				require.Equal(t, i, pos)
				i++
			}
			require.NoError(t, rows.Err())
			rows.Close()
			require.Equal(t, len(expected), i)
			require.EqualValues(t, len(expected), sd8Scalar(t, h, `SELECT participant_count FROM rotations WHERE id=$1`, rot))
			require.EqualValues(t, len(users)-len(expected), sd8Scalar(t, h, `SELECT count(*) FROM user_delete_audit_effects f JOIN user_delete_audit_events e USING(event_id) WHERE e.root_id=ANY($1::uuid[]) AND f.resource_type='rotation_participant' AND f.payload->>'change'='relationship_removed'`, uuidArray(input)))
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
