package smoke

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/assignment"
	"github.com/target/goalert/organization"
	sraudit "github.com/target/goalert/schedule/deleteaudit"
	"github.com/target/goalert/test/smoke/harness"
)

func TestSRDeleteAuditLockWaitSnapshots(t *testing.T) {
	for _, mode := range []string{"action_retarget", "step_reparent_rejected", "rule_reparent", "json_update", "favorite_owner", "favorite_assignment", "history_update", "rotation_table_order", "root_organization"} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			h := sd1Harness(t)
			db := h.App().DB()
			s, r := sd6Root(t, h, sraudit.Schedule, harness.SmokeOrganizationID), sd6Root(t, h, sraudit.Rotation, harness.SmokeOrganizationID)
			otherS := sd6Root(t, h, sraudit.Schedule, harness.SmokeOrganizationID)
			root, target := s, assignment.TargetTypeSchedule
			var id, parentPolicy string
			switch mode {
			case "action_retarget", "step_reparent_rejected":
				parentPolicy = sd5EP(t, h, harness.SmokeOrganizationID)
				step := sd5Step(t, h, parentPolicy)
				id = sd6Action(t, h, step, sraudit.Schedule, s)
			case "rule_reparent":
				root, target = r, assignment.TargetTypeRotation
				id = sd6Rule(t, h, s, r)
			case "json_update":
				_, err := db.Exec(`INSERT INTO schedule_data(schedule_id,data) VALUES($1,'{}')`, s)
				require.NoError(t, err)
			case "favorite_owner", "favorite_assignment":
				require.NoError(t, db.QueryRow(`INSERT INTO user_favorites(user_id,tgt_schedule_id) VALUES($1,$2) RETURNING id::text`, h.UUID("user-a"), s).Scan(&id))
			case "history_update":
				require.NoError(t, db.QueryRow(`INSERT INTO schedule_on_call_users(user_id,schedule_id,start_time,end_time) VALUES($1,$2,'2020-01-01','2020-01-02') RETURNING id::text`, h.UUID("user-a"), s).Scan(&id))
			case "rotation_table_order":
				root, target = r, assignment.TargetTypeRotation
			}
			conn, err := db.Conn(t.Context())
			require.NoError(t, err)
			defer conn.Close()
			tx, err := conn.BeginTx(t.Context(), nil)
			require.NoError(t, err)
			defer func() { _ = tx.Rollback() }()
			var pid int
			require.NoError(t, tx.QueryRow(`SELECT pg_backend_pid()`).Scan(&pid))
			switch mode {
			case "action_retarget", "step_reparent_rejected":
				_, err = tx.Exec(`SELECT id FROM escalation_policy_actions WHERE id=$1 FOR UPDATE`, id)
			case "rule_reparent":
				_, err = tx.Exec(`SELECT id FROM schedule_rules WHERE id=$1 FOR UPDATE`, id)
			case "json_update":
				_, err = tx.Exec(`SELECT id FROM schedule_data WHERE schedule_id=$1 FOR UPDATE`, s)
			case "favorite_owner":
				_, err = tx.Exec(`SELECT id FROM user_favorites WHERE id=$1 FOR UPDATE`, id)
			case "favorite_assignment":
				_, err = tx.Exec(`SELECT user_id FROM user_organization_assignments WHERE user_id=$1 FOR UPDATE`, h.UUID("user-a"))
			case "history_update":
				_, err = tx.Exec(`SELECT id FROM schedule_on_call_users WHERE id=$1 FOR UPDATE`, id)
			case "rotation_table_order":
				_, err = tx.Exec(`LOCK rotation_participants,rotation_state IN EXCLUSIVE MODE`)
			case "root_organization":
				_, err = tx.Exec(`SELECT id FROM schedules WHERE id=$1 FOR UPDATE`, s)
			}
			require.NoError(t, err)
			ctx, cancel := context.WithTimeout(sd3System(), 15*time.Second)
			defer cancel()
			done := make(chan error, 1)
			go func() {
				_, err := sd5App(h).Mutation().DeleteAll(ctx, []assignment.RawTarget{sd3Target(target, root)})
				done <- err
			}()
			sd3WaitBlocked(t, db, pid)
			newUser := uuid.NewString()
			_, err = tx.Exec(`INSERT INTO users(id,name) VALUES($1,'SYNTHETIC_PRIVATE')`, newUser)
			require.NoError(t, err)
			switch mode {
			case "action_retarget":
				_, err = tx.Exec(`UPDATE escalation_policy_actions SET schedule_id=$2 WHERE id=$1`, id, otherS)
			case "step_reparent_rejected":
				newPolicy := sd5EP(t, h, harness.SmokeOrganizationID)
				_, err = tx.Exec(`UPDATE escalation_policy_steps SET escalation_policy_id=$2 WHERE id=(SELECT escalation_policy_step_id FROM escalation_policy_actions WHERE id=$1)`, id, newPolicy)
			case "rule_reparent":
				_, err = tx.Exec(`UPDATE schedule_rules SET schedule_id=$2 WHERE id=$1`, id, otherS)
			case "json_update":
				data := fmt.Sprintf(`{"V1":{"TemporarySchedules":[{"Start":"2020-01-01T00:00:00Z","End":"2020-01-02T00:00:00Z","Shifts":[{"UserID":%q,"Start":"2020-01-01T00:00:00Z","End":"2020-01-02T00:00:00Z"}]}]}}`, newUser)
				_, err = tx.Exec(`UPDATE schedule_data SET data=$2::jsonb WHERE schedule_id=$1`, s, data)
			case "favorite_owner":
				_, err = tx.Exec(`UPDATE user_favorites SET user_id=$2 WHERE id=$1`, id, newUser)
			case "favorite_assignment":
				_, err = tx.Exec(`UPDATE user_organization_assignments SET effective_organization_id=$2,effective_organization_classification='DEFAULT',effective_normal_organization_id=NULL,organization_role='NONE',mapping_outcome='ZERO',matched_count=0 WHERE user_id=$1`, h.UUID("user-a"), organization.DefaultOrganizationID)
			case "history_update":
				_, err = tx.Exec(`UPDATE schedule_on_call_users SET user_id=$2,end_time='2020-01-03' WHERE id=$1`, id, newUser)
			case "rotation_table_order":
				_, err = tx.Exec(`INSERT INTO rotation_participants(rotation_id,user_id) VALUES($1,$2)`, r, newUser)
			case "root_organization":
				_, err = tx.Exec(`UPDATE schedules SET organization_id=$2 WHERE id=$1`, s, h.UUID("org-b"))
			}
			require.NoError(t, err)
			if mode == "step_reparent_rejected" {
				// The existing no-reparent constraint is deferred until Commit.
				err = tx.Commit()
				var pg *pgconn.PgError
				require.ErrorAs(t, err, &pg)
				require.Equal(t, "P0001", pg.Code)
			} else {
				require.NoError(t, tx.Commit())
			}
			require.NoError(t, <-done)
			effects := sd6Effects(t, h, root)
			switch mode {
			case "action_retarget":
				require.Empty(t, effects)
				require.Equal(t, 1, serviceManagementCount(t, h, "escalation_policy_actions", id))
			case "step_reparent_rejected":
				require.Len(t, effects, 1)
				require.Equal(t, parentPolicy, effects[0].Action.PolicyID.String())
			case "rule_reparent":
				require.Len(t, effects, 1)
				require.Equal(t, otherS, effects[0].Rule.ScheduleID.String())
			case "json_update":
				require.Len(t, effects, 2)
				found := false
				for _, f := range effects {
					if f.Shift != nil {
						found = true
						require.Equal(t, newUser, f.Shift.UserID.String())
					}
				}
				require.True(t, found)
			case "favorite_owner":
				require.Len(t, effects, 1)
				require.Equal(t, newUser, effects[0].Favorite.OwnerUserID.String())
				require.Equal(t, "unknown", effects[0].Favorite.OwnerOrgResolution)
			case "favorite_assignment":
				require.Len(t, effects, 1)
				require.Equal(t, "known_default", effects[0].Favorite.OwnerOrgResolution)
				require.Equal(t, organization.DefaultOrganizationID, effects[0].Favorite.OwnerOrganizationID.String())
			case "history_update":
				require.Len(t, effects, 1)
				require.Equal(t, newUser, effects[0].History.UserID.String())
				require.Equal(t, 3, effects[0].History.End.Day())
			case "rotation_table_order":
				require.Len(t, effects, 1)
				require.Equal(t, newUser, effects[0].Participant.UserID.String())
				var state string
				require.NoError(t, db.QueryRow(`SELECT before_state::text FROM schedule_rotation_delete_audit_events WHERE root_id=$1`, root).Scan(&state))
				require.NotEqual(t, "null", state)
			case "root_organization":
				var org string
				require.NoError(t, db.QueryRow(`SELECT target_organization_id FROM schedule_rotation_delete_audit_events WHERE root_id=$1`, root).Scan(&org))
				require.Equal(t, h.UUID("org-b"), org)
			}
		})
	}
}

func TestSRDeleteAuditUpdateBoundary(t *testing.T) {
	h := sd1Harness(t)
	ikSetAuthority(t, h, "ORG_ADMIN", false)
	s, r := sd6Root(t, h, sraudit.Schedule, harness.SmokeOrganizationID), sd6Root(t, h, sraudit.Rotation, harness.SmokeOrganizationID)
	_ = sd6Rule(t, h, s, r)
	_, err := h.App().DB().Exec(`INSERT INTO rotation_participants(rotation_id,user_id) VALUES($1,$2)`, r, h.UUID("user-a"))
	require.NoError(t, err)
	for _, q := range []string{fmt.Sprintf(`mutation{updateScheduleTarget(input:{scheduleID:%q,target:{type:rotation,id:%q},rules:[]})}`, s, r), fmt.Sprintf(`mutation{updateRotation(input:{id:%q,userIDs:[]})}`, r), fmt.Sprintf(`mutation{clearTemporarySchedules(input:{scheduleID:%q,start:"2090-01-01T00:00:00Z",end:"2090-01-02T00:00:00Z"})}`, s), fmt.Sprintf(`mutation{setScheduleOnCallNotificationRules(input:{scheduleID:%q,rules:[]})}`, s)} {
		response := stepOrganizationQuery(t, h, q)
		require.Empty(t, response.Errors)
	}
	require.Zero(t, sd6Count(t, h))
	require.Equal(t, 1, serviceManagementCount(t, h, "schedules", s))
	require.Equal(t, 1, serviceManagementCount(t, h, "rotations", r))
}
