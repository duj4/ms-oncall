package smoke

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/assignment"
	sraudit "github.com/target/goalert/schedule/deleteaudit"
	"github.com/target/goalert/test/smoke/harness"
)

func sd6Root(t *testing.T, h *harness.Harness, typ, org string) string {
	t.Helper()
	id := uuid.NewString()
	q := `INSERT INTO schedules(id,organization_id,name,time_zone) VALUES($1,$2,$3,'UTC')`
	if typ == sraudit.Rotation {
		q = `INSERT INTO rotations(id,organization_id,name,type,time_zone) VALUES($1,$2,$3,'daily','UTC')`
	}
	_, err := h.App().DB().Exec(q, id, org, "SYNTHETIC_PRIVATE "+id)
	require.NoError(t, err)
	return id
}
func sd6Query(typ string, ids []string, others ...string) string {
	targets := append([]string{}, others...)
	for _, id := range ids {
		targets = append(targets, fmt.Sprintf(`{type:%s,id:%q}`, typ, id))
	}
	return `mutation{deleteAll(input:[` + strings.Join(targets, ",") + `])}`
}
func sd6Count(t *testing.T, h *harness.Harness) int {
	t.Helper()
	var n int
	require.NoError(t, h.App().DB().QueryRow(`SELECT count(*) FROM schedule_rotation_delete_audit_events WHERE record_kind='success_witness'`).Scan(&n))
	return n
}
func sd6Effects(t *testing.T, h *harness.Harness, root string) []sraudit.Effect {
	t.Helper()
	var raw []byte
	require.NoError(t, h.App().DB().QueryRow(`SELECT effects FROM schedule_rotation_delete_audit_events WHERE root_id=$1 AND record_kind='success_witness'`, root).Scan(&raw))
	var effects []sraudit.Effect
	require.NoError(t, json.Unmarshal(raw, &effects))
	return effects
}
func sd6Rows(t *testing.T, h *harness.Harness) string {
	t.Helper()
	var raw string
	require.NoError(t, h.App().DB().QueryRow(`SELECT coalesce(jsonb_agg(to_jsonb(e)),'[]')::text FROM schedule_rotation_delete_audit_events e`).Scan(&raw))
	return raw
}
func sd6Rule(t *testing.T, h *harness.Harness, s, r string) string {
	t.Helper()
	id := uuid.NewString()
	_, err := h.App().DB().Exec(`INSERT INTO schedule_rules(id,schedule_id,tgt_rotation_id) VALUES($1,$2,$3)`, id, s, r)
	require.NoError(t, err)
	return id
}
func sd6Action(t *testing.T, h *harness.Harness, step, typ, root string) string {
	t.Helper()
	id := uuid.NewString()
	_, err := h.App().DB().Exec(`INSERT INTO escalation_policy_actions(id,escalation_policy_step_id,`+typ+`_id) VALUES($1,$2,$3)`, id, step, root)
	require.NoError(t, err)
	return id
}

func TestSRDeleteAuditDetailedEffectsHTTP(t *testing.T) {
	for _, typ := range []string{sraudit.Schedule, sraudit.Rotation} {
		t.Run(typ, func(t *testing.T) {
			t.Parallel()
			h := sd1Harness(t)
			ikSetAuthority(t, h, "ORG_ADMIN", false)
			db := h.App().DB()
			s, r := sd6Root(t, h, sraudit.Schedule, harness.SmokeOrganizationID), sd6Root(t, h, sraudit.Rotation, harness.SmokeOrganizationID)
			root := s
			if typ == sraudit.Rotation {
				root = r
			}
			rule := sd6Rule(t, h, s, r)
			policy := sd5EP(t, h, harness.SmokeOrganizationID)
			step := sd5Step(t, h, policy)
			action := sd6Action(t, h, step, typ, root)
			untouched := uuid.NewString()
			_, err := db.Exec(`INSERT INTO escalation_policy_actions(id,escalation_policy_step_id,user_id) VALUES($1,$2,$3)`, untouched, step, h.UUID("user-a"))
			require.NoError(t, err)
			user := h.UUID("user-a")
			expected := map[string]string{sraudit.Rule: rule, sraudit.Action: action}
			var favorite int64
			require.NoError(t, db.QueryRow(`INSERT INTO user_favorites(user_id,tgt_`+typ+`_id) VALUES($1,$2) RETURNING id`, user, root).Scan(&favorite))
			if typ == sraudit.Rotation {
				for i := 0; i < 2; i++ {
					id := uuid.NewString()
					_, err = db.Exec(`INSERT INTO rotation_participants(id,rotation_id,user_id) VALUES($1,$2,$3)`, id, r, user)
					require.NoError(t, err)
				}
			} else {
				override := uuid.NewString()
				_, err = db.Exec(`INSERT INTO user_overrides(id,tgt_schedule_id,add_user_id,start_time,end_time) VALUES($1,$2,$3,'2020-01-01','2020-01-02')`, override, s, user)
				require.NoError(t, err)
				expected[sraudit.Override] = override
				_, err = db.Exec(`INSERT INTO schedule_on_call_users(schedule_id,user_id,start_time,end_time) VALUES($1,$2,'2020-01-01','2020-01-02'),($1,$2,'2020-01-02',NULL)`, s, user)
				require.NoError(t, err)
				channel := uuid.NewString()
				_, err = db.Exec(`INSERT INTO notification_channels(id,name,type,value) VALUES($1,'SYNTHETIC_PRIVATE','WEBHOOK','https://synthetic.invalid/SYNTHETIC_DEST')`, channel)
				require.NoError(t, err)
				data := fmt.Sprintf(`{"V1":{"TemporarySchedules":[{"Start":"2020-01-01T00:00:00Z","End":"2020-01-02T00:00:00Z","Shifts":[{"UserID":%q,"Start":"2020-01-01T00:00:00Z","End":"2020-01-02T00:00:00Z"},{"UserID":%q,"Start":"2020-01-01T00:00:00Z","End":"2020-01-02T00:00:00Z"}]}],"OnCallNotificationRules":[{"ID":%q,"ChannelID":%q,"Time":"12:30","WeekdayFilter":"1010101","NextNotification":"SYNTHETIC_PRIVATE"}],"future":"SYNTHETIC_PRIVATE"},"future":"SYNTHETIC_PRIVATE"}`, user, user, s+":1", channel)
				_, err = db.Exec(`INSERT INTO schedule_data(schedule_id,data) VALUES($1,$2::jsonb)`, s, data)
				require.NoError(t, err)
			}
			response := stepOrganizationQuery(t, h, sd6Query(typ, []string{root, root}))
			require.Empty(t, response.Errors)
			require.Equal(t, 1, sd6Count(t, h))
			effects := sd6Effects(t, h, root)
			counts := map[string]int{}
			for _, f := range effects {
				counts[f.ResourceType]++
				require.Equal(t, root, f.RootID.String())
				require.Equal(t, harness.SmokeOrganizationID, f.TargetOrganizationID.String())
				if id := expected[f.ResourceType]; id != "" {
					require.Equal(t, id, f.ResourceUUID.String())
				}
				if f.Favorite != nil {
					require.Equal(t, favorite, *f.ResourceNumericID)
					require.Equal(t, "known_normal", f.Favorite.OwnerOrgResolution)
				}
				if f.Rule != nil {
					require.Equal(t, s, f.Rule.ScheduleID.String())
					require.Equal(t, r, f.Rule.TargetID.String())
				}
				if f.Action != nil {
					require.Equal(t, step, f.Action.StepID.String())
					require.Equal(t, policy, f.Action.PolicyID.String())
				}
			}
			require.Equal(t, 1, counts[sraudit.Rule])
			require.Equal(t, 1, counts[sraudit.Action])
			require.Equal(t, 1, counts[sraudit.Favorite])
			if typ == sraudit.Schedule {
				require.Len(t, effects, 10)
				require.Equal(t, 2, counts[sraudit.FixedShift])
				require.Equal(t, 2, counts[sraudit.History])
				require.Equal(t, 1, serviceManagementCount(t, h, "rotations", r))
			} else {
				require.Len(t, effects, 5)
				require.Equal(t, 2, counts[sraudit.Participant])
				var state []byte
				require.NoError(t, db.QueryRow(`SELECT before_state FROM schedule_rotation_delete_audit_events WHERE root_id=$1`, root).Scan(&state))
				require.NotEqual(t, "null", string(state))
				require.Equal(t, 1, serviceManagementCount(t, h, "schedules", s))
			}
			for table, id := range map[string]string{"users": user, "escalation_policy_steps": step, "escalation_policies": policy, "escalation_policy_actions": untouched} {
				require.Equal(t, 1, serviceManagementCount(t, h, table, id))
			}
			require.NotContains(t, sd6Rows(t, h), "SYNTHETIC_")
		})
	}
}

func TestSRDeleteAuditMixedProvenance(t *testing.T) {
	h := sd1Harness(t)
	ikSetAuthority(t, h, "ORG_ADMIN", false)
	s, r := sd6Root(t, h, sraudit.Schedule, harness.SmokeOrganizationID), sd6Root(t, h, sraudit.Rotation, harness.SmokeOrganizationID)
	rule := sd6Rule(t, h, s, r)
	policy := sd5EP(t, h, harness.SmokeOrganizationID)
	step := sd5Step(t, h, policy)
	srAction := sd6Action(t, h, step, sraudit.Schedule, s)
	rAction := sd6Action(t, h, step, sraudit.Rotation, r)
	override := uuid.NewString()
	_, err := h.App().DB().Exec(`INSERT INTO user_overrides(id,tgt_schedule_id,add_user_id,start_time,end_time) VALUES($1,$2,$3,'2020-01-01','2020-01-02')`, override, s, h.UUID("user-a"))
	require.NoError(t, err)
	response := stepOrganizationQuery(t, h, sd6Query(sraudit.Schedule, []string{s}, fmt.Sprintf(`{type:escalationPolicy,id:%q},{type:userOverride,id:%q},{type:rotation,id:%q}`, policy, override, r)))
	require.Empty(t, response.Errors)
	require.Equal(t, 2, sd6Count(t, h))
	se, re, pe := sd6Effects(t, h, s), sd6Effects(t, h, r), sd5Effects(t, h, policy)
	require.Len(t, se, 1)
	require.Equal(t, srAction, se[0].ResourceUUID.String())
	require.Len(t, re, 2)
	ids := map[string]bool{}
	for _, f := range re {
		ids[f.ResourceUUID.String()] = true
	}
	require.True(t, ids[rule])
	require.True(t, ids[rAction])
	require.Len(t, pe, 1)
	require.Equal(t, "escalation_policy_step", pe[0].ResourceType)
}

func TestSRDeleteAuditRollbackAndProjection(t *testing.T) {
	for _, mode := range []string{"append", "root_delete", "receipt_suppressed", "surviving_child", "deferred_commit", "later_service", "invalid_json", "nested_overflow", "absent_data", "empty_data", "unknown_json"} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			h := sd1Harness(t)
			ikSetAuthority(t, h, "ORG_ADMIN", false)
			db := h.App().DB()
			s, r := sd6Root(t, h, sraudit.Schedule, harness.SmokeOrganizationID), sd6Root(t, h, sraudit.Rotation, harness.SmokeOrganizationID)
			_ = sd6Rule(t, h, s, r)
			if mode == "invalid_json" || mode == "nested_overflow" || mode == "empty_data" || mode == "unknown_json" {
				data := `{}`
				if mode == "unknown_json" {
					data = `{"V1":{"future":"SYNTHETIC_PRIVATE"}}`
				}
				if mode == "invalid_json" {
					data = `{"V1":{"TemporarySchedules":[{"Start":"SYNTHETIC_PRIVATE"}]}}`
				}
				if mode == "nested_overflow" {
					shift := fmt.Sprintf(`{"UserID":%q,"Start":"2020-01-01T00:00:00Z","End":"2020-01-02T00:00:00Z"}`, h.UUID("user-a"))
					data = `{"V1":{"TemporarySchedules":[{"Start":"2020-01-01T00:00:00Z","End":"2020-01-02T00:00:00Z","Shifts":[` + strings.Repeat(shift+",", sraudit.MaxEffects-1) + shift + `]}]}}`
				}
				_, err := db.Exec(`INSERT INTO schedule_data(schedule_id,data) VALUES($1,$2::jsonb)`, s, data)
				require.NoError(t, err)
			}
			others := fmt.Sprintf(`{type:rotation,id:%q}`, r)
			if mode == "later_service" {
				others += fmt.Sprintf(`,{type:service,id:%q}`, h.UUID("service-b"))
			}
			if mode == "surviving_child" {
				other := sd6Root(t, h, sraudit.Schedule, harness.SmokeOrganizationID)
				_, err := db.Exec(`INSERT INTO schedule_on_call_users(schedule_id,user_id,start_time,end_time) VALUES($1,$2,'2020-01-01','2020-01-02')`, s, h.UUID("user-a"))
				require.NoError(t, err)
				_, err = db.Exec(`CREATE FUNCTION sd6_reparent() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN UPDATE schedule_on_call_users SET schedule_id='` + other + `' WHERE schedule_id=OLD.id;RETURN OLD;END;$$;CREATE TRIGGER sd6_reparent BEFORE DELETE ON schedules FOR EACH ROW EXECUTE FUNCTION sd6_reparent()`)
				require.NoError(t, err)
			}
			if mode == "receipt_suppressed" {
				_, err := db.Exec(`CREATE FUNCTION sd6_suppress() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RETURN NULL;END;$$;CREATE TRIGGER sd6_suppress BEFORE DELETE ON schedules FOR EACH ROW EXECUTE FUNCTION sd6_suppress()`)
				require.NoError(t, err)
			}
			if mode == "deferred_commit" {
				_, err := db.Exec(`CREATE FUNCTION sd6_deferred() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='SYNTHETIC_PRIVATE';END;$$;CREATE CONSTRAINT TRIGGER sd6_deferred AFTER DELETE ON schedules DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION sd6_deferred()`)
				require.NoError(t, err)
			}
			if mode == "append" || mode == "root_delete" {
				table, event, condition := "schedule_rotation_delete_audit_events", "INSERT", `WHEN (NEW.record_kind='success_witness')`
				if mode == "root_delete" {
					table, event, condition = "schedules", "DELETE", ""
				}
				_, err := db.Exec(`CREATE FUNCTION sd6_fail() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'SYNTHETIC_PRIVATE';END;$$;CREATE TRIGGER sd6_fail BEFORE ` + event + ` ON ` + table + ` FOR EACH ROW ` + condition + ` EXECUTE FUNCTION sd6_fail()`)
				require.NoError(t, err)
			}
			allowed := mode == "absent_data" || mode == "empty_data" || mode == "unknown_json"
			var expected func()
			if !allowed {
				message := "deleteAll transaction failed"
				if mode == "later_service" || mode == "receipt_suppressed" {
					message = "sql: no rows in result set"
				}
				expected = h.ExpectBackendError(message)
			}
			response := stepOrganizationQuery(t, h, sd6Query(sraudit.Schedule, []string{s}, others))
			if expected != nil {
				expected()
			}
			if allowed {
				require.Empty(t, response.Errors)
				require.Equal(t, 2, sd6Count(t, h))
			} else {
				require.NotEmpty(t, response.Errors)
				require.Zero(t, sd6Count(t, h))
				require.Equal(t, 1, serviceManagementCount(t, h, "schedules", s))
				require.Equal(t, 1, serviceManagementCount(t, h, "rotations", r))
				var effects int
				require.NoError(t, db.QueryRow(`SELECT count(*) FROM schedule_rotation_delete_audit_events WHERE effects<>'[]' OR before_state<>'null'`).Scan(&effects))
				require.Zero(t, effects)
			}
			require.NotContains(t, sd6Rows(t, h), "SYNTHETIC_")
		})
	}
}

func TestSRDeleteAuditControlledCommit(t *testing.T) {
	for _, typ := range []string{sraudit.Schedule, sraudit.Rotation} {
		for _, mode := range []string{"commit_then_error", "rollback_then_error", "completion_unknown", "begin_failed"} {
			t.Run(typ+"/"+mode, func(t *testing.T) {
				t.Parallel()
				h := sd1Harness(t)
				root := sd6Root(t, h, typ, harness.SmokeOrganizationID)
				var database string
				require.NoError(t, h.App().DB().QueryRow(`SELECT current_database()`).Scan(&database))
				cfg, err := pgx.ParseConfig(harness.DBURL(database))
				require.NoError(t, err)
				connector := &serviceAuditFaultConnector{base: stdlib.GetConnector(*cfg), mode: mode}
				controlled := sql.OpenDB(connector)
				defer controlled.Close()
				controlled.SetMaxOpenConns(1)
				app := sd5App(h)
				app.DB = controlled
				target := assignment.TargetTypeSchedule
				if typ == sraudit.Rotation {
					target = assignment.TargetTypeRotation
				}
				ok, err := app.Mutation().DeleteAll(sd3System(), []assignment.RawTarget{sd3Target(target, root)})
				require.Error(t, err)
				require.False(t, ok)
				require.EqualValues(t, 2, connector.begins.Load())
				want := 0
				if mode == "commit_then_error" || mode == "completion_unknown" {
					want = 1
				}
				require.Equal(t, want, sd6Count(t, h))
				require.Equal(t, 1-want, serviceManagementCount(t, h, typ+"s", root))
			})
		}
	}
}
