package smoke

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/auth"
	"github.com/target/goalert/executioncontext"
	"github.com/target/goalert/gadb"
	"github.com/target/goalert/graphql2"
	"github.com/target/goalert/graphql2/graphqlapp"
	"github.com/target/goalert/notificationchannel"
	"github.com/target/goalert/permission"
	"github.com/target/goalert/schedule"
	"github.com/target/goalert/test/smoke/harness"
	"github.com/target/goalert/util/timeutil"
)

func TestScheduleDataTemporaryValidationPrecedence(t *testing.T) {
	h := scheduleDataHarness(t)
	org := uuid.MustParse(harness.SmokeOrganizationID)
	for _, tc := range []struct {
		name   string
		change func(*schedule.TemporarySchedule)
	}{
		{"invalid-range", func(s *schedule.TemporarySchedule) { s.End = s.Start }},
		{"future-end", func(s *schedule.TemporarySchedule) {
			s.Start = time.Now()
			s.End = s.Start.Add(time.Minute)
			s.Shifts = nil
		}},
		{"shift-limit", func(s *schedule.TemporarySchedule) { s.Shifts = make([]schedule.FixedShift, 151) }},
		{"malformed-user", func(s *schedule.TemporarySchedule) { s.Shifts[0].UserID = "bad" }},
		{"missing-user", func(s *schedule.TemporarySchedule) { s.Shifts[0].UserID = h.UUID("missing-user") }},
		{"shift-range", func(s *schedule.TemporarySchedule) { s.Shifts[0].End = s.Shifts[0].Start }},
		{"shift-containment", func(s *schedule.TemporarySchedule) { s.Shifts[0].End = s.End.Add(time.Hour) }},
		{"combined", func(s *schedule.TemporarySchedule) { s.End = s.Start; s.Shifts[0].UserID = "bad" }},
	} {
		for _, op := range []string{"set", "set-clear"} {
			for _, parent := range []string{"own", "foreign", "missing"} {
				t.Run(tc.name+"/"+op+"/"+parent, func(t *testing.T) {
					temp := scheduleDataTemp(h)
					tc.change(&temp)
					id, ctx := uuid.MustParse(h.UUID(parent)), scheduleDataContext(t)
					want := scheduleDataUnscoped(ctx, h.App().ScheduleStore, nil, id, temp, op)
					require.Error(t, want)
					err := scheduleDataMutate(ctx, h.App().ScheduleStore, nil, id, temp, op, &org)
					scheduleDataRecord(t, scheduleDataOutcome(err))
					require.EqualError(t, err, want.Error())
					require.Empty(t, scheduleDataRaw(t, h, parent))
				})
			}
		}
	}
	for _, parent := range []string{"own", "foreign", "missing"} {
		for _, op := range []string{"clear-range", "clear-future", "set-clear-range"} {
			t.Run(op+"/"+parent, func(t *testing.T) {
				ctx, id, temp := scheduleDataContext(t), uuid.MustParse(h.UUID(parent)), scheduleDataTemp(h)
				start, end := temp.End, temp.Start
				if op == "clear-future" {
					start, end = time.Now().Add(-time.Hour), time.Now().Add(time.Minute)
				}
				var want, got error
				if op == "set-clear-range" {
					want = h.App().ScheduleStore.SetClearTemporarySchedule(ctx, nil, id, temp, start, end)
					got = h.App().ScheduleStore.SetClearTemporaryScheduleScoped(ctx, nil, id, temp, start, end, &org)
				} else {
					want = h.App().ScheduleStore.ClearTemporarySchedules(ctx, nil, id, start, end)
					got = h.App().ScheduleStore.ClearTemporarySchedulesScoped(ctx, nil, id, start, end, &org)
				}
				scheduleDataRecord(t, scheduleDataOutcome(got))
				require.Error(t, want)
				require.EqualError(t, got, want.Error())
			})
		}
	}
}

func scheduleDataRuleID(t *testing.T, id uuid.UUID, index int) schedule.RuleID {
	t.Helper()
	var result schedule.RuleID
	require.NoError(t, result.UnmarshalText([]byte(fmt.Sprintf("%s:%d", id, index))))
	return result
}

func TestScheduleDataNotificationValidationPrecedence(t *testing.T) {
	h := scheduleDataHarness(t)
	org := uuid.MustParse(harness.SmokeOrganizationID)
	all, never, clock := timeutil.EveryDay(), timeutil.WeekdayFilter{}, timeutil.NewClock(12, 0)
	for _, tc := range []struct {
		name  string
		rules func(uuid.UUID) []schedule.OnCallNotificationRule
	}{
		{"rule-limit", func(uuid.UUID) []schedule.OnCallNotificationRule { return make([]schedule.OnCallNotificationRule, 51) }},
		{"never-days", func(uuid.UUID) []schedule.OnCallNotificationRule {
			return []schedule.OnCallNotificationRule{{WeekdayFilter: &never}}
		}},
		{"days-without-time", func(uuid.UUID) []schedule.OnCallNotificationRule {
			return []schedule.OnCallNotificationRule{{WeekdayFilter: &all}}
		}},
		{"time-without-days", func(uuid.UUID) []schedule.OnCallNotificationRule {
			return []schedule.OnCallNotificationRule{{Time: &clock}}
		}},
		{"duplicate-on-change", func(uuid.UUID) []schedule.OnCallNotificationRule { return []schedule.OnCallNotificationRule{{}, {}} }},
		{"duplicate-time", func(uuid.UUID) []schedule.OnCallNotificationRule {
			return []schedule.OnCallNotificationRule{{Time: &clock, WeekdayFilter: &all}, {Time: &clock, WeekdayFilter: &all}}
		}},
		{"negative-id", func(id uuid.UUID) []schedule.OnCallNotificationRule {
			return []schedule.OnCallNotificationRule{{ID: scheduleDataRuleID(t, id, -1)}}
		}},
		{"large-id", func(id uuid.UUID) []schedule.OnCallNotificationRule {
			return []schedule.OnCallNotificationRule{{ID: scheduleDataRuleID(t, id, 51)}}
		}},
		{"wrong-schedule-id", func(uuid.UUID) []schedule.OnCallNotificationRule {
			return []schedule.OnCallNotificationRule{{ID: scheduleDataRuleID(t, uuid.MustParse(h.UUID("other")), 0)}}
		}},
		{"duplicate-id", func(id uuid.UUID) []schedule.OnCallNotificationRule {
			return []schedule.OnCallNotificationRule{{ID: scheduleDataRuleID(t, id, 0)}, {ID: scheduleDataRuleID(t, id, 0), ChannelID: uuid.MustParse(h.UUID("channel"))}}
		}},
	} {
		for _, parent := range []string{"own", "foreign", "missing"} {
			t.Run(tc.name+"/"+parent, func(t *testing.T) {
				id, ctx := uuid.MustParse(h.UUID(parent)), scheduleDataContext(t)
				want := h.App().ScheduleStore.SetOnCallNotificationRules(ctx, nil, id, tc.rules(id))
				err := h.App().ScheduleStore.SetOnCallNotificationRulesScoped(ctx, nil, id, tc.rules(id), &org)
				scheduleDataRecord(t, scheduleDataOutcome(err))
				require.Error(t, want)
				require.EqualError(t, err, want.Error())
				require.Empty(t, scheduleDataRaw(t, h, parent))
			})
		}
	}
	// Keep the existing inclusive range / slice-index boundary visible. This
	// mutation-only authorization change does not repair index 50 semantics.
	for _, parent := range []string{"own", "foreign", "missing"} {
		t.Run("index-50-baseline-panic/"+parent, func(t *testing.T) {
			defer func() { r := recover(); require.NotNil(t, r); scheduleDataRecord(t, fmt.Sprint(r)) }()
			id := uuid.MustParse(h.UUID(parent))
			_ = h.App().ScheduleStore.SetOnCallNotificationRulesScoped(scheduleDataContext(t), nil, id, []schedule.OnCallNotificationRule{{ID: scheduleDataRuleID(t, id, 50)}}, &org)
		})
	}
	t.Run("count-50-omitted-and-supplied-id-allocation", func(t *testing.T) {
		id := uuid.MustParse(h.UUID("own"))
		rules := make([]schedule.OnCallNotificationRule, 50)
		for i := range rules {
			rules[i].ChannelID = uuid.NewSHA1(uuid.Nil, []byte(fmt.Sprint(i)))
		}
		rules[0].ID = scheduleDataRuleID(t, id, 49)
		err := h.App().ScheduleStore.SetOnCallNotificationRulesScoped(scheduleDataContext(t), nil, id, rules, &org)
		require.NoError(t, err)
		got, err := h.App().ScheduleStore.OnCallNotificationRules(scheduleDataContext(t), nil, id)
		require.NoError(t, err)
		require.Len(t, got, 50)
		for i, rule := range got {
			want := i - 1
			if i == 0 {
				want = 49
			}
			require.Equal(t, fmt.Sprintf("%s:%d", id, want), rule.ID.String())
		}
		scheduleDataRecord(t, "50 rules: supplied 49, allocated 0..48")
	})
}

func TestScheduleDataGraphQLValidationPrecedence(t *testing.T) {
	h := scheduleDataHarness(t)
	ctx := scheduleDataHuman(t, h, permission.RoleUser)
	app, provider := scheduleDataProviderApp(t, h)
	for _, op := range scheduleDataOperations {
		t.Run("malformed-schedule/"+op, func(t *testing.T) {
			err := scheduleDataGraphQL(ctx, app, "bad", scheduleDataTemp(h), op)
			scheduleDataRecord(t, scheduleDataOutcome(err))
			require.ErrorContains(t, err, "ScheduleID")
			require.ErrorContains(t, err, "must be a valid UUID")
		})
	}
	for _, parent := range []string{"own", "foreign", "missing"} {
		for _, tc := range []string{"clear-start-only", "clear-end-only", "unknown-dest", "unsupported-dest", "invalid-dest", "combined-dest-before-rule-count"} {
			t.Run(tc+"/"+parent, func(t *testing.T) {
				var err error
				temp := scheduleDataTemp(h)
				provider.capable = tc != "unsupported-dest"
				switch tc {
				case "clear-start-only", "clear-end-only":
					input := graphql2.SetTemporaryScheduleInput{ScheduleID: h.UUID(parent), Start: temp.Start, End: temp.End}
					if tc == "clear-start-only" {
						input.ClearStart = &temp.Start
					} else {
						input.ClearEnd = &temp.End
					}
					_, err = app.Mutation().SetTemporarySchedule(ctx, input)
					require.ErrorContains(t, err, "must be set if")
				default:
					dest := gadb.NewDestV1(provider.ID(), "id", "local-test")
					if tc == "unknown-dest" {
						dest.Type = "unknown"
					}
					if tc == "invalid-dest" || tc == "combined-dest-before-rule-count" {
						dest.Args = nil
					}
					rules := []graphql2.OnCallNotificationRuleInput{{Dest: dest}}
					if tc == "combined-dest-before-rule-count" {
						for len(rules) < 51 {
							rules = append(rules, rules[0])
						}
					}
					_, err = app.Mutation().SetScheduleOnCallNotificationRules(ctx, graphql2.SetScheduleOnCallNotificationRulesInput{ScheduleID: h.UUID(parent), Rules: rules})
					require.Error(t, err)
					require.NotContains(t, err.Error(), "schedule does not exist")
					if tc == "combined-dest-before-rule-count" {
						require.ErrorContains(t, err, "required")
					}
				}
				scheduleDataRecord(t, scheduleDataOutcome(err))
				require.Empty(t, scheduleDataRaw(t, h, parent))
			})
		}
	}
}

func scheduleDataMissingAuthority(t *testing.T, h *harness.Harness) context.Context {
	t.Helper()
	session := uuid.NewString()
	requester, err := auth.NewRequester(h.UUID("user-a"), session)
	require.NoError(t, err)
	return auth.WithRequester(permission.UserSourceContext(scheduleDataRequestContext(t), h.UUID("user-a"), permission.RoleUser,
		&permission.SourceInfo{Type: permission.SourceTypeAuthProvider, ID: session}), requester)
}

// Observe query starts, including failed parent checks and child reads/locks.
// Fixture setup and durable-state checks use the independent harness connection.
func scheduleDataValidationTrace(t *testing.T, h *harness.Harness, app *graphqlapp.App) (scheduleQueries, channelWrites *atomic.Int32) {
	t.Helper()
	scheduleQueries, channelWrites = new(atomic.Int32), new(atomic.Int32)
	tr := &scheduleDataTrace{before: func(_ context.Context, query string) {
		if strings.Contains(query, "-- name: Sched") || strings.Contains(query, "schedule_data") {
			scheduleQueries.Add(1)
		}
		if strings.Contains(query, "-- name: NotifChanUpsertDest") {
			channelWrites.Add(1)
		}
	}}
	app.DB, app.ScheduleStore = scheduleDataTraced(t, h, tr)
	var err error
	app.NCStore, err = notificationchannel.NewStore(context.Background(), app.DB, app.DestReg)
	require.NoError(t, err)
	return scheduleQueries, channelWrites
}

// Safe input errors precede missing human authority, but neither safe validation
// nor authority rejection may enter Schedule parent/data access.
func TestScheduleDataInvalidAuthorityPrecedence(t *testing.T) {
	h := scheduleDataHarness(t)
	app := scheduleDataApp(h)
	scheduleQueries, channelWrites := scheduleDataValidationTrace(t, h, app)
	for _, op := range scheduleDataOperations {
		t.Run(op, func(t *testing.T) {
			ctx := scheduleDataMissingAuthority(t, h)
			temp := scheduleDataTemp(h)
			temp.End = temp.Start
			want := "invalid value for 'End': must be after Start"
			if op == "set" || op == "set-clear" {
				want += "\ninvalid value for 'Shifts[0].Start': must be before End"
			}
			var err error
			if op == "rules" {
				want = "unknown destination type"
				_, err = app.Mutation().SetScheduleOnCallNotificationRules(ctx, graphql2.SetScheduleOnCallNotificationRulesInput{
					ScheduleID: h.UUID("own"), Rules: []graphql2.OnCallNotificationRuleInput{{Dest: gadb.NewDestV1("unknown")}},
				})
			} else {
				err = scheduleDataGraphQL(ctx, app, h.UUID("own"), temp, op)
			}
			scheduleDataRecord(t, scheduleDataOutcome(err))
			require.EqualError(t, err, want)
			require.Zero(t, scheduleQueries.Load(), "safe validation must not access Schedule state")
			require.Zero(t, channelWrites.Load())
			require.Empty(t, scheduleDataRaw(t, h, "own"))
			t.Log("safe error preserved; Schedule queries=0; channel writes=0")
		})
	}
}

func TestScheduleDataInvalidAuthorityAdmission(t *testing.T) {
	h := scheduleDataHarness(t)
	app, provider := scheduleDataProviderApp(t, h)
	scheduleQueries, channelWrites := scheduleDataValidationTrace(t, h, app)
	for _, authority := range []string{"missing", "zero"} {
		for _, parent := range []string{"own", "foreign", "missing"} {
			for _, op := range []string{"set", "set-clear", "clear", "rules", "rules-update"} {
				t.Run(authority+"/"+parent+"/"+op, func(t *testing.T) {
					ctx := scheduleDataMissingAuthority(t, h)
					if authority == "zero" {
						ctx = executioncontext.WithExecutionContext(ctx, executioncontext.ExecutionContext{})
					}
					raw := ""
					if parent != "missing" {
						// Decoding this as schedule.Data would fail if admission reached child state.
						scheduleDataReset(t, h, parent, `{"V1":"invalid schedule data"}`)
						raw = scheduleDataRaw(t, h, parent)
					}
					beforeWrites := channelWrites.Load()
					var err error
					if op == "rules" || op == "rules-update" {
						dest := gadb.NewDestV1(provider.ID(), "id", authority+"-"+parent+"-"+op)
						if op == "rules-update" {
							_, err = h.App().DB().Exec(`INSERT INTO notification_channels(id,dest,name) VALUES($1,$2,'original display name')`, uuid.New(), gadb.NullDestV1{Valid: true, DestV1: dest})
							require.NoError(t, err)
						}
						_, err = app.Mutation().SetScheduleOnCallNotificationRules(ctx, graphql2.SetScheduleOnCallNotificationRulesInput{
							ScheduleID: h.UUID(parent), Rules: []graphql2.OnCallNotificationRuleInput{{Dest: dest}},
						})
						require.Equal(t, beforeWrites+1, channelWrites.Load(), "observe the transaction-local destination write")
						var name string
						lookup := h.App().DB().QueryRow(`SELECT name FROM notification_channels WHERE dest=$1`, gadb.NullDestV1{Valid: true, DestV1: dest}).Scan(&name)
						if op == "rules" {
							require.ErrorIs(t, lookup, sql.ErrNoRows, "destination insert must roll back")
						} else {
							require.NoError(t, lookup)
							require.Equal(t, "original display name", name, "destination update must roll back")
						}
					} else {
						err = scheduleDataGraphQL(ctx, app, h.UUID(parent), scheduleDataTemp(h), op)
					}
					require.EqualError(t, err, "access denied: normal Organization scoped authority is required")
					require.True(t, permission.IsPermissionError(err))
					require.Zero(t, scheduleQueries.Load(), "authority denial must precede every Schedule query")
					require.Equal(t, raw, scheduleDataRaw(t, h, parent))
					t.Log("authority denied; Schedule queries=0; durable Schedule/channel changes=0")
				})
			}
		}
	}
}

func TestScheduleDataJSONAndTemporaryCompatibility(t *testing.T) {
	h := scheduleDataHarness(t)
	org, id := uuid.MustParse(harness.SmokeOrganizationID), uuid.MustParse(h.UUID("own"))
	ctx := scheduleDataContext(t)
	temp := scheduleDataTemp(h)
	scheduleDataReset(t, h, "own", `{"Future":{"value":7},"V1":{"Unknown":{"keep":true},"OnCallNotificationRules":[]}}`)
	read := func() schedule.Data {
		var data schedule.Data
		raw := scheduleDataRaw(t, h, "own")
		require.NoError(t, json.Unmarshal([]byte(raw), &data))
		var generic map[string]json.RawMessage
		require.NoError(t, json.Unmarshal([]byte(raw), &generic))
		require.JSONEq(t, `{"value":7}`, string(generic["Future"]))
		require.Contains(t, string(generic["V1"]), `"Unknown"`)
		return data
	}
	t.Run("temporary-preserves-rules", func(t *testing.T) {
		rules := []schedule.OnCallNotificationRule{{ChannelID: uuid.MustParse(h.UUID("channel"))}}
		require.NoError(t, h.App().ScheduleStore.SetOnCallNotificationRulesScoped(ctx, nil, id, rules, &org))
		before := read().V1.OnCallNotificationRules
		require.NoError(t, h.App().ScheduleStore.SetTemporaryScheduleScoped(ctx, nil, id, temp, &org))
		require.Equal(t, before, read().V1.OnCallNotificationRules)
		scheduleDataRecord(t, "preserved notification rules and unknown object fields")
	})
	t.Run("rules-preserve-temporary", func(t *testing.T) {
		before := read().V1.TemporarySchedules
		require.NoError(t, h.App().ScheduleStore.SetOnCallNotificationRulesScoped(ctx, nil, id, nil, &org))
		require.Equal(t, before, read().V1.TemporarySchedules)
		scheduleDataRecord(t, "empty replacement preserved temporary schedules and unknown object fields")
	})
	t.Run("split-and-merge", func(t *testing.T) {
		start, end := temp.Start.Add(time.Hour), temp.End.Add(-time.Hour)
		require.NoError(t, h.App().ScheduleStore.ClearTemporarySchedulesScoped(ctx, nil, id, start, end, &org))
		got := read().V1.TemporarySchedules
		require.Len(t, got, 2)
		require.Equal(t, start, got[0].End)
		require.Equal(t, end, got[1].Start)
		middle := temp
		middle.Start = start
		middle.End = end
		middle.Shifts = []schedule.FixedShift{{Start: start, End: end, UserID: h.UUID("user-a")}}
		require.NoError(t, h.App().ScheduleStore.SetTemporaryScheduleScoped(ctx, nil, id, middle, &org))
		got = read().V1.TemporarySchedules
		require.Len(t, got, 1)
		require.Len(t, got[0].Shifts, 1)
		require.Equal(t, temp.Start, got[0].Start)
		require.Equal(t, temp.End, got[0].End)
		scheduleDataRecord(t, "split into two; adjacent replacement merges into one")
	})
	t.Run("past-start-clipping", func(t *testing.T) {
		past := time.Now().Add(-time.Hour)
		end := time.Now().Add(time.Hour)
		active := schedule.TemporarySchedule{Start: past, End: end}
		before := time.Now().Truncate(time.Minute)
		require.NoError(t, h.App().ScheduleStore.SetClearTemporaryScheduleScoped(ctx, nil, id, active, past, end, &org))
		got := read().V1.TemporarySchedules
		require.False(t, got[0].Start.Before(before))
		require.True(t, got[0].Start.Before(time.Now().Add(time.Minute)))
		require.NoError(t, h.App().ScheduleStore.ClearTemporarySchedulesScoped(ctx, nil, id, past, end, &org))
		got = read().V1.TemporarySchedules
		// A historical prefix may remain because Clear clips to now, preserving
		// the base behavior rather than erasing already elapsed state.
		for _, s := range got {
			require.False(t, s.Start.Before(before))
		}
		scheduleDataRecord(t, "set-clear and clear clipped past starts")
	})
}
