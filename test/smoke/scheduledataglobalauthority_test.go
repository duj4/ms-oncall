package smoke

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/gadb"
	"github.com/target/goalert/graphql2"
	"github.com/target/goalert/permission"
	"github.com/target/goalert/schedule"
	"github.com/target/goalert/util/timeutil"
)

func scheduleDataGlobalRecord(t *testing.T, value any) {
	t.Helper()
	b, err := json.Marshal(map[string]any{"case": t.Name(), "outcome": value})
	require.NoError(t, err)
	t.Log("SCHEDULE_DATA_GLOBAL_CASE " + string(b))
}

func scheduleDataExplorationRecord(t *testing.T, value any) {
	t.Helper()
	b, err := json.Marshal(map[string]any{"case": t.Name(), "outcome": value})
	require.NoError(t, err)
	t.Log("SCHEDULE_DATA_EXPLORATION_CASE " + string(b))
}

func TestScheduleDataTemporaryValidationCombinations(t *testing.T) {
	h := scheduleDataHarness(t)
	app := scheduleDataApp(h)
	queries, _ := scheduleDataValidationTrace(t, h, app)
	for _, parent := range []string{"own", "foreign", "missing"} {
		for _, op := range []string{"set", "set-clear"} {
			for _, kind := range []string{
				"malformed-before-missing", "valid-missing-malformed", "shift-limit-151-with-missing",
				"shift-limit-150-with-missing", "shift-limit-150-valid", "parent-and-shift-range",
				"parent-range-and-missing", "empty-shifts-parent-range", "clear-range-after-missing", "clear-range-after-valid",
			} {
				if (kind == "clear-range-after-missing" || kind == "clear-range-after-valid") && op != "set-clear" {
					continue
				}
				t.Run(parent+"/"+op+"/"+kind, func(t *testing.T) {
					ctx := scheduleDataMissingAuthority(t, h)
					temp := scheduleDataTemp(h)
					scheduleDataReset(t, h, parent, "")
					clearStart, clearEnd := temp.Start, temp.End
					switch kind {
					case "malformed-before-missing", "valid-missing-malformed":
						shift := temp.Shifts[0]
						missing, malformed := shift, shift
						missing.UserID, malformed.UserID = h.UUID("missing-user"), "bad"
						if kind == "malformed-before-missing" {
							temp.Shifts = []schedule.FixedShift{malformed, missing}
						} else {
							temp.Shifts = []schedule.FixedShift{shift, missing, malformed}
						}
					case "shift-limit-151-with-missing", "shift-limit-150-with-missing", "shift-limit-150-valid":
						count := 150
						if kind == "shift-limit-151-with-missing" {
							count++
						}
						for len(temp.Shifts) < count {
							temp.Shifts = append(temp.Shifts, temp.Shifts[0])
						}
						if kind != "shift-limit-150-valid" {
							temp.Shifts[0].UserID = h.UUID("missing-user")
						}
					case "parent-and-shift-range":
						temp.End, temp.Shifts[0].End = temp.Start, temp.Start
					case "parent-range-and-missing":
						temp.End, temp.Shifts[0].UserID = temp.Start, h.UUID("missing-user")
					case "empty-shifts-parent-range":
						temp.End, temp.Shifts = temp.Start, nil
					case "clear-range-after-missing", "clear-range-after-valid":
						clearStart, clearEnd = temp.End, temp.Start
						if kind == "clear-range-after-missing" {
							temp.Shifts[0].UserID = h.UUID("missing-user")
						}
					}
					valid := kind == "shift-limit-150-valid"
					var want error
					if !valid {
						// The unchanged Store validation is also exercised on exact base
						// by the differential runner. It cannot reach state for these inputs.
						id := uuid.MustParse(h.UUID(parent))
						if op == "set-clear" {
							want = h.App().ScheduleStore.SetClearTemporarySchedule(ctx, nil, id, temp, clearStart, clearEnd)
						} else {
							want = h.App().ScheduleStore.SetTemporarySchedule(ctx, nil, id, temp)
						}
						require.Error(t, want)
					}
					input := graphql2.SetTemporaryScheduleInput{ScheduleID: h.UUID(parent), Start: temp.Start, End: temp.End, Shifts: temp.Shifts}
					if op == "set-clear" {
						input.ClearStart, input.ClearEnd = &clearStart, &clearEnd
					}
					queries.Store(0)
					_, err := app.Mutation().SetTemporarySchedule(ctx, input)
					scheduleDataExplorationRecord(t, map[string]any{"error": scheduleDataOutcome(err), "schedule_queries": queries.Load()})
					if valid {
						require.True(t, permission.IsPermissionError(err))
					} else {
						require.EqualError(t, err, want.Error())
					}
					require.Zero(t, queries.Load())
					require.Empty(t, scheduleDataRaw(t, h, parent))
				})
			}
		}
	}
}

func TestScheduleDataNotificationValidationCombinations(t *testing.T) {
	h := scheduleDataHarness(t)
	app, provider := scheduleDataProviderApp(t, h)
	queries, writes := scheduleDataValidationTrace(t, h, app)
	for _, parent := range []string{"own", "foreign", "missing"} {
		for _, kind := range []string{
			"count-before-weekday", "weekday-before-duplicate", "earlier-duplicate-before-later-weekday",
			"later-negative-id", "later-large-id", "mismatched-id-before-duplicate-id", "duplicate-id-before-later-mismatch",
			"late-destination-before-rule-fields", "late-invalid-destination-before-count", "omitted-with-invalid-supplied-id",
			"omitted-with-supplied-valid", "count-50-mixed-valid", "index-50-baseline-panic",
		} {
			t.Run(parent+"/"+kind, func(t *testing.T) {
				ctx := scheduleDataMissingAuthority(t, h)
				scheduleDataReset(t, h, parent, "")
				_, err := h.App().DB().Exec(`DELETE FROM notification_channels`)
				require.NoError(t, err)
				id := uuid.MustParse(h.UUID(parent))
				all, never, clock := timeutil.EveryDay(), timeutil.WeekdayFilter{}, timeutil.NewClock(12, 0)
				rule := func(i int) graphql2.OnCallNotificationRuleInput {
					return graphql2.OnCallNotificationRuleInput{Dest: gadb.NewDestV1(provider.ID(), "id", fmt.Sprintf("combination-%s-%s-%d", parent, kind, i))}
				}
				rules := []graphql2.OnCallNotificationRuleInput{rule(0), rule(1), rule(2)}
				want := ""
				switch kind {
				case "count-before-weekday", "late-invalid-destination-before-count":
					for len(rules) < 51 {
						rules = append(rules, rule(len(rules)))
					}
					rules[0].WeekdayFilter = &never
					want = "'Rules': must not be over 50"
					if kind == "late-invalid-destination-before-count" {
						rules[50].Dest.Args = nil
						want = "required"
					}
				case "weekday-before-duplicate":
					rules[0].Time, rules[0].WeekdayFilter = &clock, &all
					rules[1] = rules[0]
					rules[1].WeekdayFilter = &never
					want = "At least one day must be enabled"
				case "earlier-duplicate-before-later-weekday":
					rules[1] = rules[0]
					rules[2].WeekdayFilter = &never
					want = "'Rules[1]': On-change rule already exists"
				case "later-negative-id", "later-large-id", "omitted-with-invalid-supplied-id":
					ruleID := -1
					want = "'Rules[2].ID': must not be negative"
					if kind == "later-large-id" {
						ruleID = 51
						want = "'Rules[2].ID': must not be over 50"
					}
					rules[2].ID = scheduleDataRuleID(t, id, ruleID)
					if kind == "omitted-with-invalid-supplied-id" {
						rules[0].ID = scheduleDataRuleID(t, id, 49)
					}
				case "mismatched-id-before-duplicate-id":
					rules[0].ID = scheduleDataRuleID(t, uuid.MustParse(h.UUID("other")), 0)
					rules[1].ID = rules[0].ID
					want = "'Rules[0].ID': wrong schedule ID"
				case "duplicate-id-before-later-mismatch":
					rules[0].ID = scheduleDataRuleID(t, id, 1)
					rules[1].ID = rules[0].ID
					rules[2].ID = scheduleDataRuleID(t, uuid.MustParse(h.UUID("other")), 2)
					want = "'Rules[1].ID': duplicate ID value not allowed"
				case "late-destination-before-rule-fields":
					rules[0].WeekdayFilter = &never
					rules[2].Dest.Type = "unknown"
					want = "unknown destination type"
				case "omitted-with-supplied-valid", "count-50-mixed-valid":
					if kind == "count-50-mixed-valid" {
						for len(rules) < 50 {
							rules = append(rules, rule(len(rules)))
						}
					}
					rules[1].ID = scheduleDataRuleID(t, id, 49)
				case "index-50-baseline-panic":
					rules[1].ID = scheduleDataRuleID(t, id, 50)
				}
				queries.Store(0)
				writes.Store(0)
				var panicked any
				func() {
					defer func() { panicked = recover() }()
					_, err = app.Mutation().SetScheduleOnCallNotificationRules(ctx, graphql2.SetScheduleOnCallNotificationRulesInput{ScheduleID: h.UUID(parent), Rules: rules})
				}()
				outcome := scheduleDataOutcome(err)
				if panicked != nil {
					outcome = fmt.Sprint(panicked)
				}
				var channels int
				require.NoError(t, h.App().DB().QueryRow(`SELECT count(*) FROM notification_channels`).Scan(&channels))
				scheduleDataExplorationRecord(t, map[string]any{"error": outcome, "schedule_queries": queries.Load(), "channel_write_attempts": writes.Load(), "durable_channels": channels})
				if kind == "index-50-baseline-panic" {
					require.Contains(t, outcome, "index out of range [50]")
				} else if want == "" {
					require.True(t, permission.IsPermissionError(err))
				} else {
					require.ErrorContains(t, err, want)
				}
				require.Zero(t, queries.Load())
				require.Zero(t, channels)
				require.Empty(t, scheduleDataRaw(t, h, parent))
			})
		}
	}
}

// Safe global validation must precede authority denial without Schedule access.
// Every notification case also exercises rollback of an existing channel update.
func TestScheduleDataGlobalValidationPrecedence(t *testing.T) {
	h := scheduleDataHarness(t)
	app, provider := scheduleDataProviderApp(t, h)
	wantRuleError := map[string]string{
		"days-without-time":      "invalid value for 'Rules[%d].WeekdayFilter': Weekday filter may only be used with Time.",
		"duplicate-channel":      "invalid value for 'Rules[1]': On-change rule already exists for that channel.",
		"duplicate-channel-time": "invalid value for 'Rules[1]': Rule already exists for that channel and time-of-day.",
		"duplicate-id":           "invalid value for 'Rules[1].ID': duplicate ID value not allowed",
		"large-id":               "invalid value for 'Rules[0].ID': must not be over 50",
		"negative-id":            "invalid value for 'Rules[0].ID': must not be negative",
		"never-days":             "invalid value for 'Rules[%d].WeekdayFilter': At least one day must be enabled when specifying a weekday filter.",
		"rule-limit":             "invalid value for 'Rules': must not be over 50",
		"time-without-days":      "invalid value for 'Rules[%d].WeekdayFilter': Weekday filter is required with Time.",
		"wrong-schedule-id":      "invalid value for 'Rules[0].ID': wrong schedule ID",
	}
	queries, writes := scheduleDataValidationTrace(t, h, app)
	ctx := scheduleDataMissingAuthority(t, h)
	for _, parent := range []string{"own", "foreign", "missing"} {
		for _, op := range []string{"set", "set-clear"} {
			for _, kind := range []string{"missing-user", "missing-user-before-later-bad-uuid"} {
				t.Run(parent+"/"+op+"/"+kind, func(t *testing.T) {
					temp := scheduleDataTemp(h)
					temp.Shifts[0].UserID = h.UUID("nonexistent-user")
					if kind == "missing-user-before-later-bad-uuid" {
						later := temp.Shifts[0]
						later.UserID = "not-a-uuid"
						temp.Shifts = append(temp.Shifts, later)
					}
					err := scheduleDataGraphQL(ctx, app, h.UUID(parent), temp, op)
					require.Error(t, err)
					require.Zero(t, queries.Load())
					require.Empty(t, scheduleDataRaw(t, h, parent))
					scheduleDataGlobalRecord(t, map[string]any{"error": err.Error(), "schedule_queries": queries.Load()})
					require.EqualError(t, err, "invalid value for 'Shifts[0].UserID': user does not exist")
				})
			}
		}
		for _, kind := range []string{"rule-limit", "never-days", "days-without-time", "time-without-days", "duplicate-channel", "duplicate-channel-time", "negative-id", "large-id", "wrong-schedule-id", "duplicate-id"} {
			t.Run(parent+"/rules/"+kind, func(t *testing.T) {
				all, never, clock := timeutil.EveryDay(), timeutil.WeekdayFilter{}, timeutil.NewClock(12, 0)
				rule := func(i int) graphql2.OnCallNotificationRuleInput {
					return graphql2.OnCallNotificationRuleInput{Dest: gadb.NewDestV1(provider.ID(), "id", fmt.Sprintf("global-precedence-%s-%s-%d", parent, kind, i))}
				}
				rules := []graphql2.OnCallNotificationRuleInput{rule(0)}
				id := uuid.MustParse(h.UUID(parent))
				switch kind {
				case "rule-limit":
					for i := 1; i < 51; i++ {
						rules = append(rules, rule(i))
					}
				case "never-days":
					rules[0].WeekdayFilter = &never
				case "days-without-time":
					rules[0].WeekdayFilter = &all
				case "time-without-days":
					rules[0].Time = &clock
				case "duplicate-channel":
					rules = append(rules, rules[0])
				case "duplicate-channel-time":
					rules[0].Time = &clock
					rules[0].WeekdayFilter = &all
					rules = append(rules, rules[0])
				case "negative-id":
					rules[0].ID = scheduleDataRuleID(t, id, -1)
				case "large-id":
					rules[0].ID = scheduleDataRuleID(t, id, 51)
				case "wrong-schedule-id":
					rules[0].ID = scheduleDataRuleID(t, uuid.MustParse(h.UUID("other")), 0)
				case "duplicate-id":
					rules = append(rules, rule(1))
					rules[0].ID = scheduleDataRuleID(t, id, 0)
					rules[1].ID = rules[0].ID
				}
				_, err := h.App().DB().Exec(`DELETE FROM notification_channels`)
				require.NoError(t, err)
				seedID := uuid.New()
				_, err = h.App().DB().Exec(`INSERT INTO notification_channels(id,dest,name) VALUES($1,$2,'original name')`, seedID, gadb.NullDestV1{Valid: true, DestV1: rules[0].Dest})
				require.NoError(t, err)
				before := writes.Load()
				_, err = app.Mutation().SetScheduleOnCallNotificationRules(ctx, graphql2.SetScheduleOnCallNotificationRulesInput{ScheduleID: h.UUID(parent), Rules: rules})
				require.Error(t, err)
				require.Zero(t, queries.Load())
				require.Empty(t, scheduleDataRaw(t, h, parent))
				var n int
				require.NoError(t, h.App().DB().QueryRow(`SELECT count(*) FROM notification_channels`).Scan(&n))
				require.Equal(t, 1, n, "new destination inserts must roll back")
				var name string
				require.NoError(t, h.App().DB().QueryRow(`SELECT name FROM notification_channels WHERE id=$1`, seedID).Scan(&name))
				require.Equal(t, "original name", name, "destination update must roll back")
				require.EqualError(t, err, wantRuleError[kind])
				require.EqualValues(t, len(rules), writes.Load()-before)
				scheduleDataGlobalRecord(t, map[string]any{"error": err.Error(), "schedule_queries": queries.Load(), "channel_write_attempts": writes.Load() - before, "durable_channels": n})
			})
		}
	}
}
