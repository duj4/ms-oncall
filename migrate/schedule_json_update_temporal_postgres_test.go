package migrate

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/target/goalert/permission"
	"github.com/target/goalert/schedule"
)

func TestPostgresScheduleJSONUpdateTemporalSemantics(t *testing.T) {
	base, _, db := boundedAuditDB(t, len(Names()))
	ctx := permission.SystemContext(base, "ScheduleJSONContractTest")
	f, g := newUserPhaseAFixture(t, ctx, db), newUserPhaseAFixture(t, ctx, db)
	enforcementExec(t, ctx, db, `UPDATE user_organization_assignments SET effective_organization_id=$2,effective_normal_organization_id=$2 WHERE user_id=$1`, g.user, f.org)
	app := updateNativeApp(t, ctx, db)
	app.ScheduleStore = f.schedules
	app.UserStore = f.users
	for _, kind := range []string{"split", "trim", "half_open_noop", "adjacent_merge", "user_replace", "overlap_replace", "same_user_disjoint", "equivalent_reorder"} {
		t.Run(kind, func(t *testing.T) {
			id := f.newSchedule(t, ctx)
			temp := userPhaseATemp(f.user)
			temp.End = temp.Start.Add(4 * time.Hour)
			temp.Shifts[0].End = temp.End
			if kind == "same_user_disjoint" {
				temp.Shifts[0].End = temp.Start.Add(time.Hour)
				temp.Shifts = append(temp.Shifts, schedule.FixedShift{Start: temp.End.Add(-time.Hour), End: temp.End, UserID: f.user.String()})
			}
			require.NoError(t, f.schedules.SetTemporaryScheduleScoped(ctx, nil, id, temp, &f.org))
			clear := kind == "split" || kind == "trim" || kind == "half_open_noop"
			var input map[string]any
			if clear {
				start, end := temp.Start.Add(time.Hour), temp.End.Add(-time.Hour)
				if kind == "trim" {
					start = temp.Start
				}
				if kind == "half_open_noop" {
					start = temp.End
					end = temp.End.Add(time.Hour)
				}
				input = map[string]any{"scheduleID": id.String(), "start": start, "end": end}
			} else {
				next := temp
				next.Shifts = append([]schedule.FixedShift{}, temp.Shifts...)
				switch kind {
				case "adjacent_merge":
					next.Start = temp.End
					next.End = temp.End.Add(time.Hour)
					next.Shifts = []schedule.FixedShift{{Start: next.Start, End: next.End, UserID: f.user.String()}}
				case "user_replace":
					next.Shifts[0].UserID = g.user.String()
				case "overlap_replace":
					next.Start = temp.Start.Add(time.Hour)
					next.End = temp.End.Add(time.Hour)
					next.Shifts = []schedule.FixedShift{{Start: next.Start, End: next.End, UserID: g.user.String()}}
				case "same_user_disjoint":
					next.Shifts = []schedule.FixedShift{{Start: temp.Start, End: temp.End, UserID: f.user.String()}}
				case "equivalent_reorder":
					next.Shifts = append(next.Shifts, next.Shifts[0])
				}
				input = scheduleJSONSetWire(id, next)
			}
			p, errs := scheduleJSONHTTP(t, ctx, app, input, clear, false)
			require.Empty(t, errs)
			destructive := kind == "split" || kind == "trim" || kind == "user_replace" || kind == "overlap_replace"
			require.Equal(t, destructive, p.RequiresConfirmation)
			if destructive {
				input["confirmation"] = scheduleJSONConfirm(p)
			}
			_, errs = scheduleJSONHTTP(t, ctx, app, input, clear, true)
			require.Empty(t, errs)
			tx := userPhaseATx(t, ctx, db)
			_, after, err := f.schedules.ReadTemporaryUpdate(ctx, tx, id, false)
			require.NoError(t, err)
			require.NoError(t, tx.Rollback())
			if kind == "split" {
				require.Len(t, after, 2)
				require.Equal(t, temp.Start.Add(time.Hour), after[0].End)
				require.Equal(t, temp.End.Add(-time.Hour), after[1].Start)
			}
			if kind == "adjacent_merge" {
				require.Len(t, after, 1)
				require.Len(t, after[0].Shifts, 1)
			}
			if kind == "half_open_noop" || kind == "equivalent_reorder" {
				require.Zero(t, enforcementCount(t, ctx, db, `SELECT count(*) FROM schedule_json_update_audit_events WHERE schedule_id=$1`, id))
			}
		})
	}
	// Real offset timestamps across DST are UTC intervals; no local-clock
	// subtraction is used by the semantic diff or the existing writer.
	t.Run("offset_DST_and_validation", func(t *testing.T) {
		id := f.newSchedule(t, ctx)
		start, err := time.Parse(time.RFC3339, "2027-03-14T01:30:00-05:00")
		require.NoError(t, err)
		end, err := time.Parse(time.RFC3339, "2027-03-14T03:30:00-04:00")
		require.NoError(t, err)
		temp := schedule.TemporarySchedule{Start: start, End: end, Shifts: []schedule.FixedShift{{Start: start, End: end, UserID: f.user.String()}}}
		_, errs := scheduleJSONHTTP(t, ctx, app, scheduleJSONSetWire(id, temp), false, true)
		require.Empty(t, errs)
		before := scheduleJSONInventory(t, ctx, db, id)
		foreign := newUserPhaseAFixture(t, ctx, db)
		bad := temp
		bad.Shifts = []schedule.FixedShift{{Start: start, End: end, UserID: foreign.user.String()}}
		_, errs = scheduleJSONHTTP(t, ctx, app, scheduleJSONSetWire(id, bad), false, true)
		require.NotEmpty(t, errs)
		invalid := scheduleJSONSetWire(id, temp)
		invalid["end"] = start
		_, errs = scheduleJSONHTTP(t, ctx, app, invalid, false, true)
		require.NotEmpty(t, errs)
		invalid = scheduleJSONSetWire(id, temp)
		invalid["shifts"] = nil
		_, errs = scheduleJSONHTTP(t, ctx, app, invalid, false, true)
		require.NotEmpty(t, errs)
		require.Equal(t, before, scheduleJSONInventory(t, ctx, db, id))
	})
}
