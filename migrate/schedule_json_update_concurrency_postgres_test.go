package migrate

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/target/goalert/assignment"
	ds "github.com/target/goalert/deletionsafety"
	"github.com/target/goalert/graphql2"
	"github.com/target/goalert/permission"
	"github.com/target/goalert/schedule"
)

func TestPostgresScheduleJSONUpdateConcurrency(t *testing.T) {
	base, uri, db := boundedAuditDB(t, len(Names()))
	db.SetMaxOpenConns(12)
	ctx := permission.SystemContext(base, "ScheduleJSONContractTest")
	f := newUserPhaseAFixture(t, ctx, db)
	app := updateNativeApp(t, ctx, db)
	app.ScheduleStore = f.schedules
	app.UserStore = f.users
	for _, kind := range []string{"two_writers", "user_delete", "schedule_delete", "assignment_writer", "cleanup_envelope"} {
		t.Run(kind, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(ctx, 12*time.Second)
			defer cancel()
			id := f.newSchedule(t, ctx)
			temp := userPhaseATemp(f.user)
			require.NoError(t, f.schedules.SetTemporaryScheduleScoped(ctx, nil, id, temp, &f.org))
			input := graphql2.ClearTemporarySchedulesInput{ScheduleID: id.String(), Start: temp.Start, End: temp.End}
			p, err := app.Query().PreviewClearTemporarySchedules(ctx, input)
			require.NoError(t, err)
			input.Confirmation = updateNativeConfirmation(p)
			before := scheduleJSONInventory(t, ctx, db, id)

			var rootConfirmation *graphql2.DeletionSafetyConfirmationInput
			if kind == "schedule_delete" {
				rootConfirmation = enforcementPreview(t, ctx, app, graphql2.DeletionResourceInput{Type: graphql2.DeletionTargetTypeSchedule, ID: id.String()})
			}
			// All JSON, User, assignment and Organization locks exist at this real
			// database query boundary, immediately before actual SchedUpdateData.
			traced, barrier := jsonWriterTraced(t, uri, "-- name: SchedUpdateData")
			store, err := schedule.NewStore(ctx, traced, f.users)
			require.NoError(t, err)
			copyApp := *app
			copyApp.DB = traced
			copyApp.ScheduleStore = store
			done := make(chan error, 1)
			go func() { _, err := copyApp.Mutation().ClearTemporarySchedules(ctx, input); done <- err }()
			jsonWriterWait(t, ctx, barrier, done)
			scheduleJSONNoPartial(t, ctx, db, id, before)
			switch kind {
			case "two_writers":
				_, err := app.Mutation().ClearTemporarySchedules(ctx, input)
				require.Error(t, err)
			case "assignment_writer":
				tx := userPhaseATx(t, ctx, db)
				_, err := tx.ExecContext(ctx, `UPDATE user_organization_assignments SET organization_role=organization_role WHERE user_id=$1`, f.user)
				jsonWriterCode(t, err, "55P03")
				require.NoError(t, tx.Rollback())
			case "cleanup_envelope":
				tx := userPhaseATx(t, ctx, db)
				var envelope int64
				err := tx.QueryRowContext(ctx, `SELECT id FROM schedule_data WHERE schedule_id=$1 FOR UPDATE NOWAIT`, id).Scan(&envelope)
				jsonWriterCode(t, err, "55P03")
				require.NoError(t, tx.Rollback())
			case "user_delete":
				probe := userPhaseATx(t, ctx, db)
				_, writerErr := probe.ExecContext(ctx, `UPDATE users SET name=name WHERE id=$1`, f.user)
				jsonWriterCode(t, writerErr, "55P03")
				require.NoError(t, probe.Rollback())
				_, err := app.Mutation().DeleteAll(ctx, []assignment.RawTarget{{Type: assignment.TargetTypeUser, ID: f.user.String()}}, nil)
				require.Error(t, err)
			case "schedule_delete":
				_, err := app.Mutation().DeleteAll(ctx, []assignment.RawTarget{{Type: assignment.TargetTypeSchedule, ID: id.String()}}, rootConfirmation)
				require.Error(t, err)
			}
			close(barrier.resume)
			require.NoError(t, <-done)
			_, err = app.Mutation().ClearTemporarySchedules(ctx, input)
			enforceCode(t, err, ds.DeletionDependencyChanged)
			require.Equal(t, 1, enforcementCount(t, ctx, db, `SELECT count(*) FROM schedule_json_update_audit_events WHERE schedule_id=$1`, id))
		})
	}
}

func TestPostgresScheduleJSONUpdateLockThenFreshRead(t *testing.T) {
	base, uri, db := boundedAuditDB(t, len(Names()))
	ctx := permission.SystemContext(base, "ScheduleJSONContractTest")
	f := newUserPhaseAFixture(t, ctx, db)
	app := updateNativeApp(t, ctx, db)
	app.ScheduleStore = f.schedules
	app.UserStore = f.users
	id := f.newSchedule(t, ctx)
	temp := userPhaseATemp(f.user)
	require.NoError(t, f.schedules.SetTemporaryScheduleScoped(ctx, nil, id, temp, &f.org))
	input := graphql2.ClearTemporarySchedulesInput{ScheduleID: id.String(), Start: temp.Start, End: temp.End}
	p, err := app.Query().PreviewClearTemporarySchedules(ctx, input)
	require.NoError(t, err)
	input.Confirmation = updateNativeConfirmation(p)
	traced, barrier := jsonWriterTraced(t, uri, "SELECT id,data FROM schedule_data")
	store, err := schedule.NewStore(ctx, traced, f.users)
	require.NoError(t, err)
	copyApp := *app
	copyApp.DB = traced
	copyApp.ScheduleStore = store
	done := make(chan error, 1)
	go func() { _, err := copyApp.Mutation().ClearTemporarySchedules(ctx, input); done <- err }()
	jsonWriterWait(t, ctx, barrier, done)
	// A real writer commits new coverage before the guarded locking read starts.
	next := temp
	next.Start = next.End
	next.End = next.End.Add(time.Hour)
	next.Shifts = nil
	require.NoError(t, f.schedules.SetTemporaryScheduleScoped(ctx, nil, id, next, &f.org))
	before := scheduleJSONInventory(t, ctx, db, id)
	close(barrier.resume)
	enforceCode(t, <-done, ds.DeletionDependencyChanged)
	scheduleJSONNoPartial(t, ctx, db, id, before)
}
