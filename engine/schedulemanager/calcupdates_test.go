package schedulemanager

import (
	"encoding/json"
	"testing"
	"time"

	mapset "github.com/deckarep/golang-set/v2"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/gadb"
	"github.com/target/goalert/schedule"
	"github.com/target/goalert/util/timeutil"
)

func TestUpdateInfo_calcUpdates_NotifyOnChange(t *testing.T) {
	channelID1 := uuid.MustParse("123e4567-e89b-12d3-a456-426614174000")
	channelID2 := uuid.MustParse("123e4567-e89b-12d3-a456-426614174001")
	var sData schedule.Data
	sData.V1.OnCallNotificationRules = []schedule.OnCallNotificationRule{
		{ChannelID: channelID1}, {ChannelID: channelID2},
	}
	data, err := json.Marshal(sData)
	require.NoError(t, err)
	info := updateInfo{
		ScheduleID:      uuid.New(),
		TimeZone:        time.UTC,
		RawScheduleData: data,
		ScheduleData:    sData,
		CurrentOnCall:   mapset.NewThreadUnsafeSet(uuid.New()), // no rules, so no longer on-call
		Rules:           []gadb.SchedMgrRulesRow{},
		ActiveOverrides: []gadb.SchedMgrOverridesRow{},
	}

	result, err := info.calcUpdates(time.Now())
	require.NoError(t, err)
	require.ElementsMatch(t, []uuid.UUID{channelID1, channelID2}, result.NotificationChannels.ToSlice())
}

func TestUpdateInfo_calcUpdates_NotifyAtTime(t *testing.T) {
	channelID := uuid.MustParse("123e4567-e89b-12d3-a456-426614174000")
	var sData schedule.Data
	everyDay := timeutil.EveryDay()
	at9am := timeutil.NewClock(9, 0)
	nextRun := time.Date(2023, 10, 1, 9, 0, 0, 0, time.UTC)
	sData.V1.OnCallNotificationRules = []schedule.OnCallNotificationRule{
		{
			ChannelID:        channelID,
			NextNotification: &nextRun,
			WeekdayFilter:    &everyDay,
			Time:             &at9am,
		},
	}
	data, err := json.Marshal(sData)
	require.NoError(t, err)
	info := updateInfo{
		ScheduleID:      uuid.New(),
		TimeZone:        time.UTC,
		RawScheduleData: data,
		ScheduleData:    sData,
		CurrentOnCall:   mapset.NewThreadUnsafeSet[uuid.UUID](),
		Rules:           []gadb.SchedMgrRulesRow{},
		ActiveOverrides: []gadb.SchedMgrOverridesRow{},
	}

	result, err := info.calcUpdates(nextRun.Add(-1 * time.Hour))
	require.NoError(t, err)
	require.Empty(t, result.NotificationChannels.ToSlice()) // 8 am, no notification yet

	require.Empty(t, result.NewRawScheduleData) // no update necessary

	result, err = info.calcUpdates(nextRun)
	require.NoError(t, err)
	require.Equal(t, []uuid.UUID{channelID}, result.NotificationChannels.ToSlice())

	var expected schedule.Data
	expectedNext := nextRun.AddDate(0, 0, 1)
	expected.V1.OnCallNotificationRules = []schedule.OnCallNotificationRule{
		{
			ChannelID:        channelID,
			NextNotification: &expectedNext,
			WeekdayFilter:    &everyDay,
			Time:             &at9am,
		},
	}
	expectedData, err := json.Marshal(expected)
	require.NoError(t, err)
	require.JSONEq(t, string(expectedData), string(result.NewRawScheduleData))
}

func TestUpdateInfo_calcUpdates_TempSchedMissingUser(t *testing.T) {
	channelID := uuid.MustParse("123e4567-e89b-12d3-a456-426614174000")
	validUser := uuid.MustParse("223e4567-e89b-12d3-a456-426614174000")
	deletedUser := uuid.MustParse("323e4567-e89b-12d3-a456-426614174000")
	now := time.Date(2023, 10, 1, 9, 0, 0, 0, time.UTC)

	var sData schedule.Data
	sData.V1.OnCallNotificationRules = []schedule.OnCallNotificationRule{{ChannelID: channelID}}
	sData.V1.TemporarySchedules = []schedule.TemporarySchedule{{
		Start: now.Add(-time.Hour),
		End:   now.Add(time.Hour),
		Shifts: []schedule.FixedShift{
			{Start: now.Add(-time.Hour), End: now.Add(time.Hour), UserID: validUser.String()},
			{Start: now.Add(-time.Hour), End: now.Add(time.Hour), UserID: deletedUser.String()},
		},
	}}
	data, err := json.Marshal(sData)
	require.NoError(t, err)

	info := updateInfo{
		ScheduleID:      uuid.New(),
		TimeZone:        time.UTC,
		RawScheduleData: data,
		ScheduleData:    sData,
		// the deleted user can never be recorded as on-call, so only the valid user is
		CurrentOnCall: mapset.NewThreadUnsafeSet(validUser),
		MissingUsers:  mapset.NewThreadUnsafeSet(deletedUser),
	}

	result, err := info.calcUpdates(now)
	require.NoError(t, err)
	require.Empty(t, result.UsersToStart.ToSlice(), "deleted user should not be started")
	require.Empty(t, result.UsersToStop.ToSlice())
	require.Empty(t, result.NotificationChannels.ToSlice(), "should not notify when on-call is unchanged")

	// without MissingUsers, the deleted user is always "new", which triggers a notification every cycle
	info.MissingUsers = nil
	result, err = info.calcUpdates(now)
	require.NoError(t, err)
	require.Equal(t, []uuid.UUID{deletedUser}, result.UsersToStart.ToSlice())
	require.Equal(t, []uuid.UUID{channelID}, result.NotificationChannels.ToSlice())
}

func TestUpdateInfo_calcUpdates_TempSchedValidUsers(t *testing.T) {
	channelID := uuid.New()
	validUser1, validUser2, deletedUser, ruleUser := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	now := time.Date(2023, 10, 1, 9, 0, 0, 0, time.UTC)

	var sData schedule.Data
	sData.V1.OnCallNotificationRules = []schedule.OnCallNotificationRule{{ChannelID: channelID}}
	sData.V1.TemporarySchedules = []schedule.TemporarySchedule{{
		Start: now.Add(-time.Hour),
		End:   now.Add(time.Hour),
		Shifts: []schedule.FixedShift{
			{Start: now.Add(-time.Hour), End: now.Add(time.Hour), UserID: validUser1.String()},
			{Start: now.Add(-time.Hour), End: now.Add(time.Hour), UserID: validUser2.String()},
			{Start: now.Add(-time.Hour), End: now.Add(time.Hour), UserID: deletedUser.String()},
		},
	}}
	data, err := json.Marshal(sData)
	require.NoError(t, err)
	info := updateInfo{
		ScheduleID:      uuid.New(),
		TimeZone:        time.UTC,
		RawScheduleData: data,
		ScheduleData:    sData,
		CurrentOnCall:   mapset.NewThreadUnsafeSet(ruleUser),
		MissingUsers:    mapset.NewThreadUnsafeSet(deletedUser),
		Rules: []gadb.SchedMgrRulesRow{{
			ResolvedUserID: ruleUser,
			Sunday:         true,
		}},
	}

	// Active temporary schedules take precedence and preserve every valid user.
	result, err := info.calcUpdates(now)
	require.NoError(t, err)
	require.ElementsMatch(t, []uuid.UUID{validUser1, validUser2}, result.UsersToStart.ToSlice())
	require.Equal(t, []uuid.UUID{ruleUser}, result.UsersToStop.ToSlice())
	require.Equal(t, []uuid.UUID{channelID}, result.NotificationChannels.ToSlice())

	info.CurrentOnCall = mapset.NewThreadUnsafeSet(validUser1, validUser2)
	for cycle := range 3 {
		result, err = info.calcUpdates(now.Add(time.Duration(cycle) * time.Minute))
		require.NoError(t, err)
		require.Empty(t, result.UsersToStart.ToSlice())
		require.Empty(t, result.UsersToStop.ToSlice())
		require.Empty(t, result.NotificationChannels.ToSlice())
		require.Nil(t, result.NewRawScheduleData, "missing users must not cause stored JSON cleanup")
	}

	// Once the temporary schedule ends, the ordinary rule resumes and the real change notifies.
	result, err = info.calcUpdates(now.Add(2 * time.Hour))
	require.NoError(t, err)
	require.Equal(t, []uuid.UUID{ruleUser}, result.UsersToStart.ToSlice())
	require.ElementsMatch(t, []uuid.UUID{validUser1, validUser2}, result.UsersToStop.ToSlice())
	require.Equal(t, []uuid.UUID{channelID}, result.NotificationChannels.ToSlice())
	info.MissingUsers = nil
	control, err := info.calcUpdates(now.Add(2 * time.Hour))
	require.NoError(t, err)
	require.True(t, result.UsersToStart.Equal(control.UsersToStart))
	require.True(t, result.UsersToStop.Equal(control.UsersToStop))
	require.True(t, result.NotificationChannels.Equal(control.NotificationChannels))
}
