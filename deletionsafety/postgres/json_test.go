package postgres

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	ds "github.com/target/goalert/deletionsafety"
)

const testUser = "11111111-1111-4111-8111-111111111111"
const testSchedule = "22222222-2222-4222-8222-222222222222"

var observed = time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)

func v1JSON(start, end, shiftStart, shiftEnd time.Time, user string) string {
	return fmt.Sprintf(`{"TemporarySchedules":[{"Start":%q,"End":%q,"Shifts":[{"Start":%q,"End":%q,"UserID":%q}]}],"OnCallNotificationRules":[]}`,
		start.Format(time.RFC3339Nano), end.Format(time.RFC3339Nano), shiftStart.Format(time.RFC3339Nano), shiftEnd.Format(time.RFC3339Nano), user)
}

func TestRawTemporarySchedulePeriodsAndIntersection(t *testing.T) {
	for _, tc := range []struct {
		name                             string
		start, end, shiftStart, shiftEnd time.Duration
		want                             ds.PeriodState
		effectiveStart, effectiveEnd     time.Duration
	}{
		{"active", -2 * time.Hour, 2 * time.Hour, -time.Hour, time.Hour, ds.PeriodActive, -time.Hour, time.Hour},
		{"future", time.Hour, 4 * time.Hour, 2 * time.Hour, 3 * time.Hour, ds.PeriodFuture, 2 * time.Hour, 3 * time.Hour},
		{"ended", -4 * time.Hour, -time.Hour, -3 * time.Hour, -2 * time.Hour, ds.PeriodEnded, -3 * time.Hour, -2 * time.Hour},
		{"partial", -time.Hour, time.Hour, -3 * time.Hour, 3 * time.Hour, ds.PeriodActive, -time.Hour, time.Hour},
		{"start-inclusive", 0, time.Hour, 0, time.Hour, ds.PeriodActive, 0, time.Hour},
		{"end-exclusive", -time.Hour, 0, -time.Hour, 0, ds.PeriodEnded, -time.Hour, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := v1JSON(observed.Add(tc.start), observed.Add(tc.end), observed.Add(tc.shiftStart), observed.Add(tc.shiftEnd), testUser)
			deps, n, err := projectV1(123, testSchedule, []byte(raw), observed, 10)
			require.NoError(t, err)
			require.Equal(t, 2, n)
			require.Len(t, deps, 4)
			d := deps[3]
			require.Equal(t, ds.RelationshipShiftUser, d.Relationship)
			require.Equal(t, tc.want, d.State.Period)
			require.Equal(t, observed.Add(tc.effectiveStart), d.Before.WindowStart)
			require.Equal(t, observed.Add(tc.effectiveEnd), d.Before.WindowEnd)
			require.Equal(t, "schedule-data:123:temporary:0:shift:0", d.Referencing.ID)
			require.Equal(t, "schedule-data:123:temporary:0", d.Parent.ID)
			for _, d := range deps {
				_, err := ds.Evaluate(ds.EvaluationInput{Dependency: d})
				require.NoError(t, err)
			}
		})
	}
}

func TestRawTemporaryScheduleMalformedAndUnknown(t *testing.T) {
	base := v1JSON(observed.Add(-time.Hour), observed.Add(time.Hour), observed.Add(-time.Hour), observed.Add(time.Hour), testUser)
	for name, raw := range map[string]string{
		"empty": "", "null": "null", "array": "[]", "empty-object": "{}",
		"temporary-object": `{"TemporarySchedules":{}}`,
		"temporary-scalar": `{"TemporarySchedules":[1]}`, "shift-null": strings.Replace(base, `"Shifts":[{`, `"Shifts":null,"Unused":[{`, 1),
		"missing-user":    strings.Replace(base, `"UserID":"`+testUser+`"`, `"UserID":null`, 1),
		"absent-user":     strings.Replace(base, `,"UserID":"`+testUser+`"`, "", 1),
		"invalid-user":    strings.Replace(base, testUser, "invalid-uuid", 1),
		"zero-user":       strings.Replace(base, testUser, "00000000-0000-0000-0000-000000000000", 1),
		"invalid-time":    strings.Replace(base, observed.Add(-time.Hour).Format(time.RFC3339Nano), "invalid-time", 1),
		"missing-time":    strings.Replace(base, `"Start":`, `"Other":`, 1),
		"unknown-version": `{"V2":{},"TemporarySchedules":[]}`, "oncall-object": `{"TemporarySchedules":[],"OnCallNotificationRules":{}}`,
	} {
		t.Run(name, func(t *testing.T) {
			deps, n, err := projectV1(12, testSchedule, []byte(raw), observed, 20)
			require.Error(t, err)
			require.Nil(t, deps)
			require.Zero(t, n)
		})
	}
	// A syntactically valid UUID is retained without consulting a user getter.
	deps, _, err := projectV1(12, testSchedule, []byte(base), observed, 20)
	require.NoError(t, err)
	require.Equal(t, testUser, deps[3].Target.ID)
	_, _, err = projectV1(12, testSchedule, []byte(v1JSON(observed, observed.Add(time.Hour), observed.Add(2*time.Hour), observed.Add(3*time.Hour), testUser)), observed, 20)
	require.ErrorIs(t, err, errUnsupported, "empty effective interval cannot be assigned a fictitious V1 period")
}

func TestRawTemporaryScheduleOrdinalsAndBudget(t *testing.T) {
	base := v1JSON(observed.Add(-time.Hour), observed.Add(time.Hour), observed.Add(-time.Hour), observed.Add(time.Hour), testUser)
	var data map[string]json.RawMessage
	require.NoError(t, json.Unmarshal([]byte(base), &data))
	var temporaries []map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(data["TemporarySchedules"], &temporaries))
	var shifts []json.RawMessage
	require.NoError(t, json.Unmarshal(temporaries[0]["Shifts"], &shifts))
	shifts = append(shifts, shifts[0])
	temporaries[0]["Shifts"], _ = json.Marshal(shifts)
	temporaries = append(temporaries, temporaries[0])
	data["TemporarySchedules"], _ = json.Marshal(temporaries)
	raw, err := json.Marshal(data)
	require.NoError(t, err)
	deps, n, err := projectV1(99, testSchedule, raw, observed, 6)
	require.NoError(t, err)
	require.Equal(t, 6, n)
	require.Len(t, deps, 14)
	seen := map[string]bool{}
	for _, d := range deps {
		if d.Relationship == ds.RelationshipShiftUser {
			seen[d.Referencing.ID] = true
		}
	}
	require.Len(t, seen, 4)
	require.True(t, seen["schedule-data:99:temporary:1:shift:1"])
	_, _, err = projectV1(99, testSchedule, raw, observed, 5)
	var typed *ds.DeletionSafetyError
	require.ErrorAs(t, err, &typed)
	require.Equal(t, ds.DeletionPreviewLimitExceeded, typed.Code)
	deps, n, err = projectV1(99, testSchedule, []byte(`{"TemporarySchedules":[],"OnCallNotificationRules":[]}`), observed, 1)
	require.NoError(t, err)
	require.Empty(t, deps)
	require.Zero(t, n)
}

func TestLargeRawFragmentsAreBounded(t *testing.T) {
	var shifts []string
	for range 1001 {
		shifts = append(shifts, fmt.Sprintf(`{"Start":%q,"End":%q,"UserID":%q}`, observed.Format(time.RFC3339), observed.Add(time.Hour).Format(time.RFC3339), testUser))
	}
	raw := fmt.Sprintf(`{"TemporarySchedules":[{"Start":%q,"End":%q,"Shifts":[%s]}]}`, observed.Format(time.RFC3339), observed.Add(time.Hour).Format(time.RFC3339), strings.Join(shifts, ","))
	deps, n, err := projectV1(1, testSchedule, []byte(raw), observed, 1002)
	require.NoError(t, err)
	require.Equal(t, 1002, n)
	require.Len(t, deps, 3004)
	_, _, err = projectV1(1, testSchedule, []byte(raw), observed, 1001)
	var typed *ds.DeletionSafetyError
	require.True(t, errors.As(err, &typed))
	require.Equal(t, ds.DeletionPreviewLimitExceeded, typed.Code)
}

func TestRawScheduleKnownNilSlices(t *testing.T) {
	for _, raw := range []string{
		`{"TemporarySchedules":null}`,
		`{"TemporarySchedules":null,"OnCallNotificationRules":null}`,
		`{"TemporarySchedules":[],"OnCallNotificationRules":null}`,
		`{"TemporarySchedules":[],"OnCallNotificationRules":[]}`,
	} {
		deps, n, err := projectV1(1, testSchedule, []byte(raw), observed, 10)
		require.NoError(t, err)
		require.Empty(t, deps)
		require.Zero(t, n)
	}
	for _, value := range []string{`{}`, `"bad"`, `1`, `true`, `[null]`} {
		_, _, err := projectV1(1, testSchedule, []byte(`{"TemporarySchedules":`+value+`}`), observed, 10)
		require.Error(t, err)
	}
}
