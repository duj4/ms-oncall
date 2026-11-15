package migrate

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	ds "github.com/target/goalert/deletionsafety"
	collector "github.com/target/goalert/deletionsafety/postgres"
	"github.com/target/goalert/permission"
)

func TestPostgresDeletionCollectorsTemporalFragments(t *testing.T) {
	ctx, _, db := boundedAuditDB(t, len(Names()))
	f := newDeletionFixture(t, ctx, db)
	ctx = permission.SystemContext(ctx, "DeletionCollectorsTest")
	for _, tc := range []struct {
		name                        string
		start, end                  time.Duration
		period                      ds.PeriodState
		overridePolicy, shiftPolicy ds.DeletionPolicy
	}{
		{"active", -time.Hour, time.Hour, ds.PeriodActive, ds.PolicyBlock, ds.PolicyBlock},
		{"future", time.Hour, 2 * time.Hour, ds.PeriodFuture, ds.PolicyBlock, ds.PolicyBlock},
		{"ended", -2 * time.Hour, -time.Hour, ds.PeriodEnded, ds.PolicyCascade, ds.PolicyInformational},
	} {
		t.Run(tc.name, func(t *testing.T) {
			start, end := f.now.Add(tc.start), f.now.Add(tc.end)
			_, err := db.ExecContext(ctx, `UPDATE user_overrides SET start_time=$1,end_time=$2 WHERE id=$3`, start, end, f.override)
			require.NoError(t, err)
			setDeletionJSON(t, ctx, db, f, f.user.String(), start, end)
			for _, user := range []string{f.user.String(), f.actor.String()} {
				root := ds.Resource{Kind: ds.ResourceUser, ID: user}
				result, err := collectDeletion(t, ctx, db, root, collector.Limits{})
				require.NoError(t, err)
				plan := deletionPlan(t, root, result)
				var overrides, shifts int
				for _, impact := range plan.Impacts() {
					if impact.IsDerived {
						continue
					}
					switch impact.Relationship {
					case ds.RelationshipOverrideAddUser, ds.RelationshipOverrideRemoveUser:
						if impact.Target != root {
							require.Equal(t, ds.PolicyInformational, impact.Policy)
							require.Equal(t, ds.ChangePreserved, impact.Change)
							continue
						}
						overrides++
						require.Equal(t, tc.period, impact.State.Period)
						require.Equal(t, tc.overridePolicy, impact.Policy)
					case ds.RelationshipShiftUser:
						shifts++
						require.Equal(t, tc.period, impact.State.Period)
						require.Equal(t, tc.shiftPolicy, impact.Policy)
					}
				}
				require.Positive(t, overrides)
				if user == f.user.String() {
					require.Positive(t, shifts)
				}
				for _, change := range plan.Changes() {
					require.NotContains(t, []ds.ResourceKind{ds.ResourceSchedule, ds.ResourceRotation, ds.ResourceFixedShift}, change.Resource.Kind)
				}
			}
		})
	}
	// SQL WITH ORDINALITY preserves stored order; both ordinals in public
	// fragment identities are zero-based, including repeated User references.
	shift := map[string]any{"Start": f.now.Add(-2 * time.Hour), "End": f.now.Add(2 * time.Hour), "UserID": f.user.String()}
	temporary := map[string]any{"Start": f.now.Add(-time.Hour), "End": f.now.Add(time.Hour), "Shifts": []any{shift, shift}}
	raw, err := json.Marshal(map[string]any{"V1": map[string]any{"TemporarySchedules": []any{temporary, temporary}, "OnCallNotificationRules": []any{map[string]any{"ID": f.schedule.String() + ":0", "ChannelID": f.channel.String(), "Time": "12:30", "WeekdayFilter": "1111111"}}}})
	require.NoError(t, err)
	_, err = db.ExecContext(ctx, `UPDATE schedule_data SET data=$1::jsonb WHERE schedule_id=$2`, string(raw), f.schedule)
	require.NoError(t, err)
	root := ds.Resource{Kind: ds.ResourceUser, ID: f.user.String()}
	limits := collector.DefaultLimits()
	limits.PageSize = 1
	result, err := collectDeletion(t, ctx, db, root, limits)
	require.NoError(t, err)
	seen := map[string]bool{}
	for _, d := range result.Collection.Dependencies {
		if d.Relationship == ds.RelationshipShiftUser {
			seen[d.Referencing.ID] = true
			require.Equal(t, f.now.Add(-time.Hour), d.Before.WindowStart)
			require.Equal(t, f.now.Add(time.Hour), d.Before.WindowEnd)
		}
	}
	require.Len(t, seen, 4)
	var envelope int64
	require.NoError(t, db.QueryRowContext(ctx, `SELECT id FROM schedule_data WHERE schedule_id=$1`, f.schedule).Scan(&envelope))
	require.True(t, seen[fmt.Sprintf("schedule-data:%d:temporary:1:shift:1", envelope)])
	schedule := ds.Resource{Kind: ds.ResourceSchedule, ID: f.schedule.String()}
	result, err = collectDeletion(t, ctx, db, schedule, limits)
	require.NoError(t, err)
	var oncall int
	for _, d := range result.Collection.Dependencies {
		if d.Relationship == ds.RelationshipScheduleOnCallRule {
			oncall++
			require.Equal(t, fmt.Sprintf("schedule-data:%d:oncall:0:0", envelope), d.Referencing.ID)
		}
	}
	require.Equal(t, 1, oncall)
	_ = deletionPlan(t, schedule, result)
	outside := fmt.Sprintf(`{"V1":{"TemporarySchedules":[{"Start":%q,"End":%q,"Shifts":[{"Start":%q,"End":%q,"UserID":%q}]}],"OnCallNotificationRules":[]}}`, f.now.Add(-time.Hour).Format(time.RFC3339), f.now.Add(time.Hour).Format(time.RFC3339), f.now.Add(2*time.Hour).Format(time.RFC3339), f.now.Add(3*time.Hour).Format(time.RFC3339), f.user.String())
	_, err = db.ExecContext(ctx, `UPDATE schedule_data SET data=$1::jsonb WHERE schedule_id=$2`, outside, f.schedule)
	require.NoError(t, err)
	result, err = collectDeletion(t, ctx, db, root, limits)
	require.Error(t, err)
	require.Equal(t, ds.DependenciesUnsupported, result.Collection.Completeness)
	_, err = db.ExecContext(ctx, `UPDATE schedule_data SET data=$1::jsonb WHERE schedule_id=$2`, string(raw), f.schedule)
	require.NoError(t, err)
	// Unknown nested members cannot be stripped by the safe SQL projection and
	// mistaken for a complete scan. No raw unknown value is returned to Go.
	_, err = db.ExecContext(ctx, `UPDATE schedule_data SET data=jsonb_set(data,'{V1,TemporarySchedules,0,Shifts,0,FutureReference}','"SYNTHETIC_PRIVATE_UNKNOWN"') WHERE schedule_id=$1`, f.schedule)
	require.NoError(t, err)
	result, err = collectDeletion(t, ctx, db, root, limits)
	require.Error(t, err)
	require.Equal(t, ds.DependenciesUnsupported, result.Collection.Completeness)
	// A large envelope is bounded by business fragments, not by envelope count.
	shifts := make([]any, 1000)
	for i := range shifts {
		shifts[i] = shift
	}
	large, err := json.Marshal(map[string]any{"V1": map[string]any{"TemporarySchedules": []any{map[string]any{"Start": f.now.Add(-time.Hour), "End": f.now.Add(time.Hour), "Shifts": shifts}}, "OnCallNotificationRules": []any{}}})
	require.NoError(t, err)
	_, err = db.ExecContext(ctx, `UPDATE schedule_data SET data=$1::jsonb WHERE schedule_id=$2`, string(large), f.schedule)
	require.NoError(t, err)
	limited := collector.DefaultLimits()
	limited.MaxFragments = 1000
	result, err = collectDeletion(t, ctx, db, root, limited)
	var typed *ds.DeletionSafetyError
	require.ErrorAs(t, err, &typed)
	require.Equal(t, ds.DeletionPreviewLimitExceeded, typed.Code)
	require.Empty(t, result.Collection.Dependencies)
	limited.MaxFragments = 1001
	result, err = collectDeletion(t, ctx, db, root, limited)
	require.NoError(t, err)
	count := 0
	for _, d := range result.Collection.Dependencies {
		if d.Relationship == ds.RelationshipShiftUser {
			count++
		}
	}
	require.Equal(t, 1000, count)
}
