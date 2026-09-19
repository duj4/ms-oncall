package graphqlapp

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/auth"
	"github.com/target/goalert/executioncontext"
	"github.com/target/goalert/graphql2"
	"github.com/target/goalert/permission"
)

func TestScheduleDataAuthorityBeforeDatabase(t *testing.T) {
	id, session := uuid.NewString(), uuid.NewString()
	legacy := permission.UserSourceContext(context.Background(), id, permission.RoleAdmin, &permission.SourceInfo{Type: permission.SourceTypeAuthProvider, ID: session})
	requester, err := auth.NewRequester(id, session)
	require.NoError(t, err)
	contexts := map[string]context.Context{
		"missing requester":   legacy,
		"missing authority":   auth.WithRequester(legacy, requester),
		"zero authority":      executioncontext.WithExecutionContext(auth.WithRequester(legacy, requester), executioncontext.ExecutionContext{}),
		"inconsistent source": auth.WithRequester(context.Background(), requester),
	}
	for name, ctx := range contexts {
		t.Run(name, func(t *testing.T) {
			app := new(App) // Any database/Store/destination access would panic.
			start, end := time.Now().Add(time.Hour), time.Now().Add(2*time.Hour)
			for _, clear := range []bool{false, true} {
				input := graphql2.SetTemporaryScheduleInput{ScheduleID: uuid.NewString(), Start: start, End: end}
				if clear {
					input.ClearStart, input.ClearEnd = &start, &end
				}
				_, err := app.Mutation().SetTemporarySchedule(ctx, input)
				require.True(t, permission.IsPermissionError(err))
			}
			_, err := app.Mutation().ClearTemporarySchedules(ctx, graphql2.ClearTemporarySchedulesInput{ScheduleID: uuid.NewString(), Start: start, End: end})
			require.True(t, permission.IsPermissionError(err))
			_, err = app.Mutation().SetScheduleOnCallNotificationRules(ctx, graphql2.SetScheduleOnCallNotificationRulesInput{ScheduleID: uuid.NewString(), Rules: []graphql2.OnCallNotificationRuleInput{{}}})
			require.True(t, permission.IsPermissionError(err))
		})
	}
}

func TestScheduleDataLocalValidationBeforeAuthority(t *testing.T) {
	app := new(App)
	ctx := permission.UserSourceContext(context.Background(), uuid.NewString(), permission.RoleUser, &permission.SourceInfo{Type: permission.SourceTypeAuthProvider, ID: uuid.NewString()})
	_, err := app.Mutation().SetTemporarySchedule(ctx, graphql2.SetTemporaryScheduleInput{ScheduleID: "bad"})
	require.ErrorContains(t, err, "must be a valid UUID")
	_, err = app.Mutation().ClearTemporarySchedules(ctx, graphql2.ClearTemporarySchedulesInput{ScheduleID: "bad"})
	require.ErrorContains(t, err, "must be a valid UUID")
	_, err = app.Mutation().SetScheduleOnCallNotificationRules(ctx, graphql2.SetScheduleOnCallNotificationRulesInput{ScheduleID: "bad"})
	require.ErrorContains(t, err, "must be a valid UUID")
	stamp := time.Now()
	_, err = app.Mutation().SetTemporarySchedule(ctx, graphql2.SetTemporaryScheduleInput{ScheduleID: uuid.NewString(), ClearStart: &stamp})
	require.EqualError(t, err, "invalid value for 'ClearEnd': must be set if ClearStart is set")
	_, err = app.Mutation().SetTemporarySchedule(ctx, graphql2.SetTemporaryScheduleInput{ScheduleID: uuid.NewString(), ClearEnd: &stamp})
	require.EqualError(t, err, "invalid value for 'ClearStart': must be set if ClearEnd is set")
}
