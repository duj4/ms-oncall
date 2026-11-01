package graphqlapp

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/assignment"
	"github.com/target/goalert/auth"
	"github.com/target/goalert/executioncontext"
	"github.com/target/goalert/graphql2"
	"github.com/target/goalert/organization"
	"github.com/target/goalert/permission"
)

func TestScheduleRotationManagementAuthority(t *testing.T) {
	for _, role := range []organization.OrganizationRole{organization.OrganizationRoleMember, organization.OrganizationRoleAdmin} {
		for _, pa := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/PA=%t", role, pa), func(t *testing.T) {
				ctx, _, fixture := ikAuthorityContext(t, role, pa)
				for _, op := range []scheduleRotationManagementOperation{scheduleRotationManagementCreate, scheduleRotationManagementUpdate} {
					home, err := scheduleRotationManagementAuthority(ctx, op)
					if pa || role == organization.OrganizationRoleAdmin {
						require.NoError(t, err)
						require.NotNil(t, home)
						require.Equal(t, fixture.home, *home)
					} else {
						require.Nil(t, home)
						require.True(t, permission.IsPermissionError(err))
					}
				}
				require.Equal(t, 1, fixture.queries, "authority stays bound to finite request admission")
				require.Zero(t, fixture.begins)
			})
		}
	}
}

func TestScheduleRotationManagementIdentity(t *testing.T) {
	ctx, _, f := ikAuthorityContext(t, organization.OrganizationRoleAdmin, true)
	other, err := auth.NewRequester(uuid.NewString(), uuid.NewString())
	require.NoError(t, err)
	missingEC := auth.WithRequester(permission.UserSourceContext(context.Background(), f.user.String(), permission.RoleAdmin,
		&permission.SourceInfo{Type: permission.SourceTypeAuthProvider, ID: f.session.String()}), *auth.RequesterFromContext(ctx))
	for name, c := range map[string]context.Context{
		"nil": nil, "unauthenticated": context.Background(),
		"legacy user":        permission.UserContext(context.Background(), f.user.String(), permission.RoleUser),
		"legacy admin":       permission.UserContext(context.Background(), f.user.String(), permission.RoleAdmin),
		"missing EC":         missingEC,
		"zero EC":            executioncontext.WithExecutionContext(missingEC, executioncontext.ExecutionContext{}),
		"other requester":    auth.WithRequester(ctx, other),
		"source mismatch":    permission.SourceContext(ctx, &permission.SourceInfo{Type: permission.SourceTypeAuthProvider, ID: uuid.NewString()}),
		"PA mismatch":        permission.UserContext(ctx, f.user.String(), permission.RoleUser),
		"System over Human":  permission.SystemContext(ctx, "Test"),
		"Machine over Human": permission.ServiceContext(ctx, uuid.NewString()),
		"legacy key": permission.UserSourceContext(context.Background(), f.user.String(), permission.RoleAdmin,
			&permission.SourceInfo{Type: permission.SourceTypeGQLAPIKey, ID: uuid.NewString()}),
		"integration": permission.ServiceSourceContext(context.Background(), uuid.NewString(),
			&permission.SourceInfo{Type: permission.SourceTypeIntegrationKey, ID: uuid.NewString()}),
		"System with source": permission.SourceContext(permission.SystemContext(context.Background(), "Test"), &permission.SourceInfo{Type: permission.SourceTypeGQLAPIKey}),
	} {
		t.Run(name, func(t *testing.T) {
			for _, op := range []scheduleRotationManagementOperation{scheduleRotationManagementCreate, scheduleRotationManagementUpdate} {
				home, err := scheduleRotationManagementAuthority(c, op)
				require.Nil(t, home)
				require.True(t, permission.IsPermissionError(err))
			}
		})
	}
	sys := permission.SystemContext(context.Background(), "Engine")
	home, err := scheduleRotationManagementAuthority(sys, scheduleRotationManagementUpdate)
	require.NoError(t, err)
	require.Nil(t, home)
	_, err = scheduleRotationManagementAuthority(sys, scheduleRotationManagementCreate)
	require.True(t, permission.IsPermissionError(err))
	_, err = scheduleRotationManagementAuthority(ctx, scheduleRotationManagementOperation(255))
	require.True(t, permission.IsPermissionError(err))
}

func TestScheduleRotationManagementBeforeBusinessWork(t *testing.T) {
	ctx, _, f := ikAuthorityContext(t, organization.OrganizationRoleMember, false)
	app := new(App) // Business Store, destination mapping or transaction access would panic.
	id := uuid.NewString()
	_, err := app.Mutation().CreateSchedule(ctx, graphql2.CreateScheduleInput{})
	require.True(t, permission.IsPermissionError(err))
	_, err = app.Mutation().CreateRotation(ctx, graphql2.CreateRotationInput{})
	require.True(t, permission.IsPermissionError(err))
	_, err = app.Mutation().UpdateSchedule(ctx, graphql2.UpdateScheduleInput{ID: id})
	require.True(t, permission.IsPermissionError(err))
	_, err = app.Mutation().UpdateRotation(ctx, graphql2.UpdateRotationInput{ID: id})
	require.True(t, permission.IsPermissionError(err))
	for _, current := range []string{id, "__current_user"} {
		_, err = app.Mutation().UpdateScheduleTarget(ctx, graphql2.ScheduleTargetInput{ScheduleID: &id, Target: &assignment.RawTarget{Type: assignment.TargetTypeUser, ID: current}})
		require.True(t, permission.IsPermissionError(err))
	}
	_, err = app.Mutation().SetTemporarySchedule(ctx, graphql2.SetTemporaryScheduleInput{ScheduleID: id})
	require.True(t, permission.IsPermissionError(err))
	_, err = app.Mutation().ClearTemporarySchedules(ctx, graphql2.ClearTemporarySchedulesInput{ScheduleID: id, Start: time.Now().Add(time.Hour), End: time.Now().Add(2 * time.Hour)})
	require.True(t, permission.IsPermissionError(err))
	_, err = app.Mutation().SetScheduleOnCallNotificationRules(ctx, graphql2.SetScheduleOnCallNotificationRulesInput{ScheduleID: id})
	require.True(t, permission.IsPermissionError(err))
	require.Equal(t, 1, f.queries)
	require.Zero(t, f.begins)
}
