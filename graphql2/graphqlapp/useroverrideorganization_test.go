package graphqlapp

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/assignment"
	"github.com/target/goalert/auth"
	"github.com/target/goalert/graphql2"
	"github.com/target/goalert/permission"
)

func TestUserOverrideOrganizationMissingOrInconsistentAuthority(t *testing.T) {
	userID, sessionID, id := uuid.NewString(), uuid.NewString(), uuid.NewString()
	ctx := permission.UserSourceContext(context.Background(), userID, permission.RoleUser,
		&permission.SourceInfo{Type: permission.SourceTypeAuthProvider, ID: sessionID})
	requester, err := auth.NewRequester(userID, sessionID)
	require.NoError(t, err)
	contexts := map[string]context.Context{
		"missing requester":   ctx,
		"missing authority":   auth.WithRequester(ctx, requester),
		"inconsistent source": auth.WithRequester(context.Background(), requester),
		"inconsistent session": auth.WithRequester(permission.UserSourceContext(context.Background(), userID, permission.RoleAdmin,
			&permission.SourceInfo{Type: permission.SourceTypeAuthProvider, ID: uuid.NewString()}), requester),
	}
	for name, ctx := range contexts {
		t.Run(name, func(t *testing.T) {
			app := new(App) // No database: fail closed before Store access.
			checks := map[string]func() error{
				"read":   func() error { _, err := app.Query().UserOverride(ctx, id); return err },
				"search": func() error { _, err := app.Query().UserOverrides(ctx, nil); return err },
				"create": func() error {
					_, err := app.Mutation().CreateUserOverride(ctx, graphql2.CreateUserOverrideInput{ScheduleID: &id})
					return err
				},
				"update": func() error {
					_, err := app.Mutation().UpdateUserOverride(ctx, graphql2.UpdateUserOverrideInput{ID: id})
					return err
				},
				"pure override DeleteAll": func() error {
					_, err := app.Mutation().DeleteAll(ctx, []assignment.RawTarget{{Type: assignment.TargetTypeUserOverride, ID: id}})
					return err
				},
			}
			for name, check := range checks {
				t.Run(name, func(t *testing.T) { require.True(t, permission.IsPermissionError(check())) })
			}
		})
	}
}
