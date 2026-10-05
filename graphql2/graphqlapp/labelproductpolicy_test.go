package graphqlapp

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/assignment"
	"github.com/target/goalert/escalation"
	"github.com/target/goalert/graphql2"
	"github.com/target/goalert/label"
	"github.com/target/goalert/permission"
	"github.com/target/goalert/schedule"
	"github.com/target/goalert/schedule/rotation"
	"github.com/target/goalert/search"
	"github.com/target/goalert/service"
)

func TestLabelResolversProductPolicyBeforeStoreAndTransaction(t *testing.T) {
	// No Store or DB exists. This proves the resolver boundary independently
	// from the Store guards, including transaction creation and cursor handling.
	app := new(App)
	userID := uuid.NewString()
	contexts := map[string]context.Context{
		"missing":                context.Background(),
		"human-nil-organization": permission.UserContext(context.Background(), userID, permission.RoleUser),
		"legacy-admin":           permission.UserContext(context.Background(), userID, permission.RoleAdmin),
		"system":                 permission.SystemContext(context.Background(), "test"),
		"api-key":                permission.UserSourceContext(context.Background(), userID, permission.RoleAdmin, &permission.SourceInfo{Type: permission.SourceTypeGQLAPIKey, ID: uuid.NewString()}),
	}
	for name, ctx := range contexts {
		t.Run(name, func(t *testing.T) {
			for _, state := range []any{label.KeySearchOptions{Search: "policy/key", After: "policy/key"}, label.ValueSearchOptions{Key: "policy/key", KeySearchOptions: label.KeySearchOptions{After: "value"}}, map[string]any{"s": "forged", "a": "value", "k": "policy/key", "target": "foreign"}} {
				cursor, err := search.Cursor(state)
				require.NoError(t, err)
				_, err = app.Query().LabelKeys(ctx, &graphql2.LabelKeySearchOptions{After: &cursor})
				require.ErrorIs(t, err, label.ErrDisabled)
				_, err = app.Query().LabelValues(ctx, &graphql2.LabelValueSearchOptions{Key: "policy/key", After: &cursor})
				require.ErrorIs(t, err, label.ErrDisabled)
				_, err = app.Query().Labels(ctx, &graphql2.LabelSearchOptions{After: &cursor})
				require.ErrorIs(t, err, label.ErrDisabled)
			}
			_, err := app.Query().LabelKeys(ctx, nil)
			require.EqualError(t, err, "labels are disabled")
			for _, tgt := range []*assignment.RawTarget{{Type: assignment.TargetTypeService, ID: uuid.NewString()}, {Type: assignment.TargetTypeSchedule, ID: uuid.NewString()}, {Type: assignment.TargetTypeRotation, ID: uuid.NewString()}, {Type: assignment.TargetTypeEscalationPolicy, ID: uuid.NewString()}, {Type: assignment.TargetTypeService, ID: "malformed"}, nil} {
				for _, value := range []string{"create", "update", "same-value", ""} {
					ok, err := app.Mutation().SetLabel(ctx, graphql2.SetLabelInput{Target: tgt, Key: "policy/key", Value: value})
					require.False(t, ok)
					require.ErrorIs(t, err, label.ErrDisabled)
				}
			}
			serviceLabels, err := app.Service().Labels(ctx, &service.Service{ID: uuid.NewString()})
			require.NoError(t, err)
			require.NotNil(t, serviceLabels)
			require.Empty(t, serviceLabels)
			scheduleLabels, err := app.Schedule().Labels(ctx, &schedule.Schedule{ID: uuid.NewString()})
			require.NoError(t, err)
			require.NotNil(t, scheduleLabels)
			require.Empty(t, scheduleLabels)
			rotationLabels, err := app.Rotation().Labels(ctx, &rotation.Rotation{ID: uuid.NewString()})
			require.NoError(t, err)
			require.NotNil(t, rotationLabels)
			require.Empty(t, rotationLabels)
			policyLabels, err := app.EscalationPolicy().Labels(ctx, &escalation.Policy{ID: uuid.NewString()})
			require.NoError(t, err)
			require.NotNil(t, policyLabels)
			require.Empty(t, policyLabels)
			labels := []graphql2.SetLabelInput{{Key: "policy/key", Value: "value"}}
			_, err = app.Mutation().CreateService(ctx, graphql2.CreateServiceInput{Labels: labels})
			require.ErrorIs(t, err, label.ErrDisabled)
			_, err = app.Mutation().CreateSchedule(ctx, graphql2.CreateScheduleInput{Labels: labels})
			require.ErrorIs(t, err, label.ErrDisabled)
			_, err = app.Mutation().CreateRotation(ctx, graphql2.CreateRotationInput{Labels: labels})
			require.ErrorIs(t, err, label.ErrDisabled)
			_, err = app.Mutation().CreateEscalationPolicy(ctx, graphql2.CreateEscalationPolicyInput{Labels: labels})
			require.ErrorIs(t, err, label.ErrDisabled)
		})
	}
}

func TestServiceLabelCursorsBeforeStore(t *testing.T) {
	ctx := permission.SystemContext(context.Background(), "test")
	token := "token=" + uuid.NewString()
	for _, criteria := range []string{"policy/key=value", "policy/key!=value", "policy/key=", "policy/key!=*", token + " policy/key=value"} {
		for _, state := range []any{service.SearchOptions{Search: criteria, After: service.SearchCursor{Name: "old"}}, map[string]any{"s": criteria, "a": map[string]any{"n": "forged", "f": true}}} {
			cursor, err := search.Cursor(state)
			require.NoError(t, err)
			// Visible criteria omitted; only restored cursor state carries Labels.
			_, err = new(App).Query().Services(ctx, &graphql2.ServiceSearchOptions{After: &cursor})
			require.ErrorIs(t, err, label.ErrDisabled)
		}
		normalCursor, err := search.Cursor(service.SearchOptions{Search: "neighbor"})
		require.NoError(t, err)
		// A normal cursor must not silently strip explicitly supplied Label intent.
		_, err = new(App).Query().Services(ctx, &graphql2.ServiceSearchOptions{Search: &criteria, After: &normalCursor})
		require.ErrorIs(t, err, label.ErrDisabled)
	}
}
