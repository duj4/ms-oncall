package graphqlapp

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/alert"
	"github.com/target/goalert/alert/alertlog"
	"github.com/target/goalert/auth"
	"github.com/target/goalert/graphql2"
	"github.com/target/goalert/permission"
	"github.com/target/goalert/service"
)

func TestAlertOrganizationMissingHumanAuthority(t *testing.T) {
	userID, sessionID, serviceID := uuid.NewString(), uuid.NewString(), uuid.NewString()
	ctx := permission.UserSourceContext(context.Background(), userID, permission.RoleUser,
		&permission.SourceInfo{Type: permission.SourceTypeAuthProvider, ID: sessionID})
	requester, err := auth.NewRequester(userID, sessionID)
	require.NoError(t, err)
	contexts := []context.Context{ctx, auth.WithRequester(ctx, requester), auth.WithRequester(context.Background(), requester)}
	for _, ctx := range contexts {
		app := new(App) // No database: every boundary must fail before Store access.
		raw := &alert.Alert{ID: 1, ServiceID: serviceID}
		checks := map[string]func() error{
			"single": func() error { _, err := app.Query().Alert(ctx, 1); return err },
			"search": func() error { _, err := app.Query().Alerts(ctx, nil); return err },
			"create": func() error {
				_, err := app.Mutation().CreateAlert(ctx, graphql2.CreateAlertInput{ServiceID: serviceID, Summary: "test"})
				return err
			},
			"close dedup": func() error {
				_, err := app.Mutation().CloseMatchingAlert(ctx, graphql2.CloseMatchingAlertInput{ServiceID: serviceID})
				return err
			},
			"status": func() error {
				_, err := app.Mutation().UpdateAlerts(ctx, graphql2.UpdateAlertsInput{AlertIDs: []int{1}})
				return err
			},
			"service status": func() error {
				_, err := app.Mutation().UpdateAlertsByService(ctx, graphql2.UpdateAlertsByServiceInput{ServiceID: serviceID})
				return err
			},
			"escalate": func() error { _, err := app.Mutation().EscalateAlerts(ctx, []int{1}); return err },
			"feedback write": func() error {
				_, err := app.Mutation().SetAlertNoiseReason(ctx, graphql2.SetAlertNoiseReasonInput{AlertID: 1, NoiseReason: "test"})
				return err
			},
			"state":          func() error { _, err := app.Alert().State(ctx, raw); return err },
			"metrics":        func() error { _, err := app.Alert().Metrics(ctx, raw); return err },
			"meta":           func() error { _, err := app.Alert().Meta(ctx, raw); return err },
			"meta value":     func() error { _, err := app.Alert().MetaValue(ctx, raw, "key"); return err },
			"noise":          func() error { _, err := app.Alert().NoiseReason(ctx, raw); return err },
			"logs":           func() error { _, err := app.Alert().RecentEvents(ctx, raw, nil); return err },
			"pending":        func() error { _, err := app.Alert().PendingNotifications(ctx, raw); return err },
			"service":        func() error { _, err := app.Alert().Service(ctx, raw); return err },
			"service counts": func() error { _, err := app.Service().AlertsByStatus(ctx, &service.Service{ID: serviceID}); return err },
			"service stats": func() error {
				_, err := app.Service().AlertStats(ctx, &service.Service{ID: serviceID}, nil)
				return err
			},
			"service logs": func() error {
				_, err := app.Service().RecentEvents(ctx, &service.Service{ID: serviceID}, nil)
				return err
			},
			"log state":   func() error { _, err := app.AlertLogEntry().State(ctx, &alertlog.Entry{}); return err },
			"log message": func() error { _, err := app.AlertLogEntry().Message(ctx, &alertlog.Entry{}); return err },
		}
		for name, check := range checks {
			t.Run(name, func(t *testing.T) { require.True(t, permission.IsPermissionError(check())) })
		}
	}
}
