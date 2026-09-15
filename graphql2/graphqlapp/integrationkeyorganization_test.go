package graphqlapp

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/assignment"
	"github.com/target/goalert/graphql2"
	"github.com/target/goalert/integrationkey"
	"github.com/target/goalert/permission"
	"github.com/target/goalert/service"
)

func TestIntegrationKeyOrganizationMissingHumanAuthority(t *testing.T) {
	ctx := permission.UserSourceContext(context.Background(), uuid.NewString(), permission.RoleUser,
		&permission.SourceInfo{Type: permission.SourceTypeAuthProvider, ID: uuid.NewString()})
	id := uuid.NewString()
	app := new(App) // No DB: these boundaries must reject before any Store access.
	checks := map[string]func() error{
		"query":  func() error { _, err := app.Query().IntegrationKey(ctx, id); return err },
		"search": func() error { _, err := app.Query().IntegrationKeys(ctx, nil); return err },
		"create": func() error {
			_, err := app.Mutation().CreateIntegrationKey(ctx, graphql2.CreateIntegrationKeyInput{Name: "key", Type: graphql2.IntegrationKeyTypeGeneric, ServiceID: &id})
			return err
		},
		"generate":         func() error { _, err := app.Mutation().GenerateKeyToken(ctx, id); return err },
		"promote":          func() error { _, err := app.Mutation().PromoteSecondaryToken(ctx, id); return err },
		"delete secondary": func() error { _, err := app.Mutation().DeleteSecondaryToken(ctx, id); return err },
		"token info": func() error {
			_, err := app.IntegrationKey().TokenInfo(ctx, &integrationkey.IntegrationKey{ID: id})
			return err
		},
		"config": func() error {
			_, err := app.IntegrationKey().Config(ctx, &integrationkey.IntegrationKey{ID: id})
			return err
		},
		"raw Service children": func() error { _, err := app.Service().IntegrationKeys(ctx, &service.Service{ID: id}); return err },
		"DeleteAll IntegrationKey requires root authority": func() error {
			_, err := app.Mutation().DeleteAll(ctx, []assignment.RawTarget{{Type: assignment.TargetTypeIntegrationKey, ID: id}})
			return err
		},
	}
	for name, check := range checks {
		t.Run(name, func(t *testing.T) { require.True(t, permission.IsPermissionError(check())) })
	}
}
