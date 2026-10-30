package integrationkey

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/search"
)

func TestIntegrationKeySearchAuthorityIsNotCursorState(t *testing.T) {
	home := uuid.New()
	encoded, err := search.Cursor(map[string]any{"s": "prefix", "a": "Same", "i": uuid.NewString(), "OrganizationID": uuid.NewString(), "PlatformAdminHome": home.String(), "platformAdmin": true})
	require.NoError(t, err)
	var opts InKeySearchOptions
	require.NoError(t, search.ParseCursor(encoded, &opts))
	data, err := (intKeyRenderData{InKeySearchOptions: opts, OrganizationID: uuid.NullUUID{UUID: home, Valid: true}}).Normalize()
	require.NoError(t, err)
	query, _, err := search.RenderQuery(context.Background(), intKeySearchTemplate, data)
	require.NoError(t, err)
	require.Contains(t, query, "s.organization_id =")
	require.NotContains(t, query, "key.type IN")
	require.NotRegexp(t, `[^:]:[a-zA-Z]`, query)
	require.Contains(t, query, "AND (lower(key.name), key.id) >")
	require.Contains(t, query, "ORDER BY lower(key.name), key.id")
}

func TestIntegrationKeySearchPlatformTargetsBeforeLimit(t *testing.T) {
	for _, afterID := range []string{"", uuid.NewString()} {
		data, err := (intKeyRenderData{InKeySearchOptions: InKeySearchOptions{After: "Same", AfterID: afterID, Limit: 2}, PlatformAdminHome: uuid.NullUUID{UUID: uuid.New(), Valid: true}}).Normalize()
		require.NoError(t, err)
		query, _, err := search.RenderQuery(context.Background(), intKeySearchTemplate, data)
		require.NoError(t, err)
		require.Contains(t, query, "JOIN normal_organizations")
		require.Contains(t, query, "o.classification = 'NORMAL'")
		require.Contains(t, query, "key.type IN ('generic','grafana','site24x7','prometheusAlertmanager','email')")
		require.Contains(t, query, "OR (key.type = 'universal' AND s.organization_id =")
		require.Contains(t, query, "s.organization_id <>")
		require.NotRegexp(t, `[^:]:[a-zA-Z]`, query)
		if afterID == "" {
			require.Contains(t, query, "AND lower(key.name) >")
		}
	}
}
