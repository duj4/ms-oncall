package config

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLabelProductPolicyConfigSources(t *testing.T) {
	require.True(t, LabelsDisabled())
	for _, stored := range []bool{false, true} {
		for _, required := range [][]string{nil, {}, {"foo"}} {
			var raw Config
			raw.General.DisableLabelCreation = stored
			raw.Services.RequiredLabels = required
			raw.General.ApplicationName = "Label neighbor control"
			raw.General.DisableSMSLinks = true
			check := func(cfg Config) {
				t.Helper()
				require.True(t, cfg.General.DisableLabelCreation)
				require.Empty(t, cfg.Services.RequiredLabels)
				require.True(t, cfg.General.DisableCalendarSubscriptions)
				cfg.General.DisableCalendarSubscriptions = raw.General.DisableCalendarSubscriptions
				cfg.General.DisableLabelCreation = raw.General.DisableLabelCreation
				cfg.Services.RequiredLabels = raw.Services.RequiredLabels
				require.Equal(t, raw, cfg, "other configuration must be preserved")
			}
			check(Static(raw).Config())
			check((&Store{rawCfg: raw}).Config())
			check(FromContext(raw.Context(context.Background())))
			Handler(http.HandlerFunc(func(_ http.ResponseWriter, req *http.Request) {
				check(FromContext(req.Context()))
			}), unnormalizedSource{raw}).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/", nil))
			require.Equal(t, stored, raw.General.DisableLabelCreation)
			require.Equal(t, required, raw.Services.RequiredLabels)
		}
	}
}
