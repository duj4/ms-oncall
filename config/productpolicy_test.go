package config

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

type unnormalizedSource struct{ cfg Config }

func (s unnormalizedSource) Config() Config { return s.cfg }

func TestCalendarProductPolicyConfigSources(t *testing.T) {
	for _, stored := range []bool{false, true} {
		var raw Config
		raw.General.DisableCalendarSubscriptions = stored
		raw.General.ApplicationName = "Calendar policy control"
		raw.General.DisableSMSLinks = true
		check := func(cfg Config) {
			t.Helper()
			require.True(t, cfg.General.DisableCalendarSubscriptions)
			cfg.General.DisableCalendarSubscriptions = stored
			require.Equal(t, raw, cfg, "unrelated config must be preserved")
		}
		check(Static(raw).Config())
		check((&Store{rawCfg: raw}).Config())
		check(FromContext(raw.Context(context.Background())))
		Handler(http.HandlerFunc(func(_ http.ResponseWriter, req *http.Request) {
			check(FromContext(req.Context()))
		}), unnormalizedSource{raw}).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/", nil))
		require.Equal(t, stored, raw.General.DisableCalendarSubscriptions, "normalization must not mutate the input")
	}
}
