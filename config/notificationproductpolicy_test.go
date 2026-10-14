package config

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestExcludedProviderConfig(t *testing.T) {
	var raw Config
	require.NoError(t, json.Unmarshal([]byte(`{"Twilio":{"Enable":true,"SMSCarrierLookup":true,"VoiceName":"dormant","FromNumber":"invalid"},"Slack":{"Enable":true,"InteractiveMessages":true},"SMTP":{"Enable":true,"From":"test@example.invalid","Address":"smtp.example.invalid"},"Webhook":{"Enable":true,"AllowedURLs":["https://example.invalid"]}}`), &raw))
	data, err := json.Marshal(raw)
	require.NoError(t, err)
	var roundTrip Config
	require.NoError(t, json.Unmarshal(data, &roundTrip))
	check := func(cfg Config) {
		t.Helper()
		require.False(t, cfg.Twilio.Enable)
		require.False(t, cfg.Twilio.SMSCarrierLookup)
		require.False(t, cfg.Slack.Enable)
		require.False(t, cfg.Slack.InteractiveMessages)
		require.True(t, cfg.General.DisableCalendarSubscriptions)
		require.True(t, cfg.General.DisableLabelCreation)
		require.Equal(t, raw.SMTP, cfg.SMTP)
		require.Equal(t, raw.Webhook, cfg.Webhook)
	}
	for range 2 {
		check(Static(roundTrip).Config())
		check((&Store{rawCfg: roundTrip}).Config()) // Snapshot only; no SQL reload/import claim.
		check(FromContext(roundTrip.Context(context.Background())))
		Handler(http.HandlerFunc(func(_ http.ResponseWriter, req *http.Request) {
			check(FromContext(req.Context()))
		}), unnormalizedSource{roundTrip}).ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/", nil))
	}
	require.True(t, roundTrip.Twilio.Enable, "raw history must remain unmodified")
	require.True(t, roundTrip.Slack.Enable)
	require.NoError(t, raw.Validate())
	raw.SMTP.From = "invalid"
	require.ErrorContains(t, raw.Validate(), "SMTP.From")
	raw = roundTrip
	raw.Webhook.AllowedURLs = []string{"invalid"}
	require.ErrorContains(t, raw.Validate(), "Webhook.AllowedURLs")
}
