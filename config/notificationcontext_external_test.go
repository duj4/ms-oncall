package config_test

import (
	"context"
	"encoding/json"
	"net/http"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/target/goalert/config"
	"github.com/target/goalert/notification/nfydest"
	"github.com/target/goalert/notification/slack"
	"github.com/target/goalert/notification/twilio"
)

type restoredRawContext struct {
	context.Context
	raw config.Config
}

func (c restoredRawContext) Value(key any) any {
	if _, ok := c.Context.Value(key).(config.Config); ok {
		return c.raw
	}
	return c.Context.Value(key)
}

type metadataTransport struct{ calls atomic.Int32 }

func (tr *metadataTransport) RoundTrip(*http.Request) (*http.Response, error) {
	tr.calls.Add(1)
	return nil, nfydest.ErrNotEnabled
}

func TestExcludedRestoredContext(t *testing.T) {
	var raw config.Config
	require.NoError(t, json.Unmarshal([]byte(`{"Twilio":{"Enable":true,"SMSCarrierLookup":true},"Slack":{"Enable":true,"InteractiveMessages":true,"AccessToken":"synthetic-f1-token"},"SMTP":{"Enable":true,"From":"test@example.invalid","Address":"smtp.example.invalid"},"Webhook":{"Enable":true,"AllowedURLs":["https://example.invalid/"]},"Services":{"RequiredLabels":["dormant"]}}`), &raw))
	before, err := json.Marshal(raw)
	require.NoError(t, err)
	ctx := restoredRawContext{raw.Context(context.Background()), raw}
	for range 2 {
		for _, c := range []context.Context{ctx.Context, ctx} {
			effective := config.FromContext(c)
			require.Equal(t, []bool{false, false, false, false}, []bool{effective.Twilio.Enable, effective.Twilio.SMSCarrierLookup, effective.Slack.Enable, effective.Slack.InteractiveMessages})
			require.Equal(t, []bool{true, true}, []bool{effective.General.DisableCalendarSubscriptions, effective.General.DisableLabelCreation})
			require.Nil(t, effective.Services.RequiredLabels)
			require.Equal(t, raw.SMTP, effective.SMTP)
			require.Equal(t, raw.Webhook, effective.Webhook)
		}
	}
	require.Panics(t, func() { config.FromContext(context.Background()) })
	tr := new(metadataTransport)
	sender, err := slack.NewChannelSender(ctx, slack.Config{Client: &http.Client{Transport: tr}, BaseURL: "https://example.invalid/"})
	require.NoError(t, err)
	for _, p := range []nfydest.Provider{new(twilio.SMS), new(twilio.Voice), sender.DMSender(), sender, sender.UserGroupSender()} {
		t.Run(p.ID(), func(t *testing.T) {
			info, err := p.TypeInfo(ctx)
			require.NoError(t, err)
			require.False(t, info.Enabled)
		})
	}
	require.Zero(t, tr.calls.Load())
	after, err := json.Marshal(raw)
	require.NoError(t, err)
	require.Equal(t, before, after)
}
