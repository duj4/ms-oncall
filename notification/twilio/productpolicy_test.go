package twilio

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/target/goalert/config"
	"github.com/target/goalert/notification/nfydest"
	"github.com/target/goalert/retry"
	"github.com/target/goalert/user/contactmethod"
	"github.com/target/goalert/util/log"
)

type policyTransport struct{ calls atomic.Int32 }

func (p *policyTransport) RoundTrip(*http.Request) (*http.Response, error) {
	p.calls.Add(1)
	return nil, errors.New("unexpected excluded provider request")
}

func TestExcludedTwilioOutbound(t *testing.T) {
	transport := new(policyTransport)
	client := Config{Client: &http.Client{Transport: transport}, CMStore: new(contactmethod.Store)}
	var cfg config.Config
	cfg.Twilio.Enable, cfg.Twilio.SMSCarrierLookup = true, true
	logger := log.NewLogger()
	logger.EnableJSON()
	var captured bytes.Buffer
	logger.SetOutput(&captured)
	ctx := cfg.Context(log.WithLogger(context.Background(), logger))
	raw := "https://example.invalid/private/policy-token"
	for range 2 {
		for _, call := range []func() error{
			func() error { _, err := (&SMS{c: &client}).SendMessage(ctx, nil); return err },
			func() error { _, err := (&Voice{c: &client}).SendMessage(ctx, nil); return err },
			func() error { _, err := (&SMS{c: &client}).MessageStatus(ctx, raw); return err },
			func() error { _, err := (&Voice{c: &client}).MessageStatus(ctx, raw); return err },
			func() error { _, err := client.SendSMS(ctx, raw, raw, nil); return err },
			func() error { _, err := client.StartVoice(ctx, raw, nil); return err },
			func() error { _, err := client.GetSMS(ctx, raw); return err },
			func() error { _, err := client.GetVoice(ctx, raw); return err },
			func() error { _, err := client.CarrierInfo(ctx, raw, false); return err },
			func() error { _, err := client.CarrierInfo(ctx, raw, true); return err },
			func() error { _, err := client.FetchCarrierInfo(ctx, raw); return err },
			func() error { _, err := client.get(ctx, raw); return err },
			func() error { _, err := client.post(ctx, raw, nil); return err },
		} {
			err := call()
			require.ErrorIs(t, err, nfydest.ErrNotEnabled)
			require.False(t, retry.IsTemporaryError(err))
			log.Log(ctx, err)
		}
		require.Zero(t, transport.calls.Load())
	}
	require.NotContains(t, captured.String(), raw)
}
