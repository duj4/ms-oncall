package nfydest

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/target/goalert/gadb"
	"github.com/target/goalert/notification/nfymsg"
	"github.com/target/goalert/validation"
)

type policyProvider struct {
	c9UntrustedProvider
	id      string
	enabled bool
	calls   int
}

func (p *policyProvider) ID() string { return p.id }
func (p *policyProvider) TypeInfo(context.Context) (*TypeInfo, error) {
	p.calls++
	return &TypeInfo{Enabled: p.enabled}, nil
}
func (p *policyProvider) ValidateField(ctx context.Context, field, value string) error {
	p.calls++
	return p.c9UntrustedProvider.ValidateField(ctx, field, value)
}
func (p *policyProvider) DisplayInfo(ctx context.Context, args map[string]string) (*DisplayInfo, error) {
	p.calls++
	return p.c9UntrustedProvider.DisplayInfo(ctx, args)
}
func (p *policyProvider) SearchField(ctx context.Context, field string, options SearchOptions) (*SearchResult, error) {
	p.calls++
	return p.c9UntrustedProvider.SearchField(ctx, field, options)
}
func (p *policyProvider) FieldLabel(ctx context.Context, field, value string) (string, error) {
	p.calls++
	return p.c9UntrustedProvider.FieldLabel(ctx, field, value)
}
func (p *policyProvider) SendMessage(ctx context.Context, msg nfymsg.Message) (*nfymsg.SentMessage, error) {
	p.calls++
	return p.c9UntrustedProvider.SendMessage(ctx, msg)
}
func (p *policyProvider) MessageStatus(ctx context.Context, id string) (*nfymsg.Status, error) {
	p.calls++
	return p.c9UntrustedProvider.MessageStatus(ctx, id)
}

func TestExcludedDestinationRegistry(t *testing.T) {
	ctx := context.Background()
	reg := NewRegistry()
	raw := "https://example.invalid/private/policy-token +15551234567"
	var excluded []*policyProvider
	for _, id := range []string{"builtin-twilio-sms", "builtin-twilio-voice", "builtin-slack-dm", "builtin-slack-channel", "builtin-slack-usergroup"} {
		p := &policyProvider{id: id, enabled: true, c9UntrustedProvider: c9UntrustedProvider{err: errors.New(raw)}}
		reg.RegisterProvider(ctx, p)
		excluded = append(excluded, p)
	}
	for _, id := range []string{"builtin-email", "builtin-webhook", "builtin-schedule", "builtin-rotation", "builtin-user", "future-sms", "future-voice"} {
		reg.RegisterProvider(ctx, &policyProvider{id: id, enabled: true})
	}
	reg.RegisterProvider(ctx, &policyProvider{id: "other-disabled"})
	for range 2 {
		types, err := reg.Types(ctx)
		require.NoError(t, err)
		require.Len(t, types, 8, "retain supported and unrelated disabled types")
		for _, p := range excluded {
			dest := gadb.NewDestV1(p.id, "address", raw)
			_, infoErr := reg.TypeInfo(ctx, p.id)
			_, displayErr := reg.DisplayInfo(ctx, dest)
			_, searchErr := reg.SearchField(ctx, p.id, raw, SearchOptions{Search: raw})
			_, labelErr := reg.FieldLabel(ctx, p.id, raw, raw)
			_, sendErr := reg.SendMessage(ctx, nfymsg.Test{Base: nfymsg.Base{Dest: dest}})
			_, statusErr := reg.MessageStatus(ctx, p.id, raw)
			for _, err := range []error{infoErr, displayErr, searchErr, labelErr, sendErr, statusErr, reg.ValidateDest(ctx, dest), reg.ValidateField(ctx, p.id, raw, raw)} {
				require.ErrorIs(t, err, ErrUnknownType)
				require.True(t, validation.IsClientError(err))
				require.NotContains(t, fmt.Sprintf("%+v", err), raw)
			}
			require.Zero(t, p.calls, "excluded provider methods must never run")
			require.Nil(t, reg.Provider(p.id))
		}
		sent, err := reg.SendMessage(ctx, nfymsg.Test{Base: nfymsg.Base{Dest: gadb.NewDestV1("builtin-email")}})
		require.NoError(t, err)
		if !reg.stubSender {
			require.Equal(t, "safe-correlation-id", sent.ExternalID)
		}
		_, err = reg.SendMessage(ctx, nfymsg.Test{Base: nfymsg.Base{Dest: gadb.NewDestV1("other-disabled")}})
		require.ErrorIs(t, err, ErrNotEnabled)
		reg.StubNotifiers() // Exclusion also precedes stub success on the second pass.
	}
	require.Panics(t, func() { reg.RegisterProvider(ctx, excluded[0]) }, "duplicate registration semantics retained")
}
