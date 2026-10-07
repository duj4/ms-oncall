package nfydest

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/target/goalert/gadb"
	"github.com/target/goalert/notification/nfymsg"
	"github.com/target/goalert/retry"
	"github.com/target/goalert/validation"
)

type c9UntrustedProvider struct {
	err     error
	details string
}

func (c9UntrustedProvider) ID() string { return "c9-provider" }
func (c9UntrustedProvider) TypeInfo(context.Context) (*TypeInfo, error) {
	return &TypeInfo{Enabled: true, SupportsAlertNotifications: true, SupportsUserVerification: true, RequiredFields: []FieldConfig{{FieldID: "address"}}}, nil
}
func (p c9UntrustedProvider) ValidateField(context.Context, string, string) error { return p.err }
func (p c9UntrustedProvider) DisplayInfo(context.Context, map[string]string) (*DisplayInfo, error) {
	return nil, p.err
}
func (p c9UntrustedProvider) SearchField(context.Context, string, SearchOptions) (*SearchResult, error) {
	return nil, p.err
}
func (p c9UntrustedProvider) FieldLabel(context.Context, string, string) (string, error) {
	return "", p.err
}
func (p c9UntrustedProvider) SendMessage(context.Context, nfymsg.Message) (*nfymsg.SentMessage, error) {
	return &nfymsg.SentMessage{ExternalID: "safe-correlation-id", State: nfymsg.StateDelivered, StateDetails: p.details}, p.err
}
func (p c9UntrustedProvider) MessageStatus(context.Context, string) (*nfymsg.Status, error) {
	return &nfymsg.Status{State: nfymsg.StateFailedPerm, Details: p.details, Sequence: 4}, p.err
}

func TestC9RegistryProviderBoundaries(t *testing.T) {
	ctx := context.Background()
	for _, raw := range []string{"c9-private-leak@example.invalid", "+15551234567", "https://example.invalid/private/c9-super-secret-token"} {
		for _, cause := range []error{errors.New("failed delivery to " + raw), retry.TemporaryError(errors.New(raw)), validation.WrapError(errors.New(raw)), fmt.Errorf("%s: %w", raw, ErrUnsupported), fmt.Errorf("%s: %w", raw, sql.ErrNoRows)} {
			reg := NewRegistry()
			reg.RegisterProvider(ctx, c9UntrustedProvider{err: cause})
			dest := gadb.NewDestV1("c9-provider", "address", raw)
			_, sendErr := reg.SendMessage(ctx, nfymsg.Test{Base: nfymsg.Base{ID: "safe-id", Dest: dest}})
			_, statusErr := reg.MessageStatus(ctx, dest.Type, "safe-id")
			_, displayErr := reg.DisplayInfo(ctx, dest)
			_, labelErr := reg.FieldLabel(ctx, dest.Type, "address", raw)
			_, searchErr := reg.SearchField(ctx, dest.Type, "address", SearchOptions{})
			for _, err := range []error{sendErr, statusErr, displayErr, labelErr, searchErr, reg.ValidateField(ctx, dest.Type, "address", raw), reg.ValidateDest(ctx, dest)} {
				require.Error(t, err)
				require.NotContains(t, fmt.Sprintf("%+v", err), raw)
			}
			require.Equal(t, retry.IsTemporaryError(cause), retry.IsTemporaryError(sendErr))
			require.Equal(t, validation.IsClientError(cause), validation.IsClientError(sendErr))
			if errors.Is(cause, ErrUnsupported) {
				require.ErrorIs(t, sendErr, ErrUnsupported)
			}
			if errors.Is(cause, sql.ErrNoRows) {
				require.ErrorIs(t, sendErr, sql.ErrNoRows)
				require.True(t, validation.IsClientError(reg.ValidateDest(ctx, dest)))
			}
		}
		reg := NewRegistry()
		reg.RegisterProvider(ctx, c9UntrustedProvider{details: "delivered to " + raw})
		sent, err := reg.SendMessage(ctx, nfymsg.Test{Base: nfymsg.Base{Dest: gadb.NewDestV1("c9-provider", "address", raw)}})
		require.NoError(t, err)
		require.NotContains(t, sent.StateDetails, raw)
		require.Equal(t, "safe-correlation-id", sent.ExternalID)
		require.Equal(t, nfymsg.StateDelivered, sent.State)
		status, err := reg.MessageStatus(ctx, "c9-provider", "safe-correlation-id")
		require.NoError(t, err)
		require.NotContains(t, status.Details, raw)
		require.Equal(t, 4, status.Sequence)
	}
}
