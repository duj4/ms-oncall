package nfymsg

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/target/goalert/retry"
	"github.com/target/goalert/validation"
)

func TestC9DiagnosticText(t *testing.T) {
	for _, safe := range []string{"", "delivered", "failed: [21614]", "Twilio error code 21614", "webhook request failed: HTTP status 503", "No escalation policy steps", "alerts acked/closed before message sent"} {
		require.Equal(t, safe, DiagnosticText(safe))
	}
	for _, raw := range []string{
		"failed sending SMS to +15551234567", "invalid destination c9-private-leak@example.invalid",
		"webhook https://example.invalid/private/c9-super-secret-token failed",
		"delivered\nc9-private-leak@example.invalid", "failed: [21614] +15551234567",
		"failed: [15551234567]", "webhook request failed: HTTP status 503 c9-super-secret-token",
		"https%3A%2F%2Fexample.invalid%2Fprivate%2Fc9-super-secret-token",
		"destination ending 4567", "provider diagnostic without a known destination",
	} {
		require.Equal(t, "provider details withheld", DiagnosticText(raw))
	}
}

func TestC9ProviderErrorClassificationsAndUnwrap(t *testing.T) {
	raw := errors.New("failed delivery to c9-private-leak@example.invalid +15551234567 https://example.invalid/c9-super-secret-token")
	for _, tc := range []struct {
		name              string
		err               error
		temporary, client bool
		is                error
	}{
		{name: "permanent", err: raw},
		{name: "temporary", err: retry.TemporaryError(raw), temporary: true},
		{name: "network", err: &url.Error{Op: "Post", URL: "https://example.invalid/c9-super-secret-token", Err: raw}, temporary: true},
		{name: "client", err: validation.WrapError(raw), client: true},
		{name: "cancel", err: errors.Join(raw, context.Canceled), is: context.Canceled},
		{name: "timeout", err: errors.Join(raw, context.DeadlineExceeded), is: context.DeadlineExceeded},
	} {
		t.Run(tc.name, func(t *testing.T) {
			safe := ProviderError(tc.err)
			require.Equal(t, tc.temporary, retry.IsTemporaryError(safe))
			require.Equal(t, tc.client, validation.IsClientError(safe))
			if tc.is != nil {
				require.ErrorIs(t, safe, tc.is)
			}
			require.NotErrorIs(t, safe, raw)
			for err := safe; err != nil; err = errors.Unwrap(err) {
				for _, format := range []string{"%s", "%v", "%+v", "%#v"} {
					str := fmt.Sprintf(format, err)
					for _, sentinel := range []string{"c9-private-leak", "+15551234567", "c9-super-secret-token"} {
						require.NotContains(t, str, sentinel)
					}
				}
			}
		})
	}
	for _, reason := range []string{"webhook request failed: HTTP status 503", "Twilio error code 21614"} {
		require.EqualError(t, ProviderError(errors.New(reason)), reason)
	}
	require.NoError(t, ProviderError(nil))
}
