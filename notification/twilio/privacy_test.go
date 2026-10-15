package twilio

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/target/goalert/config"
	"github.com/target/goalert/notification"
	"github.com/target/goalert/notification/nfymsg"
	"github.com/target/goalert/permission"
	"github.com/target/goalert/retry"
	"github.com/target/goalert/util/log"
)

type c9FailTransport struct{}

func (c9FailTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return nil, errors.New("failed dialing " + req.URL.String() + " +15551234567 c9-private-leak@example.invalid")
}

type c9StatusReceiver struct {
	notification.Receiver
	calls int
}

func (r *c9StatusReceiver) SetMessageStatus(context.Context, string, *notification.Status) error {
	r.calls++
	return nil
}

func TestC9TwilioCallbackStructuredLogs(t *testing.T) {
	logger := log.NewLogger()
	logger.EnableJSON()
	logger.EnableDebug()
	var captured bytes.Buffer
	logger.SetOutput(&captured)
	cfg := config.Config{}
	cfg.Twilio.Enable = true
	ctx := cfg.Context(log.WithLogger(context.Background(), logger))
	recv := new(c9StatusReceiver)
	for _, status := range []string{"delivered", "failed to +15551234567"} {
		for _, voice := range []bool{false, true} {
			values := url.Values{"To": {"+15551234567"}, "From": {"+15550001111"}}
			if voice {
				values.Set("CallStatus", status)
				values.Set("CallSid", "CA"+strings.Repeat("a", 32))
			} else {
				values.Set("MessageStatus", status)
				values.Set("MessageSid", "SM"+strings.Repeat("a", 32))
			}
			req := httptest.NewRequest(http.MethodPost, "/callback", strings.NewReader(values.Encode())).WithContext(ctx)
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			response := httptest.NewRecorder()
			if voice {
				v := Voice{r: recv}
				v.ServeStatusCallback(response, req)
			} else {
				s := SMS{r: recv}
				s.ServeStatusCallback(response, req)
			}
			require.Equal(t, http.StatusForbidden, response.Code)
		}
	}
	require.NotContains(t, captured.String(), "+15551234567")
	require.NotContains(t, captured.String(), "Number")
	require.Contains(t, captured.String(), "Twilio provider is disabled")
	require.NotContains(t, captured.String(), "SID")
	require.Zero(t, recv.calls)
}

func TestC9TwilioSDKDiagnostics(t *testing.T) {
	raw := "+15551234567 c9-private-leak@example.invalid https://example.invalid/c9-super-secret-token"
	exception := Exception{Code: 21614, Message: "invalid destination " + raw, MoreInfo: raw}
	for _, format := range []string{"%s", "%v", "%+v", "%#v"} {
		require.NotContains(t, fmt.Sprintf(format, exception), raw)
		require.Contains(t, fmt.Sprintf(format, &exception), "21614")
	}
	msgCode, callCode := MessageErrorCode(21614), CallErrorCode(21614)
	msg := Message{Status: MessageStatusFailed, ErrorCode: &msgCode, ErrorMessage: &raw}
	call := Call{Status: CallStatusFailed, ErrorCode: &callCode, ErrorMessage: &raw}
	for _, status := range []*nfymsg.Status{msg.messageStatus(), call.messageStatus()} {
		require.Equal(t, "failed: [21614]", status.Details)
		require.NotContains(t, status.Details, raw)
	}
	// Retain the upstream transport-error privacy regression independently of
	// the product entry points, which now reject before invoking any transport.
	client := &http.Client{Transport: c9FailTransport{}}
	logger := log.NewLogger()
	logger.EnableJSON()
	logger.EnableDebug()
	var captured bytes.Buffer
	logger.SetOutput(&captured)
	ctx := permission.SystemContext(log.WithLogger(context.Background(), logger), "C9ProviderTest")
	ctx = config.Config{}.Context(ctx)
	req, err := http.NewRequestWithContext(ctx, "GET", "https://example.invalid/c9-super-secret-token", nil)
	require.NoError(t, err)
	_, err = client.Do(req)
	err = nfymsg.ProviderError(err)
	require.Error(t, err)
	require.True(t, retry.IsTemporaryError(err))
	log.Log(ctx, err)
	req, err = http.NewRequestWithContext(ctx, "GET", "https://example.invalid/private/c9-super-secret-token", nil)
	require.NoError(t, err)
	_, err = client.Do(req)
	err = nfymsg.ProviderError(err)
	require.Error(t, err)
	log.Debug(ctx, err)
	for _, secret := range []string{"+15551234567", "c9-private-leak@example.invalid", "c9-super-secret-token"} {
		require.NotContains(t, captured.String(), secret)
		require.NotContains(t, err.Error(), secret)
	}
}
