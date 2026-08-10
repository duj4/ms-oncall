package webhook

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/config"
	"github.com/target/goalert/notification"
	"github.com/target/goalert/notification/nfymsg"
	"github.com/target/goalert/retry"
)

const testDeliveryID = "11111111-2222-4333-8444-555555555555"

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

type trackingBody struct {
	io.Reader
	closed     bool
	reachedEOF bool
}

func (b *trackingBody) Read(p []byte) (int, error) {
	n, err := b.Reader.Read(p)
	if errors.Is(err, io.EOF) {
		b.reachedEOF = true
	}
	return n, err
}

func (b *trackingBody) Close() error {
	b.closed = true
	return nil
}

type infiniteTrackingBody struct {
	bytesRead int
	closed    bool
}

func (b *infiniteTrackingBody) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 'x'
	}
	b.bytesRead += len(p)
	return len(p), nil
}

func (b *infiniteTrackingBody) Close() error {
	b.closed = true
	return nil
}

type countingTransport struct {
	base  http.RoundTripper
	calls int32
}

func (t *countingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	atomic.AddInt32(&t.calls, 1)
	return t.base.RoundTrip(req)
}

func testContext() context.Context {
	return (config.Config{}).Context(context.Background())
}

func testMessage(webURL string) notification.Test {
	return notification.Test{
		Base: nfymsg.Base{
			ID:   testDeliveryID,
			Dest: NewWebhookDest(webURL),
		},
	}
}

func testResponse(req *http.Request, status int, body io.ReadCloser) *http.Response {
	return &http.Response{
		StatusCode: status,
		Header:     make(http.Header),
		Body:       body,
		Request:    req,
	}
}

func TestSenderUsesInjectedHTTPClient(t *testing.T) {
	ctx := testContext()
	body := &trackingBody{Reader: strings.NewReader("ignored")}
	var called bool
	client := &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			called = true
			assert.Equal(t, "test", req.URL.Scheme)
			assert.Equal(t, testDeliveryID, req.Header.Get(idempotencyKeyHeader))
			return testResponse(req, http.StatusNoContent, body), nil
		}),
	}

	result, err := NewSender(ctx, client).SendMessage(ctx, testMessage("test://gateway.invalid/hook"))
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, notification.StateSent, result.State)
	assert.True(t, called, "injected HTTP client was not called")
	assert.True(t, body.closed, "response body was not closed")
	assert.True(t, body.reachedEOF, "small response body was not drained to EOF")
}

func TestSenderHTTPStatusAndResponseBody(t *testing.T) {
	const (
		webURL          = "https://gateway.invalid/v1/goalert/contact-method/opaque-secret-token?route=secret-query"
		responseContent = "sensitive-response-content"
	)
	tests := []struct {
		name    string
		status  int
		wantErr bool
	}{
		{name: "200", status: http.StatusOK},
		{name: "204", status: http.StatusNoContent},
		{name: "302", status: http.StatusFound, wantErr: true},
		{name: "400", status: http.StatusBadRequest, wantErr: true},
		{name: "429", status: http.StatusTooManyRequests, wantErr: true},
		{name: "500", status: http.StatusInternalServerError, wantErr: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := testContext()
			body := &trackingBody{Reader: strings.NewReader(responseContent)}
			client := &http.Client{
				Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
					return testResponse(req, test.status, body), nil
				}),
			}

			result, err := NewSender(ctx, client).SendMessage(ctx, testMessage(webURL))
			assert.True(t, body.closed, "response body was not closed")
			assert.True(t, body.reachedEOF, "small response body was not drained to EOF")
			if !test.wantErr {
				require.NoError(t, err)
				require.NotNil(t, result)
				assert.Equal(t, notification.StateSent, result.State)
				return
			}

			require.Error(t, err)
			assert.Nil(t, result)
			assert.Contains(t, err.Error(), strconv.Itoa(test.status))
			assert.NotContains(t, err.Error(), webURL)
			assert.NotContains(t, err.Error(), "opaque-secret-token")
			assert.NotContains(t, err.Error(), "secret-query")
			assert.NotContains(t, err.Error(), responseContent)
		})
	}
}

func TestSenderRejectsRedirectsWithoutMutatingClient(t *testing.T) {
	const responseContent = "sensitive-redirect-response-content"
	tests := []struct {
		name   string
		status int
	}{
		{name: "301", status: http.StatusMovedPermanently},
		{name: "302", status: http.StatusFound},
		{name: "303", status: http.StatusSeeOther},
		{name: "307 method preserving", status: http.StatusTemporaryRedirect},
		{name: "308 method preserving", status: http.StatusPermanentRedirect},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var targetRequests int32
			target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				atomic.AddInt32(&targetRequests, 1)
			}))
			defer target.Close()

			var sourceRequests int32
			source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				atomic.AddInt32(&sourceRequests, 1)
				assert.Equal(t, http.MethodPost, req.Method)
				w.Header().Set("Location", target.URL+"/opaque-target-token?route=secret-target-query")
				w.WriteHeader(test.status)
				_, _ = io.WriteString(w, responseContent)
			}))
			defer source.Close()

			transport := &countingTransport{base: http.DefaultTransport}
			var originalPolicyCalls int32
			originalPolicy := func(*http.Request, []*http.Request) error {
				atomic.AddInt32(&originalPolicyCalls, 1)
				return nil
			}
			client := &http.Client{
				Transport:     transport,
				CheckRedirect: originalPolicy,
				Timeout:       2 * time.Second,
			}

			result, err := NewSender(testContext(), client).SendMessage(testContext(), testMessage(source.URL+"/opaque-source-token?route=secret-source-query"))
			require.Error(t, err)
			assert.Nil(t, result)
			assert.Contains(t, err.Error(), strconv.Itoa(test.status))
			assert.Equal(t, int32(1), atomic.LoadInt32(&sourceRequests))
			assert.Equal(t, int32(0), atomic.LoadInt32(&targetRequests), "redirect target must not receive a request")
			assert.Equal(t, int32(1), atomic.LoadInt32(&transport.calls))
			assert.Same(t, transport, client.Transport)
			assert.Equal(t, 2*time.Second, client.Timeout)
			assert.Equal(t, int32(0), atomic.LoadInt32(&originalPolicyCalls), "injected redirect policy must not run during delivery")
			require.NoError(t, client.CheckRedirect(nil, nil), "sender must not mutate the injected client")
			assert.Equal(t, int32(1), atomic.LoadInt32(&originalPolicyCalls))

			for _, secret := range []string{
				source.URL,
				target.URL,
				"opaque-source-token",
				"opaque-target-token",
				"secret-source-query",
				"secret-target-query",
				responseContent,
			} {
				assert.NotContains(t, err.Error(), secret)
			}
		})
	}
}

func TestSenderResponseBodyDrainIsBounded(t *testing.T) {
	body := new(infiniteTrackingBody)
	client := &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return testResponse(req, http.StatusOK, body), nil
		}),
	}

	result, err := NewSender(testContext(), client).SendMessage(testContext(), testMessage("test://gateway.invalid/hook"))
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, notification.StateSent, result.State)
	assert.True(t, body.closed)
	assert.Equal(t, maxResponseBodyDrainBytes, body.bytesRead)
}

func TestSenderSanitizesConnectionError(t *testing.T) {
	const (
		webURL        = "https://gateway.invalid/v1/goalert/contact-method/opaque-secret-token?route=secret-query"
		requestSecret = "sensitive-request-content"
	)
	ctx := testContext()
	client := &http.Client{
		Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return nil, errors.New("dial failed for " + webURL + ": sensitive-response-content")
		}),
	}
	msg := notification.Verification{
		Base: nfymsg.Base{
			ID:   testDeliveryID,
			Dest: NewWebhookDest(webURL),
		},
		Code: requestSecret,
	}

	result, err := NewSender(ctx, client).SendMessage(ctx, msg)
	require.Error(t, err)
	assert.Nil(t, result)
	assert.Equal(t, "webhook request failed", err.Error())
	assert.True(t, retry.IsTemporaryError(err), "connection errors must retain their existing retry classification")
	assert.NotContains(t, err.Error(), "opaque-secret-token")
	assert.NotContains(t, err.Error(), "secret-query")
	assert.NotContains(t, err.Error(), requestSecret)
	assert.NotContains(t, err.Error(), "sensitive-response-content")
}

func TestSenderRejectsMissingDeliveryIdentity(t *testing.T) {
	const (
		webURL        = "https://gateway.invalid/v1/goalert/contact-method/opaque-secret-token?route=secret-query"
		requestSecret = "sensitive-request-content"
	)
	ctx := testContext()
	client := &http.Client{
		Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			t.Fatal("HTTP client must not be called without a delivery identity")
			return nil, nil
		}),
	}
	msg := notification.Verification{
		Base: nfymsg.Base{
			Dest: NewWebhookDest(webURL),
		},
		Code: requestSecret,
	}

	result, err := NewSender(ctx, client).SendMessage(ctx, msg)
	require.Error(t, err)
	assert.Nil(t, result)
	assert.Equal(t, "webhook delivery identity is required", err.Error())
	assert.NotContains(t, err.Error(), webURL)
	assert.NotContains(t, err.Error(), "opaque-secret-token")
	assert.NotContains(t, err.Error(), "secret-query")
	assert.NotContains(t, err.Error(), requestSecret)
}

func TestSenderAlertStatusWireState(t *testing.T) {
	const webURL = "test://gateway.invalid/v1/goalert/contact-method/opaque-secret-token?route=secret-query"
	tests := []struct {
		name      string
		state     notification.AlertState
		logEntry  string
		wireState string
		wantBody  string
	}{
		{
			name:      "acknowledged",
			state:     notification.AlertStateAcknowledged,
			logEntry:  "误导文本：已关闭",
			wireState: "Acknowledged",
			wantBody:  `{"AppName":"GoAlert","Type":"AlertStatus","AlertID":42,"LogEntry":"误导文本：已关闭","AlertState":"Acknowledged"}`,
		},
		{
			name:      "closed",
			state:     notification.AlertStateClosed,
			logEntry:  "Misleading: acknowledged",
			wireState: "Closed",
			wantBody:  `{"AppName":"GoAlert","Type":"AlertStatus","AlertID":42,"LogEntry":"Misleading: acknowledged","AlertState":"Closed"}`,
		},
		{
			name:      "unacknowledged",
			state:     notification.AlertStateUnacknowledged,
			logEntry:  "Texte localisé sans état",
			wireState: "Unacknowledged",
			wantBody:  `{"AppName":"GoAlert","Type":"AlertStatus","AlertID":42,"LogEntry":"Texte localisé sans état","AlertState":"Unacknowledged"}`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := testContext()
			var requestCount int
			client := &http.Client{
				Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
					requestCount++
					assert.Equal(t, testDeliveryID, req.Header.Get(idempotencyKeyHeader))
					body, err := io.ReadAll(req.Body)
					require.NoError(t, err)
					assert.Equal(t, test.wantBody, string(body))
					assert.NotContains(t, string(body), "NewAlertState")

					var decoded map[string]interface{}
					require.NoError(t, json.Unmarshal(body, &decoded))
					require.Len(t, decoded, 5)
					assert.Equal(t, test.wireState, decoded["AlertState"])
					_, isString := decoded["AlertState"].(string)
					assert.True(t, isString, "AlertState must be encoded as a JSON string")

					return testResponse(req, http.StatusAccepted, io.NopCloser(strings.NewReader("ignored"))), nil
				}),
			}
			msg := notification.AlertStatus{
				Base: nfymsg.Base{
					ID:   testDeliveryID,
					Dest: NewWebhookDest(webURL),
				},
				AlertID:       42,
				LogEntry:      test.logEntry,
				NewAlertState: test.state,
			}

			result, err := NewSender(ctx, client).SendMessage(ctx, msg)
			require.NoError(t, err)
			require.NotNil(t, result)
			assert.Equal(t, notification.StateSent, result.State)
			assert.Equal(t, 1, requestCount)
		})
	}
}

func TestSenderRejectsInvalidAlertStateBeforeRequest(t *testing.T) {
	const (
		webURL  = "https://gateway.invalid/v1/goalert/contact-method/opaque-secret-token?route=secret-query"
		logText = "sensitive localized log entry"
	)
	tests := []struct {
		name  string
		state notification.AlertState
	}{
		{name: "unknown", state: notification.AlertStateUnknown},
		{name: "out of range", state: notification.AlertState(99)},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := testContext()
			client := &http.Client{
				Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
					t.Fatal("HTTP client must not be called for an invalid alert state")
					return nil, nil
				}),
			}
			msg := notification.AlertStatus{
				Base: nfymsg.Base{
					ID:   testDeliveryID,
					Dest: NewWebhookDest(webURL),
				},
				AlertID:       42,
				LogEntry:      logText,
				NewAlertState: test.state,
			}

			result, err := NewSender(ctx, client).SendMessage(ctx, msg)
			require.Error(t, err)
			assert.Nil(t, result)
			assert.Equal(t, "webhook alert state is invalid", err.Error())
			assert.NotContains(t, err.Error(), webURL)
			assert.NotContains(t, err.Error(), "opaque-secret-token")
			assert.NotContains(t, err.Error(), "secret-query")
			assert.NotContains(t, err.Error(), logText)
		})
	}
}

func TestSenderContextFailure(t *testing.T) {
	const webURL = "https://gateway.invalid/v1/goalert/contact-method/opaque-secret-token?route=secret-query"
	client := &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			<-req.Context().Done()
			return nil, req.Context().Err()
		}),
	}

	t.Run("canceled", func(t *testing.T) {
		ctx, cancel := context.WithCancel(testContext())
		cancel()

		result, err := NewSender(ctx, client).SendMessage(ctx, testMessage(webURL))
		require.Error(t, err)
		assert.Nil(t, result)
		assert.ErrorIs(t, err, context.Canceled)
		assert.False(t, retry.IsTemporaryError(err), "cancellation must retain its existing retry classification")
		assert.NotContains(t, err.Error(), "opaque-secret-token")
		assert.NotContains(t, err.Error(), "secret-query")
	})

	t.Run("timeout", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(testContext(), 10*time.Millisecond)
		defer cancel()

		result, err := NewSender(ctx, client).SendMessage(ctx, testMessage(webURL))
		require.Error(t, err)
		assert.Nil(t, result)
		assert.ErrorIs(t, err, context.DeadlineExceeded)
		assert.False(t, retry.IsTemporaryError(err), "deadline failures must retain their existing retry classification")
		assert.NotContains(t, err.Error(), "opaque-secret-token")
		assert.NotContains(t, err.Error(), "secret-query")
	})
}

func TestSenderSanitizesRequestConstructionError(t *testing.T) {
	const webURL = "https://gateway.invalid/opaque-secret-token\n?route=secret-query"
	ctx := testContext()
	client := &http.Client{
		Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			t.Fatal("HTTP client must not be called for an invalid request URL")
			return nil, nil
		}),
	}

	result, err := NewSender(ctx, client).SendMessage(ctx, testMessage(webURL))
	require.Error(t, err)
	assert.Nil(t, result)
	assert.Equal(t, "webhook request could not be created", err.Error())
	assert.NotContains(t, err.Error(), "opaque-secret-token")
	assert.NotContains(t, err.Error(), "secret-query")
}
