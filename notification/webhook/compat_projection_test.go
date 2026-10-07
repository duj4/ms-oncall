package webhook

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/config"
	"github.com/target/goalert/notification"
	"github.com/target/goalert/notification/nfymsg"
)

type recordingGatewaySigner struct {
	*GatewaySigner
	bodies [][]byte
}

func (s *recordingGatewaySigner) SignRequest(ctx context.Context, req *http.Request, body []byte) (bool, error) {
	s.bodies = append(s.bodies, append([]byte(nil), body...))
	return s.GatewaySigner.SignRequest(ctx, req, body)
}

func projectionTestSigner(t *testing.T) *recordingGatewaySigner {
	t.Helper()
	source := &testGatewayCredentialSource{credential: testGatewayCredential(t)}
	return &recordingGatewaySigner{GatewaySigner: testGatewaySigner(t, source,
		bytes.NewReader(bytes.Repeat([]byte{0x11}, 256)), func() time.Time {
			return time.Unix(1700000000, 0)
		})}
}

func projectionTestContext() context.Context {
	var cfg config.Config
	cfg.General.ApplicationName = "MS OnCall"
	cfg.General.PublicURL = "https://core.test.invalid/base"
	return cfg.Context(context.Background())
}

type projectionCase struct {
	name     string
	msg      notification.Message
	ordinary map[string]interface{}
	gateway  map[string]interface{}
}

// Expected objects are independent wire fixtures, checked against the exact
// v0.35 sender and frozen Gateway V1 decoder, not the production wire structs.
func projectionCases(target string) []projectionCase {
	base := nfymsg.Base{ID: testDeliveryID, Dest: NewWebhookDest(target)}
	serviceID := "123e4567-e89b-12d3-a456-426614174000"
	meta := map[string]string{"severity": "critical", "link": "雪<&>"}
	alert := notification.Alert{
		Base: base, AlertID: 42, Summary: "Incident <&> \"雪\"", Details: "Line 1\nLine 2",
		ServiceID: serviceID, ServiceName: "Sample Service", Meta: meta,
	}
	ordinaryAlert := map[string]interface{}{
		"AppName": "MS OnCall", "Type": "Alert", "AlertID": 42, "Summary": alert.Summary,
		"Details": alert.Details, "ServiceID": serviceID, "ServiceName": alert.ServiceName,
		"Meta": meta, "GoAlertURL": "https://core.test.invalid/base/alerts/42",
	}
	gatewayAlert := map[string]interface{}{
		"AppName": "MS OnCall", "Type": "Alert", "AlertID": 42, "Summary": alert.Summary,
		"Details": alert.Details, "ServiceID": serviceID, "ServiceName": alert.ServiceName, "Meta": meta,
	}
	cases := []projectionCase{
		{"Test", notification.Test{Base: base},
			map[string]interface{}{"AppName": "MS OnCall", "Type": "Test"},
			map[string]interface{}{"AppName": "MS OnCall", "Type": "Test"}},
		{"Verification", notification.Verification{Base: base, Code: "123456"},
			map[string]interface{}{"AppName": "MS OnCall", "Type": "Verification", "Code": "123456"},
			map[string]interface{}{"AppName": "MS OnCall", "Type": "Verification", "Code": "123456"}},
		{"Alert", alert, ordinaryAlert, gatewayAlert},
		{"AlertBundle", notification.AlertBundle{Base: base, ServiceID: serviceID, ServiceName: "Sample Service", Count: 3},
			map[string]interface{}{
				"AppName": "MS OnCall", "Type": "AlertBundle", "ServiceID": serviceID,
				"ServiceName": "Sample Service", "Count": 3,
				"GoAlertURL": "https://core.test.invalid/base/services/" + serviceID + "/alerts",
			}, nil},
		{"ScheduleOnCallUsers", notification.ScheduleOnCallUsers{
			Base: base, ScheduleID: serviceID, ScheduleName: "Primary",
			ScheduleURL: "https://core.test.invalid/schedules/primary",
			Users:       []notification.User{{ID: serviceID, Name: "Sample User", URL: "https://core.test.invalid/users/sample"}},
		}, map[string]interface{}{
			"AppName": "MS OnCall", "Type": "ScheduleOnCallUsers", "ScheduleID": serviceID,
			"ScheduleName": "Primary", "ScheduleURL": "https://core.test.invalid/schedules/primary",
			"Users": []map[string]string{{"ID": serviceID, "Name": "Sample User", "URL": "https://core.test.invalid/users/sample"}},
		}, nil},
	}
	for _, state := range []struct {
		state notification.AlertState
		wire  string
	}{
		{notification.AlertStateUnacknowledged, "Unacknowledged"},
		{notification.AlertStateAcknowledged, "Acknowledged"},
		{notification.AlertStateClosed, "Closed"},
	} {
		status := notification.AlertStatus{
			Base: base, AlertID: 42, Summary: alert.Summary, Details: alert.Details,
			ServiceID: serviceID, ServiceName: alert.ServiceName, Meta: meta,
			LogEntry: "Localized log: 已关闭 <&>", NewAlertState: state.state,
		}
		cases = append(cases, projectionCase{
			"AlertStatus/" + state.wire, status,
			map[string]interface{}{
				"AppName": "MS OnCall", "Type": "AlertStatus", "AlertID": 42,
				"Summary": status.Summary, "Details": status.Details, "ServiceID": serviceID,
				"ServiceName": status.ServiceName, "Meta": meta, "LogEntry": status.LogEntry,
				"GoAlertURL": "https://core.test.invalid/base/alerts/42",
			},
			map[string]interface{}{
				"AppName": "MS OnCall", "Type": "AlertStatus", "AlertID": 42,
				"LogEntry": status.LogEntry, "AlertState": state.wire,
			},
		})
	}
	return cases
}

func assertProjectionJSON(t *testing.T, want map[string]interface{}, body []byte) {
	t.Helper()
	expected, err := json.Marshal(want)
	require.NoError(t, err)
	assert.JSONEq(t, string(expected), string(body))
}

// This verifier independently reconstructs the frozen Gateway signing input
// from the captured HTTP bytes; it does not call gatewaySigningInput.
func capturedGatewaySignatureValid(req *http.Request, body []byte) bool {
	prefix := "MSOnCall-HMAC-SHA256 Credential=" + testOnlyCredentialID + ", Signature="
	authorization := req.Header.Get("Authorization")
	if !strings.HasPrefix(authorization, prefix) {
		return false
	}
	signature, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(authorization, prefix))
	if err != nil {
		return false
	}
	digest := sha256.Sum256(body)
	input := strings.Join([]string{
		"MS_ONCALL_GATEWAY_REQUEST_V1", testOnlyAudienceID, "POST", req.URL.EscapedPath(),
		testOnlyCredentialID, req.Header.Get("Idempotency-Key"),
		req.Header.Get("X-MS-OnCall-Timestamp"), req.Header.Get("X-MS-OnCall-Nonce"),
		hex.EncodeToString(digest[:]),
	}, "\n")
	mac := hmac.New(sha256.New, testOnlySecretMaterial)
	_, _ = mac.Write([]byte(input))
	return hmac.Equal(mac.Sum(nil), signature)
}

func TestSenderOrdinaryUpstreamV035EventMatrix(t *testing.T) {
	for _, fixture := range projectionCases("https://hooks.test.invalid/notify") {
		t.Run(fixture.name, func(t *testing.T) {
			signer := projectionTestSigner(t)
			calls := 0
			client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				calls++
				body, err := io.ReadAll(req.Body)
				require.NoError(t, err)
				assertProjectionJSON(t, fixture.ordinary, body)
				assert.NotNil(t, req.GetBody)
				for _, header := range []string{gatewayAuthorizationHeader, gatewayTimestampHeader, gatewayNonceHeader} {
					assert.Empty(t, req.Header.Values(header))
				}
				return testResponse(req, http.StatusAccepted, io.NopCloser(strings.NewReader(""))), nil
			})}
			result, err := NewSenderWithGatewaySigner(projectionTestContext(), client, signer).
				SendMessage(projectionTestContext(), fixture.msg)
			require.NoError(t, err)
			require.NotNil(t, result)
			assert.Equal(t, notification.StateSent, result.State)
			assert.Equal(t, 1, calls)
			assert.Empty(t, signer.bodies)
			assert.Equal(t, int32(0), atomic.LoadInt32(&signer.source.(*testGatewayCredentialSource).calls))
		})
	}
}

func TestSenderGatewayV1EventMatrixAndFinalBytes(t *testing.T) {
	for _, fixture := range projectionCases(testOnlyGatewayURL) {
		t.Run(fixture.name, func(t *testing.T) {
			signer := projectionTestSigner(t)
			before, err := json.Marshal(fixture.msg)
			require.NoError(t, err)
			calls := 0
			client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				calls++
				require.NotNil(t, fixture.gateway, "unsupported events must not reach HTTP")
				body, err := io.ReadAll(req.Body)
				require.NoError(t, err)
				assertProjectionJSON(t, fixture.gateway, body)
				require.Len(t, signer.bodies, 1)
				assert.Equal(t, signer.bodies[0], body, "SignRequest bytes must be transmitted unchanged")
				assert.True(t, capturedGatewaySignatureValid(req, body))
				changed := append([]byte(nil), body...)
				changed[len(changed)-1] ^= 1
				assert.False(t, capturedGatewaySignatureValid(req, changed), "a one-byte change must invalidate HMAC")
				assert.Nil(t, req.GetBody)
				deadline, ok := req.Context().Deadline()
				require.True(t, ok)
				assert.InDelta(t, 3.0, time.Until(deadline).Seconds(), 0.1)
				assert.Equal(t, testDeliveryID, req.Header.Get(idempotencyKeyHeader))
				assert.Equal(t, "application/json", req.Header.Get("Content-Type"))
				return testResponse(req, http.StatusAccepted, io.NopCloser(strings.NewReader(""))), nil
			})}
			result, err := NewSenderWithGatewaySigner(projectionTestContext(), client, signer).
				SendMessage(projectionTestContext(), fixture.msg)
			require.NoError(t, err)
			require.NotNil(t, result)
			if fixture.gateway == nil {
				assert.Equal(t, notification.StateFailedPerm, result.State)
				assert.Equal(t, "gateway message type is not supported", result.StateDetails)
				assert.Zero(t, calls)
				assert.Empty(t, signer.bodies, "unsupported projection must not call SignRequest")
				assert.Zero(t, atomic.LoadInt32(&signer.source.(*testGatewayCredentialSource).calls))
			} else {
				assert.Equal(t, notification.StateSent, result.State)
				assert.Equal(t, 1, calls)
			}
			after, err := json.Marshal(fixture.msg)
			require.NoError(t, err)
			assert.Equal(t, before, after, "projection must not mutate the message")
		})
	}
}

func TestSenderGatewayNearMatchesUseOrdinaryPayload(t *testing.T) {
	targets := map[string]string{
		"scheme":            "http://gateway.test.invalid" + testOnlyGatewayPath,
		"host":              "https://other.test.invalid" + testOnlyGatewayPath,
		"subdomain":         "https://sub.gateway.test.invalid" + testOnlyGatewayPath,
		"port":              testOnlyGatewayOrigin + ":444" + testOnlyGatewayPath,
		"query":             testOnlyGatewayURL + "?test=1",
		"bare query":        testOnlyGatewayURL + "?",
		"fragment":          testOnlyGatewayURL + "#fragment",
		"userinfo":          "https://test-user@gateway.test.invalid" + testOnlyGatewayPath,
		"malformed token":   testOnlyGatewayOrigin + gatewayContactMethodPathPrefix + "mso1_invalid",
		"path lookalike":    testOnlyGatewayOrigin + strings.Replace(testOnlyGatewayPath, "contact-method", "contact-methods", 1),
		"extra path":        testOnlyGatewayURL + "/extra",
		"escaped slash":     testOnlyGatewayOrigin + strings.Replace(testOnlyGatewayPath, "/v1/", "/v1%2f", 1),
		"escaped token":     testOnlyGatewayOrigin + strings.Replace(testOnlyGatewayPath, "mso1_", "%6dso1_", 1),
		"noncanonical port": testOnlyGatewayOrigin + ":0443" + testOnlyGatewayPath,
	}
	for name, target := range targets {
		t.Run(name, func(t *testing.T) {
			signer := projectionTestSigner(t)
			u, err := url.Parse(target)
			require.NoError(t, err)
			_, matched := signer.matcher.Match(u)
			require.False(t, matched, "fixture must exercise the accepted ordinary boundary")
			for _, fixture := range projectionCases(target) {
				t.Run(fixture.name, func(t *testing.T) {
					client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
						body, err := io.ReadAll(req.Body)
						require.NoError(t, err)
						assertProjectionJSON(t, fixture.ordinary, body)
						// net/http retains upstream Basic auth for URL userinfo.
						// No near match may acquire Gateway authentication.
						assert.NotContains(t, req.Header.Get(gatewayAuthorizationHeader), "MSOnCall-HMAC-SHA256")
						for _, header := range []string{gatewayTimestampHeader, gatewayNonceHeader} {
							assert.Empty(t, req.Header.Values(header))
						}
						return testResponse(req, http.StatusNoContent, io.NopCloser(strings.NewReader(""))), nil
					})}
					result, err := NewSenderWithGatewaySigner(projectionTestContext(), client, signer).
						SendMessage(projectionTestContext(), fixture.msg)
					require.NoError(t, err)
					assert.Equal(t, notification.StateSent, result.State)
				})
			}
			assert.Empty(t, signer.bodies)
			assert.Zero(t, atomic.LoadInt32(&signer.source.(*testGatewayCredentialSource).calls))
		})
	}
}

func TestSenderGatewayRetryKeepsIdentityAndRefreshesAuthentication(t *testing.T) {
	source := &testGatewayCredentialSource{credential: testGatewayCredential(t)}
	var tick int64
	signer := &recordingGatewaySigner{GatewaySigner: testGatewaySigner(t, source,
		bytes.NewReader(append(bytes.Repeat([]byte{0x11}, 16), bytes.Repeat([]byte{0x22}, 16)...)),
		func() time.Time { return time.Unix(1700000000+atomic.AddInt64(&tick, 1), 0) })}
	var requests []*http.Request
	var bodies [][]byte
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		body, err := io.ReadAll(req.Body)
		require.NoError(t, err)
		assert.True(t, capturedGatewaySignatureValid(req, body))
		assert.Nil(t, req.GetBody)
		requests = append(requests, req)
		bodies = append(bodies, body)
		status := http.StatusServiceUnavailable
		if len(requests) == 2 {
			status = http.StatusAccepted
		}
		return testResponse(req, status, io.NopCloser(strings.NewReader(""))), nil
	})}
	sender := NewSenderWithGatewaySigner(projectionTestContext(), client, signer)
	msg := projectionCases(testOnlyGatewayURL)[2].msg
	result, err := sender.SendMessage(projectionTestContext(), msg)
	require.Error(t, err)
	require.Nil(t, result)
	result, err = sender.SendMessage(projectionTestContext(), msg)
	require.NoError(t, err)
	assert.Equal(t, notification.StateSent, result.State)
	require.Len(t, requests, 2)
	assert.Equal(t, bodies[0], bodies[1])
	assert.Equal(t, signer.bodies, bodies)
	for _, req := range requests {
		assert.Equal(t, testDeliveryID, req.Header.Get(idempotencyKeyHeader))
	}
	for _, header := range []string{gatewayAuthorizationHeader, gatewayTimestampHeader, gatewayNonceHeader} {
		assert.NotEqual(t, requests[0].Header.Get(header), requests[1].Header.Get(header))
	}
}

func TestSenderGatewayMetaIsAnObjectWithoutChangingMessage(t *testing.T) {
	for _, meta := range []map[string]string{nil, {}, {"severity": "critical"}} {
		for _, gateway := range []bool{false, true} {
			target := "https://hooks.test.invalid/notify"
			if gateway {
				target = testOnlyGatewayURL
			}
			msg := projectionCases(target)[2].msg.(notification.Alert)
			msg.Meta = meta
			signer := projectionTestSigner(t)
			client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				body, err := io.ReadAll(req.Body)
				require.NoError(t, err)
				var payload map[string]json.RawMessage
				require.NoError(t, json.Unmarshal(body, &payload))
				if gateway && len(meta) == 0 {
					assert.Equal(t, "{}", string(payload["Meta"]))
				} else {
					expected, err := json.Marshal(meta)
					require.NoError(t, err)
					assert.Equal(t, string(expected), string(payload["Meta"]))
				}
				return testResponse(req, http.StatusOK, io.NopCloser(strings.NewReader(""))), nil
			})}
			result, err := NewSenderWithGatewaySigner(projectionTestContext(), client, signer).
				SendMessage(projectionTestContext(), msg)
			require.NoError(t, err)
			assert.Equal(t, notification.StateSent, result.State)
			assert.Equal(t, meta, msg.Meta)
		}
	}
}

type refusingGatewaySigner struct {
	*GatewaySigner
	err error
}

func (s refusingGatewaySigner) SignRequest(context.Context, *http.Request, []byte) (bool, error) {
	return false, s.err
}

func TestSenderRecognizedGatewayCannotBeSentUnsigned(t *testing.T) {
	for _, signingErr := range []error{nil, errors.New("gateway signing unavailable")} {
		signer := refusingGatewaySigner{GatewaySigner: projectionTestSigner(t).GatewaySigner, err: signingErr}
		client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			t.Fatal("recognized Gateway must never be transmitted unsigned")
			return nil, nil
		})}
		result, err := NewSenderWithGatewaySigner(testContext(), client, signer).
			SendMessage(testContext(), testMessage(testOnlyGatewayURL))
		require.Error(t, err)
		assert.Nil(t, result)
	}
}

func TestSenderUnsupportedGatewayMessageAndInvalidClassifierFailClosed(t *testing.T) {
	signer := projectionTestSigner(t)
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("unsupported message or invalid classifier must not reach HTTP")
		return nil, nil
	})}
	msg := nfymsg.SignalMessage{Base: testMessage(testOnlyGatewayURL).Base}
	result, err := NewSenderWithGatewaySigner(testContext(), client, signer).SendMessage(testContext(), msg)
	require.NoError(t, err)
	assert.Equal(t, notification.StateFailedPerm, result.State)
	assert.Empty(t, signer.bodies)
	for _, invalid := range []*GatewaySigner{nil, {}} {
		result, err = NewSenderWithGatewaySigner(testContext(), client, invalid).
			SendMessage(testContext(), testMessage(testOnlyGatewayURL))
		require.ErrorIs(t, err, errGatewaySigningInvalid)
		assert.Nil(t, result)
	}
}

func TestSenderSignedGatewayRejectsRedirectAndBoundsDrain(t *testing.T) {
	signer := projectionTestSigner(t)
	body := new(infiniteTrackingBody)
	calls := 0
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		calls++
		require.Equal(t, 1, calls, "Gateway authentication must not follow redirects")
		assert.NotEmpty(t, req.Header.Get(gatewayAuthorizationHeader))
		response := testResponse(req, http.StatusTemporaryRedirect, body)
		response.Header.Set("Location", "https://other.test.invalid/redirect")
		return response, nil
	})}
	result, err := NewSenderWithGatewaySigner(testContext(), client, signer).
		SendMessage(testContext(), testMessage(testOnlyGatewayURL))
	require.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "307")
	assert.NotContains(t, err.Error(), testOnlyGatewayURL)
	assert.NotContains(t, err.Error(), testOnlyGatewayToken)
	assert.True(t, body.closed)
	assert.Equal(t, 32<<10, body.bytesRead)
	assert.Equal(t, 1, calls)
}
