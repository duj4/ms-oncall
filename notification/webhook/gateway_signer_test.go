package webhook

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/retry"
)

const (
	testOnlyAudienceID    = "123e4567-e89b-12d3-a456-426614174000"
	testOnlyCredentialID  = "01234567-89ab-4def-8123-456789abcdef"
	testOnlyTimestamp     = "1700000000"
	testOnlyNonce         = "EBESExQVFhcYGRobHB0eHw"
	testOnlyBody          = `{"AppName":"GoAlert","Type":"Test"}`
	testOnlyBodyDigest    = "a31863e52c5bb004054421a191fd6c1f0f7184bf92312a03e4b5eae298a2a2f1"
	testOnlySignature     = "Lmxexoh8H9V0wAtro_hqBgRr0XoJnA8yVZW0Ug3MtBk"
	testOnlyAuthorization = "MSOnCall-HMAC-SHA256 Credential=" + testOnlyCredentialID +
		", Signature=" + testOnlySignature
	testOnlySigningInput = "MS_ONCALL_GATEWAY_REQUEST_V1\n" +
		testOnlyAudienceID + "\nPOST\n" + testOnlyGatewayPath + "\n" +
		testOnlyCredentialID + "\n" + testDeliveryID + "\n" +
		testOnlyTimestamp + "\n" + testOnlyNonce + "\n" + testOnlyBodyDigest
)

var testOnlySecretMaterial = []byte{
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
	0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
	0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
}

type testGatewayCredentialSource struct {
	credential GatewayCredential
	err        error
	calls      int32
}

func (s *testGatewayCredentialSource) GatewayCredential(context.Context) (GatewayCredential, error) {
	atomic.AddInt32(&s.calls, 1)
	return s.credential, s.err
}

type errorReader struct{ err error }

func (r errorReader) Read([]byte) (int, error) { return 0, r.err }

func testGatewayCredential(t *testing.T) GatewayCredential {
	t.Helper()
	credential, err := NewGatewayCredential(testOnlyCredentialID, testOnlySecretMaterial)
	require.NoError(t, err)
	return credential
}

func testGatewaySigner(t *testing.T, source GatewayCredentialSource, random io.Reader, now func() time.Time) *GatewaySigner {
	t.Helper()
	matcher, err := NewGatewayTargetMatcher(testOnlyGatewayOrigin)
	require.NoError(t, err)
	signer, err := NewGatewaySignerWithSources(matcher, testOnlyAudienceID, source, now, random)
	require.NoError(t, err)
	return signer
}

func testGatewayRequest(t *testing.T, target string, body []byte) *http.Request {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, target, bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set(idempotencyKeyHeader, testDeliveryID)
	return req
}

func TestGatewaySignerGoldenVector(t *testing.T) {
	source := &testGatewayCredentialSource{credential: testGatewayCredential(t)}
	nonceBytes := append([]byte(nil), testOnlySecretMaterial[16:]...)
	signer := testGatewaySigner(t, source, bytes.NewReader(nonceBytes), func() time.Time {
		return time.Unix(1700000000, 999999999)
	})
	req := testGatewayRequest(t, testOnlyGatewayURL, []byte(testOnlyBody))

	signed, err := signer.SignRequest(context.Background(), req, []byte(testOnlyBody))
	require.NoError(t, err)
	assert.True(t, signed)

	digest := sha256.Sum256([]byte(testOnlyBody))
	assert.Equal(t, testOnlyBodyDigest, hex.EncodeToString(digest[:]))
	assert.Equal(t, testOnlySigningInput, gatewaySigningInput(
		testOnlyAudienceID,
		testOnlyGatewayPath,
		testOnlyCredentialID,
		testDeliveryID,
		testOnlyTimestamp,
		testOnlyNonce,
		[]byte(testOnlyBody),
	))
	assert.Equal(t, testOnlyTimestamp, req.Header.Get(gatewayTimestampHeader))
	assert.Equal(t, testOnlyNonce, req.Header.Get(gatewayNonceHeader))
	assert.Equal(t, testOnlyAuthorization, req.Header.Get(gatewayAuthorizationHeader))
	assert.Len(t, req.Header.Values(gatewayAuthorizationHeader), 1)
	assert.Len(t, req.Header.Values(gatewayTimestampHeader), 1)
	assert.Len(t, req.Header.Values(gatewayNonceHeader), 1)
	assert.Equal(t, int32(1), atomic.LoadInt32(&source.calls))
}

func TestGatewaySignerNearMatchesRemainUnsigned(t *testing.T) {
	source := &testGatewayCredentialSource{credential: testGatewayCredential(t)}
	signer := testGatewaySigner(t, source, bytes.NewReader(make([]byte, 16)), time.Now)
	targets := []string{
		"https://hooks.test.invalid/notify",
		"http://gateway.test.invalid" + testOnlyGatewayPath,
		"https://gateway.test.invalid:444" + testOnlyGatewayPath,
		"https://gateway.test.invalid" + testOnlyGatewayPath + "?test=1",
		"https://sub.gateway.test.invalid" + testOnlyGatewayPath,
	}

	for _, target := range targets {
		req := testGatewayRequest(t, target, []byte(testOnlyBody))
		signed, err := signer.SignRequest(context.Background(), req, []byte(testOnlyBody))
		require.NoError(t, err)
		assert.False(t, signed)
		assert.Empty(t, req.Header.Values(gatewayAuthorizationHeader))
		assert.Empty(t, req.Header.Values(gatewayTimestampHeader))
		assert.Empty(t, req.Header.Values(gatewayNonceHeader))
	}
	assert.Equal(t, int32(0), atomic.LoadInt32(&source.calls))
}

func TestGatewaySignerFailuresArePreRequestAndRedacted(t *testing.T) {
	marker := "test-only-sensitive-provider-marker"
	validCredential := testGatewayCredential(t)
	tests := []struct {
		name   string
		source GatewayCredentialSource
		random io.Reader
		ctx    context.Context
		temp   bool
	}{
		{name: "credential source", source: &testGatewayCredentialSource{err: errors.New(marker)}, random: bytes.NewReader(make([]byte, 16)), temp: true},
		{name: "random source", source: &testGatewayCredentialSource{credential: validCredential}, random: errorReader{err: errors.New(marker)}, temp: true},
		{name: "malformed credential", source: &testGatewayCredentialSource{}, random: bytes.NewReader(make([]byte, 16))},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := test.ctx
			if ctx == nil {
				ctx = context.Background()
			}
			signer := testGatewaySigner(t, test.source, test.random, time.Now)
			req := testGatewayRequest(t, testOnlyGatewayURL, []byte(testOnlyBody))
			signed, err := signer.SignRequest(ctx, req, []byte(testOnlyBody))
			require.Error(t, err)
			assert.False(t, signed)
			assert.Equal(t, test.temp, retry.IsTemporaryError(err))
			assert.NotContains(t, err.Error(), marker)
			assert.False(t, errors.Is(err, test.source.(*testGatewayCredentialSource).err))
			assert.Empty(t, req.Header.Values(gatewayAuthorizationHeader))
			assert.Empty(t, req.Header.Values(gatewayTimestampHeader))
			assert.Empty(t, req.Header.Values(gatewayNonceHeader))
		})
	}
}

func TestGatewaySignerContextCancellation(t *testing.T) {
	source := &testGatewayCredentialSource{credential: testGatewayCredential(t)}
	signer := testGatewaySigner(t, source, bytes.NewReader(make([]byte, 16)), time.Now)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	signed, err := signer.SignRequest(ctx, testGatewayRequest(t, testOnlyGatewayURL, []byte(testOnlyBody)), []byte(testOnlyBody))
	require.Error(t, err)
	assert.False(t, signed)
	assert.ErrorIs(t, err, context.Canceled)
	assert.Equal(t, int32(0), atomic.LoadInt32(&source.calls))
}

func TestGatewaySignerFreshValuesPerAttempt(t *testing.T) {
	source := &testGatewayCredentialSource{credential: testGatewayCredential(t)}
	randomBytes := append(bytes.Repeat([]byte{0x11}, 16), bytes.Repeat([]byte{0x22}, 16)...)
	var clockCalls int64
	signer := testGatewaySigner(t, source, bytes.NewReader(randomBytes), func() time.Time {
		return time.Unix(1700000000+atomic.AddInt64(&clockCalls, 1), 0)
	})

	first := testGatewayRequest(t, testOnlyGatewayURL, []byte(testOnlyBody))
	second := testGatewayRequest(t, testOnlyGatewayURL, []byte(testOnlyBody))
	firstSigned, err := signer.SignRequest(context.Background(), first, []byte(testOnlyBody))
	require.NoError(t, err)
	secondSigned, err := signer.SignRequest(context.Background(), second, []byte(testOnlyBody))
	require.NoError(t, err)
	assert.True(t, firstSigned)
	assert.True(t, secondSigned)
	assert.NotEqual(t, first.Header.Get(gatewayTimestampHeader), second.Header.Get(gatewayTimestampHeader))
	assert.NotEqual(t, first.Header.Get(gatewayNonceHeader), second.Header.Get(gatewayNonceHeader))
	assert.NotEqual(t, first.Header.Get(gatewayAuthorizationHeader), second.Header.Get(gatewayAuthorizationHeader))
	assert.Equal(t, testDeliveryID, first.Header.Get(idempotencyKeyHeader))
	assert.Equal(t, testDeliveryID, second.Header.Get(idempotencyKeyHeader))
}

func TestGatewaySignerConcurrentNoncesAreDistinct(t *testing.T) {
	const attempts = 32
	randomBytes := make([]byte, 0, attempts*16)
	for i := 0; i < attempts; i++ {
		randomBytes = append(randomBytes, bytes.Repeat([]byte{byte(i + 1)}, 16)...)
	}
	signer := testGatewaySigner(t,
		&testGatewayCredentialSource{credential: testGatewayCredential(t)},
		bytes.NewReader(randomBytes),
		func() time.Time { return time.Unix(1700000000, 0) },
	)

	nonces := make(chan string, attempts)
	errs := make(chan error, attempts)
	requests := make([]*http.Request, attempts)
	for i := range requests {
		requests[i] = testGatewayRequest(t, testOnlyGatewayURL, []byte(testOnlyBody))
	}
	var wg sync.WaitGroup
	for i := 0; i < attempts; i++ {
		wg.Add(1)
		go func(req *http.Request) {
			defer wg.Done()
			signed, err := signer.SignRequest(context.Background(), req, []byte(testOnlyBody))
			if !signed && err == nil {
				err = errors.New("request was not signed")
			}
			errs <- err
			nonces <- req.Header.Get(gatewayNonceHeader)
		}(requests[i])
	}
	wg.Wait()
	close(errs)
	close(nonces)
	for err := range errs {
		require.NoError(t, err)
	}
	unique := make(map[string]struct{}, attempts)
	for nonce := range nonces {
		assert.Len(t, nonce, 22)
		unique[nonce] = struct{}{}
	}
	assert.Len(t, unique, attempts)
}

func TestGatewaySensitiveValuesAlwaysFormatRedacted(t *testing.T) {
	audience, err := NewGatewayAudienceID(testOnlyAudienceID)
	require.NoError(t, err)
	id, err := NewGatewayCredentialID(testOnlyCredentialID)
	require.NoError(t, err)
	secret, err := NewGatewayAuthenticationSecret(testOnlySecretMaterial)
	require.NoError(t, err)
	credential := testGatewayCredential(t)

	for _, value := range []interface{}{audience, id, secret, credential} {
		assert.Equal(t, "[redacted]", fmt.Sprintf("%v", value))
		assert.Equal(t, "[redacted]", fmt.Sprintf("%+v", value))
		assert.Equal(t, "[redacted]", fmt.Sprintf("%#v", value))
	}
}

func TestGatewayCredentialDefensiveCopy(t *testing.T) {
	material := append([]byte(nil), testOnlySecretMaterial...)
	credential, err := NewGatewayCredential(testOnlyCredentialID, material)
	require.NoError(t, err)
	for i := range material {
		material[i] = 0xff
	}
	source := &testGatewayCredentialSource{credential: credential}
	signer := testGatewaySigner(t, source, bytes.NewReader(testOnlySecretMaterial[16:]), func() time.Time {
		return time.Unix(1700000000, 0)
	})
	req := testGatewayRequest(t, testOnlyGatewayURL, []byte(testOnlyBody))
	signed, err := signer.SignRequest(context.Background(), req, []byte(testOnlyBody))
	require.NoError(t, err)
	assert.True(t, signed)
	assert.Equal(t, testOnlyAuthorization, req.Header.Get(gatewayAuthorizationHeader))
}

func TestGatewaySignerValidatesConfiguration(t *testing.T) {
	matcher, err := NewGatewayTargetMatcher(testOnlyGatewayOrigin)
	require.NoError(t, err)
	source := &testGatewayCredentialSource{credential: testGatewayCredential(t)}

	for _, audience := range []string{"", "00000000-0000-0000-0000-000000000000", "123E4567-E89B-12D3-A456-426614174000", "123e4567e89b12d3a456426614174000"} {
		signer, err := NewGatewaySigner(matcher, audience, source)
		require.Error(t, err)
		assert.Nil(t, signer)
	}
	for _, credentialID := range []string{"", "01234567-89ab-3def-8123-456789abcdef", "01234567-89AB-4DEF-8123-456789ABCDEF", "0123456789ab4def8123456789abcdef"} {
		credential, err := NewGatewayCredential(credentialID, testOnlySecretMaterial)
		require.Error(t, err)
		assert.Equal(t, GatewayCredential{}, credential)
	}
	for _, size := range []int{0, 31, 33} {
		credential, err := NewGatewayCredential(testOnlyCredentialID, make([]byte, size))
		require.Error(t, err)
		assert.Equal(t, GatewayCredential{}, credential)
	}
}

func TestGatewaySignerZeroValueFailsClosed(t *testing.T) {
	req := testGatewayRequest(t, testOnlyGatewayURL, []byte(testOnlyBody))
	signed, err := new(GatewaySigner).SignRequest(context.Background(), req, []byte(testOnlyBody))
	require.Error(t, err)
	assert.False(t, signed)
	assert.Equal(t, errGatewaySigningInvalid.Error(), err.Error())
	assert.Empty(t, req.Header.Values(gatewayAuthorizationHeader))
}

func TestGatewaySignerRequiresCanonicalDeliveryIdentity(t *testing.T) {
	source := &testGatewayCredentialSource{credential: testGatewayCredential(t)}
	signer := testGatewaySigner(t, source, bytes.NewReader(make([]byte, 16)), time.Now)
	for _, deliveryID := range []string{"", "00000000-0000-0000-0000-000000000000", "11111111222243338444555555555555", "11111111-2222-4333-8444-555555555555 "} {
		req := testGatewayRequest(t, testOnlyGatewayURL, []byte(testOnlyBody))
		if deliveryID == "" {
			req.Header.Del(idempotencyKeyHeader)
		} else {
			req.Header.Set(idempotencyKeyHeader, deliveryID)
		}
		signed, err := signer.SignRequest(context.Background(), req, []byte(testOnlyBody))
		require.Error(t, err)
		assert.False(t, signed)
		assert.Equal(t, errGatewaySigningInvalid.Error(), err.Error())
	}
}

func TestGatewaySignerDoesNotLeakMarkers(t *testing.T) {
	markers := []string{
		"test-only-url-marker", "test-only-token-marker", "test-only-credential-marker",
		"test-only-audience-marker", "test-only-nonce-marker", "test-only-signature-marker",
		"test-only-body-marker", "test-only-digest-marker",
	}
	joined := strings.Join(markers, " ")
	sourceErr := errors.New(joined)
	signer := testGatewaySigner(t, &testGatewayCredentialSource{err: sourceErr}, bytes.NewReader(make([]byte, 16)), time.Now)
	signed, err := signer.SignRequest(context.Background(), testGatewayRequest(t, testOnlyGatewayURL, []byte(joined)), []byte(joined))
	require.Error(t, err)
	assert.False(t, signed)
	for _, marker := range markers {
		assert.NotContains(t, err.Error(), marker)
	}
}
