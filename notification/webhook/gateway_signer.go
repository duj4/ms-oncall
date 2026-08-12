package webhook

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/target/goalert/retry"
)

const (
	gatewayAuthorizationHeader = "Authorization"
	gatewayTimestampHeader     = "X-MS-OnCall-Timestamp"
	gatewayNonceHeader         = "X-MS-OnCall-Nonce"
	gatewaySigningDomain       = "MS_ONCALL_GATEWAY_REQUEST_V1"
)

var (
	errGatewaySigningInvalid     = errors.New("gateway signing configuration is invalid")
	errGatewaySigningUnavailable = errors.New("gateway signing unavailable")
)

type redactedValue struct{}

func (redactedValue) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, "[redacted]")
}

// GatewayAudienceID is a canonical non-zero lowercase hyphenated UUID. Its
// formatted representation is always redacted.
type GatewayAudienceID struct {
	redactedValue
	value string
}

// NewGatewayAudienceID validates a configured Gateway realm audience.
func NewGatewayAudienceID(value string) (GatewayAudienceID, error) {
	parsed, ok := parseCanonicalUUID(value, false)
	if !ok || parsed == uuid.Nil {
		return GatewayAudienceID{}, errGatewaySigningInvalid
	}
	return GatewayAudienceID{value: value}, nil
}

// GatewayCredentialID is a canonical lowercase UUIDv4. Its formatted
// representation is always redacted.
type GatewayCredentialID struct {
	redactedValue
	value string
}

// NewGatewayCredentialID validates the public credential identifier.
func NewGatewayCredentialID(value string) (GatewayCredentialID, error) {
	parsed, ok := parseCanonicalUUID(value, true)
	if !ok || parsed == uuid.Nil {
		return GatewayCredentialID{}, errGatewaySigningInvalid
	}
	return GatewayCredentialID{value: value}, nil
}

// GatewayAuthenticationSecret contains exactly 32 authentication-only bytes.
// Its formatted representation is always redacted.
type GatewayAuthenticationSecret struct {
	redactedValue
	value [32]byte
}

// NewGatewayAuthenticationSecret defensively copies 32 bytes supplied by the
// dedicated Authentication credential source.
func NewGatewayAuthenticationSecret(material []byte) (GatewayAuthenticationSecret, error) {
	if len(material) != sha256.Size {
		return GatewayAuthenticationSecret{}, errGatewaySigningInvalid
	}
	var secret GatewayAuthenticationSecret
	copy(secret.value[:], material)
	return secret, nil
}

// GatewayCredential is one public credential ID and its dedicated HMAC secret.
// Its formatted representation is always redacted.
type GatewayCredential struct {
	redactedValue
	id     GatewayCredentialID
	secret GatewayAuthenticationSecret
}

// NewGatewayCredential validates and defensively copies a credential.
func NewGatewayCredential(id string, material []byte) (GatewayCredential, error) {
	credentialID, err := NewGatewayCredentialID(id)
	if err != nil {
		return GatewayCredential{}, errGatewaySigningInvalid
	}
	secret, err := NewGatewayAuthenticationSecret(material)
	if err != nil {
		return GatewayCredential{}, errGatewaySigningInvalid
	}
	return GatewayCredential{id: credentialID, secret: secret}, nil
}

func (c GatewayCredential) valid() bool {
	parsed, ok := parseCanonicalUUID(c.id.value, true)
	return ok && parsed != uuid.Nil
}

// GatewayCredentialSource supplies one Authentication-only Core credential.
// Production implementations are intentionally outside this foundation.
type GatewayCredentialSource interface {
	GatewayCredential(context.Context) (GatewayCredential, error)
}

// GatewayRequestSigner is the narrow optional dependency used by Sender.
type GatewayRequestSigner interface {
	SignRequest(context.Context, *http.Request, []byte) (bool, error)
}

// GatewaySigner signs only requests accepted by its strict target matcher.
type GatewaySigner struct {
	matcher  *GatewayTargetMatcher
	audience GatewayAudienceID
	source   GatewayCredentialSource
	now      func() time.Time
	random   io.Reader
	randomMu sync.Mutex
}

// NewGatewaySigner constructs a signer with the system clock and crypto/rand.
func NewGatewaySigner(matcher *GatewayTargetMatcher, audience string, source GatewayCredentialSource) (*GatewaySigner, error) {
	return NewGatewaySignerWithSources(matcher, audience, source, time.Now, rand.Reader)
}

// NewGatewaySignerWithSources permits deterministic clocks and random sources
// in tests. Runtime wiring is intentionally not provided by this foundation.
func NewGatewaySignerWithSources(matcher *GatewayTargetMatcher, audience string, source GatewayCredentialSource, now func() time.Time, random io.Reader) (*GatewaySigner, error) {
	audienceID, err := NewGatewayAudienceID(audience)
	if err != nil || matcher == nil || source == nil || now == nil || random == nil {
		return nil, errGatewaySigningInvalid
	}
	return &GatewaySigner{
		matcher:  matcher,
		audience: audienceID,
		source:   source,
		now:      now,
		random:   random,
	}, nil
}

func parseCanonicalUUID(value string, requireV4 bool) (uuid.UUID, bool) {
	parsed, err := uuid.Parse(value)
	if err != nil || parsed.String() != value {
		return uuid.Nil, false
	}
	if requireV4 && (parsed.Version() != 4 || parsed.Variant() != uuid.RFC4122) {
		return uuid.Nil, false
	}
	return parsed, true
}

func gatewaySigningFailure(ctx context.Context) error {
	if ctx != nil {
		if err := ctx.Err(); errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return fmt.Errorf("gateway signing failed: %w", err)
		}
	}
	return retry.TemporaryError(errGatewaySigningUnavailable)
}

// SignRequest adds Authentication V1 headers only to an exact Gateway target.
// It computes all values before changing the request, so failures leave no
// partial authentication headers.
func (s *GatewaySigner) SignRequest(ctx context.Context, req *http.Request, body []byte) (bool, error) {
	if s == nil || !s.matcher.valid() || s.source == nil || s.now == nil || s.random == nil ||
		req == nil || req.URL == nil {
		return false, errGatewaySigningInvalid
	}
	canonicalPath, matches := s.matcher.Match(req.URL)
	if !matches {
		return false, nil
	}
	if ctx == nil || req.Method != http.MethodPost ||
		len(req.Header.Values(gatewayAuthorizationHeader)) != 0 ||
		len(req.Header.Values(gatewayTimestampHeader)) != 0 ||
		len(req.Header.Values(gatewayNonceHeader)) != 0 {
		return false, errGatewaySigningInvalid
	}
	deliveryValues := req.Header.Values(idempotencyKeyHeader)
	if len(deliveryValues) != 1 {
		return false, errGatewaySigningInvalid
	}
	deliveryID, ok := parseCanonicalUUID(deliveryValues[0], false)
	if !ok || deliveryID == uuid.Nil {
		return false, errGatewaySigningInvalid
	}
	if err := ctx.Err(); err != nil {
		return false, gatewaySigningFailure(ctx)
	}

	credential, err := s.source.GatewayCredential(ctx)
	if err != nil {
		return false, gatewaySigningFailure(ctx)
	}
	if !credential.valid() {
		return false, errGatewaySigningInvalid
	}

	timestampValue := s.now().Unix()
	if timestampValue < 0 {
		return false, errGatewaySigningInvalid
	}
	timestamp := strconv.FormatInt(timestampValue, 10)

	var nonceBytes [16]byte
	s.randomMu.Lock()
	_, err = io.ReadFull(s.random, nonceBytes[:])
	s.randomMu.Unlock()
	if err != nil {
		return false, gatewaySigningFailure(ctx)
	}
	nonce := base64.RawURLEncoding.EncodeToString(nonceBytes[:])

	signingInput := gatewaySigningInput(
		s.audience.value,
		canonicalPath,
		credential.id.value,
		deliveryValues[0],
		timestamp,
		nonce,
		body,
	)

	mac := hmac.New(sha256.New, credential.secret.value[:])
	_, _ = mac.Write([]byte(signingInput))
	signature := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	authorization := "MSOnCall-HMAC-SHA256 Credential=" + credential.id.value + ", Signature=" + signature

	req.Header.Set(gatewayAuthorizationHeader, authorization)
	req.Header.Set(gatewayTimestampHeader, timestamp)
	req.Header.Set(gatewayNonceHeader, nonce)
	return true, nil
}

func gatewaySigningInput(audience, canonicalPath, credentialID, deliveryID, timestamp, nonce string, body []byte) string {
	bodyDigest := sha256.Sum256(body)
	return strings.Join([]string{
		gatewaySigningDomain,
		audience,
		http.MethodPost,
		canonicalPath,
		credentialID,
		deliveryID,
		timestamp,
		nonce,
		hex.EncodeToString(bodyDigest[:]),
	}, "\n")
}
