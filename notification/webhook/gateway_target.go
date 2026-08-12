package webhook

import (
	"encoding/base64"
	"errors"
	"net/url"
	"strconv"
	"strings"
)

const gatewayContactMethodPathPrefix = "/v1/goalert/contact-method/"

var errGatewayTargetConfiguration = errors.New("gateway target configuration is invalid")

// GatewayTargetMatcher identifies only canonical webhook targets at one
// configured HTTPS Gateway origin. It performs no network or DNS operations.
type GatewayTargetMatcher struct {
	hostname      string
	effectivePort string
}

func (m *GatewayTargetMatcher) valid() bool {
	if m == nil || m.hostname == "" || m.hostname != strings.ToLower(m.hostname) || strings.Contains(m.hostname, "*") {
		return false
	}
	port, ok := canonicalHTTPSPort(m.effectivePort)
	return ok && port == m.effectivePort
}

// NewGatewayTargetMatcher validates a Gateway origin containing only a
// canonical HTTPS scheme and authority.
func NewGatewayTargetMatcher(origin string) (*GatewayTargetMatcher, error) {
	u, err := url.Parse(origin)
	if err != nil || u.Scheme != "https" || u.Opaque != "" || u.User != nil ||
		u.Host == "" || u.Path != "" || u.RawPath != "" || u.ForceQuery ||
		u.RawQuery != "" || u.Fragment != "" || u.RawFragment != "" ||
		strings.HasSuffix(u.Host, ":") {
		return nil, errGatewayTargetConfiguration
	}

	hostname := u.Hostname()
	if hostname == "" || hostname != strings.ToLower(hostname) || strings.Contains(hostname, "*") {
		return nil, errGatewayTargetConfiguration
	}
	port, ok := canonicalHTTPSPort(u.Port())
	if !ok {
		return nil, errGatewayTargetConfiguration
	}

	return &GatewayTargetMatcher{hostname: hostname, effectivePort: port}, nil
}

func canonicalHTTPSPort(port string) (string, bool) {
	if port == "" {
		return "443", true
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 || strconv.Itoa(n) != port {
		return "", false
	}
	return port, true
}

// Match returns the canonical request path when target is an exact Gateway
// contact-method target. Every near match is treated as a normal webhook.
func (m *GatewayTargetMatcher) Match(target *url.URL) (string, bool) {
	if !m.valid() || target == nil || target.Scheme != "https" || target.Opaque != "" ||
		target.User != nil || target.ForceQuery || target.RawQuery != "" ||
		target.Fragment != "" || target.RawFragment != "" || target.RawPath != "" ||
		strings.HasSuffix(target.Host, ":") {
		return "", false
	}
	if target.Hostname() != m.hostname {
		return "", false
	}
	port, ok := canonicalHTTPSPort(target.Port())
	if !ok || port != m.effectivePort {
		return "", false
	}
	if target.EscapedPath() != target.Path || !strings.HasPrefix(target.Path, gatewayContactMethodPathPrefix) {
		return "", false
	}

	token := strings.TrimPrefix(target.Path, gatewayContactMethodPathPrefix)
	if !validGatewayToken(token) {
		return "", false
	}
	return target.Path, true
}

func validGatewayToken(token string) bool {
	if len(token) != len("mso1_")+43 || !strings.HasPrefix(token, "mso1_") {
		return false
	}
	body := strings.TrimPrefix(token, "mso1_")
	decoded, err := base64.RawURLEncoding.DecodeString(body)
	if err != nil || len(decoded) != 32 {
		return false
	}
	return base64.RawURLEncoding.EncodeToString(decoded) == body
}
