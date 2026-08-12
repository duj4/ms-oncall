package webhook

import (
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testOnlyGatewayOrigin = "https://gateway.test.invalid"
	testOnlyGatewayToken  = "mso1_AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"
	testOnlyGatewayPath   = gatewayContactMethodPathPrefix + testOnlyGatewayToken
	testOnlyGatewayURL    = testOnlyGatewayOrigin + testOnlyGatewayPath
)

func TestGatewayTargetMatcher(t *testing.T) {
	matcher, err := NewGatewayTargetMatcher(testOnlyGatewayOrigin)
	require.NoError(t, err)

	tests := []struct {
		name  string
		value string
		match bool
	}{
		{name: "exact", value: testOnlyGatewayURL, match: true},
		{name: "explicit default port", value: "https://gateway.test.invalid:443" + testOnlyGatewayPath, match: true},
		{name: "ordinary webhook", value: "https://hooks.test.invalid/notify"},
		{name: "http", value: "http://gateway.test.invalid" + testOnlyGatewayPath},
		{name: "wrong host", value: "https://other.test.invalid" + testOnlyGatewayPath},
		{name: "subdomain", value: "https://child.gateway.test.invalid" + testOnlyGatewayPath},
		{name: "host case", value: "https://Gateway.test.invalid" + testOnlyGatewayPath},
		{name: "wrong port", value: "https://gateway.test.invalid:444" + testOnlyGatewayPath},
		{name: "explicit empty port", value: "https://gateway.test.invalid:" + testOnlyGatewayPath},
		{name: "userinfo", value: "https://user@gateway.test.invalid" + testOnlyGatewayPath},
		{name: "query", value: testOnlyGatewayURL + "?route=test"},
		{name: "empty query marker", value: testOnlyGatewayURL + "?"},
		{name: "fragment", value: testOnlyGatewayURL + "#test"},
		{name: "encoded route", value: testOnlyGatewayOrigin + "/v1/goalert/contact%2Dmethod/" + testOnlyGatewayToken},
		{name: "encoded token", value: testOnlyGatewayOrigin + gatewayContactMethodPathPrefix + "mso1_%41AECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"},
		{name: "padded base64", value: testOnlyGatewayURL + "="},
		{name: "wrong prefix", value: testOnlyGatewayOrigin + gatewayContactMethodPathPrefix + "mso2_" + strings.TrimPrefix(testOnlyGatewayToken, "mso1_")},
		{name: "wrong length", value: testOnlyGatewayURL[:len(testOnlyGatewayURL)-1]},
		{name: "alternate alphabet", value: testOnlyGatewayURL[:len(testOnlyGatewayURL)-1] + "+"},
		{name: "duplicate slash", value: testOnlyGatewayOrigin + "/v1/goalert//contact-method/" + testOnlyGatewayToken},
		{name: "dot segment", value: testOnlyGatewayOrigin + "/v1/goalert/./contact-method/" + testOnlyGatewayToken},
		{name: "path suffix", value: testOnlyGatewayURL + "/extra"},
		{name: "path case", value: testOnlyGatewayOrigin + "/v1/GoAlert/contact-method/" + testOnlyGatewayToken},
		{name: "token case", value: testOnlyGatewayOrigin + gatewayContactMethodPathPrefix + "MSO1_" + strings.TrimPrefix(testOnlyGatewayToken, "mso1_")},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			target, err := url.Parse(test.value)
			require.NoError(t, err)
			path, matched := matcher.Match(target)
			assert.Equal(t, test.match, matched)
			if test.match {
				assert.Equal(t, testOnlyGatewayPath, path)
			} else {
				assert.Empty(t, path)
			}
		})
	}
}

func TestGatewayTokenCanonicalDecodedLength(t *testing.T) {
	assert.True(t, validGatewayToken(testOnlyGatewayToken))
	assert.False(t, validGatewayToken("mso1_"+strings.Repeat("A", 42)), "31 decoded bytes must be rejected")
	assert.False(t, validGatewayToken("mso1_"+strings.Repeat("A", 44)), "33 decoded bytes must be rejected")
}

func TestGatewayTargetMatcherRejectsInvalidOrigin(t *testing.T) {
	for _, origin := range []string{
		"", "http://gateway.test.invalid", "https://Gateway.test.invalid",
		"https://gateway.test.invalid/", "https://user@gateway.test.invalid",
		"https://gateway.test.invalid?test", "https://gateway.test.invalid#test",
		"https://gateway.test.invalid:0443", "https://gateway.test.invalid:", "https://*.test.invalid",
	} {
		matcher, err := NewGatewayTargetMatcher(origin)
		require.Error(t, err)
		assert.Nil(t, matcher)
		assert.Equal(t, errGatewayTargetConfiguration.Error(), err.Error())
		if origin != "" {
			assert.NotContains(t, err.Error(), origin)
		}
	}
}
