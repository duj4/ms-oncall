package gadb

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestC9DestinationDiagnosticFormattingPreservesWireAndHash(t *testing.T) {
	for _, tc := range []struct{ typ, key, raw string }{
		{"builtin-smtp-email", "email_address", "c9-private-leak@example.invalid"},
		{"builtin-twilio-sms", "phone_number", "+15551234567"},
		{"builtin-webhook", "webhook_url", "https://example.invalid/private/c9-super-secret-token"},
	} {
		dest := NewDestV1(tc.typ, tc.key, tc.raw)
		for _, format := range []string{"%s", "%v", "%+v", "%#v", "%q"} {
			require.NotContains(t, fmt.Sprintf(format, dest), tc.raw)
			require.NotContains(t, fmt.Sprintf(format, &dest), tc.raw)
			require.Contains(t, fmt.Sprintf(format, dest), tc.typ)
		}
		require.NotContains(t, fmt.Errorf("lookup dest %s", dest).Error(), tc.raw)
		encoded, err := json.Marshal(dest)
		require.NoError(t, err)
		require.Contains(t, string(encoded), tc.raw, "legitimate wire representation remains raw")
		require.Equal(t, DestHashV1(sha256.Sum256(encoded)), dest.DestHash())
		value, err := dest.Value()
		require.NoError(t, err)
		var scanned DestV1
		require.NoError(t, scanned.Scan(value))
		require.True(t, dest.Equal(scanned))
	}
}
