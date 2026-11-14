package migrate

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

// This test reads/parses source only. It never connects to a database or
// executes Up/Down. Runtime schema proof requires separate test authority.
func TestEPUpdateDeleteAudit305CanonicalAppend(t *testing.T) {
	h, err := loadEmbeddedHistory()
	require.NoError(t, err)
	require.Len(t, h.entries, 305)
	e := h.entries[304]
	require.Equal(t, "20261114215338-ep-update-delete-audit-v2.sql", e.ID)
	require.Equal(t, int64(305), e.Position)
	require.Equal(t, h.entries[303].ID, e.PredecessorID)
	marker := []byte(",\n    {\n      \"id\": \"ms-oncall-ep-update-delete-audit-d09-sd10\",")
	i := bytes.Index(h.manifest, marker)
	require.Positive(t, i)
	prefix := append(append([]byte{}, h.manifest[:i]...), []byte("\n  ]\n}\n")...)
	require.Equal(t, "5165c5309fdf385242838914d48e80ff386f63e6ef57966d08fc0450f5467d33", fmt.Sprintf("%x", sha256.Sum256(prefix)), "the complete accepted 1–304 manifest remains byte-identical")
	parsed, err := parseMigrations(h)
	require.NoError(t, err)
	require.False(t, parsed[304].Up.disableTx)
	require.False(t, parsed[304].Down.disableTx)
}
