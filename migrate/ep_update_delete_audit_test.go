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
	require.GreaterOrEqual(t, len(h.entries), 306)
	e := h.entries[304]
	require.Equal(t, "20261114215338-ep-update-delete-audit-v2.sql", e.ID)
	require.Equal(t, e.ID, e.OriginalID)
	require.Equal(t, "bb40457319a2a5016e98e91442dc54bc6af901e3ba89ca8aa47571fee7725167", e.SHA256)
	require.Equal(t, int64(305), e.Position)
	require.Equal(t, h.entries[303].ID, e.PredecessorID)
	marker := []byte(",\n    {\n      \"id\": \"ms-oncall-ep-update-delete-audit-d09-sd10\",")
	i := bytes.Index(h.manifest, marker)
	require.Positive(t, i)
	prefix := append(append([]byte{}, h.manifest[:i]...), []byte("\n  ]\n}\n")...)
	require.Equal(t, "5165c5309fdf385242838914d48e80ff386f63e6ef57966d08fc0450f5467d33", fmt.Sprintf("%x", sha256.Sum256(prefix)), "the complete accepted 1–304 manifest remains byte-identical")

	// Migrations 305 and 306 retain their historical identities.
	tail := h.entries[305]
	require.Equal(t, "20261115004448-schedule-target-update-delete-audit-v2.sql", tail.ID)
	require.Equal(t, tail.ID, tail.OriginalID)
	require.Equal(t, int64(306), tail.Position)
	require.Equal(t, "9b9afbd909fcfc46e07c1035e73b84b6592f30d033cb1caf246c9f947dc2279c", tail.SHA256)
	require.Equal(t, e.ID, tail.PredecessorID)
	require.Equal(t, provenanceMSOnCall, tail.Provenance)
	require.Equal(t, "ms-oncall-schedule-target-update-delete-audit-d09-sd10", tail.BundleID)
	for _, entry := range []canonicalMigration{e, tail} {
		raw, err := migrationFS.ReadFile("migrations/" + entry.ID)
		require.NoError(t, err)
		require.Equal(t, entry.SHA256, fmt.Sprintf("%x", sha256.Sum256(raw)))
	}
	marker306 := []byte(",\n    {\n      \"id\": \"ms-oncall-schedule-target-update-delete-audit-d09-sd10\",")
	require.Equal(t, 1, bytes.Count(h.manifest, marker306))
	j := bytes.Index(h.manifest, marker306)
	require.Greater(t, j, i)
	prefix305 := append(append([]byte{}, h.manifest[:j]...), []byte("\n  ]\n}\n")...)
	require.Equal(t, "0234f8e4af500489845100664e24723298fb89fe0531fa430f8bc2ce10414145", fmt.Sprintf("%x", sha256.Sum256(prefix305)), "the complete accepted 1–305 manifest remains byte-identical")

	parsed, err := parseMigrations(h)
	require.NoError(t, err)
	require.False(t, parsed[304].Up.disableTx)
	require.False(t, parsed[304].Down.disableTx)
}
