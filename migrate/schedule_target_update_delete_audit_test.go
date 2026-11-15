package migrate

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

// Source parsing only: never connects to PostgreSQL or executes Up/Down.
func TestScheduleTargetUpdateDeleteAudit306CanonicalAppend(t *testing.T) {
	h, err := loadEmbeddedHistory()
	require.NoError(t, err)
	require.Len(t, h.entries, 306)
	e := h.entries[305]
	require.Equal(t, "20261115004448-schedule-target-update-delete-audit-v2.sql", e.ID)
	require.Equal(t, int64(306), e.Position)
	require.Equal(t, h.entries[304].ID, e.PredecessorID)
	marker := []byte(",\n    {\n      \"id\": \"ms-oncall-schedule-target-update-delete-audit-d09-sd10\",")
	i := bytes.Index(h.manifest, marker)
	require.Positive(t, i)
	prefix := append(append([]byte{}, h.manifest[:i]...), []byte("\n  ]\n}\n")...)
	require.Equal(t, "0234f8e4af500489845100664e24723298fb89fe0531fa430f8bc2ce10414145", fmt.Sprintf("%x", sha256.Sum256(prefix)), "complete accepted 1–305 manifest is byte-identical")
	parsed, err := parseMigrations(h)
	require.NoError(t, err)
	require.False(t, parsed[305].Up.disableTx)
	require.False(t, parsed[305].Down.disableTx)
}
