package deleteaudit

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// State is already representable under its enclosing Rotation root. Explicit
// child DELETE RETURNING, however, cannot truthfully use the frozen fk_cascade
// mechanism. Keep this contract closed until a separately approved change.
func TestRotationStateExplicitParticipantContractBoundary(t *testing.T) {
	e := testEvent(Rotation)
	e.Effects = []Effect{testParticipant(e)}
	e.BeforeState = &RotationState{
		ID: 42, ParticipantID: *e.Effects[0].ResourceUUID, Position: 0,
		Version: 2, ShiftStart: time.Date(2026, 1, 2, 3, 4, 5, 123456000, time.UTC),
	}
	require.NoError(t, e.Validate())
	raw, err := json.Marshal(e.BeforeState)
	require.NoError(t, err)
	var state map[string]any
	require.NoError(t, json.Unmarshal(raw, &state))
	require.Len(t, state, 5)
	require.Equal(t, float64(42), state["id"])
	require.Equal(t, e.BeforeState.ParticipantID.String(), state["participant_id"])
	require.Equal(t, float64(0), state["position"])
	require.Equal(t, float64(2), state["version"])
	require.Equal(t, "2026-01-02T03:04:05.123456Z", state["shift_start"])

	// CASCADE expresses product ownership; explicit_sql records the actual
	// physical deletion. This combination is rejected by the current adapter.
	e.Effects[0].DeletionMechanism = "explicit_sql"
	require.Equal(t, "CASCADE", e.Effects[0].Provenance)
	require.ErrorIs(t, e.Validate(), ErrInvalid)
	require.ErrorIs(t, Append(t.Context(), nil, e), ErrInvalid)
}
