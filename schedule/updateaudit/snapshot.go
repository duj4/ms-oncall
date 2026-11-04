package updateaudit

import (
	"context"
	"database/sql"
	"time"

	"github.com/google/uuid"
)

// Participant records an actual persisted relationship, not a modified User or
// a claim about that User's current Organization. Duplicate UserIDs are retained.
type Participant struct {
	ID, UserID uuid.UUID
	Position   int32
}

// RotationState contains every non-parent column of the actual state row.
type RotationState struct {
	ID                int64
	Position, Version int32
	ParticipantID     uuid.UUID
	ShiftStart        time.Time
}

type RotationSnapshot struct {
	Participants     []Participant
	ParticipantCount int32
	State            *RotationState
}

func (s *RotationSnapshot) valid() bool {
	if s == nil || int64(s.ParticipantCount) != int64(len(s.Participants)) {
		return false
	}
	seen := make(map[uuid.UUID]bool, len(s.Participants))
	for i, p := range s.Participants {
		if p.ID == uuid.Nil || p.UserID == uuid.Nil || p.Position < 0 || seen[p.ID] || i > 0 && s.Participants[i-1].Position >= p.Position {
			return false
		}
		seen[p.ID] = true
	}
	if s.State == nil {
		return true
	}
	if !finiteTime(s.State.ShiftStart) {
		return false
	}
	for _, p := range s.Participants {
		if p.ID == s.State.ParticipantID && p.Position == s.State.Position {
			return true
		}
	}
	return false
}

// CaptureRotation reads only the approved non-secret effects. The caller MUST
// already hold the existing Rotation and participant/state locks, and capture
// before/after within that same transaction. This helper grants no authority,
// changes no lock policy and never reads related Users' current Organizations.
func CaptureRotation(ctx context.Context, tx *sql.Tx, rotationID uuid.UUID) (*RotationSnapshot, error) {
	if tx == nil {
		return nil, ErrUnavailable
	}
	if rotationID == uuid.Nil {
		return nil, ErrInvalid
	}
	s := &RotationSnapshot{}
	if err := tx.QueryRowContext(ctx, "SELECT participant_count FROM rotations WHERE id=$1", rotationID.String()).Scan(&s.ParticipantCount); err != nil {
		return nil, ErrUnavailable
	}
	rows, err := tx.QueryContext(ctx, "SELECT id,user_id,position FROM rotation_participants WHERE rotation_id=$1 ORDER BY position", rotationID.String())
	if err != nil {
		return nil, ErrUnavailable
	}
	defer rows.Close()
	for rows.Next() {
		var p Participant
		if err := rows.Scan(&p.ID, &p.UserID, &p.Position); err != nil {
			return nil, ErrUnavailable
		}
		s.Participants = append(s.Participants, p)
	}
	if rows.Err() != nil {
		return nil, ErrUnavailable
	}
	if err := rows.Close(); err != nil {
		return nil, ErrUnavailable
	}
	state := &RotationState{}
	err = tx.QueryRowContext(ctx, "SELECT id,position,rotation_participant_id,shift_start,version FROM rotation_state WHERE rotation_id=$1", rotationID.String()).Scan(&state.ID, &state.Position, &state.ParticipantID, &state.ShiftStart, &state.Version)
	if err != nil && err != sql.ErrNoRows {
		return nil, ErrUnavailable
	}
	if err == nil {
		s.State = state
	}
	if !s.valid() {
		return nil, ErrInvalid
	}
	return s, nil
}
