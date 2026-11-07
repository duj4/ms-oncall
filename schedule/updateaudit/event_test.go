package updateaudit

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestEventPrivacyAndCombinations(t *testing.T) {
	org := uuid.New()
	base := Event{EventID: uuid.New(), RequestID: uuid.New(), AttemptID: uuid.New(), Operation: ScheduleUpdate,
		ActorKind: "human", ActorID: uuid.New(), HomeOrganizationID: org, AuthoritySource: "current_local_user_organization_at_admission", AuthorityRole: "org_admin", OrganizationRole: "ORG_ADMIN",
		TargetID: uuid.New(), TargetOrganizationID: org, Outcome: "committed", Reason: "updated", OccurredAt: time.Now(), ScheduleRowWritten: true}
	require.True(t, base.valid())
	for _, mask := range []Fields{0, ScheduleName, ScheduleDescription, ScheduleTimeZone, 7} {
		e := base
		e.RequestedFields = mask
		require.True(t, e.valid())
	}
	for _, mask := range []Fields{0, RotationName, RotationDescription, RotationStart, RotationType, RotationShiftLength, RotationTimeZone, RotationUserIDs, RotationActiveUserIndex, 255} {
		e := base
		e.Operation = RotationUpdate
		e.ScheduleRowWritten = false
		e.RequestedFields = mask
		e.RotationRowWritten = mask&63 != 0
		e.Before = &RotationSnapshot{}
		e.After = &RotationSnapshot{}
		require.True(t, e.valid())
	}
	for _, field := range []string{"actor", "authority", "reason", "operation"} {
		e := base
		switch field {
		case "actor":
			e.ActorKind = "synthetic-session-marker"
		case "authority":
			e.AuthoritySource = "synthetic-token-marker"
		case "reason":
			e.Reason = "synthetic-SQL-error-detail"
		case "operation":
			e.Operation = "synthetic-request-body"
		}
		err := Append(context.Background(), nil, e)
		require.ErrorIs(t, err, ErrInvalid)
		require.NotContains(t, err.Error(), "synthetic")
	}
	for name, mutate := range map[string]func(*Event){
		"zero-event":             func(e *Event) { e.EventID = uuid.Nil },
		"zero-attempt":           func(e *Event) { e.AttemptID = uuid.Nil },
		"zero-request":           func(e *Event) { e.RequestID = uuid.Nil },
		"zero-time":              func(e *Event) { e.OccurredAt = time.Time{} },
		"foreign-home":           func(e *Event) { e.HomeOrganizationID = uuid.New() },
		"missing-target":         func(e *Event) { e.TargetID = uuid.Nil },
		"member-success":         func(e *Event) { e.AuthorityRole = "org_member"; e.OrganizationRole = "ORG_MEMBER" },
		"bad-reason-combination": func(e *Event) { e.Reason = "commit_unconfirmed" },
		"bad-schema-fields":      func(e *Event) { e.RequestedFields = 256 },
		"unknown-success":        func(e *Event) { e.ActorKind = "unknown" },
		"unexpected-effects":     func(e *Event) { e.Before = &RotationSnapshot{} },
		"missing-effects":        func(e *Event) { e.ScheduleRowWritten = false },
	} {
		t.Run(name, func(t *testing.T) { e := base; mutate(&e); require.False(t, e.valid()) })
	}
	for outcome, reasons := range map[string][]string{"denied": {"authority_denied", "target_unavailable"}, "validation_failed": {"invalid_fields", "target_unavailable"}, "tx_failed": {"begin_failed", "write_failed", "audit_write_failed", "commit_rejected"}, "commit_unknown": {"commit_unconfirmed"}, "rollback_unconfirmed": {"rollback_unconfirmed"}} {
		for _, reason := range reasons {
			e := base
			e.Outcome = outcome
			e.Reason = reason
			e.ScheduleRowWritten = false
			require.True(t, e.valid())
			e.ScheduleRowWritten = true
			require.False(t, e.valid())
		}
	}
	require.ErrorIs(t, Append(context.Background(), nil, base), ErrUnavailable)
}

func TestGlobalExistingRootEventKeepsHomeAndTargetSeparate(t *testing.T) {
	for _, role := range []string{"ORG_MEMBER", "ORG_ADMIN"} {
		e := Event{EventID: uuid.New(), RequestID: uuid.New(), AttemptID: uuid.New(), Operation: ScheduleUpdate,
			ActorKind: "human", ActorID: uuid.New(), HomeOrganizationID: uuid.New(), AuthoritySource: "current_local_user_organization_at_admission", AuthorityRole: "platform_admin", OrganizationRole: role,
			TargetID: uuid.New(), TargetOrganizationID: uuid.New(), Outcome: "committed", Reason: "updated", OccurredAt: time.Now(), ScheduleRowWritten: true}
		require.True(t, e.valid())
		e.AuthorityRole, e.OrganizationRole = "org_admin", "ORG_ADMIN"
		require.False(t, e.valid(), "ordinary OrgAdmin still requires Home=Target")
		e.AuthorityRole, e.OrganizationRole = "org_member", "ORG_MEMBER"
		require.False(t, e.valid())
	}
}

func TestSnapshotRejectsPartialAndMisattributedState(t *testing.T) {
	p := Participant{ID: uuid.New(), UserID: uuid.New(), Position: 0}
	state := RotationState{ID: 1, Position: 0, Version: 2, ParticipantID: p.ID, ShiftStart: time.Now()}
	s := RotationSnapshot{ParticipantCount: 1, Participants: []Participant{p}, State: &state}
	require.True(t, s.valid())
	duplicate := s
	duplicate.Participants = append(append([]Participant(nil), s.Participants...), p)
	duplicate.ParticipantCount = 2
	require.False(t, duplicate.valid())
	state.ParticipantID = uuid.New()
	require.False(t, s.valid())
	state.ParticipantID = p.ID
	state.Position = 1
	require.False(t, s.valid())
	state.Position = 0
	s.ParticipantCount = 2
	require.False(t, s.valid())
	s.ParticipantCount = 1
	s.Participants[0].UserID = uuid.Nil
	require.False(t, s.valid())
}
