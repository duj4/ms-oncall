package deleteaudit

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/organization"
)

func validEvent() Event {
	home := uuid.New()
	return Event{EventID: uuid.New(), AttemptID: uuid.New(), RequestID: uuid.New(), ExecutionID: uuid.New(), EffectsVersion: 1, ActorKind: "human", ActorID: uuid.New(), HomeOrganizationID: home, AuthoritySource: "current_local_user_organization_at_admission", AuthorityRole: "org_admin", OrganizationRole: "ORG_ADMIN", ServiceID: uuid.New(), TargetOrganizationID: home, Outcome: "committed", Reason: "deleted", OccurredAt: time.Now()}
}

func TestEventAttributionAndOutcomeContract(t *testing.T) {
	for name, mutate := range map[string]func(*Event){
		"nil event":         func(e *Event) { e.EventID = uuid.Nil },
		"nil attempt":       func(e *Event) { e.AttemptID = uuid.Nil },
		"nil request":       func(e *Event) { e.RequestID = uuid.Nil },
		"nil actor":         func(e *Event) { e.ActorID = uuid.Nil },
		"nil home":          func(e *Event) { e.HomeOrganizationID = uuid.Nil },
		"untrusted source":  func(e *Event) { e.AuthoritySource = "client" },
		"ordinary foreign":  func(e *Event) { e.TargetOrganizationID = uuid.New() },
		"member committed":  func(e *Event) { e.AuthorityRole, e.OrganizationRole = "org_member", "ORG_MEMBER" },
		"default target":    func(e *Event) { e.TargetOrganizationID = uuid.MustParse(organization.DefaultOrganizationID) },
		"unknown service":   func(e *Event) { e.ServiceID = uuid.Nil },
		"unknown target":    func(e *Event) { e.TargetOrganizationID = uuid.Nil },
		"unknown outcome":   func(e *Event) { e.Outcome = "success" },
		"wrong reason":      func(e *Event) { e.Reason = "commit_unconfirmed" },
		"zero time":         func(e *Event) { e.OccurredAt = time.Time{} },
		"outside timestamp": func(e *Event) { e.OccurredAt = time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC) },
	} {
		t.Run(name, func(t *testing.T) {
			e := validEvent()
			mutate(&e)
			require.False(t, e.valid())
			require.ErrorIs(t, Append(context.Background(), nil, e), ErrInvalid)
		})
	}
	e := validEvent()
	require.True(t, e.valid())
	require.ErrorIs(t, Append(context.Background(), nil, e), ErrUnavailable)
	for outcome, reasons := range map[string][]string{"denied": {"authority_denied"}, "validation_failed": {"invalid_fields", "target_unavailable"}, "tx_failed": {"begin_failed", "write_failed", "audit_write_failed", "commit_rejected"}, "commit_unknown": {"commit_unconfirmed"}, "rollback_unconfirmed": {"rollback_unconfirmed"}} {
		for _, reason := range reasons {
			e.Outcome, e.Reason = outcome, reason
			require.True(t, e.valid(), outcome+"/"+reason)
		}
	}
	e = validEvent()
	e.AuthorityRole, e.OrganizationRole, e.HomeOrganizationID = "platform_admin", "NONE", uuid.MustParse(organization.DefaultOrganizationID)
	require.True(t, e.valid())
	e.AuthorityRole = "none"
	require.False(t, e.valid())
	e.Outcome, e.Reason = "denied", "authority_denied"
	require.True(t, e.valid())
	e.ActorKind, e.ActorID, e.HomeOrganizationID = "unknown", uuid.Nil, uuid.Nil
	e.AuthoritySource, e.AuthorityRole, e.OrganizationRole = "unknown", "unknown", "unknown"
	require.True(t, e.valid())
	e.Outcome, e.Reason = "committed", "deleted"
	require.False(t, e.valid())
	e.ActorKind, e.AuthoritySource, e.AuthorityRole = "internal_system", "trusted_internal_system", "internal_system"
	require.True(t, e.valid())
	require.ErrorIs(t, RecordFailures(nil, []Event{e}), ErrUnavailable)
}
