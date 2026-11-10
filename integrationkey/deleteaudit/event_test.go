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
	org := uuid.New()
	return Event{SchemaVersion: 1, EventID: uuid.New(), RequestID: uuid.New(), ExecutionID: uuid.New(), AttemptID: uuid.New(), RecordKind: "success_witness", ResourceID: uuid.New(), ParentServiceID: uuid.New(), TargetOrganizationID: org, TargetOrgResolution: "known_normal", Provenance: "EXPLICIT", DeletionMechanism: "explicit_sql", Cause: "explicit_target", ActorKind: "human", ActorID: uuid.New(), HomeOrganizationID: org, AuthoritySource: "current_local_user_organization_at_admission", AuthorityRole: "org_admin", OrganizationRole: "ORG_ADMIN", Outcome: "committed", Reason: "deleted", OccurredAt: time.Now()}
}
func TestStrictEventValidation(t *testing.T) {
	e := validEvent()
	require.NoError(t, e.Validate())
	require.ErrorIs(t, Append(context.Background(), nil, e), ErrUnavailable)
	for name, change := range map[string]func(*Event){
		"version": func(e *Event) { e.SchemaVersion = 2 }, "event": func(e *Event) { e.EventID = uuid.Nil }, "request": func(e *Event) { e.RequestID = uuid.Nil }, "execution": func(e *Event) { e.ExecutionID = uuid.Nil }, "attempt": func(e *Event) { e.AttemptID = uuid.Nil }, "time": func(e *Event) { e.OccurredAt = time.Time{} }, "root": func(e *Event) { e.ResourceID = uuid.Nil }, "parent": func(e *Event) { e.ParentServiceID = uuid.Nil }, "target": func(e *Event) { e.TargetOrganizationID = uuid.Nil }, "classification": func(e *Event) { e.TargetOrgResolution = "unknown" }, "cascade": func(e *Event) { e.Provenance = "CASCADE" }, "cause": func(e *Event) { e.Cause = "SYNTHETIC_SECRET" },
		"mechanism": func(e *Event) { e.DeletionMechanism = "fk_cascade" }, "outcome": func(e *Event) { e.Outcome = "tx_failed" }, "reason": func(e *Event) { e.Reason = "SYNTHETIC_SECRET" }, "actor": func(e *Event) { e.ActorKind = "unknown" }, "member": func(e *Event) { e.AuthorityRole = "org_member"; e.OrganizationRole = "ORG_MEMBER" }, "foreign": func(e *Event) { e.HomeOrganizationID = uuid.New() }, "source": func(e *Event) { e.AuthoritySource = "caller" }, "kind": func(e *Event) { e.RecordKind = "other" },
	} {
		t.Run(name, func(t *testing.T) {
			e := validEvent()
			change(&e)
			require.ErrorIs(t, e.Validate(), ErrInvalid)
			require.ErrorIs(t, Append(context.Background(), nil, e), ErrInvalid)
		})
	}
	e = validEvent()
	e.AuthorityRole = "platform_admin"
	e.HomeOrganizationID = uuid.MustParse(organization.DefaultOrganizationID)
	e.OrganizationRole = "NONE"
	require.NoError(t, e.Validate())
	e = validEvent()
	e.ActorKind, e.ActorID, e.HomeOrganizationID, e.AuthoritySource, e.AuthorityRole, e.OrganizationRole = "internal_system", uuid.Nil, uuid.Nil, "trusted_internal_system", "internal_system", "unknown"
	require.NoError(t, e.Validate())
	for outcome, reasons := range map[string][]string{"denied": {"authority_denied"}, "validation_failed": {"invalid_fields", "target_unavailable"}, "tx_failed": {"begin_failed", "write_failed", "audit_write_failed", "commit_rejected"}, "commit_unknown": {"commit_unconfirmed"}, "rollback_unconfirmed": {"rollback_unconfirmed"}} {
		for _, reason := range reasons {
			e := validEvent()
			e.RecordKind, e.Outcome, e.Reason, e.Provenance, e.DeletionMechanism, e.Cause = "attempt_observation", outcome, reason, "", "", ""
			require.NoError(t, e.Validate())
			e.ActorKind, e.ActorID, e.HomeOrganizationID, e.AuthoritySource, e.AuthorityRole, e.OrganizationRole = "unknown", uuid.Nil, uuid.Nil, "unknown", "unknown", "unknown"
			e.ResourceID, e.ParentServiceID, e.TargetOrganizationID, e.TargetOrgResolution = uuid.Nil, uuid.Nil, uuid.Nil, "unknown"
			require.NoError(t, e.Validate())
			e.Reason = "SYNTHETIC_SECRET"
			require.ErrorIs(t, e.Validate(), ErrInvalid)
		}
	}
	canonical := validEvent().Canonical()
	require.Equal(t, time.UTC, canonical.OccurredAt.Location())
	require.Zero(t, canonical.OccurredAt.Nanosecond()%1000)
}
