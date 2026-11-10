package cmnrdeleteaudit

import (
	"encoding/json"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/target/goalert/organization"
)

func validEvent() Event {
	owner, org := uuid.New(), uuid.New()
	return Event{EventID: uuid.New(), RequestID: uuid.New(), ExecutionID: uuid.New(), AttemptID: uuid.New(), RecordKind: "success_witness", Operation: "contact_method.delete", RootType: ContactMethod, RootID: uuid.New(), RootOwnerUserID: owner, TargetOrganizationID: org, TargetOrgResolution: "known_normal", Provenance: "EXPLICIT", DeletionMechanism: "explicit_sql", ActorKind: "human", ActorID: owner, HomeOrganizationID: org, AuthoritySource: "current_local_user_organization_at_admission", AuthorityRole: "org_member", OrganizationRole: "ORG_MEMBER", Outcome: "committed", Reason: "deleted", OccurredAt: time.Now()}
}

func TestEventIdentityAndClosedValidation(t *testing.T) {
	require.NoError(t, validEvent().Validate(), "Member owner self-service must remain valid")
	for _, role := range []string{"ORG_MEMBER", "ORG_ADMIN", "NONE"} {
		e := validEvent()
		e.AuthorityRole = "platform_admin"
		e.ActorID = uuid.New()
		e.OrganizationRole = role
		if role == "NONE" {
			e.HomeOrganizationID = uuid.MustParse(organization.DefaultOrganizationID)
		}
		require.NoError(t, e.Validate())
	}
	for name, change := range map[string]func(*Event){
		"zero event": func(e *Event) { e.EventID = uuid.Nil }, "zero request": func(e *Event) { e.RequestID = uuid.Nil }, "zero execution": func(e *Event) { e.ExecutionID = uuid.Nil }, "zero attempt": func(e *Event) { e.AttemptID = uuid.Nil },
		"represented": func(e *Event) { e.RepresentedHumanID = uuid.New() }, "machine": func(e *Event) { e.ActorKind = "machine" }, "unknown success": func(e *Event) { e.ActorKind = "unknown" }, "other owner": func(e *Event) { e.RootOwnerUserID = uuid.New() }, "foreign": func(e *Event) { e.TargetOrganizationID = uuid.New() }, "unknown human target": func(e *Event) { e.TargetOrganizationID = uuid.Nil; e.TargetOrgResolution = "unknown" }, "bad provenance": func(e *Event) { e.Provenance = "CASCADE" }, "bad outcome": func(e *Event) { e.Outcome = "commit_unknown" }, "bad reason": func(e *Event) { e.Reason = "write_failed" }, "bad operation": func(e *Event) { e.Operation = "user.delete" }, "bad root": func(e *Event) { e.RootType = "user" }, "bad parent": func(e *Event) { e.ParentCMID = uuid.New() }, "bad cause": func(e *Event) { e.CauseEventID = uuid.New() },
	} {
		t.Run(name, func(t *testing.T) { e := validEvent(); change(&e); require.ErrorIs(t, e.Validate(), ErrInvalid) })
	}
	for outcome, reasons := range map[string][]string{"denied": {"authority_denied"}, "validation_failed": {"invalid_fields", "target_unavailable"}, "tx_failed": {"begin_failed", "write_failed", "audit_write_failed", "commit_rejected"}, "commit_unknown": {"commit_unconfirmed"}, "rollback_unconfirmed": {"rollback_unconfirmed"}} {
		for _, reason := range reasons {
			e := validEvent()
			e.RecordKind = "attempt_observation"
			e.Outcome, e.Reason = outcome, reason
			e.Provenance, e.DeletionMechanism = "", ""
			require.NoError(t, e.Validate())
			e.Reason = "deleted"
			require.Error(t, e.Validate())
		}
	}
	e := validEvent()
	e.ActorKind, e.AuthoritySource, e.AuthorityRole, e.OrganizationRole = "internal_system", "trusted_internal_system", "internal_system", "unknown"
	e.ActorID, e.HomeOrganizationID, e.TargetOrganizationID = uuid.Nil, uuid.Nil, uuid.Nil
	e.TargetOrgResolution = "unknown"
	require.NoError(t, e.Validate())
}

func TestEffectsCanonicalCapacityAndPrivacy(t *testing.T) {
	e := validEvent()
	id := int64(math.MaxInt64)
	e.Effects = []Effect{{EffectID: uuid.New(), ResourceType: "auth_subject", ResourceNumericID: &id, OwnerUserID: e.ActorID, OrgResolution: "unknown", Relation: "contact_method.auth_subject", Change: "deleted", Provenance: "IMPLICIT_FK_CASCADE"}}
	require.NoError(t, e.Validate())
	raw, err := json.Marshal(e.Canonical().Effects)
	require.NoError(t, err)
	require.Contains(t, string(raw), "9223372036854775807")
	require.Contains(t, string(raw), `"resource_uuid":null`)
	var fields []map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(raw, &fields))
	require.Len(t, fields[0], 10)
	for _, secret := range []string{"provider", "subject_id", "dest", "email", "phone", "verification", "session", "token"} {
		require.NotContains(t, string(raw), `"`+secret+`"`)
	}
	e.Effects = append(e.Effects, e.Effects[0])
	require.ErrorIs(t, e.Validate(), ErrInvalid)
	e = validEvent()
	for i := 0; i < MaxEffects; i++ {
		n := int64(i + 1)
		e.Effects = append(e.Effects, Effect{EffectID: uuid.New(), ResourceType: "auth_subject", ResourceNumericID: &n, OwnerUserID: e.ActorID, OrgResolution: "unknown", Relation: "contact_method.auth_subject", Change: "deleted", Provenance: "IMPLICIT_FK_CASCADE"})
	}
	require.NoError(t, e.Validate())
	canonical := e.Canonical()
	require.Equal(t, canonical, canonical.Canonical())
	require.Equal(t, 0, canonical.OccurredAt.Nanosecond()%1000)
	e.Effects = append(e.Effects, e.Effects[0])
	require.ErrorIs(t, e.Validate(), ErrCapacity)
	e = validEvent()
	e.Effects = []Effect{{EffectID: uuid.New(), ResourceType: strings.Repeat("x", MaxJSONBytes), OwnerUserID: e.ActorID}}
	require.Error(t, e.Validate())
}
