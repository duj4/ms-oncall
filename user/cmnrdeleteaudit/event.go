// Package cmnrdeleteaudit persists the SD2 DeleteAll witness. It grants no
// authorization, owns no business transaction and never retries a deletion.
package cmnrdeleteaudit

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/target/goalert/organization"
)

const (
	// These are witness resource bounds, not a business deletion quota. Exceeding
	// either fails the owning transaction closed; nothing is truncated.
	MaxEffects       = 16384
	MaxJSONBytes     = 8 << 20
	ContactMethod    = "contact_method"
	NotificationRule = "notification_rule"
)

var (
	ErrInvalid     = errors.New("invalid cmnr.delete audit event")
	ErrUnavailable = errors.New("cmnr.delete audit persistence unavailable")
	ErrConflict    = errors.New("cmnr.delete audit event identity conflict")
	ErrCapacity    = errors.New("cmnr.delete complete witness exceeds safe capacity")
)

// Effect is a closed, safe projection. Nullable identities stay JSON null. In
// particular, an AuthSubject's bigint never passes through a float64.
type Effect struct {
	EffectID             uuid.UUID  `json:"effect_id"`
	ResourceType         string     `json:"resource_type"`
	ResourceUUID         *uuid.UUID `json:"resource_uuid"`
	ResourceNumericID    *int64     `json:"resource_numeric_id"`
	OwnerUserID          uuid.UUID  `json:"owner_user_id"`
	TargetOrganizationID *uuid.UUID `json:"target_organization_id"`
	OrgResolution        string     `json:"org_resolution"`
	Relation             string     `json:"relation"`
	Change               string     `json:"change"`
	Provenance           string     `json:"provenance"`
}

// RelatedExplicitEvent references an explicit NR witness in this same attempt.
// The CM does not duplicate that NR in its implicit cascade effects.
type RelatedExplicitEvent struct {
	EventID  uuid.UUID `json:"event_id"`
	Relation string    `json:"relation"`
}

type Event struct {
	EventID, RequestID, ExecutionID, AttemptID       uuid.UUID
	RecordKind, Operation, RootType                  string
	RootID, RootOwnerUserID, TargetOrganizationID    uuid.UUID
	TargetOrgResolution                              string
	ParentCMID                                       uuid.UUID
	Provenance, DeletionMechanism                    string
	CauseEventID                                     uuid.UUID
	ActorKind                                        string
	ActorID, RepresentedHumanID, HomeOrganizationID  uuid.UUID
	AuthoritySource, AuthorityRole, OrganizationRole string
	Effects                                          []Effect
	RelatedExplicitEvents                            []RelatedExplicitEvent
	Outcome, Reason                                  string
	OccurredAt                                       time.Time
}

func validOrg(id uuid.UUID, resolution string) bool {
	switch resolution {
	case "unknown":
		return id == uuid.Nil
	case "known_normal":
		return id != uuid.Nil && id.String() != organization.DefaultOrganizationID
	case "known_default":
		return id.String() == organization.DefaultOrganizationID
	}
	return false
}

func ptrID(id *uuid.UUID) uuid.UUID {
	if id == nil {
		return uuid.Nil
	}
	return *id
}
func NullableID(id uuid.UUID) *uuid.UUID {
	if id == uuid.Nil {
		return nil
	}
	return &id
}

func effectKey(e Effect) string {
	if e.ResourceNumericID != nil {
		return fmt.Sprintf("%s/%020d/%s", e.ResourceType, *e.ResourceNumericID, e.Relation)
	}
	return e.ResourceType + "/" + ptrID(e.ResourceUUID).String() + "/" + e.Relation
}

// Canonical freezes order and microsecond time without generating new IDs.
func (e Event) Canonical() Event {
	e.Effects = append([]Effect{}, e.Effects...)
	e.RelatedExplicitEvents = append([]RelatedExplicitEvent{}, e.RelatedExplicitEvents...)
	slices.SortFunc(e.Effects, func(a, b Effect) int {
		if effectKey(a) < effectKey(b) {
			return -1
		}
		if effectKey(a) > effectKey(b) {
			return 1
		}
		return 0
	})
	slices.SortFunc(e.RelatedExplicitEvents, func(a, b RelatedExplicitEvent) int { return slices.Compare(a.EventID[:], b.EventID[:]) })
	e.OccurredAt = e.OccurredAt.UTC().Truncate(time.Microsecond)
	return e
}

func (e Event) Validate() error {
	if e.EventID == uuid.Nil || e.RequestID == uuid.Nil || e.ExecutionID == uuid.Nil || e.AttemptID == uuid.Nil || e.OccurredAt.IsZero() || e.OccurredAt.Year() < 1 || e.OccurredAt.Year() > 9999 || e.RepresentedHumanID != uuid.Nil {
		return ErrInvalid
	}
	if !validOrg(e.TargetOrganizationID, e.TargetOrgResolution) {
		return ErrInvalid
	}
	if e.RootID == uuid.Nil {
		if e.RootType != "" || e.RootOwnerUserID != uuid.Nil || e.ParentCMID != uuid.Nil || e.TargetOrgResolution != "unknown" {
			return ErrInvalid
		}
	} else {
		if e.RootOwnerUserID == uuid.Nil {
			return ErrInvalid
		}
		switch e.RootType {
		case ContactMethod:
			if e.Operation != "contact_method.delete" || e.ParentCMID != uuid.Nil {
				return ErrInvalid
			}
		case NotificationRule:
			if e.Operation != "notification_rule.delete" || e.ParentCMID == uuid.Nil {
				return ErrInvalid
			}
		default:
			return ErrInvalid
		}
	}
	if e.Operation != "contact_method.delete" && e.Operation != "notification_rule.delete" && e.Operation != "cmnr.delete_attempt" {
		return ErrInvalid
	}
	if e.Operation == "cmnr.delete_attempt" && e.RootID != uuid.Nil {
		return ErrInvalid
	}
	success := e.RecordKind == "success_witness"
	if success {
		if e.Outcome != "committed" || e.Reason != "deleted" || e.RootID == uuid.Nil || e.Provenance != "EXPLICIT" {
			return ErrInvalid
		}
		if e.DeletionMechanism == "fk_cascade" {
			if e.RootType != NotificationRule || e.CauseEventID == uuid.Nil || e.CauseEventID == e.EventID {
				return ErrInvalid
			}
		} else if e.DeletionMechanism != "explicit_sql" || e.CauseEventID != uuid.Nil {
			return ErrInvalid
		}
	} else {
		if e.RecordKind != "attempt_observation" || e.Provenance != "" || e.DeletionMechanism != "" || e.CauseEventID != uuid.Nil || len(e.Effects) != 0 || len(e.RelatedExplicitEvents) != 0 {
			return ErrInvalid
		}
		valid := false
		switch e.Outcome {
		case "denied":
			valid = e.Reason == "authority_denied"
		case "validation_failed":
			valid = e.Reason == "invalid_fields" || e.Reason == "target_unavailable"
		case "tx_failed":
			valid = e.Reason == "begin_failed" || e.Reason == "write_failed" || e.Reason == "audit_write_failed" || e.Reason == "commit_rejected"
		case "commit_unknown":
			valid = e.Reason == "commit_unconfirmed"
		case "rollback_unconfirmed":
			valid = e.Reason == "rollback_unconfirmed"
		}
		if !valid {
			return ErrInvalid
		}
	}
	switch e.ActorKind {
	case "human":
		if e.ActorID == uuid.Nil || e.HomeOrganizationID == uuid.Nil || e.AuthoritySource != "current_local_user_organization_at_admission" {
			return ErrInvalid
		}
		if e.HomeOrganizationID.String() == organization.DefaultOrganizationID {
			if e.OrganizationRole != "NONE" || (e.AuthorityRole != "platform_admin" && e.AuthorityRole != "none") {
				return ErrInvalid
			}
		} else if (e.OrganizationRole != "ORG_ADMIN" && e.OrganizationRole != "ORG_MEMBER") || !(e.AuthorityRole == "platform_admin" || e.AuthorityRole == "org_admin" && e.OrganizationRole == "ORG_ADMIN" || e.AuthorityRole == "org_member" && e.OrganizationRole == "ORG_MEMBER") {
			return ErrInvalid
		}
		if success && (e.TargetOrgResolution != "known_normal" || e.AuthorityRole != "platform_admin" && (e.ActorID != e.RootOwnerUserID || e.HomeOrganizationID != e.TargetOrganizationID || e.AuthorityRole == "none")) {
			return ErrInvalid
		}
	case "internal_system":
		if e.ActorID != uuid.Nil || e.HomeOrganizationID != uuid.Nil || e.AuthoritySource != "trusted_internal_system" || e.AuthorityRole != "internal_system" || e.OrganizationRole != "unknown" {
			return ErrInvalid
		}
	case "unknown":
		if success || e.ActorID != uuid.Nil || e.HomeOrganizationID != uuid.Nil || e.AuthoritySource != "unknown" || e.AuthorityRole != "unknown" || e.OrganizationRole != "unknown" {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	if len(e.Effects) > MaxEffects {
		return ErrCapacity
	}
	if e.RootType != ContactMethod && (len(e.Effects) != 0 || len(e.RelatedExplicitEvents) != 0) {
		return ErrInvalid
	}
	seenIDs, seenKeys := map[uuid.UUID]bool{}, map[string]bool{}
	for _, f := range e.Effects {
		if f.EffectID == uuid.Nil || f.OwnerUserID == uuid.Nil || !validOrg(ptrID(f.TargetOrganizationID), f.OrgResolution) || f.TargetOrganizationID != nil && *f.TargetOrganizationID == uuid.Nil || f.ResourceUUID != nil && *f.ResourceUUID == uuid.Nil || seenIDs[f.EffectID] || seenKeys[effectKey(f)] {
			return ErrInvalid
		}
		seenIDs[f.EffectID], seenKeys[effectKey(f)] = true, true
		switch f.ResourceType {
		case NotificationRule:
			if f.ResourceUUID == nil || f.ResourceNumericID != nil || f.Relation != "contact_method.notification_rule" || f.Change != "deleted" || f.Provenance != "IMPLICIT_FK_CASCADE" || f.OwnerUserID != e.RootOwnerUserID || ptrID(f.TargetOrganizationID) != e.TargetOrganizationID || f.OrgResolution != e.TargetOrgResolution {
				return ErrInvalid
			}
		case "auth_subject":
			if f.ResourceUUID != nil || f.ResourceNumericID == nil || *f.ResourceNumericID <= 0 || f.Relation != "contact_method.auth_subject" || f.Change != "deleted" || f.Provenance != "IMPLICIT_FK_CASCADE" {
				return ErrInvalid
			}
		case "user_status_contact_setting":
			if f.ResourceUUID == nil || f.ResourceNumericID != nil || *f.ResourceUUID != f.OwnerUserID || f.Relation != "user.alert_status_log_contact_method" || f.Change != "relationship_cleared" || f.Provenance != "IMPLICIT_FK_SET_NULL" {
				return ErrInvalid
			}
		default:
			return ErrInvalid
		}
	}
	seenRelated := map[uuid.UUID]bool{}
	if len(e.RelatedExplicitEvents) > 50 {
		return ErrInvalid
	}
	for _, r := range e.RelatedExplicitEvents {
		if r.EventID == uuid.Nil || r.EventID == e.EventID || r.Relation != "parent_cm" || seenRelated[r.EventID] {
			return ErrInvalid
		}
		seenRelated[r.EventID] = true
	}
	b, err := json.Marshal(e.Effects)
	if err != nil {
		return ErrInvalid
	}
	if len(b) > MaxJSONBytes {
		return ErrCapacity
	}
	return nil
}

// Append stages an immutable event, with full-content EventID replay checking.
// Its return says nothing about the owning transaction's Commit result.
func Append(ctx context.Context, tx *sql.Tx, event Event) error {
	if len(event.Effects) > MaxEffects {
		return ErrCapacity
	}
	if len(event.RelatedExplicitEvents) > 50 {
		return ErrInvalid
	}
	e := event.Canonical()
	if err := e.Validate(); err != nil {
		return err
	}
	if tx == nil {
		return ErrUnavailable
	}
	effects, _ := json.Marshal(e.Effects)
	related, _ := json.Marshal(e.RelatedExplicitEvents)
	args := []any{e.EventID, e.RequestID, e.ExecutionID, e.AttemptID, e.RecordKind, e.Operation, nullableText(e.RootType), NullableID(e.RootID), NullableID(e.RootOwnerUserID), NullableID(e.TargetOrganizationID), e.TargetOrgResolution, NullableID(e.ParentCMID), nullableText(e.Provenance), nullableText(e.DeletionMechanism), NullableID(e.CauseEventID), e.ActorKind, NullableID(e.ActorID), NullableID(e.RepresentedHumanID), NullableID(e.HomeOrganizationID), e.AuthoritySource, e.AuthorityRole, e.OrganizationRole, string(effects), string(related), e.Outcome, e.Reason, e.OccurredAt}
	const cols = `event_id,request_id,execution_id,attempt_id,record_kind,operation,root_type,root_id,root_owner_user_id,target_organization_id,target_org_resolution,parent_cm_id,provenance,deletion_mechanism,cause_event_id,actor_kind,actor_id,represented_human_id,home_organization_id,authority_source,authority_role,organization_role,effects,related_explicit_events,outcome,reason_code,occurred_at`
	const vals = `$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23::jsonb,$24::jsonb,$25,$26,$27`
	r, err := tx.ExecContext(ctx, `INSERT INTO user_cmnr_delete_audit_events (`+cols+`) VALUES (`+vals+`) ON CONFLICT(event_id) DO NOTHING`, args...)
	if err != nil {
		return ErrUnavailable
	}
	n, err := r.RowsAffected()
	if err != nil {
		return ErrUnavailable
	}
	if n == 1 {
		return nil
	}
	var same bool
	err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT FROM user_cmnr_delete_audit_events WHERE event_id=$1 AND ROW(`+cols+`) IS NOT DISTINCT FROM ROW(`+vals+`))`, args...).Scan(&same)
	if err != nil {
		return ErrUnavailable
	}
	if !same {
		return ErrConflict
	}
	return nil
}

func nullableText(v string) any {
	if v == "" {
		return nil
	}
	return v
}
