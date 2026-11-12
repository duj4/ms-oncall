// Package deleteaudit records User deletion in the caller's transaction.
// It grants no authority and never commits, retries, or owns a connection.
package deleteaudit

import (
	"encoding/json"
	"errors"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/target/goalert/organization"
)

const (
	MaxRoots           = 100
	PageSize           = 256
	MaxCaptureUnits    = 4096
	MaxActiveJSONBytes = 4194304
	MaxLeafBytes       = 4096
	MaxHeaderBytes     = 32768
)

var (
	ErrInvalid     = errors.New("invalid user.delete audit evidence")
	ErrCapacity    = errors.New("user.delete audit resident capacity exceeded")
	ErrUnavailable = errors.New("user.delete audit persistence unavailable")
	ErrConflict    = errors.New("user.delete audit identity conflict")
)

type Before struct {
	Version              int        `json:"version"`
	UserID               uuid.UUID  `json:"user_id"`
	UserRole             string     `json:"user_role"`
	RowVersion           uint32     `json:"row_version"`
	AssignmentPresent    bool       `json:"assignment_present"`
	AssignmentRowVersion *uint32    `json:"assignment_row_version"`
	TargetOrganizationID *uuid.UUID `json:"target_organization_id"`
	TargetOrgResolution  string     `json:"target_org_resolution"`
	OrganizationRole     string     `json:"organization_role"`
}

type RelatedExplicitEvent struct {
	EventID      uuid.UUID `json:"event_id"`
	ResourceType string    `json:"resource_type"`
	ResourceID   uuid.UUID `json:"resource_id"`
}

// Event is a bounded header. Effects are never retained in this value.
type Event struct {
	SchemaVersion         int                    `json:"schema_version"`
	EventID               uuid.UUID              `json:"event_id"`
	RequestID             uuid.UUID              `json:"request_id"`
	ExecutionID           uuid.UUID              `json:"execution_id"`
	AttemptID             uuid.UUID              `json:"attempt_id"`
	RecordKind            string                 `json:"record_kind"`
	Operation             string                 `json:"operation"`
	RootType              string                 `json:"root_type"`
	RootID                *uuid.UUID             `json:"root_id"`
	RootOrdinal           *int                   `json:"root_ordinal"`
	ActorKind             string                 `json:"actor_kind"`
	ActorID               *uuid.UUID             `json:"actor_id"`
	HomeOrganizationID    *uuid.UUID             `json:"home_organization_id"`
	AuthoritySource       string                 `json:"authority_source"`
	AuthorityRole         string                 `json:"authority_role"`
	OrganizationRole      string                 `json:"organization_role"`
	TargetOrganizationID  *uuid.UUID             `json:"target_organization_id"`
	TargetOrgResolution   string                 `json:"target_org_resolution"`
	BeforeContext         *Before                `json:"before_context"`
	Provenance            string                 `json:"provenance"`
	DeletionMechanism     string                 `json:"deletion_mechanism"`
	Cause                 string                 `json:"cause"`
	EffectCount           int64                  `json:"effect_count"`
	EffectJSONBytes       int64                  `json:"effect_json_bytes"`
	Manifest              map[string]int64       `json:"manifest"`
	RelatedExplicitEvents []RelatedExplicitEvent `json:"related_explicit_events"`
	Outcome               string                 `json:"outcome"`
	Reason                string                 `json:"reason_code"`
	OccurredAt            time.Time              `json:"occurred_at"`
}

func ID(id uuid.UUID) *uuid.UUID {
	if id == uuid.Nil {
		return nil
	}
	return &id
}
func value(id *uuid.UUID) uuid.UUID {
	if id == nil {
		return uuid.Nil
	}
	return *id
}
func ValidOrganization(id *uuid.UUID, resolution string) bool {
	switch resolution {
	case "unknown":
		return id == nil
	case "known_normal":
		return id != nil && *id != uuid.Nil && id.String() != organization.DefaultOrganizationID
	case "known_default":
		return id != nil && id.String() == organization.DefaultOrganizationID
	}
	return false
}

func (e Event) Canonical() Event {
	e.OccurredAt = e.OccurredAt.UTC().Truncate(time.Microsecond)
	e.RelatedExplicitEvents = append([]RelatedExplicitEvent{}, e.RelatedExplicitEvents...)
	slices.SortFunc(e.RelatedExplicitEvents, func(a, b RelatedExplicitEvent) int { return slices.Compare(a.EventID[:], b.EventID[:]) })
	m := make(map[string]int64, len(e.Manifest))
	for k, v := range e.Manifest {
		m[k] = v
	}
	e.Manifest = m
	return e
}

func (e Event) Validate() error {
	if e.SchemaVersion != 1 || e.EventID == uuid.Nil || e.RequestID == uuid.Nil || e.ExecutionID == uuid.Nil || e.AttemptID == uuid.Nil || e.OccurredAt.IsZero() || e.OccurredAt.Year() < 1 || e.OccurredAt.Year() > 9999 || e.Operation != "user.delete" || e.RootType != "user" || !ValidOrganization(e.TargetOrganizationID, e.TargetOrgResolution) {
		return ErrInvalid
	}
	if e.RootID != nil && *e.RootID == uuid.Nil || e.ActorID != nil && *e.ActorID == uuid.Nil || e.HomeOrganizationID != nil && *e.HomeOrganizationID == uuid.Nil {
		return ErrInvalid
	}
	success := e.RecordKind == "success_witness"
	switch e.ActorKind {
	case "human":
		if e.ActorID == nil || e.HomeOrganizationID == nil || e.AuthoritySource != "current_local_user_organization_at_admission" {
			return ErrInvalid
		}
		if e.HomeOrganizationID.String() == organization.DefaultOrganizationID {
			if e.OrganizationRole != "NONE" || e.AuthorityRole != "platform_admin" && e.AuthorityRole != "none" {
				return ErrInvalid
			}
		} else if (e.OrganizationRole != "ORG_ADMIN" && e.OrganizationRole != "ORG_MEMBER") || (e.AuthorityRole != "platform_admin" && (e.AuthorityRole != "org_admin" || e.OrganizationRole != "ORG_ADMIN") && (e.AuthorityRole != "org_member" || e.OrganizationRole != "ORG_MEMBER")) {
			return ErrInvalid
		}
		if success && (e.AuthorityRole != "platform_admin" || e.HomeOrganizationID.String() == organization.DefaultOrganizationID && e.TargetOrgResolution != "known_normal") {
			return ErrInvalid
		}
	case "internal_system":
		if e.ActorID != nil || e.HomeOrganizationID != nil || e.AuthoritySource != "trusted_internal_system" || e.AuthorityRole != "internal_system" || e.OrganizationRole != "unknown" {
			return ErrInvalid
		}
	case "unknown":
		if success || e.ActorID != nil || e.HomeOrganizationID != nil || e.AuthoritySource != "unknown" || e.AuthorityRole != "unknown" || e.OrganizationRole != "unknown" {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	if e.RootID == nil && (e.RootOrdinal != nil || e.TargetOrganizationID != nil || e.TargetOrgResolution != "unknown") {
		return ErrInvalid
	}
	if e.RootOrdinal != nil && (*e.RootOrdinal < 0 || *e.RootOrdinal >= MaxRoots) {
		return ErrInvalid
	}
	if success {
		b := e.BeforeContext
		if e.Outcome != "committed" || e.Reason != "deleted" || e.Provenance != "EXPLICIT" || e.DeletionMechanism != "explicit_sql" || e.Cause != "explicit_target" || e.RootID == nil || e.RootOrdinal == nil || b == nil || b.Version != 1 || b.UserID != *e.RootID || b.RowVersion == 0 || (b.UserRole != "user" && b.UserRole != "admin" && b.UserRole != "unknown") || !ValidOrganization(b.TargetOrganizationID, b.TargetOrgResolution) || value(b.TargetOrganizationID) != value(e.TargetOrganizationID) || b.TargetOrgResolution != e.TargetOrgResolution {
			return ErrInvalid
		}
		if b.AssignmentPresent != (b.AssignmentRowVersion != nil) || b.AssignmentRowVersion != nil && *b.AssignmentRowVersion == 0 {
			return ErrInvalid
		}
		if !b.AssignmentPresent && (b.OrganizationRole != "unknown" || b.TargetOrgResolution != "unknown") {
			return ErrInvalid
		}
		if b.OrganizationRole != "unknown" && b.OrganizationRole != "NONE" && b.OrganizationRole != "ORG_ADMIN" && b.OrganizationRole != "ORG_MEMBER" {
			return ErrInvalid
		}
	} else {
		if e.RecordKind != "attempt_observation" || e.BeforeContext != nil || e.Provenance != "" || e.DeletionMechanism != "" || e.Cause != "" || e.EffectCount != 0 || e.EffectJSONBytes != 0 || len(e.Manifest) != 0 || len(e.RelatedExplicitEvents) != 0 {
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
	if e.EffectCount < 0 || e.EffectJSONBytes < 0 || e.EffectCount == 0 && e.EffectJSONBytes != 0 || e.EffectCount > 0 && e.EffectJSONBytes < e.EffectCount {
		return ErrInvalid
	}
	var count int64
	for typ, n := range e.Manifest {
		if _, ok := projections[typ]; !ok || n <= 0 || count > e.EffectCount-n {
			return ErrInvalid
		}
		count += n
	}
	if count != e.EffectCount || len(e.RelatedExplicitEvents) > 100 {
		return ErrInvalid
	}
	seen := map[uuid.UUID]bool{}
	keys := map[string]bool{}
	for _, r := range e.RelatedExplicitEvents {
		key := r.ResourceType + r.ResourceID.String()
		if r.EventID == uuid.Nil || r.ResourceID == uuid.Nil || r.EventID == e.EventID || seen[r.EventID] || keys[key] || r.ResourceType != "contact_method" && r.ResourceType != "notification_rule" {
			return ErrInvalid
		}
		seen[r.EventID] = true
		keys[key] = true
	}
	data, err := json.Marshal(e)
	if err != nil {
		return ErrInvalid
	}
	return checkJSONBytes(data, MaxHeaderBytes)
}

func checkJSONBytes(raw []byte, limit int) error {
	if len(raw) > limit {
		return ErrCapacity
	}
	return nil
}
