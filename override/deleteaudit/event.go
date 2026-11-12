// Package deleteaudit persists safe explicit UserOverride deletion witnesses.
// It grants no authority, owns no transaction and never retries business work.
package deleteaudit

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/target/goalert/organization"
)

var (
	ErrInvalid     = errors.New("invalid user_override.delete audit event")
	ErrUnavailable = errors.New("user_override.delete audit persistence unavailable")
	ErrConflict    = errors.New("user_override.delete audit event identity conflict")
	ErrCapacity    = errors.New("user_override.delete audit capacity exceeded")
)

const (
	MaxRoots         = 50
	MaxRootJSONBytes = 4 * 1024
	MaxJSONBytes     = 256 * 1024
)

// Before is the complete safe persisted row version. Referenced Users and the
// parent Schedule are context, never child deletion effects.
type Before struct {
	Version              int        `json:"version"`
	RootID               uuid.UUID  `json:"root_id"`
	ParentScheduleID     uuid.UUID  `json:"parent_schedule_id"`
	TargetOrganizationID uuid.UUID  `json:"target_organization_id"`
	AddUserID            *uuid.UUID `json:"add_user_id"`
	RemoveUserID         *uuid.UUID `json:"remove_user_id"`
	Start                time.Time  `json:"start"`
	End                  time.Time  `json:"end"`
	RowVersion           uint32     `json:"row_version"`
}

// Event contains only closed, bounded identity and classification fields.
// Effects has zero capacity: explicit Override deletion has no child effects.
type Event struct {
	SchemaVersion        int         `json:"schema_version"`
	EventID              uuid.UUID   `json:"event_id"`
	RequestID            uuid.UUID   `json:"request_id"`
	ExecutionID          uuid.UUID   `json:"execution_id"`
	AttemptID            uuid.UUID   `json:"attempt_id"`
	RecordKind           string      `json:"record_kind"`
	Operation            string      `json:"operation"`
	RootType             string      `json:"root_type"`
	RootID               uuid.UUID   `json:"root_id"`
	ParentScheduleID     uuid.UUID   `json:"parent_schedule_id"`
	TargetOrganizationID uuid.UUID   `json:"target_organization_id"`
	TargetOrgResolution  string      `json:"target_org_resolution"`
	BeforeContext        *Before     `json:"before_context"`
	Effects              [0]struct{} `json:"effects"`
	Provenance           string      `json:"provenance"`
	DeletionMechanism    string      `json:"deletion_mechanism"`
	Cause                string      `json:"cause"`
	ActorKind            string      `json:"actor_kind"`
	ActorID              uuid.UUID   `json:"actor_id"`
	HomeOrganizationID   uuid.UUID   `json:"home_organization_id"`
	AuthoritySource      string      `json:"authority_source"`
	AuthorityRole        string      `json:"authority_role"`
	OrganizationRole     string      `json:"organization_role"`
	Outcome              string      `json:"outcome"`
	Reason               string      `json:"reason_code"`
	OccurredAt           time.Time   `json:"occurred_at"`
}

func (e Event) Canonical() Event {
	e.OccurredAt = e.OccurredAt.UTC().Truncate(time.Microsecond)
	if e.BeforeContext != nil {
		b := *e.BeforeContext
		b.Start, b.End = b.Start.UTC().Truncate(time.Microsecond), b.End.UTC().Truncate(time.Microsecond)
		e.BeforeContext = &b
	}
	return e
}

func (e Event) Validate() error {
	if e.Operation != "user_override.delete" || e.RootType != "user_override" || e.SchemaVersion != 1 || e.EventID == uuid.Nil || e.RequestID == uuid.Nil || e.ExecutionID == uuid.Nil || e.AttemptID == uuid.Nil || e.OccurredAt.IsZero() || e.OccurredAt.Year() < 1 || e.OccurredAt.Year() > 9999 {
		return ErrInvalid
	}
	if e.RootID == uuid.Nil {
		if e.ParentScheduleID != uuid.Nil || e.TargetOrganizationID != uuid.Nil || e.TargetOrgResolution != "unknown" {
			return ErrInvalid
		}
	} else if e.ParentScheduleID == uuid.Nil || e.TargetOrganizationID == uuid.Nil || (e.TargetOrgResolution != "known_normal" && e.TargetOrgResolution != "known_default") || (e.TargetOrgResolution == "known_default") != (e.TargetOrganizationID.String() == organization.DefaultOrganizationID) {
		return ErrInvalid
	}
	success := e.RecordKind == "success_witness"
	if success {
		if e.BeforeContext == nil || e.BeforeContext.Validate() != nil || e.BeforeContext.RootID != e.RootID || e.BeforeContext.ParentScheduleID != e.ParentScheduleID || e.BeforeContext.TargetOrganizationID != e.TargetOrganizationID {
			return ErrInvalid
		}
		if e.RootID == uuid.Nil || e.Outcome != "committed" || e.Reason != "deleted" || e.Provenance != "EXPLICIT" || e.DeletionMechanism != "explicit_sql" || e.Cause != "explicit_target" {
			return ErrInvalid
		}
	} else {
		if e.BeforeContext != nil || e.RecordKind != "attempt_observation" || e.Provenance != "" || e.DeletionMechanism != "" || e.Cause != "" {
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
		} else if (e.OrganizationRole != "ORG_ADMIN" && e.OrganizationRole != "ORG_MEMBER") || (e.AuthorityRole != "platform_admin" && (e.AuthorityRole != "org_admin" || e.OrganizationRole != "ORG_ADMIN") && (e.AuthorityRole != "org_member" || e.OrganizationRole != "ORG_MEMBER")) {
			return ErrInvalid
		}
		if success && (e.TargetOrgResolution != "known_normal" || e.HomeOrganizationID != e.TargetOrganizationID || e.HomeOrganizationID.String() == organization.DefaultOrganizationID || (e.AuthorityRole != "platform_admin" && e.AuthorityRole != "org_admin" && e.AuthorityRole != "org_member")) {
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
	b, err := json.Marshal(e.Canonical())
	if err != nil {
		return ErrInvalid
	}
	if len(b) > MaxRootJSONBytes {
		return ErrCapacity
	}
	return nil
}

func validTime(t time.Time) bool { return !t.IsZero() && t.Year() >= 1 && t.Year() <= 9999 }
func (b Before) Validate() error {
	if b.Version != 1 || b.RootID == uuid.Nil || b.ParentScheduleID == uuid.Nil || b.TargetOrganizationID == uuid.Nil || b.RowVersion == 0 || !validTime(b.Start) || !validTime(b.End) || !b.End.After(b.Start) || b.AddUserID == nil && b.RemoveUserID == nil || b.AddUserID != nil && *b.AddUserID == uuid.Nil || b.RemoveUserID != nil && *b.RemoveUserID == uuid.Nil {
		return ErrInvalid
	}
	return nil
}

// ValidateBatch counts full canonical safe event JSON, including before-context,
// headers and empty Effects, rather than a partial payload. PG JSONB text is
// checked independently by Append and by the Controller before Commit.
func ValidateBatch(events []Event) error {
	if len(events) > MaxRoots {
		return ErrCapacity
	}
	n := 0
	seen := map[uuid.UUID]bool{}
	for _, e := range events {
		if err := e.Validate(); err != nil {
			return err
		}
		if e.RecordKind == "success_witness" && seen[e.RootID] {
			return ErrInvalid
		}
		seen[e.RootID] = true
		b, err := json.Marshal(e.Canonical())
		if err != nil {
			return ErrInvalid
		}
		n += len(b)
	}
	if n > MaxJSONBytes {
		return ErrCapacity
	}
	return nil
}

// Append is idempotent only for the same EventID and identical canonical content.
// The caller retains ownership of Commit, Rollback and release.
func Append(ctx context.Context, tx *sql.Tx, event Event) error {
	e := event.Canonical()
	if err := e.Validate(); err != nil {
		return err
	}
	if tx == nil {
		return ErrUnavailable
	}
	before, err := json.Marshal(e.BeforeContext)
	if err != nil {
		return ErrInvalid
	}
	args := []any{e.SchemaVersion, e.EventID, e.RequestID, e.ExecutionID, e.AttemptID, e.RecordKind, nullableID(e.RootID), nullableID(e.ParentScheduleID), nullableID(e.TargetOrganizationID), e.TargetOrgResolution, nullableText(e.Provenance), nullableText(e.DeletionMechanism), nullableText(e.Cause), e.ActorKind, nullableID(e.ActorID), nullableID(e.HomeOrganizationID), e.AuthoritySource, e.AuthorityRole, e.OrganizationRole, e.Outcome, e.Reason, e.OccurredAt, string(before)}
	const cols = `schema_version,event_id,request_id,execution_id,attempt_id,record_kind,root_id,parent_schedule_id,target_organization_id,target_org_resolution,provenance,deletion_mechanism,cause,actor_kind,actor_id,home_organization_id,authority_source,authority_role,organization_role,outcome,reason_code,occurred_at,before_context`
	const vals = `$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23::jsonb`
	r, err := tx.ExecContext(ctx, `INSERT INTO user_override_delete_audit_events (`+cols+`) VALUES (`+vals+`) ON CONFLICT(event_id) DO NOTHING`, args...)
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
	err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT FROM user_override_delete_audit_events WHERE event_id=$2 AND ROW(`+cols+`) IS NOT DISTINCT FROM ROW(`+vals+`))`, args...).Scan(&same)
	if err != nil {
		return ErrUnavailable
	}
	if !same {
		return ErrConflict
	}
	return nil
}
func nullableID(id uuid.UUID) any {
	if id == uuid.Nil {
		return nil
	}
	return id
}
func nullableText(v string) any {
	if v == "" {
		return nil
	}
	return v
}
