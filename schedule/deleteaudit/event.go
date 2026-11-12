// Package deleteaudit persists safe explicit Schedule/Rotation deletion witnesses.
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
	ErrInvalid     = errors.New("invalid schedule/rotation.delete audit event")
	ErrUnavailable = errors.New("schedule/rotation.delete audit persistence unavailable")
	ErrConflict    = errors.New("schedule/rotation.delete audit event identity conflict")
	ErrCapacity    = errors.New("schedule/rotation.delete audit capacity exceeded")
)

// Event contains historical business identities and a closed safe effects projection.
type Event struct {
	SchemaVersion                                    int
	EventID, RequestID, ExecutionID, AttemptID       uuid.UUID
	RecordKind                                       string
	RootType, Operation                              string
	BeforeState                                      *RotationState
	RootID, TargetOrganizationID                     uuid.UUID
	EffectsVersion                                   int
	Effects                                          []Effect
	TargetOrgResolution                              string
	Provenance, DeletionMechanism, Cause             string
	ActorKind                                        string
	ActorID, HomeOrganizationID                      uuid.UUID
	AuthoritySource, AuthorityRole, OrganizationRole string
	Outcome, Reason                                  string
	OccurredAt                                       time.Time
}

func (e Event) Canonical() Event {
	e.OccurredAt = e.OccurredAt.UTC().Truncate(time.Microsecond)
	e.Effects = canonicalEffects(e.Effects)
	return e
}

func (e Event) Validate() error {
	if (e.RootType != Schedule && e.RootType != Rotation) || e.Operation != e.RootType+".delete" {
		return ErrInvalid
	}
	if e.SchemaVersion != 1 || e.EventID == uuid.Nil || e.RequestID == uuid.Nil || e.ExecutionID == uuid.Nil || e.AttemptID == uuid.Nil || e.OccurredAt.IsZero() || e.OccurredAt.Year() < 1 || e.OccurredAt.Year() > 9999 {
		return ErrInvalid
	}
	if e.RootID == uuid.Nil {
		if e.TargetOrganizationID != uuid.Nil || e.TargetOrgResolution != "unknown" {
			return ErrInvalid
		}
	} else if e.TargetOrganizationID == uuid.Nil || e.TargetOrganizationID.String() == organization.DefaultOrganizationID || e.TargetOrgResolution != "known_normal" {
		return ErrInvalid
	}
	if e.EffectsVersion != 1 {
		return ErrInvalid
	}
	success := e.RecordKind == "success_witness"
	if success {
		if e.RootID == uuid.Nil || e.Outcome != "committed" || e.Reason != "deleted" || e.Provenance != "EXPLICIT" || e.DeletionMechanism != "explicit_sql" || e.Cause != "explicit_target" {
			return ErrInvalid
		}
	} else {
		if e.RecordKind != "attempt_observation" || e.Provenance != "" || e.DeletionMechanism != "" || e.Cause != "" || (len(e.Effects) != 0 || e.BeforeState != nil) {
			return ErrInvalid
		}
		valid := false
		switch e.Outcome {
		case "denied":
			valid = e.Reason == "authority_denied"
		case "validation_failed":
			valid = e.Reason == "invalid_fields" || e.Reason == "target_unavailable" || e.Reason == "target_in_use"
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
		if success && (e.TargetOrgResolution != "known_normal" || e.AuthorityRole != "platform_admin" && (e.AuthorityRole != "org_admin" || e.HomeOrganizationID != e.TargetOrganizationID)) {
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
	return e.validateEffects()
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
	raw, err := json.Marshal(e.Effects)
	if err != nil {
		return ErrInvalid
	}
	args := []any{e.SchemaVersion, e.EventID, e.RequestID, e.ExecutionID, e.AttemptID, e.RecordKind, nullableID(e.RootID), nullableID(e.TargetOrganizationID), e.TargetOrgResolution, nullableText(e.Provenance), nullableText(e.DeletionMechanism), nullableText(e.Cause), e.ActorKind, nullableID(e.ActorID), nullableID(e.HomeOrganizationID), e.AuthoritySource, e.AuthorityRole, e.OrganizationRole, e.Outcome, e.Reason, e.OccurredAt, e.EffectsVersion, string(raw), e.RootType, e.Operation, stateJSON(e.BeforeState)}
	const cols = `schema_version,event_id,request_id,execution_id,attempt_id,record_kind,root_id,target_organization_id,target_org_resolution,provenance,deletion_mechanism,cause,actor_kind,actor_id,home_organization_id,authority_source,authority_role,organization_role,outcome,reason_code,occurred_at,effects_version,effects,root_type,operation,before_state`
	const vals = `$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23::jsonb,$24,$25,$26::jsonb`
	r, err := tx.ExecContext(ctx, `INSERT INTO schedule_rotation_delete_audit_events (`+cols+`) VALUES (`+vals+`) ON CONFLICT(event_id) DO NOTHING`, args...)
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
	err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT FROM schedule_rotation_delete_audit_events WHERE event_id=$2 AND ROW(`+cols+`) IS NOT DISTINCT FROM ROW(`+vals+`))`, args...).Scan(&same)
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
