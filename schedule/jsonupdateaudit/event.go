package jsonupdateaudit

import (
	"context"
	"database/sql"
	"encoding/json"
	"reflect"
	"time"

	"github.com/google/uuid"
	"github.com/target/goalert/organization"
)

const (
	Set   = "setTemporarySchedule"
	Clear = "clearTemporarySchedules"
)

func validOperation(op string) bool { return op == Set || op == Clear }

func (c Coverage) valid() bool {
	if !validInstant(c.Start) || !validInstant(c.End) || instantCompare(c.Start, c.End) >= 0 {
		return false
	}
	if c.Kind == "temporary" {
		return c.UserID == ""
	}
	id, err := uuid.Parse(c.UserID)
	return c.Kind == "fixed_shift" && err == nil && id != uuid.Nil && id.String() == c.UserID
}

// Event contains only a validated minimal business projection. Neither the raw
// envelope nor request headers, destinations, display names or credentials enter
// this contract. It is a staged success witness until the owning Tx commits.
type Event struct {
	Version                                                     int
	EventID, RequestID, AttemptID                               uuid.UUID
	ActorID, HomeOrganizationID                                 uuid.UUID
	ActorKind, AuthoritySource, AuthorityRole, OrganizationRole string
	ScheduleID, OrganizationID                                  uuid.UUID
	EnvelopeID                                                  int64
	Mode                                                        string
	Operation                                                   string
	OccurredAt                                                  time.Time
	Before, After                                               []Coverage
	Effects                                                     []Effect
}

func (e Event) Validate() error {
	if e.Version != 1 || !validOperation(e.Operation) || (e.Operation == Set && e.Mode != "set" && e.Mode != "set_clear" || e.Operation == Clear && e.Mode != "clear") || e.EventID == uuid.Nil || e.RequestID == uuid.Nil || e.AttemptID == uuid.Nil || e.ScheduleID == uuid.Nil || e.OrganizationID == uuid.Nil || e.EnvelopeID <= 0 || e.OccurredAt.IsZero() || e.OccurredAt.Year() < 1 || e.OccurredAt.Year() > 9999 {
		return ErrInvalid
	}
	switch e.ActorKind {
	case "human":
		defaultPA := e.HomeOrganizationID.String() == organization.DefaultOrganizationID && e.OrganizationRole == "NONE" && e.AuthorityRole == "platform_admin" && e.OrganizationID != e.HomeOrganizationID
		organizationRoleValid := defaultPA || e.OrganizationRole == "ORG_ADMIN" || e.AuthorityRole == "platform_admin" && e.OrganizationRole == "ORG_MEMBER"
		scopeValid := e.AuthorityRole == "platform_admin" || e.AuthorityRole == "org_admin" && e.HomeOrganizationID == e.OrganizationID
		if e.ActorID == uuid.Nil || e.HomeOrganizationID == uuid.Nil || e.AuthoritySource != "current_local_user_organization_at_admission" || !organizationRoleValid || !scopeValid {
			return ErrInvalid
		}

	case "internal_system":
		if e.ActorID != uuid.Nil || e.HomeOrganizationID != uuid.Nil || e.AuthoritySource != "trusted_internal_system" || e.AuthorityRole != "internal_system" || e.OrganizationRole != "unknown" {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	if ValidateSnapshot(e.Before) != nil || ValidateSnapshot(e.After) != nil || e.Effects == nil {
		return ErrInvalid
	}
	effects, err := Diff(e.Before, e.After)
	if err != nil || !reflect.DeepEqual(effects, e.Effects) {
		return ErrInvalid
	}
	for _, effect := range e.Effects {
		if e.Operation == Clear && effect.Change != "coverage_removed" {
			return ErrInvalid
		}
	}
	return nil
}

// Append stages exactly one immutable event in the caller's business Tx. An
// exact EventID retry is idempotent; any conflicting reuse fails closed.
func Append(ctx context.Context, tx *sql.Tx, e Event) error {
	if err := e.Validate(); err != nil {
		return err
	}
	if tx == nil {
		return ErrInvalid
	}
	b, err := json.Marshal(e.Before)
	if err != nil {
		return err
	}
	a, err := json.Marshal(e.After)
	if err != nil {
		return err
	}
	effects, err := json.Marshal(e.Effects)
	if err != nil {
		return err
	}
	var actor, home any
	if e.ActorID != uuid.Nil {
		actor = e.ActorID.String()
		home = e.HomeOrganizationID.String()
	}
	args := []any{e.EventID, e.RequestID, e.AttemptID, e.Version, e.Operation, e.ActorKind, actor, home, e.AuthoritySource, e.AuthorityRole, e.OrganizationRole, e.ScheduleID, e.OrganizationID, e.EnvelopeID, e.OccurredAt.UTC().Truncate(time.Microsecond), b, a, effects, len(e.Effects), e.Mode}
	const columns = `event_id,request_id,attempt_id,schema_version,operation,actor_kind,actor_id,home_organization_id,authority_source,authority_role,organization_role,schedule_id,organization_id,envelope_id,occurred_at,before_coverage,after_coverage,effects,effect_count,update_mode`
	const values = `$1::uuid,$2::uuid,$3::uuid,$4::smallint,$5::text,$6::text,$7::uuid,$8::uuid,$9::text,$10::text,$11::text,$12::uuid,$13::uuid,$14::bigint,$15::timestamptz,$16::jsonb,$17::jsonb,$18::jsonb,$19::integer,$20::text`
	r, err := tx.ExecContext(ctx, `INSERT INTO schedule_json_update_audit_events (`+columns+`) VALUES (`+values+`) ON CONFLICT(event_id) DO NOTHING`, args...)
	if err != nil {
		return ErrInvalid
	}
	n, err := r.RowsAffected()
	if err != nil {
		return ErrInvalid
	}
	if n == 1 {
		return nil
	}
	var same bool
	err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT FROM schedule_json_update_audit_events WHERE event_id=$1 AND ROW(`+columns+`) IS NOT DISTINCT FROM ROW(`+values+`))`, args...).Scan(&same)
	if err != nil || !same {
		return ErrInvalid
	}
	return nil
}
