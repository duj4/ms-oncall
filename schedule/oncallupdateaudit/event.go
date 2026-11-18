package oncallupdateaudit

import (
	"context"
	"database/sql"
	"encoding/json"
	"reflect"
	"time"

	"github.com/google/uuid"
	temporary "github.com/target/goalert/schedule/jsonupdateaudit"
)

type Event struct {
	Version                                                     int
	EventID, RequestID, AttemptID                               uuid.UUID
	ActorID, HomeOrganizationID                                 uuid.UUID
	ActorKind, AuthoritySource, AuthorityRole, OrganizationRole string
	ScheduleID, OrganizationID                                  uuid.UUID
	EnvelopeID                                                  int64
	Operation                                                   string
	OccurredAt                                                  time.Time
	Before, After                                               []Rule
	Effects                                                     []Effect
}

func (e Event) Validate() error {
	// Reuse trusted identity validation, without changing the Temporary audit
	// contract or persisting any OnCall facts into that contract.
	identity := temporary.Event{Version: e.Version, EventID: e.EventID, RequestID: e.RequestID, AttemptID: e.AttemptID, ActorID: e.ActorID, HomeOrganizationID: e.HomeOrganizationID, ActorKind: e.ActorKind, AuthoritySource: e.AuthoritySource, AuthorityRole: e.AuthorityRole, OrganizationRole: e.OrganizationRole, ScheduleID: e.ScheduleID, OrganizationID: e.OrganizationID, EnvelopeID: e.EnvelopeID, Operation: temporary.Set, Mode: "set", OccurredAt: e.OccurredAt, Before: []temporary.Coverage{}, After: []temporary.Coverage{}, Effects: []temporary.Effect{}}
	if e.Operation != Operation || identity.Validate() != nil || e.Effects == nil {
		return ErrInvalid
	}
	effects, err := Diff(e.ScheduleID, e.Before, e.After)
	if err != nil || !reflect.DeepEqual(effects, e.Effects) {
		return ErrInvalid
	}
	return nil
}

// Append is idempotent only for an identical event. Request/attempt conflicts
// and all persistence failures fail closed in the business transaction.
func Append(ctx context.Context, tx *sql.Tx, e Event) error {
	if tx == nil || e.Validate() != nil {
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
	f, err := json.Marshal(e.Effects)
	if err != nil {
		return err
	}
	var actor, home any
	if e.ActorID != uuid.Nil {
		actor = e.ActorID.String()
		home = e.HomeOrganizationID.String()
	}
	args := []any{e.EventID, e.RequestID, e.AttemptID, e.Version, e.Operation, e.ActorKind, actor, home, e.AuthoritySource, e.AuthorityRole, e.OrganizationRole, e.ScheduleID, e.OrganizationID, e.EnvelopeID, e.OccurredAt.UTC().Truncate(time.Microsecond), b, a, f, len(e.Effects)}
	const columns = `event_id,request_id,attempt_id,schema_version,operation,actor_kind,actor_id,home_organization_id,authority_source,authority_role,organization_role,schedule_id,organization_id,envelope_id,occurred_at,before_rules,after_rules,effects,effect_count`
	const values = `$1::uuid,$2::uuid,$3::uuid,$4::smallint,$5::text,$6::text,$7::uuid,$8::uuid,$9::text,$10::text,$11::text,$12::uuid,$13::uuid,$14::bigint,$15::timestamptz,$16::jsonb,$17::jsonb,$18::jsonb,$19::integer`
	r, err := tx.ExecContext(ctx, `INSERT INTO schedule_oncall_update_audit_events (`+columns+`) VALUES (`+values+`) ON CONFLICT(event_id) DO NOTHING`, args...)
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
	err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT FROM schedule_oncall_update_audit_events WHERE event_id=$1 AND ROW(`+columns+`) IS NOT DISTINCT FROM ROW(`+values+`))`, args...).Scan(&same)
	if err != nil || !same {
		return ErrInvalid
	}
	return nil
}
