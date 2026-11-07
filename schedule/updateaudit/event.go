// Package updateaudit persists only schedule.update and rotation.update events.
// It does not authorize mutations or expose a product audit reader.
package updateaudit

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/target/goalert/util/sqlutil"
)

var (
	ErrInvalid     = errors.New("invalid schedule/rotation update audit event")
	ErrUnavailable = errors.New("schedule/rotation update audit persistence unavailable")
	ErrConflict    = errors.New("schedule/rotation update audit event identity conflict")
)

type Operation string

const (
	ScheduleUpdate Operation = "schedule.update"
	RotationUpdate Operation = "rotation.update"
)

// Fields records presence, never the request values or a claim of changed values.
type Fields uint16

const (
	ScheduleName Fields = 1 << iota
	ScheduleDescription
	ScheduleTimeZone
)
const (
	RotationName Fields = 1 << iota
	RotationDescription
	RotationStart
	RotationType
	RotationShiftLength
	RotationTimeZone
	RotationUserIDs
	RotationActiveUserIndex
)

// Event is a closed allowlist. Target identity must come from the locked stored
// resource. Home is attribution, not a fallback target. Committed means a staged
// witness until the caller observes Commit nil. No raw text or error is accepted.
type Event struct {
	EventID, AttemptID, RequestID                    uuid.UUID
	Operation                                        Operation
	ActorKind                                        string
	ActorID, HomeOrganizationID                      uuid.UUID
	AuthoritySource, AuthorityRole, OrganizationRole string
	TargetID, TargetOrganizationID                   uuid.UUID
	RequestedFields                                  Fields
	Outcome, Reason                                  string
	OccurredAt                                       time.Time
	ScheduleRowWritten, RotationRowWritten           bool
	Before, After                                    *RotationSnapshot
}

func (e Event) valid() bool {
	if e.EventID == uuid.Nil || e.AttemptID == uuid.Nil || e.RequestID == uuid.Nil || !finiteTime(e.OccurredAt) {
		return false
	}
	if e.Operation != ScheduleUpdate && e.Operation != RotationUpdate || e.RequestedFields > 255 || e.Operation == ScheduleUpdate && e.RequestedFields > 7 {
		return false
	}
	if (e.TargetID == uuid.Nil) != (e.TargetOrganizationID == uuid.Nil) {
		return false
	}
	reasons := map[string][]string{
		"committed":            {"updated"},
		"denied":               {"authority_denied", "target_unavailable"},
		"validation_failed":    {"invalid_fields", "target_unavailable"},
		"tx_failed":            {"begin_failed", "write_failed", "audit_write_failed", "commit_rejected"},
		"commit_unknown":       {"commit_unconfirmed"},
		"rollback_unconfirmed": {"rollback_unconfirmed"},
	}
	matched := false
	for _, reason := range reasons[e.Outcome] {
		matched = matched || reason == e.Reason
	}
	if !matched {
		return false
	}
	switch e.ActorKind {
	case "human":
		if e.ActorID == uuid.Nil || e.HomeOrganizationID == uuid.Nil || e.AuthoritySource != "current_local_user_organization_at_admission" || (e.OrganizationRole != "ORG_ADMIN" && e.OrganizationRole != "ORG_MEMBER") {
			return false
		}
		roleMatches := e.AuthorityRole == "platform_admin" || e.AuthorityRole == "org_admin" && e.OrganizationRole == "ORG_ADMIN" || e.AuthorityRole == "org_member" && e.OrganizationRole == "ORG_MEMBER"
		if !roleMatches {
			return false
		}
	case "internal_system":
		if e.ActorID != uuid.Nil || e.HomeOrganizationID != uuid.Nil || e.AuthoritySource != "trusted_internal_system" || e.AuthorityRole != "internal_system" || e.OrganizationRole != "unknown" {
			return false
		}
	case "unknown":
		if e.ActorID != uuid.Nil || e.HomeOrganizationID != uuid.Nil || e.AuthoritySource != "unknown" || e.AuthorityRole != "unknown" || e.OrganizationRole != "unknown" || e.TargetID != uuid.Nil {
			return false
		}
	default:
		return false
	}
	if e.Outcome != "committed" {
		return !e.ScheduleRowWritten && !e.RotationRowWritten && e.Before == nil && e.After == nil
	}
	if e.TargetID == uuid.Nil || e.ActorKind == "unknown" || e.ActorKind == "human" && (e.AuthorityRole == "org_member" || e.AuthorityRole != "platform_admin" && e.HomeOrganizationID != e.TargetOrganizationID) {
		return false
	}
	if e.Operation == ScheduleUpdate {
		return e.ScheduleRowWritten && !e.RotationRowWritten && e.Before == nil && e.After == nil
	}
	return !e.ScheduleRowWritten && e.RotationRowWritten == (e.RequestedFields&63 != 0) && e.Before.valid() && e.After.valid()
}

func finiteTime(t time.Time) bool { return !t.IsZero() && t.Year() >= 1 && t.Year() <= 9999 }
func nullable(id uuid.UUID) any {
	if id == uuid.Nil {
		return nil
	}
	return id.String()
}

// Explicit column/type pairs are the entire persisted payload, including every
// target/effect. They are code constants, never request-supplied SQL identifiers.
var columns = []string{
	"schema_version:smallint", "event_id:uuid", "attempt_id:uuid", "request_id:uuid", "operation:text", "target_type:text",
	"actor_kind:text", "actor_id:uuid", "home_organization_id:uuid", "authority_source:text", "authority_role:text", "organization_role:text",
	"target_id:uuid", "target_organization_id:uuid", "requested_fields:smallint", "outcome:text", "reason_code:text", "occurred_at:timestamptz",
	"schedule_row_written:boolean", "rotation_row_written:boolean",
	"before_participant_ids:uuid[]", "before_user_ids:uuid[]", "before_positions:integer[]", "before_participant_count:integer",
	"before_state_id:bigint", "before_state_position:integer", "before_state_participant_id:uuid", "before_shift_start:timestamptz", "before_state_version:integer",
	"after_participant_ids:uuid[]", "after_user_ids:uuid[]", "after_positions:integer[]", "after_participant_count:integer",
	"after_state_id:bigint", "after_state_position:integer", "after_state_participant_id:uuid", "after_shift_start:timestamptz", "after_state_version:integer",
}

func snapshotArgs(s *RotationSnapshot) []any {
	if s == nil {
		return make([]any, 9)
	}
	ids, users := make(sqlutil.UUIDArray, 0, len(s.Participants)), make(sqlutil.UUIDArray, 0, len(s.Participants))
	positions := make([]int32, 0, len(s.Participants))
	for _, p := range s.Participants {
		ids = append(ids, p.ID.String())
		users = append(users, p.UserID.String())
		positions = append(positions, p.Position)
	}
	a := []any{ids, users, pq.Array(positions), s.ParticipantCount}
	if s.State == nil {
		return append(a, make([]any, 5)...)
	}
	return append(a, s.State.ID, s.State.Position, s.State.ParticipantID.String(), s.State.ShiftStart.UTC().Truncate(time.Microsecond), s.State.Version)
}

// Append only stages a single immutable row in the caller's business transaction.
// Exact full-event retries are idempotent. A conflict never rewrites any history.
// PostgreSQL diagnostics and driver errors do not escape this privacy boundary.
func Append(ctx context.Context, tx *sql.Tx, e Event) error {
	if !e.valid() {
		return ErrInvalid
	}
	if tx == nil {
		return ErrUnavailable
	}
	targetType := "schedule"
	if e.Operation == RotationUpdate {
		targetType = "rotation"
	}
	args := []any{1, e.EventID.String(), e.AttemptID.String(), e.RequestID.String(), string(e.Operation), targetType, e.ActorKind, nullable(e.ActorID), nullable(e.HomeOrganizationID), e.AuthoritySource, e.AuthorityRole, e.OrganizationRole, nullable(e.TargetID), nullable(e.TargetOrganizationID), int(e.RequestedFields), e.Outcome, e.Reason, e.OccurredAt.UTC().Truncate(time.Microsecond), e.ScheduleRowWritten, e.RotationRowWritten}
	args = append(args, snapshotArgs(e.Before)...)
	args = append(args, snapshotArgs(e.After)...)
	names, values := make([]string, len(columns)), make([]string, len(columns))
	for i, column := range columns {
		parts := strings.SplitN(column, ":", 2)
		names[i] = parts[0]
		values[i] = fmt.Sprintf("$%d::%s", i+1, parts[1])
	}
	cols, vals := strings.Join(names, ","), strings.Join(values, ",")
	r, err := tx.ExecContext(ctx, "INSERT INTO schedule_rotation_update_audit_events ("+cols+") VALUES ("+vals+") ON CONFLICT(event_id) DO NOTHING", args...)
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
	err = tx.QueryRowContext(ctx, "SELECT EXISTS(SELECT FROM schedule_rotation_update_audit_events WHERE event_id=$2::uuid AND ROW("+cols+") IS NOT DISTINCT FROM ROW("+vals+"))", args...).Scan(&same)
	if err != nil {
		return ErrUnavailable
	}
	if !same {
		return ErrConflict
	}
	return nil
}

// RecordFailure must only be called AFTER the caller has positively confirmed
// its business transaction/connection release barrier. This storage API cannot
// establish that external fact. No request context, cancellation or fields cross
// into the independent bounded transaction. A failed/unknown commit is not retried.
func RecordFailure(db *sql.DB, e Event) (resultErr error) {
	if db == nil || e.Outcome == "committed" {
		return ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return ErrUnavailable
	}
	defer func() {
		done := make(chan error, 1)
		go func() { done <- tx.Rollback() }()
		timer := time.NewTimer(2 * time.Second)
		defer timer.Stop()
		select {
		case err := <-done:
			if err != nil && !errors.Is(err, sql.ErrTxDone) {
				resultErr = ErrUnavailable
			}
		case <-timer.C:
			resultErr = ErrUnavailable
		}
	}()
	if err := Append(ctx, tx, e); err != nil {
		return err
	}
	done := make(chan error, 1)
	go func() { done <- tx.Commit() }()
	select {
	case err := <-done:
		if err != nil {
			return ErrUnavailable
		}
	case <-ctx.Done():
		return ErrUnavailable
	}
	return nil
}
