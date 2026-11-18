package schedule

import (
	"context"
	"database/sql"
	"encoding/json"
	"slices"
	"sort"
	"time"

	"github.com/google/uuid"
	"github.com/target/goalert/internal/scheduledataref"
	"github.com/target/goalert/internal/schedulejsonguard"
	"github.com/target/goalert/permission"
	audit "github.com/target/goalert/schedule/jsonupdateaudit"
	"github.com/target/goalert/validation/validate"
)

// TemporaryUpdate is the real Store intent after its existing validation and
// clock normalization, never a client-provided final JSON document.
type TemporaryUpdate struct {
	Operation            string
	Mode                 string
	Temporary            TemporarySchedule
	ClearStart, ClearEnd time.Time
}

// NormalizeTemporaryUpdate uses the same normalization as the three original
// entry points. Callers must authorize the parent before invoking this method.
func (store *Store) NormalizeTemporaryUpdate(ctx context.Context, tx *sql.Tx, id uuid.UUID, org *uuid.UUID, u TemporaryUpdate) (TemporaryUpdate, error) {
	return store.NormalizeTemporaryUpdateAt(ctx, tx, id, org, u, time.Now())
}

func (store *Store) NormalizeTemporaryUpdateAt(ctx context.Context, tx *sql.Tx, id uuid.UUID, org *uuid.UUID, u TemporaryUpdate, now time.Time) (TemporaryUpdate, error) {
	if err := permission.LimitCheckAny(ctx, permission.User); err != nil {
		return u, err
	}
	if u.Mode != "clear" {
		t := u.Temporary
		t.Shifts = slices.Clone(t.Shifts)
		n, err := t.normalizeAt(nil, now)
		if err != nil {
			return u, err
		}
		u.Temporary = *n
		if err := store.validateTemporaryScheduleUsers(ctx, tx, id, org, n); err != nil {
			return u, err
		}
	}
	if u.Mode == "clear" {
		if err := validate.Many(validateFutureAt("End", u.ClearEnd, now), validateTimeRange("", u.ClearStart, u.ClearEnd)); err != nil {
			return u, err
		}
	} else if u.Mode == "set_clear" {
		if err := validateTimeRange("Clear", u.ClearStart, u.ClearEnd); err != nil {
			return u, err
		}
	} else if u.Mode != "set" {
		return u, audit.ErrInvalid
	}
	if u.Mode != "set" && u.ClearStart.Before(now) {
		u.ClearStart = now
	}
	return u, nil
}

// ExecuteTemporaryUpdate consumes an exact internal capability, including for
// additions, so this prepared-intent entry cannot bypass normal validation.
func (store *Store) ExecuteTemporaryUpdate(ctx context.Context, tx *sql.Tx, id uuid.UUID, org *uuid.UUID, u TemporaryUpdate) error {
	if !schedulejsonguard.Bound(ctx, tx) {
		return audit.ErrInvalid
	}
	return store.updateTemporaryData(ctx, tx, id, org, u)
}

func cloneTemporary(in []TemporarySchedule) []TemporarySchedule {
	out := slices.Clone(in)
	for i := range out {
		out[i].Shifts = slices.Clone(out[i].Shifts)
	}
	return out
}

// TemporaryCoverage rejects malformed or overlapping envelopes whose first-
// match TempOnCall semantics cannot be proven equal to interval union. Adjacent
// segments and shift reordering/duplicates are business-equivalent.
func TemporaryCoverage(in []TemporarySchedule) ([]audit.Coverage, error) {
	in = cloneTemporary(in)
	sort.Slice(in, func(i, j int) bool { return in[i].Start.Before(in[j].Start) })
	coverage := make([]audit.Coverage, 0)
	for i, t := range in {
		if t.Start.IsZero() || t.End.IsZero() || i > 0 && t.Start.Before(in[i-1].End) || !t.Start.Before(t.End) {
			return nil, audit.ErrInvalid
		}
		coverage = append(coverage, audit.Coverage{Kind: "temporary", Start: audit.Instant(t.Start), End: audit.Instant(t.End)})
		for _, s := range t.Shifts {
			id, err := uuid.Parse(s.UserID)
			if err != nil || s.Start.Before(t.Start) || s.End.After(t.End) {
				return nil, audit.ErrInvalid
			}
			coverage = append(coverage, audit.Coverage{Kind: "fixed_shift", UserID: id.String(), Start: audit.Instant(s.Start), End: audit.Instant(s.End)})
		}
	}
	return audit.Canonical(coverage)
}

func (u TemporaryUpdate) Apply(before []TemporarySchedule) []TemporarySchedule {
	result := cloneTemporary(before)
	if u.Mode == "clear" || u.Mode == "set_clear" {
		result = deleteFixedShifts(result, u.ClearStart, u.ClearEnd)
	}
	if u.Mode != "clear" {
		t := u.Temporary
		t.Shifts = slices.Clone(t.Shifts)
		result = setFixedShifts(result, t)
	}
	return result
}

// ReadTemporaryUpdate reads the complete raw envelope, without the public
// getter's user filtering. Mutation locks the envelope before reading; preview
// must supply a read-only repeatable-read transaction and never INSERTs.
func (store *Store) ReadTemporaryUpdate(ctx context.Context, tx *sql.Tx, id uuid.UUID, locked bool) (int64, []TemporarySchedule, error) {
	if tx == nil {
		return 0, nil, audit.ErrInvalid
	}
	query := `SELECT id,data FROM schedule_data WHERE schedule_id=$1`
	if locked {
		query += ` FOR UPDATE NOWAIT`
	}
	var envelope int64
	var raw []byte
	err := tx.QueryRowContext(ctx, query, id).Scan(&envelope, &raw)
	if err == sql.ErrNoRows {
		return 0, []TemporarySchedule{}, nil
	}
	if err != nil {
		return 0, nil, err
	}
	if string(raw) != "{}" {
		if _, err := scheduledataref.Users(raw, id); err != nil {
			return 0, nil, err
		}
	}
	var data Data
	if err := json.Unmarshal(raw, &data); err != nil {
		return 0, nil, err
	}
	if _, err := TemporaryCoverage(data.V1.TemporarySchedules); err != nil {
		return 0, nil, err
	}
	return envelope, cloneTemporary(data.V1.TemporarySchedules), nil
}

func (store *Store) updateTemporaryData(ctx context.Context, tx *sql.Tx, id uuid.UUID, org *uuid.UUID, u TemporaryUpdate) error {
	var before []audit.Coverage
	var envelope int64
	return store.updateScheduleData(ctx, tx, id, org, func(tx *sql.Tx, data *Data) error {
		var err error
		err = tx.QueryRowContext(ctx, `SELECT id FROM schedule_data WHERE schedule_id=$1`, id).Scan(&envelope)
		if err != nil {
			return err
		}
		before, err = TemporaryCoverage(data.V1.TemporarySchedules)
		if err != nil {
			return err
		}
		if u.Mode != "clear" {
			if err := store.validateTemporaryScheduleUsers(ctx, tx, id, org, &u.Temporary); err != nil {
				return err
			}
		}
		data.V1.TemporarySchedules = u.Apply(data.V1.TemporarySchedules)
		after, err := TemporaryCoverage(data.V1.TemporarySchedules)
		if err != nil {
			return err
		}
		return schedulejsonguard.Authorize(ctx, tx, id, envelope, u.Operation, u.Mode, before, after)
	}, func(tx *sql.Tx, _ *Data) error {
		// Re-read the actual bytes, including any trigger mutation. The audit
		// cannot claim the predicted payload if persistence wrote another value.
		_, actual, err := store.ReadTemporaryUpdate(ctx, tx, id, false)
		if err != nil {
			return err
		}
		after, err := TemporaryCoverage(actual)
		if err != nil {
			return err
		}
		return schedulejsonguard.Finish(ctx, tx, id, envelope, u.Operation, u.Mode, before, after)
	})
}
