// Package scheduledataref validates persisted ScheduleData without normalizing,
// filtering or rewriting it. It grants no deletion or authorization capability.
package scheduledataref

import (
	"bytes"
	"encoding/json"
	"errors"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/target/goalert/util/timeutil"
)

const MaxBytes = 1 << 20
const MaxFragments = 10000

var ErrInvalid = errors.New("invalid or unsupported schedule data")

// NilSlice recognizes the JSON representation of a nil Go slice, only for
// callers that have already identified a supported slice field.
func NilSlice(raw []byte) bool { return bytes.Equal(bytes.TrimSpace(raw), []byte("null")) }

// Slice accepts null only at a known Go slice field. A missing required field,
// scalar, object, corrupt array or over-budget array is never an empty slice.
func Slice(raw json.RawMessage, limit int) ([]json.RawMessage, error) {
	if limit < 0 || len(raw) == 0 {
		return nil, ErrInvalid
	}
	if NilSlice(raw) {
		return nil, nil
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	tok, err := d.Token()
	if err != nil || tok != json.Delim('[') {
		return nil, ErrInvalid
	}
	var out []json.RawMessage
	for d.More() {
		if len(out) >= limit {
			return nil, ErrInvalid
		}
		var value json.RawMessage
		if d.Decode(&value) != nil {
			return nil, ErrInvalid
		}
		out = append(out, value)
	}
	if tok, err = d.Token(); err != nil || tok != json.Delim(']') || !json.Valid(raw) {
		return nil, ErrInvalid
	}
	return out, nil
}

func object(raw []byte, keys ...string) (map[string]json.RawMessage, error) {
	var m map[string]json.RawMessage
	if json.Unmarshal(raw, &m) != nil || m == nil {
		return nil, ErrInvalid
	}
	for k := range m {
		if !slices.Contains(keys, k) {
			return nil, ErrInvalid
		}
	}
	return m, nil
}

func period(raw []byte) (start, end time.Time, err error) {
	var p struct{ Start, End time.Time }
	if json.Unmarshal(raw, &p) != nil || p.Start.IsZero() || p.End.IsZero() || !p.Start.Before(p.End) {
		return start, end, ErrInvalid
	}
	return p.Start, p.End, nil
}

// Users returns the complete, sorted, deduplicated reference set, including
// ended shifts. It never consults a UserExists cache or drops a bad fragment.
func Users(raw []byte, scheduleID uuid.UUID) ([]uuid.UUID, error) {
	if len(raw) > MaxBytes || scheduleID == uuid.Nil {
		return nil, ErrInvalid
	}
	envelope, err := object(raw, "V1")
	if err != nil {
		return nil, err
	}
	v1, err := object(envelope["V1"], "TemporarySchedules", "OnCallNotificationRules")
	if err != nil {
		return nil, err
	}
	temps, err := Slice(v1["TemporarySchedules"], MaxFragments)
	if err != nil {
		return nil, err
	}
	units := len(temps)
	var users []uuid.UUID
	for _, rawTemp := range temps {
		temp, err := object(rawTemp, "Start", "End", "Shifts")
		if err != nil {
			return nil, err
		}
		start, end, err := period(rawTemp)
		if err != nil {
			return nil, err
		}
		shifts, err := Slice(temp["Shifts"], MaxFragments-units)
		if err != nil {
			return nil, err
		}
		units += len(shifts)
		for _, rawShift := range shifts {
			m, err := object(rawShift, "Start", "End", "UserID")
			if err != nil {
				return nil, err
			}
			ss, se, err := period(rawShift)
			if err != nil || !ss.Before(end) || !start.Before(se) {
				return nil, ErrInvalid
			}
			var text string
			if json.Unmarshal(m["UserID"], &text) != nil {
				return nil, ErrInvalid
			}
			id, err := uuid.Parse(text)
			if err != nil || id == uuid.Nil || !strings.EqualFold(id.String(), text) {
				return nil, ErrInvalid
			}
			users = append(users, id)
		}
	}
	if rawRules, ok := v1["OnCallNotificationRules"]; ok {
		rules, err := Slice(rawRules, MaxFragments-units)
		if err != nil {
			return nil, err
		}
		seen := make(map[string]bool)
		for _, rawRule := range rules {
			if _, err := object(rawRule, "ID", "ChannelID", "Time", "WeekdayFilter", "NextNotification"); err != nil {
				return nil, err
			}
			var r struct {
				ID               string
				ChannelID        uuid.UUID
				Time             *timeutil.Clock
				WeekdayFilter    *timeutil.WeekdayFilter
				NextNotification *time.Time
			}
			if json.Unmarshal(rawRule, &r) != nil || r.ChannelID == uuid.Nil || seen[r.ID] {
				return nil, ErrInvalid
			}
			prefix := scheduleID.String() + ":"
			local, err := strconv.ParseInt(strings.TrimPrefix(r.ID, prefix), 10, 32)
			if err != nil || local < 0 || r.ID != prefix+strconv.FormatInt(local, 10) {
				return nil, ErrInvalid
			}
			seen[r.ID] = true
		}
	}
	slices.SortFunc(users, func(a, b uuid.UUID) int { return bytes.Compare(a[:], b[:]) })
	return slices.Compact(users), nil
}
