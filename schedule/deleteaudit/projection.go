package deleteaudit

import (
	"encoding/json"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

// ProjectData consumes only the SQL-selected known V1 members, never the raw
// envelope. It preserves stored times, ordinals and historical users without
// normalization, filtering, or a transaction-external getter.
func ProjectData(e Event, envelope int64, raw []byte, remaining int) ([]Effect, error) {
	if len(raw) > MaxJSONBytes {
		return nil, ErrCapacity
	}
	var data struct {
		TemporarySchedules []struct {
			Start, End time.Time
			Shifts     []struct {
				Start, End time.Time
				UserID     uuid.UUID
			}
		}
		OnCallNotificationRules []struct {
			ID                  string
			ChannelID           uuid.UUID
			Time, WeekdayFilter *string
		}
	}
	if json.Unmarshal(raw, &data) != nil {
		return nil, ErrInvalid
	}
	units := len(data.TemporarySchedules) + len(data.OnCallNotificationRules)
	for _, t := range data.TemporarySchedules {
		units += len(t.Shifts)
	}
	if units > remaining {
		return nil, ErrCapacity
	}
	effects := make([]Effect, 0, units)
	base := func(typ string, index int) Effect {
		return Effect{EffectID: uuid.New(), ResourceType: typ, RootID: e.RootID, TargetOrganizationID: e.TargetOrganizationID, Relation: Schedule + "." + typ, Change: "deleted", Provenance: "CASCADE", DeletionMechanism: "envelope_cascade", Cause: "schedule_delete", Fragment: &FragmentIdentity{EnvelopeID: envelope, Ordinal: index}}
	}
	for i, t := range data.TemporarySchedules {
		f := base(Temporary, i)
		f.Temporary = &TemporaryDetail{Start: t.Start, End: t.End}
		effects = append(effects, f)
		for j, s := range t.Shifts {
			f := base(FixedShift, j)
			parent := i
			f.Fragment.ParentOrdinal = &parent
			f.Shift = &ShiftDetail{UserID: s.UserID, Start: s.Start, End: s.End}
			effects = append(effects, f)
		}
	}
	for i, r := range data.OnCallNotificationRules {
		prefix := e.RootID.String() + ":"
		if !strings.HasPrefix(r.ID, prefix) {
			return nil, ErrInvalid
		}
		n, err := strconv.ParseInt(strings.TrimPrefix(r.ID, prefix), 10, 32)
		if err != nil || n < 0 || r.ID != prefix+strconv.FormatInt(n, 10) {
			return nil, ErrInvalid
		}
		f := base(OnCallRule, i)
		f.OnCallRule = &OnCallRuleDetail{LocalID: int32(n), ChannelID: r.ChannelID, Time: r.Time, Weekdays: r.WeekdayFilter}
		effects = append(effects, f)
	}
	e.Effects = effects
	if err := e.validateEffects(); err != nil {
		return nil, err
	}
	return effects, nil
}
