package oncallupdateaudit

import (
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func testEvent() Event {
	id := uuid.New()
	b := []Rule{{ID: id.String() + ":0", Channel: uuid.NewString(), Time: "09:00", Weekdays: "0111110"}}
	a := []Rule{}
	f, _ := Diff(id, b, a)
	return Event{Version: 1, EventID: uuid.New(), RequestID: uuid.New(), AttemptID: uuid.New(), ActorKind: "internal_system", AuthoritySource: "trusted_internal_system", AuthorityRole: "internal_system", OrganizationRole: "unknown", ScheduleID: id, OrganizationID: uuid.New(), EnvelopeID: 1, Operation: Operation, OccurredAt: time.Now(), Before: b, After: a, Effects: f}
}

func TestSemanticDiff(t *testing.T) {
	e := testEvent()
	r := e.Before[0]
	for _, tc := range []struct {
		name        string
		after       []Rule
		changes     []string
		destructive bool
	}{
		{"equivalent", []Rule{r}, nil, false},
		{"clear", []Rule{}, []string{"rule_removed"}, true},
		{"add", []Rule{r, {ID: e.ScheduleID.String() + ":1", Channel: uuid.NewString()}}, []string{"rule_added"}, false},
		{"channel", []Rule{{ID: r.ID, Channel: uuid.NewString(), Time: r.Time, Weekdays: r.Weekdays}}, []string{"channel_replaced"}, true},
		{"time", []Rule{{ID: r.ID, Channel: r.Channel, Time: "10:00", Weekdays: r.Weekdays}}, []string{"trigger_replaced"}, true},
		{"mode", []Rule{{ID: r.ID, Channel: r.Channel}}, []string{"trigger_replaced"}, true},
		{"weekdays_trim", []Rule{{ID: r.ID, Channel: r.Channel, Time: r.Time, Weekdays: "0011110"}}, []string{"trigger_trimmed"}, true},
		{"weekdays_expand", []Rule{{ID: r.ID, Channel: r.Channel, Time: r.Time, Weekdays: "1111111"}}, []string{"trigger_expanded"}, false},
		{"weekdays_replace", []Rule{{ID: r.ID, Channel: r.Channel, Time: r.Time, Weekdays: "1000001"}}, []string{"trigger_expanded", "trigger_trimmed"}, true},
		{"reused_id", []Rule{{ID: r.ID, Channel: uuid.NewString()}}, []string{"channel_replaced", "trigger_replaced"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, err := Canonical(e.ScheduleID, tc.after)
			require.NoError(t, err)
			f, err := Diff(e.ScheduleID, e.Before, a)
			require.NoError(t, err)
			var changes []string
			for _, effect := range f {
				changes = append(changes, effect.Change)
			}
			require.Equal(t, tc.changes, changes)
			require.Equal(t, tc.destructive, Destructive(f))
		})
	}
	a, err := Canonical(e.ScheduleID, []Rule{r, {ID: e.ScheduleID.String() + ":1", Channel: uuid.NewString()}})
	require.NoError(t, err)
	b := slices.Clone(a)
	slices.Reverse(b)
	b, err = Canonical(e.ScheduleID, b)
	require.NoError(t, err)
	f, err := Diff(e.ScheduleID, a, b)
	require.NoError(t, err)
	require.Empty(t, f)
}

func TestEventFailsClosed(t *testing.T) {
	for name, patch := range map[string]func(*Event){
		"version": func(e *Event) { e.Version = 2 }, "operation": func(e *Event) { e.Operation = "schedule.delete" },
		"scope": func(e *Event) { e.ScheduleID = uuid.New() }, "missing_before": func(e *Event) { e.Before = nil },
		"missing_after": func(e *Event) { e.After = nil }, "missing_effect": func(e *Event) { e.Effects = []Effect{} },
		"duplicate_effect": func(e *Event) { e.Effects = append(e.Effects, e.Effects[0]) },
		"fake_source":      func(e *Event) { e.Effects[0].Source = "CASCADE" },
		"channel":          func(e *Event) { e.Before[0].Channel = uuid.Nil.String() },
		"time":             func(e *Event) { e.Before[0].Time = "24:00" }, "weekdays": func(e *Event) { e.Before[0].Weekdays = "0000000" },
		"rule_id":   func(e *Event) { e.Before[0].ID = e.ScheduleID.String() + ":50" },
		"authority": func(e *Event) { e.ActorKind = "human" },
	} {
		t.Run(name, func(t *testing.T) {
			e := testEvent()
			require.NoError(t, e.Validate())
			patch(&e)
			require.ErrorIs(t, e.Validate(), ErrInvalid)
		})
	}
}
