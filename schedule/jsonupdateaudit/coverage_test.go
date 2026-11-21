package jsonupdateaudit

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func temp(start, end string) Coverage { return Coverage{Kind: "temporary", Start: start, End: end} }
func shift(user, start, end string) Coverage {
	return Coverage{Kind: "fixed_shift", UserID: user, Start: start, End: end}
}
func eventFixture(t *testing.T) Event {
	t.Helper()
	b := []Coverage{temp("0", "10")}
	a := []Coverage{temp("0", "3"), temp("7", "10")}
	effects, err := Diff(b, a)
	require.NoError(t, err)
	return Event{Version: 1, EventID: uuid.New(), RequestID: uuid.New(), AttemptID: uuid.New(), ActorKind: "internal_system", AuthoritySource: "trusted_internal_system", AuthorityRole: "internal_system", OrganizationRole: "unknown", ScheduleID: uuid.New(), OrganizationID: uuid.New(), EnvelopeID: 1, Operation: Clear, Mode: "clear", OccurredAt: time.Now(), Before: b, After: a, Effects: effects}
}
func TestCoverageSemanticDifference(t *testing.T) {
	user := uuid.NewString()
	for _, tc := range []struct {
		name string
		b, a []Coverage
		want []Effect
	}{
		{"remove empty temporary", []Coverage{temp("0", "10")}, []Coverage{}, []Effect{{temp("0", "10"), "coverage_removed", "EXPLICIT"}}},
		{"trim", []Coverage{temp("0", "10")}, []Coverage{temp("0", "7")}, []Effect{{temp("7", "10"), "coverage_removed", "EXPLICIT"}}},
		{"split", []Coverage{temp("0", "10")}, []Coverage{temp("0", "3"), temp("7", "10")}, []Effect{{temp("3", "7"), "coverage_removed", "EXPLICIT"}}},
		{"adjacent merge reorder", []Coverage{temp("5", "10"), temp("0", "5")}, []Coverage{temp("0", "10")}, []Effect{}},
		{"overlap equivalent", []Coverage{temp("0", "7"), temp("3", "10")}, []Coverage{temp("0", "10")}, []Effect{}},
		{"shifts cleared temporary retained", []Coverage{temp("0", "10"), shift(user, "0", "10")}, []Coverage{temp("0", "10")}, []Effect{{shift(user, "0", "10"), "coverage_removed", "EXPLICIT"}}},
		{"same user disjoint", []Coverage{shift(user, "0", "3"), shift(user, "7", "10")}, []Coverage{shift(user, "0", "10")}, []Effect{{shift(user, "3", "7"), "coverage_added", "EXPLICIT"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Diff(tc.b, tc.a)
			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}
}
func TestCoverageDifferenceAgainstDiscreteOracle(t *testing.T) {
	// Every combination of eight half-open cells, independently of segmentation.
	for b := 0; b < 256; b++ {
		for a := 0; a < 256; a++ {
			before, after := make([]Coverage, 0), make([]Coverage, 0)
			for n := 0; n < 8; n++ {
				c := temp(Instant(time.Unix(int64(n), 0)), Instant(time.Unix(int64(n+1), 0)))
				if b&(1<<n) != 0 {
					before = append(before, c)
				}
				if a&(1<<n) != 0 {
					after = append(after, c)
				}
			}
			effects, err := Diff(before, after)
			require.NoError(t, err)
			removed, added := 0, 0
			for _, e := range effects {
				for n := int(Time(e.Start).Unix()); n < int(Time(e.End).Unix()); n++ {
					if e.Change == "coverage_removed" {
						removed |= 1 << n
					} else {
						added |= 1 << n
					}
				}
			}
			require.Equal(t, b & ^a, removed)
			require.Equal(t, a & ^b, added)
		}
	}
}
func TestScheduleJSONAuditClosedContract(t *testing.T) {
	e := eventFixture(t)
	require.NoError(t, e.Validate())
	for name, mutate := range map[string]func(*Event){
		"wrong version": func(e *Event) { e.Version = 2 }, "root delete disguise": func(e *Event) { e.Operation = "schedule.delete" },
		"wrong mode": func(e *Event) { e.Mode = "set_clear" }, "missing before": func(e *Event) { e.Before = nil },
		"invalid interval": func(e *Event) { e.After = []Coverage{temp("10", "0")} }, "noncanonical": func(e *Event) { e.After = []Coverage{temp("7", "10"), temp("0", "3")} },
		"effect omitted": func(e *Event) { e.Effects = []Effect{} }, "effect duplicate": func(e *Event) { e.Effects = append(e.Effects, e.Effects[0]) },
		"cascade fiction": func(e *Event) { e.Effects[0].Source = "CASCADE" }, "deleted fiction": func(e *Event) { e.Effects[0].Change = "deleted" },
		"missing actor": func(e *Event) { e.ActorKind = "human" }, "nil schedule": func(e *Event) { e.ScheduleID = uuid.Nil },
		"outside temporary": func(e *Event) { e.After = []Coverage{shift(uuid.NewString(), "0", "3")} },
	} {
		t.Run(name, func(t *testing.T) {
			e := eventFixture(t)
			mutate(&e)
			require.ErrorIs(t, e.Validate(), ErrInvalid)
			require.Error(t, Append(context.Background(), nil, e))
		})
	}
	for _, year := range []int{1, 1969, 2026, 9999} {
		at := time.Date(year, 12, 1, 0, 0, 0, 999999999, time.FixedZone("synthetic", 8*3600))
		require.True(t, Time(Instant(at)).Equal(at))
		require.True(t, validInstant(Instant(at)))
	}
	effects, err := Diff(e.Before, e.After)
	require.NoError(t, err)
	require.True(t, reflect.DeepEqual(effects, e.Effects))
}
