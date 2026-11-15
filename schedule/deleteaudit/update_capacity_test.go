package deleteaudit

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func capacityRuleEvent(n int, kind string) Event {
	e := targetUpdateEvent()
	f := e.Effects[0]
	f.RuleDeletion.TargetKind = kind
	e.Effects = nil
	for range n {
		id := uuid.New()
		f.ResourceUUID, f.EffectID = &id, uuid.New()
		e.Effects = append(e.Effects, f)
	}
	return e
}

func assertRuleCapacity(t *testing.T, e Event, want error) int {
	t.Helper()
	before, err := json.Marshal(e)
	require.NoError(t, err)
	raw, err := json.Marshal(e.Canonical().Effects)
	require.NoError(t, err)
	require.Equal(t, len(raw), e.JSONBytes(), "guard must use the existing canonical Effects serialization")
	var objects []map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(raw, &objects))
	for _, object := range objects {
		require.Len(t, object, 11)
		var detail map[string]json.RawMessage
		require.NoError(t, json.Unmarshal(object["rule_deletion"], &detail))
		require.Len(t, detail, 3)
		require.Contains(t, detail, "schedule_id")
		require.Contains(t, detail, "target_kind")
		require.Contains(t, detail, "target_id")
	}
	d := len(raw)
	if len(e.Effects) != 0 {
		d += 27*len(e.Effects) - 1
	}
	// Closed ASCII values have no colon/comma, so counting separators is an
	// independent check of the formula and its field/nesting assumptions.
	require.Equal(t, len(raw)+bytes.Count(raw, []byte(":"))+bytes.Count(raw, []byte(",")), d)
	if want == nil {
		require.NoError(t, e.Validate())
	} else {
		require.ErrorIs(t, e.Validate(), want)
	}
	after, err := json.Marshal(e)
	require.NoError(t, err)
	require.Equal(t, sha256.Sum256(before), sha256.Sum256(after))
	return d
}

func TestScheduleTargetUpdateExactCapacity(t *testing.T) {
	for _, tc := range []struct {
		kind string
		max  int
		unit int
	}{{"user", 14899, 563}, {"rotation", 14794, 567}} {
		t.Run(tc.kind, func(t *testing.T) {
			for _, n := range []int{1, 2, 30, tc.max, tc.max + 1, MaxEffects, MaxEffects + 1} {
				t.Run(fmt.Sprint(n), func(t *testing.T) {
					var want error
					if n > tc.max {
						want = ErrCapacity
					}
					d := assertRuleCapacity(t, capacityRuleEvent(n, tc.kind), want)
					require.Equal(t, tc.unit*n, d)
				})
			}
			// Same-target events are homogeneous: exact equality to 8 MiB is
			// unrepresentable. Exercise the nearest below/above, not padding.
			require.NotZero(t, MaxJSONBytes%tc.unit)
			require.Less(t, tc.unit*tc.max, MaxJSONBytes)
			require.Greater(t, tc.unit*(tc.max+1), MaxJSONBytes)
		})
	}
}

func TestScheduleTargetUpdateExactCapacitySemanticOrdering(t *testing.T) {
	for name, change := range map[string]func(*Event){
		"root":   func(e *Event) { e.Effects[0].RootID = uuid.New() },
		"org":    func(e *Event) { e.Effects[0].TargetOrganizationID = uuid.New() },
		"parent": func(e *Event) { e.Effects[0].RuleDeletion.ScheduleID = uuid.New() },
		"target": func(e *Event) { e.Effects[0].RuleDeletion.TargetID = uuid.Nil },
		"kind":   func(e *Event) { e.Effects[0].RuleDeletion.TargetKind = "unknown" },
		"extra":  func(e *Event) { n := int64(1); e.Effects[0].ResourceNumericID = &n },
		"mixed-kind": func(e *Event) {
			d := *e.Effects[0].RuleDeletion
			d.TargetKind = "rotation"
			e.Effects[0].RuleDeletion = &d
		},
		"mixed-target": func(e *Event) {
			d := *e.Effects[0].RuleDeletion
			d.TargetID = uuid.New()
			e.Effects[0].RuleDeletion = &d
		},
		"duplicate": func(e *Event) { e.Effects[0] = e.Effects[1] },
	} {
		t.Run(name, func(t *testing.T) {
			e := capacityRuleEvent(14900, "user")
			require.Less(t, e.JSONBytes(), MaxJSONBytes)
			change(&e)
			require.ErrorIs(t, e.Validate(), ErrInvalid)
		})
	}
	for _, empty := range [][]Effect{nil, {}} {
		e := capacityRuleEvent(0, "user")
		e.Effects = empty
		require.ErrorIs(t, e.Validate(), ErrInvalid)
		e.RecordKind, e.Outcome, e.Reason = "attempt_observation", "commit_unknown", "commit_unconfirmed"
		e.Provenance, e.DeletionMechanism, e.Cause = "", "", ""
		require.Equal(t, 2, assertRuleCapacity(t, e, nil))
	}
}
