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

func capacityEPEvent(operation string, steps, actions, number int, kinds ...string) Event {
	e := updateEvent(operation)
	parents := []uuid.UUID{e.RootID}
	for i := range steps {
		f := testStep(e)
		f.Provenance, f.DeletionMechanism, f.Cause = "EXPLICIT", "explicit_sql", "update_induced"
		n := number
		f.StepNumber = &n
		e.Effects = append(e.Effects, f)
		if i == 0 {
			parents = nil
		}
		parents = append(parents, *f.ResourceUUID)
	}
	for i := range actions {
		e.Effects = append(e.Effects, updateAction(e, parents[i%len(parents)], kinds[i%len(kinds)]))
	}
	return e
}

func assertEPCapacity(t *testing.T, e Event, want error) (compact, expanded int) {
	t.Helper()
	before, err := json.Marshal(e)
	require.NoError(t, err)
	raw, err := json.Marshal(e.Canonical().Effects)
	require.NoError(t, err)
	existing, err := json.Marshal(canonicalEffects(e.Effects))
	require.NoError(t, err)
	require.Equal(t, sha256.Sum256(existing), sha256.Sum256(raw))
	var objects []map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(raw, &objects))
	steps, actions := 0, 0
	for i, f := range e.Canonical().Effects {
		switch f.ResourceType {
		case Step:
			steps++
			require.Len(t, objects[i], 11)
		case Action:
			actions++
			require.Len(t, objects[i], 13)
		default:
			t.Fatalf("unexpected capacity fixture type: %s", f.ResourceType)
		}
	}
	require.Equal(t, len(e.Effects), steps+actions)
	expanded = len(raw)
	if len(e.Effects) != 0 {
		expanded += 22*steps + 26*actions - 1
	}
	// Independent separator oracle for the closed ASCII projection: no string
	// contains a colon/comma. This also catches added fields or nesting.
	require.Equal(t, len(raw)+bytes.Count(raw, []byte(":"))+bytes.Count(raw, []byte(",")), expanded)
	if want == nil {
		require.NoError(t, e.Validate())
	} else {
		require.ErrorIs(t, e.Validate(), want)
	}
	after, err := json.Marshal(e)
	require.NoError(t, err)
	require.Equal(t, sha256.Sum256(before), sha256.Sum256(after), "capacity validation must not mutate Effects")
	return len(raw), expanded
}

func TestEPUpdateExactCapacityShapes(t *testing.T) {
	for _, number := range []int{0, 9, 10, 99, 2147483647} {
		t.Run(fmt.Sprint(number), func(t *testing.T) {
			assertEPCapacity(t, capacityEPEvent(PolicyUpdate, 1, 0, number), nil)
		})
	}
	kinds := []string{"user", "schedule", "rotation", "notification_channel"}
	for _, kind := range kinds {
		t.Run(kind, func(t *testing.T) {
			assertEPCapacity(t, capacityEPEvent(PolicyUpdate, 1, 1, 0, kind), nil)
			assertEPCapacity(t, capacityEPEvent(StepUpdate, 0, 1, 0, kind), nil)
		})
	}
	assertEPCapacity(t, capacityEPEvent(PolicyUpdate, 2, 8, 99, kinds...), nil)
	assertEPCapacity(t, capacityEPEvent(StepUpdate, 0, 4, 0, kinds...), nil)
}

func TestPolicyUpdateExactCapacityBoundaries(t *testing.T) {
	for _, n := range []int{MaxEffects, MaxEffects + 1} {
		t.Run(fmt.Sprintf("count-%d", n), func(t *testing.T) {
			var want error
			if n > MaxEffects {
				want = ErrCapacity
			}
			assertEPCapacity(t, capacityEPEvent(PolicyUpdate, n, 0, 0), want)
		})
	}
	// Native PGVERIFY1 compositions. Only legal StepNumber digit lengths and
	// Action TargetKinds vary; no free-text padding or raw JSON is introduced.
	for i, number := range []int{0, 10, 100} {
		t.Run(fmt.Sprintf("bytes-%d", MaxJSONBytes+i-1), func(t *testing.T) {
			e := capacityEPEvent(PolicyUpdate, 1, 14589, number, "notification_channel")
			e.Effects[1].TargetKind = "user"
			for j := 2; j < 43; j++ {
				e.Effects[j].TargetKind = "schedule"
			}
			var want error
			if i == 2 {
				want = ErrCapacity
			}
			_, d := assertEPCapacity(t, e, want)
			require.Equal(t, MaxJSONBytes+i-1, d)
		})
	}
	t.Run("maximum-false-rejection-margin", func(t *testing.T) {
		e := capacityEPEvent(PolicyUpdate, 8594, 7790, 2147483647, "notification_channel")
		c, d := assertEPCapacity(t, e, nil)
		require.Equal(t, 7946349, c)
		require.Equal(t, 8337956, d)
		require.Equal(t, 8388717, c+27*len(e.Effects))
		require.Greater(t, c+27*len(e.Effects), MaxJSONBytes)
	})
}

func TestStepUpdateExactCapacityBoundaries(t *testing.T) {
	for _, tc := range []struct {
		kind string
		max  int
	}{{"user", 14847}, {"schedule", 14742}, {"rotation", 14742}, {"notification_channel", 14438}} {
		t.Run(tc.kind, func(t *testing.T) {
			e := capacityEPEvent(StepUpdate, 0, tc.max, 0, tc.kind)
			c, _ := assertEPCapacity(t, e, nil)
			require.Greater(t, c+27*len(e.Effects), MaxJSONBytes, "SQL-accepted event lost by conservative guard")
			e.Effects = append(e.Effects, updateAction(e, e.RootID, tc.kind))
			assertEPCapacity(t, e, ErrCapacity)
		})
	}
	for i, counts := range [][3]int{{2, 35, 14402}, {0, 86, 14354}, {1, 133, 14307}} {
		t.Run(fmt.Sprintf("bytes-%d", MaxJSONBytes+i-1), func(t *testing.T) {
			e := capacityEPEvent(StepUpdate, 0, counts[0]+counts[1]+counts[2], 0, "notification_channel")
			for j := range counts[0] + counts[1] {
				if j < counts[0] {
					e.Effects[j].TargetKind = "user"
				} else {
					e.Effects[j].TargetKind = "schedule"
				}
			}
			var want error
			if i == 2 {
				want = ErrCapacity
			}
			_, d := assertEPCapacity(t, e, want)
			require.Equal(t, MaxJSONBytes+i-1, d)
		})
	}
	for _, n := range []int{MaxEffects, MaxEffects + 1} {
		// Even the shortest U02 Action exceeds the byte budget at N=16384.
		assertEPCapacity(t, capacityEPEvent(StepUpdate, 0, n, 0, "user"), ErrCapacity)
	}
}

func TestEPUpdateExactCapacitySemanticOrdering(t *testing.T) {
	for _, operation := range []string{PolicyUpdate, StepUpdate} {
		for name, change := range map[string]func(*Event){
			"parent": func(e *Event) { id := uuid.New(); e.Effects[len(e.Effects)-1].ParentStepID = &id },
			"root":   func(e *Event) { e.Effects[0].RootID = uuid.New() },
			"org":    func(e *Event) { e.Effects[0].TargetOrganizationID = uuid.New() },
			"target": func(e *Event) { id := uuid.Nil; e.Effects[len(e.Effects)-1].TargetID = &id },
			"kind":   func(e *Event) { e.Effects[len(e.Effects)-1].TargetKind = "unknown" },
			"duplicate": func(e *Event) {
				e.Effects[len(e.Effects)-2] = e.Effects[len(e.Effects)-1]
			},
		} {
			t.Run(operation+"/"+name, func(t *testing.T) {
				steps := 0
				if operation == PolicyUpdate {
					steps = 1
				}
				e := capacityEPEvent(operation, steps, 14600, 0, "notification_channel")
				raw, err := json.Marshal(e.Canonical().Effects)
				require.NoError(t, err)
				require.Less(t, len(raw), MaxJSONBytes)
				require.Greater(t, len(raw)+22*steps+26*14600-1, MaxJSONBytes)
				change(&e)
				require.ErrorIs(t, e.Validate(), ErrInvalid, "new byte guard must not hide existing semantic errors")
			})
		}
		for _, empty := range [][]Effect{nil, {}} {
			e := updateEvent(operation)
			e.Effects = empty
			require.ErrorIs(t, e.Validate(), ErrInvalid)
			e.RecordKind, e.Outcome, e.Reason = "attempt_observation", "commit_unknown", "commit_unconfirmed"
			e.Provenance, e.DeletionMechanism, e.Cause = "", "", ""
			c, d := assertEPCapacity(t, e, nil)
			require.Equal(t, 2, c)
			require.Equal(t, 2, d)
		}
	}
}
