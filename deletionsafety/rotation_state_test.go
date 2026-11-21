package deletionsafety

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestRotationStateCanonicalClosure(t *testing.T) {
	root := obj(ResourceRotation, "rotation")
	state := dep(root, obj(ResourceRotationState, "42"), RelationshipRotationState, root, root)
	participant := dep(root, state.Before.References[0], RelationshipRotationParticipant, root, root)
	participant.Before.Position = state.Before.Position
	participant.Before.References = []Resource{obj(ResourceUser, "user")}
	input := inputFor([]Resource{root}, participant, state)
	plan := mustPlan(t, input)
	require.True(t, plan.CanProceed())
	require.True(t, plan.RequiresConfirmation())
	require.Len(t, plan.Changes(), 3)
	for _, change := range plan.Changes() {
		require.NotEqual(t, ResourceUser, change.Resource.Kind)
	}
	for _, edit := range []func(*Dependency){
		func(d *Dependency) {
			d.Before.RotationState.ShiftStart = d.Before.RotationState.ShiftStart.Add(time.Microsecond)
		},
		func(d *Dependency) { d.Referencing.ID = "43" },
		func(d *Dependency) { d.Before.References[0].ID = "other-participant" },
		func(d *Dependency) { n := 1; d.Before.Position = &n },
	} {
		changed := state
		changed.Before = canonicalConfiguration(state.Before)
		edit(&changed)
		require.NotEqual(t, plan.ImpactVersion(), mustPlan(t, inputFor([]Resource{root}, participant, changed)).ImpactVersion())
	}
	// Immutable input/output and timezone canonicalization use the same manifest.
	want := plan.ImpactVersion()
	state.Before.RotationState.ShiftStart = state.Before.RotationState.ShiftStart.Add(time.Hour)
	impacts := plan.Impacts()
	for i := range impacts {
		if impacts[i].Before.RotationState != nil {
			impacts[i].Before.RotationState.Version = 999
		}
	}
	require.Equal(t, want, impactVersion(plan, PolicyVersion))
	state = dep(root, obj(ResourceRotationState, "42"), RelationshipRotationState, root, root)
	state.Before.RotationState.ShiftStart = state.Before.RotationState.ShiftStart.In(time.FixedZone("same-instant", 8*3600))
	require.Equal(t, want, mustPlan(t, inputFor([]Resource{root}, participant, state)).ImpactVersion())
}

func TestRotationStateRejectsIncompleteProjection(t *testing.T) {
	root := obj(ResourceRotation, "rotation")
	for _, edit := range []func(*Dependency){
		func(d *Dependency) { d.Before.RotationState = nil },
		func(d *Dependency) { d.Before.RotationState.Version = 1 },
		func(d *Dependency) { d.Before.RotationState.Version = 3 },
		func(d *Dependency) { d.Before.RotationState.ShiftStart = time.Time{} },
		func(d *Dependency) { d.Before.RotationState.ShiftStart = time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC) },
		func(d *Dependency) {
			d.Before.RotationState.ShiftStart = time.Date(9999, 12, 31, 23, 0, 0, 0, time.FixedZone("boundary", -3600))
		},
		func(d *Dependency) { d.Before.Position = nil },
		func(d *Dependency) { d.Before.References = nil },
		func(d *Dependency) { d.Before.References[0].Kind = ResourceUser },
		func(d *Dependency) { d.Parent.ID = "foreign" },
		func(d *Dependency) { d.Owner.ID = "foreign" },
	} {
		d := dep(root, obj(ResourceRotationState, "42"), RelationshipRotationState, root, root)
		edit(&d)
		_, err := BuildPlan(inputFor([]Resource{root}, d), Budget{})
		requireCode(t, err, DeletionUnavailable)
	}
}
