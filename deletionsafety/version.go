package deletionsafety

import (
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"
)

func compareResource(a, b Resource) int {
	if c := cmp.Compare(a.Kind, b.Kind); c != 0 {
		return c
	}
	return cmp.Compare(a.ID, b.ID)
}

func uniqueResources(raw []Resource) []Resource {
	result := append([]Resource{}, raw...)
	slices.SortFunc(result, compareResource)
	return slices.Compact(result)
}

func canonicalConfiguration(c Configuration) Configuration {
	c.References = uniqueResources(c.References)
	if c.Position != nil {
		position := *c.Position
		c.Position = &position
	}
	if c.RotationState != nil {
		state := *c.RotationState
		state.ShiftStart = state.ShiftStart.Round(0).UTC()
		c.RotationState = &state
	}
	c.WindowStart = c.WindowStart.Round(0).UTC()
	c.WindowEnd = c.WindowEnd.Round(0).UTC()
	return c
}

func digest(value any) string {
	// Only closed domain structs enter this helper: valid IDs, integer enums,
	// nilable integers, slices and finite business intervals. Marshal cannot fail.
	data, err := json.Marshal(value)
	if err != nil {
		panic("invalid deletion safety canonical value")
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func edgeIdentity(d Dependency) string {
	return digest(struct {
		Target, Referencing, Parent, Owner Resource
		Relationship                       RelationshipKind
	}{d.Target, d.Referencing, d.Parent, d.Owner, d.Relationship})
}

func derivedIdentity(edge string, parent Resource) string {
	return digest(struct {
		Edge   string
		Parent Resource
	}{edge, parent})
}

// canonicalManifest contains only the safe closed projection. No names, URLs,
// destinations, credentials, arbitrary metadata or collection timestamps are
// accepted. Business intervals and ordered positions are destructive semantics.
// All relationships are included, even those retained or informational; this
// first contract deliberately favors conservative invalidation over view-only
// optimizations. Confirmation itself is excluded; its requirements are included.
type canonicalManifest struct {
	SchemaVersion string
	PolicyVersion string
	Input         PlanInput
	Impacts       []DeletionImpact
	Changes       []PlannedChange
}

func manifest(p DeletionPlan, policyVersion string) canonicalManifest {
	input := p.input
	input.Intent = slices.Clone(input.Intent)
	for i := range input.Intent {
		input.Intent[i].Before = canonicalConfiguration(input.Intent[i].Before)
		input.Intent[i].After = canonicalConfiguration(input.Intent[i].After)
	}
	impacts := p.Impacts()
	changes := p.Changes()
	return canonicalManifest{SchemaVersion: "1", PolicyVersion: policyVersion, Input: input, Impacts: impacts, Changes: changes}
}

func impactVersion(p DeletionPlan, policyVersion string) string {
	return digest(manifest(p, policyVersion))
}
