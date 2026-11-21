package deletionsafety

import (
	"cmp"
	"encoding/hex"
	"reflect"
	"slices"
	"time"
)

// DeletionPlan is immutable through its public API. It describes a proposed
// operation, never a receipt or authority to delete. A zero plan is unavailable.
type DeletionPlan struct {
	input   PlanInput
	impacts []DeletionImpact
	changes []PlannedChange
	version string
	blocked bool
	confirm bool
	valid   bool
}

func (p DeletionPlan) CanProceed() bool           { return p.valid && !p.blocked }
func (p DeletionPlan) RequiresConfirmation() bool { return p.valid && p.confirm }
func (p DeletionPlan) ImpactVersion() string      { return p.version }

func (p DeletionPlan) Targets() []Resource { return slices.Clone(p.input.Targets) }

func (p DeletionPlan) Impacts() []DeletionImpact {
	result := slices.Clone(p.impacts)
	for i := range result {
		result[i].Before = canonicalConfiguration(result[i].Before)
		result[i].After = canonicalConfiguration(result[i].After)
	}
	return result
}

func (p DeletionPlan) Changes() []PlannedChange {
	result := slices.Clone(p.changes)
	for i := range result {
		result[i].Edges = slices.Clone(result[i].Edges)
		result[i].Before = canonicalConfiguration(result[i].Before)
		result[i].After = canonicalConfiguration(result[i].After)
	}
	return result
}

// Check is a pure domain gate. A confirmation can never override BLOCK. Callers
// still own current authorization, locking, re-collection, deletion and commit.
func (p DeletionPlan) Check(expectedVersion string, confirmed bool) error {
	if !p.valid {
		return unavailable()
	}
	if p.blocked {
		return &DeletionSafetyError{Code: DeletionBlocked}
	}
	if expectedVersion != "" && expectedVersion != p.version {
		return &DeletionSafetyError{Code: DeletionDependencyChanged}
	}
	if p.confirm && (!confirmed || expectedVersion == "") {
		return &DeletionSafetyError{Code: DeletionConfirmationRequired}
	}
	return nil
}

// BuildPlan validates all raw inputs before canonical deduplication. Failed or
// partial collections return no plan. BLOCK produces a complete inspectable
// plan with CanProceed=false; Check returns the corresponding typed error.
func BuildPlan(raw PlanInput, budget Budget) (DeletionPlan, error) {
	if budget == (Budget{}) {
		budget = DefaultBudget()
	}
	if budget.MaxTargets < 1 || budget.MaxDependencies < 1 || budget.MaxImpacts < 1 ||
		budget.MaxTargets > 1000 || budget.MaxDependencies > 100000 || budget.MaxImpacts > 300000 {
		return DeletionPlan{}, unavailable()
	}
	input, err := normalizeInput(raw, budget)
	if err != nil {
		return DeletionPlan{}, err
	}
	p := DeletionPlan{input: input}
	checked := make(map[Resource]bool)
	for _, obj := range input.Collection.Checked {
		checked[obj] = true
	}
	intent := make(map[Resource]DestructiveChange)
	removed := make(map[Resource]bool)
	changes := make(map[Resource]PlannedChange)
	var queue []Resource
	for _, change := range input.Intent {
		intent[change.Resource] = change
		changes[change.Resource] = PlannedChange{DestructiveChange: change, Cause: CauseExplicit}
		if change.Kind == ChangeDeleted {
			removed[change.Resource] = true
			queue = append(queue, change.Resource)
		}
	}
	byTarget := make(map[Resource][]Dependency)
	for _, d := range input.Collection.Dependencies {
		byTarget[d.Target] = append(byTarget[d.Target], d)
	}
	for target := range intent {
		if rel := contextRelationship(input.Operation, target.Kind); rel != RelationshipUnknown {
			if !slices.ContainsFunc(byTarget[target], func(d Dependency) bool { return d.Relationship == rel }) {
				return DeletionPlan{}, unavailable()
			}
		}
	}
	// First calculate only the allowlisted ownership/runtime closure. Co-deletion
	// never invents an ownership edge to swallow an otherwise surviving blocker.
	for i := 0; i < len(queue); i++ {
		obj := queue[i]
		if !checked[obj] {
			return DeletionPlan{}, unavailable()
		}
		for _, d := range byTarget[obj] {
			decision, err := Evaluate(EvaluationInput{Dependency: d})
			if err != nil {
				return DeletionPlan{}, err
			}
			if decision.Change != ChangeDeleted || !decision.CanProceed || policyRules[d.Relationship].affectTarget {
				continue
			}
			if !removed[decision.Affected] {
				removed[decision.Affected] = true
				queue = append(queue, decision.Affected)
				if len(queue) > budget.MaxImpacts {
					return DeletionPlan{}, &DeletionSafetyError{Code: DeletionPreviewLimitExceeded}
				}
			}
		}
	}
	for _, d := range input.Collection.Dependencies {
		selected, explicit := intent[d.Target]
		relevant := removed[d.Target] || explicit && changedRelationship(input.Operation, d.Relationship)
		var decision Decision
		coDeletion := removed[d.Referencing]
		if relevant {
			decision, err = Evaluate(EvaluationInput{Dependency: d, CoDeletion: coDeletion})
			if err != nil {
				return DeletionPlan{}, err
			}
			if decision.Policy == PolicyBlock && !coDeletion && (removed[d.Parent] || removed[d.Owner]) {
				// A claimed complete ownership inventory cannot omit this row.
				return DeletionPlan{}, unavailable()
			}
			if explicit && policyRules[d.Relationship].affectTarget {
				decision.Change = selected.Kind
			}
		} else if removed[d.Referencing] && policyRules[d.Relationship].retainedReference {
			decision = Decision{Policy: PolicyInformational, Change: ChangePreserved, Affected: d.Target, CanProceed: true}
		} else {
			continue
		}
		impact := DeletionImpact{EdgeID: edgeIdentity(d), Dependency: d, Decision: decision, IsPlannedCoDeletion: coDeletion}
		if len(p.impacts) >= budget.MaxImpacts {
			return DeletionPlan{}, &DeletionSafetyError{Code: DeletionPreviewLimitExceeded}
		}
		p.impacts = append(p.impacts, impact)
		p.blocked = p.blocked || decision.Policy == PolicyBlock
		p.confirm = p.confirm || decision.RequiresConfirmation
		if decision.CanProceed && decision.Change != ChangePreserved {
			if err := mergeChange(changes, impact); err != nil {
				return DeletionPlan{}, err
			}
			if len(changes) > budget.MaxImpacts {
				return DeletionPlan{}, &DeletionSafetyError{Code: DeletionPreviewLimitExceeded}
			}
		}
		// Ancestor effects are explanatory; they cannot remove those ancestors or
		// weaken the direct classification. Keep their exact causal edge identity.
		for _, parent := range uniqueResources([]Resource{d.Parent, d.Owner}) {
			if parent == (Resource{}) || parent == decision.Affected || parent == d.Target || removed[parent] {
				continue
			}
			if len(p.impacts) >= budget.MaxImpacts {
				return DeletionPlan{}, &DeletionSafetyError{Code: DeletionPreviewLimitExceeded}
			}
			derived := impact
			derived.EdgeID = derivedIdentity(impact.EdgeID, parent)
			derived.IsDerived, derived.DerivedFrom = true, impact.EdgeID
			derived.Decision = Decision{Policy: PolicyInformational, Change: ChangePreserved, Affected: parent, CanProceed: true}
			p.impacts = append(p.impacts, derived)
		}
	}
	for _, change := range changes {
		slices.Sort(change.Edges)
		p.changes = append(p.changes, change)
	}
	slices.SortFunc(p.changes, func(a, b PlannedChange) int { return compareResource(a.Resource, b.Resource) })
	slices.SortFunc(p.impacts, func(a, b DeletionImpact) int { return cmp.Compare(a.EdgeID, b.EdgeID) })
	p.valid = true
	p.version = impactVersion(p, PolicyVersion)
	return p, nil
}

func changedRelationship(op Operation, rel RelationshipKind) bool {
	switch op {
	case OperationUpdateService:
		return rel == RelationshipChangedServicePolicy
	case OperationUpdateRotation:
		return rel == RelationshipRemovedParticipant
	case OperationSetTemporarySchedule, OperationClearTemporarySchedules:
		return rel == RelationshipChangedTemporary
	case OperationSetOnCallNotificationRules:
		return rel == RelationshipRemovedOnCallRule
	default:
		return false
	}
}

func mergeChange(changes map[Resource]PlannedChange, impact DeletionImpact) error {
	obj, kind := impact.Affected, impact.Change
	c, exists := changes[obj]
	if !exists {
		c = PlannedChange{DestructiveChange: DestructiveChange{Resource: obj, Kind: kind}, Cause: CauseCascade}
	} else if c.Cause != CauseExplicit {
		if kind == ChangeDeleted {
			c.Kind = kind
		} else if c.Kind != ChangeDeleted && c.Kind != kind {
			return unavailable()
		}
	}
	c.Edges = append(c.Edges, impact.EdgeID)
	changes[obj] = c
	return nil
}

func normalizeInput(raw PlanInput, budget Budget) (PlanInput, error) {
	// Count the original selection and all raw relation/reference records. Invalid
	// duplicates cannot first be reduced to fit a caller's operation budget.
	weight := len(raw.Collection.Dependencies)
	for _, d := range raw.Collection.Dependencies {
		weight += len(d.Before.References) + len(d.After.References)
	}
	for _, c := range raw.Intent {
		weight += len(c.Before.References) + len(c.After.References)
	}
	if len(raw.Targets) > budget.MaxTargets || len(raw.Intent) > budget.MaxTargets || len(raw.Targets) > budget.MaxImpacts ||
		weight > budget.MaxDependencies || len(raw.Collection.Checked) > budget.MaxDependencies+budget.MaxTargets {
		return PlanInput{}, &DeletionSafetyError{Code: DeletionPreviewLimitExceeded}
	}
	fingerprint, err := hex.DecodeString(raw.ScopeFingerprint)
	if err != nil || len(fingerprint) != 32 || hex.EncodeToString(fingerprint) != raw.ScopeFingerprint ||
		raw.Collection.Completeness != DependenciesComplete || len(raw.Targets) == 0 || len(raw.Intent) != len(raw.Targets) {
		return PlanInput{}, unavailable()
	}
	targets, intents := make(map[Resource]bool), make(map[Resource]bool)
	for _, obj := range raw.Targets {
		if !validResource(obj) || targets[obj] {
			return PlanInput{}, unavailable()
		}
		targets[obj] = true
	}
	input := raw
	input.Targets = uniqueResources(raw.Targets)
	input.Intent = slices.Clone(raw.Intent)
	for i, c := range input.Intent {
		if !targets[c.Resource] || intents[c.Resource] || !validIntent(raw.Operation, c) {
			return PlanInput{}, unavailable()
		}
		intents[c.Resource] = true
		c.Before, c.After = canonicalConfiguration(c.Before), canonicalConfiguration(c.After)
		input.Intent[i] = c
	}
	slices.SortFunc(input.Intent, func(a, b DestructiveChange) int { return compareResource(a.Resource, b.Resource) })
	for _, obj := range raw.Collection.Checked {
		if !validResource(obj) {
			return PlanInput{}, unavailable()
		}
	}
	input.Collection.Checked = uniqueResources(raw.Collection.Checked)
	for obj := range targets {
		if !slices.Contains(input.Collection.Checked, obj) {
			return PlanInput{}, unavailable()
		}
	}
	input.Collection.Dependencies = nil
	edges := make(map[string]Dependency)
	owners := make(map[Resource][2]Resource)
	type periodObservation struct {
		State      PeriodState
		Start, End time.Time
	}
	periods := make(map[Resource]periodObservation)
	for _, d := range raw.Collection.Dependencies {
		if err := validateDependency(d); err != nil {
			return PlanInput{}, err
		}
		d.Before, d.After = canonicalConfiguration(d.Before), canonicalConfiguration(d.After)
		if periodObject := periodResource(d); periodObject != (Resource{}) {
			observation := periodObservation{d.State.Period, d.Before.WindowStart, d.Before.WindowEnd}
			if previous, ok := periods[periodObject]; ok && previous != observation {
				return PlanInput{}, unavailable()
			}
			periods[periodObject] = observation
		}
		owner := [2]Resource{d.Parent, d.Owner}
		if previous, ok := owners[d.Referencing]; ok && previous != owner {
			return PlanInput{}, unavailable()
		}
		owners[d.Referencing] = owner
		id := edgeIdentity(d)
		if previous, ok := edges[id]; ok {
			if !reflect.DeepEqual(previous, d) {
				return PlanInput{}, unavailable()
			}
			continue
		}
		edges[id] = d
		input.Collection.Dependencies = append(input.Collection.Dependencies, d)
	}
	slices.SortFunc(input.Collection.Dependencies, func(a, b Dependency) int {
		return cmp.Compare(edgeIdentity(a), edgeIdentity(b))
	})
	return input, nil
}

func periodResource(d Dependency) Resource {
	switch d.Relationship {
	case RelationshipOverrideCoverage:
		return d.Target
	case RelationshipOverrideAddUser, RelationshipOverrideRemoveUser, RelationshipShiftUser,
		RelationshipScheduleOverride, RelationshipScheduleTemporary, RelationshipScheduleShift, RelationshipTemporaryShift:
		return d.Referencing
	default:
		return Resource{}
	}
}
