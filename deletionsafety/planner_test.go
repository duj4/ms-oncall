package deletionsafety

import (
	"reflect"
	"slices"
	"strings"
	"testing"
)

func inputFor(targets []Resource, dependencies ...Dependency) PlanInput {
	input := PlanInput{Operation: OperationDeleteResources, ScopeFingerprint: strings.Repeat("a", 64), Targets: targets,
		Collection: Collection{Completeness: DependenciesComplete, Checked: slices.Clone(targets), Dependencies: dependencies}}
	for _, target := range targets {
		input.Intent = append(input.Intent, DestructiveChange{Resource: target, Kind: ChangeDeleted})
	}
	for _, d := range dependencies {
		input.Collection.Checked = append(input.Collection.Checked, d.Target, d.Referencing)
	}
	return input
}

func mustPlan(t *testing.T, input PlanInput) DeletionPlan {
	t.Helper()
	p, err := BuildPlan(input, Budget{})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func findChange(t *testing.T, p DeletionPlan, r Resource) PlannedChange {
	t.Helper()
	for _, c := range p.Changes() {
		if c.Resource == r {
			return c
		}
	}
	t.Fatalf("missing change for %+v", r)
	return PlannedChange{}
}

func assertPreserved(t *testing.T, p DeletionPlan, resources ...Resource) {
	t.Helper()
	for _, c := range p.Changes() {
		if slices.Contains(resources, c.Resource) {
			t.Fatalf("retained resource in changes: %+v", c)
		}
	}
}

func TestRotationNeverDeletesOrReplacesUsers(t *testing.T) {
	rotation, user := obj(ResourceRotation, "rotation"), obj(ResourceUser, "user")
	participant := obj(ResourceRotationParticipant, "participant")
	edges := []Dependency{
		dep(rotation, participant, RelationshipRotationParticipant, rotation, rotation),
		dep(user, participant, RelationshipParticipantUser, rotation, rotation),
	}
	p := mustPlan(t, inputFor([]Resource{rotation}, edges...))
	if !p.CanProceed() || !p.RequiresConfirmation() || len(p.Targets()) != 1 || len(p.Changes()) != 2 {
		t.Fatalf("unexpected rotation plan: %+v", p)
	}
	assertPreserved(t, p, user)
	if c := findChange(t, p, participant); c.Kind != ChangeDeleted || c.Cause != CauseCascade {
		t.Fatalf("membership, not user, must be removed: %+v", c)
	}
	retained := false
	for _, impact := range p.Impacts() {
		if impact.Affected == user && impact.Change == ChangePreserved {
			retained = true
		}
	}
	if !retained {
		t.Fatal("referenced user must be explicitly described as preserved")
	}
	p = mustPlan(t, inputFor([]Resource{user}, edges...))
	if p.CanProceed() {
		t.Fatal("surviving rotation participant must block user deletion")
	}
	requireCode(t, p.Check(p.ImpactVersion(), true), DeletionBlocked)
	assertPreserved(t, p, participant, rotation)
	for _, c := range p.Changes() {
		if c.Kind == ChangeRelationReplaced {
			t.Fatal("no automatic roster substitution is permitted")
		}
	}
}

func TestPolicyChildrenPreserveReferencedBusinessRoots(t *testing.T) {
	policy, step := obj(ResourceEscalationPolicy, "policy"), obj(ResourceEscalationPolicyStep, "step")
	schedule, rotation, user := obj(ResourceSchedule, "schedule"), obj(ResourceRotation, "rotation"), obj(ResourceUser, "user")
	edges := []Dependency{dep(policy, step, RelationshipPolicyStep, policy, policy)}
	for i, target := range []Resource{schedule, rotation, user} {
		action := obj(ResourceEscalationPolicyAction, string(rune('a'+i)))
		edges = append(edges, dep(step, action, RelationshipStepAction, step, policy),
			dep(policy, action, RelationshipPolicyAction, step, policy),
			dep(target, action, RelationshipActionTarget, step, policy))
	}
	p := mustPlan(t, inputFor([]Resource{policy}, edges...))
	if !p.CanProceed() || len(p.Changes()) != 5 {
		t.Fatalf("expected only policy, step and three actions: %+v", p.Changes())
	}
	assertPreserved(t, p, schedule, rotation, user)
	if !reflect.DeepEqual(p.Targets(), []Resource{policy}) {
		t.Fatal("cascade must not expand explicit target selection")
	}
	for _, c := range p.Changes() {
		if c.Resource.Kind == ResourceEscalationPolicyAction && len(c.Edges) != 2 {
			t.Fatalf("one action change must retain both ownership relationships: %+v", c)
		}
	}
}

func TestBatchCoDeletionRequiresAllSurvivingReferencesResolved(t *testing.T) {
	policy := obj(ResourceEscalationPolicy, "policy")
	one, two := obj(ResourceService, "one"), obj(ResourceService, "two")
	edges := []Dependency{dep(policy, one, RelationshipServicePolicy, Resource{}, Resource{}),
		dep(policy, two, RelationshipServicePolicy, Resource{}, Resource{})}
	p := mustPlan(t, inputFor([]Resource{policy, one}, edges...))
	if p.CanProceed() {
		t.Fatal("one surviving service blocks the entire batch")
	}
	requireCode(t, p.Check(p.ImpactVersion(), true), DeletionBlocked)
	p = mustPlan(t, inputFor([]Resource{two, policy, one}, edges...))
	if !p.CanProceed() || p.RequiresConfirmation() || len(p.Targets()) != 3 || len(p.Changes()) != 3 {
		t.Fatalf("explicit complete co-deletion should clear only internal references: %+v", p)
	}
	if err := p.Check("", false); err != nil {
		t.Fatal(err)
	}
}

func TestExplicitAndCascadeProvenance(t *testing.T) {
	rotation, schedule, user := obj(ResourceRotation, "rotation"), obj(ResourceSchedule, "schedule"), obj(ResourceUser, "user")
	rule := obj(ResourceScheduleRule, "rule")
	participant := obj(ResourceRotationParticipant, "participant")
	edges := []Dependency{
		dep(schedule, rule, RelationshipScheduleRule, schedule, schedule),
		dep(rotation, rule, RelationshipRuleTarget, schedule, schedule),
		dep(rotation, participant, RelationshipRotationParticipant, rotation, rotation),
		dep(user, participant, RelationshipParticipantUser, rotation, rotation),
	}
	p := mustPlan(t, inputFor([]Resource{rotation, schedule, user}, edges...))
	if !p.CanProceed() || len(p.Changes()) != 5 || len(p.Targets()) != 3 {
		t.Fatalf("unexpected co-deletion: %+v", p.Changes())
	}
	for _, root := range []Resource{rotation, schedule, user} {
		if c := findChange(t, p, root); c.Cause != CauseExplicit {
			t.Fatalf("explicit target lost its cause: %+v", c)
		}
	}
	if c := findChange(t, p, rule); c.Cause != CauseCascade || len(c.Edges) != 2 {
		t.Fatalf("actual child should occur once, with two relationship identities: %+v", c)
	}
	// A selected CM is still explicit when its selected user also owns it.
	cm := obj(ResourceContactMethod, "cm")
	p = mustPlan(t, inputFor([]Resource{user, cm}, dep(user, cm, RelationshipUserContact, user, user)))
	if len(p.Changes()) != 2 || findChange(t, p, cm).Cause != CauseExplicit {
		t.Fatal("explicit child counted again as cascade")
	}
}

func TestScheduleChildrenAndTemporaryUserReferences(t *testing.T) {
	schedule, user := obj(ResourceSchedule, "schedule"), obj(ResourceUser, "user")
	temporary, shift := obj(ResourceTemporarySchedule, "envelope:0"), obj(ResourceFixedShift, "envelope:0:shift:0")
	owned := dep(schedule, temporary, RelationshipScheduleTemporary, schedule, schedule)
	owned.State.Period = PeriodActive
	child := dep(temporary, shift, RelationshipTemporaryShift, temporary, schedule)
	child.State.Period = PeriodActive
	reference := dep(user, shift, RelationshipShiftUser, temporary, schedule)
	reference.State.Period = PeriodActive
	p := mustPlan(t, inputFor([]Resource{schedule}, owned, child, reference))
	if !p.CanProceed() || len(p.Changes()) != 3 {
		t.Fatal("schedule should remove only its temporary configuration")
	}
	assertPreserved(t, p, user)
	p = mustPlan(t, inputFor([]Resource{user}, owned, child, reference))
	if p.CanProceed() {
		t.Fatal("active JSON user reference must block")
	}
	assertPreserved(t, p, schedule, temporary, shift)
	reference.State.Period = PeriodEnded
	p = mustPlan(t, inputFor([]Resource{user}, reference))
	if !p.CanProceed() || p.RequiresConfirmation() {
		t.Fatal("historical JSON stays; informational impact requires no extra confirmation")
	}
	assertPreserved(t, p, shift, schedule)
}

func TestOneOverrideTwoEndpointsKeepsBothRelations(t *testing.T) {
	user, schedule, override := obj(ResourceUser, "user"), obj(ResourceSchedule, "schedule"), obj(ResourceUserOverride, "override")
	add := dep(user, override, RelationshipOverrideAddUser, schedule, schedule)
	add.State.Period = PeriodEnded
	remove := add
	remove.Relationship = RelationshipOverrideRemoveUser
	p := mustPlan(t, inputFor([]Resource{user}, add, remove, add))
	if c := findChange(t, p, override); len(c.Edges) != 2 || len(p.Changes()) != 2 {
		t.Fatalf("deduplication lost endpoint identity or counted object twice: %+v", c)
	}
	if len(p.Impacts()) != 4 { // Two direct and two derived surviving-Schedule impacts.
		t.Fatalf("expected each actual endpoint plus its derived impact, got %d", len(p.Impacts()))
	}
}

func TestConfirmationAndStaleVersionGates(t *testing.T) {
	key, service := obj(ResourceIntegrationKey, "safe-audit-id"), obj(ResourceService, "service")
	p := mustPlan(t, inputFor([]Resource{key}, dep(key, service, RelationshipIntegrationSource, Resource{}, Resource{})))
	if !p.CanProceed() || !p.RequiresConfirmation() {
		t.Fatal("warning permits a confirmed operation")
	}
	requireCode(t, p.Check("", false), DeletionConfirmationRequired)
	requireCode(t, p.Check("", true), DeletionConfirmationRequired)
	requireCode(t, p.Check(p.ImpactVersion(), false), DeletionConfirmationRequired)
	requireCode(t, p.Check("stale", true), DeletionDependencyChanged)
	if err := p.Check(p.ImpactVersion(), true); err != nil {
		t.Fatal(err)
	}
	var zero DeletionPlan
	if zero.CanProceed() {
		t.Fatal("zero plan is unavailable")
	}
	requireCode(t, zero.Check("", true), DeletionUnavailable)
}

func TestIncompleteIsNotEmptyAndAllRemovedObjectsNeedCoverage(t *testing.T) {
	rotation := obj(ResourceRotation, "rotation")
	empty := inputFor([]Resource{rotation})
	if !mustPlan(t, empty).CanProceed() {
		t.Fatal("known complete empty scan should be allowed")
	}
	for _, state := range []DependencyCompleteness{DependenciesUnknown, DependenciesIncomplete, DependenciesUnsupported, DependencyCompleteness(255)} {
		input := empty
		input.Collection.Completeness = state
		p, err := BuildPlan(input, Budget{})
		requireCode(t, err, DeletionUnavailable)
		if p.CanProceed() || p.ImpactVersion() != "" {
			t.Fatal("incomplete data produced a usable preview")
		}
	}
	input := empty
	input.Collection.Checked = nil
	_, err := BuildPlan(input, Budget{})
	requireCode(t, err, DeletionUnavailable)
	participant := obj(ResourceRotationParticipant, "participant")
	input = inputFor([]Resource{rotation}, dep(rotation, participant, RelationshipRotationParticipant, rotation, rotation))
	input.Collection.Checked = []Resource{rotation}
	_, err = BuildPlan(input, Budget{})
	requireCode(t, err, DeletionUnavailable)
	// A complete claim with a missing ownership row must not be used to erase
	// a participant blocker just because its parent is explicitly selected.
	user := obj(ResourceUser, "user")
	input = inputFor([]Resource{rotation, user}, dep(user, participant, RelationshipParticipantUser, rotation, rotation))
	_, err = BuildPlan(input, Budget{})
	requireCode(t, err, DeletionUnavailable)
}

func TestRawValidationSurvivesDeduplication(t *testing.T) {
	rotation, participant := obj(ResourceRotation, "rotation"), obj(ResourceRotationParticipant, "participant")
	d := dep(rotation, participant, RelationshipRotationParticipant, rotation, rotation)
	input := inputFor([]Resource{rotation}, d, d)
	_, err := BuildPlan(input, Budget{MaxTargets: 1, MaxDependencies: 1, MaxImpacts: 10})
	requireCode(t, err, DeletionPreviewLimitExceeded)
	input = inputFor([]Resource{rotation, rotation})
	_, err = BuildPlan(input, Budget{MaxTargets: 1, MaxDependencies: 10, MaxImpacts: 10})
	requireCode(t, err, DeletionPreviewLimitExceeded)
	_, err = BuildPlan(input, Budget{})
	requireCode(t, err, DeletionUnavailable)
	// Same relationship identity, incompatible raw states. Neither input order
	// nor a canonical winner is allowed to hide the conflicting observation.
	conflict := d
	conflict.Before.References = []Resource{obj(ResourceUser, "different-user")}
	for _, edges := range [][]Dependency{{d, conflict}, {conflict, d}} {
		_, err = BuildPlan(inputFor([]Resource{rotation}, edges...), Budget{})
		requireCode(t, err, DeletionUnavailable)
	}
	d.Relationship = RelationshipUnknown
	_, err = BuildPlan(inputFor([]Resource{rotation}, d), Budget{})
	requireCode(t, err, DeletionUnavailable)
	d = dep(rotation, participant, RelationshipRotationParticipant, rotation, rotation)
	_, err = BuildPlan(inputFor([]Resource{rotation}, d), Budget{MaxTargets: 1, MaxDependencies: 10, MaxImpacts: 1})
	requireCode(t, err, DeletionPreviewLimitExceeded)
}

func TestPlanDoesNotOwnCallerMemory(t *testing.T) {
	rotation := obj(ResourceRotation, "rotation")
	position := 1
	input := inputFor([]Resource{rotation})
	input.Intent[0].Before = Configuration{Position: &position, References: []Resource{obj(ResourceUser, "user")}}
	p := mustPlan(t, input)
	version := p.ImpactVersion()
	position = 9
	input.Intent[0].Before.References[0].ID = "changed"
	input.Targets[0].ID = "changed"
	changes, targets := p.Changes(), p.Targets()
	*changes[0].Before.Position = 100
	changes[0].Before.References[0].ID = "changed-again"
	targets[0].ID = "changed-again"
	if p.ImpactVersion() != version || impactVersion(p, PolicyVersion) != version || p.Targets()[0] != rotation || *p.Changes()[0].Before.Position != 1 {
		t.Fatal("input or output mutation changed a frozen domain plan")
	}
}

func TestConcurrentPlanAccessAndEvaluation(t *testing.T) {
	rotation, participant := obj(ResourceRotation, "rotation"), obj(ResourceRotationParticipant, "participant")
	d := dep(rotation, participant, RelationshipRotationParticipant, rotation, rotation)
	position := 1
	d.Before.Position, d.Before.References = &position, []Resource{obj(ResourceUser, "user")}
	input := inputFor([]Resource{rotation}, d)
	p := mustPlan(t, input)
	for range 8 {
		t.Run("concurrent defensive copies", func(t *testing.T) {
			t.Parallel()
			for range 20 {
				fresh := mustPlan(t, input)
				if fresh.ImpactVersion() != p.ImpactVersion() {
					t.Fatal("shared pure input produced a different version")
				}
				copy := p.Impacts()
				*copy[0].Before.Position = 9
				copy[0].Before.References[0].ID = "changed"
				if err := p.Check(p.ImpactVersion(), true); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}
