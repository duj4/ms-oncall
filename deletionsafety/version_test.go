package deletionsafety

import (
	"encoding/json"
	"math/rand"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestCanonicalVersionIgnoresSetOrderingAndExactDuplicateEdges(t *testing.T) {
	rotation, schedule := obj(ResourceRotation, "rotation"), obj(ResourceSchedule, "schedule")
	participant := obj(ResourceRotationParticipant, "participant")
	edge := dep(rotation, participant, RelationshipRotationParticipant, rotation, rotation)
	edge.Before.References = []Resource{obj(ResourceUser, "one"), obj(ResourceUser, "two")}
	start := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	edge.Before.WindowStart, edge.Before.WindowEnd = start, start.Add(time.Hour)
	other := dep(schedule, obj(ResourceScheduleRule, "rule"), RelationshipScheduleRule, schedule, schedule)
	input := inputFor([]Resource{rotation, schedule}, edge, other)
	want := mustPlan(t, input).ImpactVersion()
	rng := rand.New(rand.NewSource(42))
	for range 60 {
		reordered := inputFor([]Resource{rotation, schedule}, edge, other, edge)
		rng.Shuffle(len(reordered.Targets), func(i, j int) {
			reordered.Targets[i], reordered.Targets[j] = reordered.Targets[j], reordered.Targets[i]
		})
		rng.Shuffle(len(reordered.Intent), func(i, j int) { reordered.Intent[i], reordered.Intent[j] = reordered.Intent[j], reordered.Intent[i] })
		rng.Shuffle(len(reordered.Collection.Checked), func(i, j int) {
			reordered.Collection.Checked[i], reordered.Collection.Checked[j] = reordered.Collection.Checked[j], reordered.Collection.Checked[i]
		})
		rng.Shuffle(len(reordered.Collection.Dependencies), func(i, j int) {
			reordered.Collection.Dependencies[i], reordered.Collection.Dependencies[j] = reordered.Collection.Dependencies[j], reordered.Collection.Dependencies[i]
		})
		for i := range reordered.Collection.Dependencies {
			d := &reordered.Collection.Dependencies[i]
			d.Before.References = slices.Clone(d.Before.References)
			slices.Reverse(d.Before.References)
			d.Before.WindowStart = d.Before.WindowStart.In(time.FixedZone("business-zone", 8*3600))
			d.Before.WindowEnd = d.Before.WindowEnd.In(time.FixedZone("business-zone", 8*3600))
		}
		if got := mustPlan(t, reordered).ImpactVersion(); got != want {
			t.Fatalf("same set semantics yielded a different version: %s != %s", got, want)
		}
	}
}

func TestVersionBindsExactObjectsScopePolicyIntentAndBeforeAfter(t *testing.T) {
	rotation, participant := obj(ResourceRotation, "rotation"), obj(ResourceRotationParticipant, "participant")
	edge := dep(rotation, participant, RelationshipRotationParticipant, rotation, rotation)
	edge.Before.References = []Resource{obj(ResourceUser, "original")}
	base := inputFor([]Resource{rotation}, edge)
	p := mustPlan(t, base)
	for _, tc := range []struct {
		name string
		edit func(*PlanInput)
	}{
		{"referencing row replaced with same count", func(i *PlanInput) {
			i.Collection.Dependencies[0].Referencing.ID = "replacement"
			i.Collection.Checked = append(i.Collection.Checked, obj(ResourceRotationParticipant, "replacement"))
		}},
		{"referenced user replaced with same count", func(i *PlanInput) {
			i.Collection.Dependencies[0].Before.References = []Resource{obj(ResourceUser, "replacement")}
		}},
		{"scope changed", func(i *PlanInput) { i.ScopeFingerprint = strings.Repeat("b", 64) }},
		{"destructive intent changed", func(i *PlanInput) { i.Intent[0].Before.References = []Resource{obj(ResourceUser, "replacement")} }},
		{"position changed", func(i *PlanInput) {
			position := 2
			i.Collection.Dependencies[0].Before.Position = &position
		}},
		{"business interval changed", func(i *PlanInput) {
			i.Collection.Dependencies[0].Before.WindowStart = time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
			i.Collection.Dependencies[0].Before.WindowEnd = time.Date(2026, 11, 2, 0, 0, 0, 0, time.UTC)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			changed := inputFor([]Resource{rotation}, edge)
			tc.edit(&changed)
			if got := mustPlan(t, changed).ImpactVersion(); got == p.ImpactVersion() {
				t.Fatal("safety semantics changed without version change")
			}
		})
	}
	if impactVersion(p, "next-policy-version") == p.ImpactVersion() {
		t.Fatal("policy version was not bound")
	}
	manifest := manifest(p, PolicyVersion)
	before := digest(manifest)
	manifest.Input.Operation = OperationUpdateRotation
	if digest(manifest) == before {
		t.Fatal("operation was not bound")
	}
	if impactVersion(p, PolicyVersion) != p.ImpactVersion() {
		t.Fatal("reading the manifest changed the plan")
	}
}

func TestVersionIncludesPolicyConfirmationAndRelationEndpointIdentity(t *testing.T) {
	user, rule := obj(ResourceUser, "user"), obj(ResourceNotificationRule, "rule")
	d := dep(rule, user, RelationshipNotificationConfiguration, Resource{}, Resource{})
	d.State.NotificationRisk = NotificationRiskNone
	info := mustPlan(t, inputFor([]Resource{rule}, d))
	d.State.NotificationRisk = NotificationRiskLastImmediateRoute
	warning := mustPlan(t, inputFor([]Resource{rule}, d))
	if info.RequiresConfirmation() || !warning.RequiresConfirmation() || info.ImpactVersion() == warning.ImpactVersion() {
		t.Fatal("notification classification/confirmation changed without a version change")
	}
	schedule, override := obj(ResourceSchedule, "schedule"), obj(ResourceUserOverride, "override")
	d = dep(user, override, RelationshipOverrideAddUser, schedule, schedule)
	d.State.Period = PeriodEnded
	add := mustPlan(t, inputFor([]Resource{user}, d))
	d.Relationship = RelationshipOverrideRemoveUser
	remove := mustPlan(t, inputFor([]Resource{user}, d))
	if add.ImpactVersion() == remove.ImpactVersion() {
		t.Fatal("the actual relationship endpoint identity must be included")
	}
	service, alert := obj(ResourceService, "service"), obj(ResourceAlert, "123")
	d = dep(service, alert, RelationshipServiceAlert, Resource{}, Resource{})
	d.State.Alert = AlertClosed
	closed := mustPlan(t, inputFor([]Resource{service}, d))
	d.State.Alert = AlertActive
	active := mustPlan(t, inputFor([]Resource{service}, d))
	if closed.ImpactVersion() == active.ImpactVersion() || active.CanProceed() {
		t.Fatal("closed-to-active transition must invalidate and block")
	}
}

func TestManifestOnlyReceivesSafeProjection(t *testing.T) {
	// A collector may encounter this data, but can pass only Safe to the domain.
	record := struct {
		Safe                                             Dependency
		Credential, Destination, Payload, PrivateSubject string
	}{
		Safe:       dep(obj(ResourceIntegrationKey, "nonsecret-audit-id"), obj(ResourceService, "service"), RelationshipIntegrationSource, Resource{}, Resource{}),
		Credential: "synthetic-credential-do-not-project", Destination: "synthetic@example.invalid",
		Payload: "synthetic-notification-body", PrivateSubject: "synthetic-private-subject",
	}
	p := mustPlan(t, inputFor([]Resource{record.Safe.Target}, record.Safe))
	data, err := json.Marshal(manifest(p, PolicyVersion))
	if err != nil {
		t.Fatal(err)
	}
	for _, private := range []string{record.Credential, record.Destination, record.Payload, record.PrivateSubject} {
		if strings.Contains(string(data), private) {
			t.Fatal("sensitive collector material entered manifest")
		}
	}
	if !strings.Contains(string(data), "nonsecret-audit-id") {
		t.Fatal("manifest must still bind the safe replacement identity")
	}
	invalid := inputFor([]Resource{obj(ResourceIntegrationKey, record.Destination)})
	_, err = BuildPlan(invalid, Budget{})
	requireCode(t, err, DeletionUnavailable)
	if strings.Contains(err.Error(), record.Destination) {
		t.Fatal("raw validation error disclosed its input")
	}
}
