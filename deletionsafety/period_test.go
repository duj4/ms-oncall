package deletionsafety

import (
	"testing"
	"time"
)

func TestPeriodClassificationBoundaries(t *testing.T) {
	start := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	end := start.Add(time.Hour)
	for _, tc := range []struct {
		asOf time.Time
		want PeriodState
	}{
		{start.Add(-time.Nanosecond), PeriodFuture},
		{start, PeriodActive},
		{end.Add(-time.Nanosecond), PeriodActive},
		{end, PeriodEnded},
		{end.Add(time.Nanosecond), PeriodEnded},
	} {
		got, err := ClassifyPeriod(start, end, tc.asOf.In(time.FixedZone("business-zone", 8*3600)))
		if err != nil || got != tc.want {
			t.Fatalf("classification at %v: %v/%v, want %v", tc.asOf, got, err, tc.want)
		}
	}
	for _, interval := range [][3]time.Time{{{}, end, start}, {start, {}, start}, {start, start, start}, {end, start, start}, {start, end, {}}} {
		_, err := ClassifyPeriod(interval[0], interval[1], interval[2])
		requireCode(t, err, DeletionUnavailable)
	}
}

func TestConditionalFactsNeedSafeIntervalsAndAlertIdentity(t *testing.T) {
	user, schedule := obj(ResourceUser, "user"), obj(ResourceSchedule, "schedule")
	d := dep(user, obj(ResourceUserOverride, "override"), RelationshipOverrideAddUser, schedule, schedule)
	d.State.Period = PeriodEnded
	d.Before = Configuration{}
	_, err := Evaluate(EvaluationInput{Dependency: d})
	requireCode(t, err, DeletionUnavailable)
	d = dep(user, obj(ResourceNotificationPolicyCycle, "cycle"), RelationshipUserCycle, Resource{}, Resource{})
	d.State.Alert = AlertClosed
	d.Before = Configuration{}
	_, err = Evaluate(EvaluationInput{Dependency: d})
	requireCode(t, err, DeletionUnavailable)
	add := dep(user, obj(ResourceUserOverride, "override"), RelationshipOverrideAddUser, schedule, schedule)
	add.State.Period = PeriodEnded
	remove := add
	remove.Relationship, remove.State.Period = RelationshipOverrideRemoveUser, PeriodActive
	_, err = BuildPlan(inputFor([]Resource{user}, add, remove), Budget{})
	requireCode(t, err, DeletionUnavailable)
}

func TestUserOverrideRootFrozenLifecycle(t *testing.T) {
	root, schedule := obj(ResourceUserOverride, "override"), obj(ResourceSchedule, "schedule")
	start := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	end := start.Add(time.Hour)
	for _, tc := range []struct {
		at     time.Time
		period PeriodState
		policy DeletionPolicy
	}{
		{start.Add(-time.Nanosecond), PeriodFuture, PolicyWarning},
		{start, PeriodActive, PolicyWarning},
		{end.Add(-time.Nanosecond), PeriodActive, PolicyWarning},
		{end, PeriodEnded, PolicyInformational},
	} {
		d := dep(root, schedule, RelationshipOverrideCoverage, Resource{}, Resource{})
		d.Before.WindowStart, d.Before.WindowEnd = start, end
		var err error
		d.State.Period, err = ClassifyPeriod(start, end, tc.at)
		if err != nil {
			t.Fatal(err)
		}
		if d.State.Period != tc.period {
			t.Fatalf("period %v", d.State.Period)
		}
		decision, err := Evaluate(EvaluationInput{Dependency: d})
		if err != nil {
			t.Fatal(err)
		}
		if decision.Policy != tc.policy || !decision.CanProceed || decision.Affected != root || decision.RequiresConfirmation != (tc.policy == PolicyWarning) {
			t.Fatalf("unexpected decision: %+v", decision)
		}
	}
}
