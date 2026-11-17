package deletionsafety

import (
	"errors"
	"fmt"
	"testing"
	"time"
)

func obj(kind ResourceKind, id string) Resource { return Resource{Kind: kind, ID: id} }

func dep(target, ref Resource, rel RelationshipKind, parent, owner Resource) Dependency {
	d := Dependency{Target: target, Referencing: ref, Relationship: rel, Parent: parent, Owner: owner}
	switch rel {
	case RelationshipOverrideAddUser, RelationshipOverrideRemoveUser, RelationshipShiftUser, RelationshipOverrideCoverage,
		RelationshipScheduleOverride, RelationshipScheduleTemporary, RelationshipScheduleShift, RelationshipTemporaryShift:
		d.Before.WindowStart = time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
		d.Before.WindowEnd = d.Before.WindowStart.Add(time.Hour)
	case RelationshipRotationState:
		d.Parent, d.Owner = target, target
		position := 0
		d.Before.Position = &position
		d.Before.References = []Resource{obj(ResourceRotationParticipant, "current")}
		d.Before.RotationState = &RotationRuntime{ShiftStart: time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC), Version: 2}
	case RelationshipExecutionState, RelationshipUserCycle, RelationshipChangedServicePolicy:
		d.Before.References = []Resource{obj(ResourceAlert, "related-alert")}
	}
	return d
}

func requireCode(t *testing.T, err error, code ErrorCode) {
	t.Helper()
	var typed *DeletionSafetyError
	if !errors.As(err, &typed) || typed.Code != code {
		t.Fatalf("got %v, want code %s", err, code)
	}
}

func requireDecision(t *testing.T, d Dependency, co bool, policy DeletionPolicy, change DeletionChangeKind) Decision {
	t.Helper()
	got, err := Evaluate(EvaluationInput{Dependency: d, CoDeletion: co})
	if err != nil {
		t.Fatal(err)
	}
	if got.Policy != policy || got.Change != change || got.CanProceed != (policy != PolicyBlock) ||
		got.RequiresConfirmation != (policy == PolicyWarning || policy == PolicyCascade) {
		t.Fatalf("unexpected decision: %+v; want policy=%d change=%d", got, policy, change)
	}
	return got
}

func TestPolicyResourceBoundaries(t *testing.T) {
	policy, step := obj(ResourceEscalationPolicy, "policy"), obj(ResourceEscalationPolicyStep, "step")
	schedule, rotation := obj(ResourceSchedule, "schedule"), obj(ResourceRotation, "rotation")
	user, action := obj(ResourceUser, "user"), obj(ResourceEscalationPolicyAction, "action")
	participant, scheduleRule := obj(ResourceRotationParticipant, "participant"), obj(ResourceScheduleRule, "rule")
	service := obj(ResourceService, "service")
	cases := []struct {
		name string
		d    Dependency
		want DeletionPolicy
	}{
		{"service requires policy", dep(policy, service, RelationshipServicePolicy, Resource{}, Resource{}), PolicyBlock},
		{"policy owns step", dep(policy, step, RelationshipPolicyStep, policy, policy), PolicyCascade},
		{"policy owns action through step", dep(policy, action, RelationshipPolicyAction, step, policy), PolicyCascade},
		{"step owns action", dep(step, action, RelationshipStepAction, step, policy), PolicyCascade},
		{"schedule referenced by action", dep(schedule, action, RelationshipActionTarget, step, policy), PolicyBlock},
		{"rotation referenced by action", dep(rotation, action, RelationshipActionTarget, step, policy), PolicyBlock},
		{"user referenced by action", dep(user, action, RelationshipActionTarget, step, policy), PolicyBlock},
		{"schedule owns rule", dep(schedule, scheduleRule, RelationshipScheduleRule, schedule, schedule), PolicyCascade},
		{"rotation referenced by rule", dep(rotation, scheduleRule, RelationshipRuleTarget, schedule, schedule), PolicyBlock},
		{"user referenced by rule", dep(user, scheduleRule, RelationshipRuleTarget, schedule, schedule), PolicyBlock},
		{"rotation owns participant", dep(rotation, participant, RelationshipRotationParticipant, rotation, rotation), PolicyCascade},
		{"user referenced by participant", dep(user, participant, RelationshipParticipantUser, rotation, rotation), PolicyBlock},
		{"rotation runtime state", dep(rotation, obj(ResourceRotationState, "state"), RelationshipRotationState, rotation, rotation), PolicyCascade},
		{"policy favorite", dep(policy, obj(ResourceFavorite, "favorite"), RelationshipFavorite, Resource{}, Resource{}), PolicyInformational},
		{"service retains policy", dep(service, policy, RelationshipRetainedPolicy, Resource{}, Resource{}), PolicyInformational},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			change := ChangeDeleted
			if tc.want == PolicyBlock || tc.d.Relationship == RelationshipRetainedPolicy {
				change = ChangePreserved
			}
			decision := requireDecision(t, tc.d, false, tc.want, change)
			if decision.Affected == user && tc.d.Target != user {
				t.Fatal("deleting configuration must never delete its referenced user")
			}
		})
	}
}

func TestPeriodDependentPolicies(t *testing.T) {
	user, schedule := obj(ResourceUser, "user"), obj(ResourceSchedule, "schedule")
	override, temporary := obj(ResourceUserOverride, "override"), obj(ResourceTemporarySchedule, "envelope:0")
	shift := obj(ResourceFixedShift, "envelope:0:shift:1")
	for _, period := range []PeriodState{PeriodActive, PeriodFuture, PeriodEnded} {
		for _, rel := range []RelationshipKind{RelationshipOverrideAddUser, RelationshipOverrideRemoveUser, RelationshipShiftUser} {
			t.Run(fmt.Sprintf("period%d/relation%d", period, rel), func(t *testing.T) {
				d := dep(user, override, rel, schedule, schedule)
				if rel == RelationshipShiftUser {
					d = dep(user, shift, rel, temporary, schedule)
				}
				d.State.Period = period
				p, c := PolicyBlock, ChangePreserved
				if period == PeriodEnded {
					p, c = PolicyCascade, ChangeDeleted
					if rel == RelationshipShiftUser {
						p, c = PolicyInformational, ChangePreserved
					}
				}
				requireDecision(t, d, false, p, c)
				requireDecision(t, d, true, PolicyCascade, ChangeDeleted)
			})
		}
		d := dep(override, schedule, RelationshipOverrideCoverage, Resource{}, Resource{})
		d.State.Period = period
		p := PolicyWarning
		if period == PeriodEnded {
			p = PolicyInformational
		}
		requireDecision(t, d, false, p, ChangeDeleted)
		for _, child := range []struct {
			resource Resource
			rel      RelationshipKind
			parent   Resource
		}{
			{override, RelationshipScheduleOverride, schedule},
			{temporary, RelationshipScheduleTemporary, schedule},
			{shift, RelationshipScheduleShift, temporary},
		} {
			d := dep(schedule, child.resource, child.rel, child.parent, schedule)
			d.State.Period = period
			requireDecision(t, d, false, PolicyCascade, ChangeDeleted)
		}
	}
}

func TestOpenAlertsNeverReceiveCoDeletionExemption(t *testing.T) {
	for _, state := range []AlertState{AlertTriggered, AlertActive, AlertClosed} {
		for _, tc := range []struct {
			target ResourceKind
			ref    ResourceKind
			rel    RelationshipKind
		}{
			{ResourceService, ResourceAlert, RelationshipServiceAlert},
			{ResourceEscalationPolicy, ResourceEscalationPolicyState, RelationshipExecutionState},
			{ResourceEscalationPolicyStep, ResourceEscalationPolicyState, RelationshipExecutionState},
			{ResourceUser, ResourceNotificationPolicyCycle, RelationshipUserCycle},
		} {
			d := dep(obj(tc.target, "target"), obj(tc.ref, "runtime"), tc.rel, Resource{}, Resource{})
			d.State.Alert = state
			for _, co := range []bool{false, true} {
				p, c := PolicyBlock, ChangePreserved
				if state == AlertClosed {
					p, c = PolicyInformational, ChangeDeleted
					if tc.rel == RelationshipServiceAlert {
						p = PolicyCascade
					} else if tc.target == ResourceEscalationPolicyStep {
						c = ChangeRelationRemoved
					}
				}
				got := requireDecision(t, d, co, p, c)
				if p == PolicyBlock && got.RequiredAction != ActionCloseAlert {
					t.Fatal("open alert must require close, never force-delete")
				}
			}
		}
	}
}

func TestNotificationAndCredentialConsequences(t *testing.T) {
	user, cm := obj(ResourceUser, "user"), obj(ResourceContactMethod, "safe-cm")
	nr := obj(ResourceNotificationRule, "rule")
	d := dep(cm, nr, RelationshipContactNotificationRule, user, user)
	d.State.SameOwner = true
	requireDecision(t, d, false, PolicyCascade, ChangeDeleted)
	d.State.SameOwner = false
	_, err := Evaluate(EvaluationInput{Dependency: d, CoDeletion: true})
	requireCode(t, err, DeletionUnavailable)
	for _, risk := range []NotificationRisk{NotificationRiskNone, NotificationRiskLastImmediateRoute, NotificationRiskOpenCycle, NotificationRiskBoth} {
		d := dep(nr, user, RelationshipNotificationConfiguration, Resource{}, Resource{})
		d.State.NotificationRisk = risk
		p := PolicyInformational
		if risk != NotificationRiskNone {
			p = PolicyWarning
		}
		requireDecision(t, d, false, p, ChangeDeleted)
	}
	for _, tc := range []struct {
		d      Dependency
		policy DeletionPolicy
		change DeletionChangeKind
	}{
		{dep(cm, user, RelationshipStatusContact, Resource{}, Resource{}), PolicyWarning, ChangeRelationRemoved},
		{dep(cm, obj(ResourceAuthSubject, "safe-internal-id"), RelationshipContactAuthSubject, Resource{}, Resource{}), PolicyWarning, ChangeDeleted},
		{dep(cm, obj(ResourceVerificationState, "safe-state-id"), RelationshipVerification, Resource{}, Resource{}), PolicyInformational, ChangeDeleted},
		{dep(obj(ResourceIntegrationKey, "audit-resource-id"), obj(ResourceService, "service"), RelationshipIntegrationSource, Resource{}, Resource{}), PolicyWarning, ChangeDeleted},
		{dep(user, obj(ResourceUserSession, "safe-internal-id"), RelationshipUserIdentity, Resource{}, Resource{}), PolicyWarning, ChangeDeleted},
	} {
		requireDecision(t, tc.d, false, tc.policy, tc.change)
	}
}

func TestUnknownAndUnsupportedFailClosed(t *testing.T) {
	base := dep(obj(ResourceService, "service"), obj(ResourceAlert, "alert"), RelationshipServiceAlert, Resource{}, Resource{})
	base.State.Alert = AlertClosed
	cases := []Dependency{base, base, base, base, base, base}
	cases[0].Relationship = RelationshipUnknown
	cases[1].Relationship = RelationshipKind(255)
	cases[2].Target.Kind = ResourceKind(255)
	cases[3].State.Alert = AlertUnknown
	cases[4].Referencing.Kind = ResourceUser
	cases[5].Referencing.ID = "private@example.invalid"
	for i, d := range cases {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			_, err := Evaluate(EvaluationInput{Dependency: d, CoDeletion: true})
			requireCode(t, err, DeletionUnavailable)
		})
	}
	// Inventing an owned relationship cannot turn a business root into cascade.
	d := dep(obj(ResourceRotation, "rotation"), obj(ResourceUser, "user"), RelationshipRotationParticipant, Resource{}, Resource{})
	_, err := Evaluate(EvaluationInput{Dependency: d, CoDeletion: true})
	requireCode(t, err, DeletionUnavailable)
}
