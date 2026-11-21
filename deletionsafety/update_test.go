package deletionsafety

import (
	"testing"
	"time"
)

func TestUpdateIntentsPreserveParentsAndTargets(t *testing.T) {
	policy, step := obj(ResourceEscalationPolicy, "policy"), obj(ResourceEscalationPolicyStep, "step")
	action, schedule := obj(ResourceEscalationPolicyAction, "action"), obj(ResourceSchedule, "schedule")
	rotation, user := obj(ResourceRotation, "rotation"), obj(ResourceUser, "user")
	for _, tc := range []struct {
		name   string
		op     Operation
		target Resource
		kind   DeletionChangeKind
		edges  []Dependency
	}{
		{"step", OperationUpdateEscalationPolicy, step, ChangeDeleted, []Dependency{
			dep(step, policy, RelationshipStepRouting, Resource{}, Resource{}),
			dep(step, action, RelationshipStepAction, step, policy),
			dep(schedule, action, RelationshipActionTarget, step, policy),
		}},
		{"action", OperationUpdateEscalationPolicyStep, action, ChangeDeleted, []Dependency{
			dep(action, step, RelationshipRemovedAction, policy, policy),
			dep(schedule, action, RelationshipActionTarget, step, policy),
		}},
		{"schedule rule", OperationUpdateScheduleTarget, obj(ResourceScheduleRule, "rule"), ChangeDeleted, []Dependency{
			dep(obj(ResourceScheduleRule, "rule"), schedule, RelationshipRemovedRule, Resource{}, Resource{}),
			dep(rotation, obj(ResourceScheduleRule, "rule"), RelationshipRuleTarget, schedule, schedule),
		}},
		{"participant replacement", OperationUpdateRotation, obj(ResourceRotationParticipant, "participant"), ChangeRelationReplaced, []Dependency{
			dep(obj(ResourceRotationParticipant, "participant"), rotation, RelationshipRemovedParticipant, Resource{}, Resource{}),
		}},
		{"temporary trim", OperationSetTemporarySchedule, obj(ResourceTemporarySchedule, "envelope:0"), ChangeConfigTrimmed, []Dependency{
			dep(obj(ResourceTemporarySchedule, "envelope:0"), schedule, RelationshipChangedTemporary, Resource{}, Resource{}),
		}},
		{"clear temporary", OperationClearTemporarySchedules, obj(ResourceTemporarySchedule, "envelope:0"), ChangeDeleted, []Dependency{
			dep(obj(ResourceTemporarySchedule, "envelope:0"), schedule, RelationshipChangedTemporary, Resource{}, Resource{}),
		}},
		{"on call rule", OperationSetOnCallNotificationRules, obj(ResourceOnCallNotificationRule, "schedule:1"), ChangeRelationRemoved, []Dependency{
			dep(obj(ResourceOnCallNotificationRule, "schedule:1"), schedule, RelationshipRemovedOnCallRule, Resource{}, Resource{}),
			dep(obj(ResourceOnCallNotificationRule, "schedule:1"), obj(ResourceNotificationChannel, "channel"), RelationshipRetainedChannel, Resource{}, Resource{}),
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input := inputFor([]Resource{tc.target}, tc.edges...)
			input.Operation = tc.op
			input.Intent[0].Kind = tc.kind
			if tc.kind == ChangeRelationReplaced {
				input.Intent[0].Before.References = []Resource{user}
				input.Intent[0].After.References = []Resource{obj(ResourceUser, "replacement")}
			}
			if tc.kind == ChangeConfigTrimmed {
				input.Intent[0].Before.WindowStart = time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
				input.Intent[0].Before.WindowEnd = input.Intent[0].Before.WindowStart.Add(time.Hour)
				input.Intent[0].After.WindowStart = input.Intent[0].Before.WindowStart.Add(time.Minute)
				input.Intent[0].After.WindowEnd = input.Intent[0].Before.WindowEnd
			}
			p := mustPlan(t, input)
			if !p.CanProceed() || !p.RequiresConfirmation() || findChange(t, p, tc.target).Cause != CauseExplicit {
				t.Fatalf("unexpected update plan: %+v", p)
			}
			assertPreserved(t, p, policy, schedule, rotation, user, obj(ResourceNotificationChannel, "channel"))
			input.Collection.Dependencies = nil
			_, err := BuildPlan(input, Budget{})
			requireCode(t, err, DeletionUnavailable)
		})
	}
}

func TestServicePolicyUpdateDependsOnOpenAlertState(t *testing.T) {
	service, policy := obj(ResourceService, "service"), obj(ResourceEscalationPolicy, "policy")
	for _, state := range []AlertState{AlertTriggered, AlertActive, AlertClosed} {
		d := dep(service, policy, RelationshipChangedServicePolicy, Resource{}, Resource{})
		d.State.Alert = state
		input := inputFor([]Resource{service}, d)
		input.Operation = OperationUpdateService
		input.Intent[0].Kind = ChangeRelationReplaced
		input.Intent[0].Before.References = []Resource{policy}
		input.Intent[0].After.References = []Resource{obj(ResourceEscalationPolicy, "replacement")}
		p := mustPlan(t, input)
		if !p.CanProceed() || p.RequiresConfirmation() != (state != AlertClosed) || len(p.Changes()) != 1 {
			t.Fatal("routing update must warn only for open execution state and preserve both policies")
		}
		assertPreserved(t, p, policy, obj(ResourceEscalationPolicy, "replacement"))
	}
}

func TestInvalidIntentsAndBusinessIntervalsFailClosed(t *testing.T) {
	rotation := obj(ResourceRotation, "rotation")
	for _, edit := range []func(*PlanInput){
		func(i *PlanInput) { i.Operation = OperationUnknown },
		func(i *PlanInput) { i.ScopeFingerprint = "client-selected-organization" },
		func(i *PlanInput) { i.Intent = nil },
		func(i *PlanInput) { i.Intent[0].Resource.ID = "unselected" },
		func(i *PlanInput) { i.Intent[0].Kind = ChangePreserved },
		func(i *PlanInput) { i.Intent[0].After.References = []Resource{obj(ResourceUser, "user")} },
		func(i *PlanInput) { i.Intent[0].Before.WindowStart = time.Now() },
		func(i *PlanInput) {
			i.Intent[0].Before.WindowStart = time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)
			i.Intent[0].Before.WindowEnd = i.Intent[0].Before.WindowStart.Add(time.Hour)
		},
		func(i *PlanInput) {
			i.Intent[0].Before.WindowStart = time.Date(9999, 12, 31, 23, 0, 0, 0, time.FixedZone("offset", -3600))
			i.Intent[0].Before.WindowEnd = i.Intent[0].Before.WindowStart.Add(time.Minute)
		},
		func(i *PlanInput) { i.Intent[0].Before.References = []Resource{rotation, rotation} },
	} {
		input := inputFor([]Resource{rotation})
		edit(&input)
		_, err := BuildPlan(input, Budget{})
		requireCode(t, err, DeletionUnavailable)
	}
	// Alert is an effect of an allowed Service deletion, never an extra selector
	// that could bypass its active-alert lifecycle protection.
	_, err := BuildPlan(inputFor([]Resource{obj(ResourceAlert, "123")}), Budget{})
	requireCode(t, err, DeletionUnavailable)
}
