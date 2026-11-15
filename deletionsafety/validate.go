package deletionsafety

import (
	"slices"
	"strings"
)

func safeID(id string) bool {
	if len(id) == 0 || len(id) > 256 {
		return false
	}
	for _, c := range id {
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("-_:./", c) {
			continue
		}
		return false
	}
	return true
}

func validResource(r Resource) bool {
	return r.Kind > ResourceUnknown && r.Kind < resourceKindEnd && safeID(r.ID)
}

func validConfiguration(c Configuration) bool {
	if c.Position != nil && *c.Position < 0 {
		return false
	}
	if c.WindowStart.IsZero() != c.WindowEnd.IsZero() || !c.WindowStart.IsZero() && !c.WindowStart.Before(c.WindowEnd) {
		return false
	}
	if c.WindowStart.UTC().Year() < 0 || c.WindowStart.UTC().Year() > 9999 || c.WindowEnd.UTC().Year() < 0 || c.WindowEnd.UTC().Year() > 9999 {
		return false
	}
	seen := make(map[Resource]bool)
	for _, ref := range c.References {
		if !validResource(ref) || seen[ref] {
			return false
		}
		seen[ref] = true
	}
	return true
}

func validateDependency(d Dependency) error {
	r, ok := policyRules[d.Relationship]
	if !ok || !validResource(d.Target) || !validResource(d.Referencing) || d.Target == d.Referencing ||
		!slices.Contains(r.targets, d.Target.Kind) || !slices.Contains(r.references, d.Referencing.Kind) ||
		!validConfiguration(d.Before) || !validConfiguration(d.After) || !validOwnership(d) ||
		d.State.Alert > AlertClosed || d.State.Period > PeriodEnded || d.State.NotificationRisk > NotificationRiskBoth {
		return unavailable()
	}
	switch d.Relationship {
	case RelationshipServiceAlert, RelationshipExecutionState, RelationshipUserCycle, RelationshipChangedServicePolicy:
		if d.State.Alert == AlertUnknown {
			return unavailable()
		}
		if (d.Relationship == RelationshipExecutionState || d.Relationship == RelationshipUserCycle ||
			d.Relationship == RelationshipChangedServicePolicy && d.State.Alert != AlertClosed) &&
			!slices.ContainsFunc(d.Before.References, func(r Resource) bool { return r.Kind == ResourceAlert }) {
			return unavailable()
		}
	case RelationshipOverrideAddUser, RelationshipOverrideRemoveUser, RelationshipShiftUser, RelationshipOverrideCoverage,
		RelationshipScheduleOverride, RelationshipScheduleTemporary, RelationshipScheduleShift, RelationshipTemporaryShift:
		if d.State.Period == PeriodUnknown || d.Before.WindowStart.IsZero() {
			return unavailable()
		}
	case RelationshipNotificationConfiguration, RelationshipImmediateRoute:
		if d.State.NotificationRisk == NotificationRiskUnknown {
			return unavailable()
		}
	case RelationshipContactNotificationRule:
		if !d.State.SameOwner {
			return unavailable()
		}
	}
	return nil
}

func validOwnership(d Dependency) bool {
	var parentKind, ownerKind ResourceKind
	switch d.Referencing.Kind {
	case ResourceEscalationPolicyStep:
		parentKind, ownerKind = ResourceEscalationPolicy, ResourceEscalationPolicy
	case ResourceEscalationPolicyAction:
		parentKind, ownerKind = ResourceEscalationPolicyStep, ResourceEscalationPolicy
	case ResourceScheduleRule, ResourceTemporarySchedule, ResourceOnCallNotificationRule, ResourceUserOverride:
		parentKind, ownerKind = ResourceSchedule, ResourceSchedule
	case ResourceFixedShift:
		parentKind, ownerKind = ResourceTemporarySchedule, ResourceSchedule
	case ResourceRotationParticipant:
		parentKind, ownerKind = ResourceRotation, ResourceRotation
	case ResourceNotificationRule, ResourceContactMethod:
		parentKind, ownerKind = ResourceUser, ResourceUser
	case ResourceIntegrationKey:
		parentKind, ownerKind = ResourceService, ResourceService
	default:
		return d.Parent == (Resource{}) && d.Owner == (Resource{})
	}
	if !validResource(d.Parent) || !validResource(d.Owner) || d.Parent.Kind != parentKind || d.Owner.Kind != ownerKind ||
		parentKind == ownerKind && d.Parent != d.Owner {
		return false
	}
	switch d.Relationship {
	case RelationshipPolicyStep, RelationshipPolicyAction, RelationshipScheduleRule, RelationshipScheduleOverride,
		RelationshipScheduleTemporary, RelationshipScheduleShift, RelationshipScheduleOnCallRule,
		RelationshipRotationParticipant, RelationshipServiceIntegrationKey, RelationshipUserContact, RelationshipUserNotificationRule:
		return d.Owner == d.Target
	case RelationshipStepAction, RelationshipTemporaryShift:
		return d.Parent == d.Target
	}
	return true
}

func validIntent(op Operation, c DestructiveChange) bool {
	if !validResource(c.Resource) || !validConfiguration(c.Before) || !validConfiguration(c.After) ||
		c.Kind < ChangeDeleted || c.Kind > ChangeConfigTrimmed {
		return false
	}
	if c.Kind == ChangeDeleted && !emptyConfiguration(c.After) {
		return false
	}
	if op == OperationDeleteResources {
		return c.Kind == ChangeDeleted && slices.Contains([]ResourceKind{ResourceService, ResourceEscalationPolicy, ResourceSchedule,
			ResourceRotation, ResourceContactMethod, ResourceNotificationRule, ResourceIntegrationKey, ResourceUserOverride, ResourceUser}, c.Resource.Kind)
	}
	switch op {
	case OperationUpdateEscalationPolicy:
		return c.Resource.Kind == ResourceEscalationPolicyStep && c.Kind == ChangeDeleted
	case OperationUpdateEscalationPolicyStep:
		return c.Resource.Kind == ResourceEscalationPolicyAction && c.Kind == ChangeDeleted
	case OperationUpdateScheduleTarget:
		return c.Resource.Kind == ResourceScheduleRule && c.Kind == ChangeDeleted
	case OperationUpdateRotation:
		return c.Resource.Kind == ResourceRotationParticipant &&
			(c.Kind == ChangeDeleted || c.Kind == ChangeRelationRemoved || c.Kind == ChangeRelationReplaced && changedConfiguration(c))
	case OperationUpdateService:
		return c.Resource.Kind == ResourceService && c.Kind == ChangeRelationReplaced && changedConfiguration(c)
	case OperationSetTemporarySchedule:
		return (c.Resource.Kind == ResourceTemporarySchedule || c.Resource.Kind == ResourceFixedShift) &&
			(c.Kind == ChangeDeleted || (c.Kind == ChangeRelationReplaced || c.Kind == ChangeConfigTrimmed) && changedConfiguration(c))
	case OperationClearTemporarySchedules:
		return (c.Resource.Kind == ResourceTemporarySchedule || c.Resource.Kind == ResourceFixedShift) &&
			(c.Kind == ChangeDeleted || c.Kind == ChangeConfigTrimmed && changedConfiguration(c))
	case OperationSetOnCallNotificationRules:
		return c.Resource.Kind == ResourceOnCallNotificationRule && (c.Kind == ChangeDeleted || c.Kind == ChangeRelationRemoved)
	default:
		return false
	}
}

func changedConfiguration(c DestructiveChange) bool {
	a, b := canonicalConfiguration(c.Before), canonicalConfiguration(c.After)
	return digest(a) != digest(b)
}

func contextRelationship(op Operation, resource ResourceKind) RelationshipKind {
	switch op {
	case OperationDeleteResources:
		switch resource {
		case ResourceIntegrationKey:
			return RelationshipIntegrationSource
		case ResourceUserOverride:
			return RelationshipOverrideCoverage
		case ResourceNotificationRule:
			return RelationshipNotificationConfiguration
		}
	case OperationUpdateEscalationPolicy:
		return RelationshipStepRouting
	case OperationUpdateEscalationPolicyStep:
		return RelationshipRemovedAction
	case OperationUpdateScheduleTarget:
		return RelationshipRemovedRule
	case OperationUpdateRotation:
		return RelationshipRemovedParticipant
	case OperationUpdateService:
		return RelationshipChangedServicePolicy
	case OperationSetTemporarySchedule, OperationClearTemporarySchedules:
		return RelationshipChangedTemporary
	case OperationSetOnCallNotificationRules:
		return RelationshipRemovedOnCallRule
	}
	return RelationshipUnknown
}

func emptyConfiguration(c Configuration) bool {
	return len(c.References) == 0 && c.Position == nil && c.WindowStart.IsZero() && c.WindowEnd.IsZero()
}
