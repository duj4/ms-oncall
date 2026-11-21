package deletionsafety

type policyRule struct {
	targets, references []ResourceKind
	policy              DeletionPolicy
	change              DeletionChangeKind
	affectTarget        bool
	retainedReference   bool
}

func rule(policy DeletionPolicy, change DeletionChangeKind, targets, references []ResourceKind) policyRule {
	return policyRule{targets: targets, references: references, policy: policy, change: change}
}

func kinds(k ...ResourceKind) []ResourceKind { return k }

// Every supported relationship is listed here. Neither FK actions nor caller
// strings can add a cascade rule. Conditional rows are resolved in Evaluate.
var policyRules = map[RelationshipKind]policyRule{
	RelationshipServicePolicy:             rule(PolicyBlock, ChangePreserved, kinds(ResourceEscalationPolicy), kinds(ResourceService)),
	RelationshipPolicyStep:                rule(PolicyCascade, ChangeDeleted, kinds(ResourceEscalationPolicy), kinds(ResourceEscalationPolicyStep)),
	RelationshipPolicyAction:              rule(PolicyCascade, ChangeDeleted, kinds(ResourceEscalationPolicy), kinds(ResourceEscalationPolicyAction)),
	RelationshipStepAction:                rule(PolicyCascade, ChangeDeleted, kinds(ResourceEscalationPolicyStep), kinds(ResourceEscalationPolicyAction)),
	RelationshipStepRouting:               rule(PolicyWarning, ChangeDeleted, kinds(ResourceEscalationPolicyStep), kinds(ResourceEscalationPolicy)),
	RelationshipExecutionState:            rule(PolicyBlock, ChangePreserved, kinds(ResourceEscalationPolicy, ResourceEscalationPolicyStep), kinds(ResourceEscalationPolicyState)),
	RelationshipActionTarget:              rule(PolicyBlock, ChangePreserved, kinds(ResourceSchedule, ResourceRotation, ResourceUser), kinds(ResourceEscalationPolicyAction)),
	RelationshipScheduleRule:              rule(PolicyCascade, ChangeDeleted, kinds(ResourceSchedule), kinds(ResourceScheduleRule)),
	RelationshipRuleTarget:                rule(PolicyBlock, ChangePreserved, kinds(ResourceUser, ResourceRotation), kinds(ResourceScheduleRule)),
	RelationshipScheduleOverride:          rule(PolicyCascade, ChangeDeleted, kinds(ResourceSchedule), kinds(ResourceUserOverride)),
	RelationshipOverrideAddUser:           rule(PolicyBlock, ChangePreserved, kinds(ResourceUser), kinds(ResourceUserOverride)),
	RelationshipOverrideRemoveUser:        rule(PolicyBlock, ChangePreserved, kinds(ResourceUser), kinds(ResourceUserOverride)),
	RelationshipScheduleTemporary:         rule(PolicyCascade, ChangeDeleted, kinds(ResourceSchedule), kinds(ResourceTemporarySchedule)),
	RelationshipScheduleShift:             rule(PolicyCascade, ChangeDeleted, kinds(ResourceSchedule), kinds(ResourceFixedShift)),
	RelationshipTemporaryShift:            rule(PolicyCascade, ChangeDeleted, kinds(ResourceTemporarySchedule), kinds(ResourceFixedShift)),
	RelationshipShiftUser:                 rule(PolicyBlock, ChangePreserved, kinds(ResourceUser), kinds(ResourceFixedShift)),
	RelationshipScheduleOnCallRule:        rule(PolicyCascade, ChangeDeleted, kinds(ResourceSchedule), kinds(ResourceOnCallNotificationRule)),
	RelationshipScheduleHistory:           rule(PolicyWarning, ChangeDeleted, kinds(ResourceSchedule, ResourceUser), kinds(ResourceScheduleHistory)),
	RelationshipEscalationHistory:         rule(PolicyWarning, ChangeDeleted, kinds(ResourceEscalationPolicy, ResourceEscalationPolicyStep, ResourceUser), kinds(ResourceEscalationHistory)),
	RelationshipRotationParticipant:       rule(PolicyCascade, ChangeDeleted, kinds(ResourceRotation), kinds(ResourceRotationParticipant)),
	RelationshipParticipantUser:           rule(PolicyBlock, ChangePreserved, kinds(ResourceUser), kinds(ResourceRotationParticipant)),
	RelationshipRotationState:             rule(PolicyCascade, ChangeDeleted, kinds(ResourceRotation), kinds(ResourceRotationState)),
	RelationshipServiceAlert:              rule(PolicyBlock, ChangePreserved, kinds(ResourceService), kinds(ResourceAlert)),
	RelationshipServiceIntegrationKey:     rule(PolicyCascade, ChangeDeleted, kinds(ResourceService), kinds(ResourceIntegrationKey)),
	RelationshipOutgoingMessage:           rule(PolicyWarning, ChangeDeleted, kinds(ResourceService, ResourceEscalationPolicy, ResourceSchedule, ResourceContactMethod, ResourceUser, ResourceAlert, ResourceNotificationPolicyCycle, ResourceVerificationState), kinds(ResourceOutgoingMessage)),
	RelationshipPendingSignal:             rule(PolicyWarning, ChangeDeleted, kinds(ResourceService, ResourceOutgoingMessage), kinds(ResourcePendingSignal)),
	RelationshipRetainedPolicy:            rule(PolicyInformational, ChangePreserved, kinds(ResourceService), kinds(ResourceEscalationPolicy)),
	RelationshipContactNotificationRule:   rule(PolicyCascade, ChangeDeleted, kinds(ResourceContactMethod), kinds(ResourceNotificationRule)),
	RelationshipStatusContact:             rule(PolicyWarning, ChangeRelationRemoved, kinds(ResourceContactMethod), kinds(ResourceUser)),
	RelationshipContactSubscription:       rule(PolicyCascade, ChangeDeleted, kinds(ResourceContactMethod), kinds(ResourceAlertStatusSubscription)),
	RelationshipImmediateRoute:            rule(PolicyWarning, ChangeRelationRemoved, kinds(ResourceContactMethod), kinds(ResourceUser)),
	RelationshipContactAuthSubject:        rule(PolicyWarning, ChangeDeleted, kinds(ResourceContactMethod), kinds(ResourceAuthSubject)),
	RelationshipVerification:              rule(PolicyInformational, ChangeDeleted, kinds(ResourceContactMethod), kinds(ResourceVerificationState)),
	RelationshipNotificationConfiguration: rule(PolicyInformational, ChangeDeleted, kinds(ResourceNotificationRule), kinds(ResourceUser)),
	RelationshipRetainedContact:           rule(PolicyInformational, ChangePreserved, kinds(ResourceNotificationRule), kinds(ResourceContactMethod)),
	RelationshipIntegrationSource:         rule(PolicyWarning, ChangeDeleted, kinds(ResourceIntegrationKey), kinds(ResourceService)),
	RelationshipIntegrationLog:            rule(PolicyInformational, ChangePreserved, kinds(ResourceIntegrationKey), kinds(ResourceAlertLog)),
	RelationshipOverrideCoverage:          rule(PolicyWarning, ChangeDeleted, kinds(ResourceUserOverride), kinds(ResourceSchedule)),
	RelationshipUserContact:               rule(PolicyCascade, ChangeDeleted, kinds(ResourceUser), kinds(ResourceContactMethod)),
	RelationshipUserNotificationRule:      rule(PolicyCascade, ChangeDeleted, kinds(ResourceUser), kinds(ResourceNotificationRule)),
	RelationshipUserCycle:                 rule(PolicyBlock, ChangePreserved, kinds(ResourceUser), kinds(ResourceNotificationPolicyCycle)),
	RelationshipFavorite:                  rule(PolicyInformational, ChangeDeleted, kinds(ResourceService, ResourceEscalationPolicy, ResourceSchedule, ResourceRotation, ResourceUser), kinds(ResourceFavorite)),
	RelationshipUserOrganization:          rule(PolicyInformational, ChangeDeleted, kinds(ResourceUser), kinds(ResourceOrganizationAssignment)),
	RelationshipUserIdentity:              rule(PolicyWarning, ChangeDeleted, kinds(ResourceUser), kinds(ResourceAuthSubject, ResourceUserSession, ResourceBasicAuthLink)),
	RelationshipKeyCreator:                rule(PolicyInformational, ChangeRelationRemoved, kinds(ResourceUser), kinds(ResourceLegacyKeyAttribution)),
	RelationshipKeyUpdater:                rule(PolicyInformational, ChangeRelationRemoved, kinds(ResourceUser), kinds(ResourceLegacyKeyAttribution)),
	RelationshipKeyDeleter:                rule(PolicyInformational, ChangeRelationRemoved, kinds(ResourceUser), kinds(ResourceLegacyKeyAttribution)),
	RelationshipRemovedAction:             rule(PolicyWarning, ChangeDeleted, kinds(ResourceEscalationPolicyAction), kinds(ResourceEscalationPolicyStep)),
	RelationshipRemovedRule:               rule(PolicyWarning, ChangeDeleted, kinds(ResourceScheduleRule), kinds(ResourceSchedule)),
	RelationshipRemovedParticipant:        rule(PolicyWarning, ChangeRelationRemoved, kinds(ResourceRotationParticipant), kinds(ResourceRotation)),
	RelationshipChangedTemporary:          rule(PolicyWarning, ChangeConfigTrimmed, kinds(ResourceTemporarySchedule, ResourceFixedShift), kinds(ResourceSchedule)),
	RelationshipRemovedOnCallRule:         rule(PolicyWarning, ChangeRelationRemoved, kinds(ResourceOnCallNotificationRule), kinds(ResourceSchedule)),
	RelationshipChangedServicePolicy:      rule(PolicyInformational, ChangeRelationReplaced, kinds(ResourceService), kinds(ResourceEscalationPolicy)),
	RelationshipServiceState:              rule(PolicyInformational, ChangeDeleted, kinds(ResourceService), kinds(ResourceEscalationPolicyState)),
	RelationshipAlertData:                 rule(PolicyInformational, ChangeDeleted, kinds(ResourceAlert), kinds(ResourceAlertData)),
	RelationshipAlertFeedback:             rule(PolicyInformational, ChangeDeleted, kinds(ResourceAlert), kinds(ResourceAlertFeedback)),
	RelationshipAlertMetrics:              rule(PolicyInformational, ChangeDeleted, kinds(ResourceAlert), kinds(ResourceAlertMetrics)),
	RelationshipAlertSubscription:         rule(PolicyCascade, ChangeDeleted, kinds(ResourceAlert), kinds(ResourceAlertStatusSubscription)),
	RelationshipAlertCycle:                rule(PolicyInformational, ChangeDeleted, kinds(ResourceAlert), kinds(ResourceNotificationPolicyCycle)),
	RelationshipAlertState:                rule(PolicyInformational, ChangeDeleted, kinds(ResourceAlert), kinds(ResourceEscalationPolicyState)),
	RelationshipAlertLog:                  rule(PolicyInformational, ChangePreserved, kinds(ResourceAlert), kinds(ResourceAlertLog)),
	RelationshipMessageStatus:             rule(PolicyInformational, ChangeDeleted, kinds(ResourceOutgoingMessage), kinds(ResourceMessageStatusHistory)),
	RelationshipCalendar:                  rule(PolicyInformational, ChangeDeleted, kinds(ResourceSchedule, ResourceUser), kinds(ResourceCalendarSubscription)),
	RelationshipUserLog:                   rule(PolicyInformational, ChangePreserved, kinds(ResourceUser), kinds(ResourceAlertLog)),
	RelationshipRetainedChannel:           rule(PolicyInformational, ChangePreserved, kinds(ResourceEscalationPolicyAction, ResourceOnCallNotificationRule), kinds(ResourceNotificationChannel)),
	RelationshipFavoriteOwner:             rule(PolicyInformational, ChangeDeleted, kinds(ResourceUser), kinds(ResourceFavorite)),
}

func init() {
	for _, rel := range []RelationshipKind{
		RelationshipStepRouting, RelationshipNotificationConfiguration,
		RelationshipIntegrationSource, RelationshipOverrideCoverage,
		RelationshipRemovedAction, RelationshipRemovedRule, RelationshipRemovedParticipant,
		RelationshipChangedTemporary, RelationshipRemovedOnCallRule, RelationshipChangedServicePolicy,
	} {
		r := policyRules[rel]
		r.affectTarget = true
		policyRules[rel] = r
	}
	for _, rel := range []RelationshipKind{
		RelationshipServicePolicy, RelationshipActionTarget, RelationshipRuleTarget,
		RelationshipParticipantUser, RelationshipOverrideAddUser, RelationshipOverrideRemoveUser,
		RelationshipShiftUser,
	} {
		r := policyRules[rel]
		r.retainedReference = true
		policyRules[rel] = r
	}
}

// Evaluate implements only the frozen product rules. Unknown facts or malformed
// relationships return UNAVAILABLE, never an empty/informational classification.
func Evaluate(input EvaluationInput) (Decision, error) {
	d := input.Dependency
	if err := validateDependency(d); err != nil {
		return Decision{}, err
	}
	r := policyRules[d.Relationship]
	p, change := r.policy, r.change
	affected := d.Referencing
	if r.affectTarget {
		affected = d.Target
	}
	closeAlert := false
	switch d.Relationship {
	case RelationshipServiceAlert:
		if d.State.Alert == AlertClosed {
			p, change = PolicyCascade, ChangeDeleted
		} else {
			closeAlert = true
		}
	case RelationshipExecutionState:
		if d.State.Alert == AlertClosed {
			p = PolicyInformational
			change = ChangeRelationRemoved
			if d.Target.Kind == ResourceEscalationPolicy {
				change = ChangeDeleted
			}
		} else {
			closeAlert = true
		}
	case RelationshipUserCycle:
		if d.State.Alert == AlertClosed {
			p, change = PolicyInformational, ChangeDeleted
		} else {
			closeAlert = true
		}
	case RelationshipOverrideAddUser, RelationshipOverrideRemoveUser:
		if d.State.Period == PeriodEnded || input.CoDeletion {
			p, change = PolicyCascade, ChangeDeleted
		}
	case RelationshipShiftUser:
		if input.CoDeletion {
			p, change = PolicyCascade, ChangeDeleted
		} else if d.State.Period == PeriodEnded {
			p, change = PolicyInformational, ChangePreserved
		}
	case RelationshipActionTarget, RelationshipRuleTarget, RelationshipParticipantUser:
		if input.CoDeletion {
			p, change = PolicyCascade, ChangeDeleted
		}
	case RelationshipServicePolicy:
		if input.CoDeletion {
			p, change = PolicyInformational, ChangeRelationRemoved
		}
	case RelationshipOverrideCoverage:
		if d.State.Period == PeriodEnded {
			p = PolicyInformational
		}
	case RelationshipNotificationConfiguration:
		if d.State.NotificationRisk != NotificationRiskNone {
			p = PolicyWarning
		}
	case RelationshipImmediateRoute:
		if d.State.NotificationRisk == NotificationRiskNone {
			p, change = PolicyInformational, ChangePreserved
		}
	case RelationshipChangedServicePolicy:
		if d.State.Alert != AlertClosed {
			p = PolicyWarning
		}
	case RelationshipOutgoingMessage:
		if d.Target.Kind == ResourceVerificationState {
			p = PolicyInformational
		}
	}
	action := ActionNone
	confirm := p == PolicyWarning || p == PolicyCascade
	if confirm {
		action = ActionConfirmImpact
	} else if p == PolicyBlock {
		action = ActionDetachReference
		if closeAlert {
			action = ActionCloseAlert
		}
	}
	return Decision{Policy: p, Change: change, Affected: affected, RequiredAction: action,
		RequiresConfirmation: confirm, CanProceed: p != PolicyBlock}, nil
}
