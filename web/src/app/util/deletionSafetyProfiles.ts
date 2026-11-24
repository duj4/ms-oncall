import type { DeletionImpact } from '../../schema'

// Only these reviewed single-root adapters are supported. Keep their backend
// vocabularies separate: a Schedule relationship must not become valid for EP.
export interface DeletionRootProfile {
  readonly previewType:
    | 'ESCALATION_POLICY'
    | 'SCHEDULE'
    | 'ROTATION'
    | 'NOTIFICATION_RULE'
    | 'USER_OVERRIDE'
  readonly deleteType:
    | 'escalationPolicy'
    | 'schedule'
    | 'rotation'
    | 'notificationRule'
    | 'userOverride'
  readonly typename:
    | 'EscalationPolicy'
    | 'Schedule'
    | 'Rotation'
    | 'UserNotificationRule'
    | 'UserOverride'
  readonly additionalTypenames?: readonly string[]
  readonly listPath?: string
  readonly title: string
  readonly noun: string
  readonly resourceTypes: readonly string[]
  readonly relations: readonly string[]
  readonly supportsImpact?: (impact: DeletionImpact, rootID: string) => boolean
}
export const epDeletionProfile: DeletionRootProfile = {
  previewType: 'ESCALATION_POLICY',
  deleteType: 'escalationPolicy',
  typename: 'EscalationPolicy',
  listPath: '/escalation-policies',
  title: 'Delete Escalation Policy',
  noun: 'policy',
  resourceTypes: [
    'ESCALATION_POLICY',
    'ESCALATION_POLICY_STEP',
    'ESCALATION_POLICY_ACTION',
    'SERVICE',
    'ALERT',
    'SCHEDULE',
    'ROTATION',
    'USER',
    'NOTIFICATION_CHANNEL',
    'ESCALATION_POLICY_STATE',
    'ESCALATION_HISTORY',
    'FAVORITE',
    'OUTGOING_MESSAGE',
    'MESSAGE_STATUS_HISTORY',
  ],
  relations: [
    'SERVICE_POLICY',
    'SERVICE_ALERT',
    'POLICY_STEP',
    'POLICY_ACTION',
    'STEP_ACTION',
    'STEP_ROUTING',
    'EXECUTION_STATE',
    'ACTION_TARGET',
    'ESCALATION_HISTORY',
    'OUTGOING_MESSAGE',
    'MESSAGE_STATUS',
    'RETAINED_CHANNEL',
    'FAVORITE',
  ],
}

// Evidence: deletionsafety/postgres/{queries,json}.go, policy.go and
// graphql2/graphqlapp/deletionpreviewnames.go. This is display validation,
// never an alternative to backend policy or native feasibility enforcement.
export const scheduleDeletionProfile: DeletionRootProfile = {
  previewType: 'SCHEDULE',
  deleteType: 'schedule',
  typename: 'Schedule',
  listPath: '/schedules',
  title: 'Delete Schedule',
  noun: 'schedule',
  resourceTypes: [
    'SCHEDULE',
    'SCHEDULE_RULE',
    'ESCALATION_POLICY',
    'ESCALATION_POLICY_STEP',
    'ESCALATION_POLICY_ACTION',
    'ROTATION',
    'USER',
    'USER_OVERRIDE',
    'TEMPORARY_SCHEDULE',
    'FIXED_SHIFT',
    'ON_CALL_NOTIFICATION_RULE',
    'NOTIFICATION_CHANNEL',
    'FAVORITE',
    'CALENDAR_SUBSCRIPTION',
    'SCHEDULE_HISTORY',
    'OUTGOING_MESSAGE',
    'MESSAGE_STATUS_HISTORY',
    'PENDING_SIGNAL',
  ],
  relations: [
    'ACTION_TARGET',
    'SCHEDULE_RULE',
    'RULE_TARGET',
    'SCHEDULE_OVERRIDE',
    'OVERRIDE_ADD_USER',
    'OVERRIDE_REMOVE_USER',
    'SCHEDULE_TEMPORARY',
    'SCHEDULE_SHIFT',
    'TEMPORARY_SHIFT',
    'SHIFT_USER',
    'SCHEDULE_ON_CALL_RULE',
    'RETAINED_CHANNEL',
    'FAVORITE',
    'CALENDAR',
    'SCHEDULE_HISTORY',
    'OUTGOING_MESSAGE',
    'MESSAGE_STATUS',
    'PENDING_SIGNAL',
  ],
}

// Rotation closure: queries.go Rotation/Participant projections and FAVORITE;
// planner.go projects PARTICIPANT_USER as INFORMATIONAL/PRESERVED when its
// owned participant is deleted, retaining the User target. Surviving Action/Rule references remain BLOCK.
export const rotationDeletionProfile: DeletionRootProfile = {
  previewType: 'ROTATION',
  deleteType: 'rotation',
  typename: 'Rotation',
  listPath: '/rotations',
  title: 'Delete Rotation',
  noun: 'rotation',
  resourceTypes: [
    'ROTATION',
    'ROTATION_PARTICIPANT',
    'ROTATION_STATE',
    'USER',
    'SCHEDULE',
    'SCHEDULE_RULE',
    'ESCALATION_POLICY_STEP',
    'ESCALATION_POLICY_ACTION',
    'FAVORITE',
  ],
  relations: [
    'ACTION_TARGET',
    'RULE_TARGET',
    'ROTATION_PARTICIPANT',
    'PARTICIPANT_USER',
    'ROTATION_STATE',
    'FAVORITE',
  ],
}

// queries.go contactProjections(NotificationRule) projects exactly these two
// relations. policy.go affects the rule itself for NOTIFICATION_CONFIGURATION;
// planner.go also explains the retained User parent of RETAINED_CONTACT.
// There is no NotificationRule details/list route: its owner stays on UserDetails.
export const notificationRuleDeletionProfile: DeletionRootProfile = {
  previewType: 'NOTIFICATION_RULE',
  deleteType: 'notificationRule',
  typename: 'UserNotificationRule',
  additionalTypenames: ['UserNotificationRule', 'UserContactMethod', 'User'],
  title: 'Delete Notification Rule',
  noun: 'notification rule',
  resourceTypes: ['NOTIFICATION_RULE', 'USER', 'CONTACT_METHOD'],
  relations: ['NOTIFICATION_CONFIGURATION', 'RETAINED_CONTACT'],
  supportsImpact: (impact, rootID) =>
    impact.target.type === 'NOTIFICATION_RULE' &&
    impact.target.id === rootID &&
    !impact.isPlannedCoDeletion &&
    (impact.relation === 'NOTIFICATION_CONFIGURATION'
      ? impact.referencingResource.type === 'USER' &&
        impact.parent === null &&
        !impact.isDerived &&
        impact.change === 'DELETED' &&
        ((impact.policy === 'INFORMATIONAL' &&
          impact.requiredAction === 'NONE') ||
          (impact.policy === 'WARNING' &&
            impact.requiredAction === 'CONFIRM_IMPACT'))
      : impact.relation === 'RETAINED_CONTACT' &&
        impact.referencingResource.type === 'CONTACT_METHOD' &&
        impact.parent?.type === 'USER' &&
        impact.change === 'PRESERVED' &&
        impact.policy === 'INFORMATIONAL' &&
        impact.requiredAction === 'NONE'),
}

// queries.go(UserOverride), policy.go(affectTarget), and planner.go's
// retainedReference projection: coverage affects the override, while user
// edges keep USER as target and the deleted override as referencingResource.
// Derived rows retain those identities and explain the preserved Schedule.
export const userOverrideDeletionProfile: DeletionRootProfile = {
  previewType: 'USER_OVERRIDE',
  deleteType: 'userOverride',
  typename: 'UserOverride',
  additionalTypenames: ['UserOverride', 'Schedule'],
  title: 'Delete Override',
  noun: 'user override',
  resourceTypes: ['USER_OVERRIDE', 'SCHEDULE', 'USER'],
  relations: ['OVERRIDE_COVERAGE', 'OVERRIDE_ADD_USER', 'OVERRIDE_REMOVE_USER'],
  supportsImpact: (impact, rootID) =>
    impact.relation === 'OVERRIDE_COVERAGE'
      ? impact.target.type === 'USER_OVERRIDE' &&
        impact.target.id === rootID &&
        impact.referencingResource.type === 'SCHEDULE' &&
        impact.parent === null &&
        !impact.isDerived &&
        !impact.isPlannedCoDeletion &&
        impact.change === 'DELETED' &&
        ((impact.policy === 'WARNING' &&
          impact.requiredAction === 'CONFIRM_IMPACT') ||
          (impact.policy === 'INFORMATIONAL' &&
            impact.requiredAction === 'NONE'))
      : ['OVERRIDE_ADD_USER', 'OVERRIDE_REMOVE_USER'].includes(
          impact.relation,
        ) &&
        impact.target.type === 'USER' &&
        impact.referencingResource.type === 'USER_OVERRIDE' &&
        impact.referencingResource.id === rootID &&
        impact.parent?.type === 'SCHEDULE' &&
        impact.isPlannedCoDeletion &&
        impact.change === 'PRESERVED' &&
        impact.policy === 'INFORMATIONAL' &&
        impact.requiredAction === 'NONE',
}
