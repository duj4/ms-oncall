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
    | 'CONTACT_METHOD'
    | 'SERVICE'
  readonly deleteType:
    | 'escalationPolicy'
    | 'schedule'
    | 'rotation'
    | 'notificationRule'
    | 'userOverride'
    | 'contactMethod'
    | 'service'
  readonly typename:
    | 'EscalationPolicy'
    | 'Schedule'
    | 'Rotation'
    | 'UserNotificationRule'
    | 'UserOverride'
    | 'UserContactMethod'
    | 'Service'
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

// ContactMethod closure: contactProjections plus OutgoingMessage ->
// PendingSignal/MessageStatus and VerificationState -> OutgoingMessage.
// Planner derived rows retain the original edge identities; co-deletion refers
// to referencingResource, never necessarily the displayed target or parent.
export const contactMethodDeletionProfile: DeletionRootProfile = {
  previewType: 'CONTACT_METHOD',
  deleteType: 'contactMethod',
  typename: 'UserContactMethod',
  additionalTypenames: ['UserContactMethod', 'UserNotificationRule', 'User'],
  title: 'Delete Contact Method',
  noun: 'contact method',
  resourceTypes: [
    'CONTACT_METHOD',
    'NOTIFICATION_RULE',
    'USER',
    'AUTH_SUBJECT',
    'VERIFICATION_STATE',
    'ALERT_STATUS_SUBSCRIPTION',
    'OUTGOING_MESSAGE',
    'PENDING_SIGNAL',
    'MESSAGE_STATUS_HISTORY',
  ],
  relations: [
    'CONTACT_NOTIFICATION_RULE',
    'STATUS_CONTACT',
    'IMMEDIATE_ROUTE',
    'CONTACT_AUTH_SUBJECT',
    'VERIFICATION',
    'CONTACT_SUBSCRIPTION',
    'NOTIFICATION_CONFIGURATION',
    'RETAINED_CONTACT',
    'OUTGOING_MESSAGE',
    'PENDING_SIGNAL',
    'MESSAGE_STATUS',
  ],
  supportsImpact: (impact, rootID) => {
    const {
      target,
      referencingResource: ref,
      parent,
      relation,
      isDerived,
      isPlannedCoDeletion: co,
      policy,
      change,
      requiredAction,
    } = impact
    const root = target.type === 'CONTACT_METHOD' && target.id === rootID
    const info = policy === 'INFORMATIONAL' && requiredAction === 'NONE'
    const confirmed = (p: string): boolean =>
      policy === p && requiredAction === 'CONFIRM_IMPACT'
    if (relation === 'CONTACT_NOTIFICATION_RULE')
      return (
        root &&
        ref.type === 'NOTIFICATION_RULE' &&
        parent?.type === 'USER' &&
        co &&
        (isDerived
          ? info && change === 'PRESERVED'
          : confirmed('CASCADE') && change === 'DELETED')
      )
    if (relation === 'RETAINED_CONTACT')
      return (
        target.type === 'NOTIFICATION_RULE' &&
        ref.type === 'CONTACT_METHOD' &&
        ref.id === rootID &&
        parent?.type === 'USER' &&
        co &&
        info &&
        change === 'PRESERVED'
      )
    if (isDerived || parent !== null) return false
    switch (relation) {
      case 'STATUS_CONTACT':
        return (
          root &&
          ref.type === 'USER' &&
          !co &&
          confirmed('WARNING') &&
          change === 'RELATION_REMOVED'
        )
      case 'IMMEDIATE_ROUTE':
        return (
          root &&
          ref.type === 'USER' &&
          !co &&
          ((confirmed('WARNING') && change === 'RELATION_REMOVED') ||
            (info && change === 'PRESERVED'))
        )
      case 'NOTIFICATION_CONFIGURATION':
        return (
          target.type === 'NOTIFICATION_RULE' &&
          ref.type === 'USER' &&
          !co &&
          change === 'DELETED' &&
          (info || confirmed('WARNING'))
        )
      case 'CONTACT_AUTH_SUBJECT':
        return (
          root &&
          ref.type === 'AUTH_SUBJECT' &&
          co &&
          confirmed('WARNING') &&
          change === 'DELETED'
        )
      case 'VERIFICATION':
        return (
          root &&
          ref.type === 'VERIFICATION_STATE' &&
          co &&
          info &&
          change === 'DELETED'
        )
      case 'CONTACT_SUBSCRIPTION':
        return (
          root &&
          ref.type === 'ALERT_STATUS_SUBSCRIPTION' &&
          co &&
          confirmed('CASCADE') &&
          change === 'DELETED'
        )
      case 'OUTGOING_MESSAGE':
        return (
          ref.type === 'OUTGOING_MESSAGE' &&
          co &&
          change === 'DELETED' &&
          ((root && confirmed('WARNING')) ||
            (target.type === 'VERIFICATION_STATE' && info))
        )
      case 'PENDING_SIGNAL':
        return (
          target.type === 'OUTGOING_MESSAGE' &&
          ref.type === 'PENDING_SIGNAL' &&
          co &&
          confirmed('WARNING') &&
          change === 'DELETED'
        )
      case 'MESSAGE_STATUS':
        return (
          target.type === 'OUTGOING_MESSAGE' &&
          ref.type === 'MESSAGE_STATUS_HISTORY' &&
          co &&
          info &&
          change === 'DELETED'
        )
      default:
        return false
    }
  },
}

// Frozen Service closure: postgres/queries.go, policy.go and planner.go.
// The only parent is the deleted Service owning an IntegrationKey. It cannot
// produce a derived ancestor row. IntegrationSource affects its Key target;
// co-deletion always describes the referencing resource, not the target.
export const serviceDeletionProfile: DeletionRootProfile = {
  previewType: 'SERVICE',
  deleteType: 'service',
  typename: 'Service',
  listPath: '/services',
  additionalTypenames: ['Service', 'Alert', 'IntegrationKey'],
  title: 'Delete Service',
  noun: 'service',
  resourceTypes: [
    'SERVICE',
    'ESCALATION_POLICY',
    'ALERT',
    'INTEGRATION_KEY',
    'ESCALATION_POLICY_STATE',
    'FAVORITE',
    'OUTGOING_MESSAGE',
    'PENDING_SIGNAL',
    'MESSAGE_STATUS_HISTORY',
    'ALERT_DATA',
    'ALERT_FEEDBACK',
    'ALERT_METRICS',
    'ALERT_STATUS_SUBSCRIPTION',
    'NOTIFICATION_POLICY_CYCLE',
    'ALERT_LOG',
  ],
  relations: [
    'RETAINED_POLICY',
    'SERVICE_ALERT',
    'SERVICE_INTEGRATION_KEY',
    'SERVICE_STATE',
    'FAVORITE',
    'OUTGOING_MESSAGE',
    'PENDING_SIGNAL',
    'MESSAGE_STATUS',
    'ALERT_DATA',
    'ALERT_FEEDBACK',
    'ALERT_METRICS',
    'ALERT_SUBSCRIPTION',
    'ALERT_CYCLE',
    'ALERT_STATE',
    'ALERT_LOG',
    'INTEGRATION_SOURCE',
    'INTEGRATION_LOG',
  ],
  supportsImpact: (impact, rootID) => {
    const {
      target,
      referencingResource: ref,
      parent,
      relation,
      isDerived,
      isPlannedCoDeletion: co,
      policy,
      change,
      requiredAction,
    } = impact
    if (isDerived) return false
    const root = target.type === 'SERVICE' && target.id === rootID
    const info = policy === 'INFORMATIONAL' && requiredAction === 'NONE'
    const confirmed = (p: string): boolean =>
      policy === p && requiredAction === 'CONFIRM_IMPACT'
    const deleted = (p: string): boolean =>
      co &&
      change === 'DELETED' &&
      (p === 'INFORMATIONAL' ? info : confirmed(p))
    if (relation === 'SERVICE_INTEGRATION_KEY')
      return (
        root &&
        ref.type === 'INTEGRATION_KEY' &&
        parent?.type === 'SERVICE' &&
        parent.id === rootID &&
        deleted('CASCADE')
      )
    if (parent !== null) return false
    switch (relation) {
      case 'RETAINED_POLICY':
        return (
          root &&
          ref.type === 'ESCALATION_POLICY' &&
          !co &&
          info &&
          change === 'PRESERVED'
        )
      case 'SERVICE_ALERT':
        return (
          root &&
          ref.type === 'ALERT' &&
          (deleted('CASCADE') ||
            (!co &&
              policy === 'BLOCK' &&
              change === 'PRESERVED' &&
              requiredAction === 'CLOSE_ALERT'))
        )
      case 'SERVICE_STATE':
        return (
          root &&
          ref.type === 'ESCALATION_POLICY_STATE' &&
          deleted('INFORMATIONAL')
        )
      case 'FAVORITE':
        return root && ref.type === 'FAVORITE' && deleted('INFORMATIONAL')
      case 'INTEGRATION_SOURCE':
        return (
          target.type === 'INTEGRATION_KEY' &&
          ref.type === 'SERVICE' &&
          ref.id === rootID &&
          deleted('WARNING')
        )
      case 'INTEGRATION_LOG':
        return (
          target.type === 'INTEGRATION_KEY' &&
          ref.type === 'ALERT_LOG' &&
          !co &&
          info &&
          change === 'PRESERVED'
        )
      case 'ALERT_LOG':
        return (
          target.type === 'ALERT' &&
          ref.type === 'ALERT_LOG' &&
          !co &&
          info &&
          change === 'PRESERVED'
        )
      case 'ALERT_SUBSCRIPTION':
        return (
          target.type === 'ALERT' &&
          ref.type === 'ALERT_STATUS_SUBSCRIPTION' &&
          deleted('CASCADE')
        )
      case 'ALERT_DATA':
      case 'ALERT_FEEDBACK':
      case 'ALERT_METRICS':
        return (
          target.type === 'ALERT' &&
          ref.type === relation &&
          deleted('INFORMATIONAL')
        )
      case 'ALERT_CYCLE':
        return (
          target.type === 'ALERT' &&
          ref.type === 'NOTIFICATION_POLICY_CYCLE' &&
          deleted('INFORMATIONAL')
        )
      case 'ALERT_STATE':
        return (
          target.type === 'ALERT' &&
          ref.type === 'ESCALATION_POLICY_STATE' &&
          deleted('INFORMATIONAL')
        )
      case 'OUTGOING_MESSAGE':
        return (
          (root ||
            ['ALERT', 'NOTIFICATION_POLICY_CYCLE'].includes(target.type)) &&
          ref.type === 'OUTGOING_MESSAGE' &&
          deleted('WARNING')
        )
      case 'PENDING_SIGNAL':
        return (
          (root || target.type === 'OUTGOING_MESSAGE') &&
          ref.type === 'PENDING_SIGNAL' &&
          deleted('WARNING')
        )
      case 'MESSAGE_STATUS':
        return (
          target.type === 'OUTGOING_MESSAGE' &&
          ref.type === 'MESSAGE_STATUS_HISTORY' &&
          deleted('INFORMATIONAL')
        )
      default:
        return false
    }
  },
}
