// Only these reviewed single-root adapters are supported. Keep their backend
// vocabularies separate: a Schedule relationship must not become valid for EP.
export interface DeletionRootProfile {
  readonly previewType: 'ESCALATION_POLICY' | 'SCHEDULE'
  readonly deleteType: 'escalationPolicy' | 'schedule'
  readonly typename: 'EscalationPolicy' | 'Schedule'
  readonly listPath: string
  readonly title: string
  readonly noun: string
  readonly resourceTypes: readonly string[]
  readonly relations: readonly string[]
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
