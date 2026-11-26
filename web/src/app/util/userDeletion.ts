import type {
  DeletionImpact,
  DeletionPreview,
  DeletionResource,
} from '../../schema'
import type { DeletionRootProfile } from './deletionSafetyProfiles'
import { isResourceUUID } from './integrationKeyDeletion'

const numericTypes = [
  'AUTH_SUBJECT',
  'BASIC_AUTH_LINK',
  'FAVORITE',
  'SCHEDULE_HISTORY',
  'ESCALATION_HISTORY',
  'ALERT_LOG',
  'ALERT_STATUS_SUBSCRIPTION',
  'PENDING_SIGNAL',
  'MESSAGE_STATUS_HISTORY',
]
const uuidTypes = [
  'USER',
  'CONTACT_METHOD',
  'NOTIFICATION_RULE',
  'USER_SESSION',
  'ORGANIZATION_ASSIGNMENT',
  'LEGACY_KEY_ATTRIBUTION',
  'ESCALATION_POLICY',
  'ESCALATION_POLICY_STEP',
  'ESCALATION_POLICY_ACTION',
  'SCHEDULE',
  'SCHEDULE_RULE',
  'ROTATION',
  'ROTATION_PARTICIPANT',
  'USER_OVERRIDE',
  'NOTIFICATION_POLICY_CYCLE',
  'OUTGOING_MESSAGE',
  'VERIFICATION_STATE',
]
const edgeID = (id: unknown): id is string =>
  typeof id === 'string' && /^[a-f0-9]{64}$/.test(id)
const key = (r: DeletionResource): string => r.type + ':' + r.id
const same = (
  a: DeletionResource | null | undefined,
  b: DeletionResource | null | undefined,
): boolean =>
  a == null || b == null
    ? a === b
    : key(a) === key(b) && a.organization?.id === b.organization?.id

// Identity formats come from postgres/queries.go numericIdentity and json.go.
// Session UUIDs are exclusively the backend's audit_resource_id projection.
function validIdentity(r: DeletionResource): boolean {
  if (!r.organization || !isResourceUUID(r.organization.id)) return false
  if (numericTypes.includes(r.type))
    return (
      /^[1-9][0-9]{0,18}$/.test(r.id) &&
      (r.id.length < 19 || r.id <= '9223372036854775807')
    )
  if (uuidTypes.includes(r.type)) return isResourceUUID(r.id)
  return r.type === 'TEMPORARY_SCHEDULE'
    ? /^schedule-data:[1-9][0-9]*:temporary:(0|[1-9][0-9]*)$/.test(r.id)
    : r.type === 'FIXED_SHIFT' &&
        /^schedule-data:[1-9][0-9]*:temporary:(0|[1-9][0-9]*):shift:(0|[1-9][0-9]*)$/.test(
          r.id,
        )
}

function ownership(d: DeletionImpact, root: DeletionResource): boolean {
  const kinds: Record<string, [string, string]> = {
    ESCALATION_POLICY_ACTION: ['ESCALATION_POLICY_STEP', 'ESCALATION_POLICY'],
    SCHEDULE_RULE: ['SCHEDULE', 'SCHEDULE'],
    ROTATION_PARTICIPANT: ['ROTATION', 'ROTATION'],
    USER_OVERRIDE: ['SCHEDULE', 'SCHEDULE'],
    FIXED_SHIFT: ['TEMPORARY_SCHEDULE', 'SCHEDULE'],
    CONTACT_METHOD: ['USER', 'USER'],
    NOTIFICATION_RULE: ['USER', 'USER'],
  }
  const expected = kinds[d.referencingResource.type]
  if (!expected) return d.parent === null && d.owner === null
  if (d.parent?.type !== expected[0] || d.owner?.type !== expected[1])
    return false
  if (expected[0] === expected[1] && !same(d.parent, d.owner)) return false
  if (expected[1] === 'USER' && !same(d.owner, root)) return false
  return (
    d.referencingResource.type !== 'FIXED_SHIFT' ||
    d.referencingResource.id.startsWith(d.parent.id + ':shift:')
  )
}

// Frozen policy.go/queries.go vocabularies. These are display contracts, not
// authority to execute any effect; Native UNAVAILABLE remains unavailable.
function directShape(d: DeletionImpact, root: DeletionResource): boolean {
  const t = d.target.type
  const r = d.referencingResource.type
  const rootTarget = same(d.target, root)
  const info = d.policy === 'INFORMATIONAL' && d.requiredAction === 'NONE'
  const confirmed = (p: string): boolean =>
    d.policy === p && d.requiredAction === 'CONFIRM_IMPACT'
  const blocked = (action = 'DETACH_REFERENCE'): boolean =>
    d.policy === 'BLOCK' &&
    d.change === 'PRESERVED' &&
    d.requiredAction === action
  const deleted = (p: string): boolean =>
    d.change === 'DELETED' && (p === 'INFORMATIONAL' ? info : confirmed(p))
  if (!ownership(d, root)) return false
  let affected = d.referencingResource
  let shape = false
  switch (d.relation) {
    case 'ACTION_TARGET':
      shape = rootTarget && r === 'ESCALATION_POLICY_ACTION' && blocked()
      break
    case 'RULE_TARGET':
      shape = rootTarget && r === 'SCHEDULE_RULE' && blocked()
      break
    case 'PARTICIPANT_USER':
      shape = rootTarget && r === 'ROTATION_PARTICIPANT' && blocked()
      break
    case 'SHIFT_USER':
      shape =
        rootTarget &&
        r === 'FIXED_SHIFT' &&
        (blocked() || (info && d.change === 'PRESERVED'))
      break
    case 'OVERRIDE_ADD_USER':
    case 'OVERRIDE_REMOVE_USER':
      if (!rootTarget) affected = d.target
      shape =
        t === 'USER' &&
        r === 'USER_OVERRIDE' &&
        (rootTarget
          ? blocked() || deleted('CASCADE')
          : info && d.change === 'PRESERVED')
      break
    case 'OVERRIDE_COVERAGE':
      affected = d.target
      shape =
        t === 'USER_OVERRIDE' &&
        r === 'SCHEDULE' &&
        (deleted('WARNING') || deleted('INFORMATIONAL'))
      break
    case 'USER_CONTACT':
      shape = rootTarget && r === 'CONTACT_METHOD' && deleted('CASCADE')
      break
    case 'USER_NOTIFICATION_RULE':
      shape = rootTarget && r === 'NOTIFICATION_RULE' && deleted('CASCADE')
      break
    case 'USER_CYCLE':
      shape =
        rootTarget &&
        r === 'NOTIFICATION_POLICY_CYCLE' &&
        (blocked('CLOSE_ALERT') || deleted('INFORMATIONAL'))
      break
    case 'USER_ORGANIZATION':
      shape =
        rootTarget &&
        r === 'ORGANIZATION_ASSIGNMENT' &&
        d.referencingResource.id === root.id &&
        deleted('INFORMATIONAL')
      break
    case 'USER_IDENTITY':
      shape =
        rootTarget &&
        ['AUTH_SUBJECT', 'USER_SESSION', 'BASIC_AUTH_LINK'].includes(r) &&
        deleted('WARNING')
      break
    case 'FAVORITE':
    case 'FAVORITE_OWNER':
      shape = rootTarget && r === 'FAVORITE' && deleted('INFORMATIONAL')
      break
    case 'USER_LOG':
      shape =
        rootTarget && r === 'ALERT_LOG' && info && d.change === 'PRESERVED'
      break
    case 'SCHEDULE_HISTORY':
      shape = rootTarget && r === 'SCHEDULE_HISTORY' && deleted('WARNING')
      break
    case 'ESCALATION_HISTORY':
      shape = rootTarget && r === 'ESCALATION_HISTORY' && deleted('WARNING')
      break
    case 'KEY_CREATOR':
    case 'KEY_UPDATER':
    case 'KEY_DELETER':
      shape =
        rootTarget &&
        r === 'LEGACY_KEY_ATTRIBUTION' &&
        info &&
        d.change === 'RELATION_REMOVED'
      break
    case 'CONTACT_NOTIFICATION_RULE':
      shape =
        t === 'CONTACT_METHOD' &&
        r === 'NOTIFICATION_RULE' &&
        deleted('CASCADE')
      break
    case 'STATUS_CONTACT':
      shape =
        t === 'CONTACT_METHOD' &&
        r === 'USER' &&
        confirmed('WARNING') &&
        d.change === 'RELATION_REMOVED'
      break
    case 'IMMEDIATE_ROUTE':
      shape =
        t === 'CONTACT_METHOD' &&
        same(d.referencingResource, root) &&
        ((confirmed('WARNING') && d.change === 'RELATION_REMOVED') ||
          (info && d.change === 'PRESERVED'))
      break
    case 'CONTACT_AUTH_SUBJECT':
      shape =
        t === 'CONTACT_METHOD' && r === 'AUTH_SUBJECT' && deleted('WARNING')
      break
    case 'VERIFICATION':
      shape =
        t === 'CONTACT_METHOD' &&
        r === 'VERIFICATION_STATE' &&
        deleted('INFORMATIONAL')
      break
    case 'CONTACT_SUBSCRIPTION':
      shape =
        t === 'CONTACT_METHOD' &&
        r === 'ALERT_STATUS_SUBSCRIPTION' &&
        deleted('CASCADE')
      break
    case 'NOTIFICATION_CONFIGURATION':
      affected = d.target
      shape =
        t === 'NOTIFICATION_RULE' &&
        same(d.referencingResource, root) &&
        (deleted('INFORMATIONAL') || deleted('WARNING'))
      break
    case 'RETAINED_CONTACT':
      shape =
        t === 'NOTIFICATION_RULE' &&
        r === 'CONTACT_METHOD' &&
        info &&
        d.change === 'PRESERVED'
      break
    case 'OUTGOING_MESSAGE':
      shape =
        (rootTarget ||
          [
            'CONTACT_METHOD',
            'NOTIFICATION_POLICY_CYCLE',
            'VERIFICATION_STATE',
          ].includes(t)) &&
        r === 'OUTGOING_MESSAGE' &&
        deleted(t === 'VERIFICATION_STATE' ? 'INFORMATIONAL' : 'WARNING')
      break
    case 'PENDING_SIGNAL':
      shape =
        t === 'OUTGOING_MESSAGE' && r === 'PENDING_SIGNAL' && deleted('WARNING')
      break
    case 'MESSAGE_STATUS':
      shape =
        t === 'OUTGOING_MESSAGE' &&
        r === 'MESSAGE_STATUS_HISTORY' &&
        deleted('INFORMATIONAL')
      break
  }
  return shape && same(d.affectedResource, affected)
}

export function verifyUserPreview(
  p: DeletionPreview,
  id: string,
  organizationID?: string,
): boolean {
  if (!isResourceUUID(id) || p.targets.length !== 1) return false
  const root = p.targets[0]
  if (
    root.type !== 'USER' ||
    root.id !== id ||
    !validIdentity(root) ||
    (organizationID !== undefined && root.organization!.id !== organizationID)
  )
    return false
  const impacts = p.impacts.edges.map(({ node }) => node)
  const byID = new Map<string, DeletionImpact>()
  const owners = new Map<string, string>()
  for (const d of impacts) {
    if (!edgeID(d.edgeID) || byID.has(d.edgeID)) return false
    byID.set(d.edgeID, d)
    for (const r of [
      d.target,
      d.referencingResource,
      d.parent,
      d.owner,
      d.affectedResource,
    ]) {
      if (
        r != null &&
        (!validIdentity(r) || r.organization!.id !== root.organization!.id)
      )
        return false
    }
    if (!d.affectedResource || d.owner === undefined || d.parent === undefined)
      return false
    const binding = JSON.stringify([
      d.parent && key(d.parent),
      d.owner && key(d.owner),
    ])
    const previous = owners.get(key(d.referencingResource))
    if (previous !== undefined && previous !== binding) return false
    owners.set(key(d.referencingResource), binding)
    if (!d.isDerived && (d.derivedFrom !== null || !directShape(d, root)))
      return false
  }
  const direct = impacts.filter((d) => !d.isDerived)
  const removed = new Set([key(root)])
  // Reconstruct only the visible ownership closure to bind subordinate targets.
  // This is not a deletion plan and is never passed as additional mutation input.
  let changed = true
  while (changed) {
    changed = false
    for (const d of direct) {
      if (
        removed.has(key(d.target)) &&
        d.policy !== 'BLOCK' &&
        d.change === 'DELETED' &&
        same(d.affectedResource, d.referencingResource) &&
        !removed.has(key(d.referencingResource))
      ) {
        removed.add(key(d.referencingResource))
        changed = true
      }
    }
  }
  for (const d of direct) {
    const retainedOverride =
      ['OVERRIDE_ADD_USER', 'OVERRIDE_REMOVE_USER'].includes(d.relation) &&
      d.policy === 'INFORMATIONAL' &&
      d.change === 'PRESERVED' &&
      removed.has(key(d.referencingResource))
    if (
      (!removed.has(key(d.target)) && !retainedOverride) ||
      d.isPlannedCoDeletion !== removed.has(key(d.referencingResource))
    )
      return false
  }
  const explanations = new Set<string>()
  for (const d of impacts.filter((d) => d.isDerived)) {
    if (!edgeID(d.derivedFrom) || d.derivedFrom === d.edgeID) return false
    const cause = byID.get(d.derivedFrom)
    if (
      !cause ||
      cause.isDerived ||
      d.policy !== 'INFORMATIONAL' ||
      d.change !== 'PRESERVED' ||
      d.requiredAction !== 'NONE' ||
      d.isPlannedCoDeletion !== cause.isPlannedCoDeletion ||
      d.canModifyReference !== cause.canModifyReference ||
      d.relation !== cause.relation
    )
      return false
    if (
      !same(d.target, cause.target) ||
      !same(d.referencingResource, cause.referencingResource) ||
      !same(d.parent, cause.parent) ||
      !same(d.owner, cause.owner)
    )
      return false
    const affected = d.affectedResource!
    if (
      (!same(affected, cause.parent) && !same(affected, cause.owner)) ||
      same(affected, cause.target) ||
      same(affected, cause.affectedResource) ||
      removed.has(key(affected))
    )
      return false
    const explanation = cause.edgeID + ':' + key(affected)
    if (explanations.has(explanation)) return false
    explanations.add(explanation)
  }
  for (const d of direct) {
    for (const ancestor of [d.parent, d.owner]) {
      if (
        ancestor &&
        !same(ancestor, d.target) &&
        !same(ancestor, d.affectedResource) &&
        !removed.has(key(ancestor)) &&
        !explanations.has(d.edgeID + ':' + key(ancestor))
      )
        return false
    }
  }
  const blocked = direct.some((d) => d.policy === 'BLOCK')
  const confirmation =
    !blocked && direct.some((d) => ['WARNING', 'CASCADE'].includes(d.policy))
  if (p.canProceed !== !blocked || p.requiresConfirmation !== confirmation)
    return false
  // Match feasibility.go's already frozen User boundary; do not imply that a
  // domain INFO/DELETED closed cycle is executable by the native adapter.
  if (
    !blocked &&
    direct.some(
      (d) =>
        d.change !== 'PRESERVED' &&
        ([
          'NOTIFICATION_POLICY_CYCLE',
          'OUTGOING_MESSAGE',
          'VERIFICATION_STATE',
          'ALERT_STATUS_SUBSCRIPTION',
          'LEGACY_KEY_ATTRIBUTION',
        ].includes(d.affectedResource!.type) ||
          (d.affectedResource!.type === 'USER' &&
            !same(d.affectedResource, root))),
    )
  )
    return false
  return true
}

export const userDeletionProfile: DeletionRootProfile = {
  previewType: 'USER',
  deleteType: 'user',
  typename: 'User',
  listPath: '/users',
  additionalTypenames: ['User', 'UserContactMethod', 'UserNotificationRule'],
  title: 'Delete User',
  noun: 'user',
  resourceTypes: [
    ...uuidTypes,
    ...numericTypes,
    'TEMPORARY_SCHEDULE',
    'FIXED_SHIFT',
  ],
  relations: [
    'ACTION_TARGET',
    'RULE_TARGET',
    'PARTICIPANT_USER',
    'SHIFT_USER',
    'OVERRIDE_ADD_USER',
    'OVERRIDE_REMOVE_USER',
    'OVERRIDE_COVERAGE',
    'USER_CONTACT',
    'USER_NOTIFICATION_RULE',
    'USER_CYCLE',
    'USER_ORGANIZATION',
    'USER_IDENTITY',
    'FAVORITE',
    'FAVORITE_OWNER',
    'USER_LOG',
    'SCHEDULE_HISTORY',
    'ESCALATION_HISTORY',
    'KEY_CREATOR',
    'KEY_UPDATER',
    'KEY_DELETER',
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
  validateResource: validIdentity,
  validatePreview: verifyUserPreview,
}
