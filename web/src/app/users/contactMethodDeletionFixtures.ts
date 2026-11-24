import type {
  DeletionImpact,
  DeletionPreview,
  DeletionResource,
} from '../../schema'

export const contactMethodID = '10000000-0000-4000-8000-000000000001'
export const contactUserID = '20000000-0000-4000-8000-000000000001'
export const contactResource = (
  type: string,
  id: string,
): DeletionResource => ({
  type,
  id,
  name: null,
  label: 'Synthetic ' + type,
  organization: null,
})

// Synthetic wire projection of queries.go/contactProjections, policy.go,
// planner.go and deletionpreviewprojection.go. No database/runtime evidence.
// In particular, derived rows keep target/ref/parent, and co-deletion describes
// ref. RETAINED_CONTACT may classify a reference PRESERVED even when its CM is
// the explicit root. The parent User remains preserved in every scenario.
export function contactMethodPreview(
  risk:
    | 'alternative'
    | 'last-immediate'
    | 'open-cycle'
    | 'both' = 'last-immediate',
  id = contactMethodID,
  ruleCount = 1,
  extras = false,
): DeletionPreview {
  const root = contactResource('CONTACT_METHOD', id)
  const user = contactResource('USER', contactUserID)
  const edges: DeletionPreview['impacts']['edges'] = []
  const warning = risk !== 'alternative'
  const add = (
    edgeID: string,
    target: DeletionResource,
    ref: DeletionResource,
    relation: string,
    policy: DeletionImpact['policy'],
    change: string,
    co: boolean,
    parent: DeletionResource | null = null,
    isDerived = false,
  ): void => {
    edges.push({
      cursor: edgeID,
      node: {
        edgeID,
        target,
        referencingResource: ref,
        parent,
        relation,
        policy,
        change,
        isPlannedCoDeletion: co,
        isDerived,
        requiredAction:
          policy === 'WARNING' || policy === 'CASCADE'
            ? 'CONFIRM_IMPACT'
            : 'NONE',
        canModifyReference: true,
        impact:
          change === 'PRESERVED'
            ? 'The affected resource is preserved.'
            : change === 'DELETED'
              ? 'The affected resource would be deleted.'
              : 'The affected relationship would be removed.',
      },
    })
  }
  add(
    'immediate',
    root,
    user,
    'IMMEDIATE_ROUTE',
    warning ? 'WARNING' : 'INFORMATIONAL',
    warning ? 'RELATION_REMOVED' : 'PRESERVED',
    false,
  )
  for (let i = 0; i < ruleCount; i++) {
    const rule = contactResource(
      'NOTIFICATION_RULE',
      '30000000-0000-4000-8000-' + String(i + 1).padStart(12, '0'),
    )
    add(
      'rule-' + i,
      root,
      rule,
      'CONTACT_NOTIFICATION_RULE',
      'CASCADE',
      'DELETED',
      true,
      user,
    )
    add(
      'rule-user-' + i,
      root,
      rule,
      'CONTACT_NOTIFICATION_RULE',
      'INFORMATIONAL',
      'PRESERVED',
      true,
      user,
      true,
    )
    add(
      'configuration-' + i,
      rule,
      user,
      'NOTIFICATION_CONFIGURATION',
      warning ? 'WARNING' : 'INFORMATIONAL',
      'DELETED',
      false,
    )
    add(
      'contact-' + i,
      rule,
      root,
      'RETAINED_CONTACT',
      'INFORMATIONAL',
      'PRESERVED',
      true,
      user,
    )
    add(
      'contact-user-' + i,
      rule,
      root,
      'RETAINED_CONTACT',
      'INFORMATIONAL',
      'PRESERVED',
      true,
      user,
      true,
    )
  }
  if (extras) {
    const verification = contactResource(
      'VERIFICATION_STATE',
      '40000000-0000-4000-8000-000000000001',
    )
    const message = contactResource('OUTGOING_MESSAGE', '1')
    add(
      'status',
      root,
      user,
      'STATUS_CONTACT',
      'WARNING',
      'RELATION_REMOVED',
      false,
    )
    add(
      'auth',
      root,
      contactResource('AUTH_SUBJECT', '50000000-0000-4000-8000-000000000001'),
      'CONTACT_AUTH_SUBJECT',
      'WARNING',
      'DELETED',
      true,
    )
    add(
      'verification',
      root,
      verification,
      'VERIFICATION',
      'INFORMATIONAL',
      'DELETED',
      true,
    )
    add(
      'subscription',
      root,
      contactResource(
        'ALERT_STATUS_SUBSCRIPTION',
        '60000000-0000-4000-8000-000000000001',
      ),
      'CONTACT_SUBSCRIPTION',
      'CASCADE',
      'DELETED',
      true,
    )
    add(
      'message',
      root,
      message,
      'OUTGOING_MESSAGE',
      'WARNING',
      'DELETED',
      true,
    )
    add(
      'verification-message',
      verification,
      message,
      'OUTGOING_MESSAGE',
      'INFORMATIONAL',
      'DELETED',
      true,
    )
    add(
      'signal',
      message,
      contactResource('PENDING_SIGNAL', '2'),
      'PENDING_SIGNAL',
      'WARNING',
      'DELETED',
      true,
    )
    add(
      'message-status',
      message,
      contactResource('MESSAGE_STATUS_HISTORY', '3'),
      'MESSAGE_STATUS',
      'INFORMATIONAL',
      'DELETED',
      true,
    )
  }
  return {
    operation: 'DELETE_RESOURCES',
    targets: [root],
    impactVersion: 'version-1',
    policyVersion: 'deletion-safety-spec1-v2',
    assessedAt: '2026-11-24T10:00:00Z',
    complete: true,
    canProceed: true,
    requiresConfirmation: warning || ruleCount > 0 || extras,
    notices: [],
    impacts: {
      edges,
      pageInfo: {
        hasNextPage: false,
        endCursor: edges[edges.length - 1]?.cursor ?? null,
      },
    },
  }
}
