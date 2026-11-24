import type {
  DeletionImpact,
  DeletionPreview,
  DeletionResource,
} from '../../schema'

export const notificationRuleID = '10000000-0000-4000-8000-000000000001'
export const notificationUserID = '20000000-0000-4000-8000-000000000001'
const resource = (type: string, id: string): DeletionResource => ({
  type,
  id,
  name: null,
  label: 'Synthetic ' + type,
  organization: null,
})

// Synthetic projection, not runtime evidence. Frozen backend evidence:
// queries.go:364-395: another enabled/non-pending immediate rule -> RiskNone;
// last immediate route and/or open cycle -> risk. policy.go:169-172 upgrades
// only NOTIFICATION_CONFIGURATION to WARNING. RETAINED_CONTACT is always
// INFORMATIONAL/PRESERVED. planner.go adds a derived retained User explanation;
// deletionpreviewprojection.go keeps original target/referencingResource.
export function notificationRulePreview(
  risk:
    | 'alternative'
    | 'last-immediate'
    | 'open-cycle'
    | 'both' = 'alternative',
  id = notificationRuleID,
): DeletionPreview {
  const root = resource('NOTIFICATION_RULE', id)
  const user = resource('USER', notificationUserID)
  const contact = resource(
    'CONTACT_METHOD',
    '30000000-0000-4000-8000-000000000001',
  )
  const warning = risk !== 'alternative'
  const base: Omit<DeletionImpact, 'edgeID'> = {
    target: root,
    referencingResource: user,
    parent: null,
    relation: 'NOTIFICATION_CONFIGURATION',
    change: 'DELETED',
    policy: warning ? 'WARNING' : 'INFORMATIONAL',
    requiredAction: warning ? 'CONFIRM_IMPACT' : 'NONE',
    impact: 'The affected resource would be deleted.',
    canModifyReference: true,
    isDerived: false,
    isPlannedCoDeletion: false,
  }
  const edges: DeletionPreview['impacts']['edges'] = [
    { cursor: 'configuration', node: { ...base, edgeID: 'configuration' } },
    {
      cursor: 'contact',
      node: {
        ...base,
        edgeID: 'contact',
        referencingResource: contact,
        parent: user,
        relation: 'RETAINED_CONTACT',
        change: 'PRESERVED',
        policy: 'INFORMATIONAL',
        requiredAction: 'NONE',
        impact: 'The affected resource is preserved.',
      },
    },
  ]
  edges.push({
    cursor: 'user',
    node: { ...edges[1].node, edgeID: 'user', isDerived: true },
  })
  return {
    operation: 'DELETE_RESOURCES',
    targets: [root],
    impactVersion: 'version-1',
    policyVersion: 'deletion-safety-spec1-v2',
    assessedAt: '2026-11-23T10:00:00Z',
    complete: true,
    canProceed: true,
    requiresConfirmation: warning,
    notices: [],
    impacts: { edges, pageInfo: { hasNextPage: false, endCursor: 'user' } },
  }
}
