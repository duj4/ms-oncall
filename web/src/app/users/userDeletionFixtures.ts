import type {
  DeletionImpact,
  DeletionPreview,
  DeletionResource,
} from '../../schema'

export const userID = '10000000-0000-4000-8000-000000000001'
export const userOrganizationID = '20000000-0000-4000-8000-000000000001'
export const userResource = (type = 'USER', id = userID): DeletionResource => ({
  type,
  id,
  name: null,
  label: 'Synthetic ' + type,
  organization: { id: userOrganizationID, name: 'Synthetic organization' },
})
export const userEdgeID = (n: number): string =>
  n.toString(16).padStart(64, '0')
export function userImpact(
  n: number,
  extra: Partial<DeletionImpact> = {},
): DeletionImpact {
  const ref = userResource(
    'USER_SESSION',
    '30000000-0000-4000-8000-000000000001',
  )
  return {
    edgeID: userEdgeID(n),
    target: userResource(),
    referencingResource: ref,
    parent: null,
    owner: null,
    derivedFrom: null,
    affectedResource: ref,
    relation: 'USER_IDENTITY',
    change: 'DELETED',
    policy: 'WARNING',
    impact: 'The affected resource would be deleted.',
    requiredAction: 'CONFIRM_IMPACT',
    canModifyReference: false,
    isDerived: false,
    isPlannedCoDeletion: true,
    ...extra,
  }
}
export function userPreview(rows: DeletionImpact[] = []): DeletionPreview {
  const blocked = rows.some((r) => r.policy === 'BLOCK')
  return {
    operation: 'DELETE_RESOURCES',
    targets: [userResource()],
    impactVersion: 'synthetic-user-version-1',
    policyVersion: 'deletion-safety-spec1-v2',
    assessedAt: '2026-11-26T02:00:00Z',
    complete: true,
    canProceed: !blocked,
    requiresConfirmation:
      !blocked &&
      rows.some((r) => r.policy === 'WARNING' || r.policy === 'CASCADE'),
    notices: [],
    impacts: {
      edges: rows.map((node) => ({ cursor: 'cursor-' + node.edgeID, node })),
      pageInfo: {
        hasNextPage: false,
        endCursor: rows.length
          ? 'cursor-' + rows[rows.length - 1].edgeID
          : null,
      },
    },
  }
}
// Parent and Owner are deliberately different, with two distinct explanations.
export function userActionPreview(): DeletionPreview {
  const ref = userResource(
    'ESCALATION_POLICY_ACTION',
    '30000000-0000-4000-8000-000000000001',
  )
  const parent = userResource(
    'ESCALATION_POLICY_STEP',
    '40000000-0000-4000-8000-000000000001',
  )
  const owner = userResource(
    'ESCALATION_POLICY',
    '50000000-0000-4000-8000-000000000001',
  )
  const direct = userImpact(1, {
    relation: 'ACTION_TARGET',
    referencingResource: ref,
    parent,
    owner,
    affectedResource: ref,
    policy: 'BLOCK',
    change: 'PRESERVED',
    requiredAction: 'DETACH_REFERENCE',
    isPlannedCoDeletion: false,
  })
  return userPreview([
    direct,
    {
      ...direct,
      edgeID: userEdgeID(2),
      isDerived: true,
      derivedFrom: direct.edgeID,
      affectedResource: parent,
      policy: 'INFORMATIONAL',
      requiredAction: 'NONE',
    },
    {
      ...direct,
      edgeID: userEdgeID(3),
      isDerived: true,
      derivedFrom: direct.edgeID,
      affectedResource: owner,
      policy: 'INFORMATIONAL',
      requiredAction: 'NONE',
    },
  ])
}
export function userOwnedPreview(): DeletionPreview {
  const root = userResource()
  const cm = userResource(
    'CONTACT_METHOD',
    '60000000-0000-4000-8000-000000000001',
  )
  const rule = userResource(
    'NOTIFICATION_RULE',
    '70000000-0000-4000-8000-000000000001',
  )
  return userPreview([
    userImpact(10, {
      relation: 'USER_CONTACT',
      referencingResource: cm,
      parent: root,
      owner: root,
      affectedResource: cm,
      policy: 'CASCADE',
    }),
    userImpact(11, {
      relation: 'USER_NOTIFICATION_RULE',
      referencingResource: rule,
      parent: root,
      owner: root,
      affectedResource: rule,
      policy: 'CASCADE',
    }),
    userImpact(12, {
      relation: 'CONTACT_NOTIFICATION_RULE',
      target: cm,
      referencingResource: rule,
      parent: root,
      owner: root,
      affectedResource: rule,
      policy: 'CASCADE',
    }),
    userImpact(13, {
      relation: 'NOTIFICATION_CONFIGURATION',
      target: rule,
      referencingResource: root,
      affectedResource: rule,
    }),
    userImpact(14, {
      relation: 'RETAINED_CONTACT',
      target: rule,
      referencingResource: cm,
      parent: root,
      owner: root,
      affectedResource: cm,
      policy: 'INFORMATIONAL',
      change: 'PRESERVED',
      requiredAction: 'NONE',
    }),
    userImpact(15),
    userImpact(16, {
      relation: 'USER_LOG',
      referencingResource: userResource('ALERT_LOG', '42'),
      affectedResource: userResource('ALERT_LOG', '42'),
      policy: 'INFORMATIONAL',
      change: 'PRESERVED',
      requiredAction: 'NONE',
      isPlannedCoDeletion: false,
    }),
  ])
}
