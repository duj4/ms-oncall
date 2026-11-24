import type {
  DeletionImpact,
  DeletionPreview,
  DeletionResource,
} from '../../schema'

export const userOverrideID = '10000000-0000-4000-8000-000000000001'
export const overrideScheduleID = '20000000-0000-4000-8000-000000000001'
const resource = (type: string, id: string): DeletionResource => ({
  type,
  id,
  name: null,
  label: 'Synthetic ' + type,
  organization: null,
})

// Synthetic GraphQL projections, not backend runtime evidence. Source:
// queries.go(UserOverride + overrides), policy.go(OVERRIDE_COVERAGE),
// planner.go(retainedReference + derived ancestors), deletionpreviewprojection.go.
// Retained User edges have isPlannedCoDeletion=true because their referencing
// Override is removed. That flag does NOT mean the User or Schedule is deleted.
export function userOverridePreview(
  period: 'active' | 'future' | 'ended' = 'ended',
  shape: 'add-only' | 'remove-only' | 'replace' = 'replace',
  id = userOverrideID,
): DeletionPreview {
  const root = resource('USER_OVERRIDE', id)
  const schedule = resource('SCHEDULE', overrideScheduleID)
  const warning = period !== 'ended'
  const coverage: DeletionImpact = {
    edgeID: 'coverage',
    target: root,
    referencingResource: schedule,
    parent: null,
    relation: 'OVERRIDE_COVERAGE',
    change: 'DELETED',
    policy: warning ? 'WARNING' : 'INFORMATIONAL',
    requiredAction: warning ? 'CONFIRM_IMPACT' : 'NONE',
    impact: 'The affected resource would be deleted.',
    canModifyReference: true,
    isDerived: false,
    isPlannedCoDeletion: false,
  }
  const edges: DeletionPreview['impacts']['edges'] = [
    { cursor: 'coverage', node: coverage },
  ]
  for (const side of ['add', 'remove']) {
    if (shape === 'add-only' && side === 'remove') continue
    if (shape === 'remove-only' && side === 'add') continue
    const retained: DeletionImpact = {
      ...coverage,
      edgeID: side,
      target: resource(
        'USER',
        side === 'add'
          ? '30000000-0000-4000-8000-000000000001'
          : '30000000-0000-4000-8000-000000000002',
      ),
      referencingResource: root,
      parent: schedule,
      relation: side === 'add' ? 'OVERRIDE_ADD_USER' : 'OVERRIDE_REMOVE_USER',
      change: 'PRESERVED',
      policy: 'INFORMATIONAL',
      requiredAction: 'NONE',
      impact: 'The affected resource is preserved.',
      isPlannedCoDeletion: true,
    }
    edges.push(
      { cursor: side, node: retained },
      {
        cursor: side + '-schedule',
        node: { ...retained, edgeID: side + '-schedule', isDerived: true },
      },
    )
  }
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
    impacts: {
      edges,
      pageInfo: {
        hasNextPage: false,
        endCursor: edges[edges.length - 1].cursor,
      },
    },
  }
}
