import type {
  DeletionPreview,
  DeletionResource,
  DeletionImpact,
} from '../../schema'
import { verifyIntegrationKeyIdentity } from '../util/integrationKeyDeletion'

// Synthetic frontend wire responses, NOT PostgreSQL execution fixtures.
export const legacyID = '10000000-0000-4000-8000-000000000001'
export const auditID = '20000000-0000-4000-8000-000000000001'
export const serviceID = '30000000-0000-4000-8000-000000000001'
export const organizationID = '40000000-0000-4000-8000-000000000001'
export const scopeKey = 'synthetic-current-scope'
export const expectedIdentity = {
  id: legacyID,
  serviceID,
  organizationID,
  scopeKey,
  type: 'generic',
}
export const identityResult = (): {
  data: {
    integrationKey: {
      id: string
      auditResourceID: string
      serviceID: string
      type: string
      name: string
      externalSystemName: string | null
    }
  }
} => ({
  data: {
    integrationKey: {
      id: legacyID,
      auditResourceID: auditID,
      serviceID,
      type: 'generic',
      name: 'Synthetic same name',
      externalSystemName: null as string | null,
    },
  },
})
export const keySelection = (): ReturnType<
  typeof verifyIntegrationKeyIdentity
> => verifyIntegrationKeyIdentity(identityResult(), expectedIdentity)
export function keyPreview(logs = 1): DeletionPreview {
  const resource = (type: string, id: string): DeletionResource => ({
    type,
    id,
    name: null,
    label: 'Synthetic ' + type,
    organization: { id: organizationID, name: 'Synthetic Organization' },
  })
  const root = resource('INTEGRATION_KEY', auditID)
  const nodes: DeletionImpact[] = [
    {
      edgeID: 'source',
      target: root,
      referencingResource: resource('SERVICE', serviceID),
      parent: null,
      relation: 'INTEGRATION_SOURCE',
      change: 'DELETED',
      policy: 'WARNING',
      impact: 'Synthetic key source impact',
      requiredAction: 'CONFIRM_IMPACT',
      canModifyReference: true,
      isDerived: false,
      isPlannedCoDeletion: false,
    },
    ...Array.from(
      { length: logs },
      (_, i): DeletionImpact => ({
        edgeID: 'log-' + i,
        target: root,
        referencingResource: resource('ALERT_LOG', String(i + 1)),
        parent: null,
        relation: 'INTEGRATION_LOG',
        change: 'PRESERVED',
        policy: 'INFORMATIONAL',
        impact: 'Synthetic history preserved',
        requiredAction: 'NONE',
        canModifyReference: false,
        isDerived: false,
        isPlannedCoDeletion: false,
      }),
    ),
  ]
  const edges = nodes.map((node, i) => ({ cursor: 'cursor-' + i, node }))
  return {
    operation: 'DELETE_RESOURCES',
    targets: [root],
    impactVersion: 'synthetic-exact-impact-version',
    policyVersion: 'deletion-safety-spec1-v2',
    assessedAt: '2026-11-25T00:00:00Z',
    complete: true,
    canProceed: true,
    requiresConfirmation: true,
    notices: [],
    impacts: {
      edges,
      pageInfo: {
        endCursor: edges[edges.length - 1].cursor,
        hasNextPage: false,
      },
    },
  }
}
