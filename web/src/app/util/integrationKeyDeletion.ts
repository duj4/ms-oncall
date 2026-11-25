import { gql } from 'urql'
import type { DeletionPreview, DeletionImpact } from '../../schema'

// Deliberately separate from the list query: no credential URL and no per-list
// AuditResourceID resolver cost. The caller must use a current network result.
export const integrationKeyDeletionQuery = gql`
  query IntegrationKeyDeletionIdentity($id: ID!) {
    integrationKey(id: $id) {
      id
      auditResourceID
      serviceID
      type
      name
      externalSystemName
    }
  }
`
export interface IntegrationKeyDeletionRequest {
  readonly serviceID: string
  readonly type: string
}
declare const verifiedIdentity: unique symbol
export interface IntegrationKeyDeletionSelection {
  readonly [verifiedIdentity]: true
  readonly legacyID: string
  readonly auditID: string
  readonly serviceID: string
  readonly type: string
  readonly organizationID: string
  readonly scopeKey: string
  readonly name: string
  readonly externalSystemName: string | null
}
const selections = new WeakSet<object>()
export function isResourceUUID(value: unknown): value is string {
  return (
    typeof value === 'string' &&
    /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(
      value,
    ) &&
    value !== '00000000-0000-0000-0000-000000000000'
  )
}
function isAlertLogID(value: string): boolean {
  return (
    /^[1-9][0-9]{0,18}$/.test(value) &&
    (value.length < 19 || value <= '9223372036854775807')
  )
}
export function verifyIntegrationKeyIdentity(
  result: {
    data?: {
      integrationKey?: {
        id?: unknown
        auditResourceID?: unknown
        serviceID?: unknown
        type?: unknown
        name?: unknown
        externalSystemName?: unknown
      } | null
    } | null
    error?: unknown
    stale?: boolean
    hasNext?: boolean
    fetching?: boolean
  },
  expected: IntegrationKeyDeletionRequest & {
    id: string
    organizationID: string
    scopeKey: string
  },
): IntegrationKeyDeletionSelection {
  const key = result.data?.integrationKey
  if (
    result.error ||
    result.stale ||
    result.hasNext ||
    result.fetching ||
    !key ||
    !isResourceUUID(expected.id) ||
    !isResourceUUID(expected.serviceID) ||
    !isResourceUUID(expected.organizationID) ||
    !expected.scopeKey ||
    key.id !== expected.id ||
    !isResourceUUID(key.auditResourceID) ||
    key.id === key.auditResourceID ||
    key.serviceID !== expected.serviceID ||
    key.type !== expected.type ||
    ![
      'email',
      'generic',
      'grafana',
      'prometheusAlertmanager',
      'site24x7',
      'universal',
    ].includes(expected.type) ||
    typeof key.name !== 'string' ||
    !(
      key.externalSystemName === null ||
      typeof key.externalSystemName === 'string'
    )
  )
    throw new Error('The integration key identity could not be verified.')
  const selection = Object.freeze({
    legacyID: expected.id,
    auditID: key.auditResourceID,
    serviceID: expected.serviceID,
    type: expected.type,
    organizationID: expected.organizationID,
    scopeKey: expected.scopeKey,
    name: key.name,
    externalSystemName: key.externalSystemName,
  }) as IntegrationKeyDeletionSelection
  selections.add(selection)
  return selection
}
export function isVerifiedIntegrationKeySelection(
  value: IntegrationKeyDeletionSelection | undefined,
): value is IntegrationKeyDeletionSelection {
  return !!value && selections.has(value)
}

export function supportsIntegrationKeyImpact(
  node: DeletionImpact,
  rootID: string,
  selection?: IntegrationKeyDeletionSelection,
): boolean {
  if (
    !isVerifiedIntegrationKeySelection(selection) ||
    rootID !== selection.auditID ||
    node.target.type !== 'INTEGRATION_KEY' ||
    node.target.id !== selection.auditID ||
    node.target.organization?.id !== selection.organizationID ||
    node.referencingResource.organization?.id !== selection.organizationID ||
    node.parent !== null ||
    node.isDerived ||
    node.isPlannedCoDeletion
  )
    return false
  return node.relation === 'INTEGRATION_SOURCE'
    ? node.referencingResource.type === 'SERVICE' &&
        node.referencingResource.id === selection.serviceID &&
        node.policy === 'WARNING' &&
        node.change === 'DELETED' &&
        node.requiredAction === 'CONFIRM_IMPACT'
    : node.relation === 'INTEGRATION_LOG' &&
        node.referencingResource.type === 'ALERT_LOG' &&
        isAlertLogID(node.referencingResource.id) &&
        node.policy === 'INFORMATIONAL' &&
        node.change === 'PRESERVED' &&
        node.requiredAction === 'NONE'
}

// Called after ALL pages validate and again immediately before mutation.
// A complete Key plan must explain its one actual owning Service even with no
// history. No arbitrary pair of UUIDs can authorize a dual-identity mutation.
export function verifyIntegrationKeyPreview(
  selection: IntegrationKeyDeletionSelection,
  preview: DeletionPreview,
): boolean {
  if (!isVerifiedIntegrationKeySelection(selection)) return false
  const root = preview.targets[0]
  if (
    preview.targets.length !== 1 ||
    root.type !== 'INTEGRATION_KEY' ||
    root.id !== selection.auditID ||
    root.organization?.id !== selection.organizationID
  )
    return false
  return (
    preview.impacts.edges.every(({ node }) =>
      supportsIntegrationKeyImpact(node, selection.auditID, selection),
    ) &&
    preview.impacts.edges.filter(
      ({ node }) => node.relation === 'INTEGRATION_SOURCE',
    ).length === 1
  )
}
