import {
  DocumentNode,
  DirectiveNode,
  FragmentDefinitionNode,
  SelectionSetNode,
  getDirectiveValues,
  getOperationAST,
  GraphQLIncludeDirective,
  GraphQLSkipDirective,
  valueFromASTUntyped,
  visit,
} from 'graphql'
import { gql } from 'urql'
import type {
  DeletionImpact,
  DeletionPreview,
  DeletionResource,
} from '../../schema'

export const deletionPreviewQuery = gql`
  query EPDeletionPreview(
    $input: DeletionPlanInput!
    $first: Int!
    $after: String
  ) {
    deletionPreview(input: $input, first: $first, after: $after) {
      operation
      targets {
        ...DeletionIdentity
      }
      impactVersion
      policyVersion
      assessedAt
      complete
      canProceed
      requiresConfirmation
      notices
      impacts {
        edges {
          cursor
          node {
            edgeID
            target {
              ...DeletionIdentity
            }
            referencingResource {
              ...DeletionIdentity
            }
            parent {
              ...DeletionIdentity
            }
            relation
            change
            policy
            impact
            requiredAction
            canModifyReference
            isDerived
            isPlannedCoDeletion
          }
        }
        pageInfo {
          endCursor
          hasNextPage
        }
      }
    }
  }
  fragment DeletionIdentity on DeletionResource {
    type
    id
    name
    label
    organization {
      id
      name
    }
  }
`
export const deletionMutation = gql`
  mutation EPDeleteWithSafety(
    $input: [TargetInput!]!
    $confirmation: DeletionSafetyConfirmationInput!
  ) {
    deleteAll(input: $input, confirmation: $confirmation)
  }
`

export function containsDeleteAll(document: DocumentNode): boolean {
  let found = false
  visit(document, {
    Field(node) {
      if (node.name.value === 'deleteAll') found = true
    },
  })
  return found
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === 'object' && !Array.isArray(value)
}

function onlyKeys(value: Record<string, unknown>, keys: string[]): boolean {
  return Object.keys(value).every(
    (key) => key === '__typename' || keys.includes(key),
  )
}

// Unlike the conservative retry scan, collect only executed root fields of the
// selected mutation. Undefined means execution cannot be determined safely.
function mutationFields(
  document: DocumentNode,
  variables: Record<string, unknown>,
  operationName?: string,
): { deletions: Set<string>; others: Set<string> } | undefined {
  const operation = getOperationAST(document, operationName)
  if (operation?.operation !== 'mutation') return
  const values = { ...variables }
  for (const variable of operation.variableDefinitions || []) {
    const name = variable.variable.name.value
    if (values[name] === undefined && variable.defaultValue)
      values[name] = valueFromASTUntyped(variable.defaultValue)
  }
  const fragments = new Map<string, FragmentDefinitionNode>()
  for (const definition of document.definitions)
    if (definition.kind === 'FragmentDefinition')
      fragments.set(definition.name.value, definition)
  const fields = { deletions: new Set<string>(), others: new Set<string>() }
  const visiting = new Set<string>()
  const included = (node: {
    readonly directives?: readonly DirectiveNode[]
  }): boolean => {
    for (const [directive, excluded] of [
      [GraphQLSkipDirective, true],
      [GraphQLIncludeDirective, false],
    ] as const) {
      const args = getDirectiveValues(directive, node, values)
      if (!args) continue
      if (typeof args.if !== 'boolean')
        throw new Error('Unknown directive value')
      if (args.if === excluded) return false
    }
    return true
  }
  const collect = (selection: SelectionSetNode): void => {
    for (const node of selection.selections) {
      if (!included(node)) continue
      if (node.kind === 'Field') {
        if (node.name.value === '__typename') continue
        const target =
          node.name.value === 'deleteAll' ? fields.deletions : fields.others
        target.add(node.alias?.value || node.name.value)
      } else if (node.kind === 'InlineFragment') {
        if (!node.typeCondition || node.typeCondition.name.value === 'Mutation')
          collect(node.selectionSet)
      } else {
        const name = node.name.value
        const fragment = fragments.get(name)
        if (!fragment || visiting.has(name)) throw new Error('Unknown fragment')
        if (fragment.typeCondition.name.value !== 'Mutation') continue
        visiting.add(name)
        collect(fragment.selectionSet)
        visiting.delete(name)
      }
    }
  }
  try {
    collect(operation.selectionSet)
    return fields
  } catch {
    return undefined
  }
}

export function deletionResponseSucceeded(
  document: DocumentNode,
  data: unknown,
  variables: Record<string, unknown> = {},
  operationName?: string,
): boolean {
  if (!isRecord(data)) return false
  const fields = mutationFields(document, variables, operationName)
  return (
    !!fields?.deletions.size &&
    Array.from(fields.deletions).every((key) => data[key] === true)
  )
}

export function deletionResponseAllowsRefresh(
  document: DocumentNode,
  result: {
    data?: unknown
    error?: SafetyError
    stale?: boolean
    hasNext?: boolean
  },
  variables: Record<string, unknown> = {},
  operationName?: string,
): boolean {
  const fields = mutationFields(document, variables, operationName)
  if (!fields) return false
  // A skipped/unselected Delete did not fail. Preserve the original operation's
  // cache semantics and Apollo's existing no-error rule.
  if (!fields.deletions.size) return true
  if (
    result.stale ||
    result.hasNext ||
    result.error?.networkError ||
    !isRecord(result.data)
  )
    return false
  const data = result.data
  if (
    !result.error &&
    Array.from(fields.deletions).every((key) => data[key] === true)
  )
    return true
  // Stock cacheExchange invalidates at operation granularity. A completed sibling
  // may justify that invalidation; it is never evidence that Delete succeeded.
  return Array.from(fields.others).some(
    (key) =>
      data[key] != null &&
      data[key] !== false &&
      !result.error?.graphQLErrors?.some(
        ({ path }) => !path?.length || path[0] === key,
      ),
  )
}

export type DeletionPhase =
  | 'loading'
  | 'review'
  | 'blocked'
  | 'failed'
  | 'unsupported'
  | 'limit'
  | 'confirming'
  | 'deleting'
  | 'success'
  | 'unknown'
  | 'cancelled'
export interface DeletionState {
  phase: DeletionPhase
  loaded: number
  preview?: DeletionPreview
  message?: string
}
type SafetyError = {
  networkError?: unknown
  graphQLErrors?: ReadonlyArray<{
    extensions?: Record<string, unknown>
    path?: ReadonlyArray<string | number>
  }>
}
export type PreviewResult = {
  data?: { deletionPreview?: unknown } | null
  error?: SafetyError
  stale?: boolean
  hasNext?: boolean
}
export class PreviewFailure extends Error {
  constructor(public phase: 'failed' | 'unsupported' | 'limit' | 'cancelled') {
    super('Deletion preview could not be verified.')
  }
}
const policies = ['BLOCK', 'CASCADE', 'WARNING', 'INFORMATIONAL']
// Verified EP graph vocabulary only; this enables no other Root adapter.
const resourceTypes = [
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
]
const relations = [
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
]
const changes = [
  'DELETED',
  'RELATION_REMOVED',
  'RELATION_REPLACED',
  'CONFIG_TRIMMED',
  'PRESERVED',
]
const actions = ['NONE', 'DETACH_REFERENCE', 'CLOSE_ALERT', 'CONFIRM_IMPACT']
function nonempty(value: unknown): value is string {
  return typeof value === 'string' && value.trim().length > 0
}
function resource(value: unknown): value is DeletionResource {
  if (
    !isRecord(value) ||
    !onlyKeys(value, ['type', 'id', 'name', 'label', 'organization']) ||
    !nonempty(value.id) ||
    !nonempty(value.label) ||
    typeof value.type !== 'string' ||
    !resourceTypes.includes(value.type) ||
    !(value.name === null || typeof value.name === 'string')
  )
    return false
  return (
    value.organization === null ||
    (isRecord(value.organization) &&
      onlyKeys(value.organization, ['id', 'name']) &&
      nonempty(value.organization.id) &&
      typeof value.organization.name === 'string')
  )
}
function validImpact(value: unknown): value is DeletionImpact {
  if (
    !isRecord(value) ||
    !onlyKeys(value, [
      'edgeID',
      'target',
      'referencingResource',
      'parent',
      'relation',
      'change',
      'policy',
      'impact',
      'requiredAction',
      'canModifyReference',
      'isDerived',
      'isPlannedCoDeletion',
    ])
  )
    return false
  return (
    nonempty(value.edgeID) &&
    resource(value.target) &&
    resource(value.referencingResource) &&
    (value.parent === null || resource(value.parent)) &&
    typeof value.relation === 'string' &&
    relations.includes(value.relation) &&
    typeof value.change === 'string' &&
    changes.includes(value.change) &&
    typeof value.policy === 'string' &&
    policies.includes(value.policy) &&
    nonempty(value.impact) &&
    typeof value.requiredAction === 'string' &&
    actions.includes(value.requiredAction) &&
    typeof value.canModifyReference === 'boolean' &&
    typeof value.isDerived === 'boolean' &&
    typeof value.isPlannedCoDeletion === 'boolean'
  )
}
function validatePage(value: unknown, id: string): DeletionPreview {
  if (
    !isRecord(value) ||
    !onlyKeys(value, [
      'operation',
      'targets',
      'impactVersion',
      'policyVersion',
      'assessedAt',
      'complete',
      'canProceed',
      'requiresConfirmation',
      'notices',
      'impacts',
    ]) ||
    value.operation !== 'DELETE_RESOURCES' ||
    value.policyVersion !== 'deletion-safety-spec1-v2' ||
    !nonempty(value.impactVersion) ||
    !nonempty(value.assessedAt) ||
    !Number.isFinite(Date.parse(value.assessedAt)) ||
    value.complete !== true ||
    typeof value.canProceed !== 'boolean' ||
    typeof value.requiresConfirmation !== 'boolean' ||
    !Array.isArray(value.targets) ||
    value.targets.length !== 1 ||
    !resource(value.targets[0]) ||
    value.targets[0].type !== 'ESCALATION_POLICY' ||
    value.targets[0].id !== id ||
    !Array.isArray(value.notices) ||
    !value.notices.every((n) => typeof n === 'string') ||
    !isRecord(value.impacts) ||
    !onlyKeys(value.impacts, ['edges', 'pageInfo']) ||
    !Array.isArray(value.impacts.edges) ||
    value.impacts.edges.length > 100 ||
    !isRecord(value.impacts.pageInfo) ||
    !onlyKeys(value.impacts.pageInfo, ['endCursor', 'hasNextPage']) ||
    typeof value.impacts.pageInfo.hasNextPage !== 'boolean'
  )
    throw new PreviewFailure('unsupported')
  const { edges, pageInfo } = value.impacts
  for (const edge of edges) {
    if (
      !isRecord(edge) ||
      !onlyKeys(edge, ['cursor', 'node']) ||
      !nonempty(edge.cursor) ||
      !validImpact(edge.node)
    )
      throw new PreviewFailure('unsupported')
  }
  if (
    edges.length
      ? pageInfo.endCursor !== edges[edges.length - 1].cursor
      : pageInfo.endCursor !== null || pageInfo.hasNextPage
  )
    throw new PreviewFailure('unsupported')
  return value as unknown as DeletionPreview
}
export function epPreviewVariables(
  id: string,
  after: string | null,
): {
  input: {
    operation: 'DELETE_RESOURCES'
    targets: [{ type: 'ESCALATION_POLICY'; id: string }]
  }
  first: number
  after: string | null
} {
  return {
    input: {
      operation: 'DELETE_RESOURCES',
      targets: [{ type: 'ESCALATION_POLICY', id }],
    },
    first: 100,
    after,
  }
}

export function deletionFailure(
  error?: SafetyError,
): 'recheck' | 'blocked' | 'limit' | 'unsupported' | 'failed' | 'unknown' {
  if (!error || error.networkError || !error.graphQLErrors?.length)
    return 'unknown'
  const failures = error.graphQLErrors.map(({ extensions: ext }) => {
    switch (ext?.code) {
      case 'DELETION_DEPENDENCY_CHANGED':
      case 'DELETION_CONFIRMATION_REQUIRED':
        return 'recheck'
      case 'DELETION_BLOCKED':
        return 'blocked'
      case 'DELETION_PREVIEW_LIMIT_EXCEEDED':
        return 'limit'
      case 'DELETION_UNAVAILABLE':
        return 'unsupported'
      default:
        return ext?.isFieldError || ext?.isMultiFieldError
          ? 'failed'
          : 'unknown'
    }
  })
  // Mixed/unclassified errors cannot prove a pre-commit rejection.
  if (failures.includes('unknown')) return 'unknown'
  if (failures.includes('blocked')) return 'blocked'
  if (failures.includes('limit')) return 'limit'
  if (failures.includes('unsupported')) return 'unsupported'
  if (failures.includes('failed')) return 'failed'
  return 'recheck'
}

// Pages remain disposable until the entire sequence validates. Cancellation
// invalidates even responses in flight; partial data never unlocks deletion.
export async function loadEPDeletionPreview(
  id: string,
  fetchPage: (
    variables: ReturnType<typeof epPreviewVariables>,
  ) => Promise<PreviewResult>,
  active: () => boolean,
  progress: (loaded: number) => void,
): Promise<DeletionPreview> {
  const cursors = new Set<string>()
  const edgeIDs = new Set<string>()
  let combined: DeletionPreview | undefined
  let after: string | null = null
  // The merged planner permits at most 30,000 impacts (100 per request).
  for (let pageNumber = 0; pageNumber < 300; pageNumber++) {
    if (!active()) throw new PreviewFailure('cancelled')
    const result = await fetchPage(epPreviewVariables(id, after))
    if (!active()) throw new PreviewFailure('cancelled')
    if (result.error) {
      const failure = deletionFailure(result.error)
      throw new PreviewFailure(
        failure === 'limit'
          ? 'limit'
          : failure === 'unsupported'
            ? 'unsupported'
            : 'failed',
      )
    }
    if (result.stale || result.hasNext) throw new PreviewFailure('unsupported')
    const page = validatePage(result.data?.deletionPreview, id)
    // Reaching a successor means the prior page promised more data at this
    // version. An empty successor contradicts that promise, even at termination.
    if (after !== null && !page.impacts.edges.length)
      throw new PreviewFailure('unsupported')
    if (
      combined &&
      (page.impactVersion !== combined.impactVersion ||
        page.policyVersion !== combined.policyVersion ||
        page.canProceed !== combined.canProceed ||
        page.requiresConfirmation !== combined.requiresConfirmation ||
        page.targets[0].organization?.id !==
          combined.targets[0].organization?.id)
    )
      throw new PreviewFailure('unsupported')
    for (const edge of page.impacts.edges) {
      if (cursors.has(edge.cursor) || edgeIDs.has(edge.node.edgeID))
        throw new PreviewFailure('unsupported')
      cursors.add(edge.cursor)
      edgeIDs.add(edge.node.edgeID)
    }
    if (!combined)
      combined = { ...page, impacts: { ...page.impacts, edges: [] } }
    combined.impacts.edges.push(...page.impacts.edges)
    combined.notices = Array.from(
      new Set([...combined.notices, ...page.notices]),
    )
    combined.impacts.pageInfo = page.impacts.pageInfo
    if (!page.impacts.pageInfo.hasNextPage) {
      if (
        page.canProceed &&
        !page.requiresConfirmation &&
        combined.impacts.edges.some(
          ({ node }) => node.policy === 'CASCADE' || node.policy === 'WARNING',
        )
      )
        throw new PreviewFailure('unsupported')
      return combined
    }
    if (
      !page.impacts.edges.length ||
      !page.impacts.pageInfo.endCursor ||
      page.impacts.pageInfo.endCursor === after
    )
      throw new PreviewFailure('unsupported')
    progress(combined.impacts.edges.length)
    after = page.impacts.pageInfo.endCursor
  }
  throw new PreviewFailure('limit')
}
export function isDeletionBlocked(preview: DeletionPreview): boolean {
  return (
    !preview.canProceed ||
    preview.impacts.edges.some(({ node }) => node.policy === 'BLOCK')
  )
}
export function cascadeObjects(preview: DeletionPreview): DeletionResource[] {
  const objects = new Map<string, DeletionResource>()
  for (const { node } of preview.impacts.edges) {
    const type = node.referencingResource.type
    const known =
      (node.relation === 'POLICY_STEP' && type === 'ESCALATION_POLICY_STEP') ||
      (['POLICY_ACTION', 'STEP_ACTION'].includes(node.relation) &&
        type === 'ESCALATION_POLICY_ACTION')
    if (
      known &&
      node.policy === 'CASCADE' &&
      node.change === 'DELETED' &&
      !node.isDerived
    ) {
      objects.set(
        type + ':' + node.referencingResource.id,
        node.referencingResource,
      )
    }
  }
  return Array.from(objects.values())
}
export function epDeleteVariables(
  id: string,
  preview: DeletionPreview,
  acknowledged: boolean,
): {
  input: [{ type: 'escalationPolicy'; id: string }]
  confirmation: { expectedImpactVersion: string; acknowledgeImpacts: boolean }
} {
  if (
    preview.targets.length !== 1 ||
    preview.targets[0].id !== id ||
    preview.targets[0].type !== 'ESCALATION_POLICY' ||
    preview.operation !== 'DELETE_RESOURCES' ||
    preview.policyVersion !== 'deletion-safety-spec1-v2' ||
    !preview.complete ||
    !preview.impactVersion ||
    preview.impacts.pageInfo.hasNextPage ||
    isDeletionBlocked(preview) ||
    (preview.requiresConfirmation && !acknowledged)
  )
    throw new PreviewFailure('unsupported')
  return {
    input: [{ type: 'escalationPolicy', id }],
    confirmation: {
      expectedImpactVersion: preview.impactVersion,
      acknowledgeImpacts: preview.requiresConfirmation && acknowledged,
    },
  }
}
