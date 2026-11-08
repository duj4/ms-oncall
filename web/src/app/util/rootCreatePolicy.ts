import { DocumentNode, visit } from 'graphql'

const names = new Set([
  'createService',
  'createEscalationPolicy',
  'createSchedule',
  'createRotation',
])
export function containsRootCreate(document: DocumentNode): boolean {
  let found = false
  visit(document, {
    Field(node) {
      if (names.has(node.name.value)) found = true
    },
  })
  return found
}

export function createResultUncertain(error?: {
  networkError?: unknown
  graphQLErrors?: ReadonlyArray<{ extensions?: Record<string, unknown> }>
}): boolean {
  return (
    !!error?.networkError ||
    !!error?.graphQLErrors?.some(
      (entry) =>
        !entry.extensions?.isFieldError && !entry.extensions?.isMultiFieldError,
    )
  )
}

export function hasExpectedCreatedOrganization(
  data: unknown,
  expected?: string,
): boolean {
  if (!data || typeof data !== 'object') return false
  return Object.values(data).some((value) => {
    if (!value || typeof value !== 'object' || !('id' in value) || !value.id)
      return false
    if (!expected) return true
    return (
      'organization' in value &&
      !!value.organization &&
      typeof value.organization === 'object' &&
      'id' in value.organization &&
      value.organization.id === expected
    )
  })
}
