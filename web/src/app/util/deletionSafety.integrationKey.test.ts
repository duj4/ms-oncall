import { print } from 'graphql'
import {
  deleteVariables,
  loadDeletionPreview,
  previewVariables,
} from './deletionSafety'
import {
  integrationKeyDeletionProfile as profile,
  serviceDeletionProfile,
} from './deletionSafetyProfiles'
import {
  integrationKeyDeletionQuery,
  verifyIntegrationKeyIdentity,
  verifyIntegrationKeyPreview,
} from './integrationKeyDeletion'
import {
  legacyID,
  auditID,
  serviceID,
  expectedIdentity,
  identityResult,
  keySelection,
  keyPreview,
} from '../services/integrationKeyDeletionFixtures'
const load = (...pages: unknown[]): Promise<ReturnType<typeof keyPreview>> =>
  loadDeletionPreview(
    profile,
    auditID,
    async () => ({ data: { deletionPreview: pages.shift() } }),
    () => true,
    jest.fn(),
    keySelection(),
  )

test.each([
  'email',
  'generic',
  'grafana',
  'prometheusAlertmanager',
  'site24x7',
  'universal',
])('authorized same-row identity for %s has distinct namespaces', (type) => {
  const result = identityResult()
  result.data.integrationKey.type = type
  const selection = verifyIntegrationKeyIdentity(result, {
    ...expectedIdentity,
    type,
  })
  expect(selection.legacyID).toBe(legacyID)
  expect(selection.auditID).toBe(auditID)
  expect(Object.isFrozen(selection)).toBe(true)
  expect(print(integrationKeyDeletionQuery)).not.toMatch(/href|token|config/i)
})
test.each([
  'missing-key',
  'missing-audit',
  'bad-audit',
  'zero-audit',
  'equal',
  'wrong-key',
  'wrong-service',
  'wrong-type',
  'unknown-type',
  'bad-legacy',
  'bad-service',
  'bad-org',
  'missing-scope',
  'error',
  'mixed',
  'network',
  'stale',
  'partial',
  'fetching',
])('identity rejects %s without fallback', (kind) => {
  const result: Parameters<typeof verifyIntegrationKeyIdentity>[0] =
    identityResult()
  const expected = { ...expectedIdentity }
  const key = result.data!.integrationKey!
  switch (kind) {
    case 'missing-key':
      result.data!.integrationKey = null
      break
    case 'missing-audit':
      delete key.auditResourceID
      break
    case 'bad-audit':
      key.auditResourceID = 'invalid'
      break
    case 'zero-audit':
      key.auditResourceID = '00000000-0000-0000-0000-000000000000'
      break
    case 'equal':
      key.auditResourceID = legacyID
      break
    case 'wrong-key':
      key.id = auditID
      break
    case 'wrong-service':
      key.serviceID = auditID
      break
    case 'wrong-type':
      key.type = 'grafana'
      break
    case 'unknown-type':
      key.type = expected.type = 'future'
      break
    case 'bad-legacy':
      key.id = expected.id = 'invalid'
      break
    case 'bad-service':
      key.serviceID = expected.serviceID = ''
      break
    case 'bad-org':
      expected.organizationID = ''
      break
    case 'missing-scope':
      expected.scopeKey = ''
      break
    case 'error':
      result.data = null
      result.error = {}
      break
    case 'mixed':
      result.error = { graphQLErrors: [{ message: 'Synthetic ID! error' }] }
      break
    case 'network':
      result.error = { networkError: new Error('Synthetic disconnect') }
      break
    case 'stale':
      result.stale = true
      break
    case 'partial':
      result.hasNext = true
      break
    case 'fetching':
      result.fetching = true
      break
  }
  expect(() => verifyIntegrationKeyIdentity(result, expected)).toThrow()
})
test.each([0, 1, 5, 135])(
  'full %i log plan retains Service/history and uses Audit preview / Legacy deletion',
  async (logs) => {
    const p = keyPreview(logs)
    const pages = []
    for (let i = 0; i < p.impacts.edges.length; i += 100) {
      const part = keyPreview(0)
      part.impacts.edges = p.impacts.edges.slice(i, i + 100)
      part.impacts.pageInfo = {
        endCursor: part.impacts.edges[part.impacts.edges.length - 1].cursor,
        hasNextPage: i + 100 < p.impacts.edges.length,
      }
      pages.push(part)
    }
    const preview = await load(...pages)
    expect(verifyIntegrationKeyPreview(keySelection(), preview)).toBe(true)
    expect(previewVariables(profile, auditID, null).input.targets).toEqual([
      { type: 'INTEGRATION_KEY', id: auditID },
    ])
    expect(
      deleteVariables(profile, legacyID, preview, true, keySelection()),
    ).toEqual({
      input: [{ type: 'integrationKey', id: legacyID }],
      confirmation: {
        expectedImpactVersion: preview.impactVersion,
        acknowledgeImpacts: true,
      },
    })
    expect(() =>
      deleteVariables(profile, legacyID, preview, false, keySelection()),
    ).toThrow()
    expect(
      preview.impacts.edges
        .filter((e) => e.node.referencingResource.type === 'ALERT_LOG')
        .every((e) => e.node.change === 'PRESERVED'),
    ).toBe(true)
    expect(preview.impacts.edges[0].node.isPlannedCoDeletion).toBe(false)
  },
)
test.each([
  'target',
  'ref',
  'parent',
  'derived',
  'co',
  'policy',
  'change',
  'action',
  'relation',
  'target-id',
])('every relationship rejects malformed %s', async (field) => {
  for (let i = 0; i < 2; i++) {
    const p = keyPreview()
    const n = p.impacts.edges[i].node
    if (field === 'target') n.target = { ...n.target, type: 'SERVICE' }
    if (field === 'target-id') n.target = { ...n.target, id: legacyID }
    if (field === 'ref')
      n.referencingResource = {
        ...n.referencingResource,
        type: 'INTEGRATION_KEY',
      }
    if (field === 'parent') n.parent = p.targets[0]
    if (field === 'derived') n.isDerived = true
    if (field === 'co') n.isPlannedCoDeletion = true
    if (field === 'policy') n.policy = 'CASCADE'
    if (field === 'change') n.change = 'RELATION_REMOVED'
    if (field === 'action') n.requiredAction = 'DETACH_REFERENCE'
    if (field === 'relation') n.relation = 'UNKNOWN'
    await expect(load(p)).rejects.toMatchObject({ phase: 'unsupported' })
  }
})
test.each([
  'service',
  'root-org',
  'target-org',
  'ref-org',
  'missing-source',
  'duplicate-source',
  'bad-log',
  'zero-log',
  'oversized-log',
  'foreign-root',
])('selection rejects %s even after structural validation', (kind) => {
  const p = keyPreview()
  if (kind === 'service')
    p.impacts.edges[0].node.referencingResource.id = auditID
  if (kind === 'root-org')
    p.targets[0].organization = { id: serviceID, name: 'Synthetic' }
  if (kind === 'target-org')
    p.impacts.edges[1].node.target = { ...p.targets[0], organization: null }
  if (kind === 'ref-org')
    p.impacts.edges[1].node.referencingResource.organization = null
  if (kind === 'missing-source') p.impacts.edges.shift()
  if (kind === 'duplicate-source') p.impacts.edges.push(p.impacts.edges[0])
  if (kind === 'bad-log')
    p.impacts.edges[1].node.referencingResource.id = auditID
  if (kind === 'zero-log') p.impacts.edges[1].node.referencingResource.id = '0'
  if (kind === 'oversized-log')
    p.impacts.edges[1].node.referencingResource.id = '9223372036854775808'
  if (kind === 'foreign-root') p.targets[0] = { ...p.targets[0], id: legacyID }
  expect(verifyIntegrationKeyPreview(keySelection(), p)).toBe(false)
  expect(() =>
    deleteVariables(profile, legacyID, p, true, keySelection()),
  ).toThrow()
})
test('two same-name Keys cannot exchange identities, selectors or copied authorization objects', () => {
  const a = keySelection()
  const r = identityResult()
  r.data.integrationKey.id = '10000000-0000-4000-8000-000000000002'
  r.data.integrationKey.auditResourceID = '20000000-0000-4000-8000-000000000002'
  const b = verifyIntegrationKeyIdentity(r, {
    ...expectedIdentity,
    id: r.data.integrationKey.id,
  })
  expect(a.name).toBe(b.name)
  expect(() =>
    deleteVariables(profile, b.legacyID, keyPreview(), true, a),
  ).toThrow()
  expect(() =>
    deleteVariables(profile, a.legacyID, keyPreview(), true, b),
  ).toThrow()
  expect(() =>
    deleteVariables(profile, a.legacyID, keyPreview(), true, { ...a }),
  ).toThrow()
  expect(() =>
    deleteVariables(profile, a.legacyID, keyPreview(), true),
  ).toThrow()
  expect(() =>
    deleteVariables(serviceDeletionProfile, a.legacyID, keyPreview(), true, a),
  ).toThrow()
})
test.each([
  'empty',
  'cursor',
  'duplicate-edge',
  'version',
  'policy-version',
  'org',
  'incomplete',
  'stale',
  'hasNext',
])('pagination fails closed: %s', async (kind) => {
  const a = keyPreview()
  a.impacts.edges = a.impacts.edges.slice(0, 1)
  a.impacts.pageInfo = { endCursor: 'cursor-0', hasNextPage: true }
  const b = keyPreview()
  b.impacts.edges = b.impacts.edges.slice(1)
  if (kind === 'empty') {
    b.impacts.edges = []
    b.impacts.pageInfo.endCursor = null
  }
  if (kind === 'cursor') b.impacts.pageInfo.endCursor = 'wrong'
  if (kind === 'duplicate-edge') b.impacts.edges[0].node.edgeID = 'source'
  if (kind === 'version') b.impactVersion = 'changed'
  if (kind === 'policy-version') b.policyVersion = 'changed'
  if (kind === 'org') b.targets[0].organization = null
  if (kind === 'incomplete') b.complete = false
  let count = 0
  await expect(
    loadDeletionPreview(
      profile,
      auditID,
      async () => ({
        data: { deletionPreview: count++ ? b : a },
        stale: kind === 'stale',
        hasNext: kind === 'hasNext',
      }),
      () => true,
      jest.fn(),
      keySelection(),
    ),
  ).rejects.toBeDefined()
})
test.each([
  'Universal Key',
  'UIK Config',
  'Broken Service',
  'Broken AlertLog',
  'Cross Organization',
  'Permission denied',
  'Budget limit',
])(
  'frontend simulated backend refusal (%s), NOT Native SQL proof',
  async (shape) => {
    const code =
      shape === 'Budget limit'
        ? 'DELETION_PREVIEW_LIMIT_EXCEEDED'
        : shape === 'Permission denied'
          ? 'ACCESS_DENIED'
          : 'DELETION_UNAVAILABLE'
    await expect(
      loadDeletionPreview(
        profile,
        auditID,
        async () => ({ error: { graphQLErrors: [{ extensions: { code } }] } }),
        () => true,
        jest.fn(),
        keySelection(),
      ),
    ).rejects.toBeDefined()
  },
)

test('IntegrationKey profile requires its authorized binding before fetching any page', async () => {
  const fetchPage = jest.fn(async () => ({
    data: { deletionPreview: keyPreview() },
  }))
  await expect(
    loadDeletionPreview(profile, auditID, fetchPage, () => true, jest.fn()),
  ).rejects.toMatchObject({ phase: 'unsupported' })
  expect(fetchPage).not.toHaveBeenCalled()
  expect(
    profile.supportsImpact!(
      keyPreview().impacts.edges[0].node,
      auditID,
      keySelection(),
    ),
  ).toBe(true)
  const wrong = keyPreview().impacts.edges[0].node
  wrong.referencingResource.id = auditID
  expect(profile.supportsImpact!(wrong, auditID, keySelection())).toBe(false)
})
