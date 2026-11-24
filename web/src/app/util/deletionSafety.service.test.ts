import {
  serviceID as id,
  servicePreview,
  serviceScenarios,
} from '../services/serviceDeletionFixtures'
import {
  deleteVariables,
  loadDeletionPreview,
  previewVariables,
} from './deletionSafety'
import { serviceDeletionProfile as profile } from './deletionSafetyProfiles'
import type { DeletionPreview as Preview } from '../../schema'
const load = (...pages: Preview[]): Promise<Preview> =>
  loadDeletionPreview(
    profile,
    id,
    async () => ({ data: { deletionPreview: pages.shift() } }),
    () => true,
    jest.fn(),
  )
test.each(serviceScenarios)(
  'actual Go domain Service plan: %s',
  async (name) => {
    const p = await load(servicePreview(name))
    expect(previewVariables(profile, id, null).input.targets).toEqual([
      { type: 'SERVICE', id },
    ])
    if (!p.canProceed) {
      expect(p.impacts.edges.some(({ node }) => node.policy === 'BLOCK')).toBe(
        true,
      )
      expect(() => deleteVariables(profile, id, p, true)).toThrow()
    } else {
      expect(deleteVariables(profile, id, p, true)).toEqual({
        input: [{ type: 'service', id }],
        confirmation: {
          expectedImpactVersion: p.impactVersion,
          acknowledgeImpacts: p.requiresConfirmation,
        },
      })
      if (p.requiresConfirmation)
        expect(() => deleteVariables(profile, id, p, false)).toThrow()
    }
    expect(p.impacts.edges.filter(({ node }) => node.isDerived)).toHaveLength(0)
    for (const { node } of p.impacts.edges) {
      if (
        node.relation === 'RETAINED_POLICY' ||
        node.referencingResource.type === 'ALERT_LOG'
      )
        expect(node.change).toBe('PRESERVED')
    }
  },
)
test('unique Key audit identities, retained logs and shared state provenance', async () => {
  const p = await load(servicePreview())
  const keys = p.impacts.edges.filter(
    ({ node }) => node.relation === 'SERVICE_INTEGRATION_KEY',
  )
  expect(keys).toHaveLength(2)
  expect(keys.map(({ node }) => node.referencingResource.id)).toEqual(
    expect.arrayContaining([
      '50000000-0000-4000-8000-000000000001',
      '50000000-0000-4000-8000-000000000002',
    ]),
  )
  const state = p.impacts.edges.filter(
    ({ node }) => node.referencingResource.type === 'ESCALATION_POLICY_STATE',
  )
  expect(state).toHaveLength(4)
  expect(
    new Set(state.map(({ node }) => node.referencingResource.id)).size,
  ).toBe(2)
  expect(
    p.impacts.edges
      .filter(({ node }) => node.relation === 'INTEGRATION_SOURCE')
      .every(
        ({ node }) =>
          node.target.type === 'INTEGRATION_KEY' &&
          node.referencingResource.id === id &&
          node.isPlannedCoDeletion,
      ),
  ).toBe(true)
})
test('complete pagination preserves all backend causal rows', async () => {
  const p = servicePreview()
  const a = servicePreview()
  const b = servicePreview()
  const cut = 3
  a.impacts.edges = a.impacts.edges.slice(0, cut)
  a.impacts.pageInfo = {
    hasNextPage: true,
    endCursor: a.impacts.edges[cut - 1].cursor,
  }
  b.impacts.edges = b.impacts.edges.slice(cut)
  expect((await load(a, b)).impacts.edges).toEqual(p.impacts.edges)
})
test.each([
  'incomplete',
  'version',
  'policyVersion',
  'organization',
  'cursor',
  'edgeID',
  'empty',
  'root',
  'canProceed',
  'confirmation',
])('inconsistent pagination fails closed: %s', async (failure) => {
  const a = servicePreview()
  const b = servicePreview()
  a.impacts.edges = a.impacts.edges.slice(0, 1)
  a.impacts.pageInfo = {
    hasNextPage: true,
    endCursor: a.impacts.edges[0].cursor,
  }
  b.impacts.edges = b.impacts.edges.slice(1)
  if (failure === 'incomplete') b.complete = false
  if (failure === 'version') b.impactVersion = 'changed'
  if (failure === 'policyVersion') b.policyVersion = 'changed'
  if (failure === 'organization')
    b.targets[0].organization = { id: 'another', name: 'Synthetic' }
  if (failure === 'cursor')
    b.impacts.edges[0].cursor = a.impacts.edges[0].cursor
  if (failure === 'edgeID')
    b.impacts.edges[0].node.edgeID = a.impacts.edges[0].node.edgeID
  if (failure === 'empty') {
    b.impacts.edges = []
    b.impacts.pageInfo.endCursor = null
  }
  if (failure === 'root') b.targets[0].id = 'another'
  if (failure === 'canProceed') b.canProceed = false
  if (failure === 'confirmation') b.requiresConfirmation = false
  await expect(load(a, b)).rejects.toMatchObject({ phase: 'unsupported' })
})
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
])('every closure row rejects illegal %s', async (field) => {
  for (const name of ['closure', 'blockedMessages', 'open'])
    for (let i = 0; i < servicePreview(name).impacts.edges.length; i++) {
      const p = servicePreview(name)
      const n = p.impacts.edges[i].node
      if (field === 'target') n.target = { ...n.target, type: 'USER' }
      if (field === 'ref')
        n.referencingResource = { ...n.referencingResource, type: 'USER' }
      if (field === 'parent') n.parent = n.parent ? null : p.targets[0]
      if (field === 'derived') n.isDerived = true
      if (field === 'co') n.isPlannedCoDeletion = !n.isPlannedCoDeletion
      if (field === 'policy')
        n.policy = n.policy === 'WARNING' ? 'INFORMATIONAL' : 'WARNING'
      if (field === 'change') n.change = 'CONFIG_TRIMMED'
      if (field === 'action') n.requiredAction = 'DETACH_REFERENCE'
      if (field === 'relation') n.relation = 'UNKNOWN_RELATION'
      await expect(load(p)).rejects.toMatchObject({ phase: 'unsupported' })
    }
})
test.each([
  'root',
  'edge-root',
  'key-parent',
  'key-ref-service',
  'unknown-resource',
])('rejects root identity and invalid Key boundaries: %s', async (failure) => {
  const p = servicePreview()
  if (failure === 'root') p.targets[0].id = 'another'
  if (failure === 'edge-root')
    p.impacts.edges.find(
      ({ node }) => node.relation === 'SERVICE_ALERT',
    )!.node.target.id = 'another'
  if (failure === 'key-parent')
    p.impacts.edges.find(
      ({ node }) => node.relation === 'SERVICE_INTEGRATION_KEY',
    )!.node.parent!.id = 'another'
  if (failure === 'key-ref-service')
    p.impacts.edges.find(
      ({ node }) => node.relation === 'INTEGRATION_SOURCE',
    )!.node.referencingResource.id = 'another'
  if (failure === 'unknown-resource')
    p.impacts.edges[0].node.referencingResource.type = 'UNKNOWN'
  await expect(load(p)).rejects.toMatchObject({ phase: 'unsupported' })
})
test.each(['DELETION_UNAVAILABLE', 'DELETION_PREVIEW_LIMIT_EXCEEDED'])(
  'backend %s never becomes no dependencies',
  async (code) => {
    await expect(
      loadDeletionPreview(
        profile,
        id,
        async () => ({ error: { graphQLErrors: [{ extensions: { code } }] } }),
        () => true,
        jest.fn(),
      ),
    ).rejects.toBeDefined()
  },
)
