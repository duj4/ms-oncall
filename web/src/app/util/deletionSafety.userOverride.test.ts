import {
  userOverrideID as id,
  userOverridePreview,
} from '../schedules/userOverrideDeletionFixtures'
import {
  deleteVariables,
  loadDeletionPreview,
  previewVariables,
} from './deletionSafety'
import {
  userOverrideDeletionProfile as profile,
  notificationRuleDeletionProfile,
  epDeletionProfile,
  scheduleDeletionProfile,
  rotationDeletionProfile,
} from './deletionSafetyProfiles'
type Preview = import('../../schema').DeletionPreview
const load = (...pages: Preview[]): Promise<Preview> =>
  loadDeletionPreview(
    profile,
    id,
    async () => ({ data: { deletionPreview: pages.shift()! } }),
    () => true,
    jest.fn(),
  )

describe.each(['active', 'future', 'ended'] as const)('%s', (period) => {
  test.each(['add-only', 'remove-only', 'replace'] as const)(
    'accepts the backend %s projection and preserves Schedule/User',
    async (shape) => {
      const p = await load(userOverridePreview(period, shape))
      const warning = period !== 'ended'
      expect(p.requiresConfirmation).toBe(warning)
      expect(p.impacts.edges[0].node).toMatchObject({
        relation: 'OVERRIDE_COVERAGE',
        target: { type: 'USER_OVERRIDE', id },
        referencingResource: { type: 'SCHEDULE' },
        policy: warning ? 'WARNING' : 'INFORMATIONAL',
        change: 'DELETED',
        isPlannedCoDeletion: false,
      })
      const users = p.impacts.edges.slice(1)
      expect(users).toHaveLength(shape === 'replace' ? 4 : 2)
      expect(users.filter(({ node }) => node.isDerived)).toHaveLength(
        shape === 'replace' ? 2 : 1,
      )
      for (const { node } of users)
        expect(node).toMatchObject({
          target: { type: 'USER' },
          referencingResource: { type: 'USER_OVERRIDE', id },
          parent: { type: 'SCHEDULE' },
          change: 'PRESERVED',
          policy: 'INFORMATIONAL',
          requiredAction: 'NONE',
          isPlannedCoDeletion: true,
        })
      if (warning)
        expect(() => deleteVariables(profile, id, p, false)).toThrow()
      expect(deleteVariables(profile, id, p, true)).toEqual({
        input: [{ type: 'userOverride', id }],
        confirmation: {
          expectedImpactVersion: 'version-1',
          acknowledgeImpacts: warning,
        },
      })
      expect(previewVariables(profile, id, null).input.targets).toEqual([
        { type: 'USER_OVERRIDE', id },
      ])
    },
  )
})
test('fetches all pages including retained User and derived Schedule rows', async () => {
  const a = userOverridePreview('active')
  const b = userOverridePreview('active')
  a.impacts.edges = a.impacts.edges.slice(0, 1)
  a.impacts.pageInfo = { hasNextPage: true, endCursor: 'coverage' }
  b.impacts.edges = b.impacts.edges.slice(1)
  const fetch = jest
    .fn()
    .mockResolvedValueOnce({ data: { deletionPreview: a } })
    .mockResolvedValueOnce({ data: { deletionPreview: b } })
  const p = await loadDeletionPreview(profile, id, fetch, () => true, jest.fn())
  expect(fetch.mock.calls.map(([variables]) => variables.after)).toEqual([
    null,
    'coverage',
  ])
  expect(p.impacts.edges).toHaveLength(5)
})
test.each([
  'network',
  'incomplete',
  'version',
  'policy-version',
  'cursor',
  'edge-id',
  'empty-successor',
  'confirmation',
  'canProceed',
  'root',
])('cross-page %s inconsistency fails closed', async (failure) => {
  const a = userOverridePreview()
  const b = userOverridePreview()
  a.impacts.edges = a.impacts.edges.slice(0, 1)
  a.impacts.pageInfo = { hasNextPage: true, endCursor: 'coverage' }
  b.impacts.edges = b.impacts.edges.slice(1)
  if (failure === 'incomplete') b.complete = false
  if (failure === 'version') b.impactVersion = 'other'
  if (failure === 'policy-version') b.policyVersion = 'future'
  if (failure === 'cursor') b.impacts.edges[0].cursor = 'coverage'
  if (failure === 'edge-id') b.impacts.edges[0].node.edgeID = 'coverage'
  if (failure === 'confirmation') b.requiresConfirmation = true
  if (failure === 'canProceed') b.canProceed = false
  if (failure === 'root') b.targets[0].id = 'other'
  if (failure === 'empty-successor') {
    b.impacts.edges = []
    b.impacts.pageInfo.endCursor = null
  }
  const fetch = jest
    .fn()
    .mockResolvedValueOnce({ data: { deletionPreview: a } })
    .mockResolvedValueOnce(
      failure === 'network'
        ? { error: { networkError: new Error('synthetic') } }
        : { data: { deletionPreview: b } },
    )
  await expect(
    loadDeletionPreview(profile, id, fetch, () => true, jest.fn()),
  ).rejects.toMatchObject({
    phase: failure === 'network' ? 'failed' : 'unsupported',
  })
})
test.each([
  'resource',
  'relation',
  'policy-version',
  'root',
  'coverage-root',
  'coverage-derived',
  'coverage-parent',
  'coverage-co-deletion',
  'user-target',
  'user-referencing',
  'user-parent',
  'user-deleted',
  'user-block',
  'user-co-deletion',
  'derived-deleted',
  'confirmation',
  'stale',
  'partial',
])('illegal preview %s fails closed', async (failure) => {
  const p = userOverridePreview('active')
  const c = p.impacts.edges[0].node
  const u = p.impacts.edges[1].node
  if (failure === 'resource') c.referencingResource.type = 'ROTATION'
  if (failure === 'relation') c.relation = 'SCHEDULE_OVERRIDE'
  if (failure === 'policy-version') p.policyVersion = 'future'
  if (failure === 'root') p.targets = [{ ...p.targets[0], id: 'other' }]
  if (failure === 'coverage-root') c.target = { ...c.target, id: 'other' }
  if (failure === 'coverage-derived') c.isDerived = true
  if (failure === 'coverage-parent') c.parent = c.referencingResource
  if (failure === 'coverage-co-deletion') c.isPlannedCoDeletion = true
  if (failure === 'user-target') u.target = p.targets[0]
  if (failure === 'user-referencing')
    u.referencingResource = { ...u.referencingResource, id: 'other' }
  if (failure === 'user-parent') u.parent = u.target
  if (failure === 'user-deleted') u.change = 'DELETED'
  if (failure === 'user-block') u.policy = 'BLOCK'
  if (failure === 'user-co-deletion') u.isPlannedCoDeletion = false
  if (failure === 'derived-deleted') p.impacts.edges[2].node.change = 'DELETED'
  if (failure === 'confirmation') p.requiresConfirmation = false
  await expect(
    loadDeletionPreview(
      profile,
      id,
      async () => ({
        data: { deletionPreview: p },
        stale: failure === 'stale',
        hasNext: failure === 'partial',
      }),
      () => true,
      jest.fn(),
    ),
  ).rejects.toMatchObject({ phase: 'unsupported' })
})
test('backend canProceed=false cannot be overridden by acknowledgement', async () => {
  const p = userOverridePreview()
  p.canProceed = false
  expect(() => deleteVariables(profile, id, p, true)).toThrow()
  expect((await load(p)).canProceed).toBe(false)
})
test.each([
  epDeletionProfile,
  scheduleDeletionProfile,
  rotationDeletionProfile,
  notificationRuleDeletionProfile,
])('keeps $previewType independent from Override vocabulary', async (other) => {
  const p = userOverridePreview()
  p.targets = [{ ...p.targets[0], type: other.previewType }]
  await expect(
    loadDeletionPreview(
      other,
      id,
      async () => ({ data: { deletionPreview: p } }),
      () => true,
      jest.fn(),
    ),
  ).rejects.toMatchObject({ phase: 'unsupported' })
})
