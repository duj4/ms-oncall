import type {
  DeletionImpact,
  DeletionPreview,
  DeletionResource,
} from '../../schema'
import {
  deleteVariables,
  epDeleteVariables,
  isDeletionBlocked,
  loadDeletionPreview,
  previewVariables,
} from './deletionSafety'
import {
  epDeletionProfile,
  scheduleDeletionProfile,
  rotationDeletionProfile as profile,
} from './deletionSafetyProfiles'

const id = '10000000-0000-4000-8000-000000000001'
const root = (type = 'ROTATION', key = id): DeletionResource => ({
  type,
  id: key,
  name: null,
  label: type,
  organization: null,
})
function edge(
  n: number,
  extra: Partial<DeletionImpact> = {},
): DeletionPreview['impacts']['edges'][number] {
  return {
    cursor: 'cursor-' + n,
    node: {
      edgeID: 'edge-' + n,
      target: root(),
      referencingResource: root('ROTATION_PARTICIPANT', String(n)),
      parent: root(),
      relation: 'ROTATION_PARTICIPANT',
      change: 'DELETED',
      policy: 'CASCADE',
      requiredAction: 'CONFIRM_IMPACT',
      impact: 'Owned participant deleted.',
      canModifyReference: true,
      isDerived: false,
      isPlannedCoDeletion: true,
      ...extra,
    },
  }
}
function preview(
  edges: ReturnType<typeof edge>[] = [],
  next = false,
): DeletionPreview {
  return {
    operation: 'DELETE_RESOURCES',
    targets: [root()],
    impactVersion: ' raw opaque version ',
    policyVersion: 'deletion-safety-spec1-v2',
    assessedAt: '2026-11-21T10:00:00Z',
    complete: true,
    canProceed: true,
    requiresConfirmation: edges.some(
      ({ node }) => node.policy === 'CASCADE' || node.policy === 'WARNING',
    ),
    notices: [],
    impacts: {
      edges,
      pageInfo: {
        endCursor: edges[edges.length - 1]?.cursor || null,
        hasNextPage: next,
      },
    },
  }
}
const alive = (): boolean => true
const result = (
  p: DeletionPreview,
): { data: { deletionPreview: DeletionPreview } } => ({
  data: { deletionPreview: p },
})
const load = (...pages: DeletionPreview[]): Promise<DeletionPreview> =>
  loadDeletionPreview(
    profile,
    id,
    jest.fn(async () => result(pages.shift()!)),
    alive,
    jest.fn(),
  )

test('Rotation uses one actual UUID, enum mapping, original version, and accurate ack', async () => {
  expect(previewVariables(profile, id, null)).toEqual({
    input: {
      operation: 'DELETE_RESOURCES',
      targets: [{ type: 'ROTATION', id }],
    },
    first: 100,
    after: null,
  })
  const empty = await load(preview())
  expect(deleteVariables(profile, id, empty, true)).toEqual({
    input: [{ type: 'rotation', id }],
    confirmation: {
      expectedImpactVersion: ' raw opaque version ',
      acknowledgeImpacts: false,
    },
  })
  const owned = await load(preview([edge(1)]))
  expect(() => deleteVariables(profile, id, owned, false)).toThrow()
  expect(
    deleteVariables(profile, id, owned, true).confirmation.acknowledgeImpacts,
  ).toBe(true)
  expect(() => epDeleteVariables(id, empty, true)).toThrow()
})

test.each([
  ['ROTATION_PARTICIPANT', 'ROTATION_PARTICIPANT'],
  ['ROTATION_STATE', 'ROTATION_STATE'],
  ['FAVORITE', 'FAVORITE'],
])('accepts verified Rotation closure %s / %s', async (relation, type) => {
  await expect(
    load(preview([edge(1, { relation, referencingResource: root(type) })])),
  ).resolves.toMatchObject({ targets: [{ type: 'ROTATION', id }] })
})

test('EP and Schedule profiles retain their own vocabulary boundaries', async () => {
  for (const other of [epDeletionProfile, scheduleDeletionProfile]) {
    for (const relation of [
      'ROTATION_PARTICIPANT',
      'ROTATION_STATE',
      'PARTICIPANT_USER',
    ]) {
      const p = preview([edge(1, { relation })])
      p.targets = [root(other.previewType)]
      await expect(
        loadDeletionPreview(other, id, async () => result(p), alive, jest.fn()),
      ).rejects.toMatchObject({ phase: 'unsupported' })
    }
  }
  for (const relation of [
    'POLICY_STEP',
    'SCHEDULE_RULE',
    'SCHEDULE_TEMPORARY',
  ]) {
    await expect(load(preview([edge(1, { relation })]))).rejects.toMatchObject({
      phase: 'unsupported',
    })
  }
})

test('surviving EP Action blocks; a checkbox cannot override it', async () => {
  const p = await load(
    preview([
      edge(1, {
        relation: 'ACTION_TARGET',
        referencingResource: root('ESCALATION_POLICY_ACTION'),
        parent: root('ESCALATION_POLICY_STEP'),
        policy: 'BLOCK',
        change: 'PRESERVED',
        requiredAction: 'DETACH_REFERENCE',
        isPlannedCoDeletion: false,
      }),
    ]),
  )
  expect(isDeletionBlocked(p)).toBe(true)
  expect(() => deleteVariables(profile, id, p, true)).toThrow()
})

test('Schedule Rule blocks independently of an EP Action; a checkbox cannot override either', async () => {
  const p = await load(
    preview([
      edge(1, {
        relation: 'RULE_TARGET',
        referencingResource: root('SCHEDULE_RULE'),
        parent: root('SCHEDULE'),
        policy: 'BLOCK',
        change: 'PRESERVED',
        requiredAction: 'DETACH_REFERENCE',
        isPlannedCoDeletion: false,
      }),
    ]),
  )
  expect(isDeletionBlocked(p)).toBe(true)
  expect(() => deleteVariables(profile, id, p, true)).toThrow()
  expect(p.impacts.edges[0].node.parent?.type).toBe('SCHEDULE')
})

test('PARTICIPANT_USER is INFORMATIONAL/PRESERVED while its owned participant cascades', async () => {
  const p = await load(
    preview([
      edge(1),
      edge(2, {
        target: root('USER'),
        relation: 'PARTICIPANT_USER',
        policy: 'INFORMATIONAL',
        change: 'PRESERVED',
        requiredAction: 'NONE',
        referencingResource: root('ROTATION_PARTICIPANT'),
      }),
      edge(3, {
        relation: 'ROTATION_STATE',
        referencingResource: root('ROTATION_STATE', '1'),
      }),
    ]),
  )
  expect(p.impacts.edges[1].node).toMatchObject({
    target: { type: 'USER' },
    referencingResource: { type: 'ROTATION_PARTICIPANT' },
    policy: 'INFORMATIONAL',
    change: 'PRESERVED',
  })
  const vars = deleteVariables(profile, id, p, true)
  expect(vars.input).toEqual([{ type: 'rotation', id }])
  expect(
    vars.input.some((target) => ['user', 'schedule'].includes(target.type)),
  ).toBe(false)
})

test('serial complete pagination uses only backend endCursor and never reviews partial data', async () => {
  const first = preview([edge(1)], true)
  const last = preview([edge(2)])
  const fetch = jest
    .fn()
    .mockResolvedValueOnce(result(first))
    .mockResolvedValueOnce(result(last))
  const progress = jest.fn()
  const p = await loadDeletionPreview(profile, id, fetch, alive, progress)
  expect(fetch.mock.calls.map(([v]) => v)).toEqual([
    previewVariables(profile, id, null),
    previewVariables(profile, id, 'cursor-1'),
  ])
  expect(progress).toHaveBeenCalledWith(1)
  expect(p.impacts.edges).toHaveLength(2)
})

test.each([
  'empty-last',
  'empty-more',
  'missing-cursor',
  'duplicate-cursor',
  'duplicate-edge',
  'version',
  'policy',
  'identity',
])('pagination %s fails closed', async (kind) => {
  const a = preview([edge(1)], true)
  const b = preview([edge(2)])
  if (kind.startsWith('empty')) {
    b.impacts = preview().impacts
    b.impacts.pageInfo.hasNextPage = kind === 'empty-more'
  }
  if (kind === 'missing-cursor') b.impacts.pageInfo.endCursor = null
  if (kind === 'duplicate-cursor') {
    b.impacts.edges[0].cursor = 'cursor-1'
    b.impacts.pageInfo.endCursor = 'cursor-1'
  }
  if (kind === 'duplicate-edge') b.impacts.edges[0].node.edgeID = 'edge-1'
  if (kind === 'version') b.impactVersion = 'changed'
  if (kind === 'policy') b.policyVersion = 'future-policy'
  if (kind === 'identity')
    b.targets[0].organization = { id: 'different-home', name: 'Synthetic Home' }
  await expect(load(a, b)).rejects.toMatchObject({ phase: 'unsupported' })
})

test.each([
  'relation',
  'type',
  'policy',
  'field',
  'operation',
  'target',
  'partial',
])('unknown %s fails closed', async (kind) => {
  const p = preview([edge(1)])
  if (kind === 'relation')
    p.impacts.edges[0].node.relation = 'NEW_ROTATION_RELATION'
  if (kind === 'type')
    p.impacts.edges[0].node.referencingResource.type = 'PRIVATE_UNKNOWN'
  if (kind === 'policy')
    p.impacts.edges[0].node.policy = 'FORCE_ALLOWED' as never
  if (kind === 'field')
    Object.assign(p.impacts.edges[0].node, {
      privateDestination: 'synthetic-sensitive-sentinel',
    })
  if (kind === 'operation') p.operation = 'UPDATE_ROTATION'
  if (kind === 'target') p.targets.push(root())
  if (kind === 'partial') p.complete = false
  await expect(load(p)).rejects.toMatchObject({ phase: 'unsupported' })
})

test.each(['DELETION_UNAVAILABLE', 'DELETION_PREVIEW_LIMIT_EXCEEDED'])(
  'backend %s remains unavailable',
  async (code) => {
    await expect(
      loadDeletionPreview(
        profile,
        id,
        async () => ({ error: { graphQLErrors: [{ extensions: { code } }] } }),
        alive,
        jest.fn(),
      ),
    ).rejects.toMatchObject({
      phase: code === 'DELETION_UNAVAILABLE' ? 'unsupported' : 'limit',
    })
  },
)
