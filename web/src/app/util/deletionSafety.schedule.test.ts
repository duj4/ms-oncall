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
  loadEPDeletionPreview,
  previewVariables,
} from './deletionSafety'
import {
  epDeletionProfile,
  scheduleDeletionProfile as profile,
} from './deletionSafetyProfiles'

const id = '10000000-0000-4000-8000-000000000001'
const root = (type = 'SCHEDULE', key = id): DeletionResource => ({
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
      referencingResource: root('SCHEDULE_RULE', String(n)),
      parent: root(),
      relation: 'SCHEDULE_RULE',
      change: 'DELETED',
      policy: 'CASCADE',
      requiredAction: 'CONFIRM_IMPACT',
      impact: 'Owned rule deleted.',
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

test('Schedule uses one actual UUID, enum mapping, original version, and accurate ack', async () => {
  expect(previewVariables(profile, id, null)).toEqual({
    input: {
      operation: 'DELETE_RESOURCES',
      targets: [{ type: 'SCHEDULE', id }],
    },
    first: 100,
    after: null,
  })
  const empty = await load(preview())
  expect(deleteVariables(profile, id, empty, true)).toEqual({
    input: [{ type: 'schedule', id }],
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
  ['SCHEDULE_RULE', 'SCHEDULE_RULE'],
  ['SCHEDULE_OVERRIDE', 'USER_OVERRIDE'],
  ['SCHEDULE_TEMPORARY', 'TEMPORARY_SCHEDULE'],
  ['SCHEDULE_SHIFT', 'FIXED_SHIFT'],
  ['TEMPORARY_SHIFT', 'FIXED_SHIFT'],
  ['SCHEDULE_ON_CALL_RULE', 'ON_CALL_NOTIFICATION_RULE'],
  ['FAVORITE', 'FAVORITE'],
  ['CALENDAR', 'CALENDAR_SUBSCRIPTION'],
])(
  'displays actual owned %s / %s without broadening EP vocabulary',
  async (relation, type) => {
    const p = preview([edge(1, { relation, referencingResource: root(type) })])
    await expect(load(p)).resolves.toMatchObject({
      targets: [{ type: 'SCHEDULE', id }],
    })
    p.targets = [root('ESCALATION_POLICY')]
    if (
      !epDeletionProfile.relations.includes(relation) ||
      !epDeletionProfile.resourceTypes.includes(type)
    )
      await expect(
        loadEPDeletionPreview(id, async () => result(p), alive, jest.fn()),
      ).rejects.toMatchObject({ phase: 'unsupported' })
  },
)

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

test('retained Rotation/User are INFORMATIONAL references, not cascade objects', async () => {
  for (const type of ['ROTATION', 'USER']) {
    const p = await load(
      preview([
        edge(1),
        edge(2, {
          target: root(type),
          relation: 'RULE_TARGET',
          policy: 'INFORMATIONAL',
          change: 'PRESERVED',
          requiredAction: 'NONE',
        }),
      ]),
    )
    expect(p.impacts.edges[1].node).toMatchObject({
      target: { type },
      policy: 'INFORMATIONAL',
      change: 'PRESERVED',
    })
  }
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
    p.impacts.edges[0].node.relation = 'NEW_SCHEDULE_RELATION'
  if (kind === 'type')
    p.impacts.edges[0].node.referencingResource.type = 'PRIVATE_UNKNOWN'
  if (kind === 'policy')
    p.impacts.edges[0].node.policy = 'FORCE_ALLOWED' as never
  if (kind === 'field')
    Object.assign(p.impacts.edges[0].node, {
      privateDestination: 'synthetic-sensitive-sentinel',
    })
  if (kind === 'operation') p.operation = 'UPDATE_SCHEDULE_TARGET'
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
