import { parse, visit } from 'graphql'
import {
  deleteVariables,
  deletionPreviewQuery,
  isDeletionBlocked,
  loadDeletionPreview,
  previewVariables,
} from './deletionSafety'
import { userDeletionProfile as profile } from './deletionSafetyProfiles'
import {
  userActionPreview,
  userEdgeID,
  userID,
  userImpact,
  userOrganizationID,
  userOwnedPreview,
  userPreview,
  userResource,
} from '../users/userDeletionFixtures'
import type { DeletionPreview, DeletionImpact } from '../../schema'

const load = (...pages: DeletionPreview[]): Promise<DeletionPreview> =>
  loadDeletionPreview(
    profile,
    userID,
    async () => ({ data: { deletionPreview: pages.shift() } }),
    () => true,
    jest.fn(),
  )
const split = (
  p: DeletionPreview,
  rows: DeletionImpact[],
  more: boolean,
): DeletionPreview => ({
  ...p,
  impacts: {
    edges: rows.map((node) => ({ cursor: 'c-' + node.edgeID, node })),
    pageInfo: {
      hasNextPage: more,
      endCursor: rows.length ? 'c-' + rows[rows.length - 1].edgeID : null,
    },
  },
})
test('query explicitly requests the complete safe projection', () => {
  const fields = new Set<string>()
  visit(deletionPreviewQuery, {
    Field(n) {
      fields.add(n.name.value)
    },
  })
  for (const field of [
    'edgeID',
    'target',
    'referencingResource',
    'parent',
    'owner',
    'derivedFrom',
    'affectedResource',
    'relation',
    'change',
    'policy',
    'impact',
    'requiredAction',
    'canModifyReference',
    'isDerived',
    'isPlannedCoDeletion',
    'organization',
    'id',
    'type',
  ])
    expect(fields.has(field)).toBe(true)
  expect(parse('query { __typename }')).toBeDefined()
})
test('one canonical User UUID binds preview and DeleteAll user, with backend confirmation', async () => {
  const p = await load(userOwnedPreview())
  expect(previewVariables(profile, userID, null).input.targets).toEqual([
    { type: 'USER', id: userID },
  ])
  expect(() => deleteVariables(profile, userID, p, false)).toThrow()
  expect(deleteVariables(profile, userID, p, true)).toEqual({
    input: [{ type: 'user', id: userID }],
    confirmation: {
      expectedImpactVersion: p.impactVersion,
      acknowledgeImpacts: true,
    },
  })
  expect(() =>
    deleteVariables(profile, '10000000-0000-4000-8000-000000000002', p, true),
  ).toThrow()
})
test('legal nullable owner and empty impact plan remain reviewable', async () => {
  const p = await load(userPreview([userImpact(1)]))
  expect(p.impacts.edges[0].node.owner).toBeNull()
  expect(
    deleteVariables(profile, userID, await load(userPreview()), false).input,
  ).toHaveLength(1)
})
test.each([
  [0, 1, 2],
  [2, 1, 0],
  [1, 0, 2],
  [1, 2, 0],
])(
  'direct and Parent/Owner causes validate across every page order %s',
  async (a, b, c) => {
    const p = userActionPreview()
    const rows = p.impacts.edges.map(({ node }) => node)
    const result = await load(
      split(p, [rows[a]], true),
      split(p, [rows[b]], true),
      split(p, [rows[c]], false),
    )
    expect(result.impacts.edges).toHaveLength(3)
    expect(isDeletionBlocked(result)).toBe(true)
    expect(() => deleteVariables(profile, userID, result, true)).toThrow()
    expect(
      result.impacts.edges.find(({ node }) => node.edgeID === userEdgeID(1))!
        .node.parent!.type,
    ).toBe('ESCALATION_POLICY_STEP')
  },
)
const invalid: Array<[string, (p: DeletionPreview) => void]> = [
  [
    'missing affected',
    (p) => {
      p.impacts.edges[0].node.affectedResource = null
    },
  ],
  [
    'undefined affected',
    (p) => {
      delete p.impacts.edges[0].node.affectedResource
    },
  ],
  [
    'misbound direct affected',
    (p) => {
      p.impacts.edges[0].node.affectedResource = p.targets[0]
    },
  ],
  [
    'misbound derived affected',
    (p) => {
      p.impacts.edges[1].node.affectedResource =
        p.impacts.edges[0].node.referencingResource
    },
  ],
  [
    'invalid affected UUID',
    (p) => {
      p.impacts.edges[1].node.affectedResource = userResource(
        'ESCALATION_POLICY_STEP',
        'not-an-id',
      )
    },
  ],
  [
    'invalid affected type',
    (p) => {
      p.impacts.edges[1].node.affectedResource = userResource('SERVICE')
    },
  ],
  [
    'invalid owner ID',
    (p) => {
      p.impacts.edges[0].node.owner = userResource(
        'ESCALATION_POLICY',
        'secret-shaped-opaque',
      )
    },
  ],
  [
    'missing required owner',
    (p) => {
      p.impacts.edges[0].node.owner = null
    },
  ],
  [
    'parent cannot substitute for owner',
    (p) => {
      p.impacts.edges[0].node.owner = p.impacts.edges[0].node.parent
    },
  ],
  [
    'missing derivedFrom',
    (p) => {
      p.impacts.edges[1].node.derivedFrom = null
    },
  ],
  [
    'malformed derivedFrom',
    (p) => {
      p.impacts.edges[1].node.derivedFrom = 'guess'
    },
  ],
  [
    'self causal link',
    (p) => {
      p.impacts.edges[1].node.derivedFrom = p.impacts.edges[1].node.edgeID
    },
  ],
  [
    'dangling causal link',
    (p) => {
      p.impacts.edges[1].node.derivedFrom = userEdgeID(999)
    },
  ],
  [
    'derived cannot cause derived',
    (p) => {
      p.impacts.edges[1].node.derivedFrom = p.impacts.edges[2].node.edgeID
    },
  ],
  [
    'direct cannot carry derivedFrom',
    (p) => {
      p.impacts.edges[0].node.derivedFrom = p.impacts.edges[1].node.edgeID
    },
  ],
  [
    'wrong causal target',
    (p) => {
      p.impacts.edges[1].node.target = userResource(
        'USER',
        '90000000-0000-4000-8000-000000000001',
      )
    },
  ],
  [
    'wrong causal referencing resource',
    (p) => {
      p.impacts.edges[1].node.referencingResource = userResource(
        'ESCALATION_POLICY_ACTION',
        '90000000-0000-4000-8000-000000000001',
      )
    },
  ],
  [
    'wrong causal relation',
    (p) => {
      p.impacts.edges[1].node.relation = 'RULE_TARGET'
    },
  ],
  [
    'wrong causal policy',
    (p) => {
      p.impacts.edges[1].node.policy = 'WARNING'
    },
  ],
  [
    'duplicate EdgeID',
    (p) => {
      p.impacts.edges[1].node.edgeID = p.impacts.edges[0].node.edgeID
    },
  ],
  [
    'incomplete ancestor mapping',
    (p) => {
      p.impacts.edges.pop()
      p.impacts.pageInfo.endCursor = p.impacts.edges[1].cursor
    },
  ],
  [
    'cross organization owner',
    (p) => {
      p.impacts.edges[0].node.owner = {
        ...p.impacts.edges[0].node.owner!,
        organization: {
          id: '90000000-0000-4000-8000-000000000001',
          name: 'Other',
        },
      }
    },
  ],
  [
    'missing organization',
    (p) => {
      p.targets[0].organization = null
    },
  ],
  [
    'extra root',
    (p) => {
      p.targets.push(userResource())
    },
  ],
  [
    'wrong root UUID',
    (p) => {
      p.targets = [userResource('USER', '90000000-0000-4000-8000-000000000001')]
    },
  ],
  [
    'wrong root type',
    (p) => {
      p.targets = [userResource('SCHEDULE')]
    },
  ],
  [
    'unknown relation',
    (p) => {
      p.impacts.edges[0].node.relation = 'INVENTED'
    },
  ],
  [
    'extra private resource field',
    (p) => {
      Object.assign(p.impacts.edges[0].node.affectedResource!, {
        credential: 'synthetic-forbidden-field',
      })
    },
  ],
  [
    'derived is not co-deletion',
    (p) => {
      p.impacts.edges[1].node.isPlannedCoDeletion = true
    },
  ],
]
test.each(invalid)('contract fails closed: %s', async (_name, change) => {
  const p = userActionPreview()
  change(p)
  await expect(load(p)).rejects.toMatchObject({ phase: 'unsupported' })
})
test('a valid but unrelated direct cause cannot authorize a derived explanation', async () => {
  const p = userActionPreview()
  p.impacts.edges.push({ cursor: 'another', node: userImpact(90) })
  p.impacts.pageInfo.endCursor = 'another'
  p.impacts.edges[1].node.derivedFrom = userEdgeID(90)
  await expect(load(p)).rejects.toMatchObject({ phase: 'unsupported' })
})
test.each(['AUTH_SUBJECT', 'BASIC_AUTH_LINK', 'USER_SESSION'])(
  '%s uses only its safe projected resource identity',
  async (type) => {
    const r = userResource(
      type,
      type === 'USER_SESSION' ? '30000000-0000-4000-8000-000000000001' : '17',
    )
    await expect(
      load(
        userPreview([
          userImpact(1, { referencingResource: r, affectedResource: r }),
        ]),
      ),
    ).resolves.toBeDefined()
    r.id = 'opaque-auth-locator-or-credential'
    await expect(
      load(
        userPreview([
          userImpact(1, { referencingResource: r, affectedResource: r }),
        ]),
      ),
    ).rejects.toMatchObject({ phase: 'unsupported' })
  },
)
test('subordinate targets cannot refer to unrelated contact methods', async () => {
  const p = userOwnedPreview()
  p.impacts.edges[2].node.target = userResource(
    'CONTACT_METHOD',
    '90000000-0000-4000-8000-000000000001',
  )
  await expect(load(p)).rejects.toMatchObject({ phase: 'unsupported' })
})
test('optional current organization binding must match the entire preview', async () => {
  await expect(
    loadDeletionPreview(
      profile,
      userID,
      async () => ({ data: { deletionPreview: userPreview() } }),
      () => true,
      jest.fn(),
      undefined,
      '90000000-0000-4000-8000-000000000001',
    ),
  ).rejects.toMatchObject({ phase: 'unsupported' })
  expect(userOrganizationID).not.toBe('')
})
test.each(['version', 'cursor', 'empty', 'stale', 'loop'])(
  'pagination fails closed: %s',
  async (failure) => {
    const p = userActionPreview()
    const rows = p.impacts.edges.map(({ node }) => node)
    const first = split(p, [rows[1]], true)
    const last = split(p, [rows[0], rows[2]], false)
    if (failure === 'version') last.impactVersion += '-changed'
    if (failure === 'cursor')
      last.impacts.edges[0].cursor = first.impacts.edges[0].cursor
    if (failure === 'empty') {
      last.impacts.edges = []
      last.impacts.pageInfo.endCursor = null
    }
    if (failure === 'loop') {
      last.impacts.pageInfo.hasNextPage = true
      last.impacts.pageInfo.endCursor = first.impacts.pageInfo.endCursor
    }
    const fetch = jest
      .fn()
      .mockResolvedValueOnce({ data: { deletionPreview: first } })
      .mockResolvedValueOnce({
        data: { deletionPreview: last },
        stale: failure === 'stale',
      })
    await expect(
      loadDeletionPreview(profile, userID, fetch, () => true, jest.fn()),
    ).rejects.toMatchObject({ phase: 'unsupported' })
  },
)
test('invalidated response is discarded before complete causal verification', async () => {
  let active = true
  await expect(
    loadDeletionPreview(
      profile,
      userID,
      async () => {
        active = false
        return { data: { deletionPreview: userPreview() } }
      },
      () => active,
      jest.fn(),
    ),
  ).rejects.toMatchObject({ phase: 'cancelled' })
})
test('Native UNAVAILABLE fails closed, including a domain-allowed closed cycle', async () => {
  const r = userResource(
    'NOTIFICATION_POLICY_CYCLE',
    '80000000-0000-4000-8000-000000000001',
  )
  await expect(
    load(
      userPreview([
        userImpact(1, {
          relation: 'USER_CYCLE',
          referencingResource: r,
          affectedResource: r,
          policy: 'INFORMATIONAL',
          requiredAction: 'NONE',
        }),
      ]),
    ),
  ).rejects.toMatchObject({ phase: 'unsupported' })
  await expect(
    loadDeletionPreview(
      profile,
      userID,
      async () => ({
        error: {
          graphQLErrors: [{ extensions: { code: 'DELETION_UNAVAILABLE' } }],
        },
      }),
      () => true,
      jest.fn(),
    ),
  ).rejects.toMatchObject({ phase: 'unsupported' })
})

test.each([
  ['RULE_TARGET', 'SCHEDULE_RULE', 'SCHEDULE'],
  ['PARTICIPANT_USER', 'ROTATION_PARTICIPANT', 'ROTATION'],
])(
  'User %s has one retained Parent/Owner explanation',
  async (relation, refType, ownerType) => {
    const ref = userResource(refType, '30000000-0000-4000-8000-000000000001')
    const owner = userResource(
      ownerType,
      '40000000-0000-4000-8000-000000000001',
    )
    const direct = userImpact(1, {
      relation,
      referencingResource: ref,
      parent: owner,
      owner,
      affectedResource: ref,
      policy: 'BLOCK',
      change: 'PRESERVED',
      requiredAction: 'DETACH_REFERENCE',
      isPlannedCoDeletion: false,
    })
    const derived = {
      ...direct,
      edgeID: userEdgeID(2),
      derivedFrom: direct.edgeID,
      isDerived: true,
      affectedResource: owner,
      policy: 'INFORMATIONAL' as const,
      requiredAction: 'NONE',
    }
    expect(isDeletionBlocked(await load(userPreview([derived, direct])))).toBe(
      true,
    )
  },
)
test.each([true, false])(
  'FixedShift with distinct TemporarySchedule Parent/Schedule Owner; ended=%s',
  async (ended) => {
    const parent = userResource(
      'TEMPORARY_SCHEDULE',
      'schedule-data:1:temporary:0',
    )
    const owner = userResource(
      'SCHEDULE',
      '40000000-0000-4000-8000-000000000001',
    )
    const ref = userResource('FIXED_SHIFT', parent.id + ':shift:0')
    const direct = userImpact(1, {
      relation: 'SHIFT_USER',
      referencingResource: ref,
      parent,
      owner,
      affectedResource: ref,
      policy: ended ? 'INFORMATIONAL' : 'BLOCK',
      change: 'PRESERVED',
      requiredAction: ended ? 'NONE' : 'DETACH_REFERENCE',
      isPlannedCoDeletion: false,
    })
    const explanations = [parent, owner].map((affectedResource, n) => ({
      ...direct,
      edgeID: userEdgeID(n + 2),
      derivedFrom: direct.edgeID,
      isDerived: true,
      affectedResource,
      policy: 'INFORMATIONAL' as const,
      requiredAction: 'NONE',
    }))
    expect(
      isDeletionBlocked(await load(userPreview([direct, ...explanations]))),
    ).toBe(!ended)
  },
)
test('ended Override co-deletion keeps its other User target and Schedule as explanations, never roots', async () => {
  const override = userResource(
    'USER_OVERRIDE',
    '30000000-0000-4000-8000-000000000001',
  )
  const schedule = userResource(
    'SCHEDULE',
    '40000000-0000-4000-8000-000000000001',
  )
  const otherUser = userResource('USER', '50000000-0000-4000-8000-000000000001')
  const direct = userImpact(1, {
    relation: 'OVERRIDE_ADD_USER',
    referencingResource: override,
    parent: schedule,
    owner: schedule,
    affectedResource: override,
    policy: 'CASCADE',
  })
  const retained = userImpact(3, {
    relation: 'OVERRIDE_REMOVE_USER',
    target: otherUser,
    referencingResource: override,
    parent: schedule,
    owner: schedule,
    affectedResource: otherUser,
    policy: 'INFORMATIONAL',
    change: 'PRESERVED',
    requiredAction: 'NONE',
  })
  const derived = (d: DeletionImpact, n: number): DeletionImpact => ({
    ...d,
    edgeID: userEdgeID(n),
    isDerived: true,
    derivedFrom: d.edgeID,
    affectedResource: schedule,
    policy: 'INFORMATIONAL',
    change: 'PRESERVED',
    requiredAction: 'NONE',
  })
  const coverage = userImpact(5, {
    relation: 'OVERRIDE_COVERAGE',
    target: override,
    referencingResource: schedule,
    affectedResource: override,
    policy: 'INFORMATIONAL',
    requiredAction: 'NONE',
    isPlannedCoDeletion: false,
  })
  const p = await load(
    userPreview([
      direct,
      derived(direct, 2),
      retained,
      derived(retained, 4),
      coverage,
    ]),
  )
  expect(deleteVariables(profile, userID, p, true).input).toEqual([
    { type: 'user', id: userID },
  ])
})
test.each([
  [
    'USER_ORGANIZATION',
    'ORGANIZATION_ASSIGNMENT',
    userID,
    'INFORMATIONAL',
    'DELETED',
    true,
  ],
  ['FAVORITE', 'FAVORITE', '1', 'INFORMATIONAL', 'DELETED', true],
  ['FAVORITE_OWNER', 'FAVORITE', '2', 'INFORMATIONAL', 'DELETED', true],
  ['USER_LOG', 'ALERT_LOG', '3', 'INFORMATIONAL', 'PRESERVED', false],
  ['SCHEDULE_HISTORY', 'SCHEDULE_HISTORY', '4', 'WARNING', 'DELETED', true],
  ['ESCALATION_HISTORY', 'ESCALATION_HISTORY', '5', 'WARNING', 'DELETED', true],
] as const)(
  '%s preserves its distinct policy/change semantics',
  async (relation, type, id, policy, change, co) => {
    const r = userResource(type, id)
    const p = await load(
      userPreview([
        userImpact(1, {
          relation,
          referencingResource: r,
          affectedResource: r,
          policy,
          change,
          requiredAction: policy === 'WARNING' ? 'CONFIRM_IMPACT' : 'NONE',
          isPlannedCoDeletion: co,
        }),
      ]),
    )
    expect(p.impacts.edges[0].node.change).toBe(change)
    expect(deleteVariables(profile, userID, p, true).input).toHaveLength(1)
  },
)
