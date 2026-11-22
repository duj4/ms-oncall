import { parse, print, buildSchema, validate } from 'graphql'
import { readFileSync, readdirSync } from 'node:fs'
import { resolve } from 'node:path'
import type {
  DeletionImpact,
  DeletionPreview,
  DeletionResource,
} from '../../schema'
import {
  cascadeObjects,
  containsDeleteAll,
  deletionFailure,
  deletionResponseAllowsRefresh,
  deletionResponseSucceeded,
  deletionMutation,
  deletionPreviewQuery,
  epDeleteVariables,
  epPreviewVariables,
  isDeletionBlocked,
  loadEPDeletionPreview,
  PreviewResult,
} from './deletionSafety'

const id = '10000000-0000-4000-8000-000000000001'
function identity(
  type = 'ESCALATION_POLICY',
  resourceID = id,
): DeletionResource {
  return { type, id: resourceID, label: type, name: null, organization: null }
}
function edge(
  n = 1,
  extra: Partial<DeletionImpact> = {},
): DeletionPreview['impacts']['edges'][number] {
  return {
    cursor: 'cursor-' + n,
    node: {
      edgeID: 'edge-' + n,
      target: identity(),
      referencingResource: identity('ESCALATION_POLICY_STEP', String(n)),
      parent: identity(),
      relation: 'POLICY_STEP',
      change: 'DELETED',
      policy: 'CASCADE',
      requiredAction: 'CONFIRM_IMPACT',
      impact: 'The affected resource would be deleted.',
      isDerived: false,
      isPlannedCoDeletion: false,
      canModifyReference: true,
      ...extra,
    },
  }
}
function fixture(extra: Partial<DeletionPreview> = {}): DeletionPreview {
  return {
    operation: 'DELETE_RESOURCES',
    targets: [identity()],
    impactVersion: 'opaque version, unchanged',
    policyVersion: 'deletion-safety-spec1-v2',
    assessedAt: '2026-11-21T10:00:00Z',
    complete: true,
    canProceed: true,
    requiresConfirmation: false,
    notices: [],
    impacts: { edges: [], pageInfo: { endCursor: null, hasNextPage: false } },
    ...extra,
  }
}
const alive = (): boolean => true
function load(
  pages: PreviewResult[],
  progress = jest.fn(),
): ReturnType<typeof loadEPDeletionPreview> {
  return loadEPDeletionPreview(
    id,
    jest.fn().mockImplementation(async () => pages.shift()),
    alive,
    progress,
  )
}
function page(
  edges: ReturnType<typeof edge>[],
  hasNextPage = false,
): DeletionPreview['impacts'] {
  return {
    edges,
    pageInfo: {
      endCursor: edges[edges.length - 1]?.cursor || null,
      hasNextPage,
    },
  }
}

test('wire contracts use actual fields, non-null delete variables and one EP', () => {
  expect(epPreviewVariables(id, null)).toEqual({
    input: {
      operation: 'DELETE_RESOURCES',
      targets: [{ type: 'ESCALATION_POLICY', id }],
    },
    first: 100,
    after: null,
  })
  const p = fixture()
  expect(epDeleteVariables(id, p, true)).toEqual({
    input: [{ type: 'escalationPolicy', id }],
    confirmation: {
      expectedImpactVersion: p.impactVersion,
      acknowledgeImpacts: false,
    },
  })
  p.requiresConfirmation = true
  expect(() => epDeleteVariables(id, p, false)).toThrow()
  expect(epDeleteVariables(id, p, true).confirmation.acknowledgeImpacts).toBe(
    true,
  )
  expect(() => epDeleteVariables('other', p, true)).toThrow()
  expect(print(deletionMutation)).toContain(
    '$confirmation: DeletionSafetyConfirmationInput!',
  )
  expect(print(deletionMutation)).toContain('$input: [TargetInput!]!')
  expect(print(deletionPreviewQuery)).toContain('edgeID')
})

test('serial complete pagination accepts differing assessedAt, preserves exact version and cursor', async () => {
  const progress = jest.fn()
  const fetchPage = jest
    .fn()
    .mockResolvedValueOnce({
      data: {
        deletionPreview: fixture({
          requiresConfirmation: true,
          impacts: page([edge()], true),
        }),
      },
    })
    .mockResolvedValueOnce({
      data: {
        deletionPreview: fixture({
          requiresConfirmation: true,
          assessedAt: '2026-11-21T10:01:00Z',
          impacts: page([edge(2)]),
        }),
      },
    })
  const p = await loadEPDeletionPreview(id, fetchPage, alive, progress)
  expect(fetchPage.mock.calls).toEqual([
    [epPreviewVariables(id, null)],
    [epPreviewVariables(id, 'cursor-1')],
  ])
  expect(progress).toHaveBeenCalledWith(1)
  expect(p.impacts.edges).toHaveLength(2)
  expect(p.impactVersion).toBe('opaque version, unchanged')
})

test('an empty first page remains a valid complete review', async () => {
  const p = await load([{ data: { deletionPreview: fixture() } }])
  expect(p.impacts.edges).toEqual([])
  expect(epDeleteVariables(id, p, false).confirmation.acknowledgeImpacts).toBe(
    false,
  )
})

test.each<[string, DeletionPreview['impacts']]>([
  ['empty terminal page', page([])],
  ['empty continuing page', page([], true)],
  [
    'missing successor cursor',
    { edges: [edge(101)], pageInfo: { endCursor: null, hasNextPage: false } },
  ],
  [
    'non-advancing successor cursor',
    page([{ ...edge(101), cursor: 'cursor-100' }]),
  ],
])(
  '100 edges followed by %s discards the entire plan',
  async (_name, impacts) => {
    const progress = jest.fn()
    await expect(
      load(
        [
          {
            data: {
              deletionPreview: fixture({
                requiresConfirmation: true,
                impacts: page(
                  Array.from({ length: 100 }, (_, n) => edge(n + 1)),
                  true,
                ),
              }),
            },
          },
          {
            data: {
              deletionPreview: fixture({ requiresConfirmation: true, impacts }),
            },
          },
        ],
        progress,
      ),
    ).rejects.toMatchObject({ phase: 'unsupported' })
    expect(progress).toHaveBeenCalledTimes(1)
    expect(progress).toHaveBeenCalledWith(100)
  },
)

test('100 edges followed by a nonempty terminal page produces a complete review', async () => {
  const p = await load([
    {
      data: {
        deletionPreview: fixture({
          requiresConfirmation: true,
          impacts: page(
            Array.from({ length: 100 }, (_, n) => edge(n + 1)),
            true,
          ),
        }),
      },
    },
    {
      data: {
        deletionPreview: fixture({
          requiresConfirmation: true,
          impacts: page([edge(101)]),
        }),
      },
    },
  ])
  expect(p.impacts.edges).toHaveLength(101)
  expect(p.impacts.pageInfo.hasNextPage).toBe(false)
})

test.each([
  { complete: false },
  { policyVersion: 'future' },
  { operation: 'UPDATE_ROTATION' },
  { impactVersion: '' },
  { assessedAt: 'invalid' },
  { targets: [] },
  { targets: [identity('SERVICE')] },
  { targets: [identity(), identity()] },
  { targets: [{ ...identity(), organization: {} }] },
  { requiresConfirmation: null },
])('fails closed on malformed/incompatible preview %j', async (extra) => {
  await expect(
    load([{ data: { deletionPreview: { ...fixture(), ...extra } } }]),
  ).rejects.toMatchObject({ phase: 'unsupported' })
})

test.each([
  { relation: 'FUTURE' },
  { change: 'FUTURE' },
  { requiredAction: 'FUTURE' },
  { policy: 'FUTURE' },
  { target: identity('PRIVATE_UNKNOWN') },
  { parent: {} },
  { isDerived: null },
  { edgeID: '' },
])('fails closed on unknown or missing impact fields %j', async (extra) => {
  const p = fixture({
    requiresConfirmation: true,
    impacts: page([
      { ...edge(), node: { ...edge().node, ...extra } as DeletionImpact },
    ]),
  })
  await expect(load([{ data: { deletionPreview: p } }])).rejects.toMatchObject({
    phase: 'unsupported',
  })
})

test.each([
  'impactVersion',
  'policyVersion',
  'canProceed',
  'requiresConfirmation',
] as const)('rejects cross-page %s changes', async (key) => {
  const a = fixture({
    requiresConfirmation: true,
    impacts: page([edge()], true),
  })
  const b = fixture({ requiresConfirmation: true, impacts: page([edge(2)]) })
  const changed = {
    ...b,
    [key]: typeof b[key] === 'boolean' ? !b[key] : 'different',
  }
  await expect(
    load([
      { data: { deletionPreview: a } },
      { data: { deletionPreview: changed } },
    ]),
  ).rejects.toMatchObject({ phase: 'unsupported' })
})

test.each([
  page([], true),
  { edges: [edge()], pageInfo: { hasNextPage: true, endCursor: null } },
  page([{ ...edge(), cursor: '' }]),
  page([edge(), edge()]),
])('rejects malformed pagination %j', async (impacts) => {
  await expect(
    load([
      {
        data: {
          deletionPreview: fixture({ requiresConfirmation: true, impacts }),
        },
      },
    ]),
  ).rejects.toMatchObject({ phase: 'unsupported' })
})

test('duplicate/conflicting edge IDs or cursors across pages discard the plan', async () => {
  for (const second of [
    edge(),
    { ...edge(2), node: { ...edge(2).node, edgeID: 'edge-1' } },
    { ...edge(2), cursor: 'cursor-1' },
  ]) {
    await expect(
      load([
        {
          data: {
            deletionPreview: fixture({
              requiresConfirmation: true,
              impacts: page([edge()], true),
            }),
          },
        },
        {
          data: {
            deletionPreview: fixture({
              requiresConfirmation: true,
              impacts: page([second]),
            }),
          },
        },
      ]),
    ).rejects.toMatchObject({ phase: 'unsupported' })
  }
})

test('partial GraphQL data, stale and incremental results cannot unlock deletion', async () => {
  for (const result of [
    {
      data: { deletionPreview: fixture() },
      error: {
        graphQLErrors: [{ extensions: { code: 'DELETION_UNAVAILABLE' } }],
      },
    },
    { data: { deletionPreview: fixture() }, stale: true },
    { data: { deletionPreview: fixture() }, hasNext: true },
    {},
  ])
    await expect(load([result])).rejects.toThrow()
})

test('no promise resolution or submit eligibility while more pages remain', async () => {
  let complete: (value: PreviewResult) => void = () => {}
  const second = new Promise<PreviewResult>((resolve) => {
    complete = resolve
  })
  const fetchPage = jest
    .fn()
    .mockResolvedValueOnce({
      data: {
        deletionPreview: fixture({
          requiresConfirmation: true,
          impacts: page([edge()], true),
        }),
      },
    })
    .mockReturnValueOnce(second)
  let settled = false
  const pending = loadEPDeletionPreview(id, fetchPage, alive, jest.fn()).then(
    (value) => {
      settled = true
      return value
    },
  )
  await Promise.resolve()
  await Promise.resolve()
  expect(settled).toBe(false)
  complete({
    data: {
      deletionPreview: fixture({
        requiresConfirmation: true,
        impacts: page([edge(2)]),
      }),
    },
  })
  await pending
  expect(settled).toBe(true)
})

test('cancel invalidates a late response and prevents additional pages', async () => {
  let active = true
  const fetchPage = jest.fn(async () => {
    active = false
    return {
      data: { deletionPreview: fixture({ impacts: page([edge()], true) }) },
    }
  })
  await expect(
    loadEPDeletionPreview(id, fetchPage, () => active, jest.fn()),
  ).rejects.toMatchObject({ phase: 'cancelled' })
  expect(fetchPage).toHaveBeenCalledTimes(1)
})

test('pagination is bounded by the merged impact budget', async () => {
  let n = 0
  const fetchPage = jest.fn(async () => ({
    data: {
      deletionPreview: fixture({
        requiresConfirmation: true,
        impacts: page([edge(++n)], true),
      }),
    },
  }))
  await expect(
    loadEPDeletionPreview(id, fetchPage, alive, jest.fn()),
  ).rejects.toMatchObject({ phase: 'limit' })
  expect(fetchPage).toHaveBeenCalledTimes(300)
})

test('BLOCK is authoritative even with canProceed=true; pending pages cannot submit', () => {
  const p = fixture({
    impacts: page([
      edge(1, {
        policy: 'BLOCK',
        change: 'PRESERVED',
        requiredAction: 'DETACH_REFERENCE',
      }),
    ]),
  })
  expect(isDeletionBlocked(p)).toBe(true)
  expect(() => epDeleteVariables(id, p, true)).toThrow()
  expect(() =>
    epDeleteVariables(id, fixture({ canProceed: false }), true),
  ).toThrow()
  expect(() =>
    epDeleteVariables(id, fixture({ impacts: page([edge()], true) }), true),
  ).toThrow()
})

test('only verified Step/Action cascade objects count; derived and retained relations do not', () => {
  const action = identity('ESCALATION_POLICY_ACTION', 'action-1')
  const p = fixture({
    impacts: page([
      edge(),
      edge(2, { relation: 'POLICY_ACTION', referencingResource: action }),
      edge(3, { relation: 'STEP_ACTION', referencingResource: action }),
      edge(4, { isDerived: true }),
      edge(5, { policy: 'INFORMATIONAL', relation: 'FAVORITE' }),
      edge(6, { relation: 'STEP_ROUTING', policy: 'WARNING' }),
    ]),
  })
  expect(cascadeObjects(p)).toHaveLength(2)
})

test.each([
  ['DELETION_BLOCKED', 'blocked'],
  ['DELETION_CONFIRMATION_REQUIRED', 'recheck'],
  ['DELETION_DEPENDENCY_CHANGED', 'recheck'],
  ['DELETION_PREVIEW_LIMIT_EXCEEDED', 'limit'],
  ['DELETION_UNAVAILABLE', 'unsupported'],
  ['UNKNOWN', 'unknown'],
])('classifies %s safely', (code, phase) => {
  expect(deletionFailure({ graphQLErrors: [{ extensions: { code } }] })).toBe(
    phase,
  )
})
test('transport errors and mixed errors always leave commit unknown; field errors remain rejection', () => {
  expect(deletionFailure({ networkError: new Error('synthetic') })).toBe(
    'unknown',
  )
  expect(deletionFailure()).toBe('unknown')
  expect(
    deletionFailure({
      graphQLErrors: [{ extensions: { isFieldError: true } }],
    }),
  ).toBe('failed')
  expect(
    deletionFailure({
      graphQLErrors: [{ extensions: { code: 'DELETION_BLOCKED' } }, {}],
    }),
  ).toBe('unknown')
})
test('AST detects real fields behind aliases/fragments, not operation names or strings', () => {
  expect(containsDeleteAll(parse('mutation { removed: deleteAll }'))).toBe(true)
  expect(
    containsDeleteAll(
      parse('mutation { ...D } fragment D on Mutation { removed: deleteAll }'),
    ),
  ).toBe(true)
  expect(
    containsDeleteAll(
      parse(
        'mutation deleteAll { updateService(input: {name: "deleteAll"}) { id } }',
      ),
    ),
  ).toBe(false)
})

test.each([
  { stale: true },
  { hasNext: true },
  { error: { networkError: new Error('Synthetic transport failure') } },
])(
  'uncertain Delete results never refresh, even with sibling data: %j',
  (extra) => {
    expect(
      deletionResponseAllowsRefresh(
        parse('mutation { deleteAll setFavorite }'),
        { data: { deleteAll: true, setFavorite: true }, ...extra },
      ),
    ).toBe(false)
  },
)

test.each([
  'mutation { deleteAll @skip(if: $unknown) setFavorite }',
  'mutation { ...Missing setFavorite }',
  'mutation { ...Cycle setFavorite } fragment Cycle on Mutation { ...Cycle deleteAll }',
  'mutation One { deleteAll } mutation Two { setFavorite }',
])('undetermined selected fields fail closed: %s', (text) => {
  expect(
    deletionResponseAllowsRefresh(parse(text), {
      data: { deleteAll: true, setFavorite: true },
    }),
  ).toBe(false)
})

test('selected operation name and reachable root fields determine Delete success', () => {
  const document = parse(`
    mutation Favorite { setFavorite }
    mutation Delete($include: Boolean = true) { ...Outer ...Outer }
    fragment Outer on Mutation { ... on Mutation @include(if: $include) { removed: deleteAll } }
    fragment Unused on Mutation { other: deleteAll }
  `)
  expect(
    deletionResponseSucceeded(document, { removed: true }, {}, 'Delete'),
  ).toBe(true)
  expect(
    deletionResponseSucceeded(
      document,
      { removed: false, setFavorite: true },
      {},
      'Delete',
    ),
  ).toBe(false)
  expect(
    deletionResponseSucceeded(document, { setFavorite: true }, {}, 'Favorite'),
  ).toBe(false)
  expect(
    deletionResponseSucceeded(
      document,
      { removed: true },
      { include: false },
      'Delete',
    ),
  ).toBe(false)
  expect(
    deletionResponseAllowsRefresh(
      document,
      { data: { setFavorite: true } },
      {},
      'Favorite',
    ),
  ).toBe(true)
})

test('a successful sibling does not turn a false, missing or skipped Delete into success', () => {
  for (const text of [
    'mutation { deleteAll setFavorite }',
    'mutation { deleteAll @skip(if: true) setFavorite }',
    'mutation { setFavorite { deleteAll } }',
  ]) {
    const document = parse(text)
    for (const deleteAll of [false, null, undefined]) {
      const data = { deleteAll, setFavorite: true }
      expect(deletionResponseSucceeded(document, data)).toBe(false)
      expect(deletionResponseAllowsRefresh(document, { data })).toBe(true)
    }
  }
})

test('unscoped GraphQL errors cannot prove a successful sibling', () => {
  expect(
    deletionResponseAllowsRefresh(parse('mutation { deleteAll setFavorite }'), {
      data: { deleteAll: false, setFavorite: true },
      error: { graphQLErrors: [{}] },
    }),
  ).toBe(false)
})

test('unexpected response fields fail closed; GraphQL __typename remains compatible', async () => {
  const base = fixture({ requiresConfirmation: true, impacts: page([edge()]) })
  const malformed = [
    { ...base, unexpected: 'synthetic-sensitive-sentinel' },
    {
      ...base,
      targets: [
        { ...base.targets[0], destination: 'synthetic-sensitive-sentinel' },
      ],
    },
    { ...base, impacts: { ...base.impacts, extra: true } },
    {
      ...base,
      impacts: {
        ...base.impacts,
        edges: [{ ...edge(), node: { ...edge().node, extra: true } }],
      },
    },
  ]
  for (const value of malformed)
    await expect(
      load([{ data: { deletionPreview: value } }]),
    ).rejects.toMatchObject({ phase: 'unsupported' })
  const typed = Object.assign(fixture(), { __typename: 'DeletionPreview' })
  Object.assign(typed.targets[0], { __typename: 'DeletionResource' })
  await expect(
    load([{ data: { deletionPreview: typed } }]),
  ).resolves.toMatchObject({ complete: true })
})
test.each([
  ['DELETION_PREVIEW_LIMIT_EXCEEDED', 'limit'],
  ['DELETION_UNAVAILABLE', 'unsupported'],
])('preview %s discards partial data', async (code, phase) => {
  await expect(
    load([
      {
        data: { deletionPreview: fixture() },
        error: { graphQLErrors: [{ extensions: { code } }] },
      },
    ]),
  ).rejects.toMatchObject({ phase })
})

test('both client documents validate against the exact merged GraphQL schema', () => {
  const directory = resolve(__dirname, '../../../../graphql2')
  const graph = resolve(directory, 'graph')
  const schema = buildSchema(
    readFileSync(resolve(directory, 'schema.graphql'), 'utf8') +
      '\n' +
      readdirSync(graph)
        .filter((name) => name.endsWith('.graphqls'))
        .map((name) => readFileSync(resolve(graph, name), 'utf8'))
        .join('\n'),
  )
  expect(validate(schema, deletionPreviewQuery)).toEqual([])
  expect(validate(schema, deletionMutation)).toEqual([])
})
