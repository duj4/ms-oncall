import { gql } from 'urql'
import { pipe, subscribe } from 'wonka'
import { GraphQLClient, GraphQLClientWithErrors } from './apollo'
type UrqlClient = import('urql').Client
type Document = import('graphql').DocumentNode

jest.mock('./apollo', () => ({
  GraphQLClient: { reFetchObservableQueries: jest.fn() },
  GraphQLClientWithErrors: { reFetchObservableQueries: jest.fn() },
  refetchOrganizationQueries: jest.fn(async () => {}),
}))
jest.mock('./env', () => ({ pathPrefix: '', isCypress: true }))

// Import the real client/exchanges only after supplying the browser globals.
let newClient: (typeof import('./urql'))['newClient']
let disposeClient: (typeof import('./urql'))['disposeClient']
const originalFetch = global.fetch
beforeAll(() => {
  Object.assign(global, {
    window: { addEventListener: jest.fn() },
    location: { search: '?poll=0' },
  })
  ;({ newClient, disposeClient } = jest.requireActual('./urql'))
})
beforeEach(() => {
  jest.useFakeTimers()
  jest.clearAllMocks()
})
afterEach(() => {
  global.fetch = originalFetch
  jest.useRealTimers()
})

async function failures(
  document: Document,
  kind: 'mutation' | 'query' = 'mutation',
): Promise<number> {
  const fetcher = jest
    .fn()
    .mockRejectedValue(new TypeError('synthetic network failure'))
  global.fetch = fetcher
  const client: UrqlClient = newClient(
    'https://deletion-safety.invalid/api/graphql',
  )
  const source =
    kind === 'mutation'
      ? client.mutation(document, {})
      : client.query(document, {}, { requestPolicy: 'network-only' })
  let results = 0
  const subscription = pipe(
    source,
    subscribe(() => {
      results++
    }),
  )
  await jest.advanceTimersByTimeAsync(0)
  const first = fetcher.mock.calls.length
  expect(first).toBe(1)
  await jest.runAllTimersAsync()
  expect(results).toBe(1)
  const count = fetcher.mock.calls.length
  subscription.unsubscribe()
  disposeClient(client)
  return count
}

test.each([
  'mutation { deleteAll }',
  'mutation { removed: deleteAll }',
  'mutation { ...D } fragment D on Mutation { removed: deleteAll }',
  'mutation { ...Outer } fragment Outer on Mutation { ...Inner } fragment Inner on Mutation { deleteAll @skip(if: true) }',
  'mutation { deleteAll @include(if: false) setFavorite }',
])(
  'real retry exchange sends one physical request for %s despite all retry timers',
  async (text) => {
    expect(await failures(gql(text))).toBe(1)
  },
)

const favorite = `setFavorite(input: {
  target: { type: escalationPolicy, id: "10000000-0000-4000-8000-000000000001" }
  favorite: true
})`
interface RefreshCase {
  name: string
  text: string
  variables?: Record<string, unknown>
  body?: {
    data?: Record<string, unknown> | null
    errors?: Array<{ message: string; path?: string[] }>
  }
  networkError?: boolean
  cache: boolean
  apollo: boolean
  operationName?: string
}
const refreshCases: RefreshCase[] = [
  {
    name: 'ordinary delete success',
    text: 'mutation { deleteAll(input: []) }',
    body: { data: { deleteAll: true } },
    cache: true,
    apollo: true,
  },
  ...[false, null, undefined].map(
    (value): RefreshCase => ({
      name: 'delete result ' + String(value),
      text: 'mutation { deleteAll(input: []) }',
      body: { data: value === undefined ? {} : { deleteAll: value } },
      cache: false,
      apollo: false,
    }),
  ),
  {
    name: 'missing data',
    text: 'mutation { deleteAll(input: []) }',
    body: {},
    cache: false,
    apollo: false,
  },
  {
    name: 'null data',
    text: 'mutation { deleteAll(input: []) }',
    body: { data: null },
    cache: false,
    apollo: false,
  },
  {
    name: 'delete transport failure',
    text: 'mutation { deleteAll(input: []) }',
    networkError: true,
    cache: false,
    apollo: false,
  },
  {
    name: 'GraphQL error with true',
    text: 'mutation { deleteAll(input: []) }',
    body: {
      data: { deleteAll: true },
      errors: [{ message: 'Synthetic rejection', path: ['deleteAll'] }],
    },
    cache: false,
    apollo: false,
  },
  {
    name: 'delete alias',
    text: 'mutation { removed: deleteAll(input: []) }',
    body: { data: { removed: true } },
    cache: true,
    apollo: true,
  },
  {
    name: 'wrong response key',
    text: 'mutation { removed: deleteAll(input: []) }',
    body: { data: { deleteAll: true } },
    cache: false,
    apollo: false,
  },
  {
    name: 'nested reachable fragments',
    text: 'mutation { ...Outer } fragment Outer on Mutation { ...Inner } fragment Inner on Mutation { removed: deleteAll(input: []) }',
    body: { data: { removed: true } },
    cache: true,
    apollo: true,
  },
  {
    name: 'skip Delete with successful Favorite (R1-F02)',
    text: `mutation { deleteAll(input: []) @skip(if: true) ${favorite} }`,
    body: { data: { setFavorite: true } },
    cache: true,
    apollo: true,
  },
  {
    name: 'exclude Delete with successful Favorite',
    text: `mutation { deleteAll(input: []) @include(if: false) ${favorite} }`,
    body: { data: { setFavorite: true } },
    cache: true,
    apollo: true,
  },
  {
    name: 'skip spread and nested Delete',
    text: `mutation { ...Outer @skip(if: true) ${favorite} } fragment Outer on Mutation { ...Inner } fragment Inner on Mutation { deleteAll(input: []) }`,
    body: { data: { setFavorite: true } },
    cache: true,
    apollo: true,
  },
  {
    name: 'exclude inline fragment',
    text: `mutation { ... on Mutation @include(if: false) { deleteAll(input: []) } ${favorite} }`,
    body: { data: { setFavorite: true } },
    cache: true,
    apollo: true,
  },
  {
    name: 'variable skips Delete',
    text: `mutation Change($skip: Boolean!) { deleteAll(input: []) @skip(if: $skip) ${favorite} }`,
    variables: { skip: true },
    body: { data: { setFavorite: true } },
    cache: true,
    apollo: true,
    operationName: 'Change',
  },
  {
    name: 'variable executes Delete',
    text: `mutation Change($skip: Boolean!) { deleteAll(input: []) @skip(if: $skip) ${favorite} @skip(if: true) }`,
    variables: { skip: false },
    body: { data: { deleteAll: false } },
    cache: false,
    apollo: false,
    operationName: 'Change',
  },
  {
    name: 'default excludes Delete',
    text: `mutation Change($include: Boolean = false) { deleteAll(input: []) @include(if: $include) ${favorite} }`,
    body: { data: { setFavorite: true } },
    cache: true,
    apollo: true,
    operationName: 'Change',
  },
  {
    name: 'variable overrides default and executes Delete',
    text: `mutation Change($include: Boolean = false) { deleteAll(input: []) @include(if: $include) }`,
    variables: { include: true },
    body: { data: { deleteAll: true } },
    cache: true,
    apollo: true,
    operationName: 'Change',
  },
  {
    name: 'null directive is unknown',
    text: `mutation Change($skip: Boolean = true) { deleteAll(input: []) @skip(if: $skip) ${favorite} }`,
    variables: { skip: null },
    body: { data: { setFavorite: true } },
    cache: false,
    apollo: false,
    operationName: 'Change',
  },
  {
    name: 'unselected Delete operation',
    text: `mutation Favorite { ${favorite} } mutation Delete { ...D } fragment D on Mutation { deleteAll(input: []) }`,
    body: { data: { setFavorite: true } },
    cache: true,
    apollo: true,
    operationName: 'Favorite',
  },
  {
    name: 'selected Delete ignores other operation',
    text: `mutation Delete { ...D } mutation Favorite { ${favorite} } fragment D on Mutation { deleteAll(input: []) }`,
    body: { data: { deleteAll: false } },
    cache: false,
    apollo: false,
    operationName: 'Delete',
  },
  {
    name: 'unreachable fragment',
    text: `mutation Favorite { ${favorite} } fragment D on Mutation { deleteAll(input: []) }`,
    body: { data: { setFavorite: true } },
    cache: true,
    apollo: true,
    operationName: 'Favorite',
  },
  {
    name: 'ordinary Favorite',
    text: `mutation { ${favorite} }`,
    body: { data: { setFavorite: true } },
    cache: true,
    apollo: true,
  },
  {
    name: 'failed Delete and successful Favorite alias',
    text: `mutation { deleteAll(input: []) saved: ${favorite} }`,
    body: { data: { deleteAll: false, saved: true } },
    cache: true,
    apollo: true,
  },
  {
    name: 'null Delete and successful Favorite',
    text: `mutation { deleteAll(input: []) ${favorite} }`,
    body: { data: { deleteAll: null, setFavorite: true } },
    cache: true,
    apollo: true,
  },
  {
    name: 'missing Delete and skipped Favorite cannot prove sibling success',
    text: `mutation { deleteAll(input: []) ${favorite} @skip(if: true) }`,
    body: { data: { setFavorite: true } },
    cache: false,
    apollo: false,
  },
  {
    name: 'missing Delete and false Favorite',
    text: `mutation { deleteAll(input: []) ${favorite} }`,
    body: { data: { setFavorite: false } },
    cache: false,
    apollo: false,
  },
  {
    name: 'Delete error keeps successful Favorite cache and original error rule',
    text: `mutation { deleteAll(input: []) ${favorite} }`,
    body: {
      data: { deleteAll: null, setFavorite: true },
      errors: [{ message: 'Synthetic delete error', path: ['deleteAll'] }],
    },
    cache: true,
    apollo: false,
  },
  {
    name: 'Favorite error is not successful sibling evidence',
    text: `mutation { deleteAll(input: []) ${favorite} }`,
    body: {
      data: { deleteAll: false, setFavorite: true },
      errors: [{ message: 'Synthetic Favorite error', path: ['setFavorite'] }],
    },
    cache: false,
    apollo: false,
  },
]

test.each(refreshCases)(
  'actual client/cache/retry/fetch exchanges: $name',
  async (scenario) => {
    let queries = 0
    const mutations: Array<{ operationName?: string }> = []
    global.fetch = jest.fn(async (_url: unknown, options: RequestInit) => {
      const body = JSON.parse(String(options.body))
      const isMutation = body.query.includes('mutation')
      if (isMutation) {
        mutations.push(body)
        if (scenario.networkError)
          throw new TypeError('Synthetic network failure')
      } else queries++
      return new Response(
        JSON.stringify(
          isMutation
            ? scenario.body
            : {
                data: {
                  escalationPolicy: {
                    __typename: 'EscalationPolicy',
                    id: 'synthetic-policy',
                  },
                },
              },
        ),
        { headers: { 'Content-Type': 'application/json' } },
      )
    }) as typeof fetch
    const client = newClient('https://deletion-safety.invalid/api/graphql')
    const watch = pipe(
      client.query(
        gql`
          query {
            escalationPolicy(id: "synthetic-policy") {
              id
            }
          }
        `,
        {},
      ),
      subscribe(() => {}),
    )
    try {
      await jest.runAllTimersAsync()
      expect(queries).toBe(1)
      const context = { additionalTypenames: ['EscalationPolicy'] }
      const pending = client
        .mutation(gql(scenario.text), scenario.variables || {}, context)
        .toPromise()
      await jest.runAllTimersAsync()
      const result = await pending
      expect(mutations).toHaveLength(1)
      expect(mutations[0].operationName).toBe(scenario.operationName)
      expect(queries).toBe(scenario.cache ? 2 : 1)
      expect(GraphQLClient.reFetchObservableQueries).toHaveBeenCalledTimes(
        scenario.apollo ? 1 : 0,
      )
      expect(
        GraphQLClientWithErrors.reFetchObservableQueries,
      ).toHaveBeenCalledTimes(scenario.apollo ? 1 : 0)
      expect(context.additionalTypenames).toEqual(['EscalationPolicy'])
      expect(result.data).toEqual(scenario.body?.data)
      expect(!!result.error).toBe(
        !!scenario.networkError ||
          !!scenario.body?.errors ||
          !scenario.body ||
          !('data' in scenario.body),
      )
      if (scenario.body?.errors) {
        expect(
          result.error?.graphQLErrors.map(({ message, path }) => ({
            message,
            path,
          })),
        ).toEqual(scenario.body.errors)
      }
      if (scenario.networkError)
        expect(result.error?.networkError?.message).toBe(
          'Synthetic network failure',
        )
    } finally {
      watch.unsubscribe()
      disposeClient(client)
    }
  },
)

test('actual fetchExchange partial Delete result does not invalidate or bridge success', async () => {
  let queries = 0
  let mutations = 0
  global.fetch = jest.fn(async (_url: unknown, options: RequestInit) => {
    const body = JSON.parse(String(options.body))
    const mutation = body.query.includes('mutation')
    if (mutation) mutations++
    else queries++
    return new Response(
      JSON.stringify(
        mutation
          ? {
              data: { deleteAll: true },
              hasNext: true,
            }
          : {
              data: {
                escalationPolicy: {
                  __typename: 'EscalationPolicy',
                  id: 'synthetic-policy',
                },
              },
            },
      ),
      { headers: { 'Content-Type': 'application/json' } },
    )
  }) as typeof fetch
  const client = newClient('https://deletion-safety.invalid/api/graphql')
  const watch = pipe(
    client.query(
      gql`
        query {
          escalationPolicy(id: "synthetic-policy") {
            id
          }
        }
      `,
      {},
    ),
    subscribe(() => {}),
  )
  await jest.runAllTimersAsync()
  const results: Array<import('urql').OperationResult> = []
  const mutation = pipe(
    client.mutation(
      gql`
        mutation {
          deleteAll(input: [])
        }
      `,
      {},
      {
        additionalTypenames: ['EscalationPolicy'],
      },
    ),
    subscribe((result) => results.push(result)),
  )
  try {
    await jest.runAllTimersAsync()
    expect(mutations).toBe(1)
    expect(queries).toBe(1)
    expect(results).toHaveLength(1)
    expect(results[0].data).toEqual({ deleteAll: true })
    expect(results[0].hasNext).toBe(true)
    expect(results[0].error).toBeUndefined()
    expect(GraphQLClient.reFetchObservableQueries).not.toHaveBeenCalled()
    expect(
      GraphQLClientWithErrors.reFetchObservableQueries,
    ).not.toHaveBeenCalled()
  } finally {
    mutation.unsubscribe()
    watch.unsubscribe()
    disposeClient(client)
  }
})
test.each([
  'createService',
  'createEscalationPolicy',
  'createSchedule',
  'createRotation',
])('existing %s create protection remains', async (name) => {
  expect(await failures(gql(`mutation { result: ${name} { id } }`))).toBe(1)
})
test('unrelated query and mutation retain their actual two-attempt network policy', async () => {
  expect(
    await failures(
      gql`
        query {
          services {
            nodes {
              id
            }
          }
        }
      `,
      'query',
    ),
  ).toBe(2)
  expect(
    await failures(gql`
      mutation {
        updateService {
          id
        }
      }
    `),
  ).toBe(2)
})
test.each([true, false, null])(
  'Apollo bridge refreshes exactly once only for deleteAll=true (%s)',
  async (value) => {
    global.fetch = jest.fn().mockResolvedValue(
      new Response(JSON.stringify({ data: { removed: value } }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }),
    )
    const client = newClient('https://deletion-safety.invalid/api/graphql')
    const result = client
      .mutation(
        gql`
          mutation {
            removed: deleteAll
          }
        `,
        {},
      )
      .toPromise()
    await jest.runAllTimersAsync()
    await result
    expect(GraphQLClient.reFetchObservableQueries).toHaveBeenCalledTimes(
      value === true ? 1 : 0,
    )
    expect(
      GraphQLClientWithErrors.reFetchObservableQueries,
    ).toHaveBeenCalledTimes(value === true ? 1 : 0)
    disposeClient(client)
  },
)

test.each([true, false])(
  'actual cache exchange invalidates a watched EP only after confirmed success (%s)',
  async (value) => {
    const fetcher = jest.fn(async (_url: unknown, options: RequestInit) => {
      const body = JSON.parse(String(options.body))
      const data = body.query.includes('mutation')
        ? { deleteAll: value }
        : {
            escalationPolicy: {
              __typename: 'EscalationPolicy',
              id: 'synthetic-policy',
            },
          }
      return new Response(JSON.stringify({ data }), {
        headers: { 'Content-Type': 'application/json' },
      })
    })
    global.fetch = fetcher as typeof fetch
    const client = newClient('https://deletion-safety.invalid/api/graphql')
    const watched = pipe(
      client.query(
        gql`
          query {
            escalationPolicy(id: "synthetic-policy") {
              id
            }
          }
        `,
        {},
      ),
      subscribe(() => {}),
    )
    await jest.runAllTimersAsync()
    expect(fetcher).toHaveBeenCalledTimes(1)
    const result = client
      .mutation(
        gql`
          mutation {
            deleteAll
          }
        `,
        {},
        { additionalTypenames: ['EscalationPolicy'] },
      )
      .toPromise()
    await jest.runAllTimersAsync()
    await result
    expect(fetcher).toHaveBeenCalledTimes(value ? 3 : 2)
    expect(GraphQLClient.reFetchObservableQueries).toHaveBeenCalledTimes(
      value ? 1 : 0,
    )
    watched.unsubscribe()
    disposeClient(client)
  },
)
