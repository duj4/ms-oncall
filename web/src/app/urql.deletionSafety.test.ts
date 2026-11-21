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
])(
  'real retry exchange sends one physical request for %s despite all retry timers',
  async (text) => {
    expect(await failures(gql(text))).toBe(1)
  },
)
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
