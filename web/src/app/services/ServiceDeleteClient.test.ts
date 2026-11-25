import { gql } from 'urql'
import { pipe, subscribe } from 'wonka'
import { GraphQLClient, GraphQLClientWithErrors } from '../apollo'
import {
  deletionMutation,
  deleteVariables,
  deletionPreviewQuery,
  loadDeletionPreview,
} from '../util/deletionSafety'
import { serviceDeletionProfile as profile } from '../util/deletionSafetyProfiles'
import { serviceID as id, servicePreview } from './serviceDeletionFixtures'
jest.mock('../apollo', () => ({
  GraphQLClient: { reFetchObservableQueries: jest.fn() },
  GraphQLClientWithErrors: { reFetchObservableQueries: jest.fn() },
  refetchOrganizationQueries: jest.fn(async () => {}),
}))
jest.mock('../env', () => ({ pathPrefix: '', isCypress: true }))
let newClient: typeof import('../urql').newClient
let disposeClient: typeof import('../urql').disposeClient
const originalFetch = global.fetch
beforeAll(() => {
  Object.assign(global, {
    window: { addEventListener: jest.fn() },
    location: { search: '?poll=0' },
  })
  ;({ newClient, disposeClient } = jest.requireActual('../urql'))
})
beforeEach(() => {
  jest.useFakeTimers()
  jest.clearAllMocks()
})
afterEach(() => {
  global.fetch = originalFetch
  jest.useRealTimers()
})
test('real transport retrieves all pages afresh and binds one Service root to exact version', async () => {
  const requests: Array<{ query: string; variables: Record<string, unknown> }> =
    []
  global.fetch = jest.fn(async (_url: unknown, options: RequestInit) => {
    const body = JSON.parse(String(options.body))
    requests.push(body)
    const p = servicePreview()
    p.impactVersion = ' exact raw impact version '
    if (body.variables.after) p.impacts.edges = p.impacts.edges.slice(1)
    else {
      p.impacts.edges = p.impacts.edges.slice(0, 1)
      p.impacts.pageInfo = {
        hasNextPage: true,
        endCursor: p.impacts.edges[0].cursor,
      }
    }
    return new Response(
      JSON.stringify(
        body.query.includes('mutation')
          ? { data: { deleteAll: true } }
          : { data: { deletionPreview: p } },
      ),
      { headers: { 'Content-Type': 'application/json' } },
    )
  }) as typeof fetch
  const client = newClient('https://deletion-safety.invalid/api/graphql')
  try {
    for (let i = 0; i < 2; i++) {
      const loading = loadDeletionPreview(
        profile,
        id,
        (variables) =>
          client
            .query(deletionPreviewQuery, variables, {
              requestPolicy: 'network-only',
              suspense: false,
            })
            .toPromise(),
        () => true,
        jest.fn(),
      )
      await jest.runAllTimersAsync()
      const p = await loading
      expect(p.impacts.edges).toHaveLength(
        servicePreview().impacts.edges.length,
      )
      if (i) {
        const pending = client
          .mutation(deletionMutation, deleteVariables(profile, id, p, true))
          .toPromise()
        await jest.runAllTimersAsync()
        await pending
      }
    }
    expect(
      requests
        .filter((r) => !r.query.includes('mutation'))
        .map((r) => r.variables.after),
    ).toEqual([null, 'synthetic-cursor-0', null, 'synthetic-cursor-0'])
    expect(
      requests
        .filter((r) => r.query.includes('mutation'))
        .map((r) => r.variables),
    ).toEqual([
      {
        input: [{ type: 'service', id }],
        confirmation: {
          expectedImpactVersion: ' exact raw impact version ',
          acknowledgeImpacts: true,
        },
      },
    ])
  } finally {
    disposeClient(client)
  }
})
test.each(['success', 'false', 'null', 'missing', 'network', 'mixed'])(
  'real Service list/detail/Alert/Key query invalidation and physical no-retry: %s',
  async (outcome) => {
    let mutations = 0
    const queries = { list: 0, detail: 0, alerts: 0, keys: 0 }
    global.fetch = jest.fn(async (_url: unknown, options: RequestInit) => {
      const body = JSON.parse(String(options.body))
      let response: object
      if (body.query.includes('mutation')) {
        mutations++
        if (outcome === 'network') throw new TypeError('Synthetic disconnect')
        response =
          outcome === 'success'
            ? { data: { deleteAll: true } }
            : outcome === 'false'
              ? { data: { deleteAll: false } }
              : outcome === 'null'
                ? { data: { deleteAll: null } }
                : outcome === 'missing'
                  ? { data: {} }
                  : {
                      data: { deleteAll: true },
                      errors: [{ message: 'Synthetic mixed error' }],
                    }
      } else {
        const kind = body.query.includes('servicesQuery')
          ? 'list'
          : body.query.includes('AlertsProbe')
            ? 'alerts'
            : body.query.includes('KeysProbe')
              ? 'keys'
              : 'detail'
        queries[kind]++
        // Return only the selected query's shape. Alert invalidation must rely
        // on Alert itself, not a stray Service typename in an unrelated result.
        const service = { __typename: 'Service', id, name: 'Synthetic Service' }
        response =
          kind === 'list'
            ? {
                data: {
                  services: {
                    __typename: 'ServiceConnection',
                    nodes: mutations ? [] : [service],
                    pageInfo: {
                      __typename: 'PageInfo',
                      hasNextPage: false,
                      endCursor: null,
                    },
                  },
                },
              }
            : kind === 'alerts'
              ? {
                  data: {
                    alerts: {
                      __typename: 'AlertConnection',
                      nodes: mutations
                        ? []
                        : [{ __typename: 'Alert', id: '1' }],
                    },
                  },
                }
              : kind === 'keys'
                ? {
                    data: {
                      service: mutations
                        ? null
                        : {
                            __typename: 'Service',
                            id,
                            integrationKeys: [
                              {
                                __typename: 'IntegrationKey',
                                id: 'synthetic-legacy-selector',
                              },
                            ],
                          },
                    },
                  }
                : { data: { service: mutations ? null : service } }
      }
      return new Response(JSON.stringify(response), {
        headers: { 'Content-Type': 'application/json' },
      })
    }) as typeof fetch
    const client = newClient('https://deletion-safety.invalid/api/graphql')
    const values: unknown[] = []
    const subs = [
      pipe(
        client.query(
          gql`
            query servicesQuery {
              services {
                nodes {
                  id
                  name
                }
                pageInfo {
                  hasNextPage
                  endCursor
                }
              }
            }
          `,
          {},
        ),
        subscribe((v) => values.push(v.data)),
      ),
      pipe(
        client.query(
          gql`
            query serviceDetailsQuery($serviceID: ID!) {
              service(id: $serviceID) {
                id
                name
              }
            }
          `,
          { serviceID: id },
        ),
        subscribe(() => {}),
      ),
      pipe(
        client.query(
          gql`
            query AlertsProbe {
              alerts {
                nodes {
                  id
                }
              }
            }
          `,
          { serviceID: id },
        ),
        subscribe(() => {}),
      ),
      pipe(
        client.query(
          gql`
            query KeysProbe($serviceID: ID!) {
              service(id: $serviceID) {
                id
                integrationKeys {
                  id
                }
              }
            }
          `,
          { serviceID: id },
        ),
        subscribe(() => {}),
      ),
    ]
    try {
      await jest.runAllTimersAsync()
      expect(queries).toEqual({ list: 1, detail: 1, alerts: 1, keys: 1 })
      const pending = client
        .mutation(
          deletionMutation,
          deleteVariables(profile, id, servicePreview('empty'), false),
          { additionalTypenames: [...profile.additionalTypenames!] },
        )
        .toPromise()
      await jest.runAllTimersAsync()
      await pending
      expect(mutations).toBe(1)
      const count = outcome === 'success' ? 2 : 1
      expect(queries).toEqual({
        list: count,
        detail: count,
        alerts: count,
        keys: count,
      })
      if (outcome === 'success')
        expect(values[values.length - 1]).toMatchObject({
          services: { nodes: [] },
        })
      expect(GraphQLClient.reFetchObservableQueries).toHaveBeenCalledTimes(
        count - 1,
      )
      expect(
        GraphQLClientWithErrors.reFetchObservableQueries,
      ).toHaveBeenCalledTimes(count - 1)
    } finally {
      subs.forEach((s) => s.unsubscribe())
      disposeClient(client)
    }
  },
)
