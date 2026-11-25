import { gql } from 'urql'
import { pipe, subscribe } from 'wonka'
import {
  deletionMutation,
  deletionPreviewQuery,
  deleteVariables,
  loadDeletionPreview,
} from '../util/deletionSafety'
import { integrationKeyDeletionProfile as profile } from '../util/deletionSafetyProfiles'
import {
  integrationKeyDeletionQuery,
  verifyIntegrationKeyIdentity,
} from '../util/integrationKeyDeletion'
import {
  expectedIdentity,
  identityResult,
  keyPreview,
  legacyID,
  auditID,
  serviceID,
} from './integrationKeyDeletionFixtures'
import { GraphQLClient } from '../apollo'
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

test.each([
  'success',
  'false',
  'null',
  'missing',
  'network',
  'timeout',
  'mixed',
  'blocked',
  'unavailable',
  'changed',
])(
  'real URQL transport and cache invalidation for IntegrationKey: %s',
  async (outcome) => {
    const requests: Array<{
      query: string
      variables: Record<string, unknown>
    }> = []
    let mutations = 0
    let lists = 0
    let services = 0
    let identities = 0
    const listValues: unknown[] = []
    global.fetch = jest.fn(async (_url: unknown, options: RequestInit) => {
      const body = JSON.parse(String(options.body))
      requests.push(body)
      let response: object
      if (body.query.includes('mutation')) {
        mutations++
        if (['network', 'timeout'].includes(outcome))
          throw new TypeError('Synthetic disconnect or timeout')
        response =
          outcome === 'success'
            ? { data: { deleteAll: true } }
            : outcome === 'false'
              ? { data: { deleteAll: false } }
              : outcome === 'null'
                ? { data: { deleteAll: null } }
                : outcome === 'missing'
                  ? { data: {} }
                  : outcome === 'mixed'
                    ? {
                        data: { deleteAll: true },
                        errors: [{ message: 'Synthetic mixed error' }],
                      }
                    : {
                        errors: [
                          {
                            message: 'Synthetic refusal',
                            extensions: {
                              code:
                                outcome === 'blocked'
                                  ? 'DELETION_BLOCKED'
                                  : outcome === 'changed'
                                    ? 'DELETION_DEPENDENCY_CHANGED'
                                    : 'DELETION_UNAVAILABLE',
                            },
                          },
                        ],
                      }
      } else if (body.query.includes('IntegrationKeyDeletionIdentity')) {
        identities++
        response = identityResult()
      } else if (body.query.includes('deletionPreview')) {
        const p = keyPreview(2)
        if (!body.variables.after) {
          p.impacts.edges = p.impacts.edges.slice(0, 1)
          p.impacts.pageInfo = { endCursor: 'cursor-0', hasNextPage: true }
        } else p.impacts.edges = p.impacts.edges.slice(1)
        response = { data: { deletionPreview: p } }
      } else if (body.query.includes('KeyListProbe')) {
        lists++
        response = {
          data: {
            service: {
              __typename: 'Service',
              id: serviceID,
              integrationKeys:
                mutations && outcome === 'success'
                  ? []
                  : [
                      {
                        __typename: 'IntegrationKey',
                        id: legacyID,
                        name: 'Synthetic key',
                      },
                    ],
            },
          },
        }
      } else {
        services++
        response = {
          data: {
            service: {
              __typename: 'Service',
              id: serviceID,
              name: 'Synthetic preserved Service',
            },
          },
        }
      }
      return new Response(JSON.stringify(response), {
        headers: { 'Content-Type': 'application/json' },
      })
    }) as typeof fetch
    const client = newClient('https://deletion-safety.invalid/api/graphql')
    const subscriptions = [
      pipe(
        client.query(
          gql`
            query KeyListProbe($serviceID: ID!) {
              service(id: $serviceID) {
                id
                integrationKeys {
                  id
                  name
                }
              }
            }
          `,
          { serviceID },
        ),
        subscribe((r) => listValues.push(r.data)),
      ),
      pipe(
        client.query(
          gql`
            query ServiceProbe($serviceID: ID!) {
              service(id: $serviceID) {
                id
                name
              }
            }
          `,
          { serviceID },
        ),
        subscribe(() => {}),
      ),
    ]
    try {
      await jest.runAllTimersAsync()
      expect([lists, services]).toEqual([1, 1])
      let binding
      for (let i = 0; i < 2; i++) {
        const pending = client
          .query(
            integrationKeyDeletionQuery,
            { id: legacyID },
            { requestPolicy: 'network-only', suspense: false },
          )
          .toPromise()
        await jest.runAllTimersAsync()
        binding = verifyIntegrationKeyIdentity(await pending, expectedIdentity)
      }
      expect(identities).toBe(2)
      const loading = loadDeletionPreview(
        profile,
        binding!.auditID,
        (v) =>
          client
            .query(deletionPreviewQuery, v, {
              requestPolicy: 'network-only',
              suspense: false,
            })
            .toPromise(),
        () => true,
        jest.fn(),
        binding!,
      )
      await jest.runAllTimersAsync()
      const preview = await loading
      const pending = client
        .mutation(
          deletionMutation,
          deleteVariables(profile, legacyID, preview, true, binding!),
          { additionalTypenames: [...profile.additionalTypenames!] },
        )
        .toPromise()
      await jest.runAllTimersAsync()
      await pending
      expect(mutations).toBe(1)
      const count = outcome === 'success' ? 2 : 1
      expect([lists, services]).toEqual([count, count])
      expect(GraphQLClient.reFetchObservableQueries).toHaveBeenCalledTimes(
        count - 1,
      )
      const previews = requests.filter((r) =>
        r.query.includes('deletionPreview'),
      )
      expect(previews.map((r) => r.variables.input)).toEqual(
        Array(2).fill({
          operation: 'DELETE_RESOURCES',
          targets: [{ type: 'INTEGRATION_KEY', id: auditID }],
        }),
      )
      expect(previews.map((r) => r.variables.after)).toEqual([null, 'cursor-0'])
      expect(
        requests.find((r) => r.query.includes('mutation'))!.variables,
      ).toEqual({
        input: [{ type: 'integrationKey', id: legacyID }],
        confirmation: {
          expectedImpactVersion: preview.impactVersion,
          acknowledgeImpacts: true,
        },
      })
      if (outcome === 'success')
        expect(listValues[listValues.length - 1]).toMatchObject({
          service: { id: serviceID, integrationKeys: [] },
        })
      expect(
        requests
          .filter((r) => r.query.includes('IntegrationKeyDeletionIdentity'))
          .every((r) => !r.query.includes('href')),
      ).toBe(true)
    } finally {
      subscriptions.forEach((s) => s.unsubscribe())
      disposeClient(client)
    }
  },
)
