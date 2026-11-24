import { gql } from 'urql'
import { pipe, subscribe } from 'wonka'
import { GraphQLClient, GraphQLClientWithErrors } from '../apollo'
import {
  deleteVariables,
  deletionMutation,
  deletionPreviewQuery,
  loadDeletionPreview,
} from '../util/deletionSafety'
import { contactMethodDeletionProfile as profile } from '../util/deletionSafetyProfiles'
import {
  contactMethodID as id,
  contactMethodPreview,
} from './contactMethodDeletionFixtures'

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

test('real client fetches every preview page network-only and sends only its exact version', async () => {
  const requests: Array<{ query: string; variables: Record<string, unknown> }> =
    []
  global.fetch = jest.fn(async (_url: unknown, options: RequestInit) => {
    const body = JSON.parse(String(options.body))
    requests.push(body)
    const p = contactMethodPreview('open-cycle')
    p.impactVersion = ' exact raw version '
    if (body.variables.after) p.impacts.edges = p.impacts.edges.slice(1)
    else {
      p.impacts.edges = p.impacts.edges.slice(0, 1)
      p.impacts.pageInfo = { hasNextPage: true, endCursor: 'immediate' }
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
      const pending = loadDeletionPreview(
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
      const p = await pending
      expect(p.impacts.edges).toHaveLength(6)
      if (i) {
        const deleting = client
          .mutation(deletionMutation, deleteVariables(profile, id, p, true))
          .toPromise()
        await jest.runAllTimersAsync()
        await deleting
      }
    }
    expect(
      requests
        .filter((r) => !r.query.includes('mutation'))
        .map((r) => r.variables.after),
    ).toEqual([null, 'immediate', null, 'immediate'])
    expect(
      requests
        .filter((r) => r.query.includes('mutation'))
        .map((r) => r.variables),
    ).toEqual([
      {
        input: [{ type: 'contactMethod', id }],
        confirmation: {
          expectedImpactVersion: ' exact raw version ',
          acknowledgeImpacts: true,
        },
      },
    ])
  } finally {
    disposeClient(client)
  }
})

test.each(['success', 'false', 'null', 'missing', 'network', 'error'])(
  'real parent/list invalidation and one physical Delete request: %s',
  async (outcome) => {
    let mutations = 0
    const queries = { list: 0, parent: 0, contact: 0 }
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
                      errors: [{ message: 'Synthetic error' }],
                    }
      } else {
        const list = body.query.includes('NRListCacheProbe')
        const contact = body.query.includes('CMListCacheProbe')
        queries[contact ? 'contact' : list ? 'list' : 'parent']++
        response = {
          data: {
            user: {
              __typename: 'User',
              id: 'synthetic-user',
              name: 'Synthetic user',
              contactMethods: mutations
                ? []
                : [{ __typename: 'UserContactMethod', id }],
              // An empty list must still refresh correctly after the last rule is removed.
              notificationRules: mutations
                ? []
                : [{ __typename: 'UserNotificationRule', id }],
            },
          },
        }
      }
      return new Response(JSON.stringify(response), {
        headers: { 'Content-Type': 'application/json' },
      })
    }) as typeof fetch
    const client = newClient('https://deletion-safety.invalid/api/graphql')
    const values: unknown[] = []
    const list = pipe(
      client.query(
        gql`
          query NRListCacheProbe {
            user(id: "synthetic-user") {
              id
              notificationRules {
                id
              }
            }
          }
        `,
        {},
      ),
      subscribe((value) => values.push(value.data)),
    )
    const parent = pipe(
      client.query(
        gql`
          query UserParentCacheProbe {
            user(id: "synthetic-user") {
              id
              name
            }
          }
        `,
        {},
      ),
      subscribe(() => {}),
    )
    const contactValues: unknown[] = []
    const contact = pipe(
      client.query(
        gql`
          query CMListCacheProbe {
            user(id: "synthetic-user") {
              id
              contactMethods {
                id
              }
            }
          }
        `,
        {},
      ),
      subscribe((value) => contactValues.push(value.data)),
    )
    try {
      await jest.runAllTimersAsync()
      expect(queries).toEqual({ list: 1, parent: 1, contact: 1 })
      const context = {
        additionalTypenames: [...profile.additionalTypenames!],
        suspense: false,
      }
      const deleting = client
        .mutation(
          deletionMutation,
          deleteVariables(
            profile,
            id,
            contactMethodPreview('alternative', id, 0),
            false,
          ),
          context,
        )
        .toPromise()
      await jest.runAllTimersAsync()
      await deleting
      expect(mutations).toBe(1)
      const refreshed = outcome === 'success'
      expect(queries).toEqual({
        list: refreshed ? 2 : 1,
        parent: refreshed ? 2 : 1,
        contact: refreshed ? 2 : 1,
      })
      if (refreshed)
        expect(values[values.length - 1]).toMatchObject({
          user: { notificationRules: [] },
        })
      if (refreshed)
        expect(contactValues[contactValues.length - 1]).toMatchObject({
          user: { contactMethods: [] },
        })
      expect(GraphQLClient.reFetchObservableQueries).toHaveBeenCalledTimes(
        refreshed ? 1 : 0,
      )
      expect(
        GraphQLClientWithErrors.reFetchObservableQueries,
      ).toHaveBeenCalledTimes(refreshed ? 1 : 0)
      expect(context.additionalTypenames).toEqual([
        'UserContactMethod',
        'UserNotificationRule',
        'User',
      ])
    } finally {
      list.unsubscribe()
      parent.unsubscribe()
      contact.unsubscribe()
      disposeClient(client)
    }
  },
)
