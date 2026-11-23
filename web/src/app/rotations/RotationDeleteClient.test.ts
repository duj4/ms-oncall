import { gql } from 'urql'
import { pipe, subscribe } from 'wonka'
import { GraphQLClient, GraphQLClientWithErrors } from '../apollo'
import {
  deleteVariables,
  deletionMutation,
  deletionPreviewQuery,
  loadDeletionPreview,
} from '../util/deletionSafety'
import { rotationDeletionProfile as profile } from '../util/deletionSafetyProfiles'

type DeletionPreview = import('../../schema').DeletionPreview

jest.mock('../apollo', () => ({
  GraphQLClient: { reFetchObservableQueries: jest.fn() },
  GraphQLClientWithErrors: { reFetchObservableQueries: jest.fn() },
  refetchOrganizationQueries: jest.fn(async () => {}),
}))
jest.mock('../env', () => ({ pathPrefix: '', isCypress: true }))
let newClient: typeof import('../urql').newClient
let disposeClient: typeof import('../urql').disposeClient
const originalFetch = global.fetch
const id = '10000000-0000-4000-8000-000000000001'
const root = {
  type: 'ROTATION',
  id,
  label: 'Synthetic rotation',
  name: null,
  organization: null,
}
const preview = (
  required = false,
  after: string | null = null,
): DeletionPreview => ({
  operation: 'DELETE_RESOURCES',
  targets: [root],
  impactVersion: ' exact raw version ',
  policyVersion: 'deletion-safety-spec1-v2',
  assessedAt: '2026-11-21T10:00:00Z',
  complete: true,
  canProceed: true,
  requiresConfirmation: required,
  notices: [],
  impacts: {
    edges: required
      ? [
          {
            cursor: after ? 'last' : 'first',
            node: {
              edgeID: after ? 'edge-2' : 'edge-1',
              target: root,
              referencingResource: {
                ...root,
                type: 'ROTATION_PARTICIPANT',
                id: after ? 'rule-2' : 'rule-1',
              },
              parent: root,
              relation: 'ROTATION_PARTICIPANT',
              change: 'DELETED',
              policy: 'CASCADE',
              requiredAction: 'CONFIRM_IMPACT',
              impact: 'Owned participant deleted.',
              isDerived: false,
              isPlannedCoDeletion: true,
              canModifyReference: true,
            },
          },
        ]
      : [],
    pageInfo: {
      endCursor: required ? (after ? 'last' : 'first') : null,
      hasNextPage: required && !after,
    },
  },
})
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

test.each([false, true])(
  'real network-only pagination and original confirmation, requiresConfirmation=%s',
  async (required) => {
    const requests: Array<{
      query: string
      variables: Record<string, unknown>
    }> = []
    global.fetch = jest.fn(async (_url: unknown, options: RequestInit) => {
      const body = JSON.parse(String(options.body))
      requests.push(body)
      const p = preview(required, body.variables.after)
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
      // Two complete reviews prove that a cached first page never unlocks review.
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
        const complete = await pending
        expect(complete.impacts.edges).toHaveLength(required ? 2 : 0)
        if (i) {
          const deleted = client
            .mutation(
              deletionMutation,
              deleteVariables(profile, id, complete, required),
              { additionalTypenames: ['Rotation'] },
            )
            .toPromise()
          await jest.runAllTimersAsync()
          expect((await deleted).data?.deleteAll).toBe(true)
        }
      }
      const previews = requests.filter((r) => !r.query.includes('mutation'))
      expect(previews.map((r) => r.variables)).toEqual(
        (required ? [null, 'first', null, 'first'] : [null, null]).map(
          (after) => ({
            input: {
              operation: 'DELETE_RESOURCES',
              targets: [{ type: 'ROTATION', id }],
            },
            first: 100,
            after,
          }),
        ),
      )
      const deletes = requests.filter((r) => r.query.includes('mutation'))
      expect(deletes).toHaveLength(1)
      expect(deletes[0].variables).toEqual({
        input: [{ type: 'rotation', id }],
        confirmation: {
          expectedImpactVersion: ' exact raw version ',
          acknowledgeImpacts: required,
        },
      })
    } finally {
      disposeClient(client)
    }
  },
)

test.each([
  'success',
  'false',
  'null',
  'missing',
  'partial',
  'network',
  'error',
  'sibling',
])('real Rotation cache and physical Delete requests: %s', async (outcome) => {
  let queries = 0
  let mutations = 0
  global.fetch = jest.fn(async (_url: unknown, options: RequestInit) => {
    const body = JSON.parse(String(options.body))
    let response: object
    if (body.query.includes('mutation')) {
      mutations++
      if (outcome === 'network')
        throw new TypeError('Synthetic network failure')
      response =
        outcome === 'success'
          ? { data: { deleteAll: true } }
          : outcome === 'false'
            ? { data: { deleteAll: false } }
            : outcome === 'null'
              ? { data: { deleteAll: null } }
              : outcome === 'missing'
                ? { data: {} }
                : outcome === 'partial'
                  ? { data: { deleteAll: true }, hasNext: true }
                  : outcome === 'sibling'
                    ? { data: { deleteAll: false, saved: true } }
                    : {
                        data: { deleteAll: true },
                        errors: [{ message: 'Synthetic unknown error' }],
                      }
    } else {
      queries++
      response = { data: { rotation: { __typename: 'Rotation', id } } }
    }
    return new Response(JSON.stringify(response), {
      headers: { 'Content-Type': 'application/json' },
    })
  }) as typeof fetch
  const client = newClient('https://deletion-safety.invalid/api/graphql')
  const watch = pipe(
    client.query(
      gql`
        query RotationCacheProbe($id: ID!) {
          rotation(id: $id) {
            id
          }
        }
      `,
      { id },
    ),
    subscribe(() => {}),
  )
  try {
    await jest.runAllTimersAsync()
    expect(queries).toBe(1)
    const document =
      outcome === 'sibling'
        ? gql`
            mutation {
              deleteAll(input: [])
              saved: setFavorite(
                input: {
                  target: {
                    type: rotation
                    id: "10000000-0000-4000-8000-000000000001"
                  }
                  favorite: true
                }
              )
            }
          `
        : deletionMutation
    const results: Array<import('urql').OperationResult> = []
    const context = { additionalTypenames: ['Rotation'], suspense: false }
    const deleting = pipe(
      client.mutation(
        document,
        {
          input: [{ type: 'rotation', id }],
          confirmation: {
            expectedImpactVersion: ' exact raw version ',
            acknowledgeImpacts: false,
          },
        },
        context,
      ),
      subscribe((value) => results.push(value)),
    )
    await jest.runAllTimersAsync()
    expect(mutations).toBe(1)
    expect(results).toHaveLength(1)
    expect(context).toEqual({
      additionalTypenames: ['Rotation'],
      suspense: false,
    })
    const refreshed = ['success', 'sibling'].includes(outcome)
    expect(queries).toBe(refreshed ? 2 : 1)
    expect(GraphQLClient.reFetchObservableQueries).toHaveBeenCalledTimes(
      refreshed ? 1 : 0,
    )
    expect(
      GraphQLClientWithErrors.reFetchObservableQueries,
    ).toHaveBeenCalledTimes(refreshed ? 1 : 0)
    deleting.unsubscribe()
  } finally {
    watch.unsubscribe()
    disposeClient(client)
  }
})
