import { retryExchange } from '@urql/exchange-retry'
import {
  cacheExchange,
  createClient,
  makeOperation,
  fetchExchange,
  Exchange,
  Operation,
  Client,
} from 'urql'
import { pipe, tap, map } from 'wonka'
import {
  GraphQLClient,
  GraphQLClientWithErrors,
  refetchOrganizationQueries,
} from './apollo'
import { pathPrefix, isCypress } from './env'
import { containsRootCreate } from './util/rootCreatePolicy'
import {
  containsDeleteAll,
  deletionResponseSucceeded,
} from './util/deletionSafety'

const refetch = new Map<Client, (force: boolean) => void>()
export function disposeClient(client: Client): void {
  refetch.delete(client)
}
export function refetchAll(force = false): void {
  refetch.forEach((refetch) => refetch(force))
}

Object.defineProperty(window, 'refetchAll', {
  get() {
    return refetchAll
  },
})

// allow refetching all active queries at any time
const refetchExchange = (): Exchange => {
  return ({ client, forward }) =>
    (ops) => {
      const watchedOps$ = new Map<number, Operation>()
      const observedOps$ = new Map<number, number>()

      refetch.set(client, (force) => {
        if (!force) {
          // use existing policy (cache-first will not re-fetch)
          watchedOps$.forEach((op) => {
            client.reexecuteOperation(
              client.createRequestOperation('query', op),
            )
          })
          return
        }

        watchedOps$.forEach((op) => {
          client.reexecuteOperation(
            client.createRequestOperation('query', op, {
              ...op.context,
              requestPolicy: 'cache-and-network',
            }),
          )
        })
      })

      const handleOp = (op: Operation): void => {
        if (op.kind === 'query' && !observedOps$.has(op.key)) {
          observedOps$.set(op.key, 1)
          watchedOps$.set(op.key, op)
        }

        if (op.kind === 'teardown' && observedOps$.has(op.key)) {
          observedOps$.delete(op.key)
          watchedOps$.delete(op.key)
        }
      }

      return forward(pipe(ops, tap(handleOp)))
    }
}

// refetch every 15 sec or on refocus, every 10 sec for Cypress
let poll: NodeJS.Timeout
function resetPoll(): void {
  if (new URLSearchParams(location.search).get('poll') === '0' || isCypress)
    return
  clearInterval(poll)
  poll = setInterval(refetchAll, 15000)
}
window.addEventListener('visibilitychange', () => {
  switch (document.visibilityState) {
    case 'visible':
      resetPoll()
      refetchAll(true)
      break
    case 'hidden':
      clearInterval(poll)
      break
  }
})
resetPoll()

// handle re-fetching Apollo queries on urql mutation
//
// TODO: remove this once apollo is no longer used
const apolloRefetchExchange: Exchange = ({ forward }) => {
  return (operations$) => {
    const operationResult$ = forward(operations$)
    return pipe(
      operationResult$,
      map((result) => {
        if (result.operation.kind !== 'mutation') return result
        if (
          containsDeleteAll(result.operation.query) &&
          (result.error ||
            result.stale ||
            result.hasNext ||
            !deletionResponseSucceeded(result.operation.query, result.data))
        ) {
          // cacheExchange otherwise invalidates additionalTypenames even for
          // rejected or uncertain mutations. Keep failure from refreshing the
          // policy page into its legacy missing-resource success redirect.
          return {
            ...result,
            operation: makeOperation('mutation', result.operation, {
              ...result.operation.context,
              additionalTypenames: [],
            }),
          }
        }
        if (result.error) return result
        GraphQLClient.reFetchObservableQueries(true)
        GraphQLClientWithErrors.reFetchObservableQueries(true)
        refetchOrganizationQueries().catch(() => undefined)
        return result
      }),
    )
  }
}

export function newClient(url: string): Client {
  return createClient({
    url,
    suspense: true,
    exchanges: [
      refetchExchange(),
      cacheExchange,
      apolloRefetchExchange,
      retryExchange({
        retryIf: (error, operation) =>
          !containsRootCreate(operation.query) &&
          !containsDeleteAll(operation.query) &&
          !!error.networkError,
      }) as Exchange,
      fetchExchange,
    ],
    requestPolicy: 'cache-and-network',
  })
}

export const client = newClient(pathPrefix + '/api/graphql')
