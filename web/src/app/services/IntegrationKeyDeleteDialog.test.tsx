import React from 'react'
import { useClient } from 'urql'
import { useLocation } from 'wouter'
import IntegrationKeyDeleteDialog from './IntegrationKeyDeleteDialog'
import {
  identityResult,
  keyPreview,
  legacyID,
  auditID,
  serviceID,
  organizationID,
} from './integrationKeyDeletionFixtures'
import { integrationKeyDeletionQuery } from '../util/integrationKeyDeletion'
type DeletionState = import('../util/deletionSafety').DeletionState
type DeletionSafetyDialogProps =
  import('../dialogs/DeletionSafetyDialog').DeletionSafetyDialogProps

// Controlled hook/result harness; real React/URQL/browser behavior is covered
// separately. These transport flags cannot be encoded as ordinary JSON fields.
jest.mock('react', () => ({
  ...jest.requireActual('react'),
  useState: jest.fn(),
  useRef: jest.fn(),
  useCallback: jest.fn(),
  useEffect: jest.fn(),
}))
jest.mock('urql', () => ({
  ...jest.requireActual('@urql/core'),
  useClient: jest.fn(),
}))
jest.mock('wouter', () => ({ useLocation: jest.fn() }))
jest.mock('../main/OrganizationManagement', () => ({
  useOrganizationManagement: () => ({
    identity: { userID: 'synthetic' },
    target: { id: '40000000-0000-4000-8000-000000000001' },
  }),
}))
jest.mock('../dialogs/DeletionSafetyDialog', () => ({
  __esModule: true,
  default: () => null,
}))
let state: DeletionState
let effects: Array<() => () => void>
let query: jest.Mock
let mutation: jest.Mock
const flush = async (): Promise<void> => {
  for (let i = 0; i < 20; i++) await Promise.resolve()
}
function mount(): {
  handlers: DeletionSafetyDialogProps
  cleanup: () => void
  success: jest.Mock
  close: jest.Mock
} {
  const success = jest.fn()
  const close = jest.fn()
  const el = IntegrationKeyDeleteDialog({
    integrationKeyID: legacyID,
    integrationKeyType: 'generic',
    serviceID,
    onClose: close,
    onSuccess: success,
  })
  const cleanup = effects[0]()
  return { handlers: el.props, cleanup, success, close }
}
beforeEach(() => {
  jest.clearAllMocks()
  state = { phase: 'loading', loaded: 0 }
  effects = []
  jest.mocked(React.useState).mockImplementation(
    (initial: unknown = undefined) =>
      [
        initial,
        (value: unknown) => {
          if (typeof value !== 'boolean') state = value as DeletionState
        },
      ] as never,
  )
  jest
    .mocked(React.useRef)
    .mockImplementation((value?: unknown) => ({ current: value }))
  jest.mocked(React.useCallback).mockImplementation((fn) => fn)
  jest.mocked(React.useEffect).mockImplementation((effect) => {
    effects.push(effect as () => () => void)
  })
  jest.mocked(useLocation).mockReturnValue(['', jest.fn()])
  query = jest.fn((document) =>
    document === integrationKeyDeletionQuery
      ? identityResult()
      : { data: { deletionPreview: keyPreview() } },
  )
  mutation = jest
    .fn()
    .mockReturnValue({ toPromise: async () => ({ data: { deleteAll: true } }) })
  jest.mocked(useClient).mockReturnValue({
    query: (...args: unknown[]) => ({
      subscribe: (callback: (v: unknown) => void) => {
        let subscribed = true
        Promise.resolve(query(...args)).then((value) => {
          if (subscribed) callback(value)
        })
        return {
          unsubscribe: () => {
            subscribed = false
          },
        }
      },
    }),
    mutation,
  } as unknown as import('urql').Client)
})
test('on-demand network identity precedes Audit preview and Legacy mutation with backend confirmation', async () => {
  const m = mount()
  await flush()
  expect(state.phase).toBe('review')
  expect(query.mock.calls.map((c) => c[1])).toEqual([
    { id: legacyID },
    {
      input: {
        operation: 'DELETE_RESOURCES',
        targets: [{ type: 'INTEGRATION_KEY', id: auditID }],
      },
      first: 100,
      after: null,
    },
  ])
  expect(
    query.mock.calls.every(
      (c) => c[2].requestPolicy === 'network-only' && c[2].suspense === false,
    ),
  ).toBe(true)
  await m.handlers.onConfirm()
  expect(mutation).not.toHaveBeenCalled()
  m.handlers.onAcknowledge(true)
  await m.handlers.onConfirm()
  expect(mutation.mock.calls[0][1]).toEqual({
    input: [{ type: 'integrationKey', id: legacyID }],
    confirmation: {
      expectedImpactVersion: keyPreview().impactVersion,
      acknowledgeImpacts: true,
    },
  })
  expect(m.success).toHaveBeenCalledTimes(1)
  m.cleanup()
})
test.each(['stale', 'hasNext', 'error', 'missing', 'network', 'fetching'])(
  'unreliable identity %s never starts preview or deletion',
  async (kind) => {
    query.mockImplementation(() => ({
      ...identityResult(),
      ...(kind === 'stale'
        ? { stale: true }
        : kind === 'hasNext'
          ? { hasNext: true }
          : kind === 'fetching'
            ? { fetching: true }
            : kind === 'missing'
              ? { data: { integrationKey: null } }
              : kind === 'network'
                ? { error: { networkError: {} } }
                : {
                    error: {
                      graphQLErrors: [{ message: 'Synthetic ID! error' }],
                    },
                  }),
    }))
    const m = mount()
    await flush()
    m.handlers.onAcknowledge(true)
    await m.handlers.onConfirm()
    expect(state.phase).toBe('failed')
    expect(query).toHaveBeenCalledTimes(1)
    expect(mutation).not.toHaveBeenCalled()
    expect(m.success).not.toHaveBeenCalled()
    m.cleanup()
  },
)
test.each(['stale', 'hasNext'])(
  'unreliable preview %s never starts deletion',
  async (kind) => {
    query.mockImplementation((document) =>
      document === integrationKeyDeletionQuery
        ? identityResult()
        : { data: { deletionPreview: keyPreview() }, [kind]: true },
    )
    const m = mount()
    await flush()
    m.handlers.onAcknowledge(true)
    await m.handlers.onConfirm()
    expect(state.phase).toBe('unsupported')
    expect(mutation).not.toHaveBeenCalled()
    m.cleanup()
  },
)
test.each([
  'stale',
  'hasNext',
  'false',
  'null',
  'missing',
  'mixed',
  'network',
  'reject',
  'timeout',
])(
  'unreliable mutation %s becomes CommitUnknown without success, close, refresh or retry',
  async (kind) => {
    mutation.mockReturnValue({
      toPromise: async () => {
        if (kind === 'reject' || kind === 'timeout')
          throw new Error('Synthetic timeout')
        return kind === 'false'
          ? { data: { deleteAll: false } }
          : kind === 'null'
            ? { data: { deleteAll: null } }
            : kind === 'missing'
              ? {}
              : kind === 'mixed'
                ? { data: { deleteAll: true }, error: { graphQLErrors: [{}] } }
                : kind === 'network'
                  ? { error: { networkError: {} } }
                  : { data: { deleteAll: true }, [kind]: true }
      },
    })
    const m = mount()
    await flush()
    m.handlers.onAcknowledge(true)
    await m.handlers.onConfirm()
    expect(state.phase).toBe('unknown')
    expect(m.success).not.toHaveBeenCalled()
    expect(m.close).not.toHaveBeenCalled()
    m.handlers.onPreview()
    await m.handlers.onConfirm()
    expect(mutation).toHaveBeenCalledTimes(1)
    expect(query).toHaveBeenCalledTimes(2)
    m.cleanup()
  },
)
test.each(['DELETION_DEPENDENCY_CHANGED', 'DELETION_CONFIRMATION_REQUIRED'])(
  '%s discards identities, pages, acknowledgement and version before recheck',
  async (code) => {
    mutation.mockReturnValue({
      toPromise: async () => ({
        error: { graphQLErrors: [{ extensions: { code } }] },
      }),
    })
    const m = mount()
    await flush()
    m.handlers.onAcknowledge(true)
    await m.handlers.onConfirm()
    await flush()
    expect(query).toHaveBeenCalledTimes(4)
    expect(state.phase).toBe('review')
    await m.handlers.onConfirm()
    expect(mutation).toHaveBeenCalledTimes(1)
    expect(m.success).not.toHaveBeenCalled()
    m.cleanup()
  },
)
test('cancel ignores an old authorized identity response, and never previews it', async () => {
  let finish: (value: unknown) => void = () => {}
  query.mockImplementation(
    () =>
      new Promise((resolve) => {
        finish = resolve
      }),
  )
  const m = mount()
  m.handlers.onClose()
  finish(identityResult())
  await flush()
  expect(query).toHaveBeenCalledTimes(1)
  expect(state.phase).toBe('cancelled')
  expect(mutation).not.toHaveBeenCalled()
  m.cleanup()
})
test('actual owner organization from the complete Preview must match current scope', async () => {
  const p = keyPreview()
  p.targets[0].organization = {
    id: serviceID,
    name: 'Synthetic different organization',
  }
  query.mockImplementation((document) =>
    document === integrationKeyDeletionQuery
      ? identityResult()
      : { data: { deletionPreview: p } },
  )
  const m = mount()
  await flush()
  expect(organizationID).not.toBe(serviceID)
  expect(state.phase).toBe('unsupported')
  m.handlers.onAcknowledge(true)
  await m.handlers.onConfirm()
  expect(mutation).not.toHaveBeenCalled()
  m.cleanup()
})
