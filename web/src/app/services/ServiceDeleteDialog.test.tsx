import { servicePreview } from './serviceDeletionFixtures'
import React from 'react'
import { useClient } from 'urql'
import { useLocation } from 'wouter'
import { previewVariables } from '../util/deletionSafety'
import { serviceDeletionProfile } from '../util/deletionSafetyProfiles'
import ServiceDeleteDialog from './ServiceDeleteDialog'
type UrqlClient = import('urql').Client
type DeletionPreview = import('../../schema').DeletionPreview
type DeletionSafetyDialogProps =
  import('../dialogs/DeletionSafetyDialog').DeletionSafetyDialogProps
type DeletionState = import('../util/deletionSafety').DeletionState

const servicePreviewVariables = (
  id: string,
  after: string | null,
): import('../util/deletionSafety').DeletionPreviewVariables =>
  previewVariables(serviceDeletionProfile, id, after)

// A controlled hook/callback harness: these are controller tests, not DOM tests.
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
  useOrganizationManagement: () => null,
}))
jest.mock('../dialogs/DeletionSafetyDialog', () => ({
  __esModule: true,
  default: () => null,
}))
const id = '10000000-0000-4000-8000-000000000001'
let state: DeletionState
let acknowledged: boolean
let effects: Array<() => () => void>
const navigate = jest.fn()
const query = jest.fn()
const mutation = jest.fn()
function fixture(extra: Partial<DeletionPreview> = {}): DeletionPreview {
  return {
    ...servicePreview(
      extra.requiresConfirmation === false ? 'empty' : 'closure',
      id,
    ),
    ...extra,
  }
}
async function flush(): Promise<void> {
  for (let i = 0; i < 8; i++) await Promise.resolve()
}
function mount(): {
  handlers: DeletionSafetyDialogProps
  cleanup: () => void
  close: jest.Mock
} {
  const close = jest.fn()
  const element = ServiceDeleteDialog({
    serviceID: id,
    onClose: close,
  })
  const cleanup = effects[0]()
  return {
    handlers: element.props as DeletionSafetyDialogProps,
    cleanup,
    close,
  }
}
beforeEach(() => {
  jest.clearAllMocks()
  state = { phase: 'loading', loaded: 0 }
  acknowledged = false
  effects = []
  jest.mocked(React.useState).mockImplementation(
    (initial: unknown = undefined) =>
      [
        initial,
        (value: unknown) => {
          if (typeof value === 'boolean') acknowledged = value
          else state = value as DeletionState
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
  jest.mocked(useClient).mockReturnValue({
    query: (...args: unknown[]) => {
      const source = query(...args)
      return {
        subscribe: (
          callback: (
            value: import('../util/deletionSafety').PreviewResult,
          ) => void,
        ) => {
          let subscribed = true
          source
            .toPromise()
            .then((value: import('../util/deletionSafety').PreviewResult) => {
              if (subscribed) callback(value)
            })
          return {
            unsubscribe: () => {
              subscribed = false
            },
          }
        },
      }
    },
    mutation,
  } as unknown as UrqlClient)
  jest.mocked(useLocation).mockReturnValue(['', navigate])
  query.mockReturnValue({
    toPromise: async () => ({ data: { deletionPreview: fixture() } }),
  })
  mutation.mockReturnValue({
    toPromise: async () => ({ data: { deleteAll: true } }),
  })
})
test('loads network-only preview before deletion; checkbox defaults false', async () => {
  const { handlers, cleanup } = mount()
  expect(state.phase).toBe('loading')
  await handlers.onConfirm()
  expect(mutation).not.toHaveBeenCalled()
  await flush()
  expect(query.mock.calls[0][1]).toEqual(servicePreviewVariables(id, null))
  expect(query.mock.calls[0][2]).toEqual({
    requestPolicy: 'network-only',
    suspense: false,
  })
  expect(state.phase).toBe('review')
  expect(acknowledged).toBe(false)
  await handlers.onConfirm()
  expect(mutation).not.toHaveBeenCalled()
  cleanup()
})
test('explicit ack sends only one Service with its version, invalidates affected types and navigates reliably', async () => {
  const { handlers, cleanup, close } = mount()
  await flush()
  handlers.onAcknowledge(true)
  expect(state.phase).toBe('confirming')
  await handlers.onConfirm()
  expect(mutation).toHaveBeenCalledTimes(1)
  expect(mutation.mock.calls[0][1]).toEqual({
    input: [{ type: 'service', id }],
    confirmation: {
      expectedImpactVersion: servicePreview().impactVersion,
      acknowledgeImpacts: true,
    },
  })
  expect(mutation.mock.calls[0][2]).toEqual({
    additionalTypenames: ['Service', 'Alert', 'IntegrationKey'],
  })
  expect(navigate).toHaveBeenCalledWith('/services')
  expect(close).not.toHaveBeenCalled()
  await handlers.onConfirm()
  expect(mutation).toHaveBeenCalledTimes(1)
  cleanup()
})
test('requiresConfirmation=false still waits for final click and sends ack=false', async () => {
  query.mockReturnValue({
    toPromise: async () => ({
      data: { deletionPreview: fixture({ requiresConfirmation: false }) },
    }),
  })
  const { handlers, cleanup } = mount()
  await flush()
  expect(mutation).not.toHaveBeenCalled()
  await handlers.onConfirm()
  expect(mutation.mock.calls[0][1].confirmation).toEqual({
    expectedImpactVersion: servicePreview('empty').impactVersion,
    acknowledgeImpacts: false,
  })
  cleanup()
})
test('BLOCK prohibits callbacks as well as the disabled button', async () => {
  query.mockReturnValue({
    toPromise: async () => ({
      data: { deletionPreview: fixture({ canProceed: false }) },
    }),
  })
  const { handlers, cleanup } = mount()
  await flush()
  handlers.onAcknowledge(true)
  await handlers.onConfirm()
  expect(state.phase).toBe('blocked')
  expect(mutation).not.toHaveBeenCalled()
  cleanup()
})
test.each(['DELETION_DEPENDENCY_CHANGED', 'DELETION_CONFIRMATION_REQUIRED'])(
  '%s clears every page/version/ack and fetches from page one without resubmitting',
  async (code) => {
    let finish: (value: unknown) => void = () => {}
    query
      .mockReturnValueOnce({
        toPromise: async () => ({ data: { deletionPreview: fixture() } }),
      })
      .mockReturnValueOnce({
        toPromise: () =>
          new Promise((resolve) => {
            finish = resolve
          }),
      })
    mutation.mockReturnValue({
      toPromise: async () => ({
        error: { graphQLErrors: [{ extensions: { code } }] },
      }),
    })
    const { handlers, cleanup } = mount()
    await flush()
    handlers.onAcknowledge(true)
    await handlers.onConfirm()
    expect(state.phase).toBe('loading')
    expect(state.preview).toBeUndefined()
    expect(acknowledged).toBe(false)
    expect(query.mock.calls[1][1]).toEqual(servicePreviewVariables(id, null))
    finish({
      data: { deletionPreview: fixture({ impactVersion: 'version-2' }) },
    })
    await flush()
    expect(state.preview?.impactVersion).toBe('version-2')
    await handlers.onConfirm()
    expect(mutation).toHaveBeenCalledTimes(1)
    handlers.onAcknowledge(true)
    await handlers.onConfirm()
    expect(mutation.mock.calls[1][1].confirmation.expectedImpactVersion).toBe(
      'version-2',
    )
    cleanup()
  },
)
test('cancel and unmount invalidate late preview responses', async () => {
  for (const cancel of [true, false]) {
    let finish: (value: unknown) => void = () => {}
    query.mockReturnValue({
      toPromise: () =>
        new Promise((resolve) => {
          finish = resolve
        }),
    })
    const { handlers, cleanup, close } = mount()
    if (cancel) handlers.onClose()
    else cleanup()
    finish({ data: { deletionPreview: fixture() } })
    await flush()
    expect(state.preview).toBeUndefined()
    await handlers.onConfirm()
    expect(mutation).not.toHaveBeenCalled()
    expect(close).toHaveBeenCalledTimes(cancel ? 1 : 0)
    cleanup()
  }
})
test('synchronous guard blocks double click, Enter and closing before React updates', async () => {
  let finish: (value: unknown) => void = () => {}
  mutation.mockReturnValue({
    toPromise: () =>
      new Promise((resolve) => {
        finish = resolve
      }),
  })
  const { handlers, cleanup, close } = mount()
  await flush()
  handlers.onAcknowledge(true)
  const pending = handlers.onConfirm()
  handlers.onConfirm()
  handlers.onConfirm()
  handlers.onClose()
  handlers.onPreview()
  expect(mutation).toHaveBeenCalledTimes(1)
  expect(query).toHaveBeenCalledTimes(1)
  expect(close).not.toHaveBeenCalled()
  expect(state.phase).toBe('deleting')
  finish({ data: { deleteAll: true } })
  await pending
  cleanup()
})
test.each([
  { data: { deleteAll: false } },
  { data: { deleteAll: null } },
  { data: { deleteAll: true }, stale: true },
  { data: { deleteAll: true }, hasNext: true },
  { data: {} },
  {},
  { error: { networkError: new Error('synthetic disconnect') } },
  { error: { graphQLErrors: [{}] } },
  { data: { deleteAll: true }, error: { graphQLErrors: [{}] } },
])(
  'uncertain outcome never navigates, refreshes or retries %j',
  async (result) => {
    mutation.mockReturnValue({ toPromise: async () => result })
    const { handlers, cleanup } = mount()
    await flush()
    handlers.onAcknowledge(true)
    await handlers.onConfirm()
    await handlers.onConfirm()
    expect(state.phase).toBe('unknown')
    expect(state.preview).toBeUndefined()
    expect(acknowledged).toBe(false)
    expect(navigate).not.toHaveBeenCalled()
    expect(mutation).toHaveBeenCalledTimes(1)
    cleanup()
  },
)
test.each([
  ['DELETION_BLOCKED', 'blocked'],
  ['DELETION_PREVIEW_LIMIT_EXCEEDED', 'limit'],
  ['DELETION_UNAVAILABLE', 'unsupported'],
])('known %s rejection stops safely', async (code, phase) => {
  mutation.mockReturnValue({
    toPromise: async () => ({
      error: { graphQLErrors: [{ extensions: { code } }] },
    }),
  })
  const { handlers, cleanup } = mount()
  await flush()
  handlers.onAcknowledge(true)
  await handlers.onConfirm()
  expect(state.phase).toBe(phase)
  expect(acknowledged).toBe(false)
  expect(navigate).not.toHaveBeenCalled()
  expect(query).toHaveBeenCalledTimes(1)
  cleanup()
})

test.each(['TimeoutError', 'AbortError'])(
  '%s does not imply rollback or permit retry',
  async (name) => {
    mutation.mockReturnValue({
      toPromise: async () => {
        throw new DOMException('Synthetic transport exception', name)
      },
    })
    const { handlers, cleanup } = mount()
    await flush()
    handlers.onAcknowledge(true)
    await handlers.onConfirm()
    expect(state.phase).toBe('unknown')
    handlers.onPreview()
    handlers.onAcknowledge(true)
    await handlers.onConfirm()
    expect(state.phase).toBe('unknown')
    expect(mutation).toHaveBeenCalledTimes(1)
    expect(query).toHaveBeenCalledTimes(1)
    expect(navigate).not.toHaveBeenCalled()
    cleanup()
  },
)
