import React from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import { createTheme, ThemeProvider } from '@mui/material/styles'
import * as urqlCore from '@urql/core'
import { print } from 'graphql'
import type { PolicyStepFormProps } from './PolicyStepForm'

jest.mock('urql', () => ({
  ...urqlCore,
  useQuery: jest.fn(),
  useMutation: jest.fn(),
  useClient: jest.fn(),
  useSubscription: jest.fn(),
}))
jest.mock('../env', () => ({
  isCypress: false,
  nonce: '',
  pathPrefix: '',
  applicationName: 'C8 test',
  GOALERT_VERSION: 'test',
}))
jest.mock('../util/AppLink', () => ({
  __esModule: true,
  AppLinkListItem: ({ children }: { children: React.ReactNode }) => (
    <li>{children}</li>
  ),
  default: ({ children, to }: { children: React.ReactNode; to: string }) => (
    <a href={to}>{children}</a>
  ),
}))
jest.mock('../dialogs/FormDialog', () => ({
  __esModule: true,
  default: () => null,
}))
jest.mock('../selection/DestinationField', () => ({
  __esModule: true,
  default: () => null,
}))
jest.mock('../util/DestinationInputChip', () => ({
  __esModule: true,
  default: () => null,
}))
/* eslint-disable @typescript-eslint/no-require-imports */
const { useMutation, useQuery } = require('urql') as typeof import('urql')
const { ConfigProvider } =
  require('../util/RequireConfig') as typeof import('../util/RequireConfig')
const { FormField } = require('../forms') as typeof import('../forms')
const { default: PolicyStepForm } =
  require('./PolicyStepForm') as typeof import('./PolicyStepForm')
const { default: PolicyStepCreateDialog } =
  require('./PolicyStepCreateDialog') as typeof import('./PolicyStepCreateDialog')
const { default: PolicyStepEditDialog } =
  require('./PolicyStepEditDialog') as typeof import('./PolicyStepEditDialog')
const { renderMultiAckMessage } =
  require('./stepUtil') as typeof import('./stepUtil')

const action = { type: 'builtin-user', args: { user_id: 'test-user' } }
const mockUseMutation = useMutation as jest.Mock
const mockUseQuery = useQuery as jest.Mock

const dispatcher = (
  React as typeof React & {
    __SECRET_INTERNALS_DO_NOT_USE_OR_YOU_WILL_BE_FIRED: {
      ReactCurrentDispatcher: { current: unknown }
    }
  }
).__SECRET_INTERNALS_DO_NOT_USE_OR_YOU_WILL_BE_FIRED.ReactCurrentDispatcher
const originalDispatcher = dispatcher.current

afterEach(() => {
  dispatcher.current = originalDispatcher
  jest.restoreAllMocks()
})

test.each([false, true])(
  'real form checkbox renders %s and sends the toggled boolean',
  (enabled) => {
    const onChange = jest.fn()
    const value = { actions: [action], delayMinutes: 15, multiAck: enabled }
    mockUseQuery.mockReturnValue([
      {
        data: {
          destinationTypes: [
            {
              type: 'builtin-user',
              name: 'User',
              enabled: true,
              isEPTarget: true,
            },
          ],
        },
      },
      jest.fn(),
    ])
    const markup = renderToStaticMarkup(
      <ConfigProvider>
        <ThemeProvider theme={createTheme()}>
          <PolicyStepForm value={value} onChange={onChange} />
        </ThemeProvider>
      </ConfigProvider>,
    )
    expect(markup).toContain(
      'Continue notifications after acknowledgment (multi-ack)',
    )
    const checkbox = markup.match(/<input[^>]*name="multiAck"[^>]*>/)?.[0]
    expect(checkbox).toBeDefined()
    expect(checkbox!.includes('checked=""')).toBe(enabled)
    expect(
      renderToStaticMarkup(
        <React.Fragment>{renderMultiAckMessage(value)}</React.Fragment>,
      ),
    ).toEqual(
      enabled
        ? expect.stringContaining(
            'Notifications continue after acknowledgment (multi-ack)',
          )
        : '',
    )
    dispatcher.current = {
      useContext: () => ({ value, errors: [], onChange, addField: jest.fn() }),
      useEffect: () => {},
    }
    FormField({
      name: 'multiAck',
      checkbox: true,
      render: (props: {
        checked: boolean
        onChange: (event: { target: { checked: boolean } }) => void
      }) => {
        expect(props.checked).toBe(enabled)
        props.onChange({ target: { checked: !enabled } })
        return null
      },
    })
    expect(onChange).toHaveBeenCalledWith('multiAck', !enabled)
  },
)

// Run each dialog's real hook-backed state/save code with a deterministic hook
// driver on the pinned React 18 dispatcher. It works with the repository's Bun
// runner without requiring a browser or another rendering dependency.
function dialogState(): () => void {
  const values: unknown[] = []
  let index = 0
  dispatcher.current = {
    useState: (initial: unknown) => {
      const slot = index++
      if (slot === values.length) values.push(initial)
      return [
        values[slot],
        (next: unknown) => {
          values[slot] = typeof next === 'function' ? next(values[slot]) : next
        },
      ]
    },
    useEffect: () => {},
  }
  return () => {
    index = 0
  }
}

type DialogProps = {
  form: React.ReactElement<PolicyStepFormProps>
  onSubmit: () => unknown
}

test.each([false, true])(
  'create defaults false and saves explicit %s on the parent Policy',
  async (enabled) => {
    const save = jest.fn().mockResolvedValue({})
    mockUseMutation.mockReturnValue([{ fetching: false }, save])
    const reset = dialogState()
    const render = (): DialogProps => {
      reset()
      return (
        PolicyStepCreateDialog({
          escalationPolicyID: 'own-policy',
          onClose: jest.fn(),
        }) as React.ReactElement<DialogProps>
      ).props
    }
    let dialog = render()
    expect(dialog.form.props.value.multiAck).toBe(false)
    dialog.form.props.onChange({
      ...dialog.form.props.value,
      actions: [action],
      multiAck: enabled,
    })
    dialog = render()
    await dialog.onSubmit()
    expect(save).toHaveBeenCalledWith(
      {
        input: {
          escalationPolicyID: 'own-policy',
          actions: [action],
          delayMinutes: 15,
          multiAck: enabled,
        },
      },
      { additionalTypenames: ['EscalationPolicy'] },
    )
  },
)

test.each([false, true])(
  'edit loads %s through its parent Policy and saves the opposite value',
  async (enabled) => {
    const save = jest.fn().mockResolvedValue({})
    mockUseMutation.mockReturnValue([{ fetching: false }, save])
    mockUseQuery.mockReturnValue([
      {
        fetching: false,
        stale: false,
        data: {
          escalationPolicy: {
            steps: [
              {
                id: 'own-step',
                actions: [action],
                delayMinutes: 60,
                multiAck: enabled,
              },
            ],
          },
        },
      },
      jest.fn(),
    ])
    const reset = dialogState()
    const render = (): DialogProps => {
      reset()
      return (
        PolicyStepEditDialog({
          escalationPolicyID: 'own-policy',
          stepID: 'own-step',
          onClose: jest.fn(),
        }) as React.ReactElement<DialogProps>
      ).props
    }
    let dialog = render()
    expect(dialog.form.props.value.multiAck).toBe(enabled)
    const calls = mockUseQuery.mock.calls
    const input = calls[calls.length - 1]?.[0]
    expect(input?.variables).toEqual({ id: 'own-policy' })
    expect(print(input!.query as urqlCore.TypedDocumentNode)).toContain(
      'multiAck',
    )
    dialog.form.props.onChange({
      ...dialog.form.props.value,
      multiAck: !enabled,
    })
    dialog = render()
    await dialog.onSubmit()
    expect(save).toHaveBeenCalledWith(
      {
        input: {
          id: 'own-step',
          actions: [action],
          delayMinutes: 60,
          multiAck: !enabled,
        },
      },
      { additionalTypenames: ['EscalationPolicy'] },
    )
  },
)
