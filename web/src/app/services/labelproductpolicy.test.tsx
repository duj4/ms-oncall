import React from 'react'
import { createTheme, ThemeProvider } from '@mui/material/styles'
import { renderToStaticMarkup } from 'react-dom/server'
import { print } from 'graphql'
import * as urqlCore from '@urql/core'

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
  applicationName: 'Label policy test',
  GOALERT_VERSION: 'test',
}))
jest.mock('../util/useWidth', () => ({
  useIsWidthDown: () => false,
  useIsWidthUp: () => true,
}))
jest.mock('../util/AppLink', () => ({
  AppLinkListItem: ({ children }: { children: React.ReactNode }) => (
    <li>{children}</li>
  ),
  __esModule: true,
  default: ({ children, to }: { children: React.ReactNode; to: string }) => (
    <a href={to}>{children}</a>
  ),
}))
jest.mock('../util/QuerySetFavoriteButton', () => ({
  QuerySetFavoriteButton: () => <button>Favorite</button>,
}))
jest.mock('./ServiceOnCallList', () => ({
  __esModule: true,
  default: () => <div>On Call</div>,
}))
jest.mock('./ServiceNotices', () => ({
  __esModule: true,
  default: () => null,
}))
jest.mock('./ServiceRecentEvents', () => ({
  __esModule: true,
  default: () => <div>Recent Events</div>,
}))
jest.mock('../util/FilterContainer', () => ({
  __esModule: true,
  default: ({ children }: { children: React.ReactNode }) => (
    <div>{children}</div>
  ),
}))
jest.mock('@mui/material/Drawer', () => ({
  __esModule: true,
  default: ({ children }: { children: React.ReactNode }) => (
    <div>{children}</div>
  ),
}))
jest.mock('../urql', () => ({ refetchAll: jest.fn() }))
jest.mock('../actions', () => ({
  SET_SHOW_NEW_USER_FORM: 'SET_SHOW_NEW_USER_FORM',
  AUTH_LOGOUT: 'AUTH_LOGOUT',
  getParamValues: () => ({}),
  sanitizeURLParam: (value: string) => value,
  useURLParams: () => [
    {
      epStepTgts: ['user'],
      intKeyTgts: [],
      labelKey: 'old/key',
      labelValue: 'old',
    },
    jest.fn(),
  ],
  useResetURLParams: () => jest.fn(),
  useURLParam: () => ['', jest.fn()],
  useURLKey: () => 'test',
  authLogout: jest.fn(),
}))
jest.mock('../forms', () => ({
  HelperText: ({ children }: { children: React.ReactNode }) => (
    <div>{children}</div>
  ),
  Form: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
  FormContainer: ({ children }: { children: React.ReactNode }) => (
    <div>{children}</div>
  ),
  FormField: ({
    label,
    name,
    fieldName,
  }: {
    label: string
    name: string
    fieldName: string
  }) => <input aria-label={label || name} data-field={fieldName || name} />,
}))
jest.mock('../admin/AdminSection', () => ({
  __esModule: true,
  default: ({ fields }: { fields: { id: string; label: string }[] }) => (
    <div>
      {fields.map((field) => (
        <span key={field.id}>
          {field.id} {field.label}
        </span>
      ))}
    </div>
  ),
}))
jest.mock('../dialogs/FormDialog', () => ({
  __esModule: true,
  default: ({ form, title }: { form: React.ReactNode; title: string }) => (
    <div>
      {title}
      {form}
    </div>
  ),
}))

/* eslint-disable @typescript-eslint/no-require-imports */
const { useQuery, useMutation } = require('urql') as typeof import('urql')
const { ConfigProvider } =
  require('../util/RequireConfig') as typeof import('../util/RequireConfig')
const { default: ServiceLabelList } =
  require('./ServiceLabelList') as typeof import('./ServiceLabelList')
const { default: ServiceLabelCreateDialog } =
  require('./ServiceLabelCreateDialog') as typeof import('./ServiceLabelCreateDialog')
const { default: ServiceLabelEditDialog } =
  require('./ServiceLabelEditDialog') as typeof import('./ServiceLabelEditDialog')
const { default: ServiceLabelDeleteDialog } =
  require('./ServiceLabelDeleteDialog') as typeof import('./ServiceLabelDeleteDialog')
const { default: ServiceLabelForm } =
  require('./ServiceLabelForm') as typeof import('./ServiceLabelForm')
const { LabelKeySelect } =
  require('../selection/LabelKeySelect') as typeof import('../selection/LabelKeySelect')
const { LabelValueSelect } =
  require('../selection/LabelValueSelect') as typeof import('../selection/LabelValueSelect')
const { default: ServiceDetails } =
  require('./ServiceDetails') as typeof import('./ServiceDetails')
const { default: ServiceForm } =
  require('./ServiceForm') as typeof import('./ServiceForm')
const { default: ServiceEditDialog } =
  require('./ServiceEditDialog') as typeof import('./ServiceEditDialog')
const { default: ServiceCreateDialog } =
  require('./ServiceCreateDialog') as typeof import('./ServiceCreateDialog')
const { default: ServiceFilterContainer } =
  require('./ServiceFilterContainer') as typeof import('./ServiceFilterContainer')
const { default: AdminServiceFilter } =
  require('../admin/admin-service-metrics/AdminServiceFilter') as typeof import('../admin/admin-service-metrics/AdminServiceFilter')
const { default: ScheduleForm } =
  require('../schedules/ScheduleForm') as typeof import('../schedules/ScheduleForm')
const { default: RotationForm } =
  require('../rotations/RotationForm') as typeof import('../rotations/RotationForm')
const { default: PolicyForm } =
  require('../escalation-policies/PolicyForm') as typeof import('../escalation-policies/PolicyForm')
const { useServiceMetrics: calculateServiceMetrics } =
  require('../admin/admin-service-metrics/useServiceMetrics') as typeof import('../admin/admin-service-metrics/useServiceMetrics')
const { default: AdminConfig } =
  require('../admin/AdminConfig') as typeof import('../admin/AdminConfig')
Object.defineProperty(globalThis, 'window', {
  value: { addEventListener: () => {}, removeEventListener: () => {} },
  configurable: true,
})
Object.defineProperty(globalThis, 'location', {
  value: { href: 'https://labels.invalid/', pathname: '/', search: '' },
  configurable: true,
})
const { routes } =
  require('../main/AppRoutes') as typeof import('../main/AppRoutes')
/* eslint-enable @typescript-eslint/no-require-imports */

const queryMock = useQuery as jest.MockedFunction<typeof useQuery>
const mutationMock = useMutation as jest.MockedFunction<typeof useMutation>
const testTheme = createTheme()

function renderWithConfig(
  child: React.ReactElement,
  disabled: boolean | undefined,
): string {
  queryMock.mockImplementation((args) => {
    const query =
      typeof args.query === 'string' ? args.query : print(args.query)
    if (/labelKeys|labelValues|\blabels\s*\(/.test(query))
      throw new Error('Label UI must not initialize discovery queries')
    let data = {}
    if (query.includes('RequireConfig')) {
      data = {
        user: { id: 'owner', role: 'admin' },
        integrationKeyTypes: [],
        destinationTypes: [],
        config:
          disabled === undefined
            ? []
            : [
                {
                  id: 'General.DisableLabelCreation',
                  type: 'boolean',
                  value: String(disabled),
                },
                {
                  id: 'Services.RequiredLabels',
                  type: 'stringList',
                  value: 'foo',
                },
              ],
      }
    } else if (query.includes('getConfig')) {
      data = {
        config: [
          {
            id: 'General.DisableLabelCreation',
            type: 'boolean',
            value: String(disabled),
          },
          { id: 'Services.RequiredLabels', type: 'stringList', value: 'foo' },
          { id: 'General.ApplicationName', type: 'string', value: 'Neighbor' },
        ],
        configHints: [],
      }
    } else if (
      query.includes('serviceDetailsQuery') ||
      query.includes('query service(')
    ) {
      data = {
        service: {
          id: 'service',
          name: 'Neighbor Service',
          description: 'Normal service',
          labels: [{ key: 'old/key', value: 'DORMANT_VALUE' }],
          ep: { id: 'ep', name: 'Neighbor Policy' },
          heartbeatMonitors: [],
          onCallUsers: [],
        },
        alerts: { nodes: [] },
      }
    }
    return [{ fetching: false, stale: false, hasNext: false, data }, jest.fn()]
  })
  mutationMock.mockImplementation((query) => {
    if (/\bsetLabel\b/.test(typeof query === 'string' ? query : print(query)))
      throw new Error('Label UI must not initialize mutations')
    return [{ fetching: false, stale: false, hasNext: false }, jest.fn()]
  })
  return renderToStaticMarkup(
    <ThemeProvider theme={testTheme}>
      <ConfigProvider>{child}</ConfigProvider>
    </ThemeProvider>,
  )
}

describe.each([true, false, undefined])(
  'Label immutable policy with config=%s',
  (disabled) => {
    it('gates the historical page, dialogs, forms, and selectors before any hooks', () => {
      for (const child of [
        <ServiceLabelCreateDialog
          key='create'
          serviceID='service'
          onClose={() => {}}
        />,
        <ServiceLabelEditDialog
          key='edit'
          serviceID='service'
          labelKey='old/key'
          onClose={() => {}}
        />,
        <ServiceLabelDeleteDialog
          key='delete'
          serviceID='service'
          labelKey='old/key'
          onClose={() => {}}
        />,
        <ServiceLabelForm
          key='form'
          value={{ key: 'old/key', value: 'old' }}
          errors={[]}
          onChange={() => {}}
        />,
        <LabelKeySelect key='key' name='label-key' />,
        <LabelValueSelect
          key='value'
          name='label-value'
          labelKey='old/key'
          disabled={false}
        />,
      ]) {
        queryMock.mockClear()
        mutationMock.mockClear()
        expect(renderWithConfig(child, disabled)).toBe('')
        expect(queryMock).toHaveBeenCalledTimes(1) // ConfigProvider only.
        expect(mutationMock).not.toHaveBeenCalled()
      }
      queryMock.mockClear()
      mutationMock.mockClear()
      const html = renderWithConfig(
        <ServiceLabelList serviceID='historical' />,
        disabled,
      )
      expect(html).toContain('could not be found')
      expect(html).not.toContain('Create Label')
      expect(queryMock).toHaveBeenCalledTimes(1)
      expect(mutationMock).not.toHaveBeenCalled()
    })

    it('gates the registered historical route and hides mutable Label config controls', () => {
      const LabelRoute = routes['/services/:serviceID/labels']
      queryMock.mockClear()
      const html = renderWithConfig(
        <LabelRoute serviceID='historical' />,
        disabled,
      )
      expect(html).toContain('could not be found')
      expect(queryMock).toHaveBeenCalledTimes(1)
      const config = renderWithConfig(<AdminConfig />, disabled)
      expect(config).not.toContain('Required Labels')
      expect(config).not.toContain('Disable Label Creation')
      expect(config).toContain('Application Name')
    })

    it('hides Label navigation and dormant values while preserving Service actions', () => {
      const html = renderWithConfig(
        <ServiceDetails serviceID='service' />,
        disabled,
      )
      expect(html).not.toContain('Labels')
      expect(html).not.toContain('old/key')
      expect(html).not.toContain('DORMANT_VALUE')
      expect(html).toContain('Integration Keys')
      expect(html).toContain('Alert Metrics')
      expect(html).toContain('Maintenance Mode')
      expect(html).toContain('Neighbor Service')
    })

    it('hides RequiredLabels and keeps normal Service create/edit forms', () => {
      const html = renderWithConfig(
        <ServiceForm
          value={{ name: '', description: '', labels: [] }}
          onChange={() => {}}
        />,
        disabled,
      )
      expect(html).not.toContain('foo')
      expect(html).not.toContain('Service Label')
      expect(html).toContain('Name')
      expect(html).toContain('Escalation Policy')
      expect(
        renderWithConfig(<ServiceCreateDialog onClose={() => {}} />, disabled),
      ).toContain('Create New Service')
      expect(
        renderWithConfig(
          <ServiceEditDialog serviceID='service' onClose={() => {}} />,
          disabled,
        ),
      ).toContain('Edit Service')
    })

    it('keeps Integration Key filters and admin non-Label filters', () => {
      const html = renderWithConfig(
        <ServiceFilterContainer
          value={{ labelKey: 'old/key', labelValue: 'old', integrationKey: '' }}
          onChange={() => {}}
          onReset={() => {}}
        />,
        disabled,
      )
      expect(html).toContain('Search by Integration Key')
      expect(html).not.toContain('Search by Label')
      expect(html).not.toContain('Select Label')
      const admin = renderWithConfig(<AdminServiceFilter />, disabled)
      expect(admin).toContain('EP Step Targets')
      expect(admin).toContain('Integration Key Targets')
      expect(admin).not.toContain('Select Label')
      expect(admin).not.toContain('old/key')
    })

    it('preserves Schedule, Rotation, and Policy forms without resource Label fields', () => {
      const forms = [
        <ScheduleForm
          key='schedule'
          value={{ name: '', description: '', timeZone: 'Etc/UTC' }}
          onChange={() => {}}
        />,
        <RotationForm
          key='rotation'
          value={{
            name: '',
            description: '',
            timeZone: 'Etc/UTC',
            type: 'daily',
            start: '2026-10-05T00:00:00Z',
            shiftLength: 1,
          }}
          errors={[]}
          onChange={() => {}}
        />,
        <PolicyForm
          key='policy'
          value={{
            name: '',
            description: '',
            repeat: { label: '0', value: '0' },
          }}
        />,
      ]
      for (const child of forms) {
        const html = renderWithConfig(child, disabled)
        expect(html).toContain('Name')
        expect(html).toContain('Description')
        expect(html).not.toContain('data-field="labels"')
        expect(html).not.toContain('Select Label')
      }
    })
  },
)

it('fails closed on restored admin Label filters without examining dormant rows', () => {
  for (const filters of [
    { labelKey: 'old/key' },
    { labelValue: 'old' },
    { labelKey: 'old/key', intKeyTgts: ['generic'] },
  ]) {
    const result = calculateServiceMetrics({
      services: [],
      alerts: [],
      filters,
    })
    expect(result.error).toBe('labels are disabled')
    expect(result.filteredServices).toEqual([])
  }
  expect(
    calculateServiceMetrics({ services: [], alerts: [], filters: {} }).error,
  ).toBeUndefined()
})
