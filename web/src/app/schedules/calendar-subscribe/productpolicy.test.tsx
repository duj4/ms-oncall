import React from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import { print } from 'graphql'
import * as urqlCore from '@urql/core'

jest.mock('urql', () => ({
  ...urqlCore,
  useQuery: jest.fn(),
  useClient: jest.fn(),
  useSubscription: jest.fn(),
  useMutation: jest.fn(() => {
    throw new Error('Disabled Calendar UI must not initialize mutations')
  }),
}))

// Keep unrelated profile content outside these product-boundary assertions.
jest.mock('../../details/DetailsPage', () => ({
  __esModule: true,
  default: ({ links }: { links: { label: string }[] }) => (
    <div>{links.map((link) => link.label).join(',')}</div>
  ),
}))
jest.mock('../../util/useWidth', () => ({
  useIsWidthDown: () => false,
  useIsWidthUp: () => true,
}))
jest.mock('../../env', () => ({
  isCypress: false,
  nonce: '',
  pathPrefix: '',
  applicationName: 'Calendar policy test',
  GOALERT_VERSION: 'test',
}))

// Load components after mocks to avoid initializing unrelated browser-only
// modules in the repository's Bun runner during this server-render test.
/* eslint-disable @typescript-eslint/no-require-imports */
const { useQuery } = require('urql') as typeof import('urql')
const { ConfigProvider } =
  require('../../util/RequireConfig') as typeof import('../../util/RequireConfig')
const { default: CalendarSubscribeButton } =
  require('./CalendarSubscribeButton') as typeof import('./CalendarSubscribeButton')
const { default: CalendarSubscribeCreateDialog } =
  require('./CalendarSubscribeCreateDialog') as typeof import('./CalendarSubscribeCreateDialog')
const { default: CalendarSubscribeEditDialog } =
  require('./CalendarSubscribeEditDialog') as typeof import('./CalendarSubscribeEditDialog')
const { default: UserCalendarSubscriptionList } =
  require('../../users/UserCalendarSubscriptionList') as typeof import('../../users/UserCalendarSubscriptionList')
const { default: UserDetails } =
  require('../../users/UserDetails') as typeof import('../../users/UserDetails')
/* eslint-enable @typescript-eslint/no-require-imports */

const queryMock = useQuery as jest.MockedFunction<typeof useQuery>

function renderWithConfig(
  child: React.ReactElement,
  disabled: boolean | undefined,
): string {
  queryMock.mockImplementation((args) => {
    const query =
      typeof args.query === 'string' ? args.query : print(args.query)
    if (query.includes('RequireConfig')) {
      return [
        {
          fetching: false,
          stale: false,
          hasNext: false,
          data: {
            user: { id: 'owner', role: 'user' },
            config:
              disabled === undefined
                ? []
                : [
                    {
                      id: 'General.DisableCalendarSubscriptions',
                      type: 'boolean',
                      value: String(disabled),
                    },
                  ],
          },
        },
        jest.fn(),
      ]
    }
    if (query.includes('profileInfo')) {
      return [
        {
          fetching: false,
          stale: false,
          hasNext: false,
          data: {
            user: {
              id: 'owner',
              name: 'Synthetic owner',
              contactMethods: [],
              sessions: [],
              onCallOverview: { serviceCount: 0 },
            },
          },
        },
        jest.fn(),
      ]
    }
    throw new Error('Disabled Calendar UI must not query subscription state')
  })
  return renderToStaticMarkup(<ConfigProvider>{child}</ConfigProvider>)
}

describe.each([true, undefined])('Calendar disabled config=%s', (disabled) => {
  it('hides Subscribe without querying subscriptions', () => {
    expect(
      renderWithConfig(
        <CalendarSubscribeButton scheduleID='schedule' />,
        disabled,
      ),
    ).toBe('')
  })

  it('hides the profile navigation entry and preserves neighboring links', () => {
    const html = renderWithConfig(
      <UserDetails userID='owner' readOnly={false} />,
      disabled,
    )
    expect(html).not.toContain('Schedule Calendar Subscriptions')
    expect(html).toContain('On-Call Assignments')
    expect(html).toContain('Active Sessions')
  })

  it('gates the component registered for direct subscription-list routes', () => {
    const html = renderWithConfig(
      <UserCalendarSubscriptionList userID='owner' />,
      disabled,
    )
    expect(html).toContain('could not be found')
    expect(html).not.toContain('Create Subscription')
    expect(html).not.toContain('calendar-subscriptions')
  })

  it('does not mount create or edit product actions', () => {
    expect(
      renderWithConfig(
        <CalendarSubscribeCreateDialog onClose={() => {}} />,
        disabled,
      ),
    ).toBe('')
    expect(
      renderWithConfig(
        <CalendarSubscribeEditDialog
          calSubscriptionID='historical'
          onClose={() => {}}
        />,
        disabled,
      ),
    ).toBe('')
  })
})
