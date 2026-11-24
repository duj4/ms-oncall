import React from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import { createTheme, ThemeProvider } from '@mui/material/styles'
import DeletionSafetyDialog from '../dialogs/DeletionSafetyDialog'
import { serviceDeletionProfile } from '../util/deletionSafetyProfiles'
import { servicePreview } from './serviceDeletionFixtures'
type DeletionSafetyDialogProps =
  import('../dialogs/DeletionSafetyDialog').DeletionSafetyDialogProps
jest.mock('@mui/material', () => ({
  ...jest.requireActual('@mui/material'),
  Dialog: ({ children }: { children: import('react').ReactNode }) =>
    jest
      .requireActual('react')
      .createElement('div', { role: 'dialog' }, children),
}))
jest.mock('../env', () => ({ isCypress: true, nonce: '', pathPrefix: '' }))
const props = (name = 'closure'): DeletionSafetyDialogProps => ({
  profile: serviceDeletionProfile,
  state: { phase: 'review', loaded: 0, preview: servicePreview(name) },
  acknowledged: false,
  onAcknowledge: jest.fn(),
  onConfirm: jest.fn(),
  onPreview: jest.fn(),
  onClose: jest.fn(),
})
const render = (p: DeletionSafetyDialogProps): string =>
  renderToStaticMarkup(
    React.createElement(
      ThemeProvider,
      { theme: createTheme() },
      React.createElement(DeletionSafetyDialog, p),
    ),
  ).replace(/<style[^>]*>[\s\S]*?<\/style>/g, '')
const rows = (s: string): string[] =>
  (s.match(/<li\b[^>]*>[\s\S]*?<\/li>/g) || []).map((r) =>
    r.replace(/<[^>]*>/g, ''),
  )
test('Service explains single root, retained EP, actual closure counts and history', () => {
  const p = props()
  const html = render(p)
  for (const text of [
    'Delete Service',
    'only explicit deletion root',
    'escalation policy is preserved',
    'Open alerts may block deletion',
    'Closed alerts and integration keys',
    '2 unique alerts and 2 unique integration keys',
    'RETAINED_POLICY',
    'ALERT_DATA',
    'ALERT_FEEDBACK',
    'ALERT_METRICS',
    'ALERT_CYCLE',
    'ALERT_STATE',
    'ALERT_SUBSCRIPTION',
    'INTEGRATION_SOURCE',
    'INTEGRATION_LOG',
    'FAVORITE',
  ])
    expect(html).toContain(text)
  expect(html).not.toContain('Also delete escalation policy')
  expect(html).not.toContain(p.state.preview!.impactVersion)
  for (const row of rows(html)) {
    expect(row).not.toContain('Included in the backend deletion plan.')
    if (row.includes('Change: PRESERVED')) {
      expect(row).toMatch(
        /escalation policy is preserved|history resource is preserved/,
      )
      expect(row).not.toContain('would be deleted')
    }
    if (row.includes('Relation: INTEGRATION_SOURCE'))
      expect(row).toContain('integration key target is deleted')
  }
})
test('counts unique identities rather than causal/derived rows', () => {
  const p = props()
  const preview = p.state.preview!
  const edge = preview.impacts.edges.find(
    ({ node }) => node.relation === 'SERVICE_INTEGRATION_KEY',
  )!
  preview.impacts.edges.push({
    ...edge,
    cursor: 'another-cause',
    node: { ...edge.node, edgeID: 'another-cause' },
  })
  preview.impacts.edges.push({
    ...edge,
    cursor: 'explanation',
    node: { ...edge.node, edgeID: 'explanation', isDerived: true },
  })
  expect(render(p)).toContain('2 unique alerts and 2 unique integration keys')
  expect(render(p)).toContain(
    'Derived explanation; no additional deletion root.',
  )
  // Presentation-only duplicate/derived inputs. Profile rejects derived Service
  // rows and repeated EdgeID; these do not represent an executable backend plan.
})
test.each(['open', 'acknowledged', 'mixed', 'blockedMessages'])(
  'BLOCK %s cannot be acknowledged away',
  (name) => {
    const p = props(name)
    p.state.phase = 'blocked'
    p.acknowledged = true
    const html = render(p)
    expect(html).toContain('Handle the open alert, then check again.')
    expect(html).toMatch(/<button[^>]*disabled[^>]*>Confirm<\/button>/)
    expect(html).not.toContain('type="checkbox"')
  },
)
test.each(['empty', 'policy'])(
  'INFORMATIONAL %s needs final click without risk checkbox',
  (name) => {
    const html = render(props(name))
    expect(html).not.toContain('type="checkbox"')
    expect(html).not.toMatch(/<button[^>]*disabled[^>]*>Confirm<\/button>/)
  },
)
