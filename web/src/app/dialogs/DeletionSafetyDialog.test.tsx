import React from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import { createTheme, ThemeProvider } from '@mui/material/styles'
import DeletionSafetyDialog from './DeletionSafetyDialog'
type DeletionPreview = import('../../schema').DeletionPreview
type DeletionSafetyDialogProps =
  import('./DeletionSafetyDialog').DeletionSafetyDialogProps
type DeletionPhase = import('../util/deletionSafety').DeletionPhase

// SSR assertions cover presentation only. User interactions are exercised by
// the adapter's callback tests and the separate browser/Cypress campaign.
jest.mock('@mui/material', () => ({
  ...jest.requireActual('@mui/material'),
  Dialog: ({ children }: { children: import('react').ReactNode }) =>
    jest
      .requireActual('react')
      .createElement('div', { role: 'dialog' }, children),
}))
jest.mock('../env', () => ({ isCypress: true, nonce: '', pathPrefix: '' }))
const root = {
  type: 'ESCALATION_POLICY',
  id: '10000000-0000-4000-8000-000000000001',
  label: 'Safe policy',
  name: null,
  organization: null,
}
function fixture(): DeletionPreview {
  return {
    operation: 'DELETE_RESOURCES',
    targets: [root],
    impactVersion: 'private-version-sentinel',
    policyVersion: 'deletion-safety-spec1-v2',
    assessedAt: '2026-11-21T10:00:00Z',
    complete: true,
    canProceed: true,
    requiresConfirmation: true,
    notices: ['Safe notice'],
    impacts: {
      edges: [
        {
          cursor: 'private-cursor-sentinel',
          node: {
            edgeID: 'step-edge',
            target: root,
            referencingResource: {
              ...root,
              type: 'ESCALATION_POLICY_STEP',
              id: 'step-id',
              label: '<img src=x onerror=alert(1)>',
            },
            parent: root,
            relation: 'POLICY_STEP',
            policy: 'CASCADE',
            change: 'DELETED',
            requiredAction: 'CONFIRM_IMPACT',
            impact: 'The affected resource would be deleted.',
            canModifyReference: false,
            isDerived: false,
            isPlannedCoDeletion: false,
          },
        },
      ],
      pageInfo: { endCursor: 'private-cursor-sentinel', hasNextPage: false },
    },
  }
}
function props(phase: DeletionPhase = 'review'): DeletionSafetyDialogProps {
  return {
    state: {
      phase,
      loaded: 0,
      preview: phase === 'review' ? fixture() : undefined,
    },
    acknowledged: false,
    onAcknowledge: jest.fn(),
    onConfirm: jest.fn(),
    onPreview: jest.fn(),
    onClose: jest.fn(),
  }
}
function render(p: DeletionSafetyDialogProps): string {
  return renderToStaticMarkup(
    React.createElement(
      ThemeProvider,
      { theme: createTheme() },
      React.createElement(DeletionSafetyDialog, p),
    ),
  )
}
function confirmDisabled(html: string): boolean {
  return /<button[^>]*disabled[^>]*>Confirm<\/button>/.test(html)
}
test('loading displays only loaded relationship count and cannot confirm', () => {
  const p = props('loading')
  p.state.loaded = 100
  const html = render(p)
  expect(html).toContain('Checking dependencies')
  expect(html).toContain('Loaded 100 relationships')
  expect(confirmDisabled(html)).toBe(true)
  expect(html).not.toContain('unique policy steps/actions')
})
test('root, real impact and parent render as escaped text without exposing version/cursor', () => {
  const html = render(props())
  expect(html).toContain('Safe policy')
  expect(html).toContain('Parent:')
  expect(html).toContain('CASCADE')
  expect(html).toContain('POLICY_STEP')
  expect(html).toContain('&lt;img')
  expect(html).not.toContain('<img src=x')
  expect(html).not.toContain('private-version-sentinel')
  expect(html).not.toContain('private-cursor-sentinel')
  expect(html).not.toMatch(/checked=""/)
  expect(confirmDisabled(html)).toBe(true)
})
test('requiresConfirmation true/false both require a final click; only true requires checkbox', () => {
  const p = props()
  p.acknowledged = true
  expect(confirmDisabled(render(p))).toBe(false)
  p.acknowledged = false
  p.state.preview!.requiresConfirmation = false
  const html = render(p)
  expect(confirmDisabled(html)).toBe(false)
  expect(html).not.toContain('type="checkbox"')
})
test.each([
  'blocked',
  'unsupported',
  'failed',
  'limit',
  'unknown',
  'deleting',
  'success',
  'cancelled',
] as const)('%s never offers an enabled deletion', (phase) => {
  expect(confirmDisabled(render(props(phase)))).toBe(true)
})
test('commit unknown has a neutral message and no retry/check-again action', () => {
  const html = render(props('unknown'))
  expect(html).toContain('Verify the resource status')
  expect(html).not.toContain('Check again')
  expect(html).not.toContain('Retry')
})
test('during delete Escape, backdrop and cancel cannot close the dialog', () => {
  const p = props('deleting')
  const element = DeletionSafetyDialog(p)
  expect(element.props.disableEscapeKeyDown).toBe(true)
  element.props.onClose()
  expect(p.onClose).not.toHaveBeenCalled()
  expect(render(p)).toMatch(/<button[^>]*disabled[^>]*>Cancel<\/button>/)
})
