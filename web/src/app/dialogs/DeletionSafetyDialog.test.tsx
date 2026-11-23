import {
  scheduleDeletionProfile,
  rotationDeletionProfile,
} from '../util/deletionSafetyProfiles'
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

test('Schedule shows backend owned rules, retained Rotation, parent and flags without an invented cascade count', () => {
  const p = props()
  p.profile = scheduleDeletionProfile
  const preview = p.state.preview!
  preview.targets[0].type = 'SCHEDULE'
  preview.targets[0].label = 'Synthetic schedule'
  const owned = preview.impacts.edges[0].node
  owned.target.type = 'SCHEDULE'
  owned.relation = 'SCHEDULE_RULE'
  owned.referencingResource.type = 'SCHEDULE_RULE'
  owned.referencingResource.label = 'Synthetic owned rule'
  owned.isPlannedCoDeletion = true
  preview.impacts.edges.push({
    cursor: 'second',
    node: {
      ...owned,
      edgeID: 'retained-rotation',
      target: {
        ...preview.targets[0],
        type: 'ROTATION',
        id: 'rotation-id',
        label: 'Retained rotation',
      },
      relation: 'RULE_TARGET',
      policy: 'INFORMATIONAL',
      change: 'PRESERVED',
      requiredAction: 'NONE',
      isDerived: true,
    },
  })
  const html = render(p)
  for (const text of [
    'Delete Schedule',
    'Selected schedule',
    'Synthetic schedule',
    'Synthetic owned rule',
    'CASCADE',
    'INFORMATIONAL',
    'RULE_TARGET',
    'PRESERVED',
    'Retained rotation',
    'Parent:',
    'Derived explanation',
    'Included in the backend deletion plan.',
    'Deleting a schedule does not automatically delete rotations.',
  ])
    expect(html).toContain(text)
  expect(html).not.toContain('unique policy steps/actions')
  expect(html).not.toContain('cascade-count')
})

test('Rotation displays actual participants/state and preserved User targets with no EP count or Schedule copy', () => {
  const p = props()
  p.profile = rotationDeletionProfile
  const preview = p.state.preview!
  preview.targets[0].type = 'ROTATION'
  const owned = preview.impacts.edges[0].node
  owned.relation = 'ROTATION_PARTICIPANT'
  owned.referencingResource.type = 'ROTATION_PARTICIPANT'
  owned.referencingResource.label = 'Synthetic owned participant'
  preview.impacts.edges.push(
    {
      cursor: 'state',
      node: {
        ...owned,
        edgeID: 'state',
        relation: 'ROTATION_STATE',
        referencingResource: {
          ...root,
          type: 'ROTATION_STATE',
          id: '1',
          label: 'Synthetic owned state',
        },
      },
    },
    {
      cursor: 'user',
      node: {
        ...owned,
        edgeID: 'user',
        relation: 'PARTICIPANT_USER',
        policy: 'INFORMATIONAL',
        change: 'PRESERVED',
        requiredAction: 'NONE',
        target: {
          ...root,
          type: 'USER',
          label: 'Preserved user',
        },
      },
    },
  )
  const html = render(p)
  for (const text of [
    'Delete Rotation',
    'Selected rotation',
    'ROTATION_PARTICIPANT',
    'ROTATION_STATE',
    'PARTICIPANT_USER',
    'Preserved user',
    'Synthetic owned participant',
    'Synthetic owned state',
    'CASCADE',
    'Parent:',
    'Required action:',
    'The affected resource would be deleted.',
    'Deleting a rotation does not automatically delete schedules or users.',
    'Existing references may block deletion.',
  ])
    expect(html).toContain(text)
  expect(html).not.toContain('cascade-count')
  expect(html).not.toContain('Deleting a schedule')
})
