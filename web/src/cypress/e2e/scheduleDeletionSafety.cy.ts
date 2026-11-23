import type { Schedule, DeletionImpact, DeletionPreview } from '../../schema'
import { testScreen } from '../support/e2e'

// App navigation/auth/fixtures use the existing integration environment.
// Preview/delete responses below are browser mocks, not backend evidence.
function preview(
  ep: Schedule,
  extra: Partial<DeletionPreview> = {},
): DeletionPreview {
  return {
    operation: 'DELETE_RESOURCES',
    targets: [
      {
        type: 'SCHEDULE',
        id: ep.id,
        name: ep.name,
        label: ep.name,
        organization: null,
      },
    ],
    impactVersion: 'synthetic-version-1',
    policyVersion: 'deletion-safety-spec1-v2',
    assessedAt: '2026-11-21T10:00:00Z',
    complete: true,
    canProceed: true,
    requiresConfirmation: false,
    notices: ['Synthetic safe notice'],
    impacts: { edges: [], pageInfo: { endCursor: null, hasNextPage: false } },
    ...extra,
  }
}
function impact(
  ep: Schedule,
  n: number,
  extra: Partial<DeletionImpact> = {},
): DeletionPreview['impacts']['edges'][number] {
  const root = preview(ep).targets[0]
  return {
    cursor: 'synthetic-cursor-' + n,
    node: {
      edgeID: 'synthetic-edge-' + n,
      target: root,
      referencingResource: {
        ...root,
        type: 'SCHEDULE_RULE',
        id: '20000000-0000-4000-8000-' + String(n).padStart(12, '0'),
        name: null,
        label: 'Synthetic policy step',
      },
      parent: root,
      relation: 'SCHEDULE_RULE',
      change: 'DELETED',
      policy: 'CASCADE',
      requiredAction: 'CONFIRM_IMPACT',
      impact: 'The affected resource would be deleted.',
      canModifyReference: true,
      isDerived: false,
      isPlannedCoDeletion: false,
      ...extra,
    },
  }
}
function withImpacts(ep: Schedule): DeletionPreview {
  const edges = [
    impact(ep, 1),
    impact(ep, 2, {
      relation: 'SCHEDULE_HISTORY',
      policy: 'WARNING',
      referencingResource: {
        ...preview(ep).targets[0],
        type: 'SCHEDULE_HISTORY',
        label: 'Synthetic history',
      },
    }),
    impact(ep, 4, {
      target: {
        ...preview(ep).targets[0],
        type: 'ROTATION',
        label: 'Retained synthetic rotation',
      },
      relation: 'RULE_TARGET',
      policy: 'INFORMATIONAL',
      change: 'PRESERVED',
      requiredAction: 'NONE',
      impact: 'The referenced rotation is preserved.',
    }),
    impact(ep, 3, {
      isDerived: true,
      policy: 'INFORMATIONAL',
      change: 'PRESERVED',
      requiredAction: 'NONE',
    }),
  ]
  return preview(ep, {
    requiresConfirmation: true,
    impacts: {
      edges,
      pageInfo: {
        endCursor: edges[edges.length - 1].cursor,
        hasNextPage: false,
      },
    },
  })
}
function open(): void {
  cy.get('[data-cy="card-actions"] button[aria-label="Delete"]').click()
  cy.dialogTitle('Delete Schedule')
}
function confirm(): Cypress.Chainable<JQuery<HTMLButtonElement>> {
  return cy.dialog().contains('button', /^Confirm$/)
}
function acknowledge(): void {
  cy.dialog().find('input[type=checkbox]').check()
}
function run(): void {
  let ep: Schedule
  let previewCalls: number
  let deleteCalls: number
  let response: (
    after: string | null,
  ) => DeletionPreview | Promise<DeletionPreview>
  let deletion: () => object
  beforeEach(() => {
    previewCalls = 0
    deleteCalls = 0
    response = () => preview(ep)
    deletion = () => ({ data: { deleteAll: true } })
    cy.intercept('POST', '**/api/graphql*', (req) => {
      if (req.body.query?.includes('query EPDeletionPreview')) {
        previewCalls++
        expect(req.body.variables).to.deep.equal({
          input: {
            operation: 'DELETE_RESOURCES',
            targets: [{ type: 'SCHEDULE', id: ep.id }],
          },
          first: 100,
          after: req.body.variables.after,
        })
        req.alias = 'deletionPreview'
        return Promise.resolve(response(req.body.variables.after)).then(
          (value) => {
            req.reply({ data: { deletionPreview: value } })
          },
        )
      }
      if (req.body.query?.includes('mutation EPDeleteWithSafety')) {
        deleteCalls++
        expect(req.body.variables.input).to.deep.equal([
          { type: 'schedule', id: ep.id },
        ])
        expect(
          Object.keys(req.body.variables.confirmation).sort(),
        ).to.deep.equal(['acknowledgeImpacts', 'expectedImpactVersion'])
        req.alias = 'safeDelete'
        req.reply(deletion())
      }
    })
    cy.createSchedule().then((value: Schedule) => {
      ep = value
      cy.visit(`/schedules/${ep.id}`)
    })
  })
  it('loads before review, allows cancellation, and ignores the late response', () => {
    let release: (value: DeletionPreview) => void = () => {}
    response = () =>
      new Promise((resolve) => {
        release = resolve
      })
    open()
    cy.dialogContains('Checking dependencies')
    confirm().should('be.disabled')
    cy.dialogFinish('Cancel')
    cy.then(() => release(preview(ep)))
    cy.wait('@deletionPreview')
    cy.get('[role=dialog]').should('not.exist')
    cy.then(() => expect(deleteCalls).to.eq(0))
  })
  it('displays blocking relationships and never submits', () => {
    response = () => {
      const edge = impact(ep, 1, {
        relation: 'ACTION_TARGET',
        policy: 'BLOCK',
        change: 'PRESERVED',
        requiredAction: 'DETACH_REFERENCE',
        referencingResource: {
          ...preview(ep).targets[0],
          type: 'ESCALATION_POLICY_ACTION',
          label: 'Synthetic dependent EP action',
          name: 'Synthetic dependent EP action',
        },
      })
      return preview(ep, {
        canProceed: false,
        impacts: {
          edges: [edge],
          pageInfo: { endCursor: edge.cursor, hasNextPage: false },
        },
      })
    }
    open()
    cy.wait('@deletionPreview')
    cy.dialogContains('Synthetic dependent EP action')
    cy.dialogContains('BLOCK')
    confirm().should('be.disabled')
    cy.then(() => expect(deleteCalls).to.eq(0))
  })
  it('shows cascade/warning/derived data, requires a fresh checkbox and sends exact confirmation', () => {
    response = () => withImpacts(ep)
    open()
    cy.wait('@deletionPreview')
    cy.dialogContains('CASCADE')
    cy.dialogContains('WARNING')
    cy.dialogContains('Retained synthetic rotation')
    cy.dialogContains('The referenced rotation is preserved.')
    cy.dialogContains('Derived explanation')
    cy.dialogContains(
      'Deleting a schedule does not automatically delete rotations.',
    )
    cy.dialog().find('[data-cy=cascade-count]').should('not.exist')
    cy.dialog().find('input[type=checkbox]').should('not.be.checked')
    confirm().should('be.disabled')
    acknowledge()
    confirm().click()
    cy.wait('@safeDelete')
      .its('request.body.variables.confirmation')
      .should('deep.equal', {
        expectedImpactVersion: 'synthetic-version-1',
        acknowledgeImpacts: true,
      })
    cy.location('pathname').should('eq', '/schedules')
    cy.then(() => expect(deleteCalls).to.eq(1))
  })
  it('cannot confirm before all pages complete', () => {
    let release: (value: DeletionPreview) => void = () => {}
    response = (after) => {
      if (after)
        return new Promise((resolve) => {
          release = resolve
        })
      const edge = impact(ep, 1)
      return preview(ep, {
        requiresConfirmation: true,
        impacts: {
          edges: [edge],
          pageInfo: { endCursor: edge.cursor, hasNextPage: true },
        },
      })
    }
    open()
    cy.wait('@deletionPreview')
    cy.dialogContains('Loaded 1 relationships')
    confirm().should('be.disabled')
    cy.then(() => {
      const edge = impact(ep, 2)
      release(
        preview(ep, {
          requiresConfirmation: true,
          assessedAt: '2026-11-21T10:01:00Z',
          impacts: {
            edges: [edge],
            pageInfo: { endCursor: edge.cursor, hasNextPage: false },
          },
        }),
      )
    })
    cy.wait('@deletionPreview')
    cy.dialogContains('2 relationships reviewed')
    acknowledge()
    confirm().click()
    cy.wait('@safeDelete')
    cy.then(() => expect(previewCalls).to.eq(2))
  })
  it('stale rejection reloads page one and requires another review without automatic delete', () => {
    response = () => ({
      ...withImpacts(ep),
      impactVersion:
        previewCalls > 1 ? 'synthetic-version-2' : 'synthetic-version-1',
    })
    deletion = () =>
      deleteCalls === 1
        ? {
            errors: [
              {
                message: 'Safe synthetic rejection',
                extensions: { code: 'DELETION_DEPENDENCY_CHANGED' },
              },
            ],
          }
        : { data: { deleteAll: true } }
    open()
    cy.wait('@deletionPreview')
    acknowledge()
    confirm().click()
    cy.wait('@safeDelete')
    cy.wait('@deletionPreview')
    cy.dialogContains('Review the new impact')
    cy.dialog().find('input[type=checkbox]').should('not.be.checked')
    confirm().should('be.disabled')
    cy.then(() => expect(deleteCalls).to.eq(1))
    acknowledge()
    confirm().click()
    cy.wait('@safeDelete')
      .its('request.body.variables.confirmation.expectedImpactVersion')
      .should('eq', 'synthetic-version-2')
  })
  it('blocks duplicate clicks and Escape/backdrop/cancel while deleting', () => {
    cy.intercept('POST', '**/api/graphql*', (req) => {
      if (!req.body.query?.includes('mutation EPDeleteWithSafety')) return
      deleteCalls++
      req.alias = 'pendingDelete'
      req.reply({ delay: 600, body: { data: { deleteAll: true } } })
    })
    open()
    cy.wait('@deletionPreview')
    confirm().then(($button) => {
      $button[0].click()
      $button[0].click()
      $button[0].click()
    })
    cy.dialog().contains('button', 'Cancel').should('be.disabled')
    cy.get('body').type('{esc}')
    cy.get('[role=dialog]').should('exist')
    cy.wait('@pendingDelete')
    cy.then(() => expect(deleteCalls).to.eq(1))
  })
  it('network uncertainty offers no retry, never navigates, and sends only once', () => {
    cy.intercept('POST', '**/api/graphql*', (req) => {
      if (!req.body.query?.includes('mutation EPDeleteWithSafety')) return
      deleteCalls++
      req.alias = 'lostDelete'
      req.destroy()
    })
    open()
    cy.wait('@deletionPreview')
    cy.clock()
    confirm().click()
    cy.wait('@lostDelete')
    cy.tick(60000)
    cy.dialogContains('The deletion result is unconfirmed')
    confirm().should('be.disabled')
    cy.dialog()
      .should('not.contain', 'Retry')
      .should('not.contain', 'Check again')
    cy.location('pathname').should('include', ep.id)
    cy.then(() => expect(deleteCalls).to.eq(1))
    cy.dialogFinish('Close')
  })
  it('false HTTP-200 result remains unknown, not success', () => {
    deletion = () => ({ data: { deleteAll: false } })
    open()
    cy.wait('@deletionPreview')
    confirm().click()
    cy.wait('@safeDelete')
    cy.dialogContains('The deletion result is unconfirmed')
    cy.location('pathname').should('include', ep.id)
  })
  for (const outcome of ['missing', 'error']) {
    it(`keeps CommitUnknown visible when the parent query becomes ${outcome}`, () => {
      deletion = () => ({ data: { deleteAll: false } })
      open()
      cy.wait('@deletionPreview')
      confirm().click()
      cy.wait('@safeDelete')
      cy.dialogContains('The deletion result is unconfirmed')
      cy.intercept('POST', '**/api/graphql*', (req) => {
        if (!req.body.query?.includes('query scheduleDetailsQuery')) return
        req.alias = 'changedScheduleDetails'
        req.reply(
          outcome === 'missing'
            ? { data: { schedule: null } }
            : {
                data: { schedule: null },
                errors: [{ message: 'Synthetic query failure' }],
              },
        )
      })
      cy.window().invoke('refetchAll', true)
      cy.wait('@changedScheduleDetails')
      cy.dialogContains('The deletion result is unconfirmed')
      cy.location('pathname').should('include', ep.id)
      cy.then(() => expect(deleteCalls).to.eq(1))
      cy.dialogFinish('Close')
    })
  }
  it('Escape and backdrop close preview before submission', () => {
    open()
    cy.get('body').type('{esc}')
    cy.get('[role=dialog]').should('not.exist')
    open()
    cy.get('.MuiDialog-container').click('topLeft')
    cy.get('[role=dialog]').should('not.exist')
    cy.then(() => expect(deleteCalls).to.eq(0))
  })
}
testScreen('Schedule Deletion Safety (mocked Preview/Delete)', run)
