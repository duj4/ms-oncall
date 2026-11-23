import type { DeletionImpact, DeletionPreview } from '../../schema'
import { testScreen } from '../support/e2e'

type Rotation = Pick<import('../../schema').Rotation, 'id' | 'name'>

// App navigation/auth/fixtures use the existing integration environment.
// Preview/delete responses below are browser mocks, not backend evidence.
function preview(
  ep: Rotation,
  extra: Partial<DeletionPreview> = {},
): DeletionPreview {
  return {
    operation: 'DELETE_RESOURCES',
    targets: [
      {
        type: 'ROTATION',
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
  ep: Rotation,
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
        type: 'ROTATION_PARTICIPANT',
        id: '20000000-0000-4000-8000-' + String(n).padStart(12, '0'),
        name: null,
        label: 'Synthetic rotation participant',
      },
      parent: root,
      relation: 'ROTATION_PARTICIPANT',
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
function withImpacts(ep: Rotation): DeletionPreview {
  const edges = [
    impact(ep, 1),
    impact(ep, 2, {
      relation: 'ROTATION_STATE',
      referencingResource: {
        ...preview(ep).targets[0],
        type: 'ROTATION_STATE',
        id: '1',
        name: null,
        label: 'Synthetic rotation state',
      },
    }),
    impact(ep, 3, {
      target: {
        ...preview(ep).targets[0],
        type: 'USER',
        label: 'Retained synthetic user',
        name: null,
      },
      relation: 'PARTICIPANT_USER',
      policy: 'INFORMATIONAL',
      change: 'PRESERVED',
      requiredAction: 'NONE',
      impact: 'The referenced user is preserved.',
    }),
    impact(ep, 4, {
      referencingResource: {
        ...preview(ep).targets[0],
        type: 'FAVORITE',
        label: 'Synthetic favorite',
      },
      relation: 'FAVORITE',
      policy: 'INFORMATIONAL',
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
  cy.dialogTitle('Delete Rotation')
}
function confirm(): Cypress.Chainable<JQuery<HTMLButtonElement>> {
  return cy.dialog().contains('button', /^Confirm$/)
}
function acknowledge(): void {
  cy.dialog().find('input[type=checkbox]').check()
}
function run(): void {
  let ep: Rotation
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
            targets: [{ type: 'ROTATION', id: ep.id }],
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
          { type: 'rotation', id: ep.id },
        ])
        expect(
          Object.keys(req.body.variables.confirmation).sort(),
        ).to.deep.equal(['acknowledgeImpacts', 'expectedImpactVersion'])
        req.alias = 'safeDelete'
        req.reply(deletion())
      }
    })
    cy.createRotation().then((value: Rotation) => {
      ep = value
      cy.visit(`/rotations/${ep.id}`)
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
  it('blocks a surviving Schedule Rule without adding the Schedule as a delete root', () => {
    const blocked = impact(ep, 1, {
      relation: 'RULE_TARGET',
      policy: 'BLOCK',
      change: 'PRESERVED',
      requiredAction: 'DETACH_REFERENCE',
      referencingResource: {
        ...preview(ep).targets[0],
        type: 'SCHEDULE_RULE',
        name: null,
        label: 'Surviving schedule rule',
      },
      parent: {
        ...preview(ep).targets[0],
        type: 'SCHEDULE',
        name: null,
        label: 'Retained schedule',
      },
    })
    response = () =>
      preview(ep, {
        canProceed: false,
        impacts: {
          edges: [blocked],
          pageInfo: { endCursor: blocked.cursor, hasNextPage: false },
        },
      })
    open()
    cy.wait('@deletionPreview')
    cy.dialogContains('Surviving schedule rule')
    cy.dialogContains('Retained schedule')
    confirm().should('be.disabled')
    cy.then(() => expect(deleteCalls).to.eq(0))
  })
  it('shows participant/state cascade and retained user data, requires a fresh checkbox and sends exact confirmation', () => {
    response = () => withImpacts(ep)
    open()
    cy.wait('@deletionPreview')
    cy.dialogContains('CASCADE')
    cy.dialogContains('ROTATION_PARTICIPANT')
    cy.dialogContains('ROTATION_STATE')
    cy.dialogContains('PARTICIPANT_USER')
    cy.dialogContains('Retained synthetic user')
    cy.dialogContains('INFORMATIONAL')
    cy.dialogContains(
      'Deleting a rotation does not automatically delete schedules or users.',
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
    cy.location('pathname').should('eq', '/rotations')
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
        if (!req.body.query?.includes('query rotationDetails')) return
        req.alias = 'changedRotationDetails'
        req.reply(
          outcome === 'missing'
            ? { data: { rotation: null } }
            : {
                data: { rotation: null },
                errors: [{ message: 'Synthetic query failure' }],
              },
        )
      })
      cy.window().invoke('refetchAll', true)
      cy.wait('@changedRotationDetails')
      cy.dialogContains('The deletion result is unconfirmed')
      cy.location('pathname').should('include', ep.id)
      cy.then(() => expect(deleteCalls).to.eq(1))
      cy.dialogFinish('Close')
    })
  }
  it('keeps pending Delete mounted across parent null/refetch before a false result', () => {
    cy.intercept('POST', '**/api/graphql*', (req) => {
      if (!req.body.query?.includes('mutation EPDeleteWithSafety')) return
      deleteCalls++
      req.alias = 'pendingRotationDelete'
      req.reply({ delay: 1200, body: { data: { deleteAll: false } } })
    })
    open()
    cy.wait('@deletionPreview')
    confirm().click()
    cy.dialogContains('Deleting rotation')
    cy.intercept('POST', '**/api/graphql*', (req) => {
      if (!req.body.query?.includes('query rotationDetails')) return
      req.alias = 'missingRotationDuringDelete'
      req.reply({ data: { rotation: null } })
    })
    cy.window().invoke('refetchAll', true)
    cy.wait('@missingRotationDuringDelete')
    cy.dialogContains('Deleting rotation')
    cy.wait('@pendingRotationDelete')
    cy.dialogContains('The deletion result is unconfirmed')
    cy.location('pathname').should('include', ep.id)
    cy.then(() => expect(deleteCalls).to.eq(1))
  })
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
testScreen('Rotation Deletion Safety (mocked Preview/Delete)', run)
