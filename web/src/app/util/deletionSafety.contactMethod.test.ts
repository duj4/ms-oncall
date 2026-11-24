import {
  contactMethodID as id,
  contactMethodPreview,
} from '../users/contactMethodDeletionFixtures'
import {
  deleteVariables,
  loadDeletionPreview,
  previewVariables,
} from './deletionSafety'
import {
  contactMethodDeletionProfile as profile,
  epDeletionProfile,
  scheduleDeletionProfile,
  rotationDeletionProfile,
  notificationRuleDeletionProfile,
  userOverrideDeletionProfile,
} from './deletionSafetyProfiles'
import type { DeletionPreview as Preview, DeletionImpact } from '../../schema'
const load = (...pages: Preview[]): Promise<Preview> =>
  loadDeletionPreview(
    profile,
    id,
    async () => ({ data: { deletionPreview: pages.shift()! } }),
    () => true,
    jest.fn(),
  )

test.each([0, 1, 2])(
  'single CM root; %s actual cascade rules, no User deletion',
  async (count) => {
    const p = await load(contactMethodPreview('alternative', id, count, true))
    expect(previewVariables(profile, id, null).input.targets).toEqual([
      { type: 'CONTACT_METHOD', id },
    ])
    expect(deleteVariables(profile, id, p, true).input).toEqual([
      { type: 'contactMethod', id },
    ])
    const rules = p.impacts.edges.filter(
      ({ node }) =>
        node.relation === 'CONTACT_NOTIFICATION_RULE' && !node.isDerived,
    )
    expect(
      new Set(rules.map(({ node }) => node.referencingResource.id)).size,
    ).toBe(count)
    expect(
      rules.every(
        ({ node }) =>
          node.policy === 'CASCADE' &&
          node.change === 'DELETED' &&
          node.isPlannedCoDeletion,
      ),
    ).toBe(true)
    expect(
      p.impacts.edges
        .filter(({ node }) => node.isDerived)
        .every(
          ({ node }) =>
            node.parent?.type === 'USER' &&
            node.change === 'PRESERVED' &&
            node.policy === 'INFORMATIONAL',
        ),
    ).toBe(true)
  },
)
test.each(['alternative', 'last-immediate', 'open-cycle', 'both'] as const)(
  'backend notification risk %s',
  async (risk) => {
    const p = await load(contactMethodPreview(risk, id, 0))
    const warning = risk !== 'alternative'
    expect(p.requiresConfirmation).toBe(warning)
    expect(p.impacts.edges[0].node).toMatchObject({
      policy: warning ? 'WARNING' : 'INFORMATIONAL',
      change: warning ? 'RELATION_REMOVED' : 'PRESERVED',
    })
    if (warning) expect(() => deleteVariables(profile, id, p, false)).toThrow()
    expect(
      deleteVariables(profile, id, p, true).confirmation.acknowledgeImpacts,
    ).toBe(warning)
  },
)
test('entire message/verification closure and retained reference shapes are admitted', async () => {
  const p = await load(contactMethodPreview('both', id, 2, true))
  expect(p.impacts.edges.map(({ node }) => node.relation)).toEqual(
    expect.arrayContaining([...profile.relations]),
  )
  const info = p.impacts.edges.filter(
    ({ node }) =>
      node.relation === 'OUTGOING_MESSAGE' &&
      node.target.type === 'VERIFICATION_STATE',
  )
  expect(info).toHaveLength(1)
  expect(info[0].node.policy).toBe('INFORMATIONAL')
  const retained = p.impacts.edges.filter(
    ({ node }) => node.relation === 'RETAINED_CONTACT',
  )
  expect(
    retained.every(
      ({ node }) => node.isPlannedCoDeletion && node.change === 'PRESERVED',
    ),
  ).toBe(true)
})
test('merges all pages before review, retaining derived User explanation', async () => {
  const a = contactMethodPreview('last-immediate')
  const b = contactMethodPreview('last-immediate')
  a.impacts.edges = a.impacts.edges.slice(0, 1)
  a.impacts.pageInfo = { hasNextPage: true, endCursor: 'immediate' }
  b.impacts.edges = b.impacts.edges.slice(1)
  const fetch = jest
    .fn()
    .mockResolvedValueOnce({ data: { deletionPreview: a } })
    .mockResolvedValueOnce({ data: { deletionPreview: b } })
  const p = await loadDeletionPreview(profile, id, fetch, () => true, jest.fn())
  expect(fetch.mock.calls.map(([variables]) => variables.after)).toEqual([
    null,
    'immediate',
  ])
  expect(p.impacts.edges).toHaveLength(6)
})
test.each([
  'network',
  'incomplete',
  'version',
  'cursor',
  'edge-id',
  'empty-successor',
])(
  'failed pagination never exposes an executable preview: %s',
  async (failure) => {
    const a = contactMethodPreview()
    const b = contactMethodPreview()
    a.impacts.edges = a.impacts.edges.slice(0, 1)
    a.impacts.pageInfo = { hasNextPage: true, endCursor: 'immediate' }
    b.impacts.edges = b.impacts.edges.slice(1)
    if (failure === 'incomplete') b.complete = false
    if (failure === 'version') b.impactVersion = 'other'
    if (failure === 'cursor') b.impacts.edges[0].cursor = 'immediate'
    if (failure === 'edge-id') b.impacts.edges[0].node.edgeID = 'immediate'
    if (failure === 'empty-successor') {
      b.impacts.edges = []
      b.impacts.pageInfo.endCursor = null
    }
    const fetch = jest
      .fn()
      .mockResolvedValueOnce({ data: { deletionPreview: a } })
      .mockResolvedValueOnce(
        failure === 'network'
          ? { error: { networkError: new Error('synthetic') } }
          : { data: { deletionPreview: b } },
      )
    await expect(
      loadDeletionPreview(profile, id, fetch, () => true, jest.fn()),
    ).rejects.toMatchObject({
      phase: failure === 'network' ? 'failed' : 'unsupported',
    })
  },
)
test.each([
  'resource',
  'relation',
  'policy-version',
  'root',
  'edge-root',
  'contact-shape',
  'user-deleted',
  'confirmation',
  'stale',
  'partial',
])('fails closed on unsupported notification shape: %s', async (failure) => {
  const p = contactMethodPreview('last-immediate')
  if (failure === 'resource')
    p.impacts.edges[0].node.referencingResource.type = 'UNKNOWN'
  if (failure === 'relation') p.impacts.edges[0].node.relation = 'USER_CYCLE'
  if (failure === 'policy-version') p.policyVersion = 'future'
  if (failure === 'root') p.targets = [{ ...p.targets[0], id: 'another' }]
  if (failure === 'edge-root')
    p.impacts.edges[0].node.target = { ...p.targets[0], id: 'another' }
  if (failure === 'contact-shape')
    p.impacts.edges[4].node.referencingResource.type = 'USER'
  if (failure === 'user-deleted') p.impacts.edges[2].node.change = 'DELETED'
  if (failure === 'confirmation') p.requiresConfirmation = false
  await expect(
    loadDeletionPreview(
      profile,
      id,
      async () => ({
        data: { deletionPreview: p },
        stale: failure === 'stale',
        hasNext: failure === 'partial',
      }),
      () => true,
      jest.fn(),
    ),
  ).rejects.toMatchObject({ phase: 'unsupported' })
})
test('backend canProceed=false remains authoritative, even with acknowledgement', async () => {
  const p = contactMethodPreview()
  p.canProceed = false
  const complete = await load(p)
  expect(() => deleteVariables(profile, id, complete, true)).toThrow()
})

test.each([
  'co',
  'derived',
  'parent',
  'ref',
  'target',
  'policy',
  'change',
  'action',
] as const)('rejects corrupt closure row field %s', async (field) => {
  for (
    let i = 0;
    i < contactMethodPreview('both', id, 2, true).impacts.edges.length;
    i++
  ) {
    const p = contactMethodPreview('both', id, 2, true)
    const row = p.impacts.edges[i].node
    if (field === 'co') row.isPlannedCoDeletion = !row.isPlannedCoDeletion
    if (field === 'derived') {
      // Both direct and derived RETAINED_CONTACT rows are valid and identical in classification.
      if (row.relation === 'RETAINED_CONTACT') continue
      row.isDerived = !row.isDerived
    }
    if (field === 'parent') row.parent = row.parent ? null : p.targets[0]
    if (field === 'ref')
      row.referencingResource = { ...row.referencingResource, type: 'SCHEDULE' }
    if (field === 'target') row.target = { ...row.target, type: 'USER' }
    if (field === 'policy') row.policy = 'BLOCK' as DeletionImpact['policy']
    if (field === 'change') row.change = 'CONFIG_TRIMMED'
    if (field === 'action') row.requiredAction = 'DETACH_REFERENCE'
    await expect(load(p)).rejects.toMatchObject({ phase: 'unsupported' })
  }
})
test.each([
  epDeletionProfile,
  scheduleDeletionProfile,
  rotationDeletionProfile,
  notificationRuleDeletionProfile,
  userOverrideDeletionProfile,
])('profile isolation from $previewType', async (other) => {
  const p = contactMethodPreview()
  p.targets = [{ ...p.targets[0], type: other.previewType }]
  await expect(
    loadDeletionPreview(
      other,
      id,
      async () => ({ data: { deletionPreview: p } }),
      () => true,
      jest.fn(),
    ),
  ).rejects.toMatchObject({ phase: 'unsupported' })
})
test.each(['DELETION_UNAVAILABLE', 'DELETION_BLOCKED'])(
  'backend %s never becomes an empty executable plan',
  async (code) => {
    await expect(
      loadDeletionPreview(
        profile,
        id,
        async () => ({ error: { graphQLErrors: [{ extensions: { code } }] } }),
        () => true,
        jest.fn(),
      ),
    ).rejects.toBeDefined()
  },
)
