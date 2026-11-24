import {
  notificationRuleID as id,
  notificationRulePreview,
} from '../users/notificationRuleDeletionFixtures'
import {
  deleteVariables,
  loadDeletionPreview,
  previewVariables,
} from './deletionSafety'
import {
  notificationRuleDeletionProfile as profile,
  epDeletionProfile,
  scheduleDeletionProfile,
  rotationDeletionProfile,
} from './deletionSafetyProfiles'
type Preview = import('../../schema').DeletionPreview
const load = (...pages: Preview[]): Promise<Preview> =>
  loadDeletionPreview(
    profile,
    id,
    async () => ({ data: { deletionPreview: pages.shift()! } }),
    () => true,
    jest.fn(),
  )
test.each(['alternative', 'last-immediate', 'open-cycle', 'both'] as const)(
  'actual backend policy projection: %s',
  async (risk) => {
    const p = await load(notificationRulePreview(risk))
    const warning = risk !== 'alternative'
    expect(p.requiresConfirmation).toBe(warning)
    expect(
      p.impacts.edges.map(({ node }) => [
        node.relation,
        node.policy,
        node.change,
      ]),
    ).toEqual([
      [
        'NOTIFICATION_CONFIGURATION',
        warning ? 'WARNING' : 'INFORMATIONAL',
        'DELETED',
      ],
      ['RETAINED_CONTACT', 'INFORMATIONAL', 'PRESERVED'],
      ['RETAINED_CONTACT', 'INFORMATIONAL', 'PRESERVED'],
    ])
    if (warning) expect(() => deleteVariables(profile, id, p, false)).toThrow()
    expect(deleteVariables(profile, id, p, true)).toEqual({
      input: [{ type: 'notificationRule', id }],
      confirmation: {
        expectedImpactVersion: 'version-1',
        acknowledgeImpacts: warning,
      },
    })
    expect(previewVariables(profile, id, null).input.targets).toEqual([
      { type: 'NOTIFICATION_RULE', id },
    ])
  },
)
test('merges all pages before review, retaining derived User explanation', async () => {
  const a = notificationRulePreview('last-immediate')
  const b = notificationRulePreview('last-immediate')
  a.impacts.edges = a.impacts.edges.slice(0, 1)
  a.impacts.pageInfo = { hasNextPage: true, endCursor: 'configuration' }
  b.impacts.edges = b.impacts.edges.slice(1)
  const fetch = jest
    .fn()
    .mockResolvedValueOnce({ data: { deletionPreview: a } })
    .mockResolvedValueOnce({ data: { deletionPreview: b } })
  const p = await loadDeletionPreview(profile, id, fetch, () => true, jest.fn())
  expect(fetch.mock.calls.map(([variables]) => variables.after)).toEqual([
    null,
    'configuration',
  ])
  expect(p.impacts.edges).toHaveLength(3)
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
    const a = notificationRulePreview()
    const b = notificationRulePreview()
    a.impacts.edges = a.impacts.edges.slice(0, 1)
    a.impacts.pageInfo = { hasNextPage: true, endCursor: 'configuration' }
    b.impacts.edges = b.impacts.edges.slice(1)
    if (failure === 'incomplete') b.complete = false
    if (failure === 'version') b.impactVersion = 'other'
    if (failure === 'cursor') b.impacts.edges[0].cursor = 'configuration'
    if (failure === 'edge-id') b.impacts.edges[0].node.edgeID = 'configuration'
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
  const p = notificationRulePreview('last-immediate')
  if (failure === 'resource')
    p.impacts.edges[0].node.referencingResource.type = 'SCHEDULE'
  if (failure === 'relation') p.impacts.edges[0].node.relation = 'USER_CYCLE'
  if (failure === 'policy-version') p.policyVersion = 'future'
  if (failure === 'root') p.targets = [{ ...p.targets[0], id: 'another' }]
  if (failure === 'edge-root')
    p.impacts.edges[0].node.target = { ...p.targets[0], id: 'another' }
  if (failure === 'contact-shape')
    p.impacts.edges[1].node.referencingResource.type = 'USER'
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
  const p = notificationRulePreview()
  p.canProceed = false
  const complete = await load(p)
  expect(() => deleteVariables(profile, id, complete, true)).toThrow()
})
test.each([
  epDeletionProfile,
  scheduleDeletionProfile,
  rotationDeletionProfile,
])(
  'other root $previewType cannot consume notification vocabulary',
  async (other) => {
    const p = notificationRulePreview()
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
  },
)
