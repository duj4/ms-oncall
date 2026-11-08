import { parse } from 'graphql'
import {
  containsRootCreate,
  createResultUncertain,
  hasExpectedCreatedOrganization,
} from './rootCreatePolicy'

test.each([
  'createService',
  'createEscalationPolicy',
  'createSchedule',
  'createRotation',
])('Create transport policy recognizes aliases for %s', (name) => {
  expect(
    containsRootCreate(
      parse(`mutation { alias:${name}(input:{name:"synthetic"}){id} }`),
    ),
  ).toBe(true)
})

test('Create transport policy recognizes fragments and ignores string input', () => {
  expect(
    containsRootCreate(
      parse(
        'mutation { ...M } fragment M on Mutation { createService(input:{name:"synthetic"}){id} }',
      ),
    ),
  ).toBe(true)
  expect(
    containsRootCreate(
      parse(
        'mutation { updateService(input:{id:"synthetic",name:"createService"}) }',
      ),
    ),
  ).toBe(false)
})

test('old target data cannot confirm a Create for the new target', () => {
  const data = {
    createService: { id: 'synthetic-root', organization: { id: 'B' } },
  }
  expect(hasExpectedCreatedOrganization(data, 'B')).toBe(true)
  expect(hasExpectedCreatedOrganization(data, 'C')).toBe(false)
  expect(hasExpectedCreatedOrganization({ createService: null }, 'B')).toBe(
    false,
  )
  expect(
    hasExpectedCreatedOrganization(
      { createService: { id: 'synthetic-root' } },
      'B',
    ),
  ).toBe(false)
})

test('network failures and unclassified field errors block another submission', () => {
  expect(
    createResultUncertain({
      networkError: new Error('synthetic network failure'),
    }),
  ).toBe(true)
  expect(createResultUncertain({ graphQLErrors: [{ extensions: {} }] })).toBe(
    true,
  )
  expect(
    createResultUncertain({
      graphQLErrors: [{ extensions: { isFieldError: true } }],
    }),
  ).toBe(false)
  expect(createResultUncertain()).toBe(false)
})
