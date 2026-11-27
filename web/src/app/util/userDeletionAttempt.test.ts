import {
  beginUserDeletion,
  finishUserDeletion,
  userDeletionUnresolved,
} from './userDeletionAttempt'

const id = '10000000-0000-4000-8000-000000000001'
const other = '10000000-0000-4000-8000-000000000002'
let values: Map<string, string>
let storage: Pick<Storage, 'getItem' | 'setItem' | 'removeItem'>
beforeEach(() => {
  values = new Map()
  storage = {
    getItem: jest.fn((key) => values.get(key) ?? null),
    setItem: jest.fn((key, value) => {
      values.set(key, value)
    }),
    removeItem: jest.fn((key) => {
      values.delete(key)
    }),
  }
  Object.assign(global, { window: { sessionStorage: storage } })
  finishUserDeletion(id, true)
  finishUserDeletion(other, true)
})
afterEach(() => {
  storage.removeItem = (key) => {
    values.delete(key)
  }
  finishUserDeletion(id, true)
  finishUserDeletion(other, true)
})
test('sent interlock persists only the safe target UUID and a constant marker', () => {
  expect(beginUserDeletion(id)).toBe(true)
  expect(Array.from(values)).toEqual([
    ['user-deletion-unresolved:' + id, 'sent'],
  ])
  expect(beginUserDeletion(id)).toBe(false)
  expect(beginUserDeletion(other)).toBe(true)
})
test('unknown response cannot release a sent attempt', () => {
  beginUserDeletion(id)
  finishUserDeletion(id, false)
  expect(userDeletionUnresolved(id)).toBe(true)
  expect(beginUserDeletion(id)).toBe(false)
})
test('a fresh module after same-tab reload still sees the sent marker', () => {
  beginUserDeletion(id)
  jest.isolateModules(() => {
    const reloaded: typeof import('./userDeletionAttempt') = jest.requireActual(
      './userDeletionAttempt',
    )
    expect(reloaded.userDeletionUnresolved(id)).toBe(true)
    expect(reloaded.beginUserDeletion(id)).toBe(false)
  })
})
test('only an authoritative outcome releases the matching target', () => {
  beginUserDeletion(id)
  beginUserDeletion(other)
  finishUserDeletion(id, true)
  expect(userDeletionUnresolved(id)).toBe(false)
  expect(userDeletionUnresolved(other)).toBe(true)
  expect(beginUserDeletion(id)).toBe(true)
})
test.each(['getItem', 'setItem'] as const)(
  'storage %s failure is propagated before an attempt can begin',
  (method) => {
    storage[method] = jest.fn(() => {
      throw new Error('Synthetic storage failure')
    })
    expect(() => beginUserDeletion(id)).toThrow('Synthetic storage failure')
    expect(values.size).toBe(0)
  },
)
test('silently lost writes fail closed', () => {
  storage.setItem = jest.fn()
  expect(() => beginUserDeletion(id)).toThrow('not retained')
  expect(values.size).toBe(0)
})
test('a failed clear retains the memory interlock even if storage changes', () => {
  beginUserDeletion(id)
  storage.removeItem = jest.fn(() => {
    throw new Error('Synthetic clear failure')
  })
  finishUserDeletion(id, true)
  values.clear()
  expect(beginUserDeletion(id)).toBe(false)
})
test.each(['', 'not-a-uuid', id.toUpperCase().replace('1000', 'A000')])(
  'invalid target %s never writes a marker',
  (target) => {
    expect(beginUserDeletion(target)).toBe(false)
    expect(values.size).toBe(0)
  },
)
