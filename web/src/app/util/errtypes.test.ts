import { GraphQLError } from 'graphql'
import { CombinedError } from 'urql'
import { ErrorCode } from '../../schema'
import { isDestFieldError, isInputFieldError, isKnownError } from './errtypes'
import { fieldErrors, nonFieldErrors, splitErrorsByPath } from './errutil'

const deletionErrors: [ErrorCode, string][] = [
  ['DELETION_BLOCKED', 'deletion is blocked by a dependency'],
  ['DELETION_CONFIRMATION_REQUIRED', 'deletion impact requires confirmation'],
  [
    'DELETION_DEPENDENCY_CHANGED',
    'deletion dependencies changed; preview again',
  ],
  [
    'DELETION_PREVIEW_LIMIT_EXCEEDED',
    'complete deletion preview exceeds the processing budget',
  ],
  ['DELETION_UNAVAILABLE', 'deletion safety is unavailable'],
]

describe('error code classification', () => {
  it.each<[ErrorCode, boolean, boolean]>([
    ['INVALID_INPUT_VALUE', true, false],
    ['INVALID_DEST_FIELD_VALUE', false, true],
    ['EXPR_TOO_COMPLEX', false, false],
    ['INVALID_MAP_FIELD_VALUE', false, false],
  ])('preserves %s classification', (code, inputField, destField) => {
    const error = new GraphQLError('existing error', {
      path: ['updateEscalationPolicyStep'],
      extensions: { code, fieldID: 'example-field' },
    })

    expect(isKnownError(error)).toBe(true)
    expect(isInputFieldError(error)).toBe(inputField)
    expect(isDestFieldError(error)).toBe(destField)
  })

  it.each(deletionErrors)(
    'preserves %s as a non-field failure',
    (code, message) => {
      const error = new GraphQLError(message, {
        path: ['updateEscalationPolicyStep'],
        extensions: { code },
      })
      const response = new CombinedError({ graphQLErrors: [error] })

      expect(isKnownError(error)).toBe(true)
      expect(isInputFieldError(error)).toBe(false)
      expect(isDestFieldError(error)).toBe(false)
      expect(fieldErrors(response)).toEqual([])
      expect(nonFieldErrors(response)).toEqual([error])

      const [known, other] = splitErrorsByPath(response, [
        'updateEscalationPolicyStep',
      ])
      expect(known).toEqual([error])
      expect(known[0]).toBe(error)
      expect(other).toEqual([])

      const [unmatched, dialogErrors] = splitErrorsByPath(response, [])
      expect(unmatched).toEqual([])
      expect(dialogErrors).toEqual([error])
      expect(dialogErrors[0]).toBe(error)
      expect(error.message).toBe(message)
      expect(error.extensions.code).toBe(code)
      expect(response.graphQLErrors).toEqual([error])
    },
  )

  it.each([
    undefined,
    null,
    new Error('network failure'),
    { message: 'plain' },
  ])('preserves unknown error classification for %p', (error) => {
    expect(isKnownError(error)).toBe(false)
  })
})
