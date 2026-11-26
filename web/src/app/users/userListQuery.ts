import { gql } from 'urql'

// Use the actual list document after an authoritative deletion receipt.
export const userListQuery = gql`
  query usersQuery($input: UserSearchOptions) {
    users(input: $input) {
      nodes {
        id
        name
        email
        isFavorite
      }
      pageInfo {
        hasNextPage
        endCursor
      }
    }
  }
`
export const defaultUserListInput = {
  favoritesFirst: true,
  search: '',
  CMValue: '',
  after: '',
}
