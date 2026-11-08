import React, { Suspense, useState } from 'react'
import { gql, useQuery } from 'urql'
import {
  useTargetOrganizationID,
  useOrganizationManagement,
} from '../main/OrganizationManagement'
import { GenericError } from '../error-pages'
import PolicyCreateDialog from './PolicyCreateDialog'
import Search from '../util/Search'
import FlatList from '../lists/FlatList'
import { FavoriteIcon } from '../util/SetFavoriteButton'
import ListPageControls from '../lists/ListPageControls'
import { useURLParam } from '../actions'
import { EscalationPolicyConnection } from '../../schema'

const query = gql`
  query epsQuery($input: EscalationPolicySearchOptions) {
    escalationPolicies(input: $input) {
      nodes {
        id
        name
        description
        isFavorite
      }
      pageInfo {
        hasNextPage
        endCursor
      }
    }
  }
`

const context = { suspense: false }
export default function PolicyList(): React.JSX.Element {
  const [search] = useURLParam<string>('search', '')
  const [create, setCreate] = useState(false)
  const canCreate = useOrganizationManagement()?.canCreate ?? true
  const [cursor, setCursor] = useState('')

  const inputVars = {
    targetOrganizationID: useTargetOrganizationID(),
    favoritesFirst: true,
    search,
    after: cursor,
  }

  const [q] = useQuery<{ escalationPolicies: EscalationPolicyConnection }>({
    query,
    variables: { input: inputVars },
    context,
  })
  const nextCursor = q.data?.escalationPolicies.pageInfo.hasNextPage
    ? q.data?.escalationPolicies.pageInfo.endCursor
    : ''
  // cache the next page
  useQuery({
    query,
    variables: { input: { ...inputVars, after: nextCursor } },
    context,
    pause: !nextCursor,
  })

  if (q.error) return <GenericError error={q.error.message} />

  return (
    <React.Fragment>
      <Suspense>
        {create && <PolicyCreateDialog onClose={() => setCreate(false)} />}
      </Suspense>
      <ListPageControls
        createLabel='Escalation Policy'
        nextCursor={nextCursor}
        onCursorChange={setCursor}
        loading={q.fetching}
        {...(canCreate ? { onCreateClick: () => setCreate(true) } : {})}
        slots={{
          search: <Search />,
          list: (
            <FlatList
              emptyMessage='No results'
              items={
                q.data?.escalationPolicies.nodes.map((u) => ({
                  title: u.name,
                  subText: u.description,
                  url: u.id,
                  secondaryAction: u.isFavorite ? <FavoriteIcon /> : undefined,
                })) || []
              }
            />
          ),
        }}
      />
    </React.Fragment>
  )
}
