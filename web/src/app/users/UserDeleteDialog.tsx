import React, { useEffect, useRef, useState } from 'react'
import { useClient } from 'urql'
import { useLocation } from 'wouter'
import { Alert, Button } from '@mui/material'
import DeletionSafetyDialog from '../dialogs/DeletionSafetyDialog'
import { useSessionInfo } from '../util/RequireConfig'
import { userDeletionProfile } from '../util/deletionSafetyProfiles'
import { useDeletionSafety } from '../util/useDeletionSafety'
import { defaultUserListInput, userListQuery } from './userListQuery'
import type { UserConnection } from '../../schema'
import { useOrganizationManagement } from '../main/OrganizationManagement'

export default function UserDeleteDialog(props: {
  userID: string
  onClose: () => void
}): JSX.Element {
  const { userID: currentUserID } = useSessionInfo()
  const client = useClient()
  const scope = useOrganizationManagement()
  const scopeKey = JSON.stringify([
    scope?.identity,
    scope?.target.id,
    currentUserID,
  ])
  const [, navigate] = useLocation()
  const [refreshFailed, setRefreshFailed] = useState(false)
  const receipt = useRef<{
    id: string
    client: typeof client
    scopeKey: string
  }>()
  const mounted = useRef(false)
  useEffect(() => {
    mounted.current = true
    return () => {
      mounted.current = false
    }
  }, [])
  const refreshing = useRef(false)
  const selected = useRef({ id: props.userID, client, scopeKey })
  selected.current = { id: props.userID, client, scopeKey }
  const refreshList = async (): Promise<void> => {
    const success = receipt.current
    if (!success || refreshing.current) return
    refreshing.current = true
    try {
      const result = await success.client
        .query<{
          users: UserConnection
        }>(
          userListQuery,
          { input: defaultUserListInput },
          { requestPolicy: 'network-only', suspense: false },
        )
        .toPromise()
      if (
        !mounted.current ||
        selected.current.scopeKey !== success.scopeKey ||
        selected.current.id !== success.id ||
        selected.current.client !== success.client
      )
        return
      if (
        result.error ||
        result.stale ||
        result.hasNext ||
        !result.data?.users?.nodes ||
        result.data.users.nodes.some((u) => u.id === success.id)
      ) {
        setRefreshFailed(true)
        return
      }
      props.onClose()
      navigate('/users')
    } catch {
      if (
        mounted.current &&
        selected.current.scopeKey === success.scopeKey &&
        selected.current.id === success.id &&
        selected.current.client === success.client
      )
        setRefreshFailed(true)
    } finally {
      refreshing.current = false
    }
  }
  const model = useDeletionSafety(
    userDeletionProfile,
    props.userID,
    props.onClose,
    () => {
      receipt.current = { id: props.userID, client, scopeKey }
      refreshList()
    },
    undefined,
    currentUserID,
  )
  return (
    <DeletionSafetyDialog
      {...model}
      selfDelete={props.userID === currentUserID}
      successNotice={
        refreshFailed ? (
          <Alert severity='warning'>
            The user was deleted, but the user list could not be refreshed.
            Authentication may need to be restored.
            <Button onClick={() => refreshList()}>Refresh user list</Button>
          </Alert>
        ) : undefined
      }
    />
  )
}
