import React, { useLayoutEffect, useRef, useState } from 'react'
import { visit } from 'graphql'
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

let refreshSequence = 0

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
  const selected = useRef({ id: props.userID, client, scopeKey, generation: 0 })
  type RefreshReceipt = typeof selected.current & { refreshing: boolean }
  const receipt = useRef<RefreshReceipt>()
  const [refreshFailed, setRefreshFailed] = useState<RefreshReceipt>()
  if (
    selected.current.id !== props.userID ||
    selected.current.client !== client ||
    selected.current.scopeKey !== scopeKey
  ) {
    // Invalidate during render, before an old Promise continuation can run.
    // Returning to the same IDs never restores a previous generation.
    selected.current = {
      id: props.userID,
      client,
      scopeKey,
      generation: selected.current.generation + 1,
    }
    receipt.current = undefined
  }
  const selection = selected.current
  const mounted = useRef(false)
  useLayoutEffect(() => {
    mounted.current = true
    return () => {
      mounted.current = false
      receipt.current = undefined
    }
  }, [])
  const isCurrent = (success: RefreshReceipt): boolean =>
    mounted.current &&
    receipt.current === success &&
    selected.current.generation === success.generation &&
    selected.current.id === success.id &&
    selected.current.client === success.client &&
    selected.current.scopeKey === success.scopeKey
  const refreshList = async (
    success: RefreshReceipt | undefined,
  ): Promise<void> => {
    if (!success || !isCurrent(success) || success.refreshing) return
    success.refreshing = true
    setRefreshFailed(undefined)
    try {
      // URQL coalesces identical pending queries. Give each list attempt its
      // own operation name so a new receipt immediately reaches the network.
      // The actual User List selection set and variables remain unchanged.
      const query = visit(
        // Start with a fresh document, excluding URQL's cached document key.
        { kind: userListQuery.kind, definitions: userListQuery.definitions },
        {
          OperationDefinition: (node) => ({
            ...node,
            name: {
              kind: 'Name',
              value: `usersQueryRefresh${++refreshSequence}`,
            },
          }),
        },
      )
      const result = await success.client
        .query<{
          users: UserConnection
        }>(
          query,
          { input: defaultUserListInput },
          { requestPolicy: 'network-only', suspense: false },
        )
        .toPromise()
      if (!isCurrent(success)) return
      if (
        result.error ||
        result.stale ||
        result.hasNext ||
        !result.data?.users?.nodes ||
        result.data.users.nodes.some((u) => u.id === success.id)
      ) {
        setRefreshFailed(success)
        return
      }
      props.onClose()
      navigate('/users')
    } catch {
      if (isCurrent(success)) setRefreshFailed(success)
    } finally {
      if (isCurrent(success)) success.refreshing = false
    }
  }
  const model = useDeletionSafety(
    userDeletionProfile,
    props.userID,
    props.onClose,
    () => {
      if (!mounted.current || selected.current !== selection) return
      // Object identity is the unique authoritative-success receipt; it binds
      // this deletion to its User, client, scope, actor and selection generation.
      const success = { ...selection, refreshing: false }
      receipt.current = success
      refreshList(success)
    },
    undefined,
    currentUserID,
  )
  return (
    <DeletionSafetyDialog
      {...model}
      selfDelete={props.userID === currentUserID}
      successNotice={
        refreshFailed && isCurrent(refreshFailed) ? (
          <Alert severity='warning'>
            The user was deleted, but the user list could not be refreshed.
            Authentication may need to be restored.
            <Button onClick={() => refreshList(refreshFailed)}>
              Refresh user list
            </Button>
          </Alert>
        ) : undefined
      }
    />
  )
}
