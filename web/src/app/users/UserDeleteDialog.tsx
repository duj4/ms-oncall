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
  type RefreshReceipt = typeof selected.current & {
    refreshing: boolean
    outcome?: 'success' | 'failure'
    completed?: boolean
  }
  const receipt = useRef<RefreshReceipt>()
  const [refreshFailed, setRefreshFailed] = useState<RefreshReceipt>()
  // A render may be abandoned. Compute its proposed selection without changing
  // ownership of any committed request or receipt.
  const selection =
    selected.current.id === props.userID &&
    selected.current.client === client &&
    selected.current.scopeKey === scopeKey
      ? selected.current
      : {
          id: props.userID,
          client,
          scopeKey,
          generation: selected.current.generation + 1,
        }
  const visible = useRef(false)
  const isCurrent = (success: RefreshReceipt): boolean =>
    receipt.current === success &&
    selected.current.generation === success.generation &&
    selected.current.id === success.id &&
    selected.current.client === success.client &&
    selected.current.scopeKey === success.scopeKey
  const finishRefresh = (success: RefreshReceipt | undefined): void => {
    if (!success || !visible.current || !isCurrent(success)) return
    if (success.outcome === 'failure') setRefreshFailed(success)
    if (success.outcome === 'success' && !success.completed) {
      // A reveal or StrictMode effect replay must not repeat these effects.
      success.completed = true
      props.onClose()
      navigate('/users')
    }
  }
  const refreshList = async (
    success: RefreshReceipt | undefined,
  ): Promise<void> => {
    if (
      !success ||
      !isCurrent(success) ||
      success.refreshing ||
      success.completed
    )
      return
    success.refreshing = true
    success.outcome = undefined
    if (visible.current) setRefreshFailed(undefined)
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
        success.outcome = 'failure'
      } else success.outcome = 'success'
      finishRefresh(success)
    } catch {
      if (isCurrent(success)) {
        success.outcome = 'failure'
        finishRefresh(success)
      }
    } finally {
      if (isCurrent(success)) success.refreshing = false
    }
  }
  useLayoutEffect(() => {
    if (selected.current !== selection) {
      // Only a committed change permanently invalidates the previous generation.
      selected.current = selection
      receipt.current = undefined
    }
    visible.current = true
    finishRefresh(receipt.current)
    return () => {
      // Suspense hide and StrictMode replay also disconnect layout effects.
      // Retain outcomes while disconnected; only this instance can reconnect.
      // A real unmount never reconnects, so its callbacks cannot affect a new one.
      visible.current = false
    }
  })
  const model = useDeletionSafety(
    userDeletionProfile,
    props.userID,
    props.onClose,
    () => {
      if (selected.current !== selection) return
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
        selection === selected.current &&
        refreshFailed &&
        isCurrent(refreshFailed) ? (
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
