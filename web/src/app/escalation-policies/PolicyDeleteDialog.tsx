import React, { useCallback, useEffect, useRef, useState } from 'react'
import { useClient } from 'urql'
import { useLocation } from 'wouter'
import DeletionSafetyDialog from '../dialogs/DeletionSafetyDialog'
import { useOrganizationManagement } from '../main/OrganizationManagement'
import {
  DeletionState,
  PreviewResult,
  PreviewFailure,
  deletionFailure,
  deletionMutation,
  deletionPreviewQuery,
  epDeleteVariables,
  isDeletionBlocked,
  loadEPDeletionPreview,
} from '../util/deletionSafety'

export default function PolicyDeleteDialog(props: {
  escalationPolicyID: string
  onClose: () => void
}): React.JSX.Element {
  const client = useClient()
  const [, navigate] = useLocation()
  const scope = useOrganizationManagement()
  const scopeKey = JSON.stringify([scope?.identity, scope?.target.id])
  const selection = { client, scopeKey, id: props.escalationPolicyID }
  const selected = useRef(selection)
  selected.current = selection
  const reviewed = useRef<typeof selection>()
  const sameSelection = (value: typeof selection | undefined): boolean =>
    !!value &&
    value.client === selected.current.client &&
    value.scopeKey === selected.current.scopeKey &&
    value.id === selected.current.id
  const [state, setState] = useState<DeletionState>({
    phase: 'loading',
    loaded: 0,
  })
  const [acknowledged, setAcknowledged] = useState(false)
  const current = useRef(state)
  const ack = useRef(false)
  const generation = useRef(0)
  const active = useRef(false)
  const pending = useRef(false)
  const cancelPage = useRef<(() => void) | undefined>()
  const release = useRef<(() => void) | undefined>()
  const update = useCallback((next: DeletionState) => {
    current.current = next
    setState(next)
  }, [])
  const clearAck = useCallback(() => {
    ack.current = false
    setAcknowledged(false)
  }, [])
  const preview = useCallback(
    (message?: string): void => {
      if (
        pending.current ||
        !active.current ||
        ['unknown', 'success', 'cancelled'].includes(current.current.phase)
      )
        return
      const request = ++generation.current
      cancelPage.current?.()
      const valid = (): boolean =>
        active.current &&
        generation.current === request &&
        sameSelection({ client, scopeKey, id: props.escalationPolicyID })
      clearAck()
      update({ phase: 'loading', loaded: 0, message })
      loadEPDeletionPreview(
        props.escalationPolicyID,
        (variables) =>
          new Promise<PreviewResult>((resolve) => {
            const subscription: { current?: { unsubscribe: () => void } } = {}
            let finished = false
            const finish = (result: PreviewResult): void => {
              if (finished) return
              finished = true
              cancelPage.current = undefined
              resolve(result)
              subscription.current?.unsubscribe()
            }
            const cancel = (): void => finish({})
            cancelPage.current = cancel
            subscription.current = client
              .query(deletionPreviewQuery, variables, {
                requestPolicy: 'network-only',
                suspense: false,
              })
              .subscribe(finish)
            if (finished) subscription.current.unsubscribe()
          }),
        valid,
        (loaded) => {
          if (valid()) update({ phase: 'loading', loaded, message })
        },
      )
        .then((result) => {
          if (!valid()) return
          reviewed.current = { client, scopeKey, id: props.escalationPolicyID }
          update({
            phase: isDeletionBlocked(result) ? 'blocked' : 'review',
            loaded: result.impacts.edges.length,
            preview: result,
            message,
          })
        })
        .catch((error: unknown) => {
          if (!valid()) return
          update({
            phase: error instanceof PreviewFailure ? error.phase : 'failed',
            loaded: 0,
          })
        })
    },
    [client, props.escalationPolicyID, scopeKey, clearAck, update],
  )
  useEffect(() => {
    active.current = true
    const acquire = scope?.lock
    release.current = acquire?.()
    if (pending.current) {
      pending.current = false
      clearAck()
      update({ phase: 'unknown', loaded: 0 })
    } else preview()
    return () => {
      active.current = false
      generation.current++
      cancelPage.current?.()
      release.current?.()
      release.current = undefined
    }
  }, [preview])
  const close = (): void => {
    if (pending.current) return
    active.current = false
    generation.current++
    cancelPage.current?.()
    clearAck()
    update({ phase: 'cancelled', loaded: 0 })
    release.current?.()
    release.current = undefined
    props.onClose()
  }
  const confirm = async (): Promise<void> => {
    const model = current.current
    if (
      pending.current ||
      !active.current ||
      !sameSelection({ client, scopeKey, id: props.escalationPolicyID }) ||
      !['review', 'confirming'].includes(model.phase) ||
      !sameSelection(reviewed.current) ||
      !model.preview
    )
      return
    let variables
    try {
      variables = epDeleteVariables(
        props.escalationPolicyID,
        model.preview,
        ack.current,
      )
    } catch {
      return
    }
    // Synchronous guard precedes every state update and asynchronous operation.
    pending.current = true
    const request = generation.current
    update({ ...model, phase: 'deleting' })
    let result
    try {
      result = await client
        .mutation<{
          deleteAll: boolean
        }>(deletionMutation, variables, {
          additionalTypenames: ['EscalationPolicy'],
        })
        .toPromise()
    } catch {
      // Abort/unmount/transport rejection does not prove rollback.
      result = undefined
    }
    if (
      !active.current ||
      request !== generation.current ||
      !sameSelection({ client, scopeKey, id: props.escalationPolicyID })
    )
      return
    pending.current = false
    clearAck()
    if (
      result &&
      !result.error &&
      !result.stale &&
      !result.hasNext &&
      result.data?.deleteAll === true
    ) {
      update({ phase: 'success', loaded: 0 })
      active.current = false
      generation.current++
      cancelPage.current?.()
      release.current?.()
      release.current = undefined
      navigate('/escalation-policies')
      return
    }
    const failure =
      result?.stale || result?.hasNext || result?.data?.deleteAll === true
        ? 'unknown'
        : deletionFailure(result?.error)
    // Discard every old page/version/ack before recovery.
    update({ phase: failure === 'recheck' ? 'loading' : failure, loaded: 0 })
    if (failure === 'recheck')
      preview(
        'Dependencies or confirmation requirements changed. Review the new impact and confirm again.',
      )
  }
  return (
    <DeletionSafetyDialog
      state={
        state.preview && !sameSelection(reviewed.current)
          ? { phase: 'loading', loaded: 0 }
          : state
      }
      acknowledged={sameSelection(reviewed.current) && acknowledged}
      onAcknowledge={(checked) => {
        if (
          pending.current ||
          !['review', 'confirming'].includes(current.current.phase)
        )
          return
        ack.current = checked
        setAcknowledged(checked)
        update({ ...current.current, phase: checked ? 'confirming' : 'review' })
      }}
      onConfirm={confirm}
      onPreview={() => preview()}
      onClose={close}
    />
  )
}
