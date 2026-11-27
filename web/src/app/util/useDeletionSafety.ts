import {
  IntegrationKeyDeletionRequest,
  IntegrationKeyDeletionSelection,
  integrationKeyDeletionQuery,
  verifyIntegrationKeyIdentity,
  verifyIntegrationKeyPreview,
} from './integrationKeyDeletion'
import {
  useCallback,
  useEffect,
  useLayoutEffect,
  useRef,
  useState,
} from 'react'
import { useClient } from 'urql'
import { useLocation } from 'wouter'
import type { DeletionPreview } from '../../schema'
import type { DeletionSafetyDialogProps } from '../dialogs/DeletionSafetyDialog'
import type { DeletionRootProfile } from './deletionSafetyProfiles'
import { useOrganizationManagement } from '../main/OrganizationManagement'
import {
  DeletionState,
  PreviewResult,
  PreviewFailure,
  deletionFailure,
  deletionMutation,
  deletionPreviewQuery,
  deleteVariables,
  isDeletionBlocked,
  loadDeletionPreview,
} from './deletionSafety'
import {
  beginUserDeletion,
  finishUserDeletion,
  userDeletionUnresolved,
} from './userDeletionAttempt'

export function useDeletionSafety(
  profile: DeletionRootProfile,
  id: string,
  onClose: () => void,
  // A receipt receiver may record an outcome while layout effects are hidden.
  // Ordinary callbacks/navigation run only while this instance is connected.
  onSuccess?: (() => void) | { receive: () => void },
  integrationKey?: IntegrationKeyDeletionRequest,
  actorID?: string,
): DeletionSafetyDialogProps {
  const client = useClient()
  const [, navigate] = useLocation()
  const scope = useOrganizationManagement()
  const scopeKey = JSON.stringify([
    scope?.identity,
    scope?.target.id,
    profile.previewType === 'USER' ? actorID : undefined,
  ])
  const serviceID = integrationKey?.serviceID
  const keyType = integrationKey?.type
  const organizationID = scope?.target.id
  const proposed = { client, scopeKey, id, profile, serviceID, keyType }
  const selected = useRef(proposed)
  // Object identity is a committed epoch, including A -> B -> A. Rendering a
  // speculative identity cannot revoke requests belonging to the current UI.
  const selection = Object.entries(proposed).every(
    ([key, value]) => selected.current[key as keyof typeof proposed] === value,
  )
    ? selected.current
    : proposed
  const identity = useRef<IntegrationKeyDeletionSelection>()
  const reviewed = useRef<{
    owner: typeof selection
    integrationKey?: IntegrationKeyDeletionSelection
  }>()
  const sameSelection = (value: typeof selection | undefined): boolean =>
    value === selected.current
  // The reviewed capability binds BOTH namespaces as well as the selection
  // context. Replacing or clearing the identity invalidates the old review.
  const sameReview = (): boolean =>
    sameSelection(reviewed.current?.owner) &&
    reviewed.current?.integrationKey === identity.current
  const [state, setState] = useState<DeletionState>({
    phase: 'loading',
    loaded: 0,
  })
  const [acknowledged, setAcknowledged] = useState(false)
  const current = useRef(state)
  const ack = useRef(false)
  const generation = useRef(0)
  const active = useRef(false)
  const mounted = useRef(false)
  const connected = useRef(false)
  const started = useRef<typeof selection>()
  const pending = useRef<{
    owner: typeof selection
    generation: number
  }>()
  const successEffect = useRef<{ owner: typeof selection; run: () => void }>()
  const finishSuccess = (): void => {
    const effect = successEffect.current
    if (
      !effect ||
      !mounted.current ||
      !connected.current ||
      !sameSelection(effect.owner)
    )
      return
    successEffect.current = undefined
    effect.run()
  }
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
        !mounted.current ||
        !sameSelection(selection) ||
        ['unknown', 'success', 'cancelled'].includes(current.current.phase)
      )
        return
      const request = ++generation.current
      cancelPage.current?.()
      if (profile.previewType === 'USER') {
        try {
          if (userDeletionUnresolved(id)) {
            clearAck()
            update({ phase: 'unknown', loaded: 0 })
            return
          }
        } catch {
          clearAck()
          update({
            phase: 'unsupported',
            loaded: 0,
            message:
              'The deletion safety state could not be stored. No deletion request was sent.',
          })
          return
        }
      }
      // A changed parent may invalidate a nested resource selection. Keep the
      // controller mounted, but never preview/commit an absent selection.
      if (!id) {
        clearAck()
        update({ phase: 'failed', loaded: 0 })
        return
      }
      const valid = (): boolean =>
        active.current &&
        mounted.current &&
        generation.current === request &&
        sameSelection(selection)
      clearAck()
      update({ phase: 'loading', loaded: 0, message })
      identity.current = undefined
      const fetchResult = <T>(
        document: Parameters<typeof client.query>[0],
        variables: object,
      ): Promise<T> =>
        new Promise<T>((resolve) => {
          const subscription: {
            current?: { unsubscribe: () => void }
            cancel?: () => void
          } = {}
          let finished = false
          const finish = (result: T): void => {
            if (finished) return
            finished = true
            if (cancelPage.current === subscription.cancel)
              cancelPage.current = undefined
            resolve(result)
            subscription.current?.unsubscribe()
          }
          const cancel = (): void => finish({} as T)
          subscription.cancel = cancel
          cancelPage.current = cancel
          subscription.current = client
            .query(document, variables, {
              requestPolicy: 'network-only',
              suspense: false,
            })
            .subscribe((result) => finish(result as T))
          if (finished) subscription.current.unsubscribe()
        })
      const load = async (): Promise<DeletionPreview> => {
        let binding: IntegrationKeyDeletionSelection | undefined
        if (profile.previewType === 'INTEGRATION_KEY') {
          if (!serviceID || !keyType || !organizationID)
            throw new PreviewFailure('failed')
          const result = await fetchResult<
            Parameters<typeof verifyIntegrationKeyIdentity>[0]
          >(integrationKeyDeletionQuery, { id })
          if (!valid()) throw new PreviewFailure('cancelled')
          binding = verifyIntegrationKeyIdentity(result, {
            id,
            serviceID,
            type: keyType,
            organizationID,
            scopeKey,
          })
        } else if (serviceID || keyType) throw new PreviewFailure('unsupported')
        const result = await loadDeletionPreview(
          profile,
          binding?.auditID || id,
          (variables) =>
            fetchResult<PreviewResult>(deletionPreviewQuery, variables),
          valid,
          (loaded) => {
            if (valid()) update({ phase: 'loading', loaded, message })
          },
          binding,
          organizationID,
        )
        if (binding && !verifyIntegrationKeyPreview(binding, result))
          throw new PreviewFailure('unsupported')
        if (valid()) identity.current = binding
        return result
      }
      load()
        .then((result) => {
          if (!valid()) return
          reviewed.current = {
            owner: selection,
            integrationKey: identity.current,
          }
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
    [
      client,
      id,
      profile,
      scopeKey,
      serviceID,
      keyType,
      organizationID,
      selection,
      clearAck,
      update,
    ],
  )
  useLayoutEffect(() => {
    if (selected.current !== selection) {
      selected.current = selection
      generation.current++
      cancelPage.current?.()
      // Only a committed change revokes the old request. Its continuation can
      // still settle its transaction marker, but cannot release a new request.
      pending.current = undefined
      reviewed.current = undefined
      identity.current = undefined
      successEffect.current = undefined
      active.current = true
      clearAck()
      update({ phase: 'loading', loaded: 0 })
    }
    connected.current = true
    finishSuccess()
    return () => {
      // Suspense and StrictMode also disconnect layout effects. Keep ownership
      // and asynchronous outcomes until a committed change or actual unmount.
      connected.current = false
    }
  })
  useEffect(() => {
    mounted.current = true
    const unlock = scope?.lock?.()
    release.current = unlock
    if (started.current !== selection) {
      started.current = selection
      active.current = true
      preview()
    }
    return () => {
      mounted.current = false
      unlock?.()
      if (release.current === unlock) release.current = undefined
      // StrictMode reconnects synchronously; a real removed instance does not.
      queueMicrotask(() => {
        if (mounted.current) return
        generation.current++
        cancelPage.current?.()
      })
    }
  }, [preview, selection])
  const close = (): void => {
    if (pending.current || !mounted.current || !sameSelection(selection)) return
    active.current = false
    generation.current++
    cancelPage.current?.()
    clearAck()
    update({ phase: 'cancelled', loaded: 0 })
    release.current?.()
    release.current = undefined
    onClose()
  }
  const confirm = async (): Promise<void> => {
    const model = current.current
    if (
      pending.current ||
      !active.current ||
      !mounted.current ||
      !sameSelection(selection) ||
      !['review', 'confirming'].includes(model.phase) ||
      !sameReview() ||
      !model.preview
    )
      return
    let variables
    try {
      variables = deleteVariables(
        profile,
        id,
        model.preview,
        ack.current,
        identity.current,
      )
    } catch {
      return
    }
    // Synchronous guard precedes every state update and asynchronous operation.
    if (profile.previewType === 'USER') {
      try {
        if (!beginUserDeletion(id)) {
          clearAck()
          update({ phase: 'unknown', loaded: 0 })
          return
        }
      } catch {
        clearAck()
        update({
          phase: 'unsupported',
          loaded: 0,
          message:
            'The deletion safety state could not be stored. No deletion request was sent.',
        })
        return
      }
    }
    const request = { owner: selection, generation: generation.current }
    pending.current = request
    update({ ...model, phase: 'deleting' })
    let result
    try {
      result = await client
        .mutation<{
          deleteAll: boolean
        }>(deletionMutation, variables, {
          additionalTypenames: profile.additionalTypenames
            ? [...profile.additionalTypenames]
            : [profile.typename],
        })
        .toPromise()
    } catch {
      // Abort/unmount/transport rejection does not prove rollback.
      result = undefined
    }
    const succeeded =
      !!result &&
      !result.error &&
      !result.stale &&
      !result.hasNext &&
      result.data?.deleteAll === true
    const failure =
      result?.stale || result?.hasNext || result?.data?.deleteAll === true
        ? 'unknown'
        : deletionFailure(result?.error)
    if (profile.previewType === 'USER')
      finishUserDeletion(id, succeeded || failure !== 'unknown')
    if (
      !active.current ||
      !mounted.current ||
      pending.current !== request ||
      request.generation !== generation.current ||
      !sameSelection(request.owner)
    )
      return
    pending.current = undefined
    clearAck()
    if (succeeded) {
      update({ phase: 'success', loaded: 0 })
      active.current = false
      generation.current++
      cancelPage.current?.()
      release.current?.()
      release.current = undefined
      if (onSuccess && typeof onSuccess !== 'function') onSuccess.receive()
      else {
        successEffect.current = {
          owner: request.owner,
          run: () => {
            if (onSuccess) onSuccess()
            else if (profile.listPath) navigate(profile.listPath)
          },
        }
        finishSuccess()
      }
      return
    }
    // Discard every old page/version/ack before recovery.
    update({ phase: failure === 'recheck' ? 'loading' : failure, loaded: 0 })
    if (failure === 'recheck')
      preview(
        'Dependencies or confirmation requirements changed. Review the new impact and confirm again.',
      )
  }
  return {
    profile,
    externalSystemName: identity.current?.externalSystemName,
    state:
      selection !== selected.current || (state.preview && !sameReview())
        ? { phase: 'loading', loaded: 0 }
        : state,
    acknowledged: sameReview() && acknowledged,
    onAcknowledge: (checked) => {
      if (
        pending.current ||
        !mounted.current ||
        !active.current ||
        !sameSelection(selection) ||
        !sameReview() ||
        !['review', 'confirming'].includes(current.current.phase)
      )
        return
      ack.current = checked
      setAcknowledged(checked)
      update({ ...current.current, phase: checked ? 'confirming' : 'review' })
    },
    onConfirm: confirm,
    onPreview: () => preview(),
    onClose: close,
  }
}
