import React from 'react'
import {
  Alert,
  Button,
  Checkbox,
  Dialog,
  DialogActions,
  DialogContent,
  FormControlLabel,
  Typography,
} from '@mui/material'
import type { DeletionResource } from '../../schema'
import {
  cascadeObjects,
  DeletionState,
  isDeletionBlocked,
} from '../util/deletionSafety'
import DialogTitleWrapper from './components/DialogTitleWrapper'
import Spinner from '../loading/components/Spinner'

import {
  DeletionRootProfile,
  epDeletionProfile,
} from '../util/deletionSafetyProfiles'

export interface DeletionSafetyDialogProps {
  profile?: DeletionRootProfile
  state: DeletionState
  acknowledged: boolean
  onAcknowledge: (checked: boolean) => void
  onConfirm: () => void
  onPreview: () => void
  onClose: () => void
}
function identity(value: DeletionResource): string {
  return `${value.name || value.label} (${value.type} ${value.id})${value.organization ? ' · ' + value.organization.name : ''}`
}
const messages = {
  blocked:
    'Deletion is blocked. Resolve the listed dependencies, then check again.',
  failed:
    'The request could not be verified. Check your current access and resource selection, then check again.',
  unsupported:
    'The deletion impact could not be fully verified. Deletion is unavailable.',
  limit:
    'The dependency check exceeded the current limit. Deletion is unavailable.',
  unknown:
    'The deletion result is unconfirmed. Verify the resource status before starting a new deletion. Do not repeat this request.',
  success: 'The policy was deleted.',
  cancelled: 'The dependency check was cancelled.',
}
export default function DeletionSafetyDialog(
  props: DeletionSafetyDialogProps,
): React.JSX.Element {
  const { state, acknowledged } = props
  const profile = props.profile || epDeletionProfile
  const busy = state.phase === 'deleting'
  const review = state.phase === 'review' || state.phase === 'confirming'
  const confirm =
    review &&
    !!state.preview &&
    state.preview.complete &&
    !state.preview.impacts.pageInfo.hasNextPage &&
    !isDeletionBlocked(state.preview) &&
    (!state.preview.requiresConfirmation || acknowledged)
  const close = (): void => {
    if (!busy) props.onClose()
  }
  const message =
    state.phase in messages
      ? state.phase === 'success'
        ? `The ${profile.noun} was deleted.`
        : messages[state.phase as keyof typeof messages]
      : ''
  return (
    <Dialog
      open
      fullWidth
      maxWidth='md'
      onClose={close}
      disableEscapeKeyDown={busy}
      aria-labelledby='deletion-safety-title'
      data-cy='deletion-safety-dialog'
    >
      <DialogTitleWrapper
        fullScreen={false}
        title={<span id='deletion-safety-title'>{profile.title}</span>}
      />
      <DialogContent>
        {profile.previewType === 'SCHEDULE' && (
          <Alert severity='info'>
            Deleting a schedule does not automatically delete rotations. Review
            the backend dependencies and retained references below.
          </Alert>
        )}
        {profile.previewType === 'ROTATION' && (
          <Alert severity='info'>
            Deleting a rotation does not automatically delete schedules or
            users. Existing references may block deletion.
          </Alert>
        )}
        {state.message && <Alert severity='info'>{state.message}</Alert>}
        {message && (
          <Alert
            severity={
              state.phase === 'unknown'
                ? 'warning'
                : state.phase === 'success'
                  ? 'success'
                  : 'error'
            }
          >
            {message}
          </Alert>
        )}
        {state.phase === 'loading' && (
          <div role='status'>
            <Spinner text='Checking dependencies…' />
            <Typography>
              Loaded {state.loaded} relationships. Review is available after all
              pages are checked.
            </Typography>
          </div>
        )}
        {busy && (
          <Typography role='status'>
            Deleting {profile.noun}… Keep this dialog open while the result is
            pending.
          </Typography>
        )}
        {state.preview && (
          <React.Fragment>
            <Typography component='h3'>Selected {profile.noun}</Typography>
            <Typography>{identity(state.preview.targets[0])}</Typography>
            <Typography>
              {state.preview.impacts.edges.length} relationships reviewed.
            </Typography>
            {profile.previewType === 'ESCALATION_POLICY' && (
              <Typography data-cy='cascade-count'>
                {cascadeObjects(state.preview).length} unique policy
                steps/actions would be deleted by cascade. Other relationships
                are listed below.
              </Typography>
            )}
            {state.preview.notices.map((notice, i) => (
              <Typography key={i}>{notice}</Typography>
            ))}
            {(['BLOCK', 'CASCADE', 'WARNING', 'INFORMATIONAL'] as const).map(
              (policy) => {
                const edges = state.preview!.impacts.edges.filter(
                  ({ node }) => node.policy === policy,
                )
                if (!edges.length) return null
                return (
                  <section key={policy} aria-label={policy}>
                    <Typography component='h3'>{policy}</Typography>
                    <ul>
                      {edges.map(({ node }) => (
                        <li key={node.edgeID}>
                          <Typography>
                            Target: {identity(node.target)}
                          </Typography>
                          <Typography>
                            Referencing resource:{' '}
                            {identity(node.referencingResource)}
                          </Typography>
                          {node.parent && (
                            <Typography>
                              Parent: {identity(node.parent)}
                            </Typography>
                          )}
                          <Typography>
                            Relation: {node.relation} · Change: {node.change} ·
                            Required action: {node.requiredAction}
                          </Typography>
                          <Typography>{node.impact}</Typography>
                          {node.isDerived && (
                            <Typography>
                              Derived explanation; not an additional deleted
                              object.
                            </Typography>
                          )}
                          {node.isPlannedCoDeletion && (
                            <Typography>
                              Included in the backend deletion plan.
                            </Typography>
                          )}
                        </li>
                      ))}
                    </ul>
                  </section>
                )
              },
            )}
            {review && state.preview.requiresConfirmation && (
              <FormControlLabel
                control={
                  <Checkbox
                    checked={acknowledged}
                    onChange={(_, checked) => props.onAcknowledge(checked)}
                    disabled={busy}
                  />
                }
                label='I have reviewed and acknowledge these deletion impacts.'
              />
            )}
          </React.Fragment>
        )}
      </DialogContent>
      <DialogActions>
        {!busy &&
          !['loading', 'unknown', 'success', 'cancelled'].includes(
            state.phase,
          ) && <Button onClick={props.onPreview}>Check again</Button>}
        <Button onClick={close} disabled={busy}>
          {state.phase === 'unknown' ? 'Close' : 'Cancel'}
        </Button>
        <Button
          color='error'
          variant='contained'
          onClick={props.onConfirm}
          disabled={!confirm || busy}
        >
          Confirm
        </Button>
      </DialogActions>
    </Dialog>
  )
}
