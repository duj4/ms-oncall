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
  externalSystemName?: string | null
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
        {profile.previewType === 'INTEGRATION_KEY' && (
          <Alert severity='warning'>
            Only the selected integration key is deleted. Its service and
            historical alert logs are preserved. This key can no longer create
            new alerts. External integrations may stop working. To restore them,
            create a new key and reconfigure the alert source.
            {props.externalSystemName && (
              <React.Fragment>
                {' '}
                External system: {props.externalSystemName}.
              </React.Fragment>
            )}
          </Alert>
        )}
        {profile.previewType === 'SERVICE' && (
          <Alert severity='info'>
            The selected service is the only explicit deletion root. Its
            escalation policy is preserved; use the separate escalation policy
            deletion flow to delete it. Open alerts may block deletion and must
            be handled first. Closed alerts and integration keys may be deleted
            by cascade. Other effects follow the backend plan below.
          </Alert>
        )}
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
        {profile.previewType === 'NOTIFICATION_RULE' && (
          <Alert severity='info'>
            Only the selected notification rule is deleted. Its user and contact
            method are preserved. Review any notification configuration risks
            below.
          </Alert>
        )}
        {profile.previewType === 'CONTACT_METHOD' && (
          <Alert severity='info'>
            The selected contact method is the only explicit deletion root. Its
            user is preserved. Review the backend cascade plan and notification
            path changes below.
          </Alert>
        )}
        {profile.previewType === 'USER_OVERRIDE' && (
          <Alert severity='info'>
            Only the selected user override is deleted. Its schedule and the
            added or removed users are preserved. Removing the override may
            change current or future on-call assignments. Review the backend
            coverage impact below.
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
            {profile.previewType === 'CONTACT_METHOD' && (
              <Typography data-cy='contact-rule-cascade-count'>
                {
                  new Set(
                    state.preview.impacts.edges
                      .filter(
                        ({ node }) =>
                          node.relation === 'CONTACT_NOTIFICATION_RULE' &&
                          !node.isDerived &&
                          node.policy === 'CASCADE' &&
                          node.change === 'DELETED',
                      )
                      .map(({ node }) => node.referencingResource.id),
                  ).size
                }{' '}
                unique notification rules would be deleted by backend cascade.
              </Typography>
            )}
            {profile.previewType === 'SERVICE' && (
              <Typography data-cy='service-cascade-count'>
                {
                  new Set(
                    state.preview.impacts.edges
                      .filter(
                        ({ node }) =>
                          node.relation === 'SERVICE_ALERT' &&
                          !node.isDerived &&
                          node.change === 'DELETED' &&
                          node.policy === 'CASCADE',
                      )
                      .map(({ node }) => node.referencingResource.id),
                  ).size
                }{' '}
                unique alerts and{' '}
                {
                  new Set(
                    state.preview.impacts.edges
                      .filter(
                        ({ node }) =>
                          node.relation === 'SERVICE_INTEGRATION_KEY' &&
                          !node.isDerived &&
                          node.change === 'DELETED' &&
                          node.policy === 'CASCADE',
                      )
                      .map(({ node }) => node.referencingResource.id),
                  ).size
                }{' '}
                unique integration keys would be deleted by backend cascade.
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
                          {profile.previewType === 'SERVICE' && (
                            <Typography>
                              {node.isDerived
                                ? 'Derived explanation; no additional deletion root.'
                                : node.policy === 'BLOCK'
                                  ? 'This alert blocks service deletion. Handle the open alert, then check again.'
                                  : node.relation === 'RETAINED_POLICY'
                                    ? 'The associated escalation policy is preserved.'
                                    : node.relation === 'INTEGRATION_SOURCE'
                                      ? 'The integration key target is deleted; this row describes its link to the selected service.'
                                      : node.change === 'PRESERVED'
                                        ? 'The referencing history resource is preserved.'
                                        : 'The referencing resource would be deleted by the backend plan.'}
                            </Typography>
                          )}
                          {profile.previewType === 'CONTACT_METHOD' && (
                            <Typography>
                              {node.isDerived
                                ? 'The owning user is preserved; this is an explanation of the relationship below.'
                                : node.relation === 'CONTACT_NOTIFICATION_RULE'
                                  ? 'This notification rule is deleted by backend cascade.'
                                  : node.relation ===
                                      'NOTIFICATION_CONFIGURATION'
                                    ? 'The cascaded notification rule is deleted; the user is preserved. Review the notification configuration risk.'
                                    : node.relation === 'RETAINED_CONTACT'
                                      ? 'This row describes the cascaded rule contact reference. The selected contact method remains the explicit deletion root; the user is preserved.'
                                      : node.relation === 'STATUS_CONTACT'
                                        ? 'The user status notification setting is unlinked; the user is preserved.'
                                        : node.relation === 'IMMEDIATE_ROUTE'
                                          ? 'The user is preserved. Review the backend notification path risk.'
                                          : 'The referencing resource would be deleted as part of the backend plan.'}
                            </Typography>
                          )}
                          {profile.previewType === 'INTEGRATION_KEY' && (
                            <Typography>
                              {node.relation === 'INTEGRATION_SOURCE'
                                ? 'The integration key is deleted; its owning service is preserved.'
                                : 'The historical alert log is preserved.'}
                            </Typography>
                          )}
                          {profile.previewType === 'USER_OVERRIDE' && (
                            <Typography>
                              {node.relation === 'OVERRIDE_COVERAGE'
                                ? 'The selected override is deleted; its schedule is preserved. This affects on-call coverage.'
                                : node.isDerived
                                  ? 'The owning schedule is preserved.'
                                  : node.relation === 'OVERRIDE_ADD_USER'
                                    ? 'The added user is preserved.'
                                    : 'The removed user is preserved.'}
                            </Typography>
                          )}
                          {profile.previewType === 'NOTIFICATION_RULE' && (
                            <Typography>
                              {node.relation === 'NOTIFICATION_CONFIGURATION'
                                ? 'The selected rule is deleted; the user is preserved. This affects notification configuration.'
                                : node.isDerived
                                  ? 'The owning user is preserved.'
                                  : 'The contact method is preserved.'}
                            </Typography>
                          )}
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
                          {!(
                            profile.previewType === 'CONTACT_METHOD' &&
                            node.relation === 'RETAINED_CONTACT' &&
                            !node.isDerived
                          ) && <Typography>{node.impact}</Typography>}
                          {node.isDerived && (
                            <Typography>
                              Derived explanation; not an additional deleted
                              object.
                            </Typography>
                          )}
                          {node.isPlannedCoDeletion &&
                            profile.previewType !== 'SERVICE' &&
                            !(
                              (profile.previewType === 'USER_OVERRIDE' ||
                                profile.previewType === 'CONTACT_METHOD') &&
                              node.change === 'PRESERVED'
                            ) && (
                              <Typography>
                                {profile.previewType === 'CONTACT_METHOD'
                                  ? 'The referencing resource is included in the backend deletion plan.'
                                  : 'Included in the backend deletion plan.'}
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
                label={
                  profile.previewType === 'INTEGRATION_KEY' &&
                  props.externalSystemName
                    ? 'I have reviewed these deletion impacts and understand that deleting this key may break the external integration. Recovery requires a new key and reconfiguration.'
                    : 'I have reviewed and acknowledge these deletion impacts.'
                }
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
