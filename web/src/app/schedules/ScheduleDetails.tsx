import React, { useState, useCallback, Suspense } from 'react'
import { gql, useQuery } from 'urql'
import _ from 'lodash'
import { Edit, Delete } from '@mui/icons-material'

import DetailsPage from '../details/DetailsPage'
import ScheduleEditDialog from './ScheduleEditDialog'
import ScheduleDeleteDialog from './ScheduleDeleteDialog'
import ScheduleCalendarQuery from './ScheduleCalendarQuery'
import { QuerySetFavoriteButton } from '../util/QuerySetFavoriteButton'
import CalendarSubscribeButton from './calendar-subscribe/CalendarSubscribeButton'
import { ObjectNotFound, GenericError } from '../error-pages'
import TempSchedDialog from './temp-sched/TempSchedDialog'
import TempSchedDeleteConfirmation from './temp-sched/TempSchedDeleteConfirmation'
import { ScheduleAvatar } from '../util/avatars'
import ScheduleOverrideDialog from './ScheduleOverrideDialog'
import { useIsWidthDown } from '../util/useWidth'
import { TempSchedValue, defaultTempSchedValue } from './temp-sched/sharedUtils'
import { useScheduleTZ } from './useScheduleTZ'
import { useURLParam } from '../actions'

const query = gql`
  fragment ScheduleTitleQuery on Schedule {
    id
    name
    description
  }

  query scheduleDetailsQuery($id: ID!) {
    schedule(id: $id) {
      ...ScheduleTitleQuery
      timeZone
    }
  }
`

export interface OverrideDialog {
  variantOptions: string[]
  removeUserReadOnly: boolean
  defaultValue?: {
    addUserID?: string
    removeUserID?: string
    start: string
    end: string
  }
}

interface OverrideDialogContext {
  onNewTempSched: () => void
  onEditTempSched: (v: TempSchedValue) => void
  onDeleteTempSched: React.Dispatch<React.SetStateAction<TempSchedValue | null>>
  setOverrideDialog: React.Dispatch<React.SetStateAction<OverrideDialog | null>>
}

export const OverrideDialogContext = React.createContext<OverrideDialogContext>(
  {
    onNewTempSched: () => {},
    onEditTempSched: () => {},
    onDeleteTempSched: () => {},
    setOverrideDialog: () => {},
  },
)

export type ScheduleDetailsProps = {
  scheduleID: string
}

export default function ScheduleDetails({
  scheduleID,
}: ScheduleDetailsProps): React.JSX.Element {
  const [newOverride] = useURLParam('new-override', '')
  const newValidOverride = ['add', 'remove', 'replace'].includes(newOverride)
    ? newOverride
    : ''
  const [showEdit, setShowEdit] = useState(false)
  const [showDelete, setShowDelete] = useState(false)

  const isMobile = useIsWidthDown('md')

  const [editTempSched, setEditTempSched] = useState(false)

  const [configTempSchedule, setConfigTempSchedule] =
    useState<TempSchedValue | null>(null)
  const { zone } = useScheduleTZ(scheduleID)
  const onNewTempSched = useCallback(() => {
    setEditTempSched(false)
    setConfigTempSchedule(defaultTempSchedValue(zone))
  }, [])
  const onEditTempSched = useCallback((v: TempSchedValue) => {
    setEditTempSched(true)
    setConfigTempSchedule(v)
  }, [])

  const [deleteTempSchedule, setDeleteTempSchedule] =
    useState<TempSchedValue | null>(null)
  const onDeleteTempSched = useCallback(setDeleteTempSchedule, [])
  const [overrideDialog, setOverrideDialog] = useState<OverrideDialog | null>(
    newValidOverride
      ? { variantOptions: [newValidOverride], removeUserReadOnly: false }
      : null,
  )

  const [{ data: _data, error }] = useQuery({
    query,
    variables: { id: scheduleID },
  })

  const data = _.get(_data, 'schedule', null)

  const deleteDialog = showDelete && (
    <ScheduleDeleteDialog
      key={scheduleID}
      scheduleID={scheduleID}
      onClose={() => setShowDelete(false)}
    />
  )
  // A missing/failed query is not evidence that this deletion committed. Keep
  // its controller at the same position through parent refetches, including
  // CommitUnknown. Only an explicit successful mutation may navigate away.
  if (error || !data) {
    return (
      <React.Fragment>
        {deleteDialog}
        {error ? <GenericError error={error.message} /> : <ObjectNotFound />}
      </React.Fragment>
    )
  }

  return (
    <React.Fragment>
      {deleteDialog}
      <Suspense>
        {showEdit && (
          <ScheduleEditDialog
            scheduleID={scheduleID}
            onClose={() => setShowEdit(false)}
          />
        )}
        {configTempSchedule && (
          <TempSchedDialog
            value={configTempSchedule}
            onClose={() => setConfigTempSchedule(null)}
            scheduleID={scheduleID}
            edit={editTempSched}
          />
        )}
        {deleteTempSchedule && (
          <TempSchedDeleteConfirmation
            value={deleteTempSchedule}
            onClose={() => setDeleteTempSchedule(null)}
            scheduleID={scheduleID}
          />
        )}
      </Suspense>
      <DetailsPage
        avatar={<ScheduleAvatar />}
        title={data.name}
        subheader={`Time Zone: ${data.timeZone || 'Loading...'}`}
        details={data.description}
        pageContent={
          <OverrideDialogContext.Provider
            value={{
              onNewTempSched,
              onEditTempSched,
              onDeleteTempSched,
              setOverrideDialog,
            }}
          >
            {!isMobile && <ScheduleCalendarQuery scheduleID={scheduleID} />}
            <Suspense>
              {overrideDialog && (
                <ScheduleOverrideDialog
                  defaultValue={overrideDialog.defaultValue}
                  variantOptions={overrideDialog.variantOptions}
                  scheduleID={scheduleID}
                  onClose={() => setOverrideDialog(null)}
                  removeUserReadOnly={overrideDialog.removeUserReadOnly}
                />
              )}
            </Suspense>
          </OverrideDialogContext.Provider>
        }
        primaryActions={[
          <CalendarSubscribeButton
            key='primary-action-subscribe'
            scheduleID={scheduleID}
          />,
        ]}
        secondaryActions={[
          {
            label: 'Edit',
            icon: <Edit />,
            handleOnClick: () => setShowEdit(true),
          },
          {
            label: 'Delete',
            icon: <Delete />,
            handleOnClick: () => setShowDelete(true),
          },
          <QuerySetFavoriteButton
            key='secondary-action-favorite'
            id={scheduleID}
            type='schedule'
          />,
        ]}
        links={[
          {
            label: 'Assignments',
            url: 'assignments',
            subText: 'Manage rules for rotations and users',
          },
          {
            label: 'Escalation Policies',
            url: 'escalation-policies',
            subText: 'Find escalation policies that link to this schedule',
          },
          {
            label: 'Overrides',
            url: 'overrides',
            subText: 'Add, remove, or replace a user temporarily',
          },
          {
            label: 'Shifts',
            url: 'shifts',
            subText: 'Review a list of past and future on-call shifts',
          },
          {
            label: 'On-Call Notifications',
            url: 'on-call-notifications',
            subText: 'Set up notifications to know who is on-call',
          },
        ]}
      />
    </React.Fragment>
  )
}
