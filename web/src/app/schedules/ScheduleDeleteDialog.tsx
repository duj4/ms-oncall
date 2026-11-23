import React from 'react'
import DeletionSafetyDialog from '../dialogs/DeletionSafetyDialog'
import { useDeletionSafety } from '../util/useDeletionSafety'
import { scheduleDeletionProfile } from '../util/deletionSafetyProfiles'

export default function ScheduleDeleteDialog(props: {
  scheduleID: string
  onClose: () => void
}): React.JSX.Element {
  const dialog = useDeletionSafety(
    scheduleDeletionProfile,
    props.scheduleID,
    props.onClose,
  )
  return <DeletionSafetyDialog {...dialog} />
}
