import React from 'react'
import DeletionSafetyDialog from '../dialogs/DeletionSafetyDialog'
import { userOverrideDeletionProfile } from '../util/deletionSafetyProfiles'
import { useDeletionSafety } from '../util/useDeletionSafety'

export default function ScheduleOverrideDeleteDialog(props: {
  overrideID: string
  onClose: () => void
}): JSX.Element {
  const deletion = useDeletionSafety(
    userOverrideDeletionProfile,
    props.overrideID,
    props.onClose,
    props.onClose,
  )
  return <DeletionSafetyDialog {...deletion} />
}
