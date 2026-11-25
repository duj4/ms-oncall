import React from 'react'
import DeletionSafetyDialog from '../dialogs/DeletionSafetyDialog'
import { useDeletionSafety } from '../util/useDeletionSafety'
import { serviceDeletionProfile } from '../util/deletionSafetyProfiles'

export default function ServiceDeleteDialog(props: {
  serviceID: string
  onClose: () => void
}): React.JSX.Element {
  const dialog = useDeletionSafety(
    serviceDeletionProfile,
    props.serviceID,
    props.onClose,
  )
  return <DeletionSafetyDialog {...dialog} />
}
