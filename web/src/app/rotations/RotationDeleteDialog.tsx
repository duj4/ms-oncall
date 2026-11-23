import React from 'react'
import DeletionSafetyDialog from '../dialogs/DeletionSafetyDialog'
import { useDeletionSafety } from '../util/useDeletionSafety'
import { rotationDeletionProfile } from '../util/deletionSafetyProfiles'

export default function RotationDeleteDialog(props: {
  rotationID: string
  onClose: () => void
}): React.JSX.Element {
  const dialog = useDeletionSafety(
    rotationDeletionProfile,
    props.rotationID,
    props.onClose,
  )
  return <DeletionSafetyDialog {...dialog} />
}
