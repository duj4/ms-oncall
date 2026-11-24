import React from 'react'
import DeletionSafetyDialog from '../dialogs/DeletionSafetyDialog'
import { contactMethodDeletionProfile } from '../util/deletionSafetyProfiles'
import { useDeletionSafety } from '../util/useDeletionSafety'

export default function UserContactMethodDeleteDialog(props: {
  contactMethodID: string
  onClose: () => void
}): JSX.Element {
  return (
    <DeletionSafetyDialog
      {...useDeletionSafety(
        contactMethodDeletionProfile,
        props.contactMethodID,
        props.onClose,
        props.onClose,
      )}
    />
  )
}
