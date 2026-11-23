import React from 'react'
import DeletionSafetyDialog from '../dialogs/DeletionSafetyDialog'
import { useDeletionSafety } from '../util/useDeletionSafety'
import { epDeletionProfile } from '../util/deletionSafetyProfiles'

export default function PolicyDeleteDialog(props: {
  escalationPolicyID: string
  onClose: () => void
}): React.JSX.Element {
  const dialog = useDeletionSafety(
    epDeletionProfile,
    props.escalationPolicyID,
    props.onClose,
  )
  return <DeletionSafetyDialog {...dialog} />
}
