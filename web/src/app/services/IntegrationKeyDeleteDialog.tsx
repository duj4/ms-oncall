import React from 'react'
import DeletionSafetyDialog from '../dialogs/DeletionSafetyDialog'
import { useDeletionSafety } from '../util/useDeletionSafety'
import { integrationKeyDeletionProfile } from '../util/deletionSafetyProfiles'

export default function IntegrationKeyDeleteDialog(props: {
  integrationKeyID: string
  integrationKeyType: string
  serviceID: string
  onClose: () => void
  onSuccess: () => void
}): React.JSX.Element {
  const dialog = useDeletionSafety(
    integrationKeyDeletionProfile,
    props.integrationKeyID,
    props.onClose,
    props.onSuccess,
    { serviceID: props.serviceID, type: props.integrationKeyType },
  )
  return <DeletionSafetyDialog {...dialog} />
}
