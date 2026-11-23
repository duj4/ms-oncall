import React from 'react'
import DeletionSafetyDialog from '../dialogs/DeletionSafetyDialog'
import { notificationRuleDeletionProfile } from '../util/deletionSafetyProfiles'
import { useDeletionSafety } from '../util/useDeletionSafety'
export default function UserNotificationRuleDeleteDialog(props: {
  ruleID: string
  onClose: () => void
}): JSX.Element {
  return (
    <DeletionSafetyDialog
      {...useDeletionSafety(
        notificationRuleDeletionProfile,
        props.ruleID,
        props.onClose,
        props.onClose,
      )}
    />
  )
}
