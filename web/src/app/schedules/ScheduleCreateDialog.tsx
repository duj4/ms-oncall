import React, { useState } from 'react'
import { gql, useMutation } from 'urql'
import FormDialog from '../dialogs/FormDialog'
import ScheduleForm, { Value } from './ScheduleForm'
import { nonFieldErrors, fieldErrors } from '../util/errutil'
import { Redirect } from 'wouter'
import { useCreateTarget } from '../main/OrganizationManagement'

const mutation = gql`
  mutation ($input: CreateScheduleInput!) {
    createSchedule(input: $input) {
      id
      name
      description
      timeZone
      organization {
        id
      }
    }
  }
`

export default function ScheduleCreateDialog(props: {
  onClose: () => void
}): React.JSX.Element {
  const target = useCreateTarget()
  const [value, setValue] = useState<Value>({
    name: '',
    description: '',
    timeZone: Intl.DateTimeFormat().resolvedOptions().timeZone,
    favorite: target.favorite,
  })

  const [{ fetching, data, error }, commit] = useMutation(mutation)

  if (data && data.createSchedule) {
    if (
      target.targetOrganizationID &&
      data.createSchedule.organization?.id !== target.targetOrganizationID
    )
      return (
        <FormDialog
          title='Creation result needs verification'
          alert
          onClose={props.onClose}
          errors={[
            {
              message:
                'The created organization could not be verified. Inspect existing resources before creating again.',
            },
          ]}
        />
      )
    return <Redirect to={`/schedules/${data.createSchedule.id}`} />
  }

  return (
    <FormDialog
      onClose={props.onClose}
      title='Create New Schedule'
      subTitle={'Organization: ' + target.targetName}
      loading={fetching}
      disableSubmit={target.uncertain}
      caption={
        target.uncertain
          ? 'Result unconfirmed. Verify existing resources before creating again.'
          : undefined
      }
      errors={nonFieldErrors(error)}
      onSubmit={() =>
        target.submit(() =>
          commit({
            input: {
              ...value,
              targetOrganizationID: target.targetOrganizationID,
              favorite: target.favorite,
              targets: target.canUseCurrentUser
                ? [
                    {
                      target: { type: 'user', id: '__current_user' },
                      rules: [{}],
                    },
                  ]
                : [],
            },
          }),
        )
      }
      form={
        <ScheduleForm
          disabled={fetching}
          errors={fieldErrors(error)}
          value={value}
          onChange={(value: Value) => setValue(value)}
        />
      }
    />
  )
}
