import React, { useState } from 'react'
import { gql, useMutation } from 'urql'
import { nonFieldErrors, fieldErrors } from '../util/errutil'
import FormDialog from '../dialogs/FormDialog'
import RotationForm from './RotationForm'
import { DateTime } from 'luxon'
import { Redirect } from 'wouter'
import { CreateRotationInput } from '../../schema'
import { useCreateTarget } from '../main/OrganizationManagement'

const mutation = gql`
  mutation ($input: CreateRotationInput!) {
    createRotation(input: $input) {
      id
      name
      description
      start
      timeZone
      type
      shiftLength
      organization {
        id
      }
    }
  }
`

const RotationCreateDialog = (props: {
  onClose?: () => void
}): React.JSX.Element => {
  const target = useCreateTarget()
  const [value, setValue] = useState<CreateRotationInput>({
    name: '',
    description: '',
    timeZone: Intl.DateTimeFormat().resolvedOptions().timeZone,
    type: 'daily',
    start: DateTime.local().plus({ hours: 1 }).startOf('hour').toISO(),
    shiftLength: 1,
    favorite: target.favorite,
  })
  const [{ data, error, fetching }, commit] = useMutation(mutation)

  if (data?.createRotation) {
    if (
      target.targetOrganizationID &&
      data.createRotation.organization?.id !== target.targetOrganizationID
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
    return <Redirect to={`/rotations/${data.createRotation.id}`} />
  }

  return (
    <FormDialog
      title='Create Rotation'
      subTitle={'Organization: ' + target.targetName}
      loading={fetching}
      disableSubmit={target.uncertain}
      caption={
        target.uncertain
          ? 'Result unconfirmed. Verify existing resources before creating again.'
          : undefined
      }
      errors={nonFieldErrors(error)}
      onClose={props.onClose}
      onSubmit={() =>
        target.submit(() =>
          commit({
            input: {
              ...value,
              targetOrganizationID: target.targetOrganizationID,
              favorite: target.favorite,
            },
          }),
        )
      }
      form={
        <RotationForm
          errors={fieldErrors(error)}
          value={value}
          onChange={(value) => setValue(value)}
        />
      }
    />
  )
}

export default RotationCreateDialog
