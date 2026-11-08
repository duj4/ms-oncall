import React, { useState } from 'react'
import { gql, useMutation } from 'urql'
import { fieldErrors, nonFieldErrors } from '../util/errutil'
import FormDialog from '../dialogs/FormDialog'
import PolicyForm, { PolicyFormValue } from './PolicyForm'
import { Redirect } from 'wouter'
import { useCreateTarget } from '../main/OrganizationManagement'

const mutation = gql`
  mutation ($input: CreateEscalationPolicyInput!) {
    createEscalationPolicy(input: $input) {
      id
      organization {
        id
      }
    }
  }
`

function PolicyCreateDialog(props: { onClose: () => void }): React.JSX.Element {
  const target = useCreateTarget()
  const defaultValue = {
    name: '',
    description: '',
    repeat: { label: '3', value: '3' },
    favorite: target.favorite,
  }
  const [value, setValue] = useState<PolicyFormValue>(defaultValue)
  const [createPolicyStatus, createPolicy] = useMutation(mutation)

  const { fetching, data, error } = createPolicyStatus

  if (data && data.createEscalationPolicy) {
    if (
      target.targetOrganizationID &&
      data.createEscalationPolicy.organization?.id !==
        target.targetOrganizationID
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
    return (
      <Redirect to={`/escalation-policies/${data.createEscalationPolicy.id}`} />
    )
  }

  const fieldErrs = fieldErrors(error)

  return (
    <FormDialog
      title='Create Escalation Policy'
      subTitle={'Organization: ' + target.targetName}
      disableSubmit={target.uncertain}
      caption={
        target.uncertain
          ? 'Result unconfirmed. Verify existing resources before creating again.'
          : undefined
      }
      loading={fetching}
      errors={nonFieldErrors(error)}
      onClose={props.onClose}
      onSubmit={() =>
        target.submit(() =>
          createPolicy(
            {
              input: {
                name: value && value.name,
                description: value && value.description,
                repeat: value && value.repeat.value,
                favorite: target.favorite,
                targetOrganizationID: target.targetOrganizationID,
              },
            },
            { additionalTypenames: ['EscalationPolicyConnection'] },
          ),
        )
      }
      form={
        <PolicyForm
          errors={fieldErrs}
          disabled={fetching}
          value={value}
          onChange={(value: PolicyFormValue) => setValue(value)}
        />
      }
    />
  )
}

export default PolicyCreateDialog
