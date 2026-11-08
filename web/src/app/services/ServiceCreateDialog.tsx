import { labelsDisabled } from '../util/labelProductPolicy'
import React, { useState } from 'react'
import { gql, useMutation } from 'urql'
import FormDialog from '../dialogs/FormDialog'
import ServiceForm, { Value } from './ServiceForm'
import { Redirect } from 'wouter'
import { Label } from '../../schema'
import { useErrorConsumer } from '../util/ErrorConsumer'
import { useConfigValue } from '../util/RequireConfig'
import { useCreateTarget } from '../main/OrganizationManagement'

interface InputVar {
  targetOrganizationID?: string
  name: string
  description: string
  escalationPolicyID?: string
  favorite: boolean
  labels: Label[]
  newEscalationPolicy?: {
    name: string
    description: string
    favorite: boolean
    steps: { delayMinutes: number; targets: { type: string; id: string }[] }[]
  }
}

const createMutation = gql`
  mutation createService($input: CreateServiceInput!) {
    createService(input: $input) {
      id
      name
      description
      escalationPolicyID
      organization {
        id
      }
    }
  }
`

function inputVars(
  { name, description, escalationPolicyID, labels }: Value,
  targetOrganizationID: string | undefined,
  favorite: boolean,
  canUseCurrentUser: boolean,
): InputVar {
  const vars: InputVar = {
    name,
    targetOrganizationID,
    description,
    escalationPolicyID,
    favorite,
    labels,
  }
  if (!vars.escalationPolicyID) {
    vars.newEscalationPolicy = {
      name: name + ' Policy',
      description: 'Auto-generated policy for ' + name,
      favorite,
      steps: canUseCurrentUser
        ? [
            {
              delayMinutes: 5,
              targets: [
                {
                  type: 'user',
                  id: '__current_user',
                },
              ],
            },
          ]
        : [],
    }
  }

  return vars
}

export default function ServiceCreateDialog(props: {
  onClose: () => void
}): JSX.Element {
  const target = useCreateTarget()
  const [value, setValue] = useState<Value>({
    name: '',
    description: '',
    escalationPolicyID: '',
    labels: [],
  })

  const [createKeyStatus, commit] = useMutation(createMutation)

  const { data, error } = createKeyStatus
  const errs = useErrorConsumer(error)
  const [reqLabels] = useConfigValue('Services.RequiredLabels') as [string[]]

  if (data && data.createService) {
    if (
      target.targetOrganizationID &&
      data.createService.organization?.id !== target.targetOrganizationID
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
    errs.done()
    return <Redirect to={`/services/${data.createService.id}`} />
  }
  const labelErr = { key: '', msg: '' }
  const requiredLabels = labelsDisabled() ? [] : reqLabels || []
  requiredLabels.some((key, i) => {
    labelErr.key = key
    labelErr.msg = errs.getErrorByField('labels[' + i + '].Value') || ''
    return !!labelErr.msg
  })

  return (
    <FormDialog
      title='Create New Service'
      subTitle={'Organization: ' + target.targetName}
      loading={createKeyStatus.fetching}
      disableSubmit={target.uncertain}
      caption={
        target.uncertain
          ? 'Result unconfirmed. Verify existing resources before creating again.'
          : undefined
      }
      errors={errs.remainingLegacyCallback()}
      onClose={props.onClose}
      onSubmit={() =>
        target.submit(() =>
          commit(
            {
              input: inputVars(
                value,
                target.targetOrganizationID,
                target.favorite,
                target.canUseCurrentUser,
              ),
            },
            {
              additionalTypenames: ['ServiceConnection'],
            },
          ),
        )
      }
      form={
        <ServiceForm
          nameError={errs.getErrorByField('Name')}
          descError={errs.getErrorByField('Description')}
          epError={errs.getErrorByField('EscalationPolicyID')}
          labelErrorKey={labelErr.key}
          labelErrorMsg={labelErr.msg}
          value={value}
          onChange={(val: Value) => setValue(val)}
        />
      }
    />
  )
}
