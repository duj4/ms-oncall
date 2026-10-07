import React, { useState } from 'react'
import { gql, useQuery, useMutation } from 'urql'

import FormDialog from '../dialogs/FormDialog'
import ServiceForm from './ServiceForm'
import { Label } from '../../schema'
import { useErrorConsumer } from '../util/ErrorConsumer'

interface Value {
  name: string
  description: string
  escalationPolicyID?: string
  labels: Label[]
}

const query = gql`
  query service($id: ID!) {
    service(id: $id) {
      id
      name
      description
      labels {
        key
        value
      }
      ep: escalationPolicy {
        id
        name
      }
    }
  }
`
const mutation = gql`
  mutation updateService($input: UpdateServiceInput!) {
    updateService(input: $input)
  }
`
export default function ServiceEditDialog(props: {
  serviceID: string
  onClose: () => void
}): JSX.Element {
  const [{ data, error: dataError }] = useQuery({
    query,
    variables: { id: props.serviceID },
  })
  const defaultValue = {
    name: data?.service?.name,
    description: data?.service?.description,
    escalationPolicyID: data?.service?.ep?.id,
    labels: [],
  }
  const [value, setValue] = useState<Value>(defaultValue)

  const [saveStatus, save] = useMutation(mutation)

  const errs = useErrorConsumer(saveStatus.error)
  console.log()

  return (
    <FormDialog
      title='Edit Service'
      loading={saveStatus.fetching}
      errors={errs.remainingLegacyCallback()}
      onClose={props.onClose}
      onSubmit={async () => {
        const saveRes = await save(
          {
            input: {
              id: props.serviceID,
              name: value?.name || '',
              description: value?.description || '',
              escalationPolicyID: value?.escalationPolicyID || '',
            },
          },
          {
            additionalTypenames: ['Service'],
          },
        )
        if (saveRes.error) return

        props.onClose()
      }}
      form={
        <ServiceForm
          epRequired
          nameError={errs.getErrorByField('Name')}
          descError={errs.getErrorByField('Description')}
          epError={errs.getErrorByField('EscalationPolicyID')}
          disabled={Boolean(saveStatus.fetching || !data || dataError)}
          value={value}
          onChange={(value) => setValue(value)}
        />
      }
    />
  )
}
