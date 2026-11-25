import React, { Suspense, useState, useMemo } from 'react'
import { gql, useQuery } from 'urql'
import Button from '@mui/material/Button'
import Grid from '@mui/material/Grid'
import Card from '@mui/material/Card'
import CardContent from '@mui/material/CardContent'
import CreateFAB from '../lists/CreateFAB'
import IconButton from '@mui/material/IconButton'
import { Trash } from '../icons'
import IntegrationKeyCreateDialog from './IntegrationKeyCreateDialog'
import IntegrationKeyDeleteDialog from './IntegrationKeyDeleteDialog'
import CopyText from '../util/CopyText'
import AppLink from '../util/AppLink'
import { useIsWidthDown } from '../util/useWidth'
import { Add } from '@mui/icons-material'
import makeStyles from '@mui/styles/makeStyles'
import Spinner from '../loading/components/Spinner'
import { GenericError } from '../error-pages'
import { IntegrationKey } from '../../schema'
import { useFeatures } from '../util/RequireConfig'
import {
  Accordion,
  AccordionDetails,
  AccordionSummary,
  Chip,
  Typography,
} from '@mui/material'
import { ChevronDown } from 'mdi-material-ui'
import CompList from '../lists/CompList'
import { CompListItemText } from '../lists/CompListItems'
import { useOrganizationManagement } from '../main/OrganizationManagement'

export const integrationKeyListQuery = gql`
  query ($serviceID: ID!) {
    service(id: $serviceID) {
      id # need to tie the result to the correct record
      integrationKeys {
        id
        type
        name
        href
        externalSystemName
      }
    }
  }
`

const useStyles = makeStyles({
  copyIcon: {
    paddingRight: '0.25em',
    color: 'black',
  },
  keyLink: {
    display: 'flex',
    alignItems: 'center',
    width: 'fit-content',
  },
  spacing: {
    marginBottom: 96,
  },
})

const sortItems = (a: IntegrationKey, b: IntegrationKey): number => {
  const extA = a.externalSystemName || ''
  const extB = b.externalSystemName || ''
  if (extA.toLowerCase() < extB.toLowerCase()) return -1
  if (extA.toLowerCase() > extB.toLowerCase()) return 1
  if (extA < extB) return -1
  if (extA > extB) return 1
  if (a.name.toLowerCase() < b.name.toLowerCase()) return -1
  if (a.name.toLowerCase() > b.name.toLowerCase()) return 1
  if (a.name < b.name) return -1
  if (a.name > b.name) return 1
  return 0
}

export function IntegrationKeyDetails(props: {
  href: string
  label: string
  type: string
}): JSX.Element {
  const types = useFeatures().integrationKeyTypes
  const t = types.find((t) => t.id === props.type) || {
    enabled: false,
    name: props.type,
  }

  if (!t.enabled) {
    return (
      <React.Fragment>
        {t.name} integration keys are currently disabled.
      </React.Fragment>
    )
  }

  return <CopyText title={'Copy ' + props.label} value={props.href} asURL />
}

export default function IntegrationKeyList(props: {
  serviceID: string
}): JSX.Element {
  const classes = useStyles()
  const isMobile = useIsWidthDown('md')
  const [create, setCreate] = useState<boolean>(false)
  const scope = useOrganizationManagement()
  const scopeKey = JSON.stringify([scope?.identity, scope?.target.id])
  const [deleteSelection, setDeleteSelection] = useState<{
    id: string
    type: string
    serviceID: string
    scopeKey: string
  } | null>(null)
  const queryContext = useMemo(() => ({ suspense: false }), [])

  const [{ fetching, error, data }, refresh] = useQuery({
    query: integrationKeyListQuery,
    variables: { serviceID: props.serviceID },
    context: queryContext,
  })
  const types = useFeatures().integrationKeyTypes
  const typeLabel = (type: string): string =>
    types.find((t) => t.id === type)?.label || type

  const keys: IntegrationKey[] =
    data?.service?.id === props.serviceID
      ? data.service.integrationKeys || []
      : []
  const currentKey = keys.find((key) => key.id === deleteSelection?.id)
  const validSelection =
    deleteSelection?.serviceID === props.serviceID &&
    deleteSelection?.scopeKey === scopeKey &&
    (!currentKey || currentKey.type === deleteSelection?.type)
  // This slot stays mounted outside list loading/error/null and Suspense.
  // Losing a list row is not a successful deletion receipt.
  const deleteDialog = deleteSelection && (
    <IntegrationKeyDeleteDialog
      integrationKeyID={validSelection ? deleteSelection.id : ''}
      integrationKeyType={deleteSelection.type}
      serviceID={props.serviceID}
      onClose={() => setDeleteSelection(null)}
      onSuccess={() => {
        setDeleteSelection(null)
        refresh({ requestPolicy: 'network-only' })
      }}
    />
  )
  if ((fetching && !data?.service) || error || !data?.service)
    return (
      <React.Fragment>
        {deleteDialog}
        {error ? (
          <GenericError error={error.message} />
        ) : fetching ? (
          <Spinner />
        ) : (
          <CompList emptyMessage='No integration keys exist for this service.' />
        )}
      </React.Fragment>
    )

  const uikActions = (key: IntegrationKey): React.ReactNode => {
    return (
      <Grid container spacing={2} alignItems='center' wrap='nowrap'>
        {key.type === 'universal' && (
          <Grid item>
            <AppLink to={key.id}>
              <Button
                title='Manage configuration and tokens for this key.'
                onClick={() => {}}
                variant='contained'
              >
                Manage
              </Button>
            </AppLink>
          </Grid>
        )}
        <Grid item>
          <IconButton
            title='Delete this key.'
            onClick={(): void =>
              setDeleteSelection({
                id: key.id,
                type: key.type,
                serviceID: props.serviceID,
                scopeKey,
              })
            }
            size='large'
          >
            <Trash />
          </IconButton>
        </Grid>
      </Grid>
    )
  }

  const items = keys
    .slice()
    .sort(sortItems)
    .filter((key: IntegrationKey) => !key.externalSystemName)
    .map((key: IntegrationKey) => (
      <CompListItemText
        key={key.id}
        title={key.name}
        subText={
          <IntegrationKeyDetails
            key={key.id}
            href={key.href}
            label={typeLabel(key.type)}
            type={key.type}
          />
        }
        action={uikActions(key)}
      />
    ))

  const extItems = keys
    .slice()
    .sort(sortItems)
    .filter((key: IntegrationKey) => !!key.externalSystemName)
    .map((key: IntegrationKey) => (
      <CompListItemText
        key={key.id}
        title={key.name}
        subText={<Chip label={key.externalSystemName} sx={{ mt: 1 }} />}
        action={uikActions(key)}
      />
    ))

  return (
    <React.Fragment>
      {deleteDialog}
      <Grid item xs={12} className={classes.spacing}>
        <Card>
          <CardContent>
            <CompList
              data-cy='int-keys'
              note={
                <React.Fragment>
                  API Documentation is available{' '}
                  <AppLink to='/docs'>here</AppLink>.
                </React.Fragment>
              }
              emptyMessage='No integration keys exist for this service.'
              hideActionOnMobile
              action={
                <Button
                  variant='contained'
                  onClick={(): void => setCreate(true)}
                  startIcon={<Add />}
                  data-testid='create-key'
                >
                  Create Integration Key
                </Button>
              }
            >
              {items}
            </CompList>
            {!!extItems.length && (
              <Accordion disableGutters elevation={0}>
                <AccordionSummary
                  expandIcon={<ChevronDown />}
                  sx={{ ml: '6px', mr: '12px' }}
                >
                  <Typography>Externally Managed Keys</Typography>
                </AccordionSummary>
                <AccordionDetails>
                  <CompList note='These keys are managed by other applications.'>
                    {extItems}
                  </CompList>
                </AccordionDetails>
              </Accordion>
            )}
          </CardContent>
        </Card>
      </Grid>
      {isMobile && (
        <CreateFAB
          onClick={(): void => setCreate(true)}
          title='Create Integration Key'
        />
      )}
      <Suspense>
        {create && (
          <IntegrationKeyCreateDialog
            serviceID={props.serviceID}
            onClose={(): void => setCreate(false)}
          />
        )}
      </Suspense>
    </React.Fragment>
  )
}
