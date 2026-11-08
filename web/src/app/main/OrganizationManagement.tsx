import React, {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  Suspense,
} from 'react'
import { gql, Provider, useClient, useQuery, OperationResult } from 'urql'
import { AnyAction } from 'redux'
import { ApolloProvider } from '@apollo/client'
import { useLocation, useSearch } from 'wouter'
import {
  Alert,
  Box,
  Button,
  MenuItem,
  TextField,
  Typography,
} from '@mui/material'
import { useDispatch } from 'react-redux'
import { authLogout } from '../actions'
import { createOrganizationClient } from '../apollo'
import { disposeClient, newClient, refetchAll } from '../urql'
import {
  createResultUncertain,
  hasExpectedCreatedOrganization,
} from '../util/rootCreatePolicy'
import { pathPrefix } from '../env'
import Spinner from '../loading/components/Spinner'

type Org = { id: string; displayName: string }
type DirectoryData = {
  manageableOrganizations: {
    nodes: Org[]
    pageInfo: { hasNextPage: boolean; endCursor: string | null }
  }
}
type Identity = {
  userID: string
  homeOrganization: Org
  homeClassification: string
  homeOrgRole: string
  isPlatformAdmin: boolean
  canCreateGlobalRoots: boolean
}
type Scope = {
  identity: Identity
  target: Org
  foreign: boolean
  canCreate: boolean
  lock: () => () => void
  controls: React.ReactNode
}
const OrganizationContext = createContext<Scope | null>(null)
const queryContext = { suspense: false }
const identityQuery = gql`
  query {
    currentOrganizationContext {
      userID
      homeOrganization {
        id
        displayName
      }
      homeClassification
      homeOrgRole
      isPlatformAdmin
      canCreateGlobalRoots
    }
  }
`
const directoryQuery = gql`
  query ($after: String) {
    manageableOrganizations(first: 100, after: $after) {
      nodes {
        id
        displayName
      }
      pageInfo {
        hasNextPage
        endCursor
      }
    }
  }
`
const roots: Record<string, string> = {
  services: 'service',
  schedules: 'schedule',
  rotations: 'rotation',
  'escalation-policies': 'escalationPolicy',
}

export function useOrganizationManagement(): Scope | null {
  return useContext(OrganizationContext)
}
export function useTargetOrganizationID(): string | undefined {
  return useContext(OrganizationContext)?.target.id
}
export function OrganizationControls(): JSX.Element {
  return (
    <React.Fragment>{useContext(OrganizationContext)?.controls}</React.Fragment>
  )
}

function ScopedClients({
  scope,
  children,
}: {
  scope: Scope
  children: React.ReactNode
}): JSX.Element {
  // Each target and authority identity gets independent caches and subscriptions.
  const [urql] = useState(() => newClient(pathPrefix + '/api/graphql'))
  const [apollo] = useState(createOrganizationClient)
  useEffect(
    () => () => {
      disposeClient(urql)
      apollo.stop()
    },
    [urql, apollo],
  )
  return (
    <OrganizationContext.Provider value={scope}>
      <Provider value={urql}>
        <ApolloProvider client={apollo}>
          <Suspense fallback={<Spinner />}>{children}</Suspense>
        </ApolloProvider>
      </Provider>
    </OrganizationContext.Provider>
  )
}

export default function OrganizationManagement({
  children,
}: {
  children: React.ReactNode
}): JSX.Element {
  const [path, navigate] = useLocation()
  const search = useSearch()
  const client = useClient()
  const dispatch = useDispatch()
  const [identityResult] = useQuery<{ currentOrganizationContext: Identity }>({
    query: identityQuery,
    requestPolicy: 'network-only',
    context: queryContext,
  })
  const identity = identityResult.data?.currentOrganizationContext
  const authorityKey = identity
    ? [
        identity.userID,
        identity.homeOrganization.id,
        identity.homeOrgRole,
        identity.isPlatformAdmin,
      ].join(':')
    : ''
  const [directory, setDirectory] = useState<Org[] | null>(null)
  const [directoryError, setDirectoryError] = useState('')
  const [message, setMessage] = useState('')
  const locks = useRef(0)
  const heldURL = useRef('')
  const [lockCount, setLockCount] = useState(0)
  const lock = useCallback(() => {
    if (!locks.current) heldURL.current = location.href
    locks.current++
    setLockCount(locks.current)
    let released = false
    return () => {
      if (released) return
      released = true
      locks.current--
      setLockCount(locks.current)
    }
  }, [])

  useEffect(() => {
    const push = history.pushState.bind(history)
    const replace = history.replaceState.bind(history)
    const guard = (url: string | URL | null | undefined): boolean => {
      if (!locks.current || !url) return false
      const held = new URL(heldURL.current)
      const next = new URL(url, location.href)
      if (
        held.pathname === next.pathname &&
        held.searchParams.get('org') === next.searchParams.get('org')
      )
        return false
      setMessage(
        'Close the create dialog before changing the management target.',
      )
      return true
    }
    history.pushState = (state, unused, url) => {
      if (!guard(url)) push(state, unused, url)
    }
    history.replaceState = (state, unused, url) => {
      if (!guard(url)) replace(state, unused, url)
    }
    const onPop = (event: PopStateEvent): void => {
      if (!guard(location.href)) return
      event.stopImmediatePropagation()
      replace(history.state, '', heldURL.current)
    }
    window.addEventListener('popstate', onPop, true)
    return () => {
      history.pushState = push
      history.replaceState = replace
      window.removeEventListener('popstate', onPop, true)
    }
  }, [])

  useEffect(() => {
    let active = true
    setDirectory(null)
    setDirectoryError('')
    if (!identity?.isPlatformAdmin) return
    ;(async () => {
      const orgs: Org[] = []
      let after: string | null = null
      for (;;) {
        const result: OperationResult<DirectoryData> = await client
          .query<DirectoryData>(
            directoryQuery,
            { after },
            { requestPolicy: 'network-only' },
          )
          .toPromise()
        if (!active) return
        if (result.error || !result.data) {
          setDirectoryError('Organization directory is unavailable.')
          return
        }
        const connection: DirectoryData['manageableOrganizations'] =
          result.data.manageableOrganizations
        orgs.push(...connection.nodes)
        if (!connection.pageInfo.hasNextPage) break
        if (
          !connection.pageInfo.endCursor ||
          connection.pageInfo.endCursor === after
        ) {
          setDirectoryError('Organization directory pagination failed.')
          return
        }
        after = connection.pageInfo.endCursor
      }
      if (active) setDirectory(orgs)
    })().catch(() => {
      if (active) setDirectoryError('Organization directory is unavailable.')
    })
    return () => {
      active = false
    }
  }, [authorityKey, client])

  const parts = path.split('/').filter(Boolean)
  const rootField = roots[parts[0]]
  const rootID = rootField && parts[1]
  const rootQuery = useMemo(
    () =>
      gql`query($id:ID!){root:${rootField || 'service'}(id:$id){id organization{id displayName}}}`,
    [rootField],
  )
  const [rootResult] = useQuery<{ root: { id: string; organization: Org } }>({
    query: rootQuery,
    variables: { id: rootID || '' },
    pause:
      !rootID ||
      !identity ||
      (identity.homeClassification === 'DEFAULT' && !identity.isPlatformAdmin),
    requestPolicy: 'network-only',
    context: queryContext,
  })
  const requested = new URLSearchParams(search).get('org')
  const targetID = rootID
    ? rootResult.data?.root?.id === rootID
      ? rootResult.data.root.organization.id
      : undefined
    : requested ||
      (identity?.homeClassification === 'NORMAL'
        ? identity.homeOrganization.id
        : undefined)
  const target = identity?.isPlatformAdmin
    ? directory?.find((org) => org.id === targetID)
    : identity && identity.homeOrganization.id === targetID
      ? identity.homeOrganization
      : undefined
  const logout = (): void => {
    dispatch(authLogout(true) as AnyAction)
  }
  const heading = identity && (
    <Typography variant='caption' component='div'>
      User: {identity.userID} · Home: {identity.homeOrganization.displayName} ·{' '}
      {identity.homeOrgRole} · PlatformAdmin:{' '}
      {identity.isPlatformAdmin ? 'yes' : 'no'}
    </Typography>
  )
  const choose = (id: string): void => {
    if (locks.current) {
      setMessage(
        'Close the create dialog before changing the management target.',
      )
      return
    }
    setMessage('')
    const list = rootField ? '/' + parts[0] : '/services'
    navigate(list + '?org=' + encodeURIComponent(id))
  }
  let error = identityResult.error
    ? 'Current authority is unavailable. Reload or sign out.'
    : directoryError
  if (
    rootID &&
    (rootResult.error || (rootResult.data && !rootResult.data.root))
  )
    error = 'The requested resource is unavailable.'
  if (
    identity &&
    !identity.isPlatformAdmin &&
    requested &&
    requested !== identity.homeOrganization.id
  )
    error = 'This organization is outside your Home authority.'
  if (
    identity &&
    !identity.isPlatformAdmin &&
    rootResult.data?.root &&
    rootResult.data.root.organization.id !== identity.homeOrganization.id
  )
    error = 'This resource is outside your Home authority.'
  if (identity?.isPlatformAdmin && directory && targetID && !target)
    error = 'The management organization is unavailable.'

  useEffect(() => {
    // A detail URL is a locator. Keep subsequent list navigation aligned with
    // the Organization resolved from the actual persisted Root.
    if (!rootID || !target || error || requested === target.id) return
    const params = new URLSearchParams(search)
    params.set('org', target.id)
    navigate(path + '?' + params.toString(), { replace: true })
  }, [rootID, target?.id, error, requested, path, search, navigate])

  const minimalDefault =
    identity?.homeClassification === 'DEFAULT' && !identity.isPlatformAdmin
  const defaultLanding =
    identity?.homeClassification === 'DEFAULT' && !rootField
  const scoped =
    identity && target && !error && !minimalDefault && !defaultLanding
  const controls = (
    <Box
      sx={{
        px: 1,
        height: 80,
        boxSizing: 'border-box',
        overflowX: 'auto',
        whiteSpace: 'nowrap',
      }}
      data-cy='organization-context'
    >
      {heading}
      {identity?.isPlatformAdmin && (
        <TextField
          select
          label='Management organization'
          value={target?.id || ''}
          onChange={(event) => choose(event.target.value)}
          disabled={lockCount > 0 || !directory}
          size='small'
          sx={{ minWidth: 240 }}
        >
          <MenuItem value='' disabled>
            Select an organization
          </MenuItem>
          {(directory || []).map((org) => (
            <MenuItem key={org.id} value={org.id}>
              {org.displayName}
            </MenuItem>
          ))}
        </TextField>
      )}
      <Button onClick={logout}>Sign out</Button>
      {message && <Alert severity='info'>{message}</Alert>}
      {error && <Alert severity='error'>{error}</Alert>}
    </Box>
  )
  return (
    <React.Fragment>
      {!scoped && controls}
      {!identity && !error && <Spinner />}
      {minimalDefault && (
        <Alert severity='info'>
          Your Home is Default. Ordinary business access is unavailable.
        </Alert>
      )}
      {identity?.isPlatformAdmin && !targetID && !error && (
        <Alert severity='info'>Select a Normal organization to manage.</Alert>
      )}
      {rootID && !targetID && !error && <Spinner />}
      {defaultLanding && target && !error && (
        <Box>
          {Object.keys(roots).map((group) => (
            <Button
              key={group}
              onClick={() =>
                navigate('/' + group + '?org=' + encodeURIComponent(target.id))
              }
            >
              {group}
            </Button>
          ))}
        </Box>
      )}
      {scoped && (
        <ScopedClients
          key={authorityKey + ':' + target.id}
          scope={{
            identity,
            target,
            foreign: identity.homeOrganization.id !== target.id,
            canCreate: identity.isPlatformAdmin
              ? identity.canCreateGlobalRoots
              : identity.homeOrgRole === 'ORG_ADMIN',
            lock,
            controls,
          }}
        >
          {children}
        </ScopedClients>
      )}
    </React.Fragment>
  )
}

export function useCreateTarget(): {
  targetOrganizationID?: string
  favorite: boolean
  canUseCurrentUser: boolean
  targetName: string
  uncertain: boolean
  cancel: () => void
  submit: <
    T extends {
      data?: unknown
      error?: {
        networkError?: unknown
        graphQLErrors?: ReadonlyArray<{ extensions?: Record<string, unknown> }>
      }
    },
  >(
    run: () => Promise<T>,
  ) => Promise<T | undefined>
} {
  const scope = useContext(OrganizationContext)
  const [fixed] = useState(scope)
  const pending = useRef<Promise<unknown> | null>(null)
  const release = useRef<(() => void) | undefined>(undefined)
  const [uncertain, setUncertain] = useState(false)
  const blocked = useRef(false)
  useEffect(() => {
    release.current = fixed?.lock()
    return () => release.current?.()
  }, [fixed?.lock])
  return {
    targetOrganizationID: fixed?.target.id,
    favorite: fixed ? !fixed.foreign : true,
    canUseCurrentUser: fixed
      ? !fixed.foreign && fixed.identity.homeClassification === 'NORMAL'
      : true,
    targetName: fixed?.target.displayName || '',
    uncertain,
    cancel: () => release.current?.(),
    submit: async (run) => {
      if (pending.current || blocked.current) return undefined
      // Establish the pending guard before invoking caller code, including a
      // synchronous transport failure. No second click may start a new Create.
      const request = Promise.resolve().then(run)
      pending.current = request
      try {
        const result = await request
        const matches = hasExpectedCreatedOrganization(
          result.data,
          fixed?.target.id,
        )
        if (
          createResultUncertain(result.error) ||
          (!result.error && !matches)
        ) {
          blocked.current = true
          setUncertain(true)
        }
        if (result.error) refetchAll(true)
        if (!result.error && matches) release.current?.()
        return result
      } catch {
        blocked.current = true
        setUncertain(true)
        refetchAll(true)
        return undefined
      } finally {
        pending.current = null
      }
    },
  }
}
