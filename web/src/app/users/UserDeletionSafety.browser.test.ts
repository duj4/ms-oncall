// Controlled React/URQL/Chromium tests. HTTP responses are synthetic; these do
// not claim PostgreSQL, backend runtime or full application E2E coverage.
import { createServer, Server } from 'node:http'
import { appendFileSync } from 'node:fs'
import { createRequire } from 'node:module'
import { build } from 'esbuild'
import { chromium, Browser, Page } from 'playwright'
import path from 'node:path'
import {
  userActionPreview,
  userID,
  userImpact,
  userResource,
  userOwnedPreview,
  userPreview,
} from './userDeletionFixtures'
import type { DeletionPreview } from '../../schema'

const browserTests =
  process.env.MS_ONCALL_USER_DELETION_BROWSER_TEST_ENABLE === '1'
    ? describe
    : describe.skip
browserTests('User deletion actual React controller and URQL transport', () => {
  let browser: Browser, server: Server, origin: string, bundle: Uint8Array
  beforeAll(async () => {
    const output = await build({
      stdin: {
        resolveDir: path.resolve(__dirname, '..'),
        loader: 'tsx',
        contents: `
        import React,{useState,useLayoutEffect,startTransition,Suspense} from 'react';
        import {flushSync} from 'react-dom';
        import {TestSessionContext} from './util/RequireConfig';
        import {TestScopeContext} from './main/OrganizationManagement';
        import {createRoot} from 'react-dom/client';
        import {Provider,useQuery} from 'urql';
        import {ThemeProvider,createTheme} from '@mui/material/styles';
        import {useLocation} from 'wouter';
        import {client,newClient} from './urql';
        import UserDetails from './users/UserDetails';
        import UserDeleteDialog from './users/UserDeleteDialog';
        import {useDeletionSafety} from './util/useDeletionSafety';
        import * as profiles from './util/deletionSafetyProfiles';
        import DeletionSafetyDialog from './dialogs/DeletionSafetyDialog';
        import {userListQuery,defaultUserListInput} from './users/userListQuery';
        window.selectedUser=${JSON.stringify(userID)}; window.sessionUser=window.selectedUser; window.scope=null;
        const probe=new URLSearchParams(location.search).get('probe');
        if(probe==='integrationKey')window.scope={identity:{userID:window.sessionUser},target:{id:'20000000-0000-4000-8000-000000000001'},lock:()=>()=>{}};
        function Probe(){
          const profile=Object.values(profiles).find(p=>p.deleteType===probe);
          const model=useDeletionSafety(profile,window.selectedUser,()=>{},()=>{},probe==='integrationKey'?{serviceID:'80000000-0000-4000-8000-000000000001',type:'generic'}:undefined);
          window.confirmMany=()=>{model.onConfirm();model.onConfirm();model.onConfirm()};
          return <DeletionSafetyDialog {...model}/>;
        }
        const listContext={suspense:false};
        function Harness(){
          const [,setTick]=useState(0);const [open,setOpen]=useState(false);window.rerender=(id,scope)=>{if(id)window.selectedUser=id;if(scope!==undefined)window.scope=scope;setTick(x=>x+1)};
          const [loc]=useLocation();
          const [list]=useQuery({query:userListQuery,variables:{input:defaultUserListInput},context:listContext});
          return <><div data-testid="path">{loc}</div><div data-testid="list">{JSON.stringify(list.data)}</div>{probe?<><button onClick={()=>setOpen(true)}>Delete</button>{open&&<Probe/>}</>:<UserDetails userID={window.selectedUser} readOnly={false}/>}</>;
        }
        const refreshProbe=new URLSearchParams(location.search).has('refreshProbe');
        if(refreshProbe){
          window.refreshClients=[client,newClient('/api/graphql')];window.activeClient=client;
          window.closeCount=0;window.navigationCount=0;
          for(const method of ['pushState','replaceState']){
            const original=history[method];history[method]=function(...args){
              if(args[2]&&new URL(args[2],location.href).pathname==='/users')window.navigationCount++;
              return original.apply(this,args);
            };
          }
        }
        function RefreshHarness(){
          const [,setTick]=useState(0);const [open,setOpen]=useState(false);const [loc]=useLocation();
          window.rerender=(id,scope)=>{if(id)window.selectedUser=id;if(scope!==undefined)window.scope=scope;setTick(x=>x+1)};
          return <Provider value={window.activeClient}><div data-testid="selection">{window.selectedUser}</div><div data-testid="path">{loc}</div><button onClick={()=>setOpen(true)}>Delete</button>{open&&<UserDeleteDialog userID={window.selectedUser} onClose={()=>{window.closeCount++;setOpen(false)}}/>}</Provider>;
        }
        const lifecycleProbe=new URLSearchParams(location.search).has('lifecycleProbe');
        const interrupted=new Promise(()=>{});
        window.lifecycleEvents=[];
        const record=(event,view)=>window.lifecycleEvents.push({event,id:view.id,client:view.clientIndex,scope:view.organization,actor:view.actor});
        function LifecycleGate({view,open}){
          record('render',view);
          useLayoutEffect(()=>{
            window.committedView=view;record('setup',view);
            return ()=>record('cleanup',view);
          },[view,open]);
          if(view.suspend){record('suspend',view);throw interrupted}
          return null;
        }
        function LifecycleHarness(){
          const [view,setView]=useState({id:window.selectedUser,clientIndex:0,organization:null,actor:window.sessionUser,suspend:false,instance:0});
          const [open,setOpen]=useState(false);const [loc]=useLocation();
          window.lifecycleTransition=changes=>startTransition(()=>setView(v=>({...v,...changes,suspend:true})));
          window.lifecycleCommit=changes=>flushSync(()=>setView(v=>({...v,...changes})));
          window.lifecycleAbort=()=>flushSync(()=>setView({...window.committedView}));
          window.lifecycleUnmount=()=>flushSync(()=>setOpen(false));
          window.lifecycleRemount=()=>flushSync(()=>{setView(v=>({...v,instance:v.instance+1}));setOpen(true)});
          const scope=view.organization?{identity:{userID:view.actor},target:{id:view.organization},lock:()=>()=>{}}:null;
          return <Provider value={window.refreshClients[view.clientIndex]}><TestSessionContext.Provider value={{userID:view.actor,isAdmin:true}}><TestScopeContext.Provider value={scope}>
            <div data-testid="selection">{view.id}</div><div data-testid="path">{loc}</div>
            <button onClick={()=>setOpen(true)}>Delete</button>
            {open&&<UserDeleteDialog key={view.instance} userID={view.id} onClose={()=>{record('close',view);window.closeCount++;setOpen(false)}}/>}
            <LifecycleGate view={view} open={open}/>
          </TestScopeContext.Provider></TestSessionContext.Provider></Provider>;
        }
        createRoot(document.getElementById('root')).render(<Provider value={client}><ThemeProvider theme={createTheme()}>{lifecycleProbe?<React.StrictMode><Suspense fallback={<div data-testid="suspended">Suspended</div>}><LifecycleHarness/></Suspense></React.StrictMode>:refreshProbe?<RefreshHarness/>:<Harness/>}</ThemeProvider></Provider>);
      `,
      },
      bundle: true,
      write: false,
      define: { global: 'window', 'process.env.NODE_ENV': '"test"' },
      loader: { '.js': 'jsx' },
      plugins: [
        {
          name: 'bounded-test-providers',
          setup(builder) {
            builder.onResolve(
              {
                filter:
                  /(^|\/)(env|apollo|RequireConfig|OrganizationManagement|DetailsPage|avatars|useWidth|actions|QuerySetFavoriteButton|UserContactMethodList|UserNotificationRuleList|UserShiftsCalendar|UserEditDialog|UserContactMethodCreateDialog|UserNotificationRuleCreateDialog|UserContactMethodVerificationDialog|UserContactMethodDeleteDialog|UserNotificationRuleDeleteDialog)$/,
              },
              (args) => ({
                path: args.path.split('/').pop()!,
                namespace: 'test-provider',
              }),
            )
            builder.onLoad(
              { filter: /.*/, namespace: 'test-provider' },
              ({ path: name }) => {
                const sources: Record<string, string> = {
                  env: `export const isCypress=true,nonce='',pathPrefix='';`,
                  apollo: `export const GraphQLClient={reFetchObservableQueries(){}},GraphQLClientWithErrors=GraphQLClient;export async function refetchOrganizationQueries(){}`,
                  RequireConfig: `import {createContext,useContext} from 'react';export const TestSessionContext=createContext(null);export function useSessionInfo(){return useContext(TestSessionContext)||{userID:window.sessionUser,isAdmin:true}};export function useConfigValue(){return [true]}`,
                  OrganizationManagement: `import {createContext,useContext} from 'react';export const TestScopeContext=createContext(undefined);export function useOrganizationManagement(){const value=useContext(TestScopeContext);return value===undefined?window.scope:value}`,
                  DetailsPage: `import React from 'react';export default function View(p){return <div>{p.secondaryActions.filter(x=>x.handleOnClick).map(x=><button key={x.label} onClick={x.handleOnClick}>{x.label}</button>)}</div>}`,
                  avatars: `export function UserAvatar(){return null}`,
                  useWidth: `export function useIsWidthDown(){return false}`,
                  actions: `export function useURLParam(){return ['',()=>{}]}`,
                  QuerySetFavoriteButton: `export function QuerySetFavoriteButton(){return null}`,
                }
                return {
                  loader: 'tsx',
                  resolveDir: path.resolve(__dirname, '..'),
                  contents:
                    sources[name] ||
                    'export default function UnrelatedChild(){return null}',
                }
              },
            )
          },
        },
      ],
    })
    bundle = output.outputFiles[0].contents
    server = createServer((req, res) => {
      res.setHeader(
        'Content-Type',
        req.url === '/bundle.js' ? 'application/javascript' : 'text/html',
      )
      res.end(
        req.url === '/bundle.js'
          ? bundle
          : '<div id="root"></div><script src="/bundle.js"></script>',
      )
    })
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve))
    const address = server.address()
    if (!address || typeof address === 'string')
      throw new Error('Missing loopback listener')
    origin = 'http://127.0.0.1:' + address.port
    const runtimePath = process.env.MS_ONCALL_BROWSER_RUNTIME_WRAPPER
    if (!runtimePath)
      throw new Error('A preflighted browser runtime is required')
    const runtime: { launch: (engine: typeof chromium) => Promise<Browser> } =
      createRequire(__filename)(runtimePath)
    browser = await runtime.launch(chromium)
  }, 60000)
  afterAll(async () => {
    await browser?.close()
    if (server)
      await new Promise<void>((resolve) => server.close(() => resolve()))
  })
  type State = {
    preview: DeletionPreview
    previews: number
    deletes: Array<Record<string, unknown>>
    lists: number
    removed: boolean
    detail: 'ok' | 'null' | 'error' | 'pending'
    deletion:
      | 'success'
      | 'network'
      | 'timeout'
      | 'ambiguous'
      | '401'
      | '403'
      | 'dependency'
      | 'pending'
      | 'unavailable'
    listError: boolean
    release?: () => void
    releasePreview?: () => void
    releaseList?: () => void
    holdPreview: boolean
    paginate: boolean
    holdSuccessor: boolean
    nativeUnavailable: boolean
    holdList: boolean
    deferLists: boolean
    listResponses: Array<{
      release: () => void
      error: boolean
      operationName: string
    }>
  }
  async function setup(
    preview = userPreview(),
    probe?: string,
    configure?: (state: State) => void,
    refreshProbe = false,
    lifecycleProbe = false,
  ): Promise<{ page: Page; state: State }> {
    const page = await browser.newPage()
    const state: State = {
      preview,
      previews: 0,
      deletes: [],
      lists: 0,
      removed: false,
      detail: 'ok',
      deletion: 'success',
      listError: false,
      holdPreview: false,
      paginate: false,
      holdSuccessor: false,
      nativeUnavailable: false,
      holdList: false,
      deferLists: false,
      listResponses: [],
    }
    configure?.(state)
    const caseName = expect.getState().currentTestName
    const requests = { graphql: 0, deleteAll: 0, preview: 0, list: 0 }
    page.on('request', (request) => {
      if (!new URL(request.url()).pathname.endsWith('/api/graphql')) return
      requests.graphql++
      const query = request.postDataJSON().query as string
      if (query.includes('deleteAll')) requests.deleteAll++
      if (query.includes('deletionPreview')) requests.preview++
      if (query.includes('usersQuery')) requests.list++
    })
    page.on('close', () => {
      const evidence = process.env.MS_ONCALL_BROWSER_CASE_EVIDENCE
      if (evidence)
        appendFileSync(
          evidence,
          JSON.stringify({
            caseName,
            probe: probe || null,
            requests,
            handledDeletes: state.deletes.length,
            handledLists: state.lists,
            handledPreviews: state.previews,
          }) + '\n',
        )
    })
    await page.route('**/api/graphql', async (route) => {
      const body = route.request().postDataJSON()
      const json = (value: object, status = 200): Promise<void> =>
        route.fulfill({
          status,
          contentType: 'application/json',
          body: JSON.stringify(value),
        })
      if (body.query.includes('deletionPreview')) {
        state.previews++
        if (state.holdPreview || (state.holdSuccessor && body.variables.after))
          await new Promise<void>((resolve) => {
            state.releasePreview = resolve
          })
        const target = body.variables.input.targets[0].id
        const p = JSON.parse(
          JSON.stringify(state.preview).split(userID).join(target),
        )
        if (state.nativeUnavailable)
          return json({
            errors: [
              {
                message: 'Unavailable',
                extensions: { code: 'DELETION_UNAVAILABLE' },
              },
            ],
          })
        if (state.paginate) {
          const rows = p.impacts.edges
          const index = body.variables.after
            ? rows.findIndex(
                (e: { cursor: string }) => e.cursor === body.variables.after,
              ) + 1
            : 0
          p.impacts = {
            edges: [rows[index]],
            pageInfo: {
              endCursor: rows[index].cursor,
              hasNextPage: index + 1 < rows.length,
            },
          }
        }
        if (probe) p.targets[0].type = body.variables.input.targets[0].type
        if (probe === 'integrationKey') {
          const node = userImpact(1, {
            target: p.targets[0],
            relation: 'INTEGRATION_SOURCE',
            referencingResource: userResource(
              'SERVICE',
              '80000000-0000-4000-8000-000000000001',
            ),
            affectedResource: p.targets[0],
            isPlannedCoDeletion: false,
          })
          p.requiresConfirmation = true
          p.impacts = {
            edges: [{ cursor: 'key-source', node }],
            pageInfo: { endCursor: 'key-source', hasNextPage: false },
          }
        }
        return json({ data: { deletionPreview: p } })
      }
      if (body.query.includes('IntegrationKeyDeletionIdentity'))
        return json({
          data: {
            integrationKey: {
              id: userID,
              auditResourceID: '90000000-0000-4000-8000-000000000001',
              serviceID: '80000000-0000-4000-8000-000000000001',
              type: 'generic',
              name: 'Synthetic key',
              externalSystemName: null,
            },
          },
        })
      if (body.query.includes('deleteAll')) {
        state.deletes.push(body.variables)
        if (state.deletion === 'pending')
          await new Promise<void>((resolve) => {
            state.release = resolve
          })
        if (state.deletion === 'network') return route.abort('failed')
        if (state.deletion === 'timeout') return route.abort('timedout')
        if (state.deletion === 'ambiguous')
          return json({ data: { deleteAll: null } })
        if (state.deletion === '401' || state.deletion === '403')
          return json(
            { errors: [{ message: 'Synthetic authentication revoked' }] },
            Number(state.deletion),
          )
        if (state.deletion === 'dependency') {
          state.preview.impactVersion = 'synthetic-version-2'
          return json({
            data: { deleteAll: null },
            errors: [
              {
                message: 'Changed',
                extensions: { code: 'DELETION_DEPENDENCY_CHANGED' },
              },
            ],
          })
        }
        if (state.deletion === 'unavailable')
          return json({
            data: { deleteAll: null },
            errors: [
              {
                message: 'Unavailable',
                extensions: { code: 'DELETION_UNAVAILABLE' },
              },
            ],
          })
        state.removed = true
        return json({ data: { deleteAll: true } })
      }
      if (body.query.includes('usersQuery')) {
        state.lists++
        let responseError = state.listError
        if (state.deferLists) {
          const response = {
            release: (): void => {},
            error: state.listError,
            operationName: body.operationName as string,
          }
          await new Promise<void>((resolve) => {
            response.release = resolve
            state.listResponses.push(response)
          })
          responseError = response.error
        }
        if (state.holdList)
          await new Promise<void>((resolve) => {
            // Automatic invalidation and receipt queries may now be distinct.
            // Release every held list response, preserving the original cases.
            const previous = state.releaseList
            state.releaseList = () => {
              previous?.()
              resolve()
            }
          })
        if (state.deferLists ? responseError : state.listError)
          return json({
            errors: [{ message: 'Synthetic list access failure' }],
          })
        return json({
          data: {
            users: {
              __typename: 'UserConnection',
              nodes: state.removed
                ? []
                : [
                    {
                      __typename: 'User',
                      id: userID,
                      name: 'Synthetic user',
                      email: '',
                      isFavorite: false,
                    },
                  ],
              pageInfo: { hasNextPage: false, endCursor: null },
            },
          },
        })
      }
      if (state.detail === 'pending')
        await new Promise<void>((resolve) => {
          state.release = resolve
        })
      if (state.detail === 'error')
        return json({ errors: [{ message: 'Synthetic detail failure' }] })
      const user =
        state.detail === 'null'
          ? null
          : {
              __typename: 'User',
              id: body.variables?.id || userID,
              role: 'admin',
              name: 'Synthetic user',
              email: '',
              contactMethods: [],
              sessions: [],
              onCallOverview: { serviceCount: 0 },
            }
      return json({ data: { user } })
    })
    await page.goto(
      origin +
        '/users/' +
        userID +
        '?poll=0' +
        (refreshProbe ? '&refreshProbe=1' : '') +
        (lifecycleProbe ? '&lifecycleProbe=1' : '') +
        (probe ? '&probe=' + probe : ''),
    )
    await page.getByRole('button', { name: 'Delete', exact: true }).click()
    await page.getByRole('dialog').waitFor()
    return { page, state }
  }
  const confirm = (page: Page): import('playwright').Locator =>
    page.getByRole('button', { name: 'Confirm', exact: true })
  async function waitFor(
    test: () => boolean | Promise<boolean>,
  ): Promise<void> {
    for (let n = 0; n < 200; n++) {
      if (await test()) return
      await new Promise((resolve) => setTimeout(resolve, 10))
    }
    throw new Error('Condition did not complete')
  }
  const otherUser = '90000000-0000-4000-8000-000000000001'
  async function selectUser(page: Page, id: string): Promise<void> {
    await page.evaluate((next) => {
      ;(window as unknown as { rerender: (id: string) => void }).rerender(next)
    }, id)
    await page
      .getByTestId('selection')
      .filter({ hasText: new RegExp(`^${id}$`) })
      .waitFor()
    await waitFor(async () => !(await confirm(page).isDisabled()))
  }
  async function refreshEffects(
    page: Page,
  ): Promise<{ closes: number; navigations: number }> {
    // Wait through transport delivery, Promise continuations and React commit.
    return page.evaluate(async () => {
      await new Promise((resolve) => requestAnimationFrame(resolve))
      await new Promise((resolve) => requestAnimationFrame(resolve))
      const w = window as unknown as {
        closeCount: number
        navigationCount: number
      }
      return { closes: w.closeCount, navigations: w.navigationCount }
    })
  }
  async function releaseList(
    page: Page,
    response: State['listResponses'][number],
  ): Promise<void> {
    const received = page.waitForResponse(
      (r) =>
        r.request().postDataJSON()?.operationName === response.operationName,
    )
    response.release()
    await (await received).finished()
  }

  type LifecycleView = {
    id: string
    clientIndex: number
    organization: string | null
    actor: string
    suspend: boolean
  }
  type LifecycleEvent = {
    event: string
    id: string
    client: number
    scope: string | null
    actor: string
  }
  type LifecycleWindow = {
    lifecycleEvents: LifecycleEvent[]
    lifecycleTransition: (changes: Partial<LifecycleView>) => void
    lifecycleCommit: (changes: Partial<LifecycleView>) => void
    lifecycleAbort: () => void
    lifecycleUnmount: () => void
    lifecycleRemount: () => void
  }
  const lifecycleEvents = (page: Page): Promise<LifecycleEvent[]> =>
    page.evaluate(() => (window as unknown as LifecycleWindow).lifecycleEvents)
  async function lifecycleCommit(
    page: Page,
    changes: Partial<LifecycleView>,
  ): Promise<void> {
    await page.evaluate((value) => {
      ;(window as unknown as LifecycleWindow).lifecycleCommit(value)
    }, changes)
  }
  async function lifecycleSetup(): Promise<{ page: Page; state: State }> {
    return setup(
      userPreview(),
      undefined,
      (s) => {
        s.deferLists = true
      },
      true,
      true,
    )
  }
  async function lifecycleEvidence(page: Page, state: State): Promise<void> {
    const evidence = process.env.MS_ONCALL_BROWSER_CASE_EVIDENCE
    if (evidence)
      appendFileSync(
        evidence,
        JSON.stringify({
          caseName: expect.getState().currentTestName,
          lifecycle: await lifecycleEvents(page),
          effects: await refreshEffects(page),
          deletes: state.deletes.length,
          lists: state.lists,
        }) + '\n',
      )
  }
  const abandonedIdentities = [
    { name: 'user', changes: { id: otherUser } },
    { name: 'client', changes: { clientIndex: 1 } },
    {
      name: 'organization',
      changes: { organization: '30000000-0000-4000-8000-000000000001' },
    },
    { name: 'actor', changes: { actor: otherUser } },
  ]
  test.each(abandonedIdentities)(
    'an abandoned $name selection render cannot discard the committed user successful refresh',
    async ({ changes }) => {
      const { page, state } = await lifecycleSetup()
      try {
        await confirm(page).click()
        await waitFor(() => state.listResponses.length === 1)
        const before = (await lifecycleEvents(page)).filter(
          (e) => e.event === 'setup',
        )
        await page.evaluate((value) => {
          ;(window as unknown as LifecycleWindow).lifecycleTransition(value)
        }, changes)
        await waitFor(async () =>
          (await lifecycleEvents(page)).some((e) => e.event === 'suspend'),
        )
        expect(await page.getByTestId('selection').textContent()).toBe(userID)
        expect(await page.getByTestId('suspended').count()).toBe(0)
        expect(
          (await lifecycleEvents(page)).filter((e) => e.event === 'setup'),
        ).toEqual(before)
        await page.evaluate(() =>
          (window as unknown as LifecycleWindow).lifecycleAbort(),
        )
        const commits = (await lifecycleEvents(page)).filter(
          (e) => e.event === 'setup',
        )
        expect(commits.length).toBeGreaterThan(before.length)
        expect(
          commits.every(
            (e) =>
              e.id === userID &&
              e.client === 0 &&
              e.scope === null &&
              e.actor === userID,
          ),
        ).toBe(true)
        await releaseList(page, state.listResponses[0])
        expect(await refreshEffects(page)).toEqual({
          closes: 1,
          navigations: 1,
        })
        expect(state.deletes).toHaveLength(1)
        expect(state.lists).toBe(1)
        await lifecycleEvidence(page, state)
      } finally {
        state.listResponses.forEach((r) => r.release())
        await page.close()
      }
    },
  )
  test.each(abandonedIdentities)(
    'an abandoned $name selection render cannot discard the committed user refresh recovery',
    async ({ changes }) => {
      const { page, state } = await lifecycleSetup()
      try {
        await confirm(page).click()
        await waitFor(() => state.listResponses.length === 1)
        const before = (await lifecycleEvents(page)).filter(
          (e) => e.event === 'setup',
        )
        await page.evaluate((value) => {
          ;(window as unknown as LifecycleWindow).lifecycleTransition(value)
        }, changes)
        await waitFor(async () =>
          (await lifecycleEvents(page)).some((e) => e.event === 'suspend'),
        )
        expect(
          (await lifecycleEvents(page)).filter((e) => e.event === 'setup'),
        ).toEqual(before)
        await page.evaluate(() =>
          (window as unknown as LifecycleWindow).lifecycleAbort(),
        )
        expect(await page.getByTestId('selection').textContent()).toBe(userID)
        const commits = (await lifecycleEvents(page)).filter(
          (e) => e.event === 'setup',
        )
        expect(commits.length).toBeGreaterThan(before.length)
        expect(
          commits.every(
            (e) =>
              e.id === userID &&
              e.client === 0 &&
              e.scope === null &&
              e.actor === userID,
          ),
        ).toBe(true)
        state.listResponses[0].error = true
        await releaseList(page, state.listResponses[0])
        expect(await refreshEffects(page)).toEqual({
          closes: 0,
          navigations: 0,
        })
        expect(await page.getByRole('dialog').textContent()).toContain(
          'The user was deleted, but the user list could not be refreshed.',
        )
        await page
          .getByRole('button', { name: 'Refresh user list', exact: true })
          .click()
        await waitFor(() => state.listResponses.length === 2)
        await releaseList(page, state.listResponses[1])
        expect(await refreshEffects(page)).toEqual({
          closes: 1,
          navigations: 1,
        })
        expect(state.deletes).toHaveLength(1)
        expect(state.lists).toBe(2)
        await lifecycleEvidence(page, state)
      } finally {
        state.listResponses.forEach((r) => r.release())
        await page.close()
      }
    },
  )
  test('StrictMode repeated layout setup and cleanup retain a pending receipt for the same selection', async () => {
    const { page, state } = await lifecycleSetup()
    try {
      const initial = await lifecycleEvents(page)
      expect(
        initial.filter((e) => e.event === 'setup').length,
      ).toBeGreaterThanOrEqual(3)
      expect(
        initial.filter((e) => e.event === 'cleanup').length,
      ).toBeGreaterThanOrEqual(2)
      await confirm(page).click()
      await waitFor(() => state.listResponses.length === 1)
      for (let n = 0; n < 3; n++) await lifecycleCommit(page, {})
      const repeated = await lifecycleEvents(page)
      expect(
        repeated.filter((e) => e.event === 'cleanup').length,
      ).toBeGreaterThan(initial.filter((e) => e.event === 'cleanup').length)
      expect(
        repeated
          .filter((e) => e.event === 'setup')
          .every((e) => e.id === userID),
      ).toBe(true)
      await releaseList(page, state.listResponses[0])
      expect(await refreshEffects(page)).toEqual({ closes: 1, navigations: 1 })
      expect(state.deletes).toHaveLength(1)
      expect(state.lists).toBe(1)
      await lifecycleEvidence(page, state)
    } finally {
      state.listResponses.forEach((r) => r.release())
      await page.close()
    }
  })
  test.each(['pending', 'success', 'failure'] as const)(
    'Suspense hide and reveal retain the committed receipt with a %s list result',
    async (outcome) => {
      const { page, state } = await lifecycleSetup()
      try {
        await confirm(page).click()
        await waitFor(() => state.listResponses.length === 1)
        const cleanups = (await lifecycleEvents(page)).filter(
          (e) => e.event === 'cleanup',
        ).length
        await lifecycleCommit(page, { suspend: true })
        await page.getByTestId('suspended').waitFor()
        expect(
          (await lifecycleEvents(page)).filter((e) => e.event === 'cleanup')
            .length,
        ).toBeGreaterThan(cleanups)
        if (outcome !== 'pending') {
          state.listResponses[0].error = outcome === 'failure'
          await releaseList(page, state.listResponses[0])
          expect(await refreshEffects(page)).toEqual({
            closes: 0,
            navigations: 0,
          })
          expect(await page.getByTestId('suspended').count()).toBe(1)
        }
        await lifecycleCommit(page, { suspend: false })
        await waitFor(
          async () => (await page.getByTestId('suspended').count()) === 0,
        )
        if (outcome === 'pending')
          await releaseList(page, state.listResponses[0])
        if (outcome === 'failure') {
          expect(await refreshEffects(page)).toEqual({
            closes: 0,
            navigations: 0,
          })
          expect(await page.getByRole('dialog').textContent()).toContain(
            'The user was deleted, but the user list could not be refreshed.',
          )
          await page
            .getByRole('button', { name: 'Refresh user list', exact: true })
            .click()
          await waitFor(() => state.listResponses.length === 2)
          await releaseList(page, state.listResponses[1])
        }
        expect(await refreshEffects(page)).toEqual({
          closes: 1,
          navigations: 1,
        })
        expect(state.deletes).toHaveLength(1)
        expect(state.lists).toBe(outcome === 'failure' ? 2 : 1)
        await lifecycleEvidence(page, state)
      } finally {
        state.listResponses.forEach((r) => r.release())
        await page.close()
      }
    },
  )
  test.each(['success', 'failure'] as const)(
    'an actually unmounted dialog cannot affect a new instance after its old list %s',
    async (outcome) => {
      const { page, state } = await lifecycleSetup()
      try {
        await confirm(page).click()
        await waitFor(() => state.listResponses.length === 1)
        await page.evaluate(() =>
          (window as unknown as LifecycleWindow).lifecycleUnmount(),
        )
        expect(await page.getByRole('dialog').count()).toBe(0)
        await page.evaluate(() =>
          (window as unknown as LifecycleWindow).lifecycleRemount(),
        )
        await waitFor(async () => !(await confirm(page).isDisabled()))
        state.listResponses[0].error = outcome === 'failure'
        await releaseList(page, state.listResponses[0])
        expect(await refreshEffects(page)).toEqual({
          closes: 0,
          navigations: 0,
        })
        expect(
          await page
            .getByRole('button', { name: 'Refresh user list', exact: true })
            .count(),
        ).toBe(0)
        expect(await confirm(page).isDisabled()).toBe(false)
        await confirm(page).click()
        await waitFor(() => state.listResponses.length === 2)
        await releaseList(page, state.listResponses[1])
        expect(await refreshEffects(page)).toEqual({
          closes: 1,
          navigations: 1,
        })
        expect(state.deletes).toHaveLength(2)
        expect(state.lists).toBe(2)
        await lifecycleEvidence(page, state)
      } finally {
        state.listResponses.forEach((r) => r.release())
        await page.close()
      }
    },
  )

  test('a pending refresh for user A cannot suppress user B successful refresh', async () => {
    const { page, state } = await setup(
      userPreview(),
      undefined,
      (s) => {
        s.deferLists = true
      },
      true,
    )
    try {
      await confirm(page).click()
      await waitFor(() => state.listResponses.length === 1)
      await selectUser(page, otherUser)
      await confirm(page).click()
      // B must physically issue its own query while A is still unresolved.
      await waitFor(() => state.listResponses.length === 2)
      expect(state.lists).toBe(2)
      expect(state.listResponses[1].operationName).not.toBe(
        state.listResponses[0].operationName,
      )
      expect(state.deletes.map((d) => d.input)).toEqual([
        [{ type: 'user', id: userID }],
        [{ type: 'user', id: otherUser }],
      ])
      await releaseList(page, state.listResponses[1])
      await page.getByRole('dialog').waitFor({ state: 'hidden' })
      expect(await page.getByTestId('path').textContent()).toBe('/users')
      expect(await refreshEffects(page)).toEqual({ closes: 1, navigations: 1 })
      await releaseList(page, state.listResponses[0])
      expect(await refreshEffects(page)).toEqual({ closes: 1, navigations: 1 })
      expect(state.deletes).toHaveLength(2)
      expect(state.lists).toBe(2)
    } finally {
      state.listResponses.forEach((r) => r.release())
      await page.close()
    }
  }, 20000)
  test('an old A refresh cannot affect a new dialog after A to B to A selection', async () => {
    const { page, state } = await setup(
      userPreview(),
      undefined,
      (s) => {
        s.deferLists = true
      },
      true,
    )
    try {
      await confirm(page).click()
      await waitFor(() => state.listResponses.length === 1)
      await selectUser(page, otherUser)
      await selectUser(page, userID)
      expect(state.previews).toBe(3)
      // Exercise F02 independently of F01: the new A is still reviewing.
      await releaseList(page, state.listResponses[0])
      expect(await refreshEffects(page)).toEqual({ closes: 0, navigations: 0 })
      expect(await page.getByRole('dialog').count()).toBe(1)
      expect(await confirm(page).isDisabled()).toBe(false)
      // A new authoritative receipt has its own failed-list recovery state.
      await confirm(page).click()
      await waitFor(() => state.listResponses.length === 2)
      state.listResponses[1].error = true
      await releaseList(page, state.listResponses[1])
      const retry = page.getByRole('button', {
        name: 'Refresh user list',
        exact: true,
      })
      await retry.waitFor()
      await retry.click()
      await waitFor(() => state.listResponses.length === 3)
      expect(await refreshEffects(page)).toEqual({ closes: 0, navigations: 0 })
      expect(await page.getByRole('dialog').count()).toBe(1)
      expect(await retry.count()).toBe(0)
      state.listResponses[2].error = true
      await releaseList(page, state.listResponses[2])
      await retry.waitFor()
      expect(await confirm(page).isDisabled()).toBe(true)
      // Repeated synchronous recovery clicks send only one list query.
      await retry.evaluate((button) => {
        if (!(button instanceof HTMLButtonElement))
          throw new Error('Expected a button')
        button.click()
        button.click()
        button.click()
      })
      await waitFor(() => state.listResponses.length === 4)
      await releaseList(page, state.listResponses[3])
      await page.getByRole('dialog').waitFor({ state: 'hidden' })
      expect(await refreshEffects(page)).toEqual({ closes: 1, navigations: 1 })
      expect(state.deletes).toHaveLength(2)
      expect(state.deletes.map((d) => d.input)).toEqual([
        [{ type: 'user', id: userID }],
        [{ type: 'user', id: userID }],
      ])
      expect(state.lists).toBe(4)
      expect(
        new Set(state.listResponses.map((r) => r.operationName)).size,
      ).toBe(4)
    } finally {
      state.listResponses.forEach((r) => r.release())
      await page.close()
    }
  }, 20000)
  test.each(['success', 'failure'] as const)(
    'old A refresh %s and finally cannot change the new A pending receipt',
    async (outcome) => {
      const { page, state } = await setup(
        userPreview(),
        undefined,
        (s) => {
          s.deferLists = true
        },
        true,
      )
      try {
        await confirm(page).click()
        await waitFor(() => state.listResponses.length === 1)
        await selectUser(page, otherUser)
        await selectUser(page, userID)
        await confirm(page).click()
        await waitFor(() => state.listResponses.length === 2)
        state.listResponses[0].error = outcome === 'failure'
        await releaseList(page, state.listResponses[0])
        expect(await refreshEffects(page)).toEqual({
          closes: 0,
          navigations: 0,
        })
        expect(await page.getByRole('dialog').count()).toBe(1)
        const retry = page.getByRole('button', {
          name: 'Refresh user list',
          exact: true,
        })
        expect(await retry.count()).toBe(0)
        expect(await confirm(page).isDisabled()).toBe(true)
        state.listResponses[1].error = true
        await releaseList(page, state.listResponses[1])
        await retry.waitFor()
        await retry.click()
        await waitFor(() => state.listResponses.length === 3)
        await releaseList(page, state.listResponses[2])
        await page.getByRole('dialog').waitFor({ state: 'hidden' })
        expect(await refreshEffects(page)).toEqual({
          closes: 1,
          navigations: 1,
        })
        expect(state.deletes).toHaveLength(2)
        expect(state.lists).toBe(3)
      } finally {
        state.listResponses.forEach((r) => r.release())
        await page.close()
      }
    },
    20000,
  )
  test.each(['client', 'organization', 'actor'] as const)(
    'old refresh error stays invalid after %s identity changes and returns',
    async (identity) => {
      const { page, state } = await setup(
        userPreview(),
        undefined,
        (s) => {
          s.deferLists = true
        },
        true,
      )
      try {
        await confirm(page).click()
        await waitFor(() => state.listResponses.length === 1)
        for (const restore of [false, true]) {
          await page.evaluate(
            ({ identity, restore, actor }) => {
              const w = window as unknown as {
                activeClient: unknown
                refreshClients: unknown[]
                sessionUser: string
                rerender: (id: null, scope?: object | null) => void
              }
              if (identity === 'client')
                w.activeClient = w.refreshClients[restore ? 0 : 1]
              if (identity === 'actor')
                w.sessionUser = restore
                  ? actor
                  : '90000000-0000-4000-8000-000000000001'
              w.rerender(
                null,
                identity === 'organization'
                  ? restore
                    ? null
                    : {
                        identity: { userID: actor },
                        target: { id: '90000000-0000-4000-8000-000000000002' },
                        lock: () => () => {},
                      }
                  : undefined,
              )
            },
            { identity, restore, actor: userID },
          )
          await waitFor(() => state.previews >= (restore ? 3 : 2))
        }
        await waitFor(async () => !(await confirm(page).isDisabled()))
        state.listResponses[0].error = true
        await releaseList(page, state.listResponses[0])
        expect(await refreshEffects(page)).toEqual({
          closes: 0,
          navigations: 0,
        })
        expect(await confirm(page).isDisabled()).toBe(false)
        expect(
          await page
            .getByRole('button', { name: 'Refresh user list', exact: true })
            .count(),
        ).toBe(0)
        await confirm(page).click()
        await waitFor(() => state.listResponses.length === 2)
        await releaseList(page, state.listResponses[1])
        await page.getByRole('dialog').waitFor({ state: 'hidden' })
        expect(await refreshEffects(page)).toEqual({
          closes: 1,
          navigations: 1,
        })
        expect(state.deletes).toHaveLength(2)
      } finally {
        state.listResponses.forEach((r) => r.release())
        await page.close()
      }
    },
    20000,
  )
  test.each([
    'user',
    'escalationPolicy',
    'schedule',
    'rotation',
    'notificationRule',
    'userOverride',
    'contactMethod',
    'service',
    'integrationKey',
  ])(
    'real shared Hook for %s synchronously interlocks repeated callbacks before a React update',
    async (type) => {
      const { page, state } = await setup(userPreview(), type)
      try {
        await confirm(page).waitFor()
        if (type === 'integrationKey') await page.getByRole('checkbox').check()
        await waitFor(async () => !(await confirm(page).isDisabled()))
        state.deletion = 'pending'
        await page.evaluate(() => {
          ;(window as unknown as { confirmMany: () => void }).confirmMany()
        })
        await waitFor(() => state.deletes.length === 1)
        expect(state.deletes[0].input).toEqual([{ type, id: userID }])
        expect(await confirm(page).isDisabled()).toBe(true)
        state.deletion = 'network'
        state.release!()
        await page
          .getByText('The deletion result is unconfirmed.', { exact: false })
          .waitFor()
        await page.evaluate(() => {
          ;(window as unknown as { confirmMany: () => void }).confirmMany()
        })
        expect(state.deletes).toHaveLength(1)
      } finally {
        state.release?.()
        await page.close()
      }
    },
    20000,
  )
  test('authoritative success invalidates User and refreshes actual User List Query before /users navigation', async () => {
    const { page, state } = await setup()
    try {
      await confirm(page).waitFor({ state: 'visible' })
      await confirm(page).click()
      await page
        .getByTestId('path')
        .filter({ hasText: /^\/users$/ })
        .waitFor()
      expect(state.deletes).toHaveLength(1)
      expect(state.deletes[0]).toEqual({
        input: [{ type: 'user', id: userID }],
        confirmation: {
          expectedImpactVersion: 'synthetic-user-version-1',
          acknowledgeImpacts: false,
        },
      })
      expect(state.lists).toBeGreaterThan(1)
      expect(await page.getByTestId('list').textContent()).not.toContain(userID)
    } finally {
      await page.close()
    }
  }, 20000)
  test('CASCADE and WARNING require acknowledgement; INFORMATIONAL explains only', async () => {
    const { page, state } = await setup(userOwnedPreview())
    try {
      await page
        .getByRole('heading', { name: 'CASCADE', exact: true })
        .waitFor()
      expect(await confirm(page).isDisabled()).toBe(true)
      expect(await page.getByRole('dialog').textContent()).toContain(
        'Affected resource:',
      )
      await page.getByRole('checkbox').check()
      state.deletion = 'unavailable'
      await confirm(page).click()
      await page
        .getByText('Deletion is unavailable.', { exact: false })
        .waitFor()
      expect(await confirm(page).isDisabled()).toBe(true)
      expect(state.deletes).toHaveLength(1)
    } finally {
      await page.close()
    }
  }, 20000)
  test('BLOCK Parent/Owner explanations remain distinct and cannot be acknowledged away', async () => {
    const { page, state } = await setup(userActionPreview())
    try {
      await page.getByText('Deletion is blocked.', { exact: false }).waitFor()
      expect(await page.getByRole('dialog').textContent()).toContain('Parent:')
      expect(await page.getByRole('dialog').textContent()).toContain('Owner:')
      expect(await confirm(page).isDisabled()).toBe(true)
      expect(await page.getByRole('checkbox').count()).toBe(0)
      expect(state.deletes).toHaveLength(0)
    } finally {
      await page.close()
    }
  }, 20000)
  test.each(['network', 'timeout', 'ambiguous', '401', '403'] as const)(
    'self-delete %s keeps COMMIT_UNKNOWN across close, reopen and tab reload; no retry',
    async (failure) => {
      const { page, state } = await setup()
      try {
        state.deletion = failure
        expect(await page.getByRole('dialog').textContent()).toContain(
          'current login session may become invalid',
        )
        await confirm(page).click()
        await page
          .getByText('The deletion result is unconfirmed.', { exact: false })
          .waitFor()
        expect(await confirm(page).isDisabled()).toBe(true)
        expect(state.deletes).toHaveLength(1)
        const count = state.previews
        await page.getByRole('button', { name: 'Close', exact: true }).click()
        await page.getByRole('button', { name: 'Delete', exact: true }).click()
        await page
          .getByText('The deletion result is unconfirmed.', { exact: false })
          .waitFor()
        await page.reload()
        await page.getByRole('button', { name: 'Delete', exact: true }).click()
        await page
          .getByText('The deletion result is unconfirmed.', { exact: false })
          .waitFor()
        expect(state.previews).toBe(count)
        expect(state.deletes).toHaveLength(1)
        expect(await page.getByTestId('path').textContent()).toContain(userID)
      } finally {
        await page.close()
      }
    },
    20000,
  )
  test('synchronous repeated click/Enter callback while pending sends one mutation and cannot close', async () => {
    const { page, state } = await setup()
    try {
      state.deletion = 'pending'
      await confirm(page).evaluate((button: HTMLButtonElement) => {
        button.click()
        button.click()
        button.dispatchEvent(
          new KeyboardEvent('keydown', { key: 'Enter', bubbles: true }),
        )
      })
      await waitFor(() => state.deletes.length === 1)
      expect(await confirm(page).isDisabled()).toBe(true)
      expect(
        await page
          .getByRole('button', { name: 'Cancel', exact: true })
          .isDisabled(),
      ).toBe(true)
      await page.keyboard.press('Escape')
      expect(await page.getByRole('dialog').count()).toBe(1)
      state.deletion = 'network'
      state.release!()
      await page
        .getByText('The deletion result is unconfirmed.', { exact: false })
        .waitFor()
      expect(state.deletes).toHaveLength(1)
    } finally {
      state.release?.()
      await page.close()
    }
  }, 20000)
  test('DEPENDENCY_CHANGED discards confirmation, reloads full preview, and requires a new click', async () => {
    const { page, state } = await setup(userOwnedPreview())
    try {
      await page.getByRole('checkbox').check()
      state.deletion = 'dependency'
      await confirm(page).click()
      await page
        .getByText('Dependencies or confirmation requirements changed.', {
          exact: false,
        })
        .waitFor()
      await page.getByRole('checkbox').waitFor()
      expect(await page.getByRole('checkbox').isChecked()).toBe(false)
      expect(await confirm(page).isDisabled()).toBe(true)
      expect(state.previews).toBe(2)
      expect(state.deletes).toHaveLength(1)
      state.deletion = 'success'
      await page.getByRole('checkbox').check()
      await confirm(page).click()
      await page
        .getByTestId('path')
        .filter({ hasText: /^\/users$/ })
        .waitFor()
      expect(state.deletes).toHaveLength(2)
      expect(state.deletes[1].confirmation).toEqual({
        expectedImpactVersion: 'synthetic-version-2',
        acknowledgeImpacts: true,
      })
    } finally {
      await page.close()
    }
  }, 20000)
  test.each(['null', 'error', 'pending'] as const)(
    'UserDetails keeps the same dialog slot during User %s',
    async (detail) => {
      const { page, state } = await setup()
      try {
        await confirm(page).waitFor()
        await page.getByRole('dialog').evaluate((dialog) => {
          ;(window as unknown as { originalDialog: Element }).originalDialog =
            dialog
        })
        state.detail = detail
        await page.evaluate(() => {
          ;(
            window as unknown as { refetchAll: (force: boolean) => void }
          ).refetchAll(true)
        })
        if (detail === 'pending') await waitFor(() => !!state.release)
        else if (detail === 'null')
          await page
            .getByText('Someone may have deleted it, or it never existed.', {
              exact: true,
            })
            .waitFor()
        else
          await page
            .getByText('Sorry, an error occurred.', { exact: true })
            .waitFor()
        expect(
          await page
            .getByRole('dialog')
            .evaluate(
              (dialog) =>
                (window as unknown as { originalDialog: Element })
                  .originalDialog === dialog,
            ),
        ).toBe(true)
        expect(state.deletes).toHaveLength(0)
      } finally {
        state.release?.()
        await page.close()
      }
    },
    20000,
  )
  test('User switch invalidates old acknowledgement and ignores the old preview response', async () => {
    const { page, state } = await setup(userOwnedPreview())
    try {
      await page.getByRole('checkbox').check()
      state.holdPreview = true
      await page
        .getByRole('button', { name: 'Check again', exact: true })
        .click()
      await waitFor(() => !!state.releasePreview)
      const old = state.releasePreview!
      state.holdPreview = false
      const next = '90000000-0000-4000-8000-000000000001'
      await page.evaluate((id) => {
        ;(window as unknown as { rerender: (id: string) => void }).rerender(id)
      }, next)
      await page.getByRole('checkbox').waitFor()
      expect(await page.getByRole('checkbox').isChecked()).toBe(false)
      old()
      await page.getByRole('checkbox').check()
      state.deletion = 'unavailable'
      await confirm(page).click()
      await waitFor(() => state.deletes.length === 1)
      expect(state.deletes[0].input).toEqual([{ type: 'user', id: next }])
    } finally {
      state.releasePreview?.()
      await page.close()
    }
  }, 20000)
  test('organization scope change invalidates acknowledgement and rechecks current identity', async () => {
    const { page, state } = await setup(userOwnedPreview())
    try {
      await page.getByRole('checkbox').check()
      const newOrg = '90000000-0000-4000-8000-000000000001'
      await page.evaluate((id) => {
        ;(
          window as unknown as { rerender: (id: null, scope: object) => void }
        ).rerender(null, {
          identity: { userID: 'actor' },
          target: { id },
          lock: () => () => {},
        })
      }, newOrg)
      await page
        .getByText('Deletion is unavailable.', { exact: false })
        .waitFor()
      expect(await confirm(page).isDisabled()).toBe(true)
      expect(await page.getByRole('checkbox').count()).toBe(0)
      expect(state.deletes).toHaveLength(0)
      expect(state.previews).toBe(2)
    } finally {
      await page.close()
    }
  }, 20000)
  test('list refresh error after authoritative success retries only the list, never DeleteAll', async () => {
    const { page, state } = await setup()
    try {
      state.listError = true
      await confirm(page).click()
      await page
        .getByRole('button', { name: 'Refresh user list', exact: true })
        .waitFor()
      expect(await page.getByTestId('path').textContent()).toContain(userID)
      expect(state.deletes).toHaveLength(1)
      state.listError = false
      await page
        .getByRole('button', { name: 'Refresh user list', exact: true })
        .click()
      await page
        .getByTestId('path')
        .filter({ hasText: /^\/users$/ })
        .waitFor()
      expect(state.deletes).toHaveLength(1)
    } finally {
      await page.close()
    }
  }, 20000)
  test.each(['throw', 'lost'] as const)(
    'sessionStorage %s write fails closed before the physical mutation',
    async (mode) => {
      const { page, state } = await setup()
      try {
        await waitFor(async () => !(await confirm(page).isDisabled()))
        await page.evaluate((failure) => {
          Storage.prototype.setItem = () => {
            if (failure === 'throw') throw new Error('Synthetic storage denial')
          }
        }, mode)
        await confirm(page).click()
        await page
          .getByText('No deletion request was sent.', { exact: false })
          .waitFor()
        expect(state.deletes).toHaveLength(0)
        expect(await confirm(page).isDisabled()).toBe(true)
      } finally {
        await page.close()
      }
    },
    20000,
  )
  test('all pages and cross-page causes finish before review becomes available', async () => {
    const preview = userActionPreview()
    preview.impacts.edges.reverse()
    const { page, state } = await setup(preview, undefined, (s) => {
      s.paginate = true
      s.holdSuccessor = true
    })
    try {
      await waitFor(() => !!state.releasePreview)
      expect(await confirm(page).isDisabled()).toBe(true)
      expect(await page.getByRole('checkbox').count()).toBe(0)
      state.holdSuccessor = false
      state.releasePreview!()
      await page
        .getByText('3 relationships reviewed.', { exact: true })
        .waitFor()
      await page.getByText('Deletion is blocked.', { exact: false }).waitFor()
      expect(state.previews).toBe(3)
      expect(state.deletes).toHaveLength(0)
      expect(await confirm(page).isDisabled()).toBe(true)
    } finally {
      state.releasePreview?.()
      await page.close()
    }
  }, 20000)
  test('native preview UNAVAILABLE fails closed without a fallback mutation', async () => {
    const { page, state } = await setup(userPreview(), undefined, (s) => {
      s.nativeUnavailable = true
    })
    try {
      await page
        .getByText('Deletion is unavailable.', { exact: false })
        .waitFor()
      expect(await confirm(page).isDisabled()).toBe(true)
      expect(state.deletes).toHaveLength(0)
    } finally {
      await page.close()
    }
  }, 20000)
  test('late mutation success for the previous User cannot navigate the new selection', async () => {
    const { page, state } = await setup()
    try {
      state.deletion = 'pending'
      await confirm(page).click()
      await waitFor(() => !!state.release)
      await page.evaluate(() => {
        ;(window as unknown as { rerender: (id: string) => void }).rerender(
          '90000000-0000-4000-8000-000000000001',
        )
      })
      await waitFor(async () => !(await confirm(page).isDisabled()))
      const response = page.waitForResponse(
        (r) => r.request().postData()?.includes('deleteAll') === true,
      )
      state.deletion = 'success'
      state.release!()
      await response
      await page.waitForFunction(() =>
        document
          .querySelector('[data-testid="list"]')
          ?.textContent?.includes('"nodes":[]'),
      )
      expect(await page.getByTestId('path').textContent()).toContain(userID)
      expect(await confirm(page).isDisabled()).toBe(false)
      expect(state.deletes).toHaveLength(1)
    } finally {
      state.release?.()
      await page.close()
    }
  }, 20000)
  test.each(['user', 'actor'] as const)(
    'late successful list refresh cannot navigate after %s changes',
    async (change) => {
      const { page, state } = await setup()
      try {
        state.holdList = true
        await confirm(page).click()
        await waitFor(() => !!state.releaseList)
        await page.evaluate((kind) => {
          const w = window as unknown as {
            sessionUser: string
            rerender: (id: string | null) => void
          }
          const next = '90000000-0000-4000-8000-000000000001'
          if (kind === 'actor') w.sessionUser = next
          w.rerender(kind === 'user' ? next : null)
        }, change)
        await waitFor(async () => !(await confirm(page).isDisabled()))
        state.holdList = false
        state.releaseList!()
        await page.waitForFunction(() =>
          document
            .querySelector('[data-testid="list"]')
            ?.textContent?.includes('"nodes":[]'),
        )
        expect(await page.getByTestId('path').textContent()).toContain(userID)
        expect(state.deletes).toHaveLength(1)
      } finally {
        state.releaseList?.()
        await page.close()
      }
    },
    20000,
  )
  test('unknown User A does not contaminate User B and survives switching back', async () => {
    const { page, state } = await setup()
    try {
      state.deletion = 'network'
      await confirm(page).click()
      await page
        .getByText('The deletion result is unconfirmed.', { exact: false })
        .waitFor()
      const next = '90000000-0000-4000-8000-000000000001'
      await page.evaluate((id) => {
        ;(window as unknown as { rerender: (id: string) => void }).rerender(id)
      }, next)
      await waitFor(async () => !(await confirm(page).isDisabled()))
      expect(state.previews).toBe(2)
      await page.evaluate((id) => {
        ;(window as unknown as { rerender: (id: string) => void }).rerender(id)
      }, userID)
      await page
        .getByText('The deletion result is unconfirmed.', { exact: false })
        .waitFor()
      expect(state.previews).toBe(2)
      expect(state.deletes).toHaveLength(1)
    } finally {
      await page.close()
    }
  }, 20000)
  test('authentication identity switch discards the old confirmation and stale preview', async () => {
    const { page, state } = await setup(userOwnedPreview())
    try {
      await page.getByRole('checkbox').check()
      state.holdPreview = true
      await page
        .getByRole('button', { name: 'Check again', exact: true })
        .click()
      await waitFor(() => !!state.releasePreview)
      const old = state.releasePreview!
      state.holdPreview = false
      await page.evaluate(() => {
        const w = window as unknown as {
          sessionUser: string
          rerender: (id: null) => void
        }
        w.sessionUser = '90000000-0000-4000-8000-000000000001'
        w.rerender(null)
      })
      await page.getByRole('checkbox').waitFor()
      expect(await page.getByRole('checkbox').isChecked()).toBe(false)
      old()
      expect(await confirm(page).isDisabled()).toBe(true)
      expect(state.previews).toBe(3)
      expect(state.deletes).toHaveLength(0)
    } finally {
      state.releasePreview?.()
      await page.close()
    }
  }, 20000)
  test('session revocation and organization switch preserve the unresolved sent marker', async () => {
    const { page, state } = await setup()
    try {
      state.deletion = '401'
      await confirm(page).click()
      await page
        .getByText('The deletion result is unconfirmed.', { exact: false })
        .waitFor()
      await page.evaluate(() => {
        const w = window as unknown as {
          sessionUser: string
          rerender: (id: null, scope: object) => void
        }
        w.sessionUser = ''
        w.rerender(null, {
          identity: { userID: '90000000-0000-4000-8000-000000000001' },
          target: { id: '90000000-0000-4000-8000-000000000002' },
          lock: () => () => {},
        })
      })
      await page
        .getByText('The deletion result is unconfirmed.', { exact: false })
        .waitFor()
      expect(await confirm(page).isDisabled()).toBe(true)
      expect(state.deletes).toHaveLength(1)
      expect(state.previews).toBe(1)
      const saved = await page.evaluate(() => Object.entries(sessionStorage))
      expect(saved).toEqual([['user-deletion-unresolved:' + userID, 'sent']])
    } finally {
      await page.close()
    }
  }, 20000)
})
