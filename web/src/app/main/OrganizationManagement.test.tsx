// Browser tests of the real provider and both real clients, using a synthetic
// HTTP transport. Signed-session PostgreSQL authorization is tested separately.
import { createServer, Server } from 'node:http'
import { build } from 'esbuild'
import { chromium, Browser, Page } from 'playwright'
import path from 'node:path'
import { mkdir, writeFile } from 'node:fs/promises'

const browserTest =
  process.env.MS_ONCALL_ORGANIZATION_BROWSER_TEST_ENABLE === '1'
    ? describe
    : describe.skip

browserTest('organization management browser boundary', () => {
  let browser: Browser
  let server: Server
  let origin: string
  let bundle: Uint8Array
  let evidenceID = 0
  const requests = new Map<Page, unknown[]>()
  const orgs = ['A', 'B', 'C'].map((id) => ({ id, displayName: 'Org ' + id }))

  beforeAll(async () => {
    const result = await build({
      stdin: {
        resolveDir: path.resolve(__dirname, '..'),
        loader: 'tsx',
        contents: `
          import React, {Suspense,useState} from 'react';
          import {createRoot} from 'react-dom/client';
          import {Provider as ReduxProvider} from 'react-redux';
          import {Provider,useQuery,useMutation,gql} from 'urql';
          import {useQuery as useApolloQuery,gql as agql} from '@apollo/client';
          import {useLocation} from 'wouter';
          import reduxStore from './reduxStore';
          import {client} from './urql';
          import Management,{OrganizationControls,useOrganizationManagement,useCreateTarget} from './main/OrganizationManagement';
          const queryContext={suspense:false};
          function SuspendedConfig(){const [r]=useQuery({query:gql\`{config{id}}\`});return <span data-testid="suspended-config">{JSON.stringify(r.data)}</span>;}
          function Create(){
            const target=useCreateTarget();
            const [result,mutate]=useMutation(gql\`mutation($input:CreateScheduleInput!){createSchedule(input:$input){id organization{id}}}\`);
            const submit=()=>target.submit(()=>mutate({input:{name:'Synthetic',timeZone:'Asia/Shanghai',targetOrganizationID:target.targetOrganizationID,favorite:target.favorite}}));
            return <div data-testid="dialog"><span>{target.targetName}</span><button onClick={()=>{submit();submit()}}>Submit twice</button><span data-testid="uncertain">{String(target.uncertain)}</span></div>;
          }
          function View(){
            const scope=useOrganizationManagement();const [loc,navigate]=useLocation();const [open,setOpen]=useState(false);
            const target=scope.target.id;
            const [u]=useQuery({query:gql\`query($target:ID){services(input:{targetOrganizationID:$target}){nodes{id name}}}\`,variables:{target},context:queryContext});
            const a=useApolloQuery(agql\`query($target:ID){schedules(input:{targetOrganizationID:$target}){nodes{id name}}}\`,{variables:{target},pollInterval:100});
            return <div><SuspendedConfig/><OrganizationControls/><div data-testid="target">{target}</div><div data-testid="urql">{JSON.stringify(u.data)}</div><div data-testid="apollo">{JSON.stringify(a.data)}</div><button onClick={()=>navigate('/services?org=B')}>Go B</button><button onClick={()=>navigate('/services?org=C')}>Go C</button><button onClick={()=>setOpen(true)}>Open create</button>{open&&<Create/>}<div data-testid="path">{loc}</div></div>;
          }
          createRoot(document.getElementById('root')).render(<ReduxProvider store={reduxStore}><Provider value={client}><Suspense fallback={<div>Loading</div>}><Management><View/></Management></Suspense></Provider></ReduxProvider>);
        `,
      },
      bundle: true,
      write: false,
      define: { global: 'window', 'process.env.NODE_ENV': '"test"' },
      loader: { '.js': 'jsx' },
    })
    bundle = result.outputFiles[0].contents
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
      throw new Error('missing loopback listener')
    origin = 'http://127.0.0.1:' + address.port
    browser = await chromium.launch({ headless: true })
  }, 60000)

  afterAll(async () => {
    await browser?.close()
    if (server)
      await new Promise<void>((resolve) => server.close(() => resolve()))
  })

  async function setup(mode = 'normal'): Promise<{
    page: Page
    state: {
      pa: boolean
      delayB: boolean
      failCreate: boolean
      creates: number
    }
  }> {
    const page = await browser.newPage()
    requests.set(page, [])
    if (process.env.MS_ONCALL_ORGANIZATION_BROWSER_EVIDENCE)
      await page.context().tracing.start({ screenshots: true, snapshots: true })
    const state = {
      pa: mode !== 'ordinary' && mode !== 'restricted',
      delayB: false,
      failCreate: false,
      creates: 0,
    }
    const home = mode === 'default' || mode === 'restricted' ? 'Default' : 'A'
    await page.route('**/api/graphql', async (route) => {
      const { query, variables } = route.request().postDataJSON()
      requests.get(page)?.push({ query, variables })
      let data: unknown
      if (query.includes('currentOrganizationContext'))
        data = {
          currentOrganizationContext: {
            userID: 'synthetic-actor',
            homeOrganization: { id: home, displayName: 'Org ' + home },
            homeClassification: home === 'Default' ? 'DEFAULT' : 'NORMAL',
            homeOrgRole: home === 'Default' ? 'NONE' : 'ORG_MEMBER',
            isPlatformAdmin: state.pa,
            canCreateGlobalRoots: state.pa,
          },
        }
      else if (query.includes('manageableOrganizations')) {
        if (!state.pa)
          return route.fulfill({
            json: { errors: [{ message: 'access denied' }], data: null },
          })
        data = {
          manageableOrganizations: {
            nodes: orgs,
            pageInfo: { hasNextPage: false, endCursor: null },
          },
        }
      } else if (query.includes('config')) {
        data = { config: [{ id: 'synthetic-config' }] }
      } else if (query.includes('createSchedule')) {
        state.creates++
        if (state.failCreate) return route.abort('connectionreset')
        data = {
          createSchedule: {
            id: 'synthetic-created',
            organization: { id: variables.input.targetOrganizationID },
          },
        }
      } else if (query.includes('root:'))
        data = { root: { id: variables.id, organization: orgs[1] } }
      else {
        const target = variables.target
        if (target === 'B' && state.delayB)
          await new Promise((resolve) => setTimeout(resolve, 300))
        const field = query.includes('schedules') ? 'schedules' : 'services'
        data = {
          [field]: {
            nodes: [
              {
                __typename: field === 'services' ? 'Service' : 'Schedule',
                id: target + '-' + field,
                name: 'Only ' + target,
              },
            ],
          },
        }
      }
      return route.fulfill({ json: { data } })
    })
    return { page, state }
  }

  async function finish(page: Page): Promise<void> {
    try {
      const dir = process.env.MS_ONCALL_ORGANIZATION_BROWSER_EVIDENCE
      if (dir) {
        await mkdir(dir, { recursive: true })
        const prefix = path.join(dir, String(++evidenceID))
        await page.screenshot({ path: prefix + '.png', fullPage: true })
        await page.context().tracing.stop({ path: prefix + '.trace.zip' })
        await writeFile(
          prefix + '.requests.json',
          JSON.stringify(requests.get(page), null, 2),
        )
      }
    } finally {
      requests.delete(page)
      await page.close()
    }
  }

  async function target(page: Page, id: string): Promise<void> {
    await page.waitForFunction(
      (value) =>
        document.querySelector('[data-testid="target"]')?.textContent === value,
      id,
    )
    await page.waitForFunction(
      (value) =>
        document
          .querySelector('[data-testid="urql"]')
          ?.textContent?.includes('Only ' + value) &&
        document
          .querySelector('[data-testid="apollo"]')
          ?.textContent?.includes('Only ' + value),
      id,
    )
    await page.waitForFunction(() =>
      document
        .querySelector('[data-testid="suspended-config"]')
        ?.textContent?.includes('synthetic-config'),
    )
  }

  test('independent tabs, refresh, Back/Forward and both caches', async () => {
    const { page } = await setup()
    const { page: other } = await setup()
    try {
      await page.goto(origin + '/services?org=B&poll=0')
      await other.goto(origin + '/services?org=C&poll=0')
      await target(page, 'B')
      await target(other, 'C')
      await page.getByText('Go C', { exact: true }).click()
      await target(page, 'C')
      await page.goBack()
      await target(page, 'B')
      await page.goForward()
      await target(page, 'C')
      await page.reload()
      await target(page, 'C')
      await target(other, 'C')
    } finally {
      await finish(page)
      await finish(other)
    }
  }, 30000)

  test('Default PA landing and ordinary identity boundaries', async () => {
    for (const mode of ['default', 'ordinary', 'restricted']) {
      const { page } = await setup(mode)
      try {
        await page.goto(origin + '/?poll=0')
        if (mode === 'default') {
          await page
            .getByText('Select a Normal organization to manage.')
            .waitFor()
          expect(await page.getByRole('combobox').count()).toBe(1)
          expect(await page.locator('[data-testid="target"]').count()).toBe(0)
        } else {
          await page.getByText('PlatformAdmin:', { exact: false }).waitFor()
          expect(await page.getByRole('combobox').count()).toBe(0)
          if (mode === 'ordinary') await target(page, 'A')
          else
            expect(await page.locator('[data-testid="target"]').count()).toBe(0)
        }
      } finally {
        await finish(page)
      }
    }
  }, 30000)

  test('actual detail target overrides URL locator', async () => {
    const { page } = await setup()
    try {
      await page.goto(origin + '/services/root-b?org=C&poll=0')
      await target(page, 'B')
      expect(new URL(page.url()).searchParams.get('org')).toBe('B')
    } finally {
      await finish(page)
    }
  }, 15000)

  test('dialog holds target, duplicate click and network uncertainty do not replay Create', async () => {
    const { page, state } = await setup()
    try {
      await page.goto(origin + '/services?org=B&poll=0')
      await target(page, 'B')
      await page.getByText('Open create', { exact: true }).click()
      await page.getByText('Go C', { exact: true }).click()
      await target(page, 'B')
      state.failCreate = true
      await page.getByText('Submit twice', { exact: true }).click()
      await page.waitForFunction(
        () =>
          document.querySelector('[data-testid="uncertain"]')?.textContent ===
          'true',
      )
      await page.getByText('Submit twice', { exact: true }).click()
      await page.waitForTimeout(700)
      expect(state.creates).toBe(1)
    } finally {
      await finish(page)
    }
  }, 15000)

  test('late B response cannot populate C and current PA loss removes Foreign view', async () => {
    const { page, state } = await setup()
    try {
      state.delayB = true
      await page.goto(origin + '/services?org=B&poll=0')
      await page.getByText('Go C', { exact: true }).click()
      await target(page, 'C')
      await page.waitForTimeout(500)
      await target(page, 'C')
      state.pa = false
      await page.evaluate(() =>
        (
          window as unknown as { refetchAll: (force: boolean) => void }
        ).refetchAll(true),
      )
      await page
        .getByText('This organization is outside your Home authority.')
        .waitFor()
      expect(await page.locator('[data-testid="target"]').count()).toBe(0)
      expect(await page.getByRole('combobox').count()).toBe(0)
    } finally {
      await finish(page)
    }
  }, 20000)
})
