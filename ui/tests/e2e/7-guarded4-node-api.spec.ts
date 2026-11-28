// SPDX-License-Identifier: AGPL-3.0-or-later
// REQ: API-902, API-901 (T27.14g0; ADR-956 §5, ADR-1113; owner decision 2026-11-27) — Settings -> System: the Web UI
// and API card and the Listeners card show and stage ANOTHER node's values. The e2e server is one node, so the
// guarded listing gets two more members here (the forwarding itself is covered by the cluster tests): `pi-b`, which
// announces its web UI address and answers the per-node read, and `pi-c`, an older build that cannot (409
// `upgrade_required`). A separate file, after 7-guarded3-proxies.spec.ts, which needs the admin 1-ui.spec.ts creates.
// Its own admin makes the requests, so the guarded limiter of the other files' admins is not shared.
import { expect, test, type Browser, type Page } from '@playwright/test';

test.describe.configure({ mode: 'serial' });

const FIRST = { user: 'admin', pass: 'correct horse battery' };
const FOURTH = { user: 'guarded-ad4', pass: 'fourth admin long password' };
const B_URL = 'https://192.0.2.20:8080';

async function signedIn(browser: Browser, who: { user: string; pass: string }, route?: (page: Page) => Promise<void>): Promise<Page> {
  const page = await browser.newPage();
  // Route mocks go in before the page loads, and the sign-in finishes before anything else is done.
  if (route) await route(page);
  await page.goto('/#/settings?tab=system');
  await page.getByLabel('Username', { exact: true }).fill(who.user);
  await page.getByLabel('Password', { exact: true }).fill(who.pass);
  await page.getByRole('button', { name: 'Sign in' }).click();
  return page;
}

const csrfOf = async (page: Page) => (await (await page.request.get('/api/v1/auth/status')).json()).csrfToken as string;

const listener = (addr: string, path?: string) => ({
  listener: `${addr}`,
  requireClientId: false,
  setting: 'unset',
  gatedByDefault: false,
  publicAddress: false,
  wildcardBind: true,
  defaultOn: false,
  defaultReason: 'a private address',
  publicExposure: false,
  canCarryKey: false,
  path: path ?? null,
});

/** Two more members in the guarded listing, and the per-node read for each. */
async function members(page: Page, seen: { preview: { node?: string } | null }) {
  await page.route('**/api/v1/guarded', async (route) => {
    if (route.request().method() !== 'GET') return route.continue();
    const real = await (await route.fetch()).json();
    const me = real.nodes[0];
    const other = { ...me, node: 'pi-b', apiUrl: B_URL, pending: null, pendingRestart: [], restarting: false, outcomes: [] };
    const older = { ...me, node: 'pi-c', pending: null, pendingRestart: [], restarting: false, outcomes: [] };
    await route.fulfill({ json: { nodes: [me, other, older] } });
  });
  await page.route('**/api/v1/guarded/nodes/pi-b/api', (route) =>
    route.fulfill({
      json: {
        node: 'pi-b',
        apiUrl: B_URL,
        api: { listen: '0.0.0.0:8080', scheme: 'https', certificate: 'b-ui.pem', trustedProxies: ['198.51.100.0/24'], httpRedirect: '0.0.0.0:80' },
        listeners: [listener('udp://0.0.0.0:53'), listener('tcp://0.0.0.0:53'), listener('dot://0.0.0.0:853')],
      },
    }),
  );
  await page.route('**/api/v1/guarded/nodes/pi-c/api', (route) =>
    route.fulfill({
      status: 409,
      contentType: 'application/problem+json',
      json: {
        type: 'about:blank',
        title: 'Conflict',
        status: 409,
        code: 'upgrade_required',
        detail: 'node pi-c runs a build that does not know the web UI and API address read; upgrade it first',
      },
    }),
  );
  await page.route('**/api/v1/guarded/trusted-proxies/preview', async (route) => {
    seen.preview = route.request().postDataJSON();
    await route.fulfill({
      json: {
        acknowledgements: [],
        checks: [],
        effect: 'Trusts 198.51.100.0/24 and 192.0.2.7 as proxies on pi-b.',
        mode: 'window',
        needsRecentSignIn: false,
        node: 'pi-b',
        nodes: ['pi-b'],
        phrase: 'pi-b trusted-proxies',
        previewId: 'stub-b',
        restartRequired: false,
        setByFile: false,
        setting: 'trusted-proxies',
        warnings: [],
        weakening: false,
        windowSecs: 120,
        wouldDisconnect: false,
      },
    });
  });
  await page.route('**/api/v1/guarded/trusted-proxies', async (route) => {
    if (route.request().method() !== 'POST') return route.continue();
    await route.fulfill({
      status: 202,
      json: { status: 'pending', node: 'pi-b', setting: 'trusted-proxies', pendingId: 'pend-b', confirmToken: 'tok-b', deadlineSecs: 120, pendingRestart: false, message: 'pi-b runs the new list; confirm it there.', proof: 'proxy_list' },
    });
  });
}

test.describe('api_902 another node', () => {
  test('api_902 another node admin is made', async ({ browser }) => {
    const first = await signedIn(browser, FIRST);
    try {
      await expect(first.getByTestId('guarded-card')).toBeVisible({ timeout: 30_000 });
      const made = await first.request.post('/api/v1/users', {
        headers: { 'x-csrf-token': await csrfOf(first) },
        data: { username: FOURTH.user, password: FOURTH.pass, role: 'admin' },
      });
      expect([200, 201, 409]).toContain(made.status());
    } finally {
      await first.close();
    }
  });

  test("api_902 another node's settings are shown and changed from one UI", async ({ browser }) => {
    test.setTimeout(180_000);
    const seen: { preview: { node?: string; value?: { proxies?: string[] } } | null } = { preview: null };
    const page = await signedIn(browser, FOURTH, (p) => members(p, seen));
    try {
      const web = page.getByTestId('web-api-card');
      await expect(web).toBeVisible({ timeout: 30_000 });
      // This node first: its own list (nothing in force on the e2e server).
      await expect(web.getByTestId('trusted-proxies-row')).toHaveCount(0);
      await web.getByTestId('web-api-node-select').selectOption('pi-b');
      // The picked node's own values: its address, certificate and list, read through the primary.
      await expect(web.getByTestId('web-api-facts')).toContainText('https://0.0.0.0:8080');
      await expect(web.getByTestId('web-api-facts')).toContainText('b-ui.pem');
      await expect(web.getByTestId('trusted-proxies-row')).toHaveText(/198\.51\.100\.0\/24/);
      await expect(web.getByTestId('web-api-node-note')).toContainText('confirmed on pi-b itself');
      await expect(web.getByTestId('web-api-node-link')).toHaveAttribute('href', B_URL);
      // Staging adds to THAT node's list, and the review is for that node.
      await web.getByTestId('trusted-proxies-input').fill('192.0.2.7');
      await web.getByTestId('trusted-proxies-add').click();
      await web.getByTestId('guarded-start-trusted-proxies').click();
      await expect(web.getByTestId('guarded-node')).toHaveText('pi-b');
      expect(seen.preview?.node).toBe('pi-b');
      expect(seen.preview?.value?.proxies).toEqual(['198.51.100.0/24', '192.0.2.7']);
      await web.getByTestId('guarded-phrase-input').fill('pi-b trusted-proxies');
      await web.getByTestId('guarded-apply').click();
      // The confirm must reach that node itself: a link to its own address, not a button on this node.
      const link = web.getByTestId('guarded-confirm-node-link');
      await expect(link).toHaveAttribute('href', `${B_URL}/#/guarded-confirm?id=pend-b&t=tok-b`);
      await expect(web.getByTestId('guarded-confirm-here')).toHaveCount(0);
      // The Listeners card follows the same pick: that node's listeners, not this node's.
      const lst = page.getByTestId('listeners-card');
      await expect(lst.getByTestId('listeners-row')).toHaveCount(3);
      await expect(lst.getByTestId('listeners-row').nth(2)).toHaveAttribute('data-listener', 'dot://0.0.0.0:853');
    } finally {
      await page.close();
    }
  });

  test('api_902 an older member is said so plainly and nothing is changed for it', async ({ browser }) => {
    test.setTimeout(180_000);
    const seen: { preview: { node?: string } | null } = { preview: null };
    const page = await signedIn(browser, FOURTH, (p) => members(p, seen));
    try {
      const web = page.getByTestId('web-api-card');
      await expect(web).toBeVisible({ timeout: 30_000 });
      await web.getByTestId('web-api-node-select').selectOption('pi-c');
      await expect(web.getByTestId('web-api-node-error')).toContainText('older build');
      await expect(web.getByTestId('web-api-node-error')).toContainText('pi-c');
      // The list and the other node's values are not shown, and the redirect form cannot start a change.
      await expect(web.getByTestId('trusted-proxies')).toHaveCount(0);
      await expect(web.getByTestId('guarded-start-api-http-redirect')).toBeDisabled();
      const lst = page.getByTestId('listeners-card');
      await expect(lst.getByTestId('listeners-row')).toHaveCount(0);
      await expect(lst.getByTestId('listeners-add')).toHaveCount(0);
      expect(seen.preview).toBeNull();
    } finally {
      await page.close();
    }
  });
});
