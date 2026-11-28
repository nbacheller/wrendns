// SPDX-License-Identifier: AGPL-3.0-or-later
// REQ: API-904, API-902, API-901 (T27.14g; ADR-956 §5 as amended, ADR-1098 point 3, ADR-1116; owner decision
// 2026-11-27) — Settings -> System: the confirm of a `listen` change on another node passed on by the primary, and the
// per-node public web UI address. The e2e server is one node, so the relay tests give the guarded listing two more
// members (the forwarding itself, the node's checks and the audit are the cluster tests): `pi-b`, which announces a web
// UI address and takes a relayed confirm, and `pi-c`, which does not. The public address test runs against the real
// node. A separate file, after 7-guarded4-node-api.spec.ts, which needs the admin 1-ui.spec.ts creates; a fifth admin
// makes the requests, so the guarded limiter of the other files' admins is not shared.
import { expect, test, type Browser, type Page } from '@playwright/test';

test.describe.configure({ mode: 'serial' });

const FIRST = { user: 'admin', pass: 'correct horse battery' };
const FIFTH = { user: 'guarded-ad5', pass: 'fifth admin long password' };
const B_URL = 'https://192.0.2.20:8080';
const NODE = 'home-dns';

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

const listener = (addr: string) => ({
  listener: addr,
  requireClientId: false,
  setting: 'unset',
  gatedByDefault: false,
  publicAddress: false,
  wildcardBind: true,
  defaultOn: false,
  defaultReason: 'a private address',
  publicExposure: false,
  canCarryKey: false,
  path: null,
});

interface Seen {
  relay: { id: string; body: { confirmToken?: string } } | null;
  relayCalls: number;
}

/**
 * One more member in the guarded listing, the per-node read for `pi-b`, and the guarded routes of a `listen` change
 * for it. `relay` says whether `pi-b`'s build takes a relayed confirm (the primary reports it in the listing);
 * `announces` whether it announces a web UI address at all.
 */
async function members(page: Page, seen: Seen, opts: { relay: boolean; announces?: boolean; refuse?: boolean; noPublicRow?: boolean }) {
  await page.route('**/api/v1/guarded', async (route) => {
    if (route.request().method() !== 'GET') return route.continue();
    const real = await (await route.fetch()).json();
    const me = real.nodes[0];
    // The e2e node's file sets `[[listen]]`, which locks its row; the member's own file does not.
    const settings = me.settings
      .filter((s: { id: string }) => !(opts.noPublicRow && s.id === 'api-public-url'))
      .map((s: { id: string }) => (s.id === 'listen' ? { ...s, setByFile: false } : s));
    const other = { ...me, node: 'pi-b', apiUrl: opts.announces === false ? undefined : B_URL, confirmRelay: opts.relay, settings, pending: null, pendingRestart: [], restarting: false, outcomes: [] };
    await route.fulfill({ json: { nodes: [me, other] } });
  });
  await page.route('**/api/v1/guarded/nodes/pi-b/api', (route) =>
    route.fulfill({
      json: {
        node: 'pi-b',
        apiUrl: opts.announces === false ? undefined : B_URL,
        api: { listen: '0.0.0.0:8080', scheme: 'https', certificate: 'b-ui.pem', trustedProxies: [], httpRedirect: null },
        listeners: [listener('udp://0.0.0.0:53'), listener('tcp://0.0.0.0:53')],
      },
    }),
  );
  await page.route('**/api/v1/guarded/listen/preview', (route) =>
    route.fulfill({
      json: {
        acknowledgements: [],
        checks: [],
        effect: 'Adds a listener on pi-b.',
        listeners: [{ change: 'added', listener: 'udp://192.168.1.2:5300' }],
        mode: 'window',
        needsRecentSignIn: false,
        node: 'pi-b',
        nodes: ['pi-b'],
        phrase: 'pi-b listen',
        previewId: 'stub-b',
        restartRequired: false,
        setByFile: false,
        setting: 'listen',
        warnings: [],
        weakening: false,
        windowSecs: 120,
        wouldDisconnect: false,
      },
    }),
  );
  await page.route('**/api/v1/guarded/listen', async (route) => {
    if (route.request().method() !== 'POST') return route.continue();
    await route.fulfill({
      status: 202,
      json: { status: 'pending', node: 'pi-b', setting: 'listen', pendingId: 'pend-b', confirmToken: 'tok-b', deadlineSecs: 120, pendingRestart: false, message: 'pi-b runs the new listener; confirm it there.', proof: 'new_socket' },
    });
  });
  // The countdown reads the pending change from this node, which does not hold it: 404.
  await page.route('**/api/v1/guarded/pending/pend-b', (route) =>
    route.fulfill({ status: 404, contentType: 'application/problem+json', json: { type: 'about:blank', title: 'Not found', status: 404, code: 'not_found', detail: 'no change is pending under that ID' } }),
  );
  await page.route('**/api/v1/guarded/pending/pend-b/confirm-relay', async (route) => {
    seen.relayCalls += 1;
    seen.relay = { id: 'pend-b', body: route.request().postDataJSON() };
    if (opts.refuse) {
      return route.fulfill({
        status: 403,
        contentType: 'application/problem+json',
        json: { type: 'about:blank', title: 'The relayed confirm was refused', status: 403, code: 'relay_refused', detail: "the node's own query to udp://192.168.1.2:5300 got no answer" },
      });
    }
    await route.fulfill({ json: { setting: 'listen', node: 'pi-b', outcome: 'confirmed' } });
  });
}

/** Picks `pi-b` on the Listeners card, adds a listener and applies the change: the countdown is up. */
async function applyListenOnB(page: Page) {
  const lst = page.getByTestId('listeners-card');
  await expect(lst).toBeVisible({ timeout: 30_000 });
  await lst.getByTestId('listeners-node-select').selectOption('pi-b');
  await expect(lst.getByTestId('listeners-row')).toHaveCount(2);
  await lst.getByTestId('listeners-add').click();
  const row = lst.getByTestId('listeners-row').last();
  await row.getByTestId('listeners-proto').selectOption('udp');
  await row.getByTestId('listeners-addr').fill('192.168.1.2:5300');
  await lst.getByTestId('guarded-start-listen').click();
  await expect(lst.getByTestId('guarded-preview')).toBeVisible();
  await expect(lst.getByTestId('guarded-node')).toHaveText('pi-b');
  return lst;
}

test.describe('api_902 confirm through the primary', () => {
  test('api_902 relay admin is made', async ({ browser }) => {
    const first = await signedIn(browser, FIRST);
    try {
      await expect(first.getByTestId('guarded-card')).toBeVisible({ timeout: 30_000 });
      const made = await first.request.post('/api/v1/users', {
        headers: { 'x-csrf-token': await csrfOf(first) },
        data: { username: FIFTH.user, password: FIFTH.pass, role: 'admin' },
      });
      expect([200, 201, 409]).toContain(made.status());
    } finally {
      await first.close();
    }
  });

  test('api_902 confirm through the primary', async ({ browser }) => {
    test.setTimeout(180_000);
    const seen: Seen = { relay: null, relayCalls: 0 };
    const page = await signedIn(browser, FIFTH, (p) => members(p, seen, { relay: true }));
    try {
      const lst = await applyListenOnB(page);
      // The review says where the confirm happens and that the primary can pass it on.
      await expect(lst.getByTestId('guarded-confirm-at')).toContainText(B_URL);
      await expect(lst.getByTestId('guarded-relay-note')).toContainText("can't open");
      await expect(lst.getByTestId('guarded-relay-note')).toContainText('confirm through the primary instead');
      await expect(lst.getByTestId('guarded-relay-note')).toContainText('its own test queries first');
      await lst.getByTestId('guarded-phrase-input').fill('pi-b listen');
      await lst.getByTestId('guarded-apply').click();
      // The countdown keeps the direct link as the first choice; the relay is a second one, closed until asked for.
      await expect(lst.getByTestId('guarded-pending')).toBeVisible({ timeout: 30_000 });
      await expect(lst.getByTestId('guarded-confirm-node-link')).toHaveAttribute('href', `${B_URL}/#/guarded-confirm?id=pend-b&t=tok-b`);
      await expect(lst.getByTestId('guarded-relay-confirm')).toBeHidden();
      await lst.getByTestId('guarded-relay').getByText("Can't open pi-b's web UI?").click();
      await expect(lst.getByTestId('guarded-relay')).toContainText('does not show that your devices');
      await expect(lst.getByTestId('guarded-relay')).toContainText('stronger proof');
      expect(seen.relayCalls).toBe(0);
      await lst.getByTestId('guarded-relay-confirm').click();
      // The primary was asked once, with the change's token (and the admin's session, which is the cookie).
      await expect(lst.getByTestId('guarded-result')).toContainText('Confirmed through the primary', { timeout: 30_000 });
      await expect(lst.getByTestId('guarded-result')).toContainText('own test question');
      expect(seen.relayCalls).toBe(1);
      expect(seen.relay?.body).toEqual({ confirmToken: 'tok-b' });
    } finally {
      await page.close();
    }
  });

  test('api_902 relay refused shows the node reason and the window runs on', async ({ browser }) => {
    test.setTimeout(180_000);
    const seen: Seen = { relay: null, relayCalls: 0 };
    const page = await signedIn(browser, FIFTH, (p) => members(p, seen, { relay: true, refuse: true }));
    try {
      const lst = await applyListenOnB(page);
      await lst.getByTestId('guarded-phrase-input').fill('pi-b listen');
      await lst.getByTestId('guarded-apply').click();
      await expect(lst.getByTestId('guarded-pending')).toBeVisible({ timeout: 30_000 });
      await lst.getByTestId('guarded-relay').getByText("Can't open pi-b's web UI?").click();
      await lst.getByTestId('guarded-relay-confirm').click();
      // The node's own reason is in the sentence, and the change is still pending (it can be tried again or cancelled).
      await expect(lst.getByRole('alert').filter({ hasText: 'was refused' })).toContainText("the node's own query to udp://192.168.1.2:5300 got no answer");
      await expect(lst.getByTestId('guarded-pending')).toBeVisible();
      await expect(lst.getByTestId('guarded-relay-confirm')).toBeEnabled();
      expect(seen.relayCalls).toBe(1);
    } finally {
      await page.close();
    }
  });

  test('api_902 a node with no announced address opens the relay choice by itself', async ({ browser }) => {
    test.setTimeout(180_000);
    const seen: Seen = { relay: null, relayCalls: 0 };
    const page = await signedIn(browser, FIFTH, (p) => members(p, seen, { relay: true, announces: false }));
    try {
      const lst = await applyListenOnB(page);
      await expect(lst.getByTestId('guarded-confirm-at')).toContainText('has not announced an address');
      await lst.getByTestId('guarded-phrase-input').fill('pi-b listen');
      await lst.getByTestId('guarded-apply').click();
      await expect(lst.getByTestId('guarded-confirm-node-unknown')).toBeVisible({ timeout: 30_000 });
      await expect(lst.getByTestId('guarded-relay-confirm')).toBeVisible();
      await expect(lst.getByTestId('guarded-confirm-node-link')).toHaveCount(0);
    } finally {
      await page.close();
    }
  });

  test('api_902 a node that cannot take a relayed confirm is said so plainly', async ({ browser }) => {
    test.setTimeout(180_000);
    const seen: Seen = { relay: null, relayCalls: 0 };
    const page = await signedIn(browser, FIFTH, (p) => members(p, seen, { relay: false }));
    try {
      const lst = await applyListenOnB(page);
      await expect(lst.getByTestId('guarded-relay-unavailable')).toContainText('cannot take a confirm passed on by the primary');
      await expect(lst.getByTestId('guarded-relay-note')).toHaveCount(0);
      await lst.getByTestId('guarded-phrase-input').fill('pi-b listen');
      await lst.getByTestId('guarded-apply').click();
      await expect(lst.getByTestId('guarded-pending')).toBeVisible({ timeout: 30_000 });
      await expect(lst.getByTestId('guarded-relay')).toHaveCount(0);
      await expect(lst.getByTestId('guarded-confirm-node-link')).toBeVisible();
    } finally {
      await page.close();
    }
  });
  test('api_902 a node that does not know the public address is left alone', async ({ browser }) => {
    test.setTimeout(180_000);
    const seen: Seen = { relay: null, relayCalls: 0 };
    const page = await signedIn(browser, FIFTH, (p) => members(p, seen, { relay: true, noPublicRow: true }));
    try {
      const lst = page.getByTestId('listeners-card');
      await expect(lst).toBeVisible({ timeout: 30_000 });
      await lst.getByTestId('listeners-node-select').selectOption('pi-b');
      const box = page.getByTestId('api-public-url');
      await expect(box.getByTestId('api-public-url-unknown')).toContainText('does not know the public address');
      await expect(box.getByTestId('api-public-url-input')).toBeDisabled();
      await expect(box.getByTestId('guarded-start-api-public-url')).toBeDisabled();
    } finally {
      await page.close();
    }
  });
});

test.describe('api_902 public web UI address', () => {
  test('api_902 public address is set and cleared for the node', async ({ browser }) => {
    test.setTimeout(180_000);
    const page = await signedIn(browser, FIFTH);
    try {
      const box = page.getByTestId('api-public-url');
      await expect(box).toBeVisible({ timeout: 30_000 });
      // The e2e node listens on loopback with no cluster address to borrow a host from: it announces none.
      await expect(box.getByTestId('api-public-url-announced')).toContainText('announces no address');
      // A wrong address is caught here, before the server sees it, and the help opens from the section.
      for (const bad of ['dns.example.com', 'https://user:pw@dns.example.com', 'https://dns.example.com/ui', 'ftp://dns.example.com']) {
        await box.getByTestId('api-public-url-input').fill(bad);
        await expect(box.getByTestId('api-public-url-bad')).toBeVisible();
        await expect(box.getByTestId('guarded-start-api-public-url')).toBeDisabled();
      }
      await box.getByRole('button', { name: /^Help: .*public web UI address/ }).click();
      await expect(page.getByTestId('help-panel')).toContainText('load balancer');
      await page.keyboard.press('Escape');
      // The review: weakening (the confirm link carries a token to that address), the phrase, nothing applied yet.
      await box.getByTestId('api-public-url-input').fill('https://dns.example.com');
      await expect(box.getByTestId('api-public-url-bad')).toHaveCount(0);
      await box.getByTestId('guarded-start-api-public-url').click();
      await expect(box.getByTestId('guarded-preview')).toBeVisible();
      await expect(box.getByTestId('guarded-weakens')).toBeVisible();
      await expect(box.getByTestId('guarded-effect')).toContainText('Announces https://dns.example.com');
      await expect(box.getByTestId('guarded-warning').first()).toContainText('single-use token');
      await expect(box.getByTestId('guarded-phrase')).toHaveText(`${NODE} api-public-url`);
      await box.getByTestId('guarded-phrase-input').fill(`${NODE} api-public-url`);
      await box.getByTestId('guarded-apply').click();
      await expect(box.getByTestId('guarded-result')).toBeVisible({ timeout: 30_000 });
      // Applied at once: the node announces it, and its own information reports it.
      const info = () => page.evaluate(async () => ((await (await fetch('/api/v1/system/info')).json()) as { api?: { publicUrl?: string } }).api?.publicUrl);
      await expect.poll(info).toBe('https://dns.example.com');
      await box.getByTestId('guarded-again').click();
      await expect(box.getByTestId('api-public-url-announced')).toContainText('https://dns.example.com');
      await expect(box.getByTestId('api-public-url-announced')).toContainText('set here');
      // Clearing it is an ordinary change back to what the node works out (not weakening).
      await box.getByTestId('api-public-url-input').fill('');
      await box.getByTestId('guarded-start-api-public-url').click();
      await expect(box.getByTestId('guarded-preview')).toBeVisible();
      await expect(box.getByTestId('guarded-weakens')).toHaveCount(0);
      await box.getByTestId('guarded-phrase-input').fill(`${NODE} api-public-url`);
      await box.getByTestId('guarded-apply').click();
      await expect(box.getByTestId('guarded-result')).toBeVisible({ timeout: 30_000 });
      await expect.poll(info).toBeFalsy();
      await expect(box.getByTestId('api-public-url-announced')).toContainText('announces no address');
      const audit = JSON.stringify(await (await page.request.get('/api/v1/audit?action=settings.guarded&limit=20')).json());
      expect(audit).toContain('api-public-url');
    } finally {
      await page.close();
    }
  });
});
