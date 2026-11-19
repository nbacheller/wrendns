// REQ: API-007, API-013, AGT-001, OBS-901 (T35.1, T35.2, T35.3) — names read as words: the compact Policy
// panel names up to three items per section as links and then "+N more", every server summary
// stands alone, and the map, the policy route detail and the Upstreams of a forwarded domain say
// "Reverse lookups, 192.168.x.x", not `forward:168.192.in-addr.arpa#1`. The policy and the map's
// upstream nodes are the real server's; only the device nodes of the map are mocked (the e2e server
// has no traffic). These tests sign in as the admin `1-ui.spec.ts` created, so run the whole suite,
// not this file alone. The file is named `8-` so what it creates (rules, a forward) is gone before
// it ends.
import { expect, test, type BrowserContext, type Page } from '@playwright/test';

test.describe.configure({ mode: 'serial' });

const ADMIN = { user: 'admin', pass: 'correct horse battery' };
const REVERSE = '168.192.in-addr.arpa';
const STUB = 'stub.e2e.test';

let ctx: BrowserContext;
let page: Page;
let csrf = '';
const problems: string[] = [];

test.beforeAll(async ({ browser }) => {
  ctx = await browser.newContext();
  page = await ctx.newPage();
  page.on('pageerror', (e) => problems.push(`page error: ${e.message}`));
  page.on('console', (m) => {
    if (m.type() === 'error' && !/status of (40[0134]|429) \(/.test(m.text())) problems.push(`console: ${m.text()} ${m.location().url}`);
  });
  await page.goto('/');
  await page.getByLabel('Username', { exact: true }).fill(ADMIN.user);
  await page.getByLabel('Password', { exact: true }).fill(ADMIN.pass);
  await page.getByRole('button', { name: 'Sign in' }).click();
  await expect(page.getByRole('heading', { name: 'Dashboard' })).toBeVisible({ timeout: 30_000 });
  csrf = (await (await page.request.get('/api/v1/auth/status')).json()).csrfToken as string;
});

test.afterEach(() => {
  expect(problems, 'no page errors or CSP violations').toEqual([]);
});

test.afterAll(async () => {
  await ctx.close();
});

const h = () => ({ 'x-csrf-token': csrf });

test('api_013 a forwarded domain reads as words on the map, in the policy route and in the health summary', async () => {
  const r = page.request;
  expect((await r.put(`/api/v1/forwards/${REVERSE}`, { headers: h(), data: { servers: ['192.168.1.1'] } })).status()).toBe(200);
  expect((await r.put(`/api/v1/forwards/${STUB}`, { headers: h(), data: { servers: ['192.0.2.53'], stub: true } })).status()).toBe(200);

  // The map's upstream nodes (the server's own: every configured upstream has one, idle or not).
  // (The snapshot follows a reload and a sampling tick, so it is polled until the upstreams are in.)
  type MapNode = { id: string; kind: string; label: string; address?: string };
  let nodes: MapNode[] = [];
  await expect
    .poll(
      async () => {
        nodes = ((await (await r.get('/api/v1/map')).json()).nodes ?? []) as MapNode[];
        return nodes.some((n) => n.id === `up:forward:${REVERSE}#1`) && nodes.some((n) => n.id === `up:forward:${STUB}#stub`);
      },
      { timeout: 20_000 },
    )
    .toBe(true);
  const rev = nodes.find((n) => n.id === `up:forward:${REVERSE}#1`);
  expect(rev, JSON.stringify(nodes.filter((n) => n.kind === 'upstream'))).toBeTruthy();
  expect(rev!.label).toBe('Reverse lookups, 192.168.x.x');
  expect(rev!.address).toBe('192.168.1.1');
  const stub = nodes.find((n) => n.id === `up:forward:${STUB}#stub`);
  expect(stub!.label).toBe(`${STUB} names (stub zone)`);
  expect(nodes.every((n) => !n.label.startsWith('forward:'))).toBe(true);

  // The same words in MCP's network_health source (GET /map/health).
  const health = JSON.stringify(await (await r.get('/api/v1/map/health')).json());
  expect(health).not.toContain('"label":"forward:');

  // The policy's route detail, in the full panel on the Clients page.
  await page.goto('/#/clients?device=192.168.1.77&view=policy');
  const panel = page.getByTestId('policy-panel');
  await expect(panel).toBeVisible();
  const upstream = panel.getByTestId('policy-section-upstream');
  await expect(upstream).toContainText('goes to Reverse lookups, 192.168.x.x');
  await expect(upstream).not.toContainText('forward:');
  // The section's sentence stands alone.
  await expect(upstream.locator('p.muted').first()).toContainText('upstream group');

  // The map page draws the label (the node is the real one; the device nodes are not needed).
  await page.goto('/#/map');
  await expect(page.getByRole('heading', { name: 'Network map' })).toBeVisible();
  await expect(page.locator(`[data-node="up:forward:${REVERSE}#1"]`)).toContainText('Reverse lookups');

  expect((await r.delete(`/api/v1/forwards/${REVERSE}`, { headers: h() })).status()).toBe(200);
  expect((await r.delete(`/api/v1/forwards/${STUB}`, { headers: h() })).status()).toBe(200);
});

test('agt_001 the compact policy panel names up to three items as links, then "+N more"', async () => {
  const r = page.request;
  const ids = ['e2e-names-1', 'e2e-names-2', 'e2e-names-3', 'e2e-names-4', 'e2e-names-5'];
  for (const [i, id] of ids.entries()) {
    const put = await r.put(`/api/v1/rules/${id}`, { headers: h(), data: { action: 'block', domain: `names${i + 1}.e2e.test` } });
    expect(put.status()).toBe(200);
  }
  // The map is mocked with one device on it; the policy read behind the click is the real server's.
  // A page of its own: the map's live stream is a stub that never speaks, so the mocked snapshot stays.
  const map = await ctx.newPage();
  map.on('pageerror', (e) => problems.push(`page error: ${e.message}`));
  await map.addInitScript(() => {
    const Real = window.EventSource;
    function Stub(this: unknown, url: string, init?: EventSourceInit) {
      if (String(url).includes('/map/stream')) return { readyState: 1, addEventListener() {}, close() {}, onerror: null, onopen: null };
      return new Real(url, init);
    }
    Stub.CONNECTING = 0;
    Stub.OPEN = 1;
    Stub.CLOSED = 2;
    (window as unknown as { EventSource: unknown }).EventSource = Stub;
  });
  await map.route(/\/api\/v1\/map(\?.*)?$/, async (route) => {
    await route.fulfill({
      json: {
        generatedAt: '2026-11-19T12:00:00Z', windowSecs: 60, sampleRate: 1, dropped: 0, privacy: 0, truncated: false, partial: false, missingNodes: [], health: 'green',
        counts: { green: 3, yellow: 0, red: 0, idle: 0 },
        nodes: [
          { id: 'gateway', kind: 'gateway', label: 'Gateway', health: 'green', reasons: [], qps: 0, count: 0, sampled: 0 },
          { id: 'net:lan', kind: 'network', label: 'lan', health: 'green', reasons: [], qps: 0, count: 0, sampled: 0 },
          { id: 'dev:192.168.1.10', kind: 'device', label: 'laptop', health: 'green', reasons: [], qps: 2, count: 120, sampled: 120, address: '192.168.1.10', network: 'lan', group: 'default' },
          { id: 'res:node-a', kind: 'resolver', label: 'node-a', health: 'green', reasons: [], qps: 2, count: 120, sampled: 120, node: 'node-a' },
        ],
        edges: [
          { from: 'gateway', to: 'net:lan', structural: true, qps: 0, count: 0, slowPct: 0, errPct: 0, blockedPct: 0, health: 'idle' },
          { from: 'net:lan', to: 'dev:192.168.1.10', structural: true, qps: 0, count: 0, slowPct: 0, errPct: 0, blockedPct: 0, health: 'idle' },
          { from: 'dev:192.168.1.10', to: 'res:node-a', structural: false, qps: 2, count: 120, slowPct: 0, errPct: 0, blockedPct: 0, health: 'green' },
        ],
      },
    });
  });
  await map.goto('/#/map');
  await expect(map.getByRole('heading', { name: 'Network map' })).toBeVisible();
  await map.locator('[data-node="dev:192.168.1.10"]').click();
  const compact = map.getByTestId('node-panel').getByTestId('policy-compact');
  await expect(compact.getByTestId('policy-group')).toBeVisible();
  const rules = compact.getByTestId('policy-summary-rules');
  await expect(rules).toBeVisible();
  // Three items as links to where each is set, then the rest counted and linked to the full panel.
  const peek = compact.getByTestId('policy-peek-rules');
  await expect(peek.getByTestId('policy-peek-link')).toHaveCount(3);
  const more = compact.getByTestId('policy-more-rules');
  await expect(more).toHaveText('+2 more');
  await expect(more).toHaveAttribute('href', /#\/clients\?device=192\.168\.1\.10&view=policy/);
  await expect(peek.getByTestId('policy-peek-link').first()).toHaveAttribute('href', /#\/rules/);
  // Every summary stands alone: none points at what is "below".
  for (const t of await compact.locator('ul.summaries li').allTextContents()) {
    expect(t.toLowerCase()).not.toMatch(/\bbelow\b|\bthese\b|\bthe items\b/);
  }
  // A section with no more than three items has no "+N more".
  await expect(compact.getByTestId('policy-more-block')).toHaveCount(0);
  await map.close();
  for (const id of ids) expect((await r.delete(`/api/v1/rules/${id}`, { headers: h() })).status()).toBe(200);
});
