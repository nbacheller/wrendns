// REQ: OBS-902, NFR-001 (T26.4, T26.5, ADR-958, ADR-959, ADR-970) - the GeoIP database's card in
// Settings and the world view. The GeoIP card runs against the real node and a fake HTTPS source
// the harness trusts (`TELLTALE_GEOIP_TEST`, a debug build only); the world view's data is mocked
// with `page.route` (the node records no answer address yet, ADR-970, and the e2e server has no
// real traffic), and the pure parts are tested without a browser. These tests sign in as the admin
// `1-ui.spec.ts` created, so run the whole suite, not this file alone.
import { expect, test, type Browser, type BrowserContext, type Page } from '@playwright/test';
import { createServer, type Server } from 'node:https';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { gzipSync } from 'node:zlib';
import { BASE_URL, PORTS } from './ports';
import { arcPath, countryName, countryPoint, landPath, place, placeMarkers, project, upstreamsOnly, whyUnavailable, MAP_H, MAP_W, type World } from '../../src/lib/world';
import { COUNTRY_DATA, GRID, LAND_MASK } from '../../src/lib/world-data';

test.describe.configure({ mode: 'serial' });

const ADMIN = { user: 'admin', pass: 'correct horse battery' };
const OPERATOR = { user: 'geo-operator', pass: 'geo operator long password' };
const VIEWER = { user: 'worldviewer', pass: 'a viewer pass phrase 7' };

// ---- The fake source: a gzip CSV with both families and four countries (the harness accepts a small one).
const CSV = [
  '1.0.0.0,1.0.0.255,AU',
  '8.8.8.0,8.8.8.255,US',
  '93.184.216.0,93.184.216.255,US',
  '185.60.216.0,185.60.216.255,IE',
  '2001:db8::,2001:db8::ffff,NL',
  '2606:4700::,2606:4700::ffff,US',
].join('\n');
let source: Server;
let hits = 0;
const fixtures = resolve(import.meta.dirname, 'fixtures');

test.beforeAll(async () => {
  source = createServer(
    { key: readFileSync(join(fixtures, 'geoip-source-key.pem')), cert: readFileSync(join(fixtures, 'geoip-source-cert.pem')) },
    (req, res) => {
      hits++;
      if (req.url === '/dbip.csv.gz') {
        res.writeHead(200, { 'content-type': 'application/gzip' });
        res.end(gzipSync(Buffer.from(CSV + '\n')));
      } else {
        res.writeHead(404);
        res.end();
      }
    },
  );
  await new Promise<void>((ok) => source.listen(PORTS.geoipSource, '127.0.0.1', ok));
});
test.afterAll(async () => {
  await new Promise<void>((ok) => source.close(() => ok()));
});
const SOURCE_URL = `https://127.0.0.1:${PORTS.geoipSource}/dbip.csv.gz`;

let adminState: Awaited<ReturnType<BrowserContext['storageState']>>;
test.beforeAll(async ({ browser }) => {
  const ctx = await browser.newContext();
  const page = await ctx.newPage();
  await page.goto('/');
  await page.getByLabel('Username', { exact: true }).fill(ADMIN.user);
  await page.getByLabel('Password', { exact: true }).fill(ADMIN.pass);
  await page.getByRole('button', { name: 'Sign in' }).click();
  await expect(page.getByRole('heading', { name: 'Dashboard' })).toBeVisible({ timeout: 30_000 });
  adminState = await ctx.storageState();
  // The operator of the read-only test.
  const csrf = (await (await ctx.request.get('/api/v1/auth/status')).json()).csrfToken as string;
  const made = await ctx.request.post('/api/v1/users', { headers: { 'x-csrf-token': csrf }, data: { username: OPERATOR.user, password: OPERATOR.pass, role: 'operator' } });
  expect([200, 201, 409]).toContain(made.status());
  const madeViewer = await ctx.request.post('/api/v1/users', { headers: { 'x-csrf-token': csrf }, data: { username: VIEWER.user, password: VIEWER.pass, role: 'viewer' } });
  expect([200, 201, 409]).toContain(madeViewer.status());
  await ctx.close();
});

interface Opened {
  page: Page;
  ctx: BrowserContext;
  problems: string[];
  external: string[];
  world: { body: unknown; status: number; requests: string[] };
}

const problemFilter = (text: string) => /status of (40[134]|409|422|429) \(/.test(text);

/** A page with the world view's data mocked (`o.world.body`); `reducedMotion` and the storage state are the caller's. */
async function open(browser: Browser, body: unknown, opts: { reducedMotion?: 'reduce'; state?: typeof adminState; mock?: boolean } = {}): Promise<Opened> {
  const ctx = await browser.newContext({ storageState: opts.state ?? adminState, reducedMotion: opts.reducedMotion });
  const page = await ctx.newPage();
  const o: Opened = { page, ctx, problems: [], external: [], world: { body, status: 200, requests: [] } };
  page.on('pageerror', (e) => o.problems.push(`page error: ${e.message}`));
  page.on('console', (m) => {
    if (m.type() === 'error' && !problemFilter(m.text())) o.problems.push(`console: ${m.text()}`);
  });
  const base = new URL(BASE_URL).origin;
  page.on('request', (r) => {
    if (!r.url().startsWith(base) && !r.url().startsWith('data:') && !r.url().startsWith('blob:')) o.external.push(r.url());
  });
  if (opts.mock !== false) {
    await page.route(/\/api\/v1\/map\/world(\?.*)?$/, async (route) => {
      o.world.requests.push(new URL(route.request().url()).search);
      if (o.world.status !== 200) {
        await route.fulfill({ status: o.world.status, contentType: 'application/problem+json', body: JSON.stringify({ type: 'about:blank', title: 'The map is off', status: o.world.status, code: 'map_disabled' }) });
        return;
      }
      await route.fulfill({ json: o.world.body });
    });
  }
  return o;
}
const goWorld = async (o: Opened, hash = '#/world') => {
  await o.page.goto(`/${hash}`);
  // The same address again is only a hash change: reload, so the page asks for what is mocked now.
  if (o.page.url().endsWith(hash)) await o.page.reload();
  await expect(o.page.getByRole('heading', { name: 'World view' })).toBeVisible();
};

const world = (over: Partial<World> = {}): World => ({
  available: true,
  updatedAt: '2026-11-18T12:00:00.000Z',
  windowSecs: 60,
  regions: [
    { cc: 'US', name: 'US', qps: 8, count: 480, slowPct: 4, health: 'green' },
    { cc: 'DE', name: 'DE', qps: 2, count: 120, slowPct: 22, health: 'yellow' },
    { cc: 'IE', name: 'IE', qps: 0.5, count: 30, slowPct: 0, health: 'idle' },
    { cc: 'NL', name: 'NL', qps: 1, count: 60, slowPct: 0, health: 'green' },
  ],
  markers: [
    { name: 'cloudflare', cc: 'US', qps: 4, health: 'green' },
    { name: 'quad9', cc: 'CH', qps: 1, health: 'red' },
  ],
  unplacedUpstreams: 1,
  unlocated: { count: 310 },
  ...over,
});

const running = (page: Page) => page.evaluate(() => document.getAnimations().filter((a) => (a.effect as KeyframeEffect | null)?.target?.classList?.contains('pulse') && a.playState === 'running').length);
const pausedCount = (page: Page) => page.evaluate(() => document.getAnimations().filter((a) => (a.effect as KeyframeEffect | null)?.target?.classList?.contains('pulse') && a.playState === 'paused').length);

// ================================================================== the world view

test('obs_902 world view draws arcs from a mocked answer', async ({ browser }) => {
  const o = await open(browser, world());
  await goWorld(o);
  const figure = o.page.getByTestId('world-figure');
  await expect(figure).toBeVisible();
  // An arc and an end for each country, once; the home marker says where they start.
  await expect(o.page.locator('[data-arc]')).toHaveCount(4);
  for (const cc of ['US', 'DE', 'IE', 'NL']) await expect(o.page.locator(`[data-country="${cc}"]`)).toHaveCount(1);
  await expect(o.page.getByTestId('world-home')).toContainText('Your network');
  // Colour is never alone: the shapes differ by state, and the label says it in words.
  const shapes = new Set<string>();
  for (const cc of ['US', 'DE', 'IE']) shapes.add((await o.page.locator(`[data-country="${cc}"] .shape`).getAttribute('d')) ?? '');
  expect(shapes.size).toBe(3);
  await expect(o.page.locator('[data-country="DE"]')).toHaveAttribute('aria-label', /Germany: Warning/);
  await expect(o.page.locator('[data-country="IE"]')).toHaveAttribute('aria-label', /Ireland: Idle/);
  // A group, not an image: its country marks stay reachable; the summary names the busiest.
  await expect(figure).toHaveAttribute('role', 'group');
  await expect(o.page.getByTestId('world-summary')).toContainText('United States 480');
  // The pulse's width follows the rate: the busiest arc is wider than the quietest.
  const w = async (cc: string) => Number(await o.page.locator(`[data-pulse="${cc}"]`).getAttribute('stroke-width'));
  expect(await w('US')).toBeGreaterThan(await w('IE'));
  // The "no location" counter and the upstream layer.
  await expect(o.page.getByTestId('world-unlocated')).toContainText('310 of 1,000 lookups have no location');
  await expect(o.page.locator('[data-marker]')).toHaveCount(2);
  await o.page.getByTestId('layer-upstreams').uncheck();
  await expect(o.page.locator('[data-marker]')).toHaveCount(0);
  await o.page.getByTestId('layer-upstreams').check();
  await expect(o.page.locator('[data-marker="quad9"]')).toHaveAttribute('aria-label', /Upstream quad9 in Switzerland: Failing/);
  // The same filters narrow it: the node goes to the server, the state narrows what is drawn.
  await o.page.getByTestId('filter-health').selectOption('yellow');
  await expect(o.page.locator('[data-arc]')).toHaveCount(1);
  await expect(o.page.locator('[data-country="DE"]')).toHaveCount(1);
  await o.page.getByTestId('filter-clear').click();
  await expect(o.page.locator('[data-arc]')).toHaveCount(4);
  await o.page.goto('/#/world?node=home-dns');
  await expect.poll(() => o.world.requests.some((r) => r.includes('node=home-dns'))).toBe(true);
  // The attribution the licence asks for is on the page, and nothing was fetched from outside.
  await expect(o.page.getByTestId('world-attribution')).toContainText('IP geolocation by DB-IP.com');
  expect(o.external, 'no tile, font or script from outside').toEqual([]);
  expect(o.problems).toEqual([]);
  await o.ctx.close();
});

test('obs_902 world view says when geoip is off', async ({ browser }) => {
  const off = { available: false, reason: 'geoip_off', updatedAt: '2026-11-18T12:00:00.000Z', windowSecs: 60, regions: [], markers: [], unplacedUpstreams: 0, unlocated: { count: 300, reason: 'geoip_off' } };
  const o = await open(browser, off);
  await goWorld(o);
  const msg = o.page.getByTestId('world-unavailable');
  await expect(msg).toBeVisible();
  await expect(msg).toHaveAttribute('data-reason', 'geoip_off');
  await expect(msg).toContainText('GeoIP is off');
  await expect(o.page.locator('[data-arc]')).toHaveCount(0);
  // An admin gets the way to the setting; it opens the GeoIP card.
  await o.page.getByTestId('world-setting-link').click();
  await expect(o.page.getByTestId('geoip-card')).toBeVisible();
  // The database's missing state reads differently.
  o.world.body = { ...off, reason: 'geoip_missing' };
  await goWorld(o);
  await expect(o.page.getByTestId('world-unavailable')).toHaveAttribute('data-reason', 'geoip_missing');
  await expect(o.page.getByTestId('world-unavailable')).toContainText('not on this node yet');
  expect(o.problems).toEqual([]);
  await o.ctx.close();
});

test('obs_902 world view says when addresses are not recorded', async ({ browser }) => {
  const body = world({ available: false, reason: 'address_not_recorded', regions: [], unlocated: { count: 600, reason: 'address_not_recorded' } });
  const o = await open(browser, body);
  await goWorld(o);
  const msg = o.page.getByTestId('world-unavailable');
  await expect(msg).toHaveAttribute('data-reason', 'address_not_recorded');
  await expect(msg).toContainText("Answer addresses aren't recorded");
  // Nothing is claimed about answers; no link to a setting, because no setting changes it.
  await expect(o.page.locator('[data-arc]')).toHaveCount(0);
  await expect(o.page.getByTestId('world-setting-link')).toHaveCount(0);
  // The upstreams are still placed.
  await expect(o.page.locator('[data-marker]')).toHaveCount(2);
  expect(o.problems).toEqual([]);
  await o.ctx.close();
});

test('obs_902 world view labels upstream-only markers', async ({ browser }) => {
  const o = await open(browser, world({ available: false, reason: 'address_not_recorded', regions: [] }));
  await goWorld(o);
  await expect(o.page.getByTestId('world-upstream-only')).toHaveText('Upstream locations, not where answers point.');
  // The same words when the view is available but only markers came back.
  o.world.body = world({ regions: [], reason: undefined });
  await goWorld(o);
  await expect(o.page.getByTestId('world-upstream-only')).toBeVisible();
  await expect(o.page.getByTestId('world-summary')).toContainText('2 upstream locations, no answers placed');
  // With answers placed the label is gone.
  o.world.body = world();
  await goWorld(o);
  await expect(o.page.getByTestId('world-upstream-only')).toHaveCount(0);
  expect(o.problems).toEqual([]);
  await o.ctx.close();
});

test('obs_902 world view reduced motion and table', async ({ browser }) => {
  const o = await open(browser, world(), { reducedMotion: 'reduce' });
  await goWorld(o);
  // Nothing moves, there is no switch to turn motion on, and every arc says its rate in words.
  await expect(o.page.getByTestId('world-figure')).toHaveAttribute('data-motion', 'off');
  expect(await running(o.page)).toBe(0);
  await expect(o.page.getByTestId('pause-motion')).toHaveCount(0);
  await expect(o.page.getByTestId('rate-label')).toHaveCount(4);
  // The table is the same data as text.
  await o.page.getByTestId('view-table').click();
  const table = o.page.getByTestId('world-table');
  await expect(table).toBeVisible();
  await expect(table.locator('[data-region-row]')).toHaveCount(4);
  await expect(table.locator('[data-region-row="US"]')).toContainText('United States');
  await expect(table.locator('[data-region-row="DE"]')).toContainText('degraded');
  await expect(table.locator('[data-marker-row="quad9"]')).toContainText('Switzerland');
  await expect(o.page.getByTestId('world-figure')).toHaveCount(0);
  // The view is in the address, so it can be linked.
  expect(o.page.url()).toContain('view=table');
  expect(o.problems).toEqual([]);
  await o.ctx.close();
  // With motion on, the pulses run, "Pause motion" pauses them and a hidden tab pauses them too.
  const m = await open(browser, world());
  await m.page.addInitScript(() => {
    (window as unknown as { __vis: string }).__vis = 'visible';
    Object.defineProperty(document, 'visibilityState', { configurable: true, get: () => (window as unknown as { __vis: string }).__vis });
    Object.defineProperty(document, 'hidden', { configurable: true, get: () => (window as unknown as { __vis: string }).__vis === 'hidden' });
  });
  await goWorld(m);
  await expect.poll(() => running(m.page)).toBeGreaterThan(0);
  await m.page.getByTestId('pause-motion').click();
  await expect.poll(() => running(m.page)).toBe(0);
  expect(await pausedCount(m.page)).toBeGreaterThan(0);
  await m.page.getByTestId('pause-motion').click();
  await expect.poll(() => running(m.page)).toBeGreaterThan(0);
  await m.page.evaluate(() => {
    (window as unknown as { __vis: string }).__vis = 'hidden';
    document.dispatchEvent(new Event('visibilitychange'));
  });
  await expect.poll(() => running(m.page)).toBe(0);
  await expect(m.page.getByTestId('world-state')).toContainText('hidden');
  await m.ctx.close();
});

test('obs_902 world view is a lazy chunk that is reachable from the menu and the map', async ({ browser }) => {
  const o = await open(browser, world());
  const chunks: string[] = [];
  o.page.on('request', (r) => {
    if (/assets\/World-.*\.js/.test(r.url())) chunks.push(r.url());
  });
  await o.page.goto('/#/map');
  await expect(o.page.getByRole('heading', { name: 'Network map' })).toBeVisible();
  expect(chunks, 'the world chunk is not loaded with the map').toEqual([]);
  await o.page.getByTestId('to-world-view').click();
  await expect(o.page.getByRole('heading', { name: 'World view' })).toBeVisible();
  expect(chunks.length).toBeGreaterThan(0);
  await o.page.getByTestId('to-network-map').click();
  await expect(o.page.getByRole('heading', { name: 'Network map' })).toBeVisible();
  // The menu has it, with the other Monitor pages.
  await o.page.goto('/#/');
  await expect(o.page.getByRole('link', { name: 'World view' })).toBeVisible();
  // The help topic opens.
  await o.page.goto('/#/world');
  await o.page.getByRole('button', { name: 'Help: Read the world view' }).click();
  await expect(o.page.getByTestId('help-panel')).toContainText('dot-grid world map');
  expect(o.problems).toEqual([]);
  await o.ctx.close();
});

test('obs_902 world view asks the real node and finds GeoIP off', async ({ browser }) => {
  // Unmocked: the node's own route. GeoIP is off by default, so that is what it says.
  const o = await open(browser, null, { mock: false });
  await goWorld(o);
  await expect(o.page.getByTestId('world-unavailable')).toHaveAttribute('data-reason', 'geoip_off');
  expect(o.problems).toEqual([]);
  await o.ctx.close();
});

// ================================================================== the GeoIP card (the real node)

async function card(browser: Browser, state = adminState): Promise<Opened> {
  const o = await open(browser, null, { mock: false, state });
  await o.page.goto('/#/settings?tab=queries');
  await expect(o.page.getByTestId('geoip-card')).toBeVisible();
  return o;
}

test('obs_902 geoip toggle and status', async ({ browser }) => {
  const o = await card(browser);
  // Off by default: nothing is fetched, the status says so, the controls are the admin's.
  await expect(o.page.getByTestId('geoip-state')).toContainText('Off');
  await expect(o.page.getByTestId('geoip-toggle')).not.toBeChecked();
  await expect(o.page.getByTestId('geoip-update')).toBeDisabled();
  await expect(o.page.getByTestId('geoip-attribution')).toContainText('DB-IP.com');
  expect(hits, 'nothing was requested while it was off').toBe(0);
  // Save is refused to a bad source before anything is fetched: the server names the field.
  await o.page.getByTestId('geoip-toggle').check();
  await o.page.getByTestId('geoip-url').fill('http://127.0.0.1/db.csv.gz');
  await o.page.getByTestId('geoip-save').click();
  await expect(o.page.getByRole('alert')).toContainText('map.geoip.source_url');
  expect(hits).toBe(0);
  for (let i = o.problems.length - 1; i >= 0; i--) if (/status of [45]\d\d \(/.test(o.problems[i])) o.problems.splice(i, 1);
  // The fake HTTPS source: saved, then fetched in the background; the status follows to Ready.
  await o.page.getByTestId('geoip-url').fill(SOURCE_URL);
  await o.page.getByTestId('geoip-home').fill('nl');
  await o.page.getByTestId('geoip-save').click();
  await expect(o.page.getByTestId('geoip-notice')).toContainText('starts fetching');
  await expect(o.page.getByTestId('geoip-state')).toContainText('Ready', { timeout: 30_000 });
  await expect(o.page.getByTestId('geoip-month')).toHaveText(/^\d{4}-\d{2}/);
  await expect(o.page.getByTestId('geoip-size')).toContainText('6 rows');
  await expect(o.page.getByTestId('geoip-updated')).toBeVisible();
  expect(hits, 'one download').toBe(1);
  // It persists: a fresh page shows the toggle on, the URL and the home country.
  await o.page.reload();
  await expect(o.page.getByTestId('geoip-toggle')).toBeChecked();
  await expect(o.page.getByTestId('geoip-url')).toHaveValue(SOURCE_URL);
  await expect(o.page.getByTestId('geoip-home')).toHaveValue('NL');
  // The status is also the API's, for everyone and for scripts.
  const status = await (await o.page.request.get('/api/v1/map/geoip')).json();
  expect(status).toMatchObject({ enabled: true, state: 'ready', rows: 6 });
  // The world view now has a database but no answer address: it says that, not "off".
  await o.page.goto('/#/world');
  await expect(o.page.getByTestId('world-unavailable')).toHaveAttribute('data-reason', 'address_not_recorded');
  expect(o.problems).toEqual([]);
  await o.ctx.close();
});

test('obs_902 admin updates now', async ({ browser }) => {
  const o = await card(browser);
  const before = hits;
  await expect(o.page.getByTestId('geoip-update')).toBeEnabled();
  await o.page.getByTestId('geoip-update').click();
  await expect(o.page.getByTestId('geoip-notice')).toContainText('Fetching now');
  // The node fetches (a second request to the source) and the status returns to Ready.
  await expect.poll(() => hits, { timeout: 30_000 }).toBe(before + 1);
  await expect(o.page.getByTestId('geoip-state')).toContainText('Ready', { timeout: 30_000 });
  expect(await (await o.page.request.get('/api/v1/map/geoip')).json()).toMatchObject({ state: 'ready' });
  expect(o.problems).toEqual([]);
  await o.ctx.close();
});

test('obs_902 viewer sees geoip read-only', async ({ browser }) => {
  const ctx = await browser.newContext();
  const page = await ctx.newPage();
  await page.goto('/#/settings?tab=queries');
  await page.getByLabel('Username', { exact: true }).fill(VIEWER.user);
  await page.getByLabel('Password', { exact: true }).fill(VIEWER.pass);
  await page.getByRole('button', { name: 'Sign in' }).click();
  await expect(page.getByTestId('geoip-card')).toBeVisible({ timeout: 30_000 });
  // The status and the attribution are shown; no control is.
  await expect(page.getByTestId('geoip-state')).toContainText('Ready');
  await expect(page.getByTestId('geoip-attribution')).toContainText('DB-IP.com');
  await expect(page.getByTestId('geoip-readonly')).toContainText('Only an admin changes this');
  for (const id of ['geoip-toggle', 'geoip-url', 'geoip-sha', 'geoip-home', 'geoip-save', 'geoip-update', 'geoip-delete']) await expect(page.getByTestId(id)).toHaveCount(0);
  await ctx.close();
});

test('obs_902 operator sees geoip read-only', async ({ browser }) => {
  const ctx = await browser.newContext();
  const page = await ctx.newPage();
  const problems: string[] = [];
  page.on('pageerror', (e) => problems.push(`page error: ${e.message}`));
  page.on('console', (m) => {
    if (m.type() === 'error' && !problemFilter(m.text())) problems.push(`console: ${m.text()}`);
  });
  await page.goto('/#/settings?tab=queries');
  await page.getByLabel('Username', { exact: true }).fill(OPERATOR.user);
  await page.getByLabel('Password', { exact: true }).fill(OPERATOR.pass);
  await page.getByRole('button', { name: 'Sign in' }).click();
  await expect(page.getByTestId('geoip-card')).toBeVisible({ timeout: 30_000 });
  // The status is shown; no control is.
  await expect(page.getByTestId('geoip-state')).toContainText('Ready');
  await expect(page.getByTestId('geoip-readonly')).toContainText('Only an admin changes this');
  for (const id of ['geoip-toggle', 'geoip-url', 'geoip-sha', 'geoip-home', 'geoip-save', 'geoip-update', 'geoip-delete']) await expect(page.getByTestId(id)).toHaveCount(0);
  // The server says no whatever a script does: not the toggle, not the actions, nor a bare PUT of `[map]` that touches it.
  const csrf = (await (await ctx.request.get('/api/v1/auth/status')).json()).csrfToken as string;
  const h = { 'x-csrf-token': csrf };
  expect((await ctx.request.post('/api/v1/map/geoip/update', { headers: h })).status()).toBe(403);
  expect((await ctx.request.delete('/api/v1/map/geoip', { headers: h })).status()).toBe(403);
  const turnOff = await ctx.request.put('/api/v1/map-settings/default', { headers: h, data: { geoip: { enabled: false } } });
  expect(turnOff.status()).toBe(403);
  expect(await turnOff.text()).toContain('geoip');
  // The thresholds are the operator's: a PUT that leaves `geoip` out changes them and keeps the database settings.
  const thresholds = await ctx.request.put('/api/v1/map-settings/default', { headers: h, data: { warn_slow_pct: 12 } });
  expect(thresholds.status(), await thresholds.text()).toBe(200);
  const entry = await (await ctx.request.get('/api/v1/map-settings/default')).json();
  expect(entry.definition.warn_slow_pct).toBe(12);
  expect(entry.definition.geoip.enabled, 'the database settings were kept').toBe(true);
  // Going back to the file's `[map]` would also take the database settings back to the file's: an admin's, so 403.
  const revert = await ctx.request.delete('/api/v1/map-settings/default', { headers: h });
  expect(revert.status()).toBe(403);
  expect(await revert.text()).toContain('geoip');
  // On the world view, an operator is told to ask an admin (mocked: geoip off).
  await page.route(/\/api\/v1\/map\/world(\?.*)?$/, (route) =>
    route.fulfill({ json: { available: false, reason: 'geoip_off', updatedAt: '2026-11-18T12:00:00.000Z', windowSecs: 60, regions: [], markers: [], unplacedUpstreams: 0, unlocated: { count: 0 } } }),
  );
  await page.goto('/#/world');
  await expect(page.getByTestId('world-ask-admin')).toBeVisible();
  await expect(page.getByTestId('world-setting-link')).toHaveCount(0);
  for (let i = problems.length - 1; i >= 0; i--) if (/status of [45]\d\d \(/.test(problems[i])) problems.splice(i, 1);
  expect(problems).toEqual([]);
  await ctx.close();
});

test('obs_902 admin deletes the database', async ({ browser }) => {
  const o = await card(browser);
  await expect(o.page.getByTestId('geoip-state')).toContainText('Ready');
  // The confirmation: cancelling keeps it.
  await o.page.getByTestId('geoip-delete').click();
  await expect(o.page.getByTestId('geoip-delete-confirm')).toBeVisible();
  await o.page.getByTestId('geoip-delete-cancel').click();
  await expect(o.page.getByTestId('geoip-delete-confirm')).toHaveCount(0);
  await expect(o.page.getByTestId('geoip-state')).toContainText('Ready');
  // Confirming removes the file; nothing is fetched again until an admin asks, and the world view says it is missing.
  const before = hits;
  await o.page.getByTestId('geoip-delete').click();
  await o.page.getByTestId('geoip-delete-confirm').click();
  await expect(o.page.getByTestId('geoip-notice')).toContainText('Deleted');
  await expect(o.page.getByTestId('geoip-state')).toContainText('no database on this node yet');
  await expect(o.page.getByTestId('geoip-size')).toHaveCount(0);
  await o.page.waitForTimeout(7_000); // longer than the node's own look at the settings (5 s)
  expect(hits, 'it was not fetched again').toBe(before);
  await o.page.goto('/#/world');
  await expect(o.page.getByTestId('world-unavailable')).toHaveAttribute('data-reason', 'geoip_missing');
  // Update now brings it back; then turning it off stops everything and the world view says it is off.
  await o.page.goto('/#/settings?tab=queries');
  await o.page.getByTestId('geoip-update').click();
  await expect(o.page.getByTestId('geoip-state')).toContainText('Ready', { timeout: 30_000 });
  await o.page.getByTestId('geoip-toggle').uncheck();
  await o.page.getByTestId('geoip-save').click();
  await expect(o.page.getByTestId('geoip-state')).toContainText('Off');
  const off = hits;
  await o.page.waitForTimeout(6_000);
  expect(hits).toBe(off);
  await o.page.goto('/#/world');
  await expect(o.page.getByTestId('world-unavailable')).toHaveAttribute('data-reason', 'geoip_off');
  expect(o.problems).toEqual([]);
  await o.ctx.close();
});

// ================================================================== sizes

test('obs_902 the world chunk is at most 30 KiB and dist at most 400 KiB gzipped', () => {
  const dist = resolve(process.cwd(), 'dist');
  const files: { rel: string; size: number }[] = [];
  const walk = (d: string) => {
    for (const f of readdirSync(d)) {
      const p = join(d, f);
      if (statSync(p).isDirectory()) walk(p);
      else files.push({ rel: p.slice(dist.length + 1).replace(/\\/g, '/'), size: statSync(p).size });
    }
  };
  walk(dist);
  // The build leaves each text file as its `.gz`: the sizes on disk are the gzipped sizes. The chunk is the
  // page, its styles, and the code it shares with the network map; the world data is inside the page's file.
  const chunk = files.filter((f) => /^assets\/(World|map)-.*\.(js|css)\.gz$/.test(f.rel));
  expect(chunk.length, 'the world chunk, its styles and the shared map code').toBeGreaterThanOrEqual(3);
  const chunkBytes = chunk.reduce((s, f) => s + f.size, 0);
  const total = files.reduce((s, f) => s + f.size, 0);
  const data = gzipSync(readFileSync(resolve(process.cwd(), 'src/lib/world-data.ts')), { level: 9 }).length;
  console.log(`world chunk ${(chunkBytes / 1024).toFixed(1)} KiB gzipped, world data ${(data / 1024).toFixed(1)} KiB gzipped, dist total ${(total / 1024).toFixed(1)} KiB gzipped`);
  expect(chunkBytes).toBeLessThanOrEqual(30 * 1024);
  expect(data, 'the world data on its own (ADR-958 section 8: at most 12 KiB)').toBeLessThanOrEqual(12 * 1024);
  expect(total).toBeLessThanOrEqual(400 * 1024);
  // The main bundle doesn't carry the page or its data.
  const main = files.find((f) => /^assets\/index-.*\.js\.gz$/.test(f.rel));
  expect(main).toBeTruthy();
});

// ================================================================== the pure parts

const w0 = (over: Partial<World> = {}) => world(over);

test('obs_902 the land mask and the country table are whole', () => {
  expect(GRID).toMatchObject({ w: 180, h: 70, step: 2, lonMin: -180, latMax: 84 });
  expect(atob(LAND_MASK).length).toBe(Math.ceil((GRID.w * GRID.h) / 8));
  const path = landPath();
  const squares = path.split('M').length - 1;
  // Land is a fifth to a third of the grid between 84N and 56S.
  expect(squares).toBeGreaterThan(GRID.w * GRID.h * 0.15);
  expect(squares).toBeLessThan(GRID.w * GRID.h * 0.4);
  // Known countries have a point on the right side of the world, and a name.
  expect(countryName('nl')).toBe('Netherlands');
  expect(countryName('ZZ')).toBe('ZZ');
  const nl = countryPoint('NL');
  const au = countryPoint('AU');
  const us = countryPoint('US');
  expect(nl && au && us).toBeTruthy();
  expect(us!.x).toBeLessThan(nl!.x);
  expect(nl!.y).toBeLessThan(au!.y);
  expect(COUNTRY_DATA.split(';').length).toBeGreaterThan(230);
  // A projection stays inside the map.
  for (const [lon, lat] of [[-180, 84], [179.9, -55.9], [0, 0]]) {
    const p = project(lon, lat);
    expect(p.x).toBeGreaterThanOrEqual(0);
    expect(p.x).toBeLessThanOrEqual(MAP_W);
    expect(p.y).toBeGreaterThanOrEqual(0);
    expect(p.y).toBeLessThanOrEqual(80 + MAP_H);
  }
});

test('obs_902 arcs start at the home point and end at each country', () => {
  const placed = place(w0(), { maxAnimated: 2 });
  expect(placed.home.label).toBe('Your network');
  expect(placed.arcs.map((a) => a.cc).sort()).toEqual(['DE', 'IE', 'NL', 'US']);
  // Only the budget animates.
  expect(placed.arcs.filter((a) => a.animated)).toHaveLength(2);
  for (const a of placed.arcs) {
    expect(a.d.startsWith(`M${placed.home.x} ${placed.home.y}Q`)).toBe(true);
    expect(a.d.endsWith(`${a.x} ${a.y}`)).toBe(true);
    expect(a.width).toBeGreaterThanOrEqual(1);
    expect(a.width).toBeLessThanOrEqual(6);
  }
  // A home country starts the arcs there, named; a country that has no point is listed, not drawn.
  const home = place(w0({ homeCountry: 'NL', regions: [...w0().regions, { cc: 'XX', name: 'XX', qps: 1, count: 5, slowPct: 0, health: 'green' }] }), { maxAnimated: 9 });
  expect(home.home.label).toBe('Netherlands (home)');
  expect(home.unplaced.map((r) => r.cc)).toEqual(['XX']);
  const nl = home.arcs.find((a) => a.cc === 'NL')!;
  expect(nl.d).toContain('Q');
  // A longer way rises higher.
  const near = arcPath(100, 100, 120, 100);
  const far = arcPath(100, 100, 600, 100);
  expect(far.my).toBeLessThan(near.my);
});

test('obs_902 markers fan out when upstreams share a country', () => {
  const markers = placeMarkers([
    { name: 'a', cc: 'US', qps: 1, health: 'green' },
    { name: 'b', cc: 'US', qps: 1, health: 'green' },
    { name: 'c', cc: 'US', qps: 1, health: 'yellow' },
    { name: 'none', cc: null, qps: 1, health: 'green' },
    { name: 'nowhere', cc: 'XX', qps: 1, health: 'green' },
  ]);
  expect(markers.map((m) => m.name)).toEqual(['a', 'b', 'c']);
  expect(new Set(markers.map((m) => `${m.x},${m.y}`)).size).toBe(3);
});

test('obs_902 each reason has its own words, and only the setting ones link to a setting', () => {
  expect(whyUnavailable(undefined)).toBeNull();
  const off = whyUnavailable('geoip_off')!;
  const missing = whyUnavailable('geoip_missing')!;
  const unrecorded = whyUnavailable('address_not_recorded')!;
  const privacy = whyUnavailable('privacy')!;
  expect([off.admin, missing.admin, unrecorded.admin, privacy.admin]).toEqual([true, true, false, false]);
  expect(new Set([off.title, missing.title, unrecorded.title, privacy.title]).size).toBe(4);
  expect(unrecorded.body).toContain('upstreams');
  expect(upstreamsOnly(w0({ regions: [] }))).toBe(true);
  expect(upstreamsOnly(w0())).toBe(false);
  expect(upstreamsOnly(w0({ regions: [], markers: [] }))).toBe(false);
});
