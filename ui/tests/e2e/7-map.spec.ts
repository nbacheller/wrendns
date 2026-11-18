// REQ: OBS-901, API-005 (T26.3, ADR-958, ADR-970) — the network map page. The e2e server has no real
// traffic, so snapshots are mocked with `page.route` (the map's data API is tested against a real
// node in `crates/telltale-api`), and the stream is a fake `EventSource` the test drives; one run
// at the end opens the page against the node's own stream and snapshot. These tests sign in as the
// admin `1-ui.spec.ts` created, so run the whole suite, not this file alone.
import { expect, test, type Browser, type BrowserContext, type Page, type Route } from '@playwright/test';
import { readdirSync, statSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { NO_FILTERS, animatedBudget, filterSnapshot, flowRows, layout, links, pulse, seed, via, type Snapshot } from '../../src/lib/map';

test.describe.configure({ mode: 'serial' });

const ADMIN = { user: 'admin', pass: 'correct horse battery' };

type N = Snapshot['nodes'][number];
type E = Snapshot['edges'][number];

const node = (id: string, kind: N['kind'], label: string, health: N['health'] = 'green', extra: Partial<N> = {}): N => ({
  id,
  kind,
  label,
  health,
  reasons: health === 'red' ? [{ code: 'error_rate', summary: '40% of 50 answers failed' }] : health === 'yellow' ? [{ code: 'slow', summary: '20% of answers were slow' }] : health === 'idle' ? [{ code: 'few_samples', summary: 'too few answers to say' }] : [],
  qps: 1,
  count: 60,
  sampled: 60,
  ...extra,
});
const edge = (from: string, to: string, qps: number, health: E['health'] = 'green', extra: Partial<E> = {}): E => ({ from, to, structural: false, qps, count: Math.round(qps * 60), slowPct: 0, errPct: 0, blockedPct: 0, health, ...extra });
const structural = (from: string, to: string): E => edge(from, to, 0, 'idle', { structural: true });

const dev = (ip: string, name: string, network: string, group: string, health: N['health'], qps = 2, extra: Partial<N> = {}) =>
  node(`dev:${ip}`, 'device', name, health, { address: ip, network, group, qps, ...extra });

function fixture(over: Partial<Snapshot> = {}): Snapshot {
  const nodes: N[] = [
    node('gateway', 'gateway', 'Gateway', 'green'),
    node('net:lan', 'network', 'lan', 'green', { qps: 0 }),
    node('net:iot', 'network', 'iot', 'yellow', { qps: 0 }),
    dev('192.168.1.10', 'laptop', 'lan', 'adults', 'green', 5),
    dev('192.168.1.11', 'tv', 'lan', 'kids', 'yellow', 3),
    dev('10.20.2.5', 'camera', 'iot', 'iot', 'red', 1),
    dev('10.20.2.6', 'bulb', 'iot', 'iot', 'idle', 0.1),
    node('more:iot', 'more', '+12 more', 'idle', { network: 'iot', folded: 12, qps: 2 }),
    node('res:node-a', 'resolver', 'node-a', 'yellow', { node: 'node-a', qps: 11 }),
    node('ans:node-a:cache', 'answer', 'cache', 'green', { node: 'node-a', qps: 6 }),
    node('ans:node-a:local', 'answer', 'local', 'green', { node: 'node-a', qps: 1 }),
    node('ans:node-a:blocked', 'answer', 'blocked', 'green', { node: 'node-a', qps: 2 }),
    node('up:cloudflare', 'upstream', 'cloudflare', 'green', { qps: 4 }),
    node('up:google', 'upstream', 'google', 'red', { qps: 1 }),
  ];
  const edges: E[] = [
    structural('gateway', 'net:lan'),
    structural('gateway', 'net:iot'),
    structural('net:lan', 'dev:192.168.1.10'),
    structural('net:lan', 'dev:192.168.1.11'),
    structural('net:iot', 'dev:10.20.2.5'),
    structural('net:iot', 'dev:10.20.2.6'),
    structural('net:iot', 'more:iot'),
    edge('dev:192.168.1.10', 'res:node-a', 5, 'green'),
    edge('dev:192.168.1.11', 'res:node-a', 3, 'yellow', { slowPct: 20 }),
    edge('dev:10.20.2.5', 'res:node-a', 1, 'red', { errPct: 40, recent: [{ tsUnixMicros: 1_790_000_000_000_000, totalMs: 5000, status: 'forwarded' }] }),
    edge('dev:10.20.2.6', 'res:node-a', 0.1, 'idle'),
    edge('more:iot', 'res:node-a', 2, 'idle'),
    edge('res:node-a', 'ans:node-a:cache', 6, 'green'),
    edge('res:node-a', 'ans:node-a:local', 1, 'green'),
    edge('res:node-a', 'ans:node-a:blocked', 2, 'green'),
    edge('res:node-a', 'up:cloudflare', 4, 'green'),
    edge('res:node-a', 'up:google', 1, 'red', { errPct: 40 }),
  ];
  return {
    generatedAt: '2026-11-18T12:00:00Z',
    windowSecs: 60,
    sampleRate: 1,
    dropped: 0,
    privacy: 0,
    truncated: false,
    partial: false,
    missingNodes: [],
    health: 'red',
    counts: { green: 7, yellow: 3, red: 2, idle: 3 },
    nodes,
    edges,
    ...over,
  };
}

// What the server does with `network`, `group` and `device`.
function narrowed(s: Snapshot, q: URLSearchParams): Snapshot {
  const network = q.get('network');
  const group = q.get('group');
  const device = q.get('device');
  if (!network && !group && !device) return s;
  const keep = new Set<string>();
  for (const n of s.nodes) {
    if (n.kind === 'device' || n.kind === 'more') {
      if (network && n.network !== network) continue;
      if (group && n.group !== group) continue;
      if (device && !(n.label.includes(device) || (n.address ?? '').includes(device))) continue;
      keep.add(n.id);
    }
  }
  for (const n of s.nodes) {
    if (['resolver', 'answer', 'upstream', 'gateway'].includes(n.kind)) keep.add(n.id);
    if (n.kind === 'network' && s.edges.some((e) => e.from === n.id && keep.has(e.to))) keep.add(n.id);
  }
  return { ...s, nodes: s.nodes.filter((n) => keep.has(n.id)), edges: s.edges.filter((e) => keep.has(e.from) && keep.has(e.to)) };
}

// The browser side: a fake stream for `/api/v1/map/stream` the test drives, and a page visibility
// the test sets. Nothing else is replaced.
const INIT = () => {
  const made: unknown[] = [];
  (window as unknown as { __es: unknown[] }).__es = made;
  const Real = window.EventSource;
  class Fake {
    static CONNECTING = 0;
    static OPEN = 1;
    static CLOSED = 2;
    readyState = 1;
    url: string;
    onerror: (() => void) | null = null;
    onopen: (() => void) | null = null;
    listeners: Record<string, ((m: { data: string }) => void)[]> = {};
    constructor(url: string) {
      this.url = url;
      made.push(this);
    }
    addEventListener(t: string, f: (m: { data: string }) => void) {
      (this.listeners[t] ??= []).push(f);
    }
    close() {
      this.readyState = 2;
    }
  }
  function Wrapper(this: unknown, url: string, init?: EventSourceInit) {
    return String(url).includes('/map/stream') ? new Fake(url) : new Real(url, init);
  }
  Wrapper.CONNECTING = 0;
  Wrapper.OPEN = 1;
  Wrapper.CLOSED = 2;
  (window as unknown as { EventSource: unknown }).EventSource = Wrapper;
  (window as unknown as { __emit: (s: unknown) => void }).__emit = (s) => {
    for (const es of made as InstanceType<typeof Fake>[]) if (es.readyState !== 2) for (const f of es.listeners.snapshot ?? []) f({ data: JSON.stringify(s) });
  };
  (window as unknown as { __vis: string }).__vis = 'visible';
  Object.defineProperty(document, 'visibilityState', { configurable: true, get: () => (window as unknown as { __vis: string }).__vis });
  Object.defineProperty(document, 'hidden', { configurable: true, get: () => (window as unknown as { __vis: string }).__vis === 'hidden' });
};

let state: Awaited<ReturnType<BrowserContext['storageState']>>;

test.beforeAll(async ({ browser }) => {
  const ctx = await browser.newContext();
  const page = await ctx.newPage();
  await page.goto('/');
  await page.getByLabel('Username', { exact: true }).fill(ADMIN.user);
  await page.getByLabel('Password', { exact: true }).fill(ADMIN.pass);
  await page.getByRole('button', { name: 'Sign in' }).click();
  await expect(page.getByRole('heading', { name: 'Dashboard' })).toBeVisible({ timeout: 30_000 });
  state = await ctx.storageState();
  await ctx.close();
});

interface Opened {
  page: Page;
  ctx: BrowserContext;
  problems: string[];
  requests: string[];
  current: { snap: Snapshot; status: number };
}

/** A signed-in page with the map's data mocked; `open('#/map?...')` loads it. */
async function open(browser: Browser, snap: Snapshot = fixture(), opts: { reducedMotion?: 'reduce' | 'no-preference'; colorScheme?: 'dark' | 'light' } = {}): Promise<Opened> {
  const ctx = await browser.newContext({ storageState: state, reducedMotion: opts.reducedMotion, colorScheme: opts.colorScheme });
  const page = await ctx.newPage();
  const problems: string[] = [];
  page.on('pageerror', (e) => problems.push(`page error: ${e.message}`));
  page.on('console', (m) => {
    if (m.type() === 'error' && !/status of (40[134]|429) \(/.test(m.text())) problems.push(`console: ${m.text()}`);
  });
  await page.addInitScript(INIT);
  const o: Opened = { page, ctx, problems, requests: [], current: { snap, status: 200 } };
  await page.route(/\/api\/v1\/map(\?.*)?$/, async (route: Route) => {
    const url = new URL(route.request().url());
    o.requests.push(url.search);
    if (o.current.status !== 200) {
      await route.fulfill({ status: o.current.status, contentType: 'application/problem+json', body: JSON.stringify({ type: 'about:blank', title: 'The map is off', status: o.current.status, code: 'map_disabled' }) });
      return;
    }
    await route.fulfill({ json: narrowed(o.current.snap, url.searchParams) });
  });
  return o;
}
const go = async (o: Opened, hash = '#/map') => {
  await o.page.goto(`/${hash}`);
  await expect(o.page.getByRole('heading', { name: 'Network map' })).toBeVisible();
};
const emit = (o: Opened, s: Snapshot) => o.page.evaluate((x) => (window as unknown as { __emit: (s: unknown) => void }).__emit(x), s);
const running = (page: Page) =>
  page.evaluate(() => document.getAnimations().filter((a) => (a.effect as KeyframeEffect | null)?.target?.classList?.contains('pulse') && a.playState === 'running').length);
const paused = (page: Page) =>
  page.evaluate(() => document.getAnimations().filter((a) => (a.effect as KeyframeEffect | null)?.target?.classList?.contains('pulse') && a.playState === 'paused').length);

test('obs_901 layout shows gateway networks devices nodes upstreams', async ({ browser }) => {
  const o = await open(browser);
  await go(o);
  const figure = o.page.getByTestId('map-figure');
  await expect(figure).toBeVisible();
  // Every kind is drawn, once per node of the snapshot.
  const counts: Record<string, number> = {};
  for (const k of ['gateway', 'network', 'device', 'more', 'resolver', 'answer', 'upstream']) counts[k] = await o.page.locator(`[data-node][data-kind="${k}"]`).count();
  expect(counts).toEqual({ gateway: 1, network: 2, device: 4, more: 1, resolver: 1, answer: 3, upstream: 2 });
  // The columns run left to right: gateway, networks, devices, resolvers, answers and upstreams.
  const x = async (id: string) => {
    const t = (await o.page.locator(`[data-node="${id}"]`).getAttribute('transform')) ?? '';
    return Number(/translate\(([\d.-]+)/.exec(t)?.[1]);
  };
  const xs = [await x('gateway'), await x('net:lan'), await x('dev:192.168.1.10'), await x('res:node-a'), await x('ans:node-a:cache'), await x('up:google')];
  expect(xs[0]).toBeLessThan(xs[1]);
  expect(xs[1]).toBeLessThan(xs[2]);
  expect(xs[2]).toBeLessThan(xs[3]);
  expect(xs[3]).toBeLessThan(xs[4]);
  expect(xs[4]).toBe(xs[5]);
  // The figure is a group with a label and a text summary, not an image (its nodes stay reachable).
  await expect(figure).toHaveAttribute('role', 'group');
  await expect(o.page.getByTestId('map-summary')).toContainText('2 networks');
  await expect(o.page.locator('svg[role="img"], figure[role="img"]')).toHaveCount(0);
  // The summary figure's flow lines: one per edge with a rate.
  await expect(o.page.locator('[data-flow]')).toHaveCount(10);
  // Fork #25: a node's reasons are its tooltip (an upstream with no route says why there); a node
  // with none has no tooltip.
  await expect(o.page.locator('[data-node="up:google"] title')).toContainText('40% of 50 answers failed');
  await expect(o.page.locator('[data-node="up:cloudflare"] title')).toHaveCount(0);
  expect(o.problems).toEqual([]);
  await o.ctx.close();
});

test('obs_901 colour states have shape and words', async ({ browser }) => {
  const o = await open(browser);
  await go(o);
  const shapes = new Set<string>();
  const want: Record<string, { word: string; aria: string }> = {
    green: { word: 'OK', aria: 'healthy' },
    yellow: { word: 'Warning', aria: 'degraded' },
    red: { word: 'Failing', aria: 'failing' },
    idle: { word: 'Idle', aria: 'idle' },
  };
  for (const [h, w] of Object.entries(want)) {
    const g = o.page.locator(`[data-node][data-health="${h}"]`).first();
    await expect(g, `a ${h} node`).toBeVisible();
    // The word is drawn on the node and spoken by its label, and its shape is its own.
    await expect(g.locator('.nstate')).toContainText(w.word);
    await expect(g).toHaveAttribute('aria-label', new RegExp(w.aria));
    shapes.add((await g.locator('.shape').getAttribute('d')) ?? '');
  }
  expect(shapes.size).toBe(4);
  // The legend names the four, with their shapes.
  for (const w of Object.values(want)) await expect(o.page.getByLabel('Legend')).toContainText(w.word);
  // Fork #25: no legend icon is giant (an unscoped `svg` rule once sized them like the map).
  const icons = o.page.getByLabel('Legend').locator('svg');
  expect(await icons.count()).toBe(4);
  for (const box of await icons.evaluateAll((els) => els.map((e) => e.getBoundingClientRect().toJSON()))) {
    expect(box.width, 'legend icon width').toBeGreaterThan(0);
    expect(box.width, 'legend icon width').toBeLessThan(24);
    expect(box.height, 'legend icon height').toBeLessThan(24);
  }
  expect(o.problems).toEqual([]);
  await o.ctx.close();
});

/** WCAG contrast ratio of two `rgb()` strings. */
const luminance = (rgb: string) => {
  const c = (rgb.match(/[\d.]+/g) ?? ['0', '0', '0']).slice(0, 3).map((v) => {
    const s = Number(v) / 255;
    return s <= 0.03928 ? s / 12.92 : ((s + 0.055) / 1.055) ** 2.4;
  });
  return 0.2126 * c[0] + 0.7152 * c[1] + 0.0722 * c[2];
};
const contrast = (a: string, b: string) => {
  const [x, y] = [luminance(a), luminance(b)].sort((p, q) => q - p);
  return (x + 0.05) / (y + 0.05);
};

for (const scheme of ['light', 'dark'] as const) {
  test(`obs_901 colours pass AA in the ${scheme} theme`, async ({ browser }) => {
    const o = await open(browser, fixture(), { colorScheme: scheme });
    await go(o);
    await expect(o.page.locator('[data-node]').first()).toBeVisible();
    const read = (sel: string, prop: string) => o.page.locator(sel).first().evaluate((el, p) => getComputedStyle(el).getPropertyValue(p), prop);
    const surface = await read('.node rect', 'fill');
    // Text (labels, the muted line) at 4.5:1; shapes, node outlines and pulses at 3:1 (WCAG 1.4.11).
    expect(contrast(await read('.nlabel', 'fill'), surface), 'label').toBeGreaterThanOrEqual(4.5);
    expect(contrast(await read('.nstate', 'fill'), surface), 'state line').toBeGreaterThanOrEqual(4.5);
    for (const h of ['green', 'yellow', 'red', 'idle']) {
      expect(contrast(await read(`.node.${h} .shape`, 'stroke'), surface), `${h} shape`).toBeGreaterThanOrEqual(3);
      expect(contrast(await read(`.node.${h} rect`, 'stroke'), surface), `${h} outline`).toBeGreaterThanOrEqual(3);
      expect(contrast(await read(`.pulse.${h}`, 'stroke'), surface), `${h} pulse`).toBeGreaterThanOrEqual(3);
    }
    expect(o.problems).toEqual([]);
    await o.ctx.close();
  });
}

test('obs_901 filters narrow the map', async ({ browser }) => {
  const o = await open(browser);
  await go(o);
  await expect(o.page.locator('[data-node][data-kind="device"]')).toHaveCount(4);
  // A network: sent to the server, kept in the URL, and only its devices are drawn.
  await o.page.getByTestId('filter-network').selectOption('iot');
  await expect(o.page).toHaveURL(/#\/map\?network=iot/);
  await expect(o.page.locator('[data-node="dev:10.20.2.5"]')).toBeVisible();
  await expect(o.page.locator('[data-node="dev:192.168.1.10"]')).toHaveCount(0);
  expect(o.requests.some((r) => r.includes('network=iot'))).toBe(true);
  await expect(o.page.locator('[data-node="net:lan"]')).toHaveCount(0);
  // The map polls while a server filter is set: the stream carries everything.
  await expect(o.page.getByTestId('map-state')).toHaveAttribute('data-stream', 'polling');
  // A group, then a device's name.
  await o.page.getByTestId('filter-group').selectOption('iot');
  await expect(o.page).toHaveURL(/group=iot/);
  await o.page.getByTestId('filter-network').selectOption('');
  await o.page.getByTestId('filter-group').selectOption('');
  await o.page.getByTestId('filter-device').fill('cam');
  await expect(o.page).toHaveURL(/device=cam/);
  await expect(o.page.locator('[data-node][data-kind="device"]')).toHaveCount(1);
  expect(o.requests.some((r) => r.includes('device=cam'))).toBe(true);
  // The box follows the URL when it changes elsewhere (back/forward, a link).
  await o.page.evaluate(() => { location.hash = '#/map?device=cam2'; });
  await expect(o.page.getByTestId('filter-device')).toHaveValue('cam2');
  await o.page.evaluate(() => { location.hash = '#/map?device=cam'; });
  await expect(o.page.getByTestId('filter-device')).toHaveValue('cam');
  // Clear: everything is back, and the stream again.
  await o.page.getByTestId('filter-clear').click();
  await expect(o.page.locator('[data-node][data-kind="device"]')).toHaveCount(4);
  await expect(o.page.getByTestId('map-state')).toHaveAttribute('data-stream', 'connecting');
  // A state: drawn on this side (the failing devices and what they connect to), not sent.
  const before = o.requests.length;
  await o.page.getByTestId('filter-health').selectOption('red');
  await expect(o.page).toHaveURL(/health=red/);
  await expect(o.page.locator('[data-node="dev:10.20.2.5"]')).toBeVisible();
  await expect(o.page.locator('[data-node="dev:192.168.1.10"]')).toHaveCount(0);
  expect(o.requests.slice(before).every((r) => !r.includes('health'))).toBe(true);
  // A filter in the URL is applied on load.
  await go(o, '#/map?network=lan');
  await expect(o.page.locator('[data-node="dev:192.168.1.11"]')).toBeVisible();
  await expect(o.page.locator('[data-node="dev:10.20.2.5"]')).toHaveCount(0);
  await expect(o.page.getByTestId('filter-network')).toHaveValue('lan');
  expect(o.problems).toEqual([]);
  await o.ctx.close();
});

test('obs_901 click through opens queries and explain', async ({ browser }) => {
  const o = await open(browser);
  await go(o);
  await o.page.locator('[data-node="dev:192.168.1.10"]').click();
  const panel = o.page.getByTestId('node-panel');
  await expect(panel).toContainText('laptop');
  await expect(panel.getByTestId('panel-address')).toHaveText('192.168.1.10');
  await panel.getByTestId('to-queries').click();
  await expect(o.page).toHaveURL(/#\/queries\?client=192\.168\.1\.10/);
  await expect(o.page.getByRole('heading', { name: 'Query log' })).toBeVisible();
  await o.page.goBack();
  await o.page.locator('[data-node="dev:192.168.1.10"]').click();
  await o.page.getByTestId('to-explain').click();
  await expect(o.page).toHaveURL(/#\/explain\?client=192\.168\.1\.10/);
  await expect(o.page.getByRole('heading', { name: 'Explain' })).toBeVisible();
  await o.page.goBack();
  await o.page.locator('[data-node="dev:192.168.1.10"]').click();
  await o.page.getByTestId('to-anomalies').click();
  await expect(o.page).toHaveURL(/#\/anomalies\?client=192\.168\.1\.10/);
  await expect(o.page.getByTestId('anomaly-device-filter')).toContainText('192.168.1.10');
  await o.page.goBack();
  await o.page.locator('[data-node="dev:192.168.1.10"]').click();
  await o.page.getByTestId('to-device').click();
  await expect(o.page).toHaveURL(/#\/clients\?device=192\.168\.1\.10/);
  // The other kinds: an upstream, a resolver, a network.
  for (const [id, testid, path] of [
    ['up:google', 'to-upstreams', '#/upstreams'],
    ['res:node-a', 'to-cluster', '#/cluster'],
    ['net:lan', 'to-networks', '#/networks'],
  ] as const) {
    await go(o);
    await o.page.locator(`[data-node="${id}"]`).click();
    await o.page.getByTestId(testid).click();
    await expect(o.page).toHaveURL(new RegExp(`${path}$`));
  }
  // A failing device lists its reasons and its recent lookups.
  await go(o);
  await o.page.locator('[data-node="dev:10.20.2.5"]').click();
  await expect(o.page.getByTestId('node-panel')).toContainText('40% of 50 answers failed');
  await expect(o.page.getByTestId('node-panel')).toContainText('forwarded, 5000 ms');
  expect(o.problems).toEqual([]);
  await o.ctx.close();
});

test('obs_901 reduced motion stops animation', async ({ browser }) => {
  // Without the preference the pulses run (the control case) ...
  const m = await open(browser, fixture(), { reducedMotion: 'no-preference' });
  await go(m);
  await expect.poll(() => running(m.page)).toBeGreaterThan(0);
  await expect(m.page.getByTestId('pause-motion')).toBeVisible();
  // ... and the user can pause them.
  await m.page.getByTestId('pause-motion').click();
  await expect.poll(() => running(m.page)).toBe(0);
  await expect.poll(() => paused(m.page)).toBeGreaterThan(0);
  await m.page.getByTestId('pause-motion').click();
  await expect.poll(() => running(m.page)).toBeGreaterThan(0);
  await m.ctx.close();

  // With it, nothing moves, the rate is written on the flows, and there is no switch for motion.
  const o = await open(browser, fixture(), { reducedMotion: 'reduce' });
  await go(o);
  await expect(o.page.locator('[data-node]').first()).toBeVisible();
  expect(await running(o.page)).toBe(0);
  expect(await o.page.evaluate(() => document.getAnimations().filter((a) => (a.effect as KeyframeEffect | null)?.target?.classList?.contains('pulse')).length)).toBe(0);
  await expect(o.page.getByTestId('rate-label').first()).toBeVisible();
  await expect(o.page.getByTestId('rate-label')).toHaveCount(10);
  await expect(o.page.getByTestId('pause-motion')).toHaveCount(0);
  // The dashes are still drawn, static.
  await expect(o.page.locator('.pulse').first()).toHaveAttribute('stroke-dasharray', /./);
  expect(o.problems).toEqual([]);
  await o.ctx.close();
});

test('obs_901 leaving the page closes the stream', async ({ browser }) => {
  const o = await open(browser);
  await go(o);
  const es = () => o.page.evaluate(() => (window as unknown as { __es: { readyState: number }[] }).__es.map((e) => e.readyState));
  await expect.poll(es).toEqual([1]);
  await o.page.evaluate(() => {
    location.hash = '#/dashboard';
  });
  await expect.poll(es).toEqual([2]);
  await o.ctx.close();
});

test('obs_901 hidden tab pauses and closes the stream', async ({ browser }) => {
  const o = await open(browser);
  await go(o);
  const es = () => o.page.evaluate(() => (window as unknown as { __es: { readyState: number; url: string }[] }).__es.map((e) => e.readyState));
  await expect.poll(es).toEqual([1]);
  await emit(o, fixture({ sampleRate: 4 }));
  await expect(o.page.getByTestId('map-state')).toHaveAttribute('data-stream', 'live');
  await expect.poll(() => running(o.page)).toBeGreaterThan(0);
  // The tab is hidden: the stream is closed and the pulses are paused (not removed).
  await o.page.evaluate(() => {
    (window as unknown as { __vis: string }).__vis = 'hidden';
    document.dispatchEvent(new Event('visibilitychange'));
  });
  await expect.poll(es).toEqual([2]);
  await expect(o.page.getByTestId('map-state')).toHaveAttribute('data-stream', 'paused');
  await expect.poll(() => running(o.page)).toBe(0);
  expect(await paused(o.page)).toBeGreaterThan(0);
  // It comes back: a new stream, running again.
  await o.page.evaluate(() => {
    (window as unknown as { __vis: string }).__vis = 'visible';
    document.dispatchEvent(new Event('visibilitychange'));
  });
  await expect.poll(es).toEqual([2, 1]);
  await expect.poll(() => running(o.page)).toBeGreaterThan(0);
  expect(o.problems).toEqual([]);
  await o.ctx.close();
});

test('obs_901 table view matches the map', async ({ browser }) => {
  const o = await open(browser);
  await go(o);
  const drawn = await o.page.locator('[data-flow]').evaluateAll((els) => els.map((e) => e.getAttribute('data-edge')).sort());
  const nodesDrawn = await o.page.locator('[data-node]').evaluateAll((els) => els.map((e) => e.getAttribute('data-node')).sort());
  await o.page.getByTestId('view-table').click();
  await expect(o.page).toHaveURL(/view=table/);
  const table = o.page.getByTestId('map-table');
  await expect(table).toBeVisible();
  await expect(o.page.locator('[data-node]')).toHaveCount(0);
  const rows = await o.page.locator('[data-flow-row]').evaluateAll((els) => els.map((e) => e.getAttribute('data-flow-row')).sort());
  expect(rows).toEqual(drawn);
  const nodeRows = await o.page.locator('[data-node-row]').evaluateAll((els) => els.map((e) => e.getAttribute('data-node-row')).sort());
  expect(nodeRows).toEqual(nodesDrawn);
  // Words, not colours: states and the rate, in the cells.
  const row = o.page.locator('[data-flow-row="dev:10.20.2.5>res:node-a"]');
  await expect(row).toContainText('camera');
  await expect(row).toContainText('failing');
  await expect(row).toContainText('1.0/s');
  await expect(row).toContainText('40%');
  await expect(o.page.locator('[data-node-row="up:google"]')).toContainText('failing');
  // A node opens its panel from the table too, and the view is kept after a reload.
  await o.page.locator('[data-node-row="up:google"] button').click();
  await expect(o.page.getByTestId('node-panel')).toContainText('google');
  await o.page.reload();
  await expect(o.page.getByTestId('map-table')).toBeVisible();
  await o.page.getByTestId('view-map').click();
  await expect(o.page.getByTestId('map-figure')).toBeVisible();
  expect(o.problems).toEqual([]);
  await o.ctx.close();
});

test('obs_901 privacy hides devices', async ({ browser }) => {
  const hidden = fixture({
    privacy: 2,
    nodes: [
      node('gateway', 'gateway', 'Gateway', 'green'),
      node('net:all', 'network', 'All networks', 'green', { qps: 0 }),
      node('dev:hidden', 'device', 'devices hidden by privacy', 'green', { qps: 11 }),
      node('res:node-a', 'resolver', 'node-a', 'green', { node: 'node-a', qps: 11 }),
      node('up:cloudflare', 'upstream', 'cloudflare', 'green', { qps: 4 }),
    ],
    edges: [structural('gateway', 'net:all'), structural('net:all', 'dev:hidden'), edge('dev:hidden', 'res:node-a', 11), edge('res:node-a', 'up:cloudflare', 4)],
  });
  const o = await open(browser, hidden);
  await go(o);
  await expect(o.page.getByTestId('banner-privacy')).toContainText('Privacy level 2');
  await expect(o.page.locator('[data-node][data-kind="device"]')).toHaveCount(1);
  await o.page.locator('[data-node="dev:hidden"]').click();
  const panel = o.page.getByTestId('node-panel');
  await expect(panel).toContainText('devices hidden by privacy');
  // No address, and nowhere to click through to.
  await expect(panel.getByTestId('panel-address')).toHaveCount(0);
  for (const t of ['to-queries', 'to-explain', 'to-anomalies', 'to-device']) await expect(panel.getByTestId(t)).toHaveCount(0);
  await expect(panel).toContainText('hidden at this privacy level');
  // Nothing drawn carries an address.
  expect(await o.page.getByTestId('map-figure').innerHTML()).not.toMatch(/\d+\.\d+\.\d+\.\d+/);
  // Level 3: totals only.
  await emit(o, { ...hidden, privacy: 3 });
  await expect(o.page.getByTestId('banner-privacy')).toContainText('Privacy level 3');
  expect(o.problems).toEqual([]);
  await o.ctx.close();
});

test('obs_901 keyboard opens a node panel', async ({ browser }) => {
  const o = await open(browser);
  await go(o);
  await expect(o.page.locator('[data-node]').first()).toBeVisible();
  // Tab until a node has focus: the nodes are in the tab order, in the reading order of the drawing.
  let id: string | null = null;
  await o.page.locator('h1').click();
  for (let i = 0; i < 80 && !id; i++) {
    await o.page.keyboard.press('Tab');
    id = await o.page.evaluate(() => (document.activeElement as HTMLElement | null)?.getAttribute('data-node') ?? null);
  }
  expect(id, 'a node took focus').toBeTruthy();
  const label = (await o.page.locator(`[data-node="${id}"]`).getAttribute('aria-label')) ?? '';
  expect(label.length).toBeGreaterThan(5);
  await o.page.keyboard.press('Enter');
  const panel = o.page.getByTestId('node-panel');
  await expect(panel).toBeVisible();
  await expect(panel.locator('h2')).toHaveText(label.split(',')[0]);
  // Space opens it too, and the next node by Tab.
  await o.page.keyboard.press('Tab');
  await o.page.keyboard.press('Space');
  await expect(panel).toBeVisible();
  await expect(o.page.locator('[data-node][aria-pressed="true"]')).toHaveCount(1);
  expect(o.problems).toEqual([]);
  await o.ctx.close();
});

test('obs_901 150 animated edges keep frame time', async ({ browser }) => {
  const devices: N[] = [];
  const edges: E[] = [];
  for (let i = 0; i < 170; i++) {
    const ip = `10.1.${Math.floor(i / 200)}.${i % 200}`;
    devices.push(dev(ip, `dev-${i}`, 'lan', 'adults', 'green', 1 + (i % 7)));
    edges.push(structural('net:lan', `dev:${ip}`), edge(`dev:${ip}`, 'res:node-a', 1 + (i % 7)));
  }
  const base = fixture();
  const snap = fixture({
    nodes: [...base.nodes.filter((n) => n.kind !== 'device' && n.kind !== 'more'), ...devices],
    edges: [...edges, structural('gateway', 'net:lan'), edge('res:node-a', 'up:cloudflare', 20)],
  });
  const o = await open(browser, snap);
  await go(o);
  await expect(o.page.locator('[data-node][data-kind="device"]')).toHaveCount(170);
  // At most 150 move (60 on a host with 4 cores or fewer): the busiest, the rest still.
  const cores = await o.page.evaluate(() => navigator.hardwareConcurrency);
  const budget = animatedBudget(cores);
  await expect(o.page.locator('.pulse.run')).toHaveCount(budget);
  await expect(o.page.locator('.pulse')).toHaveCount(171);
  await expect.poll(() => running(o.page)).toBe(budget);
  // The median frame stays under 33 ms (a noise band of this browser, not a Pi measurement).
  const median = await o.page.evaluate(
    () =>
      new Promise<number>((done) => {
        const t: number[] = [];
        let last = performance.now();
        const f = (now: number) => {
          t.push(now - last);
          last = now;
          if (t.length < 90) requestAnimationFrame(f);
          else done(t.sort((a, b) => a - b)[t.length >> 1]);
        };
        requestAnimationFrame(f);
      }),
  );
  expect(median).toBeLessThan(33);
  expect(o.problems).toEqual([]);
  await o.ctx.close();
});

test('obs_901 banners say sampled, partial, truncated and off', async ({ browser }) => {
  const o = await open(browser, fixture({ sampleRate: 8, dropped: 120, partial: true, missingNodes: ['node-b'], truncated: true }));
  await go(o);
  await expect(o.page.getByTestId('banner-sampled')).toContainText('1 in 8');
  await expect(o.page.getByTestId('banner-partial')).toContainText('node-b');
  await expect(o.page.getByTestId('banner-truncated')).toBeVisible();
  // A snapshot from the stream replaces it, and the banners follow it.
  await emit(o, fixture());
  await expect(o.page.getByTestId('banner-sampled')).toHaveCount(0);
  await expect(o.page.getByTestId('banner-partial')).toHaveCount(0);
  // The map turned off: a note, not an error.
  o.current.status = 404;
  await o.ctx.close();
  const off = await open(browser);
  off.current.status = 404;
  await go(off);
  await expect(off.page.getByTestId('map-off')).toBeVisible();
  await expect(off.page.getByTestId('map-state')).toHaveAttribute('data-stream', 'off');
  await expect(off.page.locator('[role="alert"]')).toHaveCount(0);
  expect(off.problems).toEqual([]);
  await off.ctx.close();
});

test('obs_901 a refused stream falls back to polling', async ({ browser }) => {
  const o = await open(browser);
  await go(o);
  // The node refuses the stream (429, a busy node): the page polls instead and still draws.
  await o.page.evaluate(() => {
    const es = (window as unknown as { __es: { readyState: number; onerror: (() => void) | null }[] }).__es[0];
    es.readyState = 2;
    es.onerror?.();
  });
  await expect(o.page.getByTestId('map-state')).toHaveAttribute('data-stream', 'polling');
  await expect(o.page.getByTestId('map-figure')).toBeVisible();
  const n = o.requests.length;
  await expect.poll(() => o.requests.length, { timeout: 10_000 }).toBeGreaterThan(n);
  expect(o.problems).toEqual([]);
  await o.ctx.close();
});

test('obs_901 a device\'s switch and port are drawn only when the snapshot carries them', async ({ browser }) => {
  const base = fixture();
  const withVia = fixture({ nodes: base.nodes.map((n) => (n.id === 'dev:192.168.1.10' ? ({ ...n, via: 'switch-garage', port: '7' } as N) : n)) });
  const o = await open(browser, withVia);
  await go(o);
  await o.page.locator('[data-node="dev:192.168.1.10"]').click();
  await expect(o.page.getByTestId('panel-via')).toHaveText('Connected through switch-garage, port 7');
  await o.page.locator('[data-node="dev:192.168.1.11"]').click();
  await expect(o.page.getByTestId('panel-via')).toHaveCount(0);
  await o.ctx.close();
});

test('obs_901 the node\'s own stream and snapshot draw the map', async ({ page }) => {
  // No mocks: the real node, signed in as the admin, over its own stream.
  await page.context().addCookies(state.cookies);
  const problems: string[] = [];
  page.on('pageerror', (e) => problems.push(e.message));
  page.on('console', (m) => {
    if (m.type() === 'error') problems.push(m.text());
  });
  await page.goto('/#/map');
  await expect(page.getByRole('heading', { name: 'Network map' })).toBeVisible();
  // The node's own resolver is always on the map, even with no traffic.
  await expect(page.locator('[data-node][data-kind="resolver"]').first()).toBeVisible({ timeout: 20_000 });
  await expect(page.getByTestId('map-state')).toHaveAttribute('data-stream', /live|connecting|polling/);
  await page.getByTestId('view-table').click();
  await expect(page.getByTestId('map-table')).toBeVisible();
  expect(problems).toEqual([]);
});

test('obs_901 the map chunk is at most 30 KiB and dist at most 400 KiB gzipped', () => {
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
  // The build leaves each text file as its `.gz`: the sizes on disk are the gzipped sizes.
  const chunk = files.filter((f) => /^assets\/Map-.*\.(js|css)\.gz$/.test(f.rel));
  expect(chunk.length, 'the map chunk and its styles are separate files').toBeGreaterThanOrEqual(2);
  const chunkBytes = chunk.reduce((s, f) => s + f.size, 0);
  const total = files.reduce((s, f) => s + f.size, 0);
  console.log(`map chunk ${(chunkBytes / 1024).toFixed(1)} KiB gzipped, dist total ${(total / 1024).toFixed(1)} KiB gzipped`);
  expect(chunkBytes).toBeLessThanOrEqual(30 * 1024);
  expect(total).toBeLessThanOrEqual(400 * 1024);
  // The main bundle doesn't carry the page: no layout code in it.
  const main = files.find((f) => /^assets\/index-.*\.js\.gz$/.test(f.rel));
  expect(main).toBeTruthy();
});

// ---- The pure parts, without a browser.

test('obs_901 filterSnapshot keeps what a filter names and what connects to it', () => {
  const s = fixture();
  const ids = (x: Snapshot) => x.nodes.map((n) => n.id);
  expect(filterSnapshot(s, NO_FILTERS)).toBe(s);
  const net = filterSnapshot(s, { ...NO_FILTERS, network: 'iot' });
  expect(ids(net)).toContain('dev:10.20.2.5');
  expect(ids(net)).toContain('more:iot');
  expect(ids(net)).not.toContain('dev:192.168.1.10');
  expect(ids(net)).not.toContain('net:lan');
  expect(ids(net)).toContain('gateway');
  expect(ids(net)).toContain('up:google');
  // A group can't match a folded node.
  const grp = filterSnapshot(s, { ...NO_FILTERS, group: 'kids' });
  expect(ids(grp).filter((i) => i.startsWith('dev:'))).toEqual(['dev:192.168.1.11']);
  expect(ids(grp)).not.toContain('more:iot');
  expect(ids(grp)).not.toContain('net:iot');
  // Text matches a name or an address.
  expect(ids(filterSnapshot(s, { ...NO_FILTERS, device: '2.6' })).filter((i) => i.startsWith('dev:'))).toEqual(['dev:10.20.2.6']);
  expect(ids(filterSnapshot(s, { ...NO_FILTERS, device: 'LAPTOP' })).filter((i) => i.startsWith('dev:'))).toEqual(['dev:192.168.1.10']);
  // A node that nothing uses leaves the map without devices.
  expect(filterSnapshot(s, { ...NO_FILTERS, node: 'node-z' }).nodes.filter((n) => n.kind === 'device')).toEqual([]);
  expect(ids(filterSnapshot(s, { ...NO_FILTERS, node: 'node-a' })).length).toBe(s.nodes.length);
  // A state keeps its nodes and their neighbours.
  const red = filterSnapshot(s, { ...NO_FILTERS, health: 'red' });
  expect(ids(red)).toEqual(expect.arrayContaining(['dev:10.20.2.5', 'up:google', 'res:node-a', 'net:iot']));
  expect(ids(red)).not.toContain('dev:192.168.1.10');
  // Every edge left has both ends.
  for (const f of [net, grp, red]) for (const e of f.edges) expect(ids(f)).toEqual(expect.arrayContaining([e.from, e.to]));
});

test('obs_901 the layout is deterministic and keeps the columns apart', () => {
  const s = fixture();
  const a = layout(s, { maxAnimated: 150 });
  const b = layout(structuredClone(s), { maxAnimated: 150 });
  expect(b).toEqual(a);
  expect(a.nodes.length).toBe(s.nodes.length);
  // No two nodes of a column overlap.
  const byCol = new Map<number, number[]>();
  for (const n of a.nodes) byCol.set(n.col, [...(byCol.get(n.col) ?? []), n.y]);
  for (const ys of byCol.values()) {
    const sorted = [...ys].sort((p, q) => p - q);
    for (let i = 1; i < sorted.length; i++) expect(sorted[i] - sorted[i - 1]).toBeGreaterThanOrEqual(30);
  }
  // Devices are by network then rate.
  const y = (id: string) => a.nodes.find((n) => n.node.id === id)!.y;
  expect(y('dev:192.168.1.10')).toBeLessThan(y('dev:192.168.1.11'));
  expect(y('dev:192.168.1.11')).toBeLessThan(y('dev:10.20.2.5'));
  expect(y('dev:10.20.2.6')).toBeLessThan(y('more:iot'));
  // Only the busiest edges animate, and a structural edge has no pulse.
  const few = layout(s, { maxAnimated: 3 });
  expect(few.edges.filter((e) => e.animated).length).toBe(3);
  expect(few.edges.filter((e) => e.structural).every((e) => e.pulse === null && !e.animated)).toBe(true);
  expect(few.edges.find((e) => e.id === 'dev:192.168.1.10>res:node-a')!.animated).toBe(true);
});

test('obs_901 pulses: density from the rate (1 to 6 dashes), width from its log, a stable seed', () => {
  expect(pulse(0.1, 'a').dashes).toBe(1);
  expect(pulse(1, 'a').dashes).toBe(2);
  expect(pulse(100, 'a').dashes).toBe(6);
  expect(pulse(10, 'a').width).toBeGreaterThan(pulse(1, 'a').width);
  expect(pulse(1e6, 'a').width).toBeLessThanOrEqual(6);
  const p = pulse(3, 'edge-x');
  expect(p.dash + p.gap).toBeCloseTo(100 / p.dashes, 1);
  expect(pulse(3, 'edge-x')).toEqual(p);
  expect(seed('x')).toBe(seed('x'));
  expect(seed('x')).not.toBe(seed('y'));
  expect(p.delay).toBeLessThanOrEqual(0);
  expect(animatedBudget(24)).toBe(150);
  expect(animatedBudget(4)).toBe(60);
  expect(animatedBudget(2)).toBe(60);
  expect(animatedBudget(undefined)).toBe(150);
});

test('obs_901 flow rows, click-through links and via', () => {
  const s = fixture();
  const rows = flowRows(s);
  expect(rows.length).toBe(10);
  expect(rows[0].qps).toBeGreaterThanOrEqual(rows[rows.length - 1].qps);
  const d = s.nodes.find((n) => n.id === 'dev:192.168.1.10')!;
  expect(links(d, 0).map((l) => l.path)).toEqual(['/queries', '/explain', '/anomalies', '/clients']);
  expect(links(d, 1).length).toBe(4);
  expect(links(d, 2)).toEqual([]);
  expect(links(s.nodes.find((n) => n.id === 'ans:node-a:cache')!, 0)[0].params).toEqual({ status: 'cached' });
  const more = s.nodes.find((n) => n.kind === 'more')!;
  expect(links(more, 1).length).toBe(1);
  expect(links(more, 2)).toEqual([]);
  expect(via(d)).toBeNull();
  expect(via({ ...d, via: 'sw1', port: '3' } as N)).toBe('sw1, port 3');
  expect(via({ ...d, via: 'sw1' } as N)).toBe('sw1');
});
