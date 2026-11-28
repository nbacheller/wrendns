// REQ: OBS-901 (T26.6, ADR-958 section 4) — the network map's settings card (Settings -> Query
// handling): the thresholds change what the map shows, the server's bounds name their field, and a
// viewer sees the values and no control. The e2e server has no traffic, so the map's snapshot is
// answered by `page.route` from the settings the real server holds (the same reclassification the
// card previews); the settings themselves are written to the real server. These tests sign in as
// the admin and the viewer `1-ui.spec.ts` created, so run the whole suite, not this file alone.
import { expect, test, type BrowserContext, type Page } from '@playwright/test';
import { signInSent } from './signin';
import type { Snapshot } from '../../src/lib/map';
import { fromSettings, reclassify, type Thresholds } from '../../src/lib/map-thresholds';

test.describe.configure({ mode: 'serial' });

const ADMIN = { user: 'admin', pass: 'correct horse battery' };
const VIEWER = { user: 'viewer1', pass: 'another long password' };

type N = Snapshot['nodes'][number];
type E = Snapshot['edges'][number];
const node = (id: string, kind: N['kind'], label: string, extra: Partial<N> = {}): N => ({ id, kind, label, health: 'green', reasons: [], qps: 1, count: 60, sampled: 60, ...extra });
const flow = (from: string, to: string, extra: Partial<E> = {}): E => ({ from, to, structural: false, qps: 1, count: 60, slowPct: 0, errPct: 0, blockedPct: 0, health: 'green', ...extra });

// A camera failing 10% of its lookups (Warning under the defaults: from 5%, failing from 25%), a
// tv that is slow 20% of the time (Warning from 10%), a laptop that is fine, and an upstream that
// fails 30% (Failing).
function raw(): Snapshot {
  const nodes: N[] = [
    node('gateway', 'gateway', 'Gateway'),
    node('net:lan', 'network', 'lan', { qps: 0 }),
    node('dev:192.168.1.10', 'device', 'laptop', { address: '192.168.1.10', network: 'lan', group: 'adults' }),
    node('dev:192.168.1.11', 'device', 'tv', { address: '192.168.1.11', network: 'lan', group: 'kids' }),
    node('dev:192.168.1.12', 'device', 'camera', { address: '192.168.1.12', network: 'lan', group: 'iot' }),
    node('res:node-a', 'resolver', 'node-a', { node: 'node-a' }),
    node('up:google', 'upstream', 'google'),
  ];
  const edges: E[] = [
    flow('gateway', 'net:lan', { structural: true }),
    flow('net:lan', 'dev:192.168.1.10', { structural: true }),
    flow('net:lan', 'dev:192.168.1.11', { structural: true }),
    flow('net:lan', 'dev:192.168.1.12', { structural: true }),
    flow('dev:192.168.1.10', 'res:node-a'),
    flow('dev:192.168.1.11', 'res:node-a', { slowPct: 20 }),
    flow('dev:192.168.1.12', 'res:node-a', { errPct: 10 }),
    flow('res:node-a', 'up:google', { errPct: 30 }),
  ];
  return {
    generatedAt: '2026-11-18T12:00:00Z', windowSecs: 60, sampleRate: 1, dropped: 0, privacy: 0, truncated: false, partial: false, missingNodes: [],
    health: 'green', counts: { green: 0, yellow: 0, red: 0, idle: 0 }, nodes, edges,
  };
}

/**
 * The snapshot as the server would colour it under these thresholds. NOTE: this uses the card's own
 * rules, so the test proves the card wires the preview and the recolour together; the server's real
 * classification is covered by the Rust test obs_901_map_settings_override_toggle_and_revert.
 */
function coloured(t: Thresholds): Snapshot {
  const s = raw();
  const to = new Map(reclassify(s, t).changes.map((c) => [c.id, c.to]));
  return { ...s, nodes: s.nodes.map((n) => ({ ...n, health: to.get(n.id) ?? n.health })) };
}

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

/** Answer the map from the settings the real server holds now (the stream is left to polling). */
async function mockMap(page: Page) {
  await page.route(/\/api\/v1\/map\/stream/, (route) => route.abort());
  await page.route(/\/api\/v1\/map(\?.*)?$/, async (route) => {
    const r = await page.request.get('/api/v1/config/entries?kind=map');
    const def = ((await r.json()).items?.[0]?.definition ?? {}) as Record<string, unknown>;
    await route.fulfill({ json: coloured(fromSettings(def)) });
  });
}

const spin = (page: Page, name: string) => page.getByRole('spinbutton', { name, exact: true });

test('obs_901 change map thresholds', async ({ browser }) => {
  const ctx = await browser.newContext({ storageState: state });
  const page = await ctx.newPage();
  const problems: string[] = [];
  page.on('pageerror', (e) => problems.push(e.message));
  await mockMap(page);
  // Under the defaults the camera (10% errors) is a Warning.
  await page.goto('/#/map');
  await expect(page.getByRole('heading', { name: 'Network map' })).toBeVisible();
  await expect(page.locator('[data-node="dev:192.168.1.12"]')).toHaveAttribute('data-health', 'yellow');
  await page.getByTestId('map-settings-link').click();
  const card = page.getByTestId('editor-map');
  await expect(card).toBeVisible();
  await expect(card.getByTestId('entry-row')).toContainText('on; 200 lookups/s sampled');
  await card.getByRole('button', { name: 'Edit' }).click();
  // One field per setting, each with its mark.
  for (const k of ['enabled', 'event_rate', 'min_sample', 'warn_latency_ms', 'warn_slow_pct', 'warn_error_pct', 'error_pct', 'warn_blocked_pct']) {
    await expect(page.locator(`[data-setting="map.${k}"]`), k).toHaveCount(1);
  }
  // The preview recolours the current map with the draft: failing from 8% makes the camera Failing.
  await spin(page, 'Warning when this % are SERVFAIL or time out').fill('3');
  await spin(page, 'Failing when this % are SERVFAIL or time out').fill('8');
  await expect(page.getByTestId('editor-note')).toContainText('camera Warning to Failing');
  await page.getByRole('button', { name: 'Check', exact: true }).click();
  await expect(page.getByTestId('entry-preview')).toBeVisible();
  await page.getByRole('button', { name: 'Apply' }).click();
  await expect(card.getByTestId('entry-row')).toContainText('failing at 8% errors');
  // The map recolours.
  await page.goto('/#/map');
  await expect(page.getByRole('heading', { name: 'Network map' })).toBeVisible();
  await expect(page.locator('[data-node="dev:192.168.1.12"]')).toHaveAttribute('data-health', 'red');
  await expect(page.locator('[data-node="dev:192.168.1.12"] .nstate')).toContainText('Failing');
  // Back to the file's settings: Warning again.
  await page.goto('/#/settings?tab=queries');
  await page.getByTestId('editor-map').getByRole('button', { name: 'Revert to the file' }).click();
  await expect(page.getByTestId('editor-map').getByTestId('entry-row')).toContainText('failing at 25% errors');
  await page.goto('/#/map');
  await expect(page.locator('[data-node="dev:192.168.1.12"]')).toHaveAttribute('data-health', 'yellow');
  expect(problems).toEqual([]);
  await ctx.close();
});

test('obs_901 out of range value names the field', async ({ browser }) => {
  const ctx = await browser.newContext({ storageState: state });
  const page = await ctx.newPage();
  await mockMap(page);
  await page.goto('/#/settings?tab=queries');
  const card = page.getByTestId('editor-map');
  await card.getByRole('button', { name: 'Edit' }).click();
  await spin(page, 'Lookups sampled per second (each node)').fill('5000');
  await page.getByRole('button', { name: 'Check', exact: true }).click();
  await expect(page.getByRole('alert')).toContainText('event_rate');
  // Red can't come before yellow either.
  await spin(page, 'Lookups sampled per second (each node)').fill('200');
  await spin(page, 'Warning when this % are SERVFAIL or time out').fill('30');
  await spin(page, 'Failing when this % are SERVFAIL or time out').fill('10');
  await page.getByRole('button', { name: 'Check', exact: true }).click();
  await expect(page.getByRole('alert')).toContainText('error_pct');
  // Nothing was stored.
  const r = await page.request.get('/api/v1/config/entries?kind=map');
  expect((await r.json()).items[0].source).toBe('file');
  await ctx.close();
});

test('obs_901 viewer sees map settings read-only', async ({ browser }) => {
  const ctx = await browser.newContext();
  const page = await ctx.newPage();
  await mockMap(page);
  await page.goto('/#/settings?tab=queries');
  await signInSent(page, VIEWER.user, VIEWER.pass);
  const row = page.getByTestId('editor-map').getByTestId('entry-row');
  await expect(row).toContainText('lookups/s sampled', { timeout: 30_000 });
  await expect(row).toContainText('warning at 10% slow');
  await expect(row.getByRole('button', { name: 'Edit' })).toHaveCount(0);
  await expect(row.getByRole('button', { name: 'Revert to the file' })).toHaveCount(0);
  // The server says no whatever the page does.
  const csrf = (await (await page.request.get('/api/v1/auth/status')).json()).csrfToken as string;
  const put = await page.request.put('/api/v1/map-settings/default', { headers: { 'x-csrf-token': csrf }, data: { event_rate: 300 } });
  expect(put.status()).toBe(403);
  await ctx.close();
});

// The preview's own rules, without a page.
test('obs_901 preview reclassifies by sample, scope and held reasons', () => {
  const s = raw();
  // Too few real answers: Idle whatever the rates say.
  const thin = { ...s, nodes: s.nodes.map((n) => (n.id === 'dev:192.168.1.12' ? { ...n, sampled: 5 } : n)) };
  expect(reclassify(thin, fromSettings({})).changes.find((c) => c.label === 'camera')?.to).toBe('idle');
  // Blocked share is a device's yellow only.
  const blocked = { ...s, edges: s.edges.map((e) => (e.to === 'up:google' ? { ...e, blockedPct: 90 } : e)) };
  expect(reclassify(blocked, fromSettings({})).changes.find((c) => c.label === 'google')?.to).toBe('red');
  // A reason a rate can't explain holds its colour (an open anomaly keeps a device yellow).
  const held = { ...s, nodes: s.nodes.map((n) => (n.id === 'dev:192.168.1.10' ? { ...n, reasons: [{ code: 'anomaly', summary: 'an open anomaly' }] } : n)) };
  expect(reclassify(held, fromSettings({})).changes.find((c) => c.label === 'laptop')?.to).toBe('yellow');
  // A blank or bad value is the default.
  expect(fromSettings({ error_pct: '', warn_error_pct: 'x' })).toMatchObject({ errorPct: 25, warnErrorPct: 5 });
});
