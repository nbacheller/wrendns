// REQ: API-003, API-005 — the UI end to end against a real server: first-run setup, the
// dashboard, the query log and "Why?", explain, tokens, users and roles, sign-out/in, and a
// phone-width layout, and the masked-client-IP banner. Any CSP violation or page error fails the suite.
import { expect, test, type Page, type Request, type Route } from '@playwright/test';
import { createHmac } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { zstdDecompressSync } from 'node:zlib';
import { BASE_URL, DNS_PORT, E2E_ROOT, MDNS_PORT, PORTS } from './ports';
import { resolve } from 'node:path';
import { query, queryDetail } from './dns';
import { pick } from './picker';
import { hoverRing, rectRing } from './svg-ring';
import { alertConditions } from '../../src/lib/alert-conditions';
import { customUrl, nextCustomName, planFor, readSaved, type Transport } from '../../src/lib/upstream-picker';
import { FrameHub, Loop, PANEL_MIN, Particles, Ticker, chooseLayout, dotBudget, lerpBoxes, motionAllowed, parseEvery, parseLayout, parsePanels, screenClass, screenClassStable, type Box } from '../../src/lib/wall';

test.describe.configure({ mode: 'serial' });

const ADMIN = { user: 'admin', pass: 'correct horse battery' };
const VIEWER = { user: 'viewer1', pass: 'another long password' };

let page: Page;
const problems: string[] = [];

test.beforeAll(async ({ browser }) => {
  page = await browser.newPage();
  page.on('pageerror', (e) => problems.push(`page error: ${e.message}`));
  page.on('console', (m) => {
    // Expected refusals (401 sign-in, 403 forbidden) are logged by the browser as resource errors. Any
    // other 4xx is a bug; a test that expects one (a 409, say) removes it from `problems` itself.
    if (m.type() === 'error' && !/status of 40[13] \(/.test(m.text())) problems.push(`console: ${m.text()}`);
  });
});

test.afterEach(() => {
  expect(problems, 'no page errors or CSP violations').toEqual([]);
});

test.afterAll(async () => {
  await page.close();
});

async function signIn(user: string, pass: string) {
  await page.getByLabel('Username', { exact: true }).fill(user);
  await page.getByLabel('Password', { exact: true }).fill(pass);
  await page.getByRole('button', { name: 'Sign in' }).click();
}

// REQ: API-005 (ADR-157) — the dashboard's top lists are plain sections, found by their heading.
const listOf = (title: string) => page.locator('section').filter({ has: page.getByRole('heading', { name: new RegExp(`^${title}`) }) });

test('first run: the setup token creates the admin', async () => {
  await page.goto('/');
  const welcome = page.getByRole('heading', { name: 'Welcome to WrenDNS' });
  const signInHeading = page.getByRole('heading', { name: 'Sign in' });
  await expect(welcome.or(signInHeading)).toBeVisible();
  if (await signInHeading.isVisible()) {
    // A CI retry: the first attempt created the admin and then timed out (a stalled runner).
    // Sign in as that admin so the serial suite doesn't fail in a cascade.
    await signIn(ADMIN.user, ADMIN.pass);
    await expect(page.getByRole('heading', { name: 'Dashboard' })).toBeVisible({ timeout: 30_000 });
    return;
  }
  const token = readFileSync(resolve(E2E_ROOT, 'data/setup-token'), 'utf8').trim();
  await page.getByLabel('Setup token').fill(token);
  await page.getByLabel('Admin username').fill(ADMIN.user);
  await page.getByLabel('Password (at least 10 characters)').fill(ADMIN.pass);
  await page.getByLabel('Repeat password').fill(ADMIN.pass);
  await page.getByRole('button', { name: 'Create admin and sign in' }).click();
  // Creating the admin hashes its password (Argon2) and loads the dashboard for the first time.
  await expect(page.getByRole('heading', { name: 'Dashboard' })).toBeVisible({ timeout: 30_000 });
});

test('dashboard shows traffic and top blocked names', async () => {
  // The blocklist compiles in the background after start (DNS never waits for it).
  await expect
    .poll(async () => (await (await page.request.get('/api/v1/system/info')).json()).filterSnapshot ?? null, {
      timeout: 30_000,
    })
    .not.toBeNull();
  for (let i = 0; i < 5; i++) expect(await query('ads.e2e.test')).toBe(0);
  for (let i = 0; i < 3; i++) expect(await query('nas.e2e.test')).toBe(0);
  await expect(async () => {
    await page.reload();
    await expect(page.getByRole('link', { name: 'ads.e2e.test', exact: true }).first()).toBeVisible({ timeout: 2000 });
  }).toPass({ timeout: 20_000 });
  // One chart: totals and blocked by default, the status split a click away.
  const chart = page.getByTestId('dashboard-chart');
  await expect(chart.getByRole('figure', { name: 'Queries', exact: true })).toBeVisible();
  await chart.getByRole('button', { name: 'Status', exact: true }).click();
  await expect(chart.getByRole('figure', { name: 'Queries by status' })).toBeVisible();
  // Every chart has a table view.
  await page.getByRole('button', { name: 'Table' }).first().click();
  await expect(page.locator('.table-view table').first()).toBeVisible();
  await page.getByRole('button', { name: 'Chart', exact: true }).click();
  // The technical parts are in the Advanced view only (owner, 2026-10-09): two sections, and two
  // more views of the chart.
  // (Headings may carry "(this hour)" and a help button after the title.)
  const heading = (h: string) => page.getByRole('heading', { name: new RegExp(`^${h}( |$)`) });
  const advancedOnly = ['Where time goes', 'Upstreams'];
  const upstreamView = chart.getByRole('button', { name: 'Upstream', exact: true });
  for (const h of advancedOnly) await expect(heading(h)).toHaveCount(0);
  await expect(upstreamView).toHaveCount(0);
  await page.getByRole('button', { name: 'Advanced', exact: true }).click();
  for (const h of advancedOnly) await expect(heading(h)).toBeVisible();
  await expect(upstreamView).toBeVisible();
  // "Where time goes": each path explains itself on hover (and keyboard focus).
  const local = page.getByRole('button', { name: 'local/udp' });
  await local.hover();
  await expect(page.getByRole('tooltip').filter({ hasText: 'names on your network' })).toBeVisible();
  await expect(local).toHaveAccessibleDescription(/names on your network.*UDP/);
  await page.getByRole('button', { name: 'Simple', exact: true }).click();
  await expect(heading('Upstreams')).toHaveCount(0);
});

// REQ: API-005 (ADR-157) — the previous dashboard is one address away: `#/?view=legacy` shows it
// and the choice is remembered in this browser; `#/?view=new` (its quiet link) goes back. Nothing
// else in the UI points at it.
test('api_005 the previous dashboard is reachable and remembered', async () => {
  await page.setViewportSize({ width: 1280, height: 800 });
  await page.goto('/#/');
  await expect(page.getByTestId('dashboard-chart')).toBeVisible();
  await expect(page.getByTestId('dashboard-new-link')).toHaveCount(0);
  await page.goto('/#/?view=legacy');
  // The old page: its own chart card, no new chart.
  await expect(page.getByRole('heading', { name: 'Queries by status' })).toBeVisible();
  await expect(page.getByTestId('dashboard-chart')).toHaveCount(0);
  // Remembered: away and back without the parameter.
  await page.goto('/#/queries');
  await page.goto('/#/');
  await expect(page.getByRole('heading', { name: 'Queries by status' })).toBeVisible();
  // And back to the new one.
  await page.getByTestId('dashboard-new-link').click();
  await expect(page.getByTestId('dashboard-chart')).toBeVisible();
  await page.goto('/#/queries');
  await page.goto('/#/');
  await expect(page.getByTestId('dashboard-chart')).toBeVisible();
});

// REQ: OBS-026 — the traffic map: the real queries above (ads.e2e.test blocked, nas.e2e.test
// answered), then stubbed top lists that fold into one service and grow between refreshes.
test('obs_026 traffic map', async () => {
  await page.goto('/#/traffic');
  await expect(page.getByRole('heading', { name: /^Traffic map/ })).toBeVisible();
  const escapeRe = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const tile = (label: string) => page.getByRole('link', { name: new RegExp(`^${escapeRe(label)}, `) });
  await page.getByRole('button', { name: 'Names', exact: true }).click();
  await expect(tile('ads.e2e.test, blocked')).toBeVisible({ timeout: 10_000 });
  await expect(tile('nas.e2e.test, allowed')).toBeVisible();
  // The domains list counts blocked queries too: a name that was only blocked isn't also blue.
  await expect(tile('ads.e2e.test, allowed')).toHaveCount(0);
  await page.getByRole('button', { name: 'Sites', exact: true }).click();
  await tile('e2e.test, allowed').hover();
  await expect(page.locator('.details')).toContainText('nas.e2e.test');
  await page.getByRole('button', { name: 'Blocked', exact: true }).click();
  await expect(tile('e2e.test, allowed')).toHaveCount(0);
  await expect(tile('e2e.test, blocked')).toBeVisible();
  await page.getByRole('button', { name: 'All', exact: true }).click();

  // Stubbed: YouTube's names make one tile in Services, and its growth (30 a refresh) is marked.
  let calls = 0;
  await page.route('**/api/v1/stats/top?*', (route) => {
    const blocked = new URL(route.request().url()).searchParams.get('kind') === 'blocked';
    if (!blocked) calls++;
    const grow = 30 * calls;
    const item = (key: string, count: number) => ({ key, count, errorBound: 0 });
    route.fulfill({
      json: {
        items: blocked
          ? [item('ads.tracker.example', 40)]
          : [item('www.youtube.com', 100 + grow), item('i.ytimg.com', 50), item('ads.tracker.example', 40), item('github.com', 20)],
      },
    });
  });
  await page.getByRole('button', { name: 'Services', exact: true }).click();
  await page.reload();
  const youtube = tile('YouTube, allowed');
  await youtube.hover();
  await expect(page.locator('.details')).toContainText('www.youtube.com');
  await expect(page.locator('.details')).toContainText('i.ytimg.com');
  await expect(tile('github.com, allowed')).toBeVisible();
  await expect(tile('tracker.example, blocked')).toHaveAccessibleName(/40 queries/);
  await expect(tile('tracker.example, allowed')).toHaveCount(0);
  // From the second refresh (5 s) on, YouTube is growing.
  await expect(youtube).toHaveClass(/hot/, { timeout: 12_000 });
  await expect(youtube).toContainText('+30');
  await youtube.click();
  await expect(page).toHaveURL(/#\/queries\?name=youtube\.com&match=suffix/);
  await page.unroute('**/api/v1/stats/top?*');
});

test('query log finds the blocked query and explains it', async () => {
  await page.goto('/#/queries?name=ads.e2e.test');
  await expect(async () => {
    await page.reload();
    await expect(page.locator('table.log tbody tr').first()).toContainText('blocked', { timeout: 2000 });
  }).toPass({ timeout: 20_000 });
  await expect(page.locator('table.log tbody tr').first()).toContainText('e2e-block');
  await page.getByRole('button', { name: 'Why?' }).first().click();
  const drawer = page.getByRole('dialog');
  await expect(drawer).toContainText('e2e-block');
  await expect(drawer.getByTestId('rule-winner').first()).toBeVisible();
  await page.keyboard.press('Escape');
  await expect(drawer).toBeHidden();
  // Status chips filter, and the filter lands in the URL.
  await page.goto('/#/queries');
  await page.getByRole('button', { name: 'local', exact: true }).click();
  await expect(page).toHaveURL(/status=local/);
  await expect(async () => {
    await page.reload();
    await expect(page.locator('table.log tbody tr').first()).toContainText('nas.e2e.test', { timeout: 2000 });
  }).toPass({ timeout: 20_000 });
});

// REQ: OBS-017 — /metrics in OpenMetrics carries an exemplar per latency bucket; its trace ID
// opens that query in the log.
test('obs_017 an exemplar opens its query in the log', async () => {
  expect(await query('nas.e2e.test')).toBe(0);
  let trace = '';
  await expect(async () => {
    const r = await fetch(`http://127.0.0.1:${PORTS.metrics}/metrics`, { headers: { accept: 'application/openmetrics-text;version=1.0.0' } });
    expect(r.headers.get('content-type')).toContain('application/openmetrics-text');
    const text = await r.text();
    expect(text.endsWith('# EOF\n')).toBe(true);
    const m = text.match(/wrendns_query_duration_seconds_bucket\{path="local",le="[^"]+"\} \d+ # \{trace_id="([0-9a-f]{32})"\}/);
    expect(m).not.toBeNull();
    trace = m?.[1] ?? '';
  }).toPass({ timeout: 15_000 });
  await page.goto(`/#/queries?trace=${trace}`);
  await expect(page.getByTestId('trace-filter')).toContainText(trace);
  await expect(async () => {
    await page.reload();
    await expect(page.locator('table.log tbody tr')).toHaveCount(1, { timeout: 2000 });
  }).toPass({ timeout: 20_000 });
  await expect(page.locator('table.log tbody tr').first()).toContainText('nas.e2e.test');
  await page.getByRole('button', { name: 'Show all queries' }).click();
  await expect(page).not.toHaveURL(/trace=/);
});

test('live view streams new queries', async () => {
  await page.goto('/#/queries?status=blocked');
  await page.getByLabel('Live').check();
  await expect(page.locator('.live-toggle .badge')).toHaveText('streaming');
  await expect(page.locator('table.log tbody tr')).toHaveCount(0);
  await expect(async () => {
    expect(await query('live.ads.e2e.test')).toBe(0);
    await expect(page.locator('table.log tbody tr').first()).toContainText('live.ads.e2e.test', { timeout: 1500 });
  }).toPass({ timeout: 15_000 });
  // Server-side filter: a local answer doesn't match status=blocked.
  expect(await query('nas.e2e.test')).toBe(0);
  await page.waitForTimeout(800);
  await expect(page.locator('table.log tbody tr', { hasText: 'nas.e2e.test' })).toHaveCount(0);
  await page.getByLabel('Live').uncheck();
});

// REQ: OBS-008 — Live starts empty: a page of the query log that was still loading when Live was
// switched on doesn't land in it afterwards (it did, on a slow machine: old rows in a live view).
test('obs_008 a late query-log answer does not fill the live view', async () => {
  await page.goto('/#/rules');
  let release!: () => void;
  const gate = new Promise<void>((r) => (release = r));
  // Only the page loads (`/queries?...`), not the stream (`/queries/stream`). One RegExp object:
  // `unroute` finds the route by identity.
  const pageLoads = /\/api\/v1\/queries\?/;
  await page.route(pageLoads, async (route) => {
    await gate;
    await route.continue();
  });
  try {
    await page.goto('/#/queries?status=blocked');
    await page.getByLabel('Live').check();
    await expect(page.locator('.live-toggle .badge')).toHaveText('streaming');
    release(); // the older answer arrives now: blocked queries from earlier tests are in it
    await page.waitForTimeout(1000);
    await expect(page.locator('table.log tbody tr')).toHaveCount(0);
  } finally {
    release();
    await page.unroute(pageLoads);
    await page.getByLabel('Live').uncheck();
  }
});

test('explain page', async () => {
  await page.goto('/#/explain?name=nas.e2e.test&client=127.0.0.1');
  await expect(page.locator('.explain')).toContainText('local');
  await page.getByRole('textbox', { name: 'Name', exact: true }).fill('ads.e2e.test');
  await page.getByRole('button', { name: 'Explain' }).click();
  await expect(page.locator('.explain')).toContainText('blocked');
});

test('the menu links to the project on GitHub and its site', async () => {
  await page.goto('/#/');
  const gh = page.getByRole('link', { name: 'WrenDNS on GitHub' });
  await expect(gh).toHaveAttribute('href', 'https://github.com/nbacheller/wrendns');
  await expect(gh).toHaveAttribute('target', '_blank');
  await expect(page.getByRole('link', { name: 'Project site and guides' })).toHaveAttribute(
    'href',
    'https://wrendns.com/',
  );
});

// REQ: OBS-015 — the health icon sits left of the project links; its shape and the panel follow
// the level; on phones a dot on the menu button says something's wrong.
test('obs_015 health icon, its reasons, and the phone dot', async () => {
  await page.setViewportSize({ width: 1280, height: 800 });
  await page.goto('/#/');
  const icon = page.getByTestId('health-icon');
  await expect(icon).toBeVisible();
  await expect(icon).toHaveAttribute('data-level', /^(healthy|degraded|severe)$/);
  const [h, gh] = [await icon.boundingBox(), await page.getByRole('link', { name: 'WrenDNS on GitHub' }).boundingBox()];
  expect(h!.x).toBeLessThan(gh!.x);
  await page.route('**/api/v1/system/health', (route) =>
    route.fulfill({
      json: {
        level: 'severe',
        checkedAt: '2026-10-08T12:00:00.000Z',
        reasons: [
          { level: 'severe', code: 'upstream_group_down', summary: 'no upstream in group default is answering (quad9, cloudflare)', node: 'home-pi', link: '#/upstreams' },
          { level: 'degraded', code: 'rate_limited', summary: '12 queries were rate-limited in the last 5 minutes', link: '#/queries?status=rate_limited' },
        ],
      },
    }),
  );
  await page.reload();
  await expect(icon).toHaveAttribute('data-level', 'severe');
  await icon.click();
  const panel = page.getByTestId('health-panel');
  await expect(panel).toContainText('Severe');
  await expect(panel).toContainText('home-pi');
  await expect(panel).toContainText('rate-limited');
  await panel.getByRole('link', { name: 'Look' }).first().click();
  await expect(page).toHaveURL(/#\/upstreams/);
  await page.setViewportSize({ width: 390, height: 844 });
  await expect(page.getByTestId('menu-health-dot')).toBeVisible();
  await page.unroute('**/api/v1/system/health');
  await page.setViewportSize({ width: 1280, height: 800 });
});

// REQ: FLT-004 — the Lists page names the nodes whose hits are left out; when the primary is one of
// them, it says the download state isn't confirmed from the primary (it names the primary by its pod).
test('flt_004 lists page names the unread nodes, and says so when the primary is one', async () => {
  let missing = ['node-b'];
  let nodes: unknown[] = [];
  await page.route('**/api/v1/lists', async (route) => {
    const r = await route.fetch();
    await route.fulfill({ response: r, json: { ...(await r.json()), missingNodes: missing } });
  });
  await page.route('**/api/v1/cluster', async (route) => {
    const r = await route.fetch();
    await route.fulfill({ response: r, json: { ...(await r.json()), nodes } });
  });
  const unread = page.getByTestId('lists-unread');
  await page.goto('/#/lists');
  await expect(unread).toContainText('Hits leave out: node-b.');
  await expect(unread).not.toContainText('confirmed from the primary');
  missing = ['home-pi-0'];
  nodes = [{ role: 'primary', nodeId: 'id-ctl', site: 'home', pod: 'home-pi-0' }];
  await page.reload();
  await expect(unread).toContainText('Not read: home-pi-0.');
  await expect(unread).toContainText("isn't confirmed from the primary");
  await page.unroute('**/api/v1/lists');
  await page.unroute('**/api/v1/cluster');
});

// REQ: OBS-004 (ADR-159, ADR-160) — a top client's bar is split by how its queries were answered
// (a device a peer on an older build reported has none), and the top lists follow the range: they
// ask for it and say which hours they cover, except for one group's lists, which are this hour's.
test('obs_004 top clients split by status; the top lists follow the range', async () => {
  await page.setViewportSize({ width: 1280, height: 800 });
  await page.route('**/api/v1/stats/top?*', (route) => {
    if (new URL(route.request().url()).searchParams.get('kind') !== 'clients') return route.fallback();
    return route.fulfill({
      json: {
        items: [
          { key: '10.9.9.9', name: 'Kitchen TV', count: 100, errorBound: 0, byStatus: { blocked: 60, cached: 25, forwarded: 10 } },
          { key: '10.9.9.8', count: 40, errorBound: 0 },
        ],
      },
    });
  });
  const clientsFrom24h = page.waitForRequest((r) => /stats\/top\?/.test(r.url()) && r.url().includes('kind=clients') && r.url().includes('from=-24h'));
  await page.goto('/#/');
  await page.reload();
  await clientsFrom24h;
  const clients = listOf('Top clients');
  await expect(clients.getByTestId('clients-legend')).toBeVisible();
  const split = clients.getByTestId('client-split');
  await expect(split).toHaveCount(1);
  await expect(split).toHaveAccessibleName('60 blocked · 25 cached · 10 forwarded · 5 other');
  // Tapping the count shows the numbers.
  await clients.getByRole('button', { name: /^Details for Kitchen TV/ }).click();
  await expect(clients.locator('.how')).toContainText('blocked');
  await expect(clients.locator('.how')).toContainText('60');
  // The headings say which hours they cover: the range, or this hour for one group.
  await expect(listOf('Top domains')).toContainText('last 24 h');
  await page.getByRole('button', { name: '15 min', exact: true }).click();
  await expect(listOf('Top domains')).toContainText(/since \d/);
  const groupOnly = page.waitForRequest((r) => /stats\/top\?/.test(r.url()) && r.url().includes('kind=blocked') && r.url().includes('group=lab') && !r.url().includes('from='));
  await pick(page, 'Group', 'lab');
  await groupOnly;
  await expect(listOf('Top domains')).toContainText('this hour');
  await page.getByRole('group', { name: 'Group', exact: true }).getByTestId('picker-clear').click();
  await page.unroute('**/api/v1/stats/top?*');
});

// T6.8 — a chart's legend sits above the plot and wraps; its values change on hover ("total"
// becomes a time, the range's sums one bucket's counts). Each keeps its width, so on a narrow
// screen the legend doesn't rewrap and move the plot under the cursor.
test('chart legend keeps its place while hovering', async () => {
  // This legend is the shared Chart's (the previous dashboard, the Cache page); the new
  // dashboard's chart has a legend of its own that doesn't change on hover (ADR-157).
  await page.goto('/#/?view=legacy');
  const card = page.locator('section.card.chart', { hasText: 'Queries by status' });
  const over = card.locator('.u-over');
  const layout = () =>
    card.evaluate((c) => {
      const top = c.getBoundingClientRect().top;
      const items = [...c.querySelectorAll('.u-legend tr')].map((t) => Math.round(t.getBoundingClientRect().width));
      return `${items.join(',')} plot at ${Math.round(c.querySelector('.u-over')!.getBoundingClientRect().top - top)}`;
    });
  for (const width of [340, 360, 390, 420]) {
    await page.setViewportSize({ width, height: 844 });
    // A new width (and every refresh) rebuilds the chart: measure once it has settled, and
    // again if a rebuild lands mid-check.
    await expect(async () => {
      await over.scrollIntoViewIfNeeded();
      await page.mouse.move(0, 0);
      const rest = await layout();
      const box = (await over.boundingBox())!;
      for (const f of [0.1, 0.5, 0.9]) {
        await page.mouse.move(box.x + box.width * f, box.y + box.height / 2);
        expect(await layout(), `${width}px wide, hovering at ${f}`).toBe(rest);
      }
    }).toPass({ timeout: 15_000 });
  }
  await page.mouse.move(0, 0);
  await page.setViewportSize({ width: 1280, height: 800 });
  // The choice of the previous dashboard is remembered: put the new one back for the tests after.
  await page.goto('/#/?view=new');
  await expect(page.getByTestId('dashboard-chart')).toBeVisible();
});

// REQ: OBS-016 — the dashboard's Service level card (Advanced view only): the server's
// objectives (a few local answers make them "on track"), then a stubbed outage that burns the
// availability budget fast.
test('obs_016 service level card', async () => {
  await page.setViewportSize({ width: 1280, height: 800 });
  for (let i = 0; i < 5; i++) await query(`slo${i}.localhost`).catch(() => 0);
  await page.goto('/#/');
  const card = page.getByTestId('slo-card');
  await expect(page.getByRole('heading', { name: 'Dashboard' })).toBeVisible();
  await expect(card).toHaveCount(0);
  await page.getByRole('button', { name: 'Advanced', exact: true }).click();
  await expect(card).toContainText('Service level');
  await expect(card).toContainText('last 30 days');
  await expect(card.getByTestId('slo-availability')).toContainText('Answers that work');
  await expect(card.getByTestId('slo-latency')).toContainText('answers sent within 250 ms');
  const burns = (rates: number[]) =>
    ['5m', '30m', '1h', '6h', '3d'].map((window, i) => ({ window, rate: rates[i], total: 10000, bad: Math.round(rates[i] * 10) }));
  await page.route('**/api/v1/stats/slo*', (route) =>
    route.fulfill({
      json: {
        enabled: true,
        windowDays: 30,
        objectives: [
          {
            name: 'availability', goodMeans: "answers that aren't SERVFAIL", targetPercent: 99.9, sliPercent: 99.912,
            good: 999120, total: 1000000, budgetRemainingPercent: 12, burnRates: burns([20.1, 17.5, 16.2, 3.1, 1.2]),
            alert: 'fast', summary: 'availability: …',
          },
          {
            name: 'latency', goodMeans: 'answers sent within 250 ms', targetPercent: 99, latencyMs: 250, sliPercent: 99.7,
            good: 997000, total: 1000000, budgetRemainingPercent: 70, burnRates: burns([0.2, 0.3, 0.3, 0.3, 0.3]), summary: 'latency: …',
          },
        ],
      },
    }),
  );
  await page.reload();
  const a = card.getByTestId('slo-availability');
  await expect(a).toContainText('burning fast');
  await expect(a).toContainText('99.912%');
  await expect(a).toContainText('12% of the error budget left');
  await expect(a).toContainText('1h 16×');
  await expect(card.getByTestId('slo-latency')).toContainText('on track');
  await page.unroute('**/api/v1/stats/slo*');
  await page.getByRole('button', { name: 'Simple', exact: true }).click();
  await expect(card).toHaveCount(0);
});

// REQ: DNS-007 (ADR-119) — the cache tile is one number for everyone (fresh, refreshed, and
// stale answers from the cache); the Advanced view splits it into fresh and refreshed.
test('dns_007 cache tile: one number, split in the Advanced view', async () => {
  await page.setViewportSize({ width: 1280, height: 800 });
  await page.route('**/api/v1/stats/summary*', (route) =>
    route.fulfill({
      json: {
        fromUnixSeconds: 0, toUnixSeconds: 1, queries: 1500, blocked: 500, blockedPercent: 33.3, cached: 600,
        refreshed: 200, cacheHitPercent: 60, forwarded: 400, nxdomain: 3, servfail: 1, activeClients: 4, latency: [],
      },
    }),
  );
  await page.goto('/#/');
  await page.reload(); // the page may already show the dashboard (a hash change doesn't reload)
  const tile = page.getByTestId('stat-cache');
  await expect(tile).toContainText('60.0%');
  await expect(tile).toContainText('600 answers');
  await page.getByRole('button', { name: 'Advanced', exact: true }).click();
  await expect(tile).toContainText('60.0%');
  await expect(tile).toContainText(/40\.0% fresh · 20\.0% refreshed/);
  await page.getByRole('button', { name: 'Simple', exact: true }).click();
  await expect(tile).toContainText('600 answers');
  await page.unroute('**/api/v1/stats/summary*');
});

// REQ: OBS-020 — Settings → System lists the listener probes: the e2e server's UDP listener
// answers its own probe (every 5 s there), and probe queries stay out of the query log.
test('obs_020 listener checks', async () => {
  await page.goto('/#/settings?tab=system');
  const card = page.getByTestId('probes');
  await expect(card).toContainText('Listener checks');
  await expect(card).toContainText(`udp://127.0.0.1:${DNS_PORT}`, { timeout: 15_000 });
  await expect(card).toContainText('answers');
  const log = await page.evaluate(async () =>
    (await fetch('/api/v1/queries?name=probe.wrendns.invalid&limit=5')).json(),
  );
  expect(log.items).toEqual([]);
  // REQ: API-003 (ADR-149) — the web UI's own check: a self-signed certificate says it doesn't
  // expire, and shows its names and fingerprint (stubbed: the e2e server has no [api] tls).
  const sha = Array.from({ length: 32 }, (_, i) => i.toString(16).padStart(2, '0').toUpperCase()).join(':');
  await page.route('**/api/v1/system/probes', (route) =>
    route.fulfill({
      json: {
        items: [{
          target: `https://127.0.0.1:${PORTS.probeTarget}/livez`, proto: 'api', listener: true, ok: true, latencyMs: 3.2,
          consecutiveFailures: 0, checkedUnixSeconds: 1, certExpiresUnixSeconds: 67_000_000_000, certDaysLeft: 770_000,
          certSha256: sha, certNames: ['localhost', '10.30.3.2'], certSelfSigned: true,
        }],
      },
    }),
  );
  await page.reload();
  await expect(card).toContainText('Web UI and API');
  await expect(card).toContainText("self-signed certificate (doesn't expire)");
  await expect(card.getByTestId('cert-names')).toContainText('localhost, 10.30.3.2');
  await expect(card.getByTestId('cert-sha256')).toContainText(sha);
  await page.unroute('**/api/v1/system/probes');
});

// REQ: DNS-901 (T36.2) — Settings → System → Listener access: each listener's device-key gate, and
// a warning for a listener on a public address that does not require a key (stubbed: the e2e
// server binds loopback), with the help topic.
test('dns_901 listener access warns about a public listener without a device key', async () => {
  await page.route('**/api/v1/system/info', async (route) => {
    const res = await route.fetch();
    const info = await res.json();
    const base = { gatedByDefault: false, wildcardBind: false, canCarryKey: true, setting: 'unset', defaultOn: false, defaultReason: 'off, because the address is not public', publicExposure: false };
    info.listenerAccess = [
      { ...base, listener: 'dot://203.0.113.5:853', requireClientId: false, publicAddress: true, publicExposure: true, setting: 'false' },
      { ...base, listener: 'doh://203.0.113.5:443', requireClientId: true, publicAddress: true, setting: 'true' },
      { ...base, listener: 'udp://192.168.1.2:53', requireClientId: false, publicAddress: false, canCarryKey: false },
      { ...base, listener: 'doq://203.0.113.5:853', requireClientId: true, publicAddress: true, gatedByDefault: true, defaultOn: true, defaultReason: 'on, because the address is public', publicExposure: true },
      { ...base, listener: 'dot://0.0.0.0:853', requireClientId: false, publicAddress: false, wildcardBind: true, defaultReason: 'off, because it binds every address and this host has no public IPv4 address' },
    ];
    await route.fulfill({ response: res, json: info });
  });
  await page.goto('/#/settings?tab=system');
  await page.reload(); // the page may already be on this tab (a hash change doesn't reload), with the real info cached
  const card = page.getByTestId('listener-access');
  await expect(card).toContainText('Listener access');
  const rows = card.getByTestId('listener-access-row');
  await expect(rows).toHaveCount(5);
  await expect(rows.nth(0)).toContainText('not required');
  await expect(rows.nth(0).getByTestId('listener-open-warning')).toContainText('public address');
  await expect(rows.nth(0)).toContainText('open resolver');
  await expect(rows.nth(1)).toContainText('required');
  await expect(rows.nth(1)).toContainText('Answers only a known device key');
  await expect(rows.nth(1).getByTestId('listener-open-warning')).toHaveCount(0);
  await expect(rows.nth(2).getByTestId('listener-open-warning')).toHaveCount(0);
  await expect(rows.nth(3).getByTestId('listener-default-notice')).toContainText('on by default');
  await expect(rows.nth(3)).toContainText('require_client_id');
  await expect(rows.nth(4).getByTestId('listener-wildcard-notice')).toContainText('every address');
  await expect(rows.nth(4)).toContainText('this host has no public IPv4 address');
  await card.getByRole('button', { name: /help/i }).first().click();
  await expect(page.getByText('Device keys on a public listener').first()).toBeVisible();
  await page.unroute('**/api/v1/system/info');
});

// REQ: DNS-901, API-902 (T27.14) — Settings → System → Listener access: the admin's three-state
// control per listener (default, on, off), what the default resolves to and why, the open-resolver
// warning when a public listener's gate is turned off, no control for plain UDP, and the guarded
// review with the whole set of listeners in its request and the red "weakens security" mark. The
// listeners and the preview are stubbed (the e2e server binds one loopback UDP listener).
test('dns_901 listener gate is changed through the guarded review', async () => {
  await page.route('**/api/v1/system/info', async (route) => {
    const res = await route.fetch();
    const info = await res.json();
    const base = { gatedByDefault: false, wildcardBind: false, canCarryKey: true, setting: 'unset', publicAddress: false, requireClientId: false, defaultOn: false, defaultReason: 'off, because the address is not public', publicExposure: false };
    info.listenerAccess = [
      { ...base, listener: 'dot://203.0.113.5:853', requireClientId: true, publicAddress: true, gatedByDefault: true, defaultOn: true, defaultReason: 'on, because the address is public', publicExposure: true },
      { ...base, listener: 'doh://192.168.1.2:443' },
      { ...base, listener: 'udp://192.168.1.2:53', canCarryKey: false },
      { ...base, listener: 'doq://0.0.0.0:853', wildcardBind: true, requireClientId: true, gatedByDefault: true, defaultOn: true, defaultReason: 'on, because it binds every address and this host has a public IPv4 address', publicExposure: true },
    ];
    await route.fulfill({ response: res, json: info });
  });
  let previewBody: { value?: { listeners?: Array<{ proto: string; addr: string; require_client_id: boolean | null }> } } = {};
  await page.route('**/api/v1/guarded/listen-access/preview', async (route) => {
    previewBody = route.request().postDataJSON();
    await route.fulfill({
      json: {
        previewId: 'stub',
        setting: 'listen-access',
        node: 'home-dns',
        nodes: ['home-dns'],
        mode: 'immediate',
        phrase: 'home-dns listen-access',
        effect: 'Changes the device key setting on home-dns.',
        weakening: true,
        needsRecentSignIn: true,
        restartRequired: false,
        setByFile: false,
        warnings: ['dot://203.0.113.5:853 is on a public address.'],
        checks: [],
      },
    });
  });
  await page.goto('/#/settings?tab=system');
  await page.reload(); // as above: the stub must answer the page's own info request
  const gate = page.getByTestId('listener-gate');
  await expect(gate).toBeVisible();
  const rows = gate.getByTestId('listener-gate-row');
  await expect(rows).toHaveCount(4);
  await expect(rows.nth(3).getByTestId('listener-gate-default')).toContainText('binds every address and this host has a public IPv4 address');
  await expect(rows.nth(0).getByTestId('listener-gate-default')).toContainText('on, because the address is public');
  await expect(rows.nth(1).getByTestId('listener-gate-default')).toContainText('off, because the address is not public');
  await expect(rows.nth(2).getByTestId('listener-gate-plain')).toContainText('not available');
  await expect(rows.nth(2).getByTestId('listener-gate-select')).toHaveCount(0);
  // Nothing to review until a state changes.
  await expect(gate.getByTestId('guarded-start-listen-access')).toBeDisabled();
  await expect(gate.getByTestId('listener-gate-open-warning')).toHaveCount(0);
  await rows.nth(0).getByTestId('listener-gate-select').selectOption('off');
  await expect(rows.nth(0).getByTestId('listener-gate-open-warning')).toContainText('open resolver');
  await expect(rows.nth(0).getByTestId('listener-gate-result')).toContainText('becomes off');
  await gate.getByTestId('guarded-start-listen-access').click();
  await expect(gate.getByTestId('guarded-weakens')).toBeVisible();
  await expect(gate.getByTestId('guarded-phrase')).toHaveText('home-dns listen-access');
  expect(previewBody.value?.listeners).toEqual([
    { proto: 'dot', addr: '203.0.113.5:853', require_client_id: false },
    { proto: 'doh', addr: '192.168.1.2:443', require_client_id: null },
    { proto: 'udp', addr: '192.168.1.2:53', require_client_id: null },
    { proto: 'doq', addr: '0.0.0.0:853', require_client_id: null },
  ]);
  await page.unroute('**/api/v1/guarded/listen-access/preview');
  await page.unroute('**/api/v1/system/info');
});

// REQ: OPS-010 — maintenance from the Cluster page (the e2e server runs on its own): /readyz
// turns 503 with the reason while DNS keeps answering, the banners and the health note show,
// and ending it makes the node ready again.
test('ops_010 maintenance from the Cluster page', async () => {
  await page.setViewportSize({ width: 1280, height: 800 });
  await page.goto('/#/cluster');
  await page.getByTestId('maintenance-open').first().click();
  const form = page.getByTestId('maintenance-form');
  await form.getByLabel('30 min').check();
  await form.getByTestId('maintenance-reason').fill('e2e SD card swap');
  await form.getByTestId('maintenance-start').click();
  const banner = page.getByTestId('maintenance-banner');
  await expect(banner).toContainText('e2e SD card swap');
  const ready = await page.request.get('/readyz');
  expect(ready.status()).toBe(503);
  expect(await ready.json()).toEqual({ ready: false, reason: 'maintenance' });
  expect((await page.request.get('/readyz?startup=1')).status()).toBe(200);
  expect(await query('nas.e2e.test')).toBe(0);
  await page.getByTestId('health-icon').click();
  await expect(page.getByTestId('health-maintenance')).toContainText('e2e SD card swap');
  await page.keyboard.press('Escape');
  await page.goto('/#/');
  await expect(page.getByTestId('maintenance-app-banner')).toContainText('e2e SD card swap');
  await page.goto('/#/cluster');
  await page.getByTestId('maintenance-end-banner').click();
  await expect(banner).toHaveCount(0);
  expect((await page.request.get('/readyz')).status()).toBe(200);
});

// REQ: API-005, OBS-011 (GitHub issue #9) — the Upstreams page says Healthy, Benched, and
// Probing, not the circuit breaker's closed, open, and half_open; the breaker's own word is the
// tooltip (and stays in the API and the metrics).
test('api_005 upstream health reads in plain words', async () => {
  const upstream = (id: number, name: string, breaker: string) => ({
    breaker,
    endpoint: `tls://192.0.2.${id}`,
    failures: 0,
    failuresByKind: {},
    groups: ['default'],
    id,
    latencyEwmaMs: 5,
    name,
    requests: 10,
  });
  const isUpstreams = (url: URL) => url.pathname === '/api/v1/upstreams';
  const stub = (route: Route) =>
    route.fulfill({
      json: {
        items: [upstream(1, 'up-ok', 'closed'), upstream(2, 'up-benched', 'open'), upstream(3, 'up-probe', 'half_open')],
      },
    });
  await page.route(isUpstreams, stub);
  try {
    await page.goto('/#/upstreams');
    const word = (name: string, text: string) => page.getByRole('row', { name: new RegExp(name) }).getByText(text, { exact: true });
    await expect(word('up-ok', 'Healthy')).toBeVisible();
    await expect(word('up-benched', 'Benched')).toBeVisible();
    await expect(word('up-probe', 'Probing')).toBeVisible();
    // The pattern's own word is one hover away, for anyone who knows it.
    await expect(word('up-benched', 'Benched')).toHaveAttribute('title', 'circuit breaker: open');
    await expect(word('up-probe', 'Probing')).toHaveAttribute('title', 'circuit breaker: half_open');
    // Nobody has to decode closed, open, or half_open.
    await expect(page.locator('main')).not.toContainText('half_open');
  } finally {
    await page.unroute(isUpstreams, stub);
  }
});

// REQ: UPS-006 (fork #25) — an upstream the node has no route to says so on the Upstreams page.
test('ups_006 upstream with no route says why', async () => {
  const upstream = (id: number, name: string, extra: object) => ({
    breaker: 'open',
    endpoint: `udp://192.0.2.${id}`,
    failures: 0,
    failuresByKind: {},
    groups: ['default'],
    id,
    latencyEwmaMs: 5,
    name,
    requests: 10,
    ...extra,
  });
  const isUpstreams = (url: URL) => url.pathname === '/api/v1/upstreams';
  const stub = (route: Route) =>
    route.fulfill({
      json: { items: [upstream(1, 'up-fine', { breaker: 'closed' }), upstream(2, 'up-v6', { routeProblem: 'this node has no IPv6 route' })] },
    });
  await page.route(isUpstreams, stub);
  try {
    await page.goto('/#/upstreams');
    await page.reload(); // the previous test left this route open, and the page polls every 10 s
    const row = (name: string) => page.getByRole('row', { name: new RegExp(name) });
    await expect(row('up-v6').getByTestId('route-problem')).toContainText('this node has no IPv6 route');
    await expect(row('up-fine').getByTestId('route-problem')).toHaveCount(0);
  } finally {
    await page.unroute(isUpstreams, stub);
  }
});

// REQ: UPS-013 (T24.31, ADR-997) — an upstream's source address: the Upstreams form offers this
// node's own addresses and networks, and a source the node lost shows as a problem on its row.
test('ups_013 upstream source address: suggestions and a lost-address problem', async () => {
  const isUpstreams = (url: URL) => url.pathname === '/api/v1/upstreams';
  const isInfo = (url: URL) => url.pathname === '/api/v1/system/info';
  const upstreams = (route: Route) =>
    route.fulfill({
      json: {
        items: [
          { breaker: 'closed', endpoint: 'tls://192.0.2.1', failures: 0, failuresByKind: {}, groups: ['default'], id: 1, latencyEwmaMs: 5, name: 'from-vlan', requests: 3, source: '198.51.100.252' },
          { breaker: 'closed', endpoint: 'tls://192.0.2.2', failures: 0, failuresByKind: {}, groups: ['default'], id: 2, latencyEwmaMs: 5, name: 'lost-src', requests: 3, source: '198.51.100.9', sourceProblem: 'its source address 198.51.100.9 is no longer held by this node: queries to it fail' },
        ],
      },
    });
  const info = async (route: Route) => {
    const res = await route.fetch();
    const body = await res.json();
    body.addresses = [{ interface: 'eth0.100', address: '198.51.100.252', network: '198.51.100.0/24' }];
    await route.fulfill({ response: res, json: body });
  };
  await page.route(isUpstreams, upstreams);
  await page.route(isInfo, info);
  try {
    await page.goto('/#/upstreams');
    await page.getByTestId('view-advanced').click(); // T24.36: the editors are in the Advanced view
    await page.reload();
    await expect(page.getByTestId('upstream-source').first()).toHaveText('from 198.51.100.252');
    await expect(page.getByTestId('upstream-source-problem')).toContainText('no longer held by this node');
    await page.getByRole('button', { name: 'Advanced', exact: true }).click();
    await page.getByRole('button', { name: 'Add upstream', exact: true }).click();
    const field = page.getByRole('combobox', { name: 'Source address', exact: true });
    await expect(field).toBeVisible();
    const listId = await field.getAttribute('list');
    expect(listId).toBeTruthy();
    const opts = await page.locator(`datalist#${listId} option`).evaluateAll((o) => o.map((x) => (x as HTMLOptionElement).value));
    expect(opts).toEqual(['198.51.100.0/24', '198.51.100.252']);
  } finally {
    await page.unroute(isUpstreams, upstreams);
    await page.unroute(isInfo, info);
  }
});

// REQ: UPS-013 (ADR-997 §4) — a real save of a `source` this node doesn't hold is refused with a
// message that names the problem, on a dry run too, and nothing is stored.
test('ups_013 a source this node does not hold is refused on save', async () => {
  const r = page.request;
  const h = { 'x-csrf-token': await csrfOf(r) };
  const body = { url: 'udp://192.0.2.1', source: '203.0.113.9' };
  for (const q of ['?dryRun=true', '']) {
    const put = await r.put(`/api/v1/upstreams/ups013-foreign${q}`, { headers: h, data: body });
    expect(put.status(), await put.text()).toBe(422);
    expect(await put.text()).toContain('holds no such address');
  }
  const list = await (await r.get('/api/v1/upstreams')).json();
  expect(list.items.some((u: { name: string }) => u.name === 'ups013-foreign')).toBe(false);
  // The loopback network is held by every node: saved, and shown on the row.
  const ok = await r.put('/api/v1/upstreams/ups013-held', { headers: h, data: { url: 'udp://192.0.2.1', source: '127.0.0.0/8' } });
  expect(ok.status(), await ok.text()).toBe(200);
  try {
    const row = (await (await r.get('/api/v1/upstreams')).json()).items.find((u: { name: string }) => u.name === 'ups013-held');
    expect(row.source).toBe('127.0.0.1');
  } finally {
    await r.delete('/api/v1/upstreams/ups013-held', { headers: h });
  }
});

// REQ: DNS-012, DNS-902 (T40.1) — the options of a recursive:// upstream (minimising names, 0x20,
// IPv6 and which server addresses are asked) are shown for that address only, start at their
// defaults, and are saved with the upstream; a recursive object is never written for another
// address.
test('dns_902 recursive upstream options are shown for recursive:// only and saved', async () => {
  const r = page.request;
  const h = { 'x-csrf-token': await csrfOf(r) };
  const labels = {
    minimise: 'Send each server only the part of the name it needs',
    caps: 'Randomise the letter case of each query (0x20)',
    ipv6: 'Ask servers over IPv6 too',
    local: 'Ask servers at loopback and link-local addresses',
    priv: 'Ask servers at private addresses outside the stub zone',
  };
  const sw = (label: string) => page.getByRole('switch', { name: label, exact: true });
  try {
    await page.goto('/#/upstreams');
    // The previous test left its "Add upstream" drawer open, and a same-hash goto does not reload:
    // its backdrop would cover the view switch and the click would wait until the test timed out.
    await page.reload();
    await page.getByTestId('view-advanced').click();
    const editor = page.getByTestId('editor-upstream');
    await editor.getByRole('button', { name: 'Add upstream', exact: true }).click();
    await page.getByRole('textbox', { name: 'Name', exact: true }).fill('dns902-rec');
    const address = page.getByRole('textbox', { name: 'Address', exact: true });
    // An ordinary address: none of the recursive options.
    await address.fill('udp://192.0.2.1');
    for (const l of Object.values(labels)) await expect(sw(l)).toHaveCount(0);
    // A recursive address: all of them, at their defaults.
    await address.fill('recursive://');
    await expect(sw(labels.minimise)).toBeChecked();
    for (const l of [labels.caps, labels.ipv6, labels.local, labels.priv]) await expect(sw(l)).not.toBeChecked();
    await sw(labels.caps).click();
    await sw(labels.priv).click();
    await page.getByRole('button', { name: 'Check', exact: true }).click();
    await expect(page.getByTestId('entry-preview')).toBeVisible();
    const isPut = (q: Request) => q.method() === 'PUT' && q.url().endsWith('/api/v1/upstreams/dns902-rec');
    const firstPut = page.waitForRequest(isPut);
    await page.getByRole('button', { name: 'Apply', exact: true }).click();
    // Only what was changed is sent: the options left at their defaults are not frozen into the entry.
    expect(JSON.parse((await firstPut).postData() ?? '{}').recursive).toEqual({ case_randomization: true, allow_private_servers: true });
    const row = editor.getByTestId('entry-row').filter({ hasText: 'dns902-rec' });
    await expect(row).toContainText('recursive://');
    // The server returns the entry with its defaults filled in.
    const saved = async () => {
      const list = await (await r.get('/api/v1/config/entries?kind=upstream')).json();
      return list.items.find((e: { name: string }) => e.name === 'dns902-rec');
    };
    expect((await saved()).definition.recursive).toMatchObject({ case_randomization: true, allow_private_servers: true, allow_local_servers: false, ipv6: false, qname_minimization: true });
    // Opened again, the saved options are what the switches show; the default-on one still reads on.
    await row.getByRole('button', { name: 'Edit' }).click();
    await expect(sw(labels.caps)).toBeChecked();
    await expect(sw(labels.priv)).toBeChecked();
    await expect(sw(labels.minimise)).toBeChecked();
    await expect(sw(labels.local)).not.toBeChecked();
    // Changing the address to a plain one hides them again and writes no recursive object.
    await page.getByRole('textbox', { name: 'Address', exact: true }).fill('udp://192.0.2.2');
    await expect(sw(labels.caps)).toHaveCount(0);
    await page.getByRole('button', { name: 'Check', exact: true }).click();
    const secondPut = page.waitForRequest(isPut);
    await page.getByRole('button', { name: 'Apply', exact: true }).click();
    expect(JSON.parse((await secondPut).postData() ?? '{}')).not.toHaveProperty('recursive');
    await expect(row).toContainText('udp://192.0.2.2');
  } finally {
    await r.delete('/api/v1/upstreams/dns902-rec', { headers: h });
    await page.getByRole('button', { name: 'Simple', exact: true }).click({ timeout: 2000 }).catch(() => {});
  }
});

// REQ: DNS-902, DNS-022 (T40.1) — a stub-zone forward whose server is on this machine cannot be
// saved until the "ask a server on this machine" box is ticked; the box is kept when the forward
// is opened again, a private server gets its own optional box, and a re-save that does not
// mention the flags (the API, an agent) keeps them.
test('dns_902 stub forward allowances in the forward form', async () => {
  const r = page.request;
  const h = { 'x-csrf-token': await csrfOf(r) };
  const forward = async () => (await (await r.get('/api/v1/forwards')).json()).items.find((f: { domain: string }) => f.domain === 'stub902.example');
  try {
    await page.goto('/#/local-dns');
    await page.reload();
    await page.getByRole('button', { name: 'Send a domain to another server', exact: true }).click();
    const form = page.locator('form').filter({ has: page.getByLabel('Only for these query types (optional)') });
    await form.getByLabel('Domain', { exact: true }).fill('stub902.example');
    await form.getByLabel('Server address', { exact: true }).fill('127.0.0.1');
    // Not a stub zone yet: no boxes, nothing blocked.
    await expect(form.locator('input[name="allow-local-servers"]')).toHaveCount(0);
    await form.locator('input[name="stub"]').check();
    const local = form.locator('input[name="allow-local-servers"]');
    await expect(local).not.toBeChecked();
    await expect(form.getByTestId('local-server-blocked')).toContainText('Tick the box above to save');
    await expect(form.getByRole('button', { name: 'Save' })).toBeDisabled();
    await local.check();
    await expect(form.getByTestId('local-server-blocked')).toHaveCount(0);
    await expect(form.locator('input[name="allow-private-servers"]')).toHaveCount(0);
    await form.getByRole('button', { name: 'Save' }).click();
    await expect(page.getByRole('status').filter({ hasText: 'stub902.example' })).toBeVisible();
    await page.getByRole('dialog').getByRole('button', { name: 'Close' }).click();
    expect(await forward()).toMatchObject({ stub: true, allowLocalServers: true, allowPrivateServers: false });
    // Opened again: ticked from the stored value; a private server adds the optional box.
    const row = page.locator('tr').filter({ hasText: 'stub902.example' });
    await row.getByRole('button', { name: 'Edit stub902.example' }).click();
    const again = page.locator('form').filter({ has: page.getByLabel('Only for these query types (optional)') });
    await expect(again.locator('input[name="allow-local-servers"]')).toBeChecked();
    await again.getByLabel('Server address', { exact: true }).fill('127.0.0.1 10.9.9.9');
    const priv = again.locator('input[name="allow-private-servers"]');
    await expect(priv).not.toBeChecked();
    await expect(again.getByRole('button', { name: 'Save' })).toBeEnabled();
    await priv.check();
    await again.getByRole('button', { name: 'Save' }).click();
    await expect(page.getByRole('status').filter({ hasText: 'stub902.example' })).toBeVisible();
    await page.getByRole('dialog').getByRole('button', { name: 'Close' }).click();
    expect(await forward()).toMatchObject({ allowLocalServers: true, allowPrivateServers: true });
    // A re-save through the API that does not mention the flags keeps them; a plain forward is refused them.
    const put = await r.put('/api/v1/forwards/stub902.example', { headers: h, data: { servers: ['127.0.0.1'], stub: true } });
    expect(put.status()).toBe(200);
    // ...but a flag that no listed server needs (here the private one, with only 127.0.0.1 left) is dropped.
    expect(await forward()).toMatchObject({ allowLocalServers: true, allowPrivateServers: false });
    const bad = await r.put('/api/v1/forwards/stub902.example', { headers: h, data: { servers: ['10.9.9.9'], allowLocalServers: true } });
    expect(bad.status()).toBeGreaterThanOrEqual(400);
    // Asking for an allowance with no matching server is refused, not stored hidden.
    const hidden = await r.put('/api/v1/forwards/stub902.example', { headers: h, data: { servers: ['203.0.113.5'], stub: true, allowLocalServers: true } });
    expect(hidden.status()).toBeGreaterThanOrEqual(400);
    expect(hidden.status()).toBeLessThan(500);
    // In the form: the server changes to a non-local address; the hidden box must not keep the allowance stored.
    await page.goto('/#/local-dns');
    await page.reload();
    await page.locator('tr').filter({ hasText: 'stub902.example' }).getByRole('button', { name: 'Edit stub902.example' }).click();
    const moved = page.locator('form').filter({ has: page.getByLabel('Only for these query types (optional)') });
    await expect(moved.locator('input[name="allow-local-servers"]')).toBeChecked();
    await moved.getByLabel('Server address', { exact: true }).fill('203.0.113.5');
    await expect(moved.locator('input[name="allow-local-servers"]')).toHaveCount(0);
    await expect(moved.locator('input[name="allow-private-servers"]')).toHaveCount(0);
    await moved.getByRole('button', { name: 'Save' }).click();
    await expect(page.getByRole('status').filter({ hasText: 'stub902.example' })).toBeVisible();
    await page.getByRole('dialog').getByRole('button', { name: 'Close' }).click();
    expect(await forward()).toMatchObject({ stub: true, allowLocalServers: false, allowPrivateServers: false });
  } finally {
    await r.delete('/api/v1/forwards/stub902.example', { headers: h });
  }
});

// REQ: UPS-004 (T24.36) — what the simple view's ticks mean as upstream entries, and back.
test('ups_004 picker plans entries from ticks and reads them back', async () => {
  const r = page.request;
  const { items, ipv6Route } = await (await r.get('/api/v1/upstream-presets')).json();
  expect(typeof ipv6Route).toBe('boolean');
  const cf = items.find((p: { id: string }) => p.id === 'cloudflare');
  const nd = items.find((p: { id: string }) => p.id === 'nextdns');
  expect(cf.simple).toBe(true);
  expect(nd.simple, 'a preset that needs a parameter is for the Advanced view').toBe(false);
  const providers = items.filter((p: { simple: boolean }) => p.simple).map((p: { provider: string }) => p.provider);
  for (const want of ['Cloudflare', 'Google', 'Quad9', 'OpenDNS', 'AdGuard', 'Mullvad', 'CleanBrowsing']) expect(providers).toContain(want);
  const urls = (t: Transport, v4: boolean, v6: boolean) =>
    planFor(items, new Set(['cloudflare']), t, v4, v6).entries.map((e) => e.url);
  expect(urls('encrypted', true, false)).toEqual(['tls://1.1.1.1', 'tls://1.0.0.1']);
  expect(urls('encrypted', false, true)).toEqual(['tls://[2606:4700:4700::1111]', 'tls://[2606:4700:4700::1001]']);
  expect(urls('plain', true, false)).toEqual(['udp://1.1.1.1', 'udp://1.0.0.1']);
  expect(urls('plain', true, true)).toHaveLength(4);
  const first = planFor(items, new Set(['cloudflare']), 'encrypted', true, false).entries[0];
  expect(first).toEqual({ name: 'pub-cloudflare-tls-1', url: 'tls://1.1.1.1', tls_server_name: 'cloudflare-dns.com' });
  // Mullvad has no plain address: the encrypted one is used, and the plan says so.
  const mv = planFor(items, new Set(['mullvad']), 'plain', true, false);
  expect(mv.fellBack).toEqual(['mullvad']);
  expect(mv.entries.every((e) => e.url.startsWith('tls://'))).toBe(true);
  // Entries come back as the same ticks, transport and families.
  const saved = (name: string, url: string) => ({ kind: 'upstream', name, source: 'added', definition: { url } }) as never;
  const back = readSaved(
    [saved('pub-cloudflare-tls-1', 'tls://1.1.1.1'), saved('pub-custom-2', 'udp://9.9.9.9'), saved('nowhere', 'udp://127.0.0.1:9')],
    items,
  );
  expect([...back.ticked]).toEqual(['cloudflare']);
  expect(back.transport).toBe('encrypted');
  expect(back.v4).toBe(true);
  expect(back.v6).toBe(false);
  expect(back.customs.map((c) => c.url)).toEqual(['udp://9.9.9.9']);
  expect(customUrl('9.9.9.9')).toBe('udp://9.9.9.9');
  expect(customUrl('2606:4700:4700::1111')).toBe('udp://[2606:4700:4700::1111]');
  expect(customUrl('https://dns.example.net/dns-query')).toBe('https://dns.example.net/dns-query');
  expect(customUrl('not an address')).toBeNull();
  expect(nextCustomName(['pub-custom-1', 'pub-custom-3'])).toBe('pub-custom-2');
});

// REQ: UPS-004, API-002 (T24.36) — the Upstreams page opens on the simple view; ticking providers
// writes upstream entries and the default group (fastest); the config file's upstream is kept;
// Advanced shows what the simple view made, and switching views loses nothing.
test('ups_004 the simple view writes upstreams and the default group', async () => {
  const r = page.request;
  const h = { 'x-csrf-token': await csrfOf(r) };
  await page.goto('/#/upstreams');
  await page.evaluate(() => localStorage.removeItem('upstreams-view'));
  await page.reload();
  await expect(page.getByTestId('upstream-picker')).toBeVisible();
  await expect(page.getByTestId('editor-upstream')).toBeHidden();
  await expect(page.getByTestId('pick-cloudflare')).not.toBeChecked();
  // The file's own upstream is listed and left alone.
  await expect(page.getByTestId('picker-others')).toContainText('nowhere');
  try {
    // Encrypted is the default; this node's IPv6 route decides whether IPv6 is on.
    await expect(page.getByTestId('transport-encrypted')).toBeChecked();
    await page.getByTestId('pick-cloudflare').check();
    await page.getByTestId('pick-quad9-unfiltered').check();
    await page.getByTestId('family-v4').check();
    if (await page.getByTestId('family-v6').isEnabled()) await page.getByTestId('family-v6').uncheck();
    // Switching views keeps the unsaved ticks.
    await page.getByTestId('view-advanced').click();
    await expect(page.getByTestId('upstream-picker')).toBeHidden();
    await expect(page.getByTestId('editor-upstream')).toBeVisible();
    await page.getByTestId('view-simple').click();
    await expect(page.getByTestId('pick-cloudflare')).toBeChecked();
    await page.getByTestId('custom-address').fill('9.9.9.9');
    await page.getByTestId('custom-add').click();
    await expect(page.getByTestId('custom-entry')).toContainText('udp://9.9.9.9');
    await page.getByTestId('picker-save').click();
    await expect(page.getByTestId('picker-note')).toContainText('Saved');
    const entries = (await (await r.get('/api/v1/config/entries?kind=upstream')).json()).items;
    const get = (n: string) => entries.find((e: { name: string }) => e.name === n);
    expect(get('pub-cloudflare-tls-1').definition.url).toBe('tls://1.1.1.1');
    expect(get('pub-cloudflare-tls-1').definition.tls_server_name).toBe('cloudflare-dns.com');
    expect(get('pub-quad9-unfiltered-tls-1').source).toBe('added');
    expect(get('pub-custom-1').definition.url).toBe('udp://9.9.9.9');
    expect(get('nowhere').source, 'the file entry is untouched').toBe('file');
    const group = (await (await r.get('/api/v1/config/entries?kind=upstream_group')).json()).items.find((e: { name: string }) => e.name === 'default');
    expect(group.definition.strategy).toBe('fastest');
    expect(group.definition.members).toEqual(expect.arrayContaining(['nowhere', 'pub-cloudflare-tls-1', 'pub-quad9-unfiltered-tls-1', 'pub-custom-1']));
    // Reloading shows the saved choices; Advanced lists the same entries, labelled where they come from.
    await page.reload();
    await expect(page.getByTestId('pick-cloudflare')).toBeChecked();
    await expect(page.getByTestId('pick-google')).not.toBeChecked();
    await expect(page.getByTestId('custom-entry')).toContainText('udp://9.9.9.9');
    await page.getByTestId('view-advanced').click();
    const row = page.getByTestId('editor-upstream').getByTestId('entry-row').filter({ hasText: 'pub-cloudflare-tls-1' });
    await expect(row).toContainText('added here');
    await expect(row).not.toContainText('config file');
    // Unticking removes what the simple view made; the rest stays.
    await page.getByTestId('view-simple').click();
    await page.getByTestId('pick-cloudflare').uncheck();
    await page.getByTestId('picker-save').click();
    await expect(page.getByTestId('picker-note')).toContainText('Saved');
    const after = (await (await r.get('/api/v1/config/entries?kind=upstream')).json()).items.map((e: { name: string }) => e.name);
    expect(after).not.toContain('pub-cloudflare-tls-1');
    expect(after).toEqual(expect.arrayContaining(['pub-quad9-unfiltered-tls-1', 'pub-custom-1', 'nowhere']));
  } finally {
    // Back to the file's configuration.
    await r.delete('/api/v1/upstream-groups/default', { headers: h });
    const all = (await (await r.get('/api/v1/config/entries?kind=upstream')).json()).items;
    for (const e of all) if (e.name.startsWith('pub-')) await r.delete(`/api/v1/upstreams/${e.name}`, { headers: h });
    await page.evaluate(() => localStorage.setItem('upstreams-view', 'advanced'));
  }
});

// REQ: UPS-004 (T24.36) — IPv6 is greyed out, with the reason, on a node with no IPv6 route; plain
// DNS says it isn't private; nothing ticked can't be saved.
test('ups_004 IPv6 is disabled without a route and plain DNS is warned about', async () => {
  const stub = async (route: Route) => {
    const res = await route.fetch();
    await route.fulfill({ response: res, json: { ...(await res.json()), ipv6Route: false } });
  };
  await page.route('**/api/v1/upstream-presets', stub);
  try {
    await page.goto('/#/upstreams');
    await page.evaluate(() => localStorage.removeItem('upstreams-view'));
    await page.reload();
    await expect(page.getByTestId('family-v6')).toBeDisabled();
    await expect(page.getByTestId('family-v6')).not.toBeChecked();
    await expect(page.getByTestId('ipv6-reason')).toContainText('no IPv6 route');
    await expect(page.getByTestId('picker-save')).toBeDisabled();
    await page.getByTestId('transport-plain').check();
    await expect(page.getByTestId('plain-warning')).toContainText('isn’t private');
    await page.getByTestId('pick-mullvad').check();
    await expect(page.getByTestId('plain-warning')).toContainText('no plain address');
    await page.getByTestId('pick-mullvad').uncheck();
    // Nothing ticked and nothing else in the group to keep is refused; the file's upstream is kept
    // here, so this saves nothing new but is allowed.
    await expect(page.getByTestId('picker-save')).toBeEnabled();
  } finally {
    await page.unroute('**/api/v1/upstream-presets', stub);
    await page.evaluate(() => localStorage.setItem('upstreams-view', 'advanced'));
  }
});

// REQ: API-002 (T24.36, fork #27) — each upstream says where it is defined: an upstream made through
// the API (the form, a Pi-hole import) reads "added through the API or UI", the file's reads "config file".
test('ups_004 an upstream made through the API is not labelled config file', async () => {
  const r = page.request;
  const h = { 'x-csrf-token': await csrfOf(r) };
  const put = await r.put('/api/v1/upstreams/ups004-api', { headers: h, data: { url: 'udp://192.0.2.44' } });
  expect(put.status(), await put.text()).toBe(200);
  try {
    await page.goto('/#/upstreams');
    await page.reload();
    const origin = (name: string) =>
      page.locator('table tbody tr', { has: page.locator('strong', { hasText: new RegExp(`^${name}$`) }) }).first().getByTestId('upstream-origin');
    await expect(origin('ups004-api')).toHaveText('defined in: added through the API or UI');
    await expect(origin('nowhere')).toHaveText('defined in: config file');
    await page.getByTestId('view-advanced').click();
    const row = page.getByTestId('editor-upstream').getByTestId('entry-row').filter({ hasText: 'ups004-api' });
    await expect(row).toContainText('added here');
    await expect(row).not.toContainText('config file');
  } finally {
    await r.delete('/api/v1/upstreams/ups004-api', { headers: h });
  }
});

// REQ: OBS-019 — the Upstreams page's Answer quality: second opinions off on the e2e server
// (it says how to turn them on), then a stubbed filtering upstream with its EDE and a
// disagreement.
test('obs_019 upstream answer quality', async () => {
  await page.goto('/#/upstreams');
  const card = page.getByTestId('upstream-quality');
  await expect(card).toContainText('Answer quality');
  await expect(card).toContainText('Second opinions are off');
  await page.route('**/api/v1/analytics/upstream-checks', (route) =>
    route.fulfill({
      json: {
        items: [
          {
            enabled: true, sampleEvery: 1000,
            upstreams: [{
              upstream: 'family-dns', same: 40, differentAddresses: 3, differentRcode: 0, filtered: 2, unanswered: 0,
              dnssecSecure: 10, dnssecInsecure: 30, dnssecBogus: 1, dnssecIndeterminate: 0,
              ede: [{ code: 17, name: 'Filtered', count: 12 }],
            }],
            recent: [{
              at: '2026-10-09T12:00:00.000Z', name: 'casino.example.org', qtype: 'A', result: 'filtered',
              upstream: 'family-dns', answer: 'NXDOMAIN', reference: 'quad9', referenceAnswer: 'NOERROR 192.0.2.7',
            }],
          },
        ],
      },
    }),
  );
  await page.reload();
  await expect(card).toContainText('2 filtered');
  await expect(card).toContainText('1 bogus');
  await expect(card).toContainText('17 Filtered: 12');
  await expect(card).toContainText('casino.example.org');
  await expect(card).toContainText('quad9: NOERROR 192.0.2.7');
  await expect(card).not.toContainText('Second opinions are off');
  await page.unroute('**/api/v1/analytics/upstream-checks');
});

// REQ: OBS-014 — acknowledging a finding hides it (and drops it from the badge) until "Show
// acknowledged"; the acknowledge itself goes to the real server. A fresh server has no
// findings yet (devices learn for a week), so the list is stubbed.
test('obs_014 acknowledge an anomaly', async () => {
  const id = '6a2c0e00a1b2c3d4';
  const acked = new Set<string>();
  const finding = {
    id,
    kind: 'rate_spike',
    client: '192.168.1.20',
    clientName: 'tablet',
    windowStart: '2026-10-08T10:00:00.000Z',
    windowSeconds: 3600,
    observed: 4100,
    baseline: 119,
    spread: 30,
    threshold: 400,
    detail: '4100 queries in an hour; usually 119 ± 30',
    nodes: ['home-pi', 'k8s'],
  };
  await page.route('**/api/v1/analytics/anomalies?*', (route) => {
    const unackedOnly = new URL(route.request().url()).searchParams.get('acknowledged') === 'false';
    const f = acked.has(id) ? { ...finding, acknowledged: { by: 'admin', at: '2026-10-08T12:00:00.000Z' } } : finding;
    return route.fulfill({ json: { items: unackedOnly && acked.has(id) ? [] : [f] } });
  });
  await page.route('**/api/v1/analytics/anomalies/*acknowledge', async (route) => {
    const res = await route.fetch();
    const body = route.request().postDataJSON() as { ids: string[] };
    if (res.ok()) {
      for (const i of body.ids) {
        if (route.request().url().endsWith('/unacknowledge')) acked.delete(i);
        else acked.add(i);
      }
    }
    await route.fulfill({ response: res });
  });
  await page.goto('/#/anomalies');
  await page.reload(); // the sidebar badge loads at start
  const badge = page.locator('a.nav[href="#/anomalies"] .count');
  await expect(badge).toHaveText('1');
  await expect(page.getByTestId('anomaly')).toContainText('Found by home-pi, k8s');
  await page.getByTestId('ack').click();
  await expect(page.getByTestId('anomaly')).toHaveCount(0);
  await expect(page.getByText('every finding in this period is acknowledged')).toBeVisible();
  await expect(badge).toHaveCount(0);
  await page.getByTestId('show-acknowledged').check();
  await expect(page.getByTestId('acknowledged')).toContainText('by admin');
  await page.getByRole('button', { name: 'Undo acknowledge' }).click();
  await expect(page.getByTestId('ack')).toBeVisible();
  await page.unroute('**/api/v1/analytics/anomalies?*');
  await page.unroute('**/api/v1/analytics/anomalies/*acknowledge');
});

// REQ: OBS-038 (ADR-161) — "Mute for this device…" fills in the device and the kind, previews through
// a dry run, and saves to the real server; the finding then counts no more (it hides, and so does
// the badge) and shows, marked, with "Show muted"; the mute is listed and can be removed. A fresh
// server has no findings, so the list is stubbed to follow the real mute.
test('obs_038 mute a kind of finding for a device', async () => {
  const muteName = '192-168-1-30-nxdomain-storm';
  let muted = false;
  const finding = {
    id: '6a2c0e00a1b2c3d5',
    kind: 'nxdomain_storm',
    client: '192.168.1.30',
    clientName: 'lg-tv',
    windowStart: '2026-10-08T10:00:00.000Z',
    windowSeconds: 60,
    observed: 225,
    baseline: 260,
    spread: 0,
    threshold: 30,
    detail: '225 NXDOMAIN answers in a minute, 87% of its 260 queries',
    nodes: [],
  };
  await page.route('**/api/v1/analytics/anomalies?*', (route) => {
    const withMuted = new URL(route.request().url()).searchParams.get('muted') === 'true';
    const f = muted ? { ...finding, mutedBy: muteName } : finding;
    return route.fulfill({ json: { items: muted && !withMuted ? [] : [f] } });
  });
  await page.route('**/api/v1/anomaly-mutes/*', async (route) => {
    const res = await route.fetch();
    const dry = new URL(route.request().url()).searchParams.get('dryRun') === 'true';
    if (res.ok() && !dry) muted = route.request().method() === 'PUT';
    await route.fulfill({ response: res });
  });
  await page.goto('/#/anomalies');
  await page.reload(); // the sidebar badge loads at start
  const badge = page.locator('a.nav[href="#/anomalies"] .count');
  await expect(badge).toHaveText('1');
  await page.getByTestId('mute').click();
  const form = page.getByTestId('mute-form');
  await expect(form.getByLabel('Device')).toHaveValue('192.168.1.30');
  await expect(form.getByTestId('picker-chip').filter({ hasText: 'Burst of failed lookups' })).toHaveCount(1);
  await expect(page.getByTestId('mute-preview')).toContainText('findings created from now on');
  await form.getByLabel('Note').fill('hourly reverse-DNS sweep');
  await page.getByTestId('mute-save').click();
  await expect(page.getByTestId('mute-saved')).toBeVisible();
  // It no longer counts: the finding and the badge are gone, and the page says so.
  await expect(page.getByText('1 muted finding is hidden')).toBeVisible();
  // The confirmation outlives the finding it was about (it sits on the page, not in the card).
  await expect(page.getByTestId('mute-saved')).toBeVisible();
  await expect(badge).toHaveCount(0);
  const row = page.getByTestId('mute-row');
  await expect(row).toContainText('192.168.1.30');
  await expect(row).toContainText('Burst of failed lookups');
  await expect(row).toContainText('hourly reverse-DNS sweep');
  await page.getByTestId('show-muted').check();
  await expect(page.getByTestId('muted')).toContainText(`by ${muteName}`);
  await expect(page.getByTestId('muted')).toContainText('hourly reverse-DNS sweep');
  // Removing it brings the finding back, counted.
  await page.getByTestId('remove-mute').click();
  await expect(page.getByTestId('mute-row')).toHaveCount(0);
  await expect(page.getByTestId('muted')).toHaveCount(0);
  await expect(page.getByTestId('mute')).toBeVisible();
  await page.unroute('**/api/v1/analytics/anomalies?*');
  await page.unroute('**/api/v1/anomaly-mutes/*');
});

// REQ: OPS-011 (ADR-156) — Settings → System → Support package: a preview of what it would hold, a
// download that is a real gzip, and a pseudonym map that can be fetched once.
test('ops_011 support package', async () => {
  await page.goto('/#/settings?tab=system');
  const card = page.getByTestId('support-package');
  await expect(card).toBeVisible();
  await expect(card.getByTestId('level-strict')).toBeChecked();
  // The sample of queries is offered above strict only.
  await expect(card.getByLabel('Query sample')).toHaveCount(0);
  await card.getByTestId('level-standard').check();
  await expect(card.getByLabel('Query sample')).toBeVisible();
  await card.getByTestId('level-strict').check();
  await card.getByTestId('support-preview').click();
  const files = card.getByTestId('support-file');
  await expect(files.filter({ hasText: 'config/effective.json' })).toBeVisible();
  await expect(files.filter({ hasText: 'logs/node.log' })).toBeVisible();
  await expect(files.filter({ hasText: 'node/host.json' })).toBeVisible();
  await expect(card.getByTestId('support-manifest')).toContainText('nothing was saved');
  // Make it: a download that is a gzip, then the map once.
  await card.getByTestId('keep-map').check();
  const [pkg] = await Promise.all([page.waitForEvent('download'), card.getByTestId('support-make').click()]);
  expect(pkg.suggestedFilename()).toMatch(/^wrendns-support-.+\.tar\.gz$/);
  const bytes = readFileSync(await pkg.path());
  expect([bytes[0], bytes[1]]).toEqual([0x1f, 0x8b]);
  await expect(card.getByTestId('support-made')).toContainText('wrendns-support-');
  await expect(files.filter({ hasText: 'MANIFEST' })).toHaveCount(0);
  await expect(files.filter({ hasText: 'config/effective.json' })).toBeVisible();
  const [map] = await Promise.all([page.waitForEvent('download'), card.getByTestId('support-map').click()]);
  expect(map.suggestedFilename()).toBe('wrendns-support-map.txt');
  await expect(card.getByTestId('support-map')).toBeDisabled();
});

// REQ: OPS-011 (ADR-172) — "Every node in the cluster": the request carries `cluster`, the pseudonym map
// is switched off with it (the names never leave their nodes), and a node that is on its own says so
// instead of making a package. (The cluster itself is `deploy/cluster/e2e.sh`.)
test('ops_011 support package for the whole cluster', async () => {
  await page.goto('/#/settings?tab=system');
  const card = page.getByTestId('support-package');
  await card.getByTestId('keep-map').check();
  await card.getByTestId('cluster').check();
  await expect(card.getByTestId('keep-map')).toBeDisabled();
  await expect(card.getByTestId('keep-map')).not.toBeChecked();
  const asked = page.waitForRequest((r) => r.url().includes('/system/support-package') && r.method() === 'POST');
  await card.getByTestId('support-preview').click();
  expect(JSON.parse((await asked).postData() ?? '{}').cluster).toBe(true);
  await expect(card.getByRole('alert')).toContainText("isn't part of a cluster");
  // The refusal is a 400, which the browser logs as a console error the suite would count: expected here.
  problems.splice(0, problems.length, ...problems.filter((m) => !/status of 400/.test(m)));
  await card.getByTestId('cluster').uncheck();
  await expect(card.getByTestId('keep-map')).toBeEnabled();
});

// The header's icon buttons match: the pause button (its own component) is the same round,
// borderless button as the theme toggle, on the same line (owner report 2026-10-06).
test('header icon buttons are the same size and aligned', async () => {
  await page.setViewportSize({ width: 1280, height: 800 });
  await page.goto('/#/');
  const pause = page.getByRole('button', { name: 'Pause blocking' });
  const theme = page.getByRole('button', { name: /^Theme:/ });
  await page.getByRole('heading', { level: 1 }).first().waitFor();
  const [p, t] = [await pause.boundingBox(), await theme.boundingBox()];
  expect(p && t).toBeTruthy();
  expect(Math.round(p!.width)).toBe(Math.round(t!.width));
  expect(Math.round(p!.height)).toBe(Math.round(t!.height));
  expect(Math.abs(p!.y + p!.height / 2 - (t!.y + t!.height / 2))).toBeLessThanOrEqual(1);
  expect(await pause.evaluate((b) => getComputedStyle(b).borderTopWidth)).toBe('0px');
  await page.locator('header').first().screenshot({ path: '.shots/header-buttons.png' });
});

test('lists, groups, clients, upstreams, local DNS render', async () => {
  for (const [path, text] of [
    ['/#/lists', 'e2e-block'],
    ['/#/groups', 'default'],
    ['/#/clients', '127.0.0.1'],
    ['/#/upstreams', 'nowhere'],
    ['/#/local-dns', 'nas.e2e.test'],
    ['/#/anomalies', 'Nothing unusual'],
  ]) {
    await page.goto(path);
    await expect(page.locator('main')).toContainText(text);
  }
});

test('API tokens: created once, usable, revocable', async ({ request }) => {
  await page.goto('/#/settings?tab=tokens');
  await page.getByLabel('Token name').fill('e2e');
  await page.getByRole('button', { name: 'Create token' }).click();
  const token = (await page.locator('code.token').textContent())?.trim() ?? '';
  expect(token).toMatch(/^tt_/);
  const auth = { authorization: `Bearer ${token}` };
  expect((await request.get('/api/v1/system/info', { headers: auth })).status()).toBe(200);
  expect((await request.get('/api/v1/system/info')).status()).toBe(401);
  await page.getByRole('button', { name: 'Revoke' }).click();
  await expect(page.getByText('No tokens yet.')).toBeVisible();
  expect((await request.get('/api/v1/system/info', { headers: auth })).status()).toBe(401);
});

test('admins add users; viewers see less', async () => {
  await page.goto('/#/settings?tab=users');
  await page.getByLabel('Username', { exact: true }).fill(VIEWER.user);
  await page.getByLabel('Password', { exact: true }).fill(VIEWER.pass);
  await page.getByRole('button', { name: 'Add', exact: true }).click();
  await expect(page.locator('main table')).toContainText(VIEWER.user);
  // REQ: API-006 — the change is in the audit log, and the chain verifies.
  await page.getByRole('tab', { name: 'Audit log' }).click();
  await expect(page.locator('table.audit tbody tr').first()).toContainText('user.create');
  await expect(page.locator('table.audit tbody tr').first()).toContainText(VIEWER.user);
  await page.getByRole('button', { name: 'Verify chain' }).click();
  await expect(page.locator('.verify-result')).toContainText('Chain intact');
  await page.getByRole('tab', { name: 'Users' }).click();
  await page.getByRole('button', { name: 'Sign out' }).click();
  await expect(page.getByRole('heading', { name: 'Sign in' })).toBeVisible();
  // The form is ready before its first submit (a click that lands while it mounts does nothing).
  await expect(page.getByRole('button', { name: 'Sign in' })).toBeEnabled();
  await signIn(VIEWER.user, 'wrong password!!');
  await expect(page.getByRole('alert')).toContainText('wrong username or password');
  await signIn(VIEWER.user, VIEWER.pass);
  // Signing in keeps the page; a viewer asking for the users tab gets their account instead.
  await expect(page.getByRole('heading', { name: 'Settings' })).toBeVisible();
  await expect(page.getByRole('tab', { name: 'Account' })).toHaveAttribute('aria-selected', 'true');
  await expect(page.getByRole('tab', { name: 'API tokens' })).toBeVisible();
  await expect(page.getByRole('tab', { name: 'Users' })).toHaveCount(0);
  await expect(page.getByRole('tab', { name: 'Audit log' })).toHaveCount(0);
  expect((await page.request.get('/api/v1/users')).status()).toBe(403);
  await page.getByRole('button', { name: 'Sign out' }).click();
  await page.goto('/');
  await signIn(ADMIN.user, ADMIN.pass);
  await expect(page.getByRole('heading', { name: 'Dashboard' })).toBeVisible();
});

// REQ: API-003 (T24.7, ADR-972) — the sign-in form's "Forgot the password" help opens from the
// sign-in page, and says the reset runs on the machine with the node stopped.
test('api_003 the sign-in page explains the offline password reset', async () => {
  await page.getByRole('button', { name: 'Sign out' }).click();
  await expect(page.getByRole('heading', { name: 'Sign in' })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Sign in' })).toBeEnabled();
  await page.getByRole('button', { name: 'Help: Forgot the password' }).click();
  const panel = page.getByTestId('help-panel');
  await expect(panel).toBeVisible();
  await expect(panel).toContainText('with it stopped');
  await page.keyboard.press('Escape');
  await expect(panel).toHaveCount(0);
  await signIn(ADMIN.user, ADMIN.pass);
  await expect(page.getByRole('heading', { name: 'Dashboard' })).toBeVisible();
});

// REQ: API-003 (issue #64) — a real 6-digit code goes through the browser's own checks: the box on
// Settings -> Account that turns two-factor on, and the one on the sign-in form. Both carried a
// `pattern` that Svelte turned into `[0-9]6`, so no code could be entered and two-factor could not
// be used from the UI at all. The codes are made here from the secret the page shows (RFC 6238).
const BASE32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
function totpAt(secretBase32: string, ms: number): string {
  const bits = [...secretBase32.toUpperCase()].map((c) => BASE32.indexOf(c).toString(2).padStart(5, '0')).join('');
  const key = Buffer.from((bits.match(/.{8}/g) ?? []).map((b) => parseInt(b, 2)));
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(ms / 30_000)));
  const h = createHmac('sha1', key).update(counter).digest();
  const o = h[19] & 0x0f;
  const n = ((h[o] & 0x7f) << 24) | (h[o + 1] << 16) | (h[o + 2] << 8) | h[o + 3];
  return String(n % 1_000_000).padStart(6, '0');
}

test('api_003 two-factor works from the browser: turn it on, sign in with a code, turn it off', async () => {
  // The helper first: RFC 6238's own secret ("12345678901234567890") at 59 s gives 94287082.
  expect(totpAt('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ', 59_000)).toBe('287082');
  await page.goto('/#/settings?tab=account');
  await page.getByRole('button', { name: 'Set up two-factor sign-in' }).click();
  const secret = ((await page.locator('div.mono.key').textContent()) ?? '').replace(/\s/g, '');
  expect(secret).toMatch(/^[A-Z2-7]{32}$/);
  await page.getByPlaceholder('123456').fill(totpAt(secret, Date.now()));
  await page.getByRole('button', { name: 'Turn on' }).click();
  await expect(page.getByText('Save these recovery codes now.')).toBeVisible();
  // Sign in again: the password, then the code. The server takes each time step's code once, so
  // this one is the next step's (it accepts one step of clock skew).
  await page.getByRole('button', { name: 'Sign out' }).click();
  await expect(page.getByRole('heading', { name: 'Sign in' })).toBeVisible();
  await signIn(ADMIN.user, ADMIN.pass);
  await expect(page.getByText('Enter the 6-digit code from your authenticator app.')).toBeVisible();
  await page.locator('input[name="totp"]').fill(totpAt(secret, Date.now() + 30_000));
  await page.getByRole('button', { name: 'Sign in' }).click();
  await expect(page.getByRole('heading', { name: 'Settings' })).toBeVisible();
  await expect(page.getByText('recovery codes left')).toBeVisible();
  // Leave the admin as the other tests expect it: no second factor.
  await page.getByLabel('Password, to turn it off').fill(ADMIN.pass);
  await page.getByRole('button', { name: 'Turn off two-factor' }).click();
  await expect(page.getByRole('button', { name: 'Set up two-factor sign-in' })).toBeVisible();
});

// REQ: OBS-003 (ADR-171) — "everything except": each negated filter keeps exactly the rows its filter
// leaves out (the two add up to the whole window), a flag without its filter is refused, and the
// Queries page writes and reads the flags: the Match menu's "is not", and the "not" chip for statuses.
test('obs_003 the query log can keep what a filter does not match', async () => {
  // One query each: a name asked again would climb the cache page's top list (by hits), which a
  // later test reads.
  expect(await query('neg-a.cache.e2e.test')).toBe(0);
  expect(await query('neg-b.cache.e2e.test')).toBe(0);
  type Row = { name: string; status: string; qtype: string; client: string; rcode?: string | null };
  const rows = async (q: string, to?: string) => {
    const r = await page.request.get(`/api/v1/queries?${q}&from=-1h${to ? `&to=${encodeURIComponent(to)}` : ''}&limit=1000`);
    expect(r.status(), q).toBe(200);
    return (await r.json()) as { items: Row[]; nextCursor?: string | null };
  };
  await expect.poll(async () => (await rows('name=neg-')).items.length, { timeout: 20_000 }).toBe(2);
  // One window for every count below, so a probe query logged meanwhile can't move them. It ends
  // in the past, where the log is whole (it is flushed about once a second), and more than a second
  // after our rows: the API reads `to` in whole seconds, so a row less than a second before it can
  // fall outside.
  await page.waitForTimeout(3000);
  const to = new Date(Date.now() - 1500).toISOString();
  const all = await rows('', to);
  expect(all.nextCursor ?? null, 'the whole window fits in one page').toBeNull();
  const cases: [string, (r: Row) => boolean][] = [
    ['name=neg-a', (r) => r.name.includes('neg-a')],
    ['name=neg-a.cache.e2e.test&match=exact', (r) => r.name === 'neg-a.cache.e2e.test'],
    ['name=cache.e2e.test&match=suffix', (r) => r.name.endsWith('cache.e2e.test')],
    ['name=neg-*.cache.e2e.test&match=glob', (r) => /^neg-.\.cache\.e2e\.test$/.test(r.name)],
    ['name=^neg-[ab][.]cache&match=regex', (r) => /^neg-[ab][.]cache/.test(r.name)],
    ['status=forwarded', (r) => r.status === 'forwarded'],
    ['qtype=A', (r) => r.qtype === 'A'],
    ['client=127.0.0.1', (r) => r.client === '127.0.0.1'],
    ['rcode=NOERROR', (r) => r.rcode === 'NOERROR'],
  ];
  for (const [q, keeps] of cases) {
    const flag = `${q.split('=')[0]}Not`;
    const positive = await rows(q, to);
    const negated = await rows(`${q}&${flag}=true`, to);
    expect(positive.items.every(keeps), q).toBe(true);
    expect(negated.items.some(keeps), `${q} negated`).toBe(false);
    expect(positive.items.length + negated.items.length, `${q}: the match and its negation make the window`).toBe(all.items.length);
  }
  expect((await rows('name=neg-a', to)).items).toHaveLength(1);
  expect((await rows('name=neg-a&nameNot=true', to)).items.filter((r) => r.name.startsWith('neg-'))).toHaveLength(1);
  // A flag without its filter is refused, naming it.
  for (const flag of ['nameNot', 'clientNot', 'statusNot', 'qtypeNot', 'rcodeNot']) {
    const r = await page.request.get(`/api/v1/queries?${flag}=true&from=-1h`);
    expect(r.status(), flag).toBe(400);
    expect(await r.text()).toContain(flag);
  }
  // The page reads the flag from the address and writes it back.
  await page.goto('/#/queries?name=neg-a.cache.e2e.test&match=exact&nameNot=true&from=-1h');
  await expect(page.locator('select[name="match"]')).toHaveValue('!exact');
  await expect(page.locator('table.log tbody tr').first()).toBeVisible();
  await expect(page.locator('table.log tbody')).not.toContainText('neg-a.cache.e2e.test');
  await page.locator('select[name="match"]').selectOption('substring');
  await page.getByRole('button', { name: 'Search', exact: true }).click();
  await expect(page).not.toHaveURL(/nameNot/);
  await expect(page.locator('table.log tbody')).toContainText('neg-a.cache.e2e.test');
  // The "not" chip turns the chosen statuses around.
  await page.goto('/#/queries?status=blocked&from=-1h');
  await expect(page.locator('table.log tbody tr').first()).toBeVisible();
  await page.getByTestId('status-not').click();
  await expect(page).toHaveURL(/statusNot=true/);
  await expect(page.locator('table.log tbody')).not.toContainText('blocked');
  await expect(page.locator('table.log tbody tr').first()).toBeVisible();
});

test('works at phone width (360 px)', async () => {
  await page.setViewportSize({ width: 360, height: 740 });
  await page.goto('/#/queries');
  await expect(page.getByRole('heading', { name: 'Query log' })).toBeVisible();
  const menu = page.getByRole('navigation', { name: 'Main' });
  await page.getByRole('button', { name: 'Menu' }).click();
  await page.getByRole('link', { name: 'Dashboard' }).click();
  await expect(page.getByRole('heading', { name: 'Dashboard' })).toBeVisible();
  await expect(menu).toBeHidden();
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
  expect(overflow).toBeLessThanOrEqual(0);
  // The menu closes on the page you're already on (no route change), on a tap beside it,
  // and on Esc: it covers its own button, so it must never stay stuck open.
  await page.getByRole('button', { name: 'Menu' }).click();
  await expect(menu).toBeVisible();
  await menu.getByRole('link', { name: 'Dashboard' }).click();
  await expect(menu).toBeHidden();
  await page.getByRole('button', { name: 'Menu' }).click();
  await page.getByTestId('menu-scrim').click({ position: { x: 350, y: 400 } });
  await expect(menu).toBeHidden();
  await page.getByRole('button', { name: 'Menu' }).click();
  await page.keyboard.press('Escape');
  await expect(menu).toBeHidden();
});

// REQ: OPS-003 — every e2e query comes from 127.0.0.1 (infrastructure), so 100+ of them
// make client IPs look masked: the banner says so and links to the fix.
test('ops_003 masked client IPs raise a banner', async () => {
  await page.setViewportSize({ width: 1280, height: 800 });
  await Promise.all(Array.from({ length: 120 }, (_, i) => query(`m${i}.nas.e2e.test`).catch(() => -1)));
  // A slow runner can drop some of those UDP queries (CI flake 2026-10-04): keep sending small
  // batches until the detector has seen its 100.
  let batch = 0;
  await expect
    .poll(
      async () => {
        const masked = (await (await page.request.get('/api/v1/system/info')).json()).clientIpsMasked;
        if (!masked) {
          batch += 1;
          await Promise.all(
            Array.from({ length: 20 }, (_, i) => query(`m${batch}-${i}.nas.e2e.test`).catch(() => -1)),
          );
        }
        return masked?.sources ?? [];
      },
      { timeout: 30_000 },
    )
    .toContain('127.0.0.1');
  await expect(async () => {
    await page.reload();
    await expect(page.getByTestId('masked-banner')).toBeVisible({ timeout: 2000 });
  }).toPass({ timeout: 20_000 });
  await expect(page.getByTestId('masked-banner')).toContainText('127.0.0.1');
  await expect(page.getByRole('link', { name: 'How to fix it' })).toHaveAttribute('href', /seeing-real-client-ips/);
});

// REQ: FLT-005 (ADR-050, T3.14 AC) — devices on a group's network are in that group: the
// Groups card shows the network and traffic, the dashboard charts traffic by group, and the
// query log filters by group.
test('flt_005 network groups: cards, chart, and query-log filter', async () => {
  for (let i = 0; i < 5; i++) await query(`g${i}.nas.e2e.test`).catch(() => -1);
  await page.goto('/#/groups');
  const card = page.getByTestId('group-card').filter({ hasText: 'lab' });
  await expect(card).toContainText('127.0.0.0/8');
  await expect(async () => {
    await page.reload();
    await expect(card.locator('dd').first()).not.toHaveText('0', { timeout: 2000 });
  }).toPass({ timeout: 20_000 });
  await page.goto('/#/');
  // Traffic by group is a view of the chart in the Advanced view.
  const groupsView = page.getByTestId('dashboard-chart').getByRole('button', { name: 'Groups', exact: true });
  // The view is remembered per user in this browser, so do not rely on what an earlier test left:
  // choose Simple and wait for the chart before checking the Groups view is not offered. The check
  // that proves it comes below, after Advanced has shown the view with its data.
  await page.getByRole('button', { name: 'Simple', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Simple', exact: true })).toHaveAttribute('aria-pressed', 'true');
  await expect(page.getByTestId('dashboard-chart').getByRole('button', { name: 'Totals', exact: true })).toBeVisible();
  await expect(groupsView, 'Simple view offers no Groups chart view').toHaveCount(0);
  await page.getByRole('button', { name: 'Advanced', exact: true }).click();
  await groupsView.click();
  await expect(page.getByRole('figure', { name: 'Traffic by group' })).toBeVisible();
  await page.getByRole('button', { name: 'Simple', exact: true }).click();
  await expect(groupsView, 'Simple view offers no Groups chart view, with group data loaded').toHaveCount(0);
  await pick(page, 'Group', 'lab');
  await expect(listOf('Top domains')).toContainText('nas.e2e.test');
  await page.goto('/#/queries?group=lab');
  await expect(page.locator('table.log tbody tr').first().locator('.group-chip')).toHaveText('lab');
  const r = await page.request.get('/api/v1/queries?group=lab&limit=5');
  expect(r.status()).toBe(200);
  expect((await r.json()).items.every((x: { group: string }) => x.group === 'lab')).toBe(true);
  expect((await page.request.get('/api/v1/queries?group=nope')).status()).toBe(400);
  // The clients list shows the group each client gets from its network.
  await page.goto('/#/clients');
  const seen = page.locator('section.card', { hasText: 'Seen in the last hour' });
  await expect(seen.locator('tbody tr', { hasText: '127.0.0.1' }).locator('.group-chip')).toHaveText('lab');
});

// REQ: CLU-008 — the Cluster page on a standalone node says so and how to start a cluster.
test('clu_008 cluster page on a standalone node', async () => {
  await page.goto('/#/cluster');
  await expect(page.getByRole('heading', { name: 'Cluster' })).toBeVisible();
  await expect(page.getByTestId('cluster-standalone')).toContainText('wrendns cluster init');
  expect((await (await page.request.get('/api/v1/cluster')).json()).enabled).toBe(false);
});

// REQ: API-010 (T3.10 AC) — name a device from the top-clients widget; the name shows at once in
// the widget, the query log (past rows included), and the live tail.
test('api_010 name a device from the dashboard', async () => {
  await page.setViewportSize({ width: 1280, height: 800 });
  await page.goto('/#/');
  const widget = listOf('Top clients');
  // A slow form load must not wipe what was typed (CI flake on 2026-10-04): delay it.
  const slow = '**/api/v1/clients';
  await page.route(slow, async (r) => {
    await new Promise((done) => setTimeout(done, 800));
    await r.continue();
  });
  await widget.getByRole('button', { name: '127.0.0.1', exact: true }).click();
  await page.getByRole('menuitem', { name: 'Name this device…' }).click();
  await page.getByLabel('Name', { exact: true }).fill('Test laptop');
  await page.unroute(slow);
  await page.getByRole('button', { name: 'Save' }).click();
  await expect(page.getByRole('status')).toContainText('Saved');
  await page.keyboard.press('Escape');
  await expect(widget).toContainText('Test laptop');
  // History is relabelled (names are resolved when read).
  await page.goto('/#/queries');
  await expect(page.locator('table.log tbody tr').first()).toContainText('Test laptop');
  // New queries in the live tail carry the name too.
  await page.getByLabel('Live').check();
  await expect(page.locator('.live-toggle .badge')).toContainText('streaming');
  await query('api010.nas.e2e.test').catch(() => -1); // no upstream: logged as servfail
  const liveRow = page.locator('table.log tbody tr', { hasText: 'api010.nas.e2e.test' });
  await expect(liveRow).toContainText('Test laptop');
  await page.getByLabel('Live').uncheck();
});

// REQ: API-010 (T24.9, ADR-973) — a device its router named ("Kitchen Tablet" in DHCP) is matched
// by that name: a client keeps it beside its address, a group takes it, a quick rule names it, and
// the query log filters by it. No router runs here, so the browser sees the lease through a stub.
test('api_010 match a client by router name', async () => {
  await page.setViewportSize({ width: 1280, height: 800 });
  const leases = {
    items: [{ mac: 'aa:bb:cc:00:00:21', ip: '127.0.0.1', hostname: 'Kitchen Tablet', expiresUnixSeconds: 0, source: 'router', router: 'udm', offline: false }],
  };
  await page.route('**/api/v1/dhcp/leases', (r) => r.fulfill({ json: leases }));
  // A client keeps the router's name beside its address.
  await page.goto('/#/');
  await listOf('Top clients').getByRole('button', { name: 'Test laptop', exact: true }).click();
  await page.getByRole('menuitem', { name: 'Name this device…' }).click();
  await page.getByRole('checkbox', { name: /Also recognize it by its router name/ }).check();
  const clientPut = page.waitForRequest((r) => r.method() === 'PUT' && r.url().includes('/api/v1/clients/') && !r.url().includes('dryRun'));
  await page.getByRole('button', { name: 'Save' }).click();
  expect((await clientPut).postDataJSON()).toMatchObject({ match: ['127.0.0.1', 'hostname:kitchen-tablet'] });
  await expect(page.getByRole('status')).toContainText('Saved');
  await page.keyboard.press('Escape');
  // A group takes the devices its router names (the group editor's Router names).
  await page.goto('/#/groups');
  const groups = page.getByTestId('editor-group');
  await groups.getByRole('button', { name: 'Add group' }).click();
  await page.getByRole('textbox', { name: 'Name', exact: true }).fill('router-kids');
  await page.getByRole('textbox', { name: 'Router names', exact: true }).fill('kitchen-tablet');
  await page.getByRole('button', { name: 'Check' }).click();
  await expect(page.getByTestId('entry-preview')).toBeVisible();
  await page.getByRole('button', { name: 'Apply' }).click();
  const groupRow = groups.getByTestId('entry-row').filter({ hasText: 'router-kids' });
  await expect(groupRow).toBeVisible();
  await groupRow.getByRole('button', { name: 'Edit' }).click();
  await expect(page.getByRole('textbox', { name: 'Router names', exact: true })).toHaveValue('kitchen-tablet');
  await page.keyboard.press('Escape');
  await groupRow.getByRole('button', { name: 'Remove' }).click();
  await expect(groupRow).toHaveCount(0);
  // A quick rule for the router's name, saved as a device by name (the rule's write is stubbed).
  let ruleBody: unknown = null;
  await page.route('**/api/v1/rules/**', async (r) => {
    if (r.request().method() !== 'PUT') return r.continue();
    if (!r.request().url().includes('dryRun')) ruleBody = r.request().postDataJSON();
    await r.fulfill({ json: { impact: 'Saved for the test.' } });
  });
  await page.goto('/#/rules');
  await page.getByLabel('Domain', { exact: true }).fill('games.example');
  await page.getByLabel('Applies to', { exact: true }).selectOption('device');
  await page.getByLabel('Device by', { exact: true }).selectOption('router');
  await page.getByLabel('Router name', { exact: true }).fill('kitchen-tablet');
  await page.getByRole('button', { name: 'Save rule' }).click();
  await expect(page.getByTestId('quick-rule-saved')).toContainText('Saved for the test');
  expect(ruleBody).toMatchObject({ devices: ['hostname:kitchen-tablet'] });
  await page.unroute('**/api/v1/rules/**');
  // The query log filters by the name: the addresses it has now.
  await page.goto('/#/queries');
  const clientBox = page.getByRole('group', { name: 'Client', exact: true }).getByRole('combobox');
  await clientBox.fill('hostname:kitchen-tablet');
  await clientBox.press('Enter');
  await clientBox.press('Escape');
  const logged = page.waitForRequest((r) => r.url().includes('/api/v1/queries') && decodeURIComponent(r.url()).includes('client=hostname:kitchen-tablet'));
  await page.getByRole('button', { name: 'Search', exact: true }).click();
  await logged;
  // The server takes the same filter: no address holds the name on this node, so no rows.
  const byName = await page.request.get('/api/v1/queries?client=hostname:kitchen-tablet');
  expect(byName.status()).toBe(200);
  expect((await byName.json()).items).toEqual([]);
  // Put the client back as it was: the device API test that follows expects its address alone.
  await page.goto('/#/');
  await listOf('Top clients').getByRole('button', { name: 'Test laptop', exact: true }).click();
  await page.getByRole('menuitem', { name: 'Name this device…' }).click();
  await page.getByRole('checkbox', { name: /Also recognize it by its router name/ }).uncheck();
  const reverted = page.waitForRequest((r) => r.method() === 'PUT' && r.url().includes('/api/v1/clients/') && !r.url().includes('dryRun'));
  await page.getByRole('button', { name: 'Save' }).click();
  expect((await reverted).postDataJSON()).toMatchObject({ match: ['127.0.0.1'] });
  await expect(page.getByRole('status')).toContainText('Saved');
  await page.keyboard.press('Escape');
  await page.unroute('**/api/v1/dhcp/leases');
});

// REQ: API-002, AGT-002, AGT-003 — the same change through the API: dry run, If-Match,
// Idempotency-Key, validation, delete, audit.
test('api_010 device API: dry run, versions, idempotency', async () => {
  const r = page.request;
  const csrf = (await (await r.get('/api/v1/auth/status')).json()).csrfToken as string;
  const h = (extra: Record<string, string> = {}) => ({ 'x-csrf-token': csrf, ...extra });
  const list = await r.get('/api/v1/clients');
  const version = Number((list.headers()['etag'] ?? '"0"').replaceAll('"', ''));
  const laptop = (await list.json()).items.find((c: { name: string }) => c.name === 'Test laptop');
  expect(laptop).toMatchObject({ source: 'api', match: ['127.0.0.1'] });

  const rename = { name: 'Renamed laptop', match: ['127.0.0.1'], groups: ['default'] };
  const url = '/api/v1/clients/Test%20laptop';
  // Dry run: reported, not applied.
  const dry = await r.put(`${url}?dryRun=true`, { headers: h(), data: rename });
  expect(dry.status()).toBe(200);
  expect(await dry.json()).toMatchObject({ applied: false, configVersion: version, after: { name: 'Renamed laptop' } });
  // A stale version is refused.
  const stale = await r.put(url, { headers: h({ 'if-match': `"${version + 99}"` }), data: rename });
  expect(stale.status()).toBe(412);
  expect((await stale.json()).code).toBe('version_conflict');
  // An unknown group is refused with the reason.
  const bad = await r.put(url, { headers: h(), data: { ...rename, groups: ['nope'] } });
  expect(bad.status()).toBe(422);
  expect((await bad.json()).detail).toContain('nope');
  // Applied once; the retry replays the first answer; the key can't be reused for another change.
  const key = `e2e-${Date.now()}`;
  const first = await r.put(url, { headers: h({ 'if-match': `"${version}"`, 'idempotency-key': key }), data: rename });
  expect(first.status()).toBe(200);
  const applied = await first.json();
  expect(applied).toMatchObject({ applied: true, configVersion: version + 1 });
  const again = await r.put(url, { headers: h({ 'if-match': `"${version}"`, 'idempotency-key': key }), data: rename });
  expect(again.headers()['idempotency-replayed']).toBe('true');
  expect(await again.json()).toEqual(applied);
  const reused = await r.put(url, { headers: h({ 'idempotency-key': key }), data: { ...rename, name: 'Other' } });
  expect(reused.status()).toBe(409);
  // Past query-log rows now show the new name.
  const rows = (await (await r.get('/api/v1/queries?client=127.0.0.1&limit=5')).json()).items;
  expect(rows.length).toBeGreaterThan(0);
  for (const row of rows) expect(row.clientName).toBe('Renamed laptop');
  // Audited with the author.
  const audit = (await (await r.get('/api/v1/audit?action=client.put')).json()).items;
  expect(audit[0]).toMatchObject({ action: 'client.put', target: 'Test laptop', actor: 'admin' });
  // Forget it: the address comes back.
  expect((await r.delete('/api/v1/clients/Renamed%20laptop', { headers: h() })).status()).toBe(200);
  const after = (await (await r.get('/api/v1/queries?client=127.0.0.1&limit=1')).json()).items[0];
  expect(after.clientName).toBeUndefined();
});

// REQ: API-011 (T3.11 AC) — a novice opens a "?" panel and sees its diagram; Explain draws the
// decision; Simple hides detail that Advanced shows.
test('api_011 help panels, diagrams, and simple/advanced', async () => {
  await page.setViewportSize({ width: 1280, height: 800 });
  await page.goto('/#/lists');
  await page.getByRole('button', { name: 'Help: Block or allow whole categories of sites' }).click();
  const panel = page.getByTestId('help-panel');
  await expect(panel).toBeVisible();
  await expect(panel).toContainText('When you');
  await expect(panel.getByRole('img')).toHaveAttribute('aria-label', /blocks it/);
  await page.keyboard.press('Escape');
  await expect(panel).toHaveCount(0);

  await page.goto('/#/explain?name=ads.e2e.test&client=127.0.0.1');
  await expect(page.getByTestId('explain-flow').getByRole('img')).toHaveAttribute('aria-label', /blocks it.*\(list e2e-block\)/);

  // Simple (the default) hides each list's source; Advanced shows it, and is remembered.
  await page.goto('/#/lists');
  await page.getByRole('button', { name: 'Simple', exact: true }).click();
  await expect(page.locator('main')).not.toContainText('Lines');
  await page.getByRole('button', { name: 'Advanced', exact: true }).click();
  await expect(page.locator('main')).toContainText('Lines');
  await page.reload();
  await expect(page.getByRole('button', { name: 'Advanced', exact: true })).toHaveAttribute('aria-pressed', 'true');
  await page.getByRole('button', { name: 'Simple', exact: true }).click();
});

// REQ: API-011 (T3.12 AC) — a novice creates nas.home.arpa and sends corp.example elsewhere through
// the wizards, without docs; DNS answers at once; the API does the same with dry-run.
test('api_011 names on your network: wizards, DNS, and the API', async () => {
  await page.setViewportSize({ width: 1280, height: 800 });
  await page.goto('/#/local-dns');
  await expect(page.getByRole('heading', { name: 'Names on your network' })).toBeVisible();

  await page.getByRole('button', { name: 'Set up your home domain', exact: true }).click();
  await expect(page.getByRole('textbox', { name: 'Home domain', exact: true })).toHaveValue('home.arpa');
  await page.getByRole('button', { name: 'Next' }).click();
  await page.getByRole('textbox', { name: 'Device name', exact: true }).fill('nas');
  await page.getByRole('textbox', { name: 'Address', exact: true }).fill('192.168.1.10');
  await expect(page.getByTestId('change-preview')).toContainText('nas.home.arpa gets the address 192.168.1.10');
  await page.getByRole('button', { name: 'Save' }).click();
  await expect(page.getByRole('status')).toContainText('nas.home.arpa now answers');
  await page.keyboard.press('Escape');
  await expect(page.locator('main')).toContainText('nas.home.arpa');
  expect(await query('nas.home.arpa')).toBe(0); // NOERROR, answered locally

  await page.getByRole('button', { name: 'Send a domain to another server', exact: true }).click();
  await page.getByRole('textbox', { name: 'Domain', exact: true }).fill('corp.example');
  await page.getByRole('textbox', { name: 'Server address', exact: true }).fill('10.0.0.53');
  await expect(page.getByTestId('change-preview')).toContainText('asked of 10.0.0.53');
  await page.getByRole('button', { name: 'Save' }).click();
  await expect(page.getByRole('status')).toContainText('corp.example');
  await page.keyboard.press('Escape');
  await expect(page.locator('main')).toContainText('udp://10.0.0.53');

  // Explain confirms both paths.
  await page.goto('/#/explain?name=nas.home.arpa&client=127.0.0.1');
  await expect(page.getByTestId('explain-flow').getByRole('img')).toHaveAttribute('aria-label', /your own names/);
  await page.goto('/#/explain?name=intranet.corp.example&client=127.0.0.1');
  await expect(page.getByTestId('explain-flow').getByRole('img')).toHaveAttribute('aria-label', /server you chose/);

  // The API: dry run, validation, and the same change.
  const r = page.request;
  const csrf = (await (await r.get('/api/v1/auth/status')).json()).csrfToken as string;
  const h = { 'x-csrf-token': csrf };
  const dry = await r.put('/api/v1/records/printer.home.arpa?dryRun=true', { headers: h, data: { records: [{ type: 'A', value: '192.168.1.20' }] } });
  expect(await dry.json()).toMatchObject({ applied: false, after: { name: 'printer.home.arpa' } });
  expect((await (await r.get('/api/v1/records')).json()).items.map((n: { name: string }) => n.name)).not.toContain('printer.home.arpa');
  const bad = await r.put('/api/v1/records/printer.home.arpa', { headers: h, data: { records: [{ type: 'A', value: 'printer' }] } });
  expect(bad.status()).toBe(422);
  const file = await r.put('/api/v1/records/nas.e2e.test', { headers: h, data: { records: [{ type: 'A', value: '10.1.1.1' }] } });
  expect(file.status()).toBe(409);
  const fwDry = await r.put('/api/v1/forwards/lab.example?dryRun=true', { headers: h, data: { servers: ['tls://10.0.0.9'] } });
  expect(await fwDry.json()).toMatchObject({ applied: false, after: { domain: 'lab.example', servers: ['tls://10.0.0.9'] } });
  expect((await r.delete('/api/v1/forwards/corp.example', { headers: h })).status()).toBe(200);
  expect((await r.delete('/api/v1/records/nas.home.arpa', { headers: h })).status()).toBe(200);
  expect(await query('nas.home.arpa').catch(() => -1)).not.toBe(0);
});

// REQ: FLT-005 (T6.12, ADR-067) — a quick rule from "Why?": allow a blocked name for this
// device for an hour; DNS stops blocking it at once, the Rules page shows it with its
// countdown, and removing it blocks the name again. No list is recompiled.
test('flt_005 quick rule: allow for 1 hour from the query log', async () => {
  // The poll below allows 60 s for the allowed query to be logged; the default 30 s test timeout
  // would end the test first on a starved runner.
  test.setTimeout(90_000);
  expect(await query('ads.e2e.test')).toBe(0); // blocked: 0.0.0.0
  await page.goto('/#/queries?status=blocked&name=ads.e2e.test&match=exact');
  await page.getByRole('button', { name: 'Why?' }).first().click();
  const form = page.getByTestId('quick-rule-form');
  await expect(form.getByRole('textbox', { name: 'Domain' })).toHaveValue('ads.e2e.test');
  await expect(form.getByRole('combobox', { name: 'Duration' })).toHaveValue('60');
  await form.getByRole('textbox', { name: 'Note' }).fill('e2e game');
  await form.getByRole('button', { name: 'Save rule' }).click();
  await expect(page.getByTestId('quick-rule-saved')).toContainText('allowed for');
  await page.keyboard.press('Escape');

  // Not blocked any more: it goes upstream (unreachable in this test, so not a 0.0.0.0 answer).
  expect(await query('ads.e2e.test').catch(() => -1)).not.toBe(0);

  await page.goto('/#/rules');
  const table = page.getByTestId('rules-table');
  await expect(table).toContainText('ads.e2e.test');
  await expect(table).toContainText('e2e game');
  await expect(table).toContainText(/in (59m|1h)/);

  // The query log attributes the decision to the rule.
  // (The allowed query is logged once its upstream attempt ends, a few seconds later here, and
  // longer on a starved runner: 20 s wasn't enough with every core busy.)
  await page.goto('/#/queries?name=ads.e2e.test&match=exact');
  await expect
    .poll(
      async () => {
        await page.reload();
        // The rows arrive a moment after the page's load event; read them once they are there.
        await page.locator('table.log tbody tr').first().waitFor({ timeout: 5_000 }).catch(() => {});
        return page.locator('table.log tbody').innerText();
      },
      { timeout: 60_000, intervals: [1000] },
    )
    .toContain('quick allow');

  // Removing it: the lists decide again.
  await page.goto('/#/rules');
  await page.getByTestId('rules-table').getByRole('button', { name: 'Remove' }).click();
  await expect(page.locator('main')).toContainText('No quick rules');
  expect(await query('ads.e2e.test')).toBe(0);
});

// REQ: FLT-005 (T20.1, ADR-162, GitHub issue #57) — Edit a quick rule in place: the form starts
// from the rule, the end time stays unless a new duration is picked, the rule keeps its ID and
// its start, DNS follows at once (the old domain is no longer allowed, and there is no second
// rule), and the confirmation stays on the page after the row is redrawn.
test('flt_005 edit a quick rule in place', async () => {
  const r = page.request;
  const csrf = (await (await r.get('/api/v1/auth/status')).json()).csrfToken as string;
  const h = { 'x-csrf-token': csrf };
  const put = await r.put('/api/v1/rules/e2e-edit', {
    headers: h,
    data: { action: 'allow', domain: 'ads.e2e.test', forMinutes: 120, note: 'first' },
  });
  expect(put.status()).toBe(200);
  expect(await query('ads.e2e.test').catch(() => -1)).not.toBe(0); // allowed by the rule
  const before = (await (await r.get('/api/v1/rules')).json()).items[0];
  expect(before.id).toBe('e2e-edit');
  await page.waitForTimeout(1100); // a refreshed start would differ by a second

  await page.goto('/#/rules');
  await page.getByTestId('rules-table').getByRole('button', { name: 'Edit' }).click();
  const form = page.getByTestId('quick-rule-edit-form');
  await expect(form.getByRole('textbox', { name: 'Domain' })).toHaveValue('ads.e2e.test');
  await expect(form.getByRole('textbox', { name: 'Note' })).toHaveValue('first');
  await expect(form.getByRole('combobox', { name: 'Duration' })).toHaveValue('keep');
  await form.getByRole('textbox', { name: 'Domain' }).fill('other.e2e.test');
  await form.getByRole('textbox', { name: 'Note' }).fill('second');
  await form.getByRole('button', { name: 'Save changes' }).click();
  await expect(page.getByTestId('rule-edited')).toContainText('Rule updated.');
  await expect(page.getByTestId('rule-edited')).toContainText('other.e2e.test'); // the new domain, not the old
  await expect(page.getByTestId('rule-edit-row')).toHaveCount(0);

  const after = (await (await r.get('/api/v1/rules')).json()).items;
  expect(after).toHaveLength(1);
  expect(after[0]).toMatchObject({ id: 'e2e-edit', domain: 'other.e2e.test', note: 'second' });
  expect(after[0].created).toBe(before.created);
  expect(after[0].createdBy).toBe(before.createdBy);
  expect(after[0].expires).toBe(before.expires);
  expect(await query('ads.e2e.test')).toBe(0); // the list blocks it again: the old rule is gone

  // Cancel leaves the rule alone.
  await page.getByTestId('rules-table').getByRole('button', { name: 'Edit' }).click();
  await page.getByTestId('quick-rule-edit-form').getByRole('button', { name: 'Cancel' }).click();
  await expect(page.getByTestId('rule-edit-row')).toHaveCount(0);
  await page.getByTestId('rules-table').getByRole('button', { name: 'Remove' }).click();
  await expect(page.locator('main')).toContainText('No quick rules');
});

// REQ: FLT-005 (ADR-067) — an expiring rule stops applying at its expiry without a restart,
// the sweep removes it within seconds, and the audit log records `rule.expire`.
test('flt_005 quick rules expire on their own and are audited', async () => {
  const r = page.request;
  const csrf = (await (await r.get('/api/v1/auth/status')).json()).csrfToken as string;
  const h = { 'x-csrf-token': csrf };
  const expires = new Date(Date.now() + 4000).toISOString().replace(/\.\d+Z$/, 'Z');
  const put = await r.put('/api/v1/rules/e2e-expiring', {
    headers: h,
    data: { action: 'allow', domain: 'ads.e2e.test', devices: ['127.0.0.1'], expires },
  });
  expect(put.status()).toBe(200);
  expect(await query('ads.e2e.test').catch(() => -1)).not.toBe(0); // allowed while it lasts
  await expect
    .poll(async () => (await (await r.get('/api/v1/rules')).json()).items.length, { timeout: 20_000, intervals: [1000] })
    .toBe(0);
  expect(await query('ads.e2e.test')).toBe(0); // the list blocks it again
  const audit = await (await r.get('/api/v1/audit?limit=20')).json();
  expect(JSON.stringify(audit)).toContain('rule.expire');
  // Mistakes are refused with a reason.
  const past = await r.put('/api/v1/rules/e2e-past', {
    headers: h,
    data: { action: 'block', domain: 'x.e2e.test', expires: '2020-01-01T00:00:00Z' },
  });
  expect(past.status()).toBe(422);
  const unknownGroup = await r.put('/api/v1/rules/e2e-bad', {
    headers: h,
    data: { action: 'block', domain: 'x.e2e.test', groups: ['nope'] },
  });
  expect(unknownGroup.status()).toBe(422);
});

// REQ: CLU-008, CLU-009 (T6.14) — the topology matches GET /cluster: a controller with 3 pods on
// two Kubernetes nodes and a Pi; 8 pods on one node fold into "+3"; a pod down is red; selecting
// a pod opens its site and highlights its row (pod name, Kubernetes node, share, cache).
test('clu_008 cluster topology', async () => {
  const node = (o: Record<string, unknown>) => ({
    ephemeral: false, witness: false, protocol: 4, role: 'replica', thisNode: false, eligible: true, version: '0.1.0',
    up: true, connected: true, link: 'inbound', lastSeenSecondsAgo: 1, rttMs: 3, configSeq: 9, configLag: 0, ready: true,
    qps: 10, servfailPercent: 0, upstreamP90Ms: 12, uptimeSeconds: 3600, restarts: 0, cacheEntries: 500,
    cacheHitPercent: 80, querySharePercent: 10, ...o,
  });
  const pod = (name: string, kube: string, o: Record<string, unknown> = {}) =>
    node({ nodeId: `id-${name}`, site: 'k8s', ephemeral: true, pod: `wrendns-resolver-${name}`, kubeNode: kube, ...o });
  const view = (pods: ReturnType<typeof node>[]) => ({
    enabled: true, clusterId: 'c1', name: 'home', thisNode: 'id-ctl', newestConfigSeq: 9, healthy: true, checks: [],
    events: [], conflicts: [], authority: 'primary',
    nodes: [
      node({ nodeId: 'id-ctl', site: 'k8s', role: 'primary', thisNode: true, link: 'self', rttMs: null, pod: 'wrendns-756965cdc7-8j9h9', kubeNode: 'k3s-node-with-a-long-name-1', qps: 40, querySharePercent: 40 }),
      node({ nodeId: 'id-pi', site: 'home-raspberry-pi-in-the-hall-closet', rttMs: 4, qps: 30, querySharePercent: 30, restarts: 2 }),
      ...pods,
    ],
  });
  let current = view([
    pod('aaaaa', 'k3s-1', { qps: 20, querySharePercent: 20 }),
    pod('bbbbb', 'k3s-2', { qps: 10, querySharePercent: 10, cacheHitPercent: 55 }),
    pod('ccccc', 'k3s-2', { up: false, qps: 0, querySharePercent: null }),
  ]);
  await page.route('**/api/v1/cluster', (route) => route.fulfill({ json: current }));
  // REQ: CLU-013 — this server runs alone: the rollout reads are part of the example too.
  await page.route('**/api/v1/cluster/rollout', (route) => route.fulfill({ json: { fromPrimary: true, canaries: [], bakeSecs: 300, stable: '1.9', stage: 'none', nodes: [] } }));
  await page.route('**/api/v1/cluster/versions', (route) => route.fulfill({ json: { items: [], history: 20 } }));
  await page.goto('/#/cluster');
  const topo = page.getByTestId('cluster-topology');
  await expect(topo.getByTestId('topology-site')).toHaveCount(2);
  await expect(topo.getByTestId('topology-node')).toHaveCount(2); // controller and Pi
  await expect(topo.getByTestId('topology-pod')).toHaveCount(3);
  await expect(topo).toContainText('node k3s-1 · 1 replica pod');
  await expect(topo).toContainText('node k3s-2 · 2 replica pods');
  await expect(topo).toContainText('4 ms'); // the Pi's round trip, measured by this node
  // Long pod and site names are shortened in the middle to fit (the full name is in the tooltip).
  await expect(topo.getByTestId('topology-node').first()).toContainText(/wrend.*….*-8j9h9/);
  // The primary is marked as such; the Pi is a replica.
  await expect(topo.getByTestId('topology-node').first().getByTestId('topology-role')).toHaveText('Primary');
  await expect(topo.getByTestId('topology-node').nth(1).getByTestId('topology-role')).toHaveText('replica');
  await expect(topo.getByTestId('topology-site').nth(1).locator('text').first()).toHaveText(/^home-.*….*closet$/);
  await expect(topo.locator('.pod.bad')).toHaveCount(1);
  await expect(topo.locator('path.link.bad')).toHaveCount(1); // the k3s-2 group has a pod down
  // REQ: UI-*, T33.6 — a node chip's and a pod's focus ring: 2px of focus-ring, 2px outside; never on hover.
  for (const chip of [topo.getByTestId('topology-node').first(), topo.getByTestId('topology-pod').first()]) {
    const ring = await rectRing(page, chip);
    expect(ring.focusVisible).toBe(true);
    expect([ring.stroke, ring.width, ring.gap]).toEqual([ring.want, '2px', [3, 3, 6, 6]]);
    expect(await hoverRing(page, chip)).toBe('none');
  }

  // Selecting a pod opens its site in the table and highlights its row.
  await topo.getByRole('button', { name: /wrendns-resolver-bbbbb/ }).click();
  const row = page.locator('#node-id-bbbbb');
  await expect(row).toHaveClass(/selected/);
  await expect(row).toContainText('wrendns-resolver-bbbbb on k3s-2');
  await expect(row).toContainText('10.0% of queries');
  await expect(row).toContainText('cache: 55.0% hits');
  await expect(page.locator('#node-id-pi')).toContainText('2 restarts');

  // Updates with the page (every 5 s): 8 pods on one node fold into 5 + "+3".
  current = view(Array.from({ length: 8 }, (_, i) => pod(`p${i}xxx`, 'k3s-1')));
  await expect(topo.getByTestId('topology-pod')).toHaveCount(6, { timeout: 10_000 });
  await expect(topo).toContainText('+3');
  await expect(topo).toContainText('node k3s-1 · 8 replica pods');
  await page.unroute('**/api/v1/cluster');
  await page.unroute('**/api/v1/cluster/rollout');
  await page.unroute('**/api/v1/cluster/versions');
});

// REQ: CLU-009 (T24.33, ADR-1011) — a witness only votes. Its row says "witness, votes only" and
// shows "not applicable" for configuration, secrets and DNS (whatever an older witness reports),
// its vote state and real uptime; the topology draws it green; the Health tab counts only real
// failures, and a witness that is down is red there and in the checks.
test('clu_009 a witness is a voter, not a full node', async () => {
  const node = (o: Record<string, unknown>) => ({
    ephemeral: false, witness: false, protocol: 4, role: 'replica', thisNode: false, eligible: true, version: '0.9.0',
    up: true, connected: true, link: 'inbound', lastSeenSecondsAgo: 1, rttMs: 3, configSeq: 14, configLag: 0, ready: true,
    qps: 10, servfailPercent: 0, upstreamP90Ms: 12, uptimeSeconds: 3600, restarts: 0, ...o,
  });
  const view = (witnessUp: boolean) => ({
    enabled: true, clusterId: 'c1', name: 'home', thisNode: 'id-pi1', newestConfigSeq: 14, events: [], conflicts: [],
    authority: 'primary',
    healthy: witnessUp,
    checks: [
      { id: 'peers_up', ok: witnessUp, summary: witnessUp ? 'All 3 nodes are up' : 'Not heard from in 15 s: id-pi3', fix: witnessUp ? null : 'Check the node.' },
      { id: 'in_sync', ok: true, summary: 'Every reachable node runs configuration version 14' },
    ],
    failover: { mode: 'auto', active: true, voters: 3, reachableVoters: witnessUp ? 3 : 2, leaseHeld: true, leaseSecondsLeft: 12, votedEpoch: 7, votedFor: 'id-pi1' },
    nodes: [
      node({ nodeId: 'id-pi1', site: 'node-a', role: 'primary', thisNode: true, link: 'self', rttMs: null }),
      node({ nodeId: 'id-pi2', site: 'node-b' }),
      // The witness as an older build would report it: no configuration, "not ready", behind, no secrets.
      node({
        nodeId: 'id-pi3', site: 'node-c', witness: true, eligible: false, up: witnessUp, connected: witnessUp, ready: false,
        configSeq: 0, configLag: 13, behindSeconds: 1920, qps: 0, uptimeSeconds: 7200, secrets: null,
        vote: { lastReplySecondsAgo: 4, lastGrantSecondsAgo: 4, votedEpoch: 7 },
      }),
    ],
  });
  let current = view(true);
  await page.route('**/api/v1/cluster', (route) => route.fulfill({ json: current }));
  await page.route('**/api/v1/cluster/rollout', (route) => route.fulfill({ json: { fromPrimary: true, canaries: [], bakeSecs: 300, stable: '1.9', stage: 'none', nodes: [] } }));
  await page.route('**/api/v1/cluster/versions', (route) => route.fulfill({ json: { items: [], history: 20 } }));
  // A fresh document, so the route's data is fetched even if the page is already on #/cluster.
  await page.goto('about:blank');
  await page.goto('/#/cluster');
  const row = page.locator('#node-id-pi3');
  await expect(row).toContainText('witness, votes only');
  await expect(row.getByTestId('cluster-node-config-na')).toHaveText('not applicable');
  await expect(row.getByTestId('cluster-node-secrets-na')).toHaveText('not applicable');
  await expect(row.getByTestId('cluster-node-dns-na')).toHaveText('not applicable');
  await expect(row.getByTestId('cluster-node-vote')).toContainText(/last vote .* ago.*epoch 7/);
  await expect(row).not.toContainText('not ready');
  await expect(row).not.toContainText('behind');
  await expect(row).not.toContainText('not reported');
  await expect(row).toContainText('2h'); // its real uptime, not 0s
  await expect(row).toContainText('0.9.0');
  // A full node still shows all three.
  await expect(page.locator('#node-id-pi2')).toContainText('in sync');
  await expect(page.locator('#node-id-pi2').getByTestId('cluster-node-dns-na')).toHaveCount(0);
  // The topology: green while it is up, not amber.
  const topo = page.getByTestId('cluster-topology');
  await expect(topo.getByTestId('topology-node')).toHaveCount(3);
  await expect(topo.locator('.chip.warn')).toHaveCount(0);
  await expect(topo).toContainText('votes only');
  await expect(topo.locator('.chip.bad')).toHaveCount(0);
  // The help topic explains it.
  await row.getByTestId('cluster-node-vote').getByRole('button').click();
  await expect(page.getByTestId('help-panel')).toContainText('vote-only member');
  await page.keyboard.press('Escape');
  // The tabs count nothing for it: Health is clean.
  await page.getByRole('tab', { name: /^Health/ }).click();
  await expect(page.locator('[data-testid="cluster-check"].fail')).toHaveCount(0);
  // Down: still a failing check (automatic failover needs its vote), and red in the topology.
  current = view(false);
  await expect(page.getByTestId('cluster-health')).toContainText('Needs attention', { timeout: 10_000 });
  await expect(page.getByTestId('cluster-check').filter({ hasText: 'Not heard from' })).toHaveCount(1);
  await page.getByRole('tab', { name: /^Nodes/ }).click();
  await expect(page.getByTestId('cluster-topology').locator('.chip.bad')).toHaveCount(1);
  await page.unroute('**/api/v1/cluster');
  await page.unroute('**/api/v1/cluster/rollout');
  await page.unroute('**/api/v1/cluster/versions');
});

// REQ: DNS-006, API-005 (T6.13) — the cache: a cached answer shows up in a lookup (the UI
// card and the API), a flush removes it and says how many, and viewers can look but not flush.
test('dns_006 cache lookup and flush', async () => {
  await query('www.cache.e2e.test'); // routed to the stub upstream (server.mjs)
  const r = page.request;
  await expect
    .poll(async () => (await (await r.get('/api/v1/cache/lookup?name=www.cache.e2e.test')).json()).entries.length, {
      timeout: 10_000,
    })
    .toBeGreaterThan(0);
  await page.goto('/#/cache'); // T6.15: its own page (Settings links to it)
  const card = page.getByTestId('cache-card');
  await card.getByRole('textbox', { name: 'Name to look up' }).fill('www.cache.e2e.test');
  await card.getByRole('button', { name: 'Look up' }).click();
  await expect(card.getByTestId('cache-entries')).toContainText('NOERROR');
  await card.getByRole('button', { name: 'Flush this name' }).click();
  await expect(card.getByTestId('cache-flushed')).toContainText(/Removed [1-9]/);
  await expect(card).toContainText('Nothing cached for');
  const stats = await (await r.get('/api/v1/cache/stats')).json();
  expect(stats.items.length).toBe(1);
  // A viewer may look but not flush.
  const viewer = await page.context().browser()!.newContext({ baseURL: page.url().split('/#')[0] });
  const vr = viewer.request;
  const st = await (await vr.get('/api/v1/auth/status')).json();
  const login = await vr.post('/api/v1/auth/login', {
    headers: { 'x-csrf-token': st.csrfToken ?? '' },
    data: { username: VIEWER.user, password: VIEWER.pass },
  });
  expect(login.ok()).toBeTruthy();
  const csrf = (await (await vr.get('/api/v1/auth/status')).json()).csrfToken as string;
  expect((await vr.get('/api/v1/cache/stats')).status()).toBe(200);
  expect((await vr.post('/api/v1/cache/flush', { headers: { 'x-csrf-token': csrf }, data: {} })).status()).toBe(403);
  await viewer.close();
});

// REQ: DNS-905 (T40.4) — the Cache page's other flush choices: one type for a name leaves its
// other types; the broad ones (a type everywhere, negative answers, failed lookups, the
// recursor's zone cuts and round-trip times) ask first and send what they say; operators only.
test('dns_905 cache flush by type, kind and recursor', async () => {
  await query('typed.cache.e2e.test'); // routed to the stub upstream: an A answer is cached
  const r = page.request;
  await expect
    .poll(async () => (await (await r.get('/api/v1/cache/lookup?name=typed.cache.e2e.test')).json()).entries.length, {
      timeout: 10_000,
    })
    .toBeGreaterThan(0);
  const bodies: Record<string, unknown>[] = [];
  await page.route('**/api/v1/cache/flush', (route) => {
    bodies.push(route.request().postDataJSON() as Record<string, unknown>);
    return route.continue();
  });
  await page.goto('/#/cache');
  await page.reload();
  const card = page.getByTestId('cache-card');
  await card.getByRole('textbox', { name: 'Name to look up' }).fill('typed.cache.e2e.test');
  await card.getByRole('button', { name: 'Look up' }).click();
  await expect(card.getByTestId('cache-entries')).toContainText('NOERROR');
  // A name and a type: narrow, so no confirmation, and the A answer stays.
  await card.getByTestId('cache-flush-type').fill('txt');
  await card.getByRole('button', { name: 'Flush TXT for this name' }).click();
  await expect(card.getByTestId('cache-flushed')).toContainText('Removed 0 entries');
  await expect.poll(() => bodies[0]).toMatchObject({ name: 'typed.cache.e2e.test', type: 'TXT' });
  await expect(card.getByTestId('cache-entries')).toContainText('NOERROR');
  // The broad ones ask first: nothing is sent until the confirmation, and Cancel sends nothing.
  await card.getByRole('button', { name: 'Flush negative answers…' }).click();
  await expect(card.getByTestId('cache-flush-confirm')).toContainText('Flush negative answers on every node?');
  await card.getByTestId('cache-flush-confirm').getByRole('button', { name: 'Cancel' }).click();
  await expect(card.getByTestId('cache-flush-confirm')).toHaveCount(0);
  expect(bodies.length).toBe(1);
  await card.getByRole('button', { name: 'Flush negative answers…' }).click();
  await card.getByRole('button', { name: 'Yes, flush' }).click();
  await expect.poll(() => bodies[1]).toEqual({ kind: 'negative' });
  // The confirmation closes only when this flush has answered, so the notice below is its own.
  await expect(card.getByTestId('cache-flush-confirm')).toHaveCount(0);
  await expect(card.getByTestId('cache-flushed')).toContainText('Removed');
  // The positive answer is still cached after negative and failed-lookup flushes.
  await card.getByRole('button', { name: 'Flush failed lookups…' }).click();
  await card.getByRole('button', { name: 'Yes, flush' }).click();
  await expect.poll(() => bodies[2]).toEqual({ kind: 'bogus' });
  await expect(card.getByTestId('cache-flush-confirm')).toHaveCount(0);
  await expect(card.getByTestId('cache-flushed')).toContainText('Removed');
  expect((await (await r.get('/api/v1/cache/lookup?name=typed.cache.e2e.test')).json()).entries.length).toBeGreaterThan(0);
  // The recursor: zone cuts and round-trip times (this build's upstream isn't recursive: none to drop).
  await card.getByRole('button', { name: 'Flush zone cuts…' }).click();
  await card.getByRole('button', { name: 'Yes, flush' }).click();
  await expect.poll(() => bodies[3]).toEqual({ recursor: 'cuts' });
  await expect(card.getByTestId('cache-flush-confirm')).toHaveCount(0);
  await expect(card.getByTestId('cache-flushed')).toContainText('Dropped 0 resolver entries');
  await card.getByRole('button', { name: 'Flush round-trip times…' }).click();
  await card.getByRole('button', { name: 'Yes, flush' }).click();
  await expect.poll(() => bodies[4]).toEqual({ recursor: 'rtts' });
  await expect(card.getByTestId('cache-flush-confirm')).toHaveCount(0);
  // A type with no name is broad: it asks, then flushes that type for every name.
  await card.getByRole('textbox', { name: 'Name to look up' }).fill('');
  await card.getByTestId('cache-flush-type').fill('aaaa');
  await card.getByRole('button', { name: 'Flush this type everywhere…' }).click();
  await expect(card.getByTestId('cache-flush-confirm')).toContainText('Flush every AAAA answer');
  await card.getByRole('button', { name: 'Yes, flush' }).click();
  await expect.poll(() => bodies[5]).toEqual({ type: 'AAAA' });
  await expect(card.getByTestId('cache-flush-confirm')).toHaveCount(0);
  await expect(card.getByTestId('cache-flushed')).toContainText('Removed');
  await page.unroute('**/api/v1/cache/flush');
  // Operators only: a viewer is refused by the API.
  const viewer = await page.context().browser()!.newContext({ baseURL: page.url().split('/#')[0] });
  const vr = viewer.request;
  const st = await (await vr.get('/api/v1/auth/status')).json();
  const login = await vr.post('/api/v1/auth/login', {
    headers: { 'x-csrf-token': st.csrfToken ?? '' },
    data: { username: VIEWER.user, password: VIEWER.pass },
  });
  expect(login.ok()).toBeTruthy();
  const csrf = (await (await vr.get('/api/v1/auth/status')).json()).csrfToken as string;
  for (const data of [{ kind: 'negative' }, { recursor: 'cuts' }, { type: 'AAAA' }]) {
    expect((await vr.post('/api/v1/cache/flush', { headers: { 'x-csrf-token': csrf }, data })).status()).toBe(403);
  }
  await viewer.close();
});

// REQ: DNS-006, OBS-003 (T6.15) — the Cache page: this node's hit rate, how full it is, its
// settings and start; what it holds by kind and its top entries (sortable); Settings links here.
test('dns_006 cache page', async () => {
  await query('top.cache.e2e.test'); // the stub upstream: one cacheable answer
  await query('top.cache.e2e.test'); // and a hit
  await page.goto('/#/cache');
  const node = page.getByTestId('cache-node');
  await expect(node).toHaveCount(1);
  // DNS-007 (ADR-119): fresh answers and those refreshed in the background, as one number.
  await expect(node.getByTestId('cache-answered')).toContainText('last hour');
  await expect(node).toContainText('Answered from the cache');
  await expect(node.getByTestId('cache-warm')).toContainText('cold (keeping the cache across restarts is off)');
  // REQ: OBS-021 — a fresh server has too few lookups to judge the size.
  await expect(node.getByTestId('cache-sizing')).toContainText('learning');
  await expect(node.getByTestId('cache-sizing')).toContainText('Not enough lookups yet');
  await node.getByText('Settings', { exact: true }).click();
  await expect(node.getByTestId('cache-settings')).toContainText('Serve stale');
  const top = page.getByTestId('cache-top');
  // `exact`: a timeline marker's label ("2 lists refreshed: ...") matches "Refresh" as a substring.
  await page.getByRole('button', { name: 'Refresh', exact: true }).click();
  await expect(top).toContainText('top.cache.e2e.test');
  await expect(page.getByTestId('cache-makeup')).toContainText(/[1-9]\d* answers?/);
  // The most-hit entry first; sorting by size and expiry also lists it.
  const firstName = top.locator('tbody tr').first().locator('td').first();
  await expect(firstName).toHaveText('top.cache.e2e.test');
  await page.getByLabel('Sort by').selectOption('expiring');
  await expect(top).toContainText('top.cache.e2e.test');
  // Clicking a name fills in the lookup below.
  await top.getByRole('button', { name: 'top.cache.e2e.test' }).first().click();
  const card = page.getByTestId('cache-card');
  await expect(card.getByRole('textbox', { name: 'Name to look up' })).toHaveValue('top.cache.e2e.test');
  await expect(card.getByTestId('cache-entries')).toContainText('NOERROR');
  // The API: top entries need a known sort.
  expect((await page.request.get('/api/v1/cache/entries?sort=nope')).status()).toBe(400);
  // ADR-121 — the Cache link is under Settings → Query handling, updates under System.
  await page.goto('/#/settings?tab=queries');
  await expect(page.getByRole('link', { name: 'Cache page' })).toHaveAttribute('href', '#/cache');
  await page.goto('/#/settings?tab=system');
  // REQ: OPS-004 — "Check now" (admins): a local build isn't compared with releases, so the
  // status stays "newer" and nothing is fetched.
  const check = page.waitForResponse('**/api/v1/system/update-check');
  await page.getByTestId('check-updates').click();
  expect((await check).status()).toBe(200);
  await expect(page.getByTestId('updates')).toContainText('Newer than the published');
});

// REQ: OBS-033, DNS-006 — past 40 markers in view a chart gives those within 8 px one button.
// Each button was keyed by its first marker's rounded x, so two neighbouring columns could share
// a key at some widths, and Svelte threw each_key_duplicate (a page error, which the afterEach
// below turns into a failure of whichever test ran then). A stubbed pile of notes on the Cache
// page, drawn at many widths: every width must draw without a page error.
test('obs_033 many markers on the Cache page never share a key at any width', async () => {
  // 173 widths, each a resize and two frames: a slow runner needs more than the default 30 s.
  test.setTimeout(120_000);
  const now = Date.now();
  const items = Array.from({ length: 150 }, (_, i) => {
    const t = new Date(now - 30_000 - i * 530 - ((i * 37) % 400));
    return { t: t.toISOString(), tUnixMs: t.getTime(), kind: 'note', summary: `note ${i}` };
  });
  await page.route('**/api/v1/annotations?**', (route) => route.fulfill({ json: { items, truncated: false, missingNodes: [] } }));
  try {
    await page.goto('/#/cache');
    await page.reload();
    const layer = page.getByTestId('chart-markers').first();
    await expect(layer.locator('button.mk').first()).toBeVisible({ timeout: 20_000 });
    const frame = () => page.evaluate(() => new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(r))));
    for (let w = 640; w <= 1500; w += 5) {
      await page.setViewportSize({ width: w, height: 800 });
      await frame();
    }
    await expect(layer.locator('button.mk').first()).toBeVisible();
  } finally {
    await page.setViewportSize({ width: 1280, height: 720 });
    await page.unroute('**/api/v1/annotations?**');
  }
});

// REQ: CLU-005 (T24.38, ADR-1018) — a voter reached only some of the time is a warning on the
// Failover line (named by site, with its drops) and a failing "voter links" check with its fix;
// a steady cluster shows neither. The help topic is on the Failover label.
test('clu_005 a voter whose link comes and goes is a warning on the Cluster page', async () => {
  const node = (o: Record<string, unknown>) => ({
    ephemeral: false, witness: false, protocol: 4, role: 'replica', thisNode: false, eligible: true, version: '0.8.0',
    up: true, connected: true, link: 'inbound', lastSeenSecondsAgo: 1, rttMs: 3, configSeq: 9, configLag: 0, ready: true,
    qps: 1, servfailPercent: 0, upstreamP90Ms: 12, uptimeSeconds: 3600, restarts: 0, cacheEntries: 5,
    cacheHitPercent: 80, querySharePercent: 10, ...o,
  });
  const view = (flaky: boolean) => ({
    enabled: true, clusterId: 'c1', name: 'home', thisNode: 'id-a', newestConfigSeq: 9, healthy: !flaky,
    checks: [
      { id: 'peers_up', ok: true, summary: 'All 3 nodes are up' },
      flaky
        ? { id: 'voter_links', ok: false, summary: "A voter's link comes and goes: id-b (dropped 5 times in 10 min)", fix: 'Check the network and cluster port between the nodes.' }
        : { id: 'voter_links', ok: true, summary: "Every voter's link is steady" },
    ],
    events: [], conflicts: [], authority: 'primary',
    failover: {
      mode: 'auto', active: true, voters: 3, reachableVoters: 3, leaseHeld: false, votedEpoch: 1,
      unstableVoters: flaky ? [{ nodeId: 'id-b', drops: 5, windowSeconds: 600, lastDropSecondsAgo: 40 }] : [],
    },
    nodes: [
      node({ nodeId: 'id-a', site: 'replica-a', thisNode: true, link: 'self', rttMs: null }),
      node({ nodeId: 'id-p', site: 'primary', role: 'primary', link: 'outbound' }),
      node({ nodeId: 'id-b', site: 'replica-b' }),
    ],
  });
  let current = view(true);
  await page.route('**/api/v1/cluster', (route) => route.fulfill({ json: current }));
  await page.route('**/api/v1/cluster/rollout', (route) => route.fulfill({ json: { fromPrimary: true, canaries: [], bakeSecs: 300, stable: '1.9', stage: 'none', nodes: [] } }));
  await page.route('**/api/v1/cluster/versions', (route) => route.fulfill({ json: { items: [], history: 20 } }));
  try {
    await page.goto('/#/cluster');
    const warn = page.getByTestId('cluster-unstable-voters');
    await expect(warn).toContainText('replica-b');
    await expect(warn).toContainText('dropped 5 times in the last 10 minutes');
    await expect(page.getByRole('button', { name: 'Help: Every voter reachable, all the time' })).toBeVisible();
    // The check, with its fix, on the Health tab.
    await page.goto('/#/cluster?tab=health');
    const check = page.getByTestId('cluster-check').filter({ hasText: 'comes and goes' });
    await expect(check).toContainText('Check the network and cluster port');
    // Steady again: no warning.
    current = view(false);
    await page.goto('/#/cluster');
    await expect(page.getByTestId('cluster-unstable-voters')).toHaveCount(0, { timeout: 12_000 });
    await expect(page.getByTestId('cluster-failover')).toContainText('automatic: 3 of 3 voters reachable');
  } finally {
    for (const r of ['**/api/v1/cluster', '**/api/v1/cluster/rollout', '**/api/v1/cluster/versions']) await page.unroute(r);
  }
});

// REQ: CLU-005 (ADR-960, T21.7) — turning automatic failover on under a running cluster needs no
// restart: the Cluster page, which polls every 5 s, goes from "manual" to "automatic" with the
// lease the primary now holds, and the other replica (no stream to this node in manual mode) is
// listed up on the primary's word, so the health check "peers up" holds in either mode.
test('clu_005 the failover mode changes on the Cluster page without a restart', async () => {
  const node = (o: Record<string, unknown>) => ({
    ephemeral: false, witness: false, protocol: 1, role: 'replica', thisNode: false, eligible: true, version: '0.8.0',
    up: true, connected: true, link: 'inbound', lastSeenSecondsAgo: 1, rttMs: 3, configSeq: 9, configLag: 0, ready: true,
    qps: 1, servfailPercent: 0, upstreamP90Ms: 12, uptimeSeconds: 3600, restarts: 0, cacheEntries: 5,
    cacheHitPercent: 80, querySharePercent: 10, ...o,
  });
  const view = (failover: Record<string, unknown>) => ({
    enabled: true, clusterId: 'c1', name: 'home', thisNode: 'id-a', newestConfigSeq: 9, healthy: true,
    checks: [{ id: 'peers_up', ok: true, summary: 'All 3 nodes are up' }],
    events: [], conflicts: [], authority: 'primary', failover,
    nodes: [
      node({ nodeId: 'id-a', site: 'replica-a', thisNode: true, link: 'self', rttMs: null }),
      node({ nodeId: 'id-p', site: 'primary', role: 'primary', link: 'outbound' }),
      node({ nodeId: 'id-b', site: 'replica-b', connected: false, link: 'relayed', rttMs: null }),
    ],
  });
  let current = view({ mode: 'manual', active: false, voters: 3, reachableVoters: 2, leaseHeld: false, votedEpoch: 0 });
  await page.route('**/api/v1/cluster', (route) => route.fulfill({ json: current }));
  await page.route('**/api/v1/cluster/rollout', (route) => route.fulfill({ json: { fromPrimary: true, canaries: [], bakeSecs: 300, stable: '1.9', stage: 'none', nodes: [] } }));
  await page.route('**/api/v1/cluster/versions', (route) => route.fulfill({ json: { items: [], history: 20 } }));
  try {
    await page.goto('/#/cluster');
    await expect(page.getByTestId('cluster-failover')).toContainText('manual');
    // The replica with no stream to this node is up, on the primary's word.
    const b = page.locator('#node-id-b');
    await expect(b).toContainText('relayed');
    await expect(b).not.toContainText('seen');
    // `wrendns cluster set-failover auto` on the primary: no restart anywhere.
    current = view({ mode: 'auto', active: true, voters: 3, reachableVoters: 3, leaseHeld: true, leaseSecondsLeft: 11, votedEpoch: 1, votedFor: 'id-p' });
    await expect(page.getByTestId('cluster-failover')).toContainText('automatic: 3 of 3 voters reachable', { timeout: 10_000 });
    await expect(page.getByTestId('cluster-failover')).toContainText("this primary's lease: 11 s left");
    await expect(page.getByTestId('cluster-failover')).not.toContainText('manual');
  } finally {
    for (const r of ['**/api/v1/cluster', '**/api/v1/cluster/rollout', '**/api/v1/cluster/versions']) await page.unroute(r);
  }
});

// REQ: DNS-006, CLU-008 (T6.15) — the Cache page scales with the cluster: with 8 nodes, each
// name is listed once (hits summed, "N of 8" nodes, per-node detail on demand), and the makeup
// is one row per node, the first 6 shown.
test('dns_006 cache page with many nodes', async () => {
  const pods = Array.from({ length: 8 }, (_, i) => `wrendns-resolver-${i}`);
  const entry = (name: string, hits: number, ttl: number) => ({
    name, qtype: 'A', rcode: 'NOERROR', answers: 1, authentic: false, dnssecOk: false,
    ttlLeftSeconds: ttl, ageSeconds: 10, bytes: 180, hits,
  });
  const makeup = { positive: 90, nxdomain: 6, nodata: 3, servfail: 1, stale: 2, validated: 40 };
  await page.route('**/api/v1/cache/entries**', (route) =>
    route.fulfill({
      json: {
        missingNodes: [],
        items: pods.map((node, i) => ({
          node,
          makeup,
          // Every node holds popular.example; the first three also hold three.example.
          entries: [entry('popular.example', 10, 100 + i), ...(i < 3 ? [entry('three.example', 5, 50)] : [])],
        })),
      },
    }),
  );
  await page.goto('/#/cache');
  const top = page.getByTestId('cache-top');
  await expect(top.locator('tbody tr')).toHaveCount(2); // two names, not 11 rows
  const first = top.locator('tbody tr').first();
  await expect(first).toContainText('popular.example');
  await expect(first).toContainText('8 of 8');
  await expect(first).toContainText('80'); // 8 × 10 hits
  await expect(top.locator('tbody tr').nth(1)).toContainText('3 of 8');
  await first.getByRole('button', { name: '8 of 8' }).click();
  await expect(top.locator('tr.detail')).toContainText('wrendns-resolver-7');
  const makeupRows = page.getByTestId('cache-makeup').locator('tbody tr');
  await expect(makeupRows).toHaveCount(6);
  await page.getByRole('button', { name: 'Show all 8 nodes' }).click();
  await expect(makeupRows).toHaveCount(8);
  await page.unroute('**/api/v1/cache/entries**');
});

// REQ: FLT-009 (T7.1) — pause blocking from the header and resume it; the API refuses bad
// input (no minutes, too many, an unknown group).
test('flt_009 pause and resume blocking', async () => {
  await page.goto('/#/');
  await page.getByRole('button', { name: 'Pause blocking' }).click();
  await page.getByRole('menuitem', { name: '5 minutes', exact: true }).click();
  const pill = page.getByTestId('blocking-paused');
  await expect(pill).toContainText(/Blocking paused · [45] min left/);
  const st = await (await page.request.get('/api/v1/blocking')).json();
  expect(st.items[0].pauses[0].group ?? null).toBeNull();
  await pill.getByRole('button', { name: 'Resume' }).click();
  await expect(pill).toHaveCount(0);
  const csrf = (await (await page.request.get('/api/v1/auth/status')).json()).csrfToken as string;
  const post = (data: object) =>
    page.request.post('/api/v1/blocking/pause', { headers: { 'x-csrf-token': csrf }, data });
  expect((await post({})).status()).toBe(400);
  expect((await post({ minutes: 5000 })).status()).toBe(400);
  expect((await post({ minutes: 5, group: 'nope' })).status()).toBe(400);
  // A group pause shows as a count, not as everyone paused.
  expect((await post({ minutes: 5, group: 'lab' })).status()).toBe(200);
  await page.reload();
  await expect(page.getByTestId('groups-paused')).toContainText('1 group paused');
  await page.request.post('/api/v1/blocking/resume', { headers: { 'x-csrf-token': csrf }, data: {} });
});

// The help drawer reads the same wherever its "?" sits (owner report: from the Quick rules
// page title it took the heading's size).
test('api_011 help drawer text is body-sized everywhere', async () => {
  const size = async () => {
    const p = page.getByRole('dialog').locator('p').first();
    await expect(p).toBeVisible();
    const px = await p.evaluate((el) => getComputedStyle(el).fontSize);
    await page.keyboard.press('Escape');
    return px;
  };
  // The header's "?" (the reference), then the one in the Quick rules title.
  await page.goto('/#/rules');
  await page.locator('header.top').getByRole('button', { name: /help/i }).first().click();
  const reference = await size();
  await page.getByRole('heading', { name: 'Quick rules' }).getByRole('button').click();
  expect(await size()).toBe(reference);
});

// REQ: API-002 (T7.5, ADR-069) — upstreams and lists through the API: add, override the
// files' entry, refuse a change that breaks the configuration, and revert.
// REQ: AGT-007 (T7.1) — an agent's plan waits for an operator: the header says so, the
// Agent changes page shows what it does and why, and approving it lets the agent apply it.
test('agt_007 approve an agent plan in the UI', async () => {
  await page.setViewportSize({ width: 1280, height: 800 });
  const r = page.request;
  const csrf = (await (await r.get('/api/v1/auth/status')).json()).csrfToken as string;
  const token = (
    await (
      await r.post('/api/v1/tokens', {
        headers: { 'x-csrf-token': csrf },
        data: { name: 'ui-agent', kind: 'agent', scopes: ['analytics:read', 'config:write:rules'] },
      })
    ).json()
  ).token as string;
  const mcp = async (name: string, args: Record<string, unknown>) => {
    const res = await r.post('/mcp', {
      headers: { authorization: `Bearer ${token}`, accept: 'application/json, text/event-stream' },
      data: { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name, arguments: args } },
    });
    return (await res.json()).result as { isError: boolean; structuredContent?: Record<string, unknown> };
  };
  const planned = await mcp('plan_block_domain', { domain: 'plan.e2e.test', groups: ['default'], reason: 'the e2e asked' });
  expect(planned.isError).toBe(false);
  const id = planned.structuredContent!.planId as string;
  expect((await mcp('apply_plan', { planId: id })).isError).toBe(true);

  await page.goto('/#/');
  await expect(page.getByTestId('agent-inbox')).toHaveText('1 agent change to review', { timeout: 20000 });
  await page.getByTestId('agent-inbox').click();
  await expect(page.getByRole('heading', { name: 'Agent changes' })).toBeVisible();
  const card = page.getByTestId('plan').filter({ hasText: 'Block plan.e2e.test' });
  await expect(card).toContainText('waiting for approval');
  await expect(card).toContainText('the e2e asked');
  await expect(card).toContainText('agent:ui-agent (owner: admin)');
  await card.getByRole('button', { name: 'Approve' }).click();
  await expect(card).toContainText('approved');
  await expect(card).toContainText('Decided by');

  const applied = await mcp('apply_plan', { planId: id });
  expect(applied.isError).toBe(false);
  await expect(card).toContainText('applied', { timeout: 10000 });
  expect((await (await r.get('/api/v1/rules')).json()).items.map((x: { id: string }) => x.id)).toContain('agent-block-plan-e2e-test');
  expect((await r.delete('/api/v1/rules/agent-block-plan-e2e-test', { headers: { 'x-csrf-token': csrf } })).status()).toBe(200);
});

// REQ: API-002 (T7.5, ADR-069) — the Lists and Upstreams pages add, change, and revert entries
// with a preview first; the config files are never rewritten.
test('api_002 lists and upstreams are edited from the UI', async () => {
  await page.setViewportSize({ width: 1280, height: 800 });
  await page.goto('/#/lists');
  const lists = page.getByTestId('editor-list');
  await lists.getByRole('button', { name: 'Add list' }).click();
  await page.getByRole('textbox', { name: 'Name', exact: true }).fill('ui-extra');
  await page.getByRole('textbox', { name: 'Rules', exact: true }).fill('||ui-extra.e2e.test^');
  // REQ: API-002 (T9.12) — try the draft before saving it.
  await page.getByRole('button', { name: 'Test it' }).click();
  await expect(page.getByTestId('form-action-result')).toContainText('Works: 1 rules from 1 lines');
  await page.getByRole('button', { name: 'Check' }).click();
  await expect(page.getByTestId('entry-preview')).toBeVisible();
  await page.getByRole('button', { name: 'Apply' }).click();
  const row = lists.getByTestId('entry-row').filter({ hasText: 'ui-extra' });
  await expect(row).toContainText('added here');
  await expect(row).toContainText('1 rules');
  await row.getByRole('button', { name: 'Remove' }).click();
  await expect(row).toHaveCount(0);

  // An upstream from the files: overridden, then back to the files' version.
  await page.goto('/#/upstreams');
  await page.getByTestId('view-advanced').click(); // T24.36: the editors are in the Advanced view
  const ups = page.getByTestId('editor-upstream');
  const router = ups.getByTestId('entry-row').filter({ hasText: 'router' });
  await expect(router).toContainText('config file');
  await router.getByRole('button', { name: 'Edit' }).click();
  await expect(page.getByRole('textbox', { name: 'Name', exact: true })).toHaveValue('router');
  await page.getByRole('textbox', { name: 'Address', exact: true }).fill(`udp://127.0.0.1:${PORTS.upstream}`);
  // The e2e fake upstream answers there (T9.12).
  await page.getByRole('button', { name: 'Test it' }).click();
  await expect(page.getByTestId('form-action-result')).toContainText('Works: answered NOERROR');
  await page.getByRole('button', { name: 'Check' }).click();
  await page.getByRole('button', { name: 'Apply' }).click();
  await expect(router).toContainText('overrides the file');
  await router.getByRole('button', { name: 'Revert to the file' }).click();
  await expect(router).toContainText('config file');
});

// REQ: FLT-004 — "Update now" on the Lists page queues every enabled list (202), follows the
// downloads, and says when they're done; the API takes a dry run and names, refuses unknown
// lists and viewers, and audits the refresh.
test('flt_004 update lists now', async () => {
  await page.goto('/#/lists');
  const btn = page.getByTestId('lists-update-now');
  await expect(btn).toHaveText('Update now');
  const queued = page.waitForResponse((r) => r.url().endsWith('/api/v1/lists/refresh') && r.request().method() === 'POST');
  await btn.click();
  const res = await queued;
  expect(res.status()).toBe(202);
  const body = await res.json();
  expect(body.queued).toContain('e2e-block');
  expect(body.dryRun).toBe(false);
  const status = page.getByTestId('lists-refresh-status');
  await expect(status).toContainText('Lists updated', { timeout: 15_000 });
  await expect(btn).toHaveText('Update now');
  await expect(page.getByTestId('list-refreshing')).toHaveCount(0);
  const lists = (await (await page.request.get('/api/v1/lists')).json()).items as { name: string; refreshing: boolean; lastSuccessUnixSeconds?: number }[];
  const block = lists.find((l) => l.name === 'e2e-block')!;
  expect(block.refreshing).toBe(false);
  // REQ: FLT-004 — an inline list has no download to confirm, so it has no "last confirmed" time
  // (735491a, merged from upstream; the e2e lists are all inline).
  expect(block.lastSuccessUnixSeconds).toBeUndefined();

  const csrf = (await (await page.request.get('/api/v1/auth/status')).json()).csrfToken as string;
  const post = (path: string, data: object) => page.request.post(path, { headers: { 'x-csrf-token': csrf }, data });
  const dry = await post('/api/v1/lists/refresh?dryRun=true', { names: ['e2e-block'] });
  expect(dry.status()).toBe(202);
  expect((await dry.json()).dryRun).toBe(true);
  expect((await post('/api/v1/lists/refresh', { names: ['no-such-list'] })).status()).toBe(404);
  const audit = (await (await page.request.get('/api/v1/audit?action=lists.refresh')).json()).items;
  expect(audit.length).toBeGreaterThan(0);

  // A viewer sees the lists but no button, and the API refuses.
  const viewer = await page.context().browser()!.newContext({ baseURL: page.url().split('/#')[0] });
  const vr = viewer.request;
  const st = await (await vr.get('/api/v1/auth/status')).json();
  const login = await vr.post('/api/v1/auth/login', {
    headers: { 'x-csrf-token': st.csrfToken ?? '' },
    data: { username: VIEWER.user, password: VIEWER.pass },
  });
  expect(login.ok()).toBeTruthy();
  const vcsrf = (await (await vr.get('/api/v1/auth/status')).json()).csrfToken as string;
  expect((await vr.post('/api/v1/lists/refresh', { headers: { 'x-csrf-token': vcsrf }, data: {} })).status()).toBe(403);
  const vpage = await viewer.newPage();
  await vpage.goto('/#/lists');
  await expect(vpage.getByRole('heading', { name: /^Lists/ })).toBeVisible();
  await expect(vpage.getByText('e2e-block').first()).toBeVisible();
  await expect(vpage.getByTestId('lists-update-now')).toHaveCount(0);
  await viewer.close();
});

// REQ: FLT-004 (T24.17) — each list's row has its own "Update now" (names: [that list]), disabled
// while the list downloads or is off, and "Confirmed current" shows when it last downloaded fine.
test('flt_004 update one list now', async () => {
  await page.goto('/#/lists');
  const row = page.locator('table:not(.compact) tbody tr').filter({ has: page.locator('strong', { hasText: /^e2e-block$/ }) });
  const rowBtn = row.getByTestId('list-update-now');
  await expect(rowBtn).toHaveText('Update now');
  await expect(rowBtn).toBeEnabled();
  const queued = page.waitForResponse((r) => r.url().endsWith('/api/v1/lists/refresh') && r.request().method() === 'POST');
  await rowBtn.click();
  const res = await queued;
  expect(res.status()).toBe(202);
  expect(res.request().postDataJSON()).toEqual({ names: ['e2e-block'] });
  const body = await res.json();
  expect(body.queued).toEqual(['e2e-block']);
  await expect(page.getByTestId('lists-refresh-status')).toContainText('e2e-block updated', { timeout: 15_000 });
  await expect(rowBtn).toHaveText('Update now');
  await expect(rowBtn).toBeEnabled();

  // While a list downloads, its row's button says so and is disabled; the others stay enabled.
  let downloading = true;
  await page.route('**/api/v1/lists', async (route) => {
    const r = await route.fetch();
    const json = await r.json();
    if (downloading) json.items = json.items.map((l: { name: string }) => (l.name === 'e2e-block' ? { ...l, refreshing: true } : l));
    await route.fulfill({ response: r, json });
  });
  await page.reload();
  await expect(rowBtn).toBeDisabled();
  await expect(rowBtn).toHaveText('Updating…');
  await expect(page.locator('table:not(.compact) tbody tr').filter({ has: page.locator('strong', { hasText: /^e2e-shadow$/ }) }).getByTestId('list-update-now')).toBeEnabled();
  downloading = false;
  await page.unroute('**/api/v1/lists');
  await page.reload();
  await expect(rowBtn).toBeEnabled();

  // "Confirmed current" reads the last successful download; an inline list has none to confirm.
  await page.route('**/api/v1/lists', async (route) => {
    const r = await route.fetch();
    const json = await r.json();
    const now = Date.now() / 1000;
    json.items = json.items.map((l: { name: string }) =>
      l.name === 'e2e-block' ? { ...l, source: 'https://lists.e2e.test/block.txt', lastSuccessUnixSeconds: Math.floor(now - 7260) } : l,
    );
    await route.fulfill({ response: r, json });
  });
  await page.reload();
  await expect(row.getByTestId('list-confirmed')).toContainText('2h 1m ago');
  await expect(page.locator('table:not(.compact) tbody tr').filter({ has: page.locator('strong', { hasText: /^e2e-shadow$/ }) }).getByTestId('list-confirmed')).toHaveText('inline');
  await page.unroute('**/api/v1/lists');
  await page.reload();
});

// REQ: FLT-004, API-005 (T24.28, ADR-992) — a list whose names another list already has shows what it
// adds and who covers it; Prune previews the lists that add little at a threshold, turns them off after
// a confirmation (the list stays in the configuration), and Undo turns it on again.
test('flt_004 prune lists that add little, then undo', async () => {
  await page.setViewportSize({ width: 1280, height: 800 });
  const csrf = (await (await page.request.get('/api/v1/auth/status')).json()).csrfToken as string;
  const names = (from: number, to: number) => Array.from({ length: to - from }, (_, i) => `||n${from + i}.prune.e2e.test^`);
  // prune-big has 60 names, prune-small the first 10 of them: nothing of its own.
  for (const [name, rules] of [['prune-big', names(0, 60)], ['prune-small', names(0, 10)]] as const) {
    const r = await page.request.put(`/api/v1/lists/${name}`, { headers: { 'x-csrf-token': csrf }, data: { rules, kind: 'block' } });
    expect(r.ok(), `${name}: ${await r.text()}`).toBeTruthy();
  }
  const listed = async () =>
    ((await (await page.request.get('/api/v1/lists')).json()).items as { name: string; enabled: boolean; entries: number; unique: number }[]);
  await expect.poll(async () => (await listed()).find((l) => l.name === 'prune-small')?.entries, { timeout: 45_000 }).toBe(10);
  await expect.poll(async () => (await listed()).find((l) => l.name === 'prune-big')?.unique, { timeout: 45_000 }).toBe(50);

  await page.goto('/#/lists');
  await page.reload(); // the page may already be on /#/lists, with the lists read before these two existed
  // The name is the first cell's own strong: a "Every name in it is also in <strong>…" note in another row's first cell must not match too.
  const row = (name: string) => page.locator('table:not(.compact) tbody tr').filter({ has: page.locator('td:first-child > strong', { hasText: new RegExp(`^${name}$`) }) });
  await expect(row('prune-small').getByTestId('list-adds')).toHaveText('adds 0%');
  await expect(row('prune-small').getByTestId('list-covered-by')).toContainText('100% also in prune-big');
  // prune-small's row names prune-big too ("also in prune-big"), so look for the figure, not the row's only cell.
  await expect(row('prune-big').getByTestId('list-adds').filter({ hasText: 'adds 83.3%' })).toHaveCount(1);

  // The read API: the overlap rows and the plan agree with the page.
  const ov = (await (await page.request.get('/api/v1/lists/overlap')).json()).items as { name: string; addsPercent: number; coveredBy: { list: string }[] }[];
  expect(ov.find((o) => o.name === 'prune-small')?.coveredBy[0].list).toBe('prune-big');
  const planned = await (await page.request.get('/api/v1/lists/prune-plan?thresholdPercent=1')).json();
  expect(planned.candidates.map((c: { name: string }) => c.name)).toContain('prune-small');
  expect(planned.candidates.map((c: { name: string }) => c.name)).not.toContain('prune-big');
  expect((await page.request.get('/api/v1/lists/prune-plan?thresholdPercent=90')).status()).toBe(400);

  await page.getByTestId('lists-prune').click();
  const panel = page.getByTestId('prune-panel');
  await expect(panel).toBeVisible();
  const cand = panel.getByTestId('prune-candidate');
  await expect(cand.filter({ hasText: 'prune-small' })).toHaveCount(1);
  await expect(cand.filter({ has: page.locator('strong', { hasText: /^prune-big$/ }) })).toHaveCount(0); // it adds 83%
  await expect(cand.filter({ hasText: 'prune-small' })).toContainText('prune-big (100%)');
  await panel.locator('summary').click();
  await expect(panel.getByTestId('prune-kept')).toContainText('prune-big: adds 83.3% of its entries, above 1%');
  await expect(panel.getByTestId('prune-kept')).toContainText('e2e-shadow: shadow mode');

  // A threshold outside 0-50 is refused in the form; 0 still proposes a list that adds nothing.
  await panel.getByTestId('prune-threshold').fill('90');
  await expect(panel.getByText('Enter a number from 0 to 50.')).toBeVisible();
  await expect(panel.getByTestId('prune-preview')).toBeDisabled();
  await panel.getByTestId('prune-threshold').fill('0');
  await panel.getByTestId('prune-preview').click();
  await expect(cand.filter({ hasText: 'prune-small' })).toHaveCount(1);

  // Nothing changes until it is confirmed; Back leaves the list on.
  await panel.getByTestId('prune-apply').click();
  await expect(panel.getByTestId('prune-confirm-text')).toBeVisible();
  expect((await listed()).find((l) => l.name === 'prune-small')?.enabled).toBe(true);
  await panel.getByRole('button', { name: 'Back' }).click();
  await expect(panel.getByTestId('prune-apply')).toBeVisible();

  // A stale preview: the configuration changed after it (any edit), so the confirmation is refused with
  // a 409, nothing is turned off, and previewing again brings the versions up to date.
  await panel.getByTestId('prune-apply').click();
  const touch = await page.request.put('/api/v1/lists/prune-touch', { headers: { 'x-csrf-token': csrf }, data: { rules: ['||touch.prune.e2e.test^'], kind: 'block' } });
  expect(touch.ok(), await touch.text()).toBeTruthy();
  await expect.poll(async () => (await listed()).find((l) => l.name === 'prune-touch')?.entries, { timeout: 45_000 }).toBe(1);
  const refusedApply = page.waitForResponse((r) => r.url().endsWith('/api/v1/lists/prune') && r.request().method() === 'POST');
  await panel.getByTestId('prune-confirm').click();
  expect((await refusedApply).status()).toBe(409);
  await expect(page.getByText(/preview again/i).first()).toBeVisible();
  await expect.poll(() => problems.some((m) => /status of 409/.test(m))).toBe(true);
  for (let i = problems.length - 1; i >= 0; i--) if (/status of 409/.test(problems[i])) problems.splice(i, 1); // the expected refusal
  expect((await listed()).find((l) => l.name === 'prune-small')?.enabled).toBe(true);
  await panel.getByTestId('prune-preview').click();
  await expect(cand.filter({ hasText: 'prune-small' })).toHaveCount(1);
  await panel.getByTestId('prune-apply').click();
  const applied = page.waitForResponse((r) => r.url().endsWith('/api/v1/lists/prune') && r.request().method() === 'POST');
  await panel.getByTestId('prune-confirm').click();
  const res = await applied;
  expect(res.status()).toBe(200);
  expect(res.request().postDataJSON().names).toContain('prune-small');
  const done = page.getByTestId('prune-done');
  await expect(done).toContainText('prune-small');
  await expect(panel).toHaveCount(0);
  // The state badge ("off"), not the "Turn it off" button of a redundant list.
  await expect(row('prune-small').locator('span.badge', { hasText: /^off$/ })).toHaveCount(1);
  expect((await listed()).find((l) => l.name === 'prune-small')?.enabled).toBe(false);
  expect((await listed()).find((l) => l.name === 'prune-big')?.enabled).toBe(true);
  const audit = (await (await page.request.get('/api/v1/audit?action=lists.prune')).json()).items;
  expect(audit.length).toBeGreaterThan(0);

  // Undo: the list is on again, with its rules.
  await done.getByTestId('prune-undo').click();
  await expect(done).toHaveCount(0);
  await expect.poll(async () => (await listed()).find((l) => l.name === 'prune-small')?.enabled).toBe(true);
  await expect(row('prune-small').locator('span.badge', { hasText: /^off$/ })).toHaveCount(0); // the "Turn it off" button is not the badge
  const def = (await (await page.request.get('/api/v1/config/entries?kind=list')).json()).items.find((e: { name: string }) => e.name === 'prune-small');
  expect(def.definition.rules).toHaveLength(10);

  // A group that names a list keeps it: the preview says so.
  const grp = await page.request.put('/api/v1/groups/prune-grp', { headers: { 'x-csrf-token': csrf }, data: { networks: ['10.78.0.0/24'], lists: ['prune-small'] } });
  expect(grp.ok(), await grp.text()).toBeTruthy();
  await page.getByTestId('lists-prune').click();
  await expect(panel).toBeVisible();
  await expect(panel.getByTestId('prune-candidate').filter({ hasText: 'prune-small' })).toHaveCount(0);
  await panel.locator('summary').click();
  await expect(panel.getByTestId('prune-kept')).toContainText('prune-small: group `prune-grp` names it');
  await panel.getByTestId('prune-close').click();
  expect((await page.request.delete('/api/v1/groups/prune-grp', { headers: { 'x-csrf-token': csrf } })).ok()).toBeTruthy();

  // Agents don't get to apply it.
  const tok = await page.request.post('/api/v1/tokens', { headers: { 'x-csrf-token': csrf }, data: { name: 'prune-agent', kind: 'agent', scopes: ['config:read', 'config:write:lists'] } });
  expect(tok.status()).toBe(201);
  const agent = (await tok.json()).token as string;
  const asAgent = await page.context().browser()!.newContext({ baseURL: page.url().split('/#')[0] });
  const plan = await asAgent.request.get('/api/v1/lists/prune-plan', { headers: { authorization: `Bearer ${agent}` } });
  expect(plan.status()).toBe(200);
  const refused = await asAgent.request.post('/api/v1/lists/prune', {
    headers: { authorization: `Bearer ${agent}`, 'x-wrendns-reason': 'tidy up the lists' },
    data: { names: ['prune-small'], snapshotVersion: 1, configVersion: 1 },
  });
  expect(refused.status()).toBe(403);
  expect((await refused.json()).code).toBe('agent_not_allowed');
  await asAgent.close();

  // Clean up: the lists, and the agent token.
  for (const name of ['prune-small', 'prune-big', 'prune-touch']) {
    expect((await page.request.delete(`/api/v1/lists/${name}`, { headers: { 'x-csrf-token': csrf } })).ok()).toBeTruthy();
  }
  const tokens = (await (await page.request.get('/api/v1/tokens')).json()).items as { id: string; name: string }[];
  for (const t of tokens.filter((x) => x.name === 'prune-agent')) await page.request.delete(`/api/v1/tokens/${t.id}`, { headers: { 'x-csrf-token': csrf } });
});

// REQ: FLT-004 (T24.17) — a viewer sees the lists and when each was confirmed, with no update button.
test('flt_004 viewer sees no update buttons', async ({ browser }) => {
  const viewer = await browser.newContext({ baseURL: page.url().split('/#')[0] || BASE_URL });
  const vpage = await viewer.newPage();
  await vpage.goto('/');
  await vpage.getByLabel('Username', { exact: true }).fill(VIEWER.user);
  await vpage.getByLabel('Password', { exact: true }).fill(VIEWER.pass);
  await vpage.getByRole('button', { name: 'Sign in' }).click();
  await expect(vpage.getByRole('heading', { name: 'Dashboard' })).toBeVisible({ timeout: 30_000 });
  await vpage.goto('/#/lists');
  await expect(vpage.getByRole('heading', { name: /^Lists/ })).toBeVisible();
  await expect(vpage.locator('table:not(.compact) tbody tr').filter({ has: vpage.locator('strong', { hasText: /^e2e-block$/ }) })).toBeVisible();
  await expect(vpage.getByRole('columnheader', { name: 'Confirmed current' })).toBeVisible();
  await expect(vpage.getByTestId('list-update-now')).toHaveCount(0);
  await expect(vpage.getByTestId('lists-update-now')).toHaveCount(0);
  await viewer.close();
});

// REQ: FLT-004 (T24.17) — while a row's request is in flight, the status says it is downloading and
// the page-wide "Update now" is disabled, so two refreshes can't start at once.
test('flt_004 a row update says it is downloading before the answer', async () => {
  await page.goto('/#/lists');
  const row = page.locator('table:not(.compact) tbody tr').filter({ has: page.locator('strong', { hasText: /^e2e-block$/ }) });
  let release!: () => void;
  const gate = new Promise<void>((resolve) => (release = resolve));
  await page.route('**/api/v1/lists/refresh', async (route) => {
    await gate;
    await route.continue();
  });
  try {
    await row.getByTestId('list-update-now').click();
    await expect(page.getByTestId('lists-refresh-status')).toContainText('Downloading e2e-block', { timeout: 10_000 });
    await expect(row.getByTestId('list-update-now')).toHaveText('Updating…');
    await expect(row.getByTestId('list-update-now')).toBeDisabled();
    await expect(page.getByTestId('lists-update-now')).toBeDisabled();
    release();
    await expect(page.getByTestId('lists-refresh-status')).toContainText('e2e-block updated', { timeout: 15_000 });
    await expect(row.getByTestId('list-update-now')).toBeEnabled();
  } finally {
    release();
    await page.unroute('**/api/v1/lists/refresh');
  }
});

// REQ: FLT-004 (T24.17) — the lists table fits a phone (375 px): the page itself doesn't scroll sideways.
test('flt_004 lists fit a phone width (375 px)', async () => {
  await page.setViewportSize({ width: 375, height: 812 });
  try {
    await page.goto('/#/lists');
    await expect(page.getByRole('heading', { name: /^Lists/ })).toBeVisible();
    await expect(page.getByRole('columnheader', { name: 'Confirmed current' })).toBeAttached();
    const overflow = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
    expect(overflow).toBeLessThanOrEqual(0);
    await expect(page.locator('table:not(.compact) tbody tr').filter({ has: page.locator('strong', { hasText: /^e2e-block$/ }) }).getByRole('button', { name: 'Update e2e-block now' })).toBeVisible();
  } finally {
    await page.setViewportSize({ width: 1280, height: 800 });
  }
});

// REQ: T24.27 — a list that failed shows why and offers the fix on its row: a raised limit for one
// that is over its size limit, remove-or-replace for a 404, and turn-off/remove for a list whose names
// are all in another. The changes are answered by a stand-in here (the lists stay as the suite expects).
test('t24_27 list failures offer a fix', async () => {
  // REQ: T24.27 - the page refreshes the lists while the test swaps their stand-in: a request the
  // old stand-in caught is finished by Playwright once it is unrouted, and its late fulfill throws
  // "Route is already handled!" (CI 2026-11-20). That request's answer no longer matters.
  const fulfillLate = async (route: Route, answer: Parameters<Route['fulfill']>[0]) => {
    try {
      await route.fulfill(answer);
    } catch (e) {
      if (!String(e).includes('Route is already handled')) throw e;
    }
  };
  const rowOf = (name: string) =>
    page.locator('table:not(.compact) tbody tr').filter({ has: page.locator('strong', { hasText: new RegExp(`^${name}$`) }) });
  const failing = {
    'e2e-block': {
      state: 'failed',
      source: 'https://lists.e2e.test/big.txt',
      error: 'larger than the 67108864-byte limit (the server says it is 70000000 bytes; raise max_bytes for this list)',
    },
    'e2e-shadow': { state: 'failed', source: 'https://lists.e2e.test/gone.txt', error: 'HTTP 404 Not Found' },
  } as Record<string, object>;
  await page.route('**/api/v1/lists', async (route) => {
    const r = await route.fetch();
    const json = await r.json();
    json.items = json.items.map((l: { name: string }) => ({ ...l, ...(failing[l.name] ?? {}) }));
    await fulfillLate(route, { response: r, json });
  });
  const changes: { method: string; url: string; body: Record<string, unknown> | null }[] = [];
  await page.route(/\/api\/v1\/lists\/e2e-(block|shadow)$/, async (route) => {
    const req = route.request();
    changes.push({ method: req.method(), url: req.url(), body: req.postDataJSON() });
    await route.fulfill({ status: 200, json: { applied: true, configVersion: 1 } });
  });
  try {
    await page.goto('/#/lists');
    await page.reload(); // the page is read through the stand-in
    // Over the size limit: the size seen, plus a quarter, in whole MiB; one click sets this list's limit.
    const big = rowOf('e2e-block');
    await expect(big.getByTestId('list-too-large')).toContainText('bigger than its 64.0 MiB limit');
    const raise = big.getByTestId('list-raise-limit');
    await expect(raise).toHaveText('Raise the limit to 84 MiB');
    await raise.click();
    await expect(page.getByTestId('list-fix-note')).toContainText('the limit is now 84 MiB');
    expect(changes).toHaveLength(1);
    expect(changes[0].method).toBe('PUT');
    expect(changes[0].body).toMatchObject({ max_bytes: '84MiB', rules: ['||ads.e2e.test^'] });
    // Not found: said plainly, with remove (asking first).
    const gone = rowOf('e2e-shadow');
    await expect(gone.getByTestId('list-not-found')).toContainText('returns "not found" (HTTP 404)');
    await expect(gone.getByTestId('list-not-found')).toContainText('Remove it, or replace it');
    await gone.getByTestId('list-remove').click();
    expect(changes).toHaveLength(1);
    await gone.getByTestId('list-remove-confirm').click();
    await expect(page.getByTestId('list-fix-note')).toContainText('e2e-shadow was removed');
    expect(changes[1].method).toBe('DELETE');
    expect(changes[1].url).toMatch(/\/api\/v1\/lists\/e2e-shadow$/);
  } finally {
    await page.unroute('**/api/v1/lists');
    await page.unroute(/\/api\/v1\/lists\/e2e-(block|shadow)$/);
  }
  // Above the cap the page doesn't offer a limit it won't allow.
  failing['e2e-block'] = {
    state: 'failed',
    source: 'https://lists.e2e.test/huge.txt',
    error: `larger than the ${128 * 1024 * 1024}-byte limit (raise max_bytes for this list)`,
  };
  await page.route('**/api/v1/lists', async (route) => {
    const r = await route.fetch();
    const json = await r.json();
    json.items = json.items.map((l: { name: string }) => ({ ...l, ...(failing[l.name] ?? {}) }));
    await fulfillLate(route, { response: r, json });
  });
  try {
    await page.reload();
    await expect(rowOf('e2e-block').getByTestId('list-too-large')).toContainText('remove it or use a smaller list');
    await expect(rowOf('e2e-block').getByTestId('list-raise-limit')).toHaveCount(0);
  } finally {
    await page.unroute('**/api/v1/lists');
  }
  // Pruning: every name is in another list.
  const redundantChanges: Record<string, unknown>[] = [];
  // A shadow list never blocks, so it is not a cover: no offer until the cover enforces.
  let coverOverride: Record<string, unknown> = { state: 'ok', enabled: true, mode: 'shadow', kind: 'block', unique: 5 };
  await page.route('**/api/v1/lists', async (route) => {
    const r = await route.fetch();
    const json = await r.json();
    json.items = json.items.map((l: { name: string }) =>
      l.name === 'e2e-block'
        ? { ...l, state: 'ok', enabled: true, entries: 5, unique: 0, overlap: [{ list: 'e2e-shadow', names: 5 }] }
        : l.name === 'e2e-shadow'
          ? { ...l, ...coverOverride }
          : l,
    );
    await fulfillLate(route, { response: r, json });
  });
  await page.route(/\/api\/v1\/lists\/e2e-block$/, async (route) => {
    redundantChanges.push(route.request().postDataJSON());
    await route.fulfill({ status: 200, json: { applied: true, configVersion: 1 } });
  });
  try {
    await page.reload();
    const row = rowOf('e2e-block');
    await expect(row).toBeVisible();
    await expect(row.getByTestId('list-redundant')).toHaveCount(0);
    coverOverride = { state: 'ok', enabled: true, mode: 'enforce', kind: 'block', unique: 5, entries: 5 };
    await page.reload();
    await expect(row.getByTestId('list-redundant')).toContainText('Every name in it is also in e2e-shadow');
    await row.getByTestId('list-turn-off').click();
    await expect(page.getByTestId('list-fix-note')).toContainText('e2e-block is off');
    expect(redundantChanges[0]).toMatchObject({ enabled: false });
  } finally {
    await page.unroute('**/api/v1/lists');
    await page.unroute(/\/api\/v1\/lists\/e2e-block$/);
    await page.goto('/#/lists');
  }
});

test('api_002 upstreams and lists can be added, overridden, and reverted', async () => {
  const r = page.request;
  const csrf = (await (await r.get('/api/v1/auth/status')).json()).csrfToken as string;
  const h = { 'x-csrf-token': csrf };
  const overrides = async () =>
    ((await (await r.get('/api/v1/config/entries')).json()).items as { kind: string; name: string; source: string }[])
      .filter((o) => o.source !== 'file')
      .map((o) => `${o.kind}:${o.name}:${o.source}`)
      .sort();
  // A dry run changes nothing.
  let res = await r.put('/api/v1/upstreams/extra?dryRun=true', { headers: h, data: { url: 'udp://127.0.0.1:9' } });
  expect(res.status()).toBe(200);
  expect((await res.json()).applied).toBe(false);
  expect(await overrides()).toEqual([]);
  // Added, and an override of the files' "router".
  expect((await r.put('/api/v1/upstreams/extra', { headers: h, data: { url: 'udp://127.0.0.1:9' } })).status()).toBe(200);
  res = await r.put('/api/v1/upstreams/router', { headers: h, data: { url: `udp://127.0.0.1:${PORTS.upstream}`, timeout_ms: 900 } });
  expect(res.status()).toBe(200);
  expect(await overrides()).toEqual(['upstream:extra:added', 'upstream:router:override']);
  // Hiding the only upstream of the default group is refused, and says what to do.
  res = await r.delete('/api/v1/upstreams/nowhere', { headers: h });
  expect(res.status()).toBe(422);
  expect(JSON.stringify(await res.json())).toContain('only upstream in upstream group');
  // REQ: API-002 (T9.22) — removing an upstream a group shares takes it out of the group too.
  expect((await r.put('/api/v1/upstream-groups/router', { headers: h, data: { members: ['router', 'extra'] } })).status()).toBe(200);
  res = await r.delete('/api/v1/upstreams/extra?dryRun=true', { headers: h });
  expect(res.status()).toBe(200);
  expect((await res.json()).impact).toContain('upstream group `router`');
  expect((await r.delete('/api/v1/upstreams/extra', { headers: h })).status()).toBe(200);
  const groups = (await (await r.get('/api/v1/config/entries')).json()).items as { kind: string; name: string; definition: { members?: string[] } }[];
  expect(groups.find((g) => g.kind === 'upstream_group' && g.name === 'router')?.definition.members).toEqual(['router']);
  // Revert the overrides.
  expect((await r.delete('/api/v1/upstream-groups/router', { headers: h })).status()).toBe(200);
  expect((await r.delete('/api/v1/upstreams/router', { headers: h })).status()).toBe(200);
  expect(await overrides()).toEqual([]);
  // A list: added, then removed.
  res = await r.put('/api/v1/lists/e2e-extra', { headers: h, data: { rules: ['||extra.e2e.test^'] } });
  expect(res.status()).toBe(200);
  expect(await overrides()).toEqual(['list:e2e-extra:added']);
  expect((await r.delete('/api/v1/lists/e2e-extra', { headers: h })).status()).toBe(200);
  expect(await overrides()).toEqual([]);
});

// REQ: AGT-012 (T8.6) — the Analyze page runs vqlog: a top list linked to the query log, a cost
// estimate without scanning, and a mistake shown with its hint.
test('agt_012 analyze page', async () => {
  for (let i = 0; i < 3; i++) await query('ads.e2e.test').catch(() => -1);
  await page.goto('/#/analyze?q=' + encodeURIComponent('from -1h | where status = blocked | top 5 name'));
  const result = page.getByTestId('vqlog-result');
  await expect(async () => {
    await page.getByRole('button', { name: 'Run' }).click();
    await expect(result.getByRole('link', { name: 'ads.e2e.test', exact: true })).toBeVisible({ timeout: 2000 });
  }).toPass({ timeout: 20_000 });
  await expect(result).toContainText('As understood: from -1h | where status = blocked | by name | stats count');
  await expect(page.getByTestId('vqlog-cost')).toContainText('Matched');
  await page.getByRole('button', { name: 'Estimate cost' }).click();
  await expect(page.getByTestId('vqlog-cost')).toContainText('Estimate: up to');
  await page.getByLabel('vqlog query').fill('top 5 colour');
  await page.getByLabel('vqlog query').press('Control+Enter');
  await expect(page.getByRole('alert')).toContainText('unknown key');
  await expect(page.getByRole('alert')).toContainText('Keys: name, domain');
  // The browser logs that 400; it's the expected answer to the typo, not a page problem.
  for (let i = problems.length - 1; i >= 0; i--) if (problems[i].includes('status of 400')) problems.splice(i, 1);
  // An example chip fills the box and runs it.
  await page.getByRole('button', { name: 'Queries per hour, with latency' }).click();
  // The query reads the log and groups it: seconds on a busy machine.
  await expect(result.locator('thead')).toContainText('p95(latency)', { timeout: 30_000 });
});

// REQ: T8.3, API-010 (T8.6) — a device found over mDNS shows under Discovered and its name is
// suggested when naming it; groups show answer settings; zones are listed.
test('t8_6 discovered devices, group settings, and zones', async () => {
  const { createSocket } = await import('node:dgram');
  const label = (s: string) => [Buffer.from([s.length]), Buffer.from(s)];
  const msg = Buffer.concat([
    Buffer.from([0, 0, 0x84, 0, 0, 0, 0, 1, 0, 0, 0, 0]),
    ...label('printer-e2e'),
    ...label('local'),
    Buffer.from([0, 0, 1, 0x80, 1, 0, 0, 0, 120, 0, 4, 127, 0, 0, 9]),
  ]);
  const sock = createSocket('udp4');
  await new Promise<void>((done) => sock.send(msg, MDNS_PORT, '127.0.0.1', () => done()));
  sock.close();
  await page.goto('/#/clients?tab=discovered');
  const found = page.getByTestId('discovered');
  await expect(async () => {
    await page.reload();
    await expect(found.locator('tbody tr', { hasText: 'printer-e2e' })).toBeVisible({ timeout: 2000 });
  }).toPass({ timeout: 20_000 });
  const row = found.locator('tbody tr', { hasText: 'printer-e2e' });
  await expect(row).toContainText('mDNS');
  await expect(row).toContainText('not named yet');
  await row.getByRole('button', { name: '127.0.0.9' }).click();
  await row.getByRole('menuitem', { name: 'Name this device…' }).click();
  await expect(page.getByLabel('Name', { exact: true })).toHaveValue('printer-e2e');
  await page.keyboard.press('Escape');

  await page.goto('/#/groups');
  const card = page.getByTestId('group-card').filter({ hasText: 'ipv6only' });
  await expect(card.getByTestId('group-dns64')).toContainText('DNS64 on (64:ff9b::/96)');
  await expect(card.getByTestId('group-rewrites')).toContainText('tv.e2e.test → 192.168.1.30');
  await expect(card.getByTestId('group-answers')).toContainText('Rebinding protection on; blocks answers in 203.0.113.0/24');

  await page.goto('/#/local-dns');
  const zones = page.getByTestId('zones');
  await expect(zones.locator('tbody tr', { hasText: 'zone.e2e.test' })).toContainText('ipv6only');
});

// REQ: OBS-010 (T9.6) — the Alerts page: add a destination, send it a test, add a rule that
// fires, see it under "Now" with the delivery, then remove both.
test('obs_010 alerts page: destinations, test, rules', async () => {
  test.setTimeout(120_000); // the rule fires on the next 5 s check
  const { createServer } = await import('node:http');
  const got: string[] = [];
  const hook = createServer((req, res) => {
    let b = '';
    req.on('data', (c) => (b += c));
    req.on('end', () => {
      got.push(b);
      res.end('ok');
    });
  });
  await new Promise<void>((r) => hook.listen(PORTS.webhook, '127.0.0.1', () => r()));
  try {
    await page.setViewportSize({ width: 1280, height: 800 });
    await page.goto('/#/alerts');
    await expect(page.locator('h1', { hasText: 'Alerts' })).toBeVisible();
    // Advanced: the rule's threshold.
    await page.getByRole('button', { name: 'Advanced', exact: true }).click();
    const dests = page.getByTestId('editor-alert_destination');
    await dests.getByRole('button', { name: 'Add destination' }).click();
    await page.getByRole('textbox', { name: 'Name', exact: true }).fill('ui-hook');
    await page.getByLabel('Type', { exact: true }).selectOption('webhook');
    await page.getByRole('textbox', { name: 'Address', exact: true }).fill(`http://127.0.0.1:${PORTS.webhook}/alert`);
    await page.getByRole('button', { name: 'Check' }).click();
    await expect(page.getByTestId('entry-preview')).toBeVisible();
    await page.getByRole('button', { name: 'Apply' }).click();
    const row = dests.getByTestId('entry-row').filter({ hasText: 'ui-hook' });
    await expect(row).toContainText(`webhook: http://127.0.0.1:${PORTS.webhook}/alert`);
    await row.getByRole('button', { name: 'Send test' }).click();
    await expect(dests.getByTestId('row-action-result')).toContainText('sent');
    expect(got.some((b) => b.includes('This is a test alert'))).toBe(true);

    const rules = page.getByTestId('editor-alert_rule');
    await rules.getByRole('button', { name: 'Add rule' }).click();
    await page.getByRole('textbox', { name: 'Name', exact: true }).fill('ui-disk');
    await page.getByLabel('When', { exact: true }).selectOption('disk_full');
    // exact: the config file's destination (file-ntfy) is listed too, and its name contains no ui-hook.
    await pick(page.locator('body'), 'Send to', 'ui-hook');
    await page.getByRole('spinbutton', { name: 'For at least (seconds)' }).fill('0');
    await page.getByRole('spinbutton', { name: 'Threshold' }).fill('0.1');
    await page.getByRole('button', { name: 'Check' }).click();
    await page.getByRole('button', { name: 'Apply' }).click();
    await expect(rules.getByTestId('entry-row').filter({ hasText: 'ui-disk' })).toContainText('disk_full → ui-hook');
    const now = page.getByTestId('alerts-now');
    await expect(async () => {
      await page.reload();
      await expect(now).toContainText('ui-disk', { timeout: 2000 });
      await expect(now).toContainText('delivered', { timeout: 2000 });
    }).toPass({ timeout: 45_000 });
    expect(got.some((b) => b.includes('"rule":"ui-disk"'))).toBe(true);

    await rules.getByTestId('entry-row').filter({ hasText: 'ui-disk' }).getByRole('button', { name: 'Remove' }).click();
    await expect(rules.getByTestId('entry-row').filter({ hasText: 'ui-disk' })).toHaveCount(0);
    await row.getByRole('button', { name: 'Remove' }).click();
    await expect(row).toHaveCount(0);
  } finally {
    await page.getByRole('button', { name: 'Simple', exact: true }).click({ timeout: 2000 }).catch(() => {});
    hook.close();
  }
});

// REQ: OBS-010 (T27.1) — every condition the server accepts can be chosen in the Alerts form: a rule
// of each of the seven added by T27.1 is added, read back after a reload, and removed.
test('obs_010 every alert condition can be chosen', async () => {
  test.setTimeout(240_000); // seven rules, each checked and applied, then read back after a reload
  const kinds = ['slo_burn', 'probe_failing', 'cert_expiring', 'rollout_failed', 'cluster_pinned', 'chatty_loop', 'drill_report'];
  const nameOf = (kind: string) => `ui-${kind.replace(/_/g, '-')}`;
  await page.setViewportSize({ width: 1280, height: 800 });
  await page.goto('/#/alerts');
  await expect(page.locator('h1', { hasText: 'Alerts' })).toBeVisible();
  const rules = page.getByTestId('editor-alert_rule');
  try {
    for (const kind of kinds) {
      await rules.getByRole('button', { name: 'Add rule' }).click();
      if (kind === kinds[0]) {
        // Every condition the server accepts is offered, not only the seven added here.
        const offered = await page.getByLabel('When', { exact: true }).locator('option').evaluateAll((os) => os.map((o) => (o as HTMLOptionElement).value).filter(Boolean));
        expect(offered.sort()).toEqual([...alertConditions].sort());
      }
      await page.getByRole('textbox', { name: 'Name', exact: true }).fill(nameOf(kind));
      await page.getByLabel('When', { exact: true }).selectOption(kind);
      // The config file's destination (file-ntfy) is the one every rule here sends to; its checkbox is
      // named "Send to file-ntfy", so match the name by part.
      await pick(page.locator('body'), 'Send to', /file-ntfy/);
      await page.getByRole('button', { name: 'Check' }).click();
      await page.getByRole('button', { name: 'Apply' }).click();
      await expect(rules.getByTestId('entry-row').filter({ hasText: nameOf(kind) })).toContainText(`${kind} → file-ntfy`);
    }
    await page.reload();
    for (const kind of kinds) {
      await expect(rules.getByTestId('entry-row').filter({ hasText: nameOf(kind) })).toContainText(`${kind} → file-ntfy`);
    }
  } finally {
    for (const kind of kinds) {
      const row = rules.getByTestId('entry-row').filter({ hasText: nameOf(kind) });
      if ((await row.count()) > 0) {
        await row.getByRole('button', { name: 'Remove' }).click();
        await expect(row).toHaveCount(0);
      }
    }
  }
});

// REQ: OBS-010 (T27.1, T24.5) — the threshold field is shown only for the four conditions that read it,
// and the server refuses an out-of-range value at Check (cert_expiring takes days from 1 to 365).
test('obs_010 threshold shown per condition and out-of-range refused', async () => {
  test.setTimeout(120_000);
  await page.setViewportSize({ width: 1280, height: 800 });
  await page.goto('/#/alerts');
  await expect(page.locator('h1', { hasText: 'Alerts' })).toBeVisible();
  await page.getByRole('button', { name: 'Advanced', exact: true }).click();
  try {
    const rules = page.getByTestId('editor-alert_rule');
    await rules.getByRole('button', { name: 'Add rule' }).click();
    await page.getByRole('textbox', { name: 'Name', exact: true }).fill('ui-range');
    await page.getByLabel('When', { exact: true }).selectOption('slo_burn');
    await expect(page.getByRole('spinbutton', { name: 'Threshold' })).toHaveCount(0);
    await page.getByLabel('When', { exact: true }).selectOption('cert_expiring');
    await expect(page.getByRole('spinbutton', { name: 'Threshold' })).toBeVisible();
    await pick(page.locator('body'), 'Send to', /file-ntfy/);
    await page.getByRole('spinbutton', { name: 'Threshold' }).fill('0');
    await page.getByRole('button', { name: 'Check' }).click();
    await expect(page.getByText('days from 1 to 365')).toBeVisible();
    // The other two ranges: seconds for primary_unreachable (15 to 86400), a percentage for servfail_rate (0 to 100).
    const refused: [string, string, string][] = [
      ['primary_unreachable', '14', 'seconds from 15 to 86400'],
      ['primary_unreachable', '86401', 'seconds from 15 to 86400'],
      ['servfail_rate', '101', 'a percentage from 0 to 100'],
    ];
    for (const [when, value, message] of refused) {
      await page.getByLabel('When', { exact: true }).selectOption(when);
      await page.getByRole('spinbutton', { name: 'Threshold' }).fill(value);
      await page.getByRole('button', { name: 'Check' }).click();
      await expect(page.getByText(message)).toBeVisible();
      // Each refused Check logs its 422; the test expects it.
      for (let i = problems.length - 1; i >= 0; i--) if (/status of 422 \(/.test(problems[i])) problems.splice(i, 1);
    }
    await expect(rules.getByTestId('entry-row').filter({ hasText: 'ui-range' })).toHaveCount(0);
  } finally {
    await page.reload();
    await page.getByRole('button', { name: 'Simple', exact: true }).click({ timeout: 2000 }).catch(() => {});
  }
});

// REQ: API-014 (T23.2) — the Alerts page shows an operator the fields only an admin changes
// read-only: a destination's token and password files always, and its address and CA once it
// holds a credential; the server refuses them anyway.
test('api_014 alerts page: operators see credential fields read-only', async () => {
  await page.setViewportSize({ width: 1280, height: 800 });
  const r = page.request;
  const csrf = (await (await r.get('/api/v1/auth/status')).json()).csrfToken as string;
  const h = { 'x-csrf-token': csrf };
  const OPERATOR = { user: 'operator1', pass: 'operator long password' };
  const made = await r.post('/api/v1/users', { headers: h, data: { username: OPERATOR.user, password: OPERATOR.pass, role: 'operator' } });
  expect([200, 201, 409]).toContain(made.status());
  const put = await r.put('/api/v1/alerts/destinations/ui-ntfy', {
    headers: h,
    data: { type: 'ntfy', url: 'https://ntfy.e2e.test/topic', token_file: '/run/secrets/ntfy-token' },
  });
  expect(put.status(), await put.text()).toBe(200);
  const op = await page.context().browser()!.newContext({ baseURL: page.url().split('/#')[0] });
  try {
    const p = await op.newPage();
    await p.goto('/#/alerts');
    await p.getByLabel('Username', { exact: true }).fill(OPERATOR.user);
    await p.getByLabel('Password', { exact: true }).fill(OPERATOR.pass);
    await p.getByRole('button', { name: 'Sign in' }).click();
    await expect(p.locator('h1', { hasText: 'Alerts' })).toBeVisible({ timeout: 30_000 });
    await p.getByRole('button', { name: 'Advanced', exact: true }).click();
    const dests = p.getByTestId('editor-alert_destination');
    await dests.getByTestId('entry-row').filter({ hasText: 'ui-ntfy' }).getByRole('button', { name: 'Edit' }).click();
    // REQ: API-015 (T23.6) — the token and password are secret fields: an operator sees no input.
    await expect(p.getByTestId('secret-token_ref').getByRole('textbox')).toHaveCount(0);
    await expect(p.getByTestId('secret-password_ref').getByRole('textbox')).toHaveCount(0);
    await expect(p.getByTestId('secret-token_ref')).toContainText('Only an admin can set a stored secret.');
    await expect(p.getByRole('textbox', { name: 'Address', exact: true })).toHaveAttribute('readonly', '');
    await expect(p.getByRole('textbox', { name: 'Private CA (email)' })).toHaveAttribute('readonly', '');
    await expect(p.getByRole('textbox', { name: 'From (email)' })).not.toHaveAttribute('readonly', '');
    await expect(p.getByTestId('admin-only').first()).toContainText('Only an admin can change this.');
    // A new destination: its files are still an admin's, its address the operator's. The
    // drawer of the entry above is still open (a hash change doesn't reload), so reload first.
    await p.reload();
    await p.getByTestId('editor-alert_destination').getByRole('button', { name: 'Add destination' }).click();
    await expect(p.getByTestId('secret-token_ref').getByRole('textbox')).toHaveCount(0);
    await expect(p.getByRole('textbox', { name: 'Address', exact: true })).not.toHaveAttribute('readonly', '');
    // And the server says no whatever the form does.
    const ocsrf = (await (await op.request.get('/api/v1/auth/status')).json()).csrfToken as string;
    const moved = await op.request.put('/api/v1/alerts/destinations/ui-ntfy', {
      headers: { 'x-csrf-token': ocsrf },
      data: { type: 'ntfy', url: 'https://elsewhere.e2e.test/topic', token_file: '/run/secrets/ntfy-token' },
    });
    expect(moved.status()).toBe(403);
    await p.getByRole('button', { name: 'Simple', exact: true }).click({ timeout: 5_000 }).catch(() => {});
  } finally {
    await op.close();
    await r.delete('/api/v1/alerts/destinations/ui-ntfy', { headers: h });
  }
});

// A test that expects a refusal (a 4xx or 5xx the form shows) removes the browser's note of it, as the
// suite's other refusal tests do.
function forgetRefusals() {
  for (let i = problems.length - 1; i >= 0; i--) if (/status of [45]\d\d \(/.test(problems[i])) problems.splice(i, 1);
}

// REQ: API-014 (T24.16, ADR-926) — the credential rules in every form. An operator sees the fields only an
// admin changes read-only (with the reason), a credential kept on the node says so, and a change the
// server refuses for a kept credential says which one to enter again.
async function operatorPage(user: string, pass: string, role: 'operator' | 'viewer' = 'operator') {
  const r = page.request;
  const csrf = (await (await r.get('/api/v1/auth/status')).json()).csrfToken as string;
  const made = await r.post('/api/v1/users', { headers: { 'x-csrf-token': csrf }, data: { username: user, password: pass, role } });
  expect([200, 201, 409]).toContain(made.status());
  const ctx = await page.context().browser()!.newContext({ baseURL: page.url().split('/#/')[0] });
  const p = await ctx.newPage();
  await p.goto('/#/');
  await p.getByLabel('Username', { exact: true }).fill(user);
  await p.getByLabel('Password', { exact: true }).fill(pass);
  await p.getByRole('button', { name: 'Sign in' }).click();
  return { p, close: () => ctx.close() };
}

test('api_014 upstream url is admin-only when it holds a credential', async () => {
  const r = page.request;
  const h = { 'x-csrf-token': await csrfOf(r) };
  const put = await r.put('/api/v1/upstreams/ui-cred-up', { headers: h, data: { url: 'https://dns.e2e.test/dns-query', headers: { Authorization: 'Bearer cred-5521' } } });
  expect(put.status(), await put.text()).toBe(200);
  const op = await operatorPage('operator1', 'operator long password');
  try {
    await op.p.goto('/#/upstreams');
    await op.p.getByTestId('view-advanced').click(); // T24.36: the editors are in the Advanced view
    await op.p.getByRole('button', { name: 'Advanced', exact: true }).click();
    const row = op.p.getByTestId('editor-upstream').getByTestId('entry-row').filter({ hasText: 'ui-cred-up' });
    await expect(row.getByTestId('kept-badge')).toHaveText('kept: re-enter to change', { timeout: 20_000 });
    // The value itself never reaches the page.
    await expect(op.p.locator('body')).not.toContainText('cred-5521');
    await row.getByRole('button', { name: 'Edit' }).click();
    await expect(op.p.getByRole('textbox', { name: 'Address', exact: true })).toHaveAttribute('readonly', '');
    await expect(op.p.getByTestId('admin-only').first()).toContainText('Only an admin can change this.');
    // REQ: API-014 (T24.16, ADR-926 §2) — the TLS server name is an admin's too while the entry keeps a credential.
    await expect(op.p.getByRole('textbox', { name: 'TLS server name', exact: true })).toHaveAttribute('readonly', '');
  } finally {
    await op.close();
    await r.delete('/api/v1/upstreams/ui-cred-up', { headers: h });
  }
});

// REQ: API-014 (T24.16, ADR-926 §2) — a credential file on an upstream keeps a credential as much as a
// header does: its address and TLS name are an admin's (the server's holds_credential). A PUT needs a
// real cert and key pair, so the entry is added to the list the operator's page reads instead.
test('api_014 a credential file on an upstream holds its address too', async () => {
  const op = await operatorPage('operator1', 'operator long password');
  try {
    await op.p.route((url) => url.pathname.endsWith('/api/v1/config/entries') && url.searchParams.get('kind') === 'upstream', async (route) => {
      const res = await route.fetch();
      const body = await res.json();
      const proto = body.items?.[0] ?? {};
      body.items = [...(body.items ?? []), { ...proto, name: 'ui-keyfile-up', kind: 'upstream', definition: { url: 'https://dns.e2e.test/dns-query', tls_client_key: '/run/secrets/ui-up-key' }, redacted: [] }];
      await route.fulfill({ response: res, json: body });
    });
    await op.p.goto('/#/upstreams');
    await op.p.getByTestId('view-advanced').click(); // T24.36: the editors are in the Advanced view
    await op.p.getByRole('button', { name: 'Advanced', exact: true }).click();
    const row = op.p.getByTestId('editor-upstream').getByTestId('entry-row').filter({ hasText: 'ui-keyfile-up' });
    await row.getByRole('button', { name: 'Edit' }).click();
    await expect(op.p.getByRole('textbox', { name: 'Address', exact: true })).toHaveAttribute('readonly', '');
    await expect(op.p.getByRole('textbox', { name: 'TLS server name', exact: true })).toHaveAttribute('readonly', '');
  } finally {
    await op.close();
  }
});

// REQ: API-014 (T24.16, ADR-926 §1) — a new draft that switches to a program address is held for an operator.
test('api_014 upstream exec draft is held for an operator', async () => {
  const op = await operatorPage('operator1', 'operator long password');
  try {
    await op.p.goto('/#/upstreams');
    await op.p.getByTestId('view-advanced').click(); // T24.36: the editors are in the Advanced view
    await op.p.getByRole('button', { name: 'Add upstream', exact: true }).click();
    await op.p.getByRole('textbox', { name: 'Name', exact: true }).fill('ui-exec-draft');
    await op.p.getByRole('textbox', { name: 'Address', exact: true }).fill('exec:///usr/bin/true');
    await expect(op.p.getByTestId('admin-only-draft')).toContainText('Only an admin can set an address that runs a program');
    await expect(op.p.getByRole('button', { name: 'Check', exact: true })).toBeDisabled();
    await op.p.getByRole('textbox', { name: 'Address', exact: true }).fill('10.0.0.53');
    await expect(op.p.getByTestId('admin-only-draft')).toHaveCount(0);
  } finally {
    await op.close();
  }
});

// REQ: API-014 (T24.16, ADR-926 §1) — a saved program address that an operator only re-times is not held:
// the server allows it (only a switch to a program, or its arguments, is an admin's).
test('api_014 operator re-times a saved program upstream', async () => {
  const r = page.request;
  const h = { 'x-csrf-token': await csrfOf(r) };
  const put = await r.put('/api/v1/upstreams/ui-exec-up', { headers: h, data: { url: 'exec:///usr/bin/true' } });
  expect(put.status(), await put.text()).toBe(200);
  const op = await operatorPage('operator1', 'operator long password');
  try {
    await op.p.goto('/#/upstreams');
    await op.p.getByTestId('view-advanced').click(); // T24.36: the editors are in the Advanced view
    await op.p.getByRole('button', { name: 'Advanced', exact: true }).click();
    const row = op.p.getByTestId('editor-upstream').getByTestId('entry-row').filter({ hasText: 'ui-exec-up' });
    await row.getByRole('button', { name: 'Edit' }).click();
    await expect(op.p.getByRole('textbox', { name: 'Address', exact: true })).toHaveAttribute('readonly', '');
    await expect(op.p.getByTestId('admin-only-draft')).toHaveCount(0);
    await op.p.getByRole('spinbutton', { name: 'Timeout (ms)', exact: true }).fill('3000');
    await expect(op.p.getByTestId('admin-only-draft')).toHaveCount(0);
    await op.p.getByRole('button', { name: 'Check', exact: true }).click();
    await expect(op.p.getByRole('button', { name: 'Apply', exact: true })).toBeEnabled({ timeout: 15_000 });
    await op.p.getByRole('button', { name: 'Apply', exact: true }).click();
    await expect.poll(async () => {
      const items = (await (await r.get('/api/v1/config/entries?kind=upstream')).json()).items as { name: string; definition?: { timeout_ms?: number } }[];
      return items.find((e) => e.name === 'ui-exec-up')?.definition?.timeout_ms;
    }, { timeout: 15_000 }).toBe(3000);
  } finally {
    await op.close();
    await r.delete('/api/v1/upstreams/ui-exec-up', { headers: h });
  }
});

// REQ: API-014, API-015 (T24.16) — a viewer sees the kept credentials, and no control that changes them.
test('api_014 a viewer sees credential entries and changes nothing', async () => {
  const r = page.request;
  const h = { 'x-csrf-token': await csrfOf(r) };
  const put = await r.put('/api/v1/upstreams/ui-view-up', { headers: h, data: { url: 'https://dns.e2e.test/dns-query', headers: { Authorization: 'Bearer view-7733' } } });
  expect(put.status(), await put.text()).toBe(200);
  const v = await operatorPage(VIEWER.user, VIEWER.pass, 'viewer');
  try {
    await v.p.goto('/#/upstreams');
    await v.p.getByTestId('view-advanced').click(); // T24.36: the editors are in the Advanced view
    const editor = v.p.getByTestId('editor-upstream');
    const row = editor.getByTestId('entry-row').filter({ hasText: 'ui-view-up' });
    await expect(row.getByTestId('kept-badge')).toBeVisible({ timeout: 20_000 });
    await expect(row.getByRole('button', { name: 'Edit' })).toHaveCount(0);
    await expect(editor.getByRole('button', { name: 'Add upstream', exact: true })).toHaveCount(0);
    await expect(v.p.locator('body')).not.toContainText('view-7733');
  } finally {
    await v.close();
    await r.delete('/api/v1/upstreams/ui-view-up', { headers: h });
  }
});

test('api_014 alert type is admin-only when it holds a credential', async () => {
  const r = page.request;
  const h = { 'x-csrf-token': await csrfOf(r) };
  const put = await r.put('/api/v1/alerts/destinations/ui-type-cred', {
    headers: h,
    data: { type: 'ntfy', url: 'https://ntfy.e2e.test/topic', token_file: '/run/secrets/ntfy-token' },
  });
  expect(put.status(), await put.text()).toBe(200);
  const op = await operatorPage('operator1', 'operator long password');
  try {
    await op.p.goto('/#/alerts');
    await op.p.getByRole('button', { name: 'Advanced', exact: true }).click();
    const row = op.p.getByTestId('editor-alert_destination').getByTestId('entry-row').filter({ hasText: 'ui-type-cred' });
    await row.getByRole('button', { name: 'Edit' }).click();
    await expect(op.p.getByLabel('Type', { exact: true })).toBeDisabled();
    await expect(op.p.getByTestId('admin-only').first()).toBeVisible();
  } finally {
    await op.close();
    await r.delete('/api/v1/alerts/destinations/ui-type-cred', { headers: h });
  }
});

test("api_014 changing a header upstream's url says which credential to re-enter", async () => {
  const r = page.request;
  const h = { 'x-csrf-token': await csrfOf(r) };
  const put = await r.put('/api/v1/upstreams/ui-hdr-up', { headers: h, data: { url: 'https://dns.e2e.test/dns-query', headers: { Authorization: 'Bearer hdr-6612' } } });
  expect(put.status(), await put.text()).toBe(200);
  try {
    await page.goto('/#/upstreams');
    await page.getByTestId('view-advanced').click(); // T24.36: the editors are in the Advanced view
    const row = page.getByTestId('editor-upstream').getByTestId('entry-row').filter({ hasText: 'ui-hdr-up' });
    await row.getByRole('button', { name: 'Edit' }).click();
    await page.getByRole('textbox', { name: 'Address', exact: true }).fill('https://other.e2e.test/dns-query');
    await page.getByRole('button', { name: 'Check', exact: true }).click();
    const alert = page.getByRole('alert').filter({ hasText: "isn't kept" });
    await expect(alert).toContainText('headers.Authorization');
    await expect(alert).toContainText('wrendns ctl');
    await expect(alert).not.toContainText('credential_reentry_required');
  } finally {
    forgetRefusals();
    await r.delete('/api/v1/upstreams/ui-hdr-up', { headers: h });
    // The drawer stays open after a refusal: reload, so it doesn't cover the next test's page.
    await page.reload();
  }
});

test('api_014 forward to exec is admin-only', async () => {
  const r = page.request;
  const csrf = await csrfOf(r);
  await r.post('/api/v1/users', { headers: { 'x-csrf-token': csrf }, data: { username: 'operator1', password: 'operator long password', role: 'operator' } });
  const op = await operatorPage('operator1', 'operator long password');
  try {
    await op.p.goto('/#/local-dns');
    await op.p.getByRole('button', { name: 'Send a domain to another server', exact: true }).click();
    await op.p.getByLabel('Domain', { exact: true }).fill('lab.e2e.test');
    await op.p.getByLabel('Server address', { exact: true }).fill('exec:///usr/bin/true');
    await expect(op.p.getByTestId('admin-only-forward')).toContainText('Only an admin can send names to a program');
    await expect(op.p.getByRole('button', { name: 'Save', exact: true })).toBeDisabled();
    await op.p.getByLabel('Server address', { exact: true }).fill('10.0.0.53');
    await expect(op.p.getByTestId('admin-only-forward')).toHaveCount(0);
  } finally {
    await op.close();
  }
});

// REQ: API-015, API-014 (T24.16, ADR-926) — each problem code a form can meet reads as a sentence: the
// code is mocked, the Check shows what it means, and the code's own name is not shown.
test('api_015 errors read as sentences', async () => {
  await page.setViewportSize({ width: 1280, height: 800 });
  const cases: [number, string, string, RegExp][] = [
    [422, 'path_not_allowed', '`token_file`: under /proc, which WrenDNS never reads', /can't be used/],
    [409, 'set_by_file', '`url` is set by the configuration file', /The configuration file sets/],
    [422, 'credential_reentry_required', '`headers.Authorization` is `<redacted>`, and there is no stored value to keep', /has no value to keep\. This form can't enter it: change it with wrendns ctl/],
    // The destination changed: the field is named, the marker is not, and the form can enter it.
    [422, 'credential_reentry_required', '`url` is `<redacted>`, and `tls_server_name` changed: a credential isn\'t sent to a new destination without being entered again', /The stored credential `url` isn't kept, because this entry now points somewhere else\. Enter it again on this form/],
    [422, 'credential_reentry_required', '`password` is `<redacted>`, and there is no stored value to keep', /The stored credential `password` has no value to keep\. Enter it again on this form/],
    [409, 'upgrade_required', 'a newer primary is needed', /too old/],
    [422, 'secret_missing', '`token_ref` names no stored secret', /doesn't store/],
    [409, 'secret_in_use', "`alert.ui-used.token` is used by alert ui-used", /still in use/],
    [503, 'secrets_locked', 'the secrets key is missing', /can't be read, so/],
    [403, 'insecure_transport', 'a secret needs HTTPS', /over HTTPS/],
    [409, 'lists_not_here', 'this node is a resolver', /doesn't download lists/],
  ];
  let current = cases[0];
  await page.route('**/api/v1/upstreams/ui-err-up*', (route) => {
    const [status, code, detail] = current;
    return route.fulfill({ status, json: { status, code, title: code, detail } });
  });
  try {
    await page.goto('/#/upstreams');
    await page.getByTestId('view-advanced').click(); // T24.36: the editors are in the Advanced view
    await page.reload();
    await page.getByRole('button', { name: 'Add upstream', exact: true }).click();
    await page.getByRole('textbox', { name: 'Name', exact: true }).fill('ui-err-up');
    await page.getByRole('textbox', { name: 'Address', exact: true }).fill('https://err.e2e.test/dns-query');
    for (const c of cases) {
      current = c;
      await page.getByRole('button', { name: 'Check', exact: true }).click();
      const alert = page.getByRole('alert').filter({ hasText: c[3] });
      await expect(alert, c[1]).toBeVisible();
      await expect(alert, c[1]).not.toContainText(c[1]);
    }
    // "Test it" runs a check, which never uses a stored value: its refusal reads as a sentence in the
    // result line (ADR-927 §3), with the server's own wording kept on the error.
    await page.route('**/api/v1/checks/upstream', (route) =>
      route.fulfill({
        status: 422,
        json: { status: 422, code: 'credential_reentry_required', title: 'credential_reentry_required', detail: 'the draft sends `<redacted>` for a credential, and a check never uses stored values' },
      }),
    );
    await page.getByRole('button', { name: 'Test it', exact: true }).click();
    await expect(page.getByTestId('form-action-result')).toContainText("A check can't use a stored credential");
    await expect(page.getByTestId('form-action-result')).not.toContainText('<redacted>');
  } finally {
    forgetRefusals();
    await page.unroute('**/api/v1/checks/upstream');
    await page.unroute('**/api/v1/upstreams/ui-err-up*');
    await page.reload();
  }
});

// Every answer the page gets while `run` executes; none may carry the secret (the network, not just the DOM).
async function noAnswerCarries(secret: string, run: () => Promise<void>) {
  const bodies: Promise<string>[] = [];
  const on = (r: import('@playwright/test').Response) => {
    if (r.url().includes('/api/v1/')) bodies.push(r.text().catch(() => ''));
  };
  page.on('response', on);
  try {
    await run();
  } finally {
    page.off('response', on);
  }
  for (const b of await Promise.all(bodies)) expect(b).not.toContain(secret);
}

// REQ: API-015, API-014 (T23.6, ADR-903 §9) — stored secrets from the UI: the field is write-only,
// a file the configuration sets is read-only, replace and clear work, an operator sees status only,
// a plain-HTTP refusal is explained, a locked store links to the secrets tab, and a stored token is
// what an alert sends.
async function csrfOf(r: import('@playwright/test').APIRequestContext) {
  return (await (await r.get('/api/v1/auth/status')).json()).csrfToken as string;
}

test('api_015 secret field is write-only', async () => {
  await page.setViewportSize({ width: 1280, height: 800 });
  await page.goto('/#/alerts');
  await page.getByRole('button', { name: 'Advanced', exact: true }).click();
  const dests = page.getByTestId('editor-alert_destination');
  await dests.getByRole('button', { name: 'Add destination' }).click();
  await page.getByRole('textbox', { name: 'Name', exact: true }).fill('ui-stored');
  await page.getByLabel('Type', { exact: true }).selectOption('ntfy');
  await page.getByRole('textbox', { name: 'Address', exact: true }).fill(`http://127.0.0.1:${PORTS.ntfy}/stored`);
  const field = page.getByTestId('secret-token_ref');
  await expect(field).toHaveAttribute('data-mode', 'unset');
  await expect(field.getByRole('button', { name: 'Save secret' })).toBeDisabled();
  await field.getByLabel('Token (ntfy, Gotify, Pushover app)', { exact: true }).fill('write-only-token-7731');
  await noAnswerCarries('write-only-token-7731', async () => {
    await field.getByRole('button', { name: 'Save secret' }).click();
    await expect(field).toHaveAttribute('data-mode', 'set');
  });
  await expect(field.getByTestId('secret-status')).toContainText('alert.ui-stored.token');
  // Never pre-filled, and never in the page after the save.
  await expect(field.getByLabel('Token (ntfy, Gotify, Pushover app)', { exact: true })).toHaveCount(0);
  expect(await page.content()).not.toContain('write-only-token-7731');
  await page.getByRole('button', { name: 'Check' }).click();
  await page.getByRole('button', { name: 'Apply' }).click();
  await expect(dests.getByTestId('entry-row').filter({ hasText: 'ui-stored' })).toContainText('ntfy');
});

test('api_015 replace and clear', async () => {
  const dests = page.getByTestId('editor-alert_destination');
  await dests.getByTestId('entry-row').filter({ hasText: 'ui-stored' }).getByRole('button', { name: 'Edit' }).click();
  const field = page.getByTestId('secret-token_ref');
  await expect(field).toHaveAttribute('data-mode', 'set');
  await field.getByRole('button', { name: 'Replace' }).click();
  await field.getByLabel('Token (ntfy, Gotify, Pushover app)', { exact: true }).fill('replaced-token-9914');
  await noAnswerCarries('replaced-token-9914', async () => {
    await field.getByRole('button', { name: 'Save new value' }).click();
    await expect(field).toHaveAttribute('data-mode', 'set');
  });
  expect(await page.content()).not.toContain('replaced-token-9914');
  await field.getByRole('button', { name: 'Clear' }).click();
  await expect(field).toHaveAttribute('data-mode', 'clear');
  await expect(field.getByTestId('secret-cleared')).toContainText('alert.ui-stored.token');
  await field.getByRole('button', { name: 'Undo' }).click();
  await expect(field).toHaveAttribute('data-mode', 'set');
  await field.getByRole('button', { name: 'Clear' }).click();
  await page.getByRole('button', { name: 'Check' }).click();
  await page.getByRole('button', { name: 'Apply' }).click();
  // The drawer closes once the change is applied; only then is the list read again.
  await expect(page.locator('.drawer')).toHaveCount(0);
  // The entry no longer names the secret; the value stays on Integrations & secrets until deleted.
  await page.goto('/#/settings?tab=secrets');
  const row = page.getByTestId('secret-row').filter({ hasText: 'alert.ui-stored.token' });
  await expect(row).toContainText('nothing');
  await row.getByRole('button', { name: 'Delete' }).click();
  await expect(row).toHaveCount(0);
});

// REQ: API-015, ADR-919 — an entry whose default name is already stored is offered that secret
// (Use it, or Replace), never a Delete; saving it links the entry.
test('api_015 an existing secret is offered to an entry, not deleted', async () => {
  const r = page.request;
  const h = { 'x-csrf-token': await csrfOf(r) };
  expect((await r.put('/api/v1/secrets/alert.ui-offer.token', { headers: h, data: { value: 'offered-value-6612', kind: 'text' } })).status()).toBe(200);
  try {
    await page.goto('/#/alerts');
    await page.getByRole('button', { name: 'Advanced', exact: true }).click();
    const dests = page.getByTestId('editor-alert_destination');
    await dests.getByRole('button', { name: 'Add destination' }).click();
    await page.getByRole('textbox', { name: 'Name', exact: true }).fill('ui-offer');
    await page.getByLabel('Type', { exact: true }).selectOption('ntfy');
    await page.getByRole('textbox', { name: 'Address', exact: true }).fill(`http://127.0.0.1:${PORTS.ntfyAlt}/offer`);
    const field = page.getByTestId('secret-token_ref');
    await expect(field).toHaveAttribute('data-mode', 'exists');
    await expect(field.getByTestId('secret-exists')).toContainText('alert.ui-offer.token');
    await expect(field.getByRole('button', { name: 'Delete' })).toHaveCount(0);
    await field.getByRole('button', { name: 'Use it' }).click();
    await expect(field).toHaveAttribute('data-mode', 'set');
    await page.getByRole('button', { name: 'Check' }).click();
    await page.getByRole('button', { name: 'Apply' }).click();
    await expect(page.locator('.drawer')).toHaveCount(0);
    await expect(dests.getByTestId('entry-row').filter({ hasText: 'ui-offer' })).toContainText('ntfy');
  } finally {
    await r.delete('/api/v1/alerts/destinations/ui-offer', { headers: h });
    await r.delete('/api/v1/secrets/alert.ui-offer.token', { headers: h });
  }
});

// REQ: API-015, CLU-002 (T24.42) — the Secrets page lists every full member of the cluster for each stored
// secret, the same on every node: one that lacks a secret shows a warning, one that didn't answer is unknown
// (named in missingNodes), and a resolver pod or a witness is listed as holding none, by design.
test('api_015 secrets are shown held by every cluster member, with a warning for one that lacks one', async () => {
  const stamp = { epoch: 1, seq: 3 };
  const node = (n: string, state: string, held = true) => ({ node: n, applied: state === 'applied', unreadable: state === 'unreadable', state, ...(held ? { stamp } : {}) });
  const body = {
    stale: false,
    head: { epoch: 1, seq: 3, digest: 'd', etag: '1.3.d' },
    store: { node: 'node-a', state: 'ready', dataEphemeral: false },
    items: [
      {
        name: 'router-key', kind: 'text', set: true, stamp, updated: '2026-11-19T10:00:00Z', updatedBy: 'root', origin: 'cluster', health: 'readable',
        usedBy: [{ kind: 'router', name: 'udm', field: 'api_key_ref', source: 'stored' }],
        nodes: [node('node-a', 'applied'), node('node-b', 'applied'), node('node-c', 'missing', false), node('node-d', 'unknown', false)],
      },
    ],
    credentials: [],
    members: [
      { node: 'node-a', kind: 'full', state: 'answered', held: 1 },
      { node: 'node-b', kind: 'full', state: 'answered', held: 1 },
      { node: 'node-c', kind: 'full', state: 'answered', held: 0 },
      { node: 'node-d', kind: 'full', state: 'unknown', held: 0 },
      { node: 'resolver-a', kind: 'resolver', state: 'not_held', held: 0 },
    ],
    missingNodes: ['node-d'],
    warnings: ['`router-key` is missing on node-c'],
  };
  await page.route('**/api/v1/secrets', (route) => (route.request().method() === 'GET' ? route.fulfill({ json: body, headers: { etag: '"1.3.d"' } }) : route.fallback()));
  try {
    await page.setViewportSize({ width: 1280, height: 800 });
    await page.goto('/#/settings?tab=secrets');
    const members = page.getByTestId('secrets-members');
    await expect(members).toBeVisible();
    await expect(members.getByTestId('secrets-member')).toHaveCount(5);
    await expect(members.getByTestId('secrets-warning')).toContainText('`router-key` is missing on node-c');
    await expect(page.getByTestId('secrets-missing-nodes')).toContainText('node-d');
    await expect(members.locator('[data-kind="resolver"]')).toContainText('holds none, by design');
    const row = page.getByTestId('secret-row').filter({ hasText: 'router-key' });
    await expect(row.locator('[data-state="applied"]')).toHaveCount(2);
    await expect(row.locator('[data-state="missing"]')).toContainText('missing');
    await expect(row.locator('[data-state="unknown"]')).toContainText('unknown');
    await expect(row.locator('[data-state="applied"]').first()).toContainText('1.3');
    // The members help topic opens from its button.
    await members.getByRole('button', { name: /help/i }).first().click();
    await expect(page.getByText('Which nodes hold a stored secret')).toBeVisible();
  } finally {
    await page.unroute('**/api/v1/secrets');
  }
});

// REQ: API-015 (T23.6, ADR-903 §9, ADR-919) — a typed value that isn't saved holds Check and Apply
// (the value would otherwise be dropped without a word); Save or Discard releases them.
test('api_015 a typed secret that is not saved holds Check and Apply', async () => {
  const r = page.request;
  const h = { 'x-csrf-token': await csrfOf(r) };
  await page.goto('/#/alerts');
  await page.getByRole('button', { name: 'Advanced', exact: true }).click();
  const dests = page.getByTestId('editor-alert_destination');
  await dests.getByRole('button', { name: 'Add destination' }).click();
  await page.getByRole('textbox', { name: 'Name', exact: true }).fill('ui-typed');
  await page.getByLabel('Type', { exact: true }).selectOption('ntfy');
  await page.getByRole('textbox', { name: 'Address', exact: true }).fill(`http://127.0.0.1:${PORTS.ntfyAlt}/typed`);
  const field = page.getByTestId('secret-token_ref');
  await field.getByLabel('Token (ntfy, Gotify, Pushover app)', { exact: true }).fill('typed-unsaved-4410');
  await expect(page.getByRole('button', { name: 'Check' })).toBeDisabled();
  await expect(page.getByTestId('secret-unsaved')).toContainText('Save or discard the secret');
  await field.getByRole('button', { name: 'Discard' }).click();
  await expect(page.getByRole('button', { name: 'Check' })).toBeEnabled();
  await expect(page.getByTestId('secret-unsaved')).toHaveCount(0);
  await field.getByLabel('Token (ntfy, Gotify, Pushover app)', { exact: true }).fill('typed-saved-4411');
  await field.getByRole('button', { name: 'Save secret' }).click();
  await expect(field).toHaveAttribute('data-mode', 'set');
  await expect(field.getByTestId('secret-status')).toContainText('alert.ui-typed.token');
  await page.getByRole('button', { name: 'Check' }).click();
  await page.getByRole('button', { name: 'Apply' }).click();
  await expect(page.locator('.drawer')).toHaveCount(0);
  try {
    await expect(dests.getByTestId('entry-row').filter({ hasText: 'ui-typed' })).toContainText('ntfy');
  } finally {
    await r.delete('/api/v1/alerts/destinations/ui-typed', { headers: h });
    await r.delete('/api/v1/secrets/alert.ui-typed.token', { headers: h });
  }
});

test('api_015 set by file is read-only', async () => {
  await page.goto('/#/alerts');
  await page.getByRole('button', { name: 'Advanced', exact: true }).click();
  const dests = page.getByTestId('editor-alert_destination');
  await dests.getByTestId('entry-row').filter({ hasText: 'file-ntfy' }).getByRole('button', { name: 'Edit' }).click();
  const field = page.getByTestId('secret-token_ref');
  await expect(field).toHaveAttribute('data-mode', 'file');
  await expect(field.getByTestId('secret-file')).toContainText('/run/secrets/e2e-ntfy-token');
  // The file is not on this node, so the field says so (the server's readability, per field).
  await expect(field.getByTestId('secret-file')).toContainText("can't read it");
  await expect(field.getByRole('textbox')).toHaveCount(0);
  await expect(field.getByRole('button', { name: /Save|Replace|Clear|Delete/ })).toHaveCount(0);
  await page.getByRole('button', { name: 'Close' }).click();
});

// REQ: API-015 (T23.6, ADR-919) — a path the API set (not the configuration file) can be removed from
// the entry; the stored-secret controls take its place.
test('api_015 an API-set file path can be removed', async () => {
  const r = page.request;
  const h = { 'x-csrf-token': await csrfOf(r) };
  const put = await r.put('/api/v1/alerts/destinations/ui-apipath', {
    headers: h,
    data: { type: 'ntfy', url: 'https://ntfy.e2e.test/apipath', token_file: '/run/secrets/ui-apipath-token' },
  });
  expect(put.status(), await put.text()).toBe(200);
  try {
    // The destination was written over the API: reload, so the list is read again (a hash change
    // keeps the list the previous test loaded).
    await page.goto('/#/alerts');
    await page.reload();
    await page.getByRole('button', { name: 'Advanced', exact: true }).click();
    const dests = page.getByTestId('editor-alert_destination');
    await dests.getByTestId('entry-row').filter({ hasText: 'ui-apipath' }).getByRole('button', { name: 'Edit' }).click();
    const field = page.getByTestId('secret-token_ref');
    await expect(field.getByTestId('secret-api-file')).toContainText('/run/secrets/ui-apipath-token');
    await field.getByRole('button', { name: 'Remove the path' }).click();
    await expect(field.getByTestId('secret-api-file')).toHaveCount(0);
    await expect(field).toHaveAttribute('data-mode', 'unset');
    await page.getByRole('button', { name: 'Close' }).click();
  } finally {
    await r.delete('/api/v1/alerts/destinations/ui-apipath', { headers: h });
  }
});

test('api_015 alert destination with a stored token delivers', async () => {
  const { createServer } = await import('node:http');
  const got: { auth?: string; body: string }[] = [];
  const ntfy = createServer((req, res) => {
    let b = '';
    req.on('data', (c) => (b += c));
    req.on('end', () => {
      got.push({ auth: req.headers.authorization, body: b });
      res.end('ok');
    });
  });
  await new Promise<void>((r) => ntfy.listen(PORTS.ntfy, '127.0.0.1', () => r()));
  try {
    await page.goto('/#/alerts');
    await page.getByRole('button', { name: 'Advanced', exact: true }).click();
    const dests = page.getByTestId('editor-alert_destination');
    await dests.getByRole('button', { name: 'Add destination' }).click();
    await page.getByRole('textbox', { name: 'Name', exact: true }).fill('ui-ntfy-stored');
    await page.getByLabel('Type', { exact: true }).selectOption('ntfy');
    await page.getByRole('textbox', { name: 'Address', exact: true }).fill(`http://127.0.0.1:${PORTS.ntfy}/topic`);
    const field = page.getByTestId('secret-token_ref');
    await field.getByLabel('Token (ntfy, Gotify, Pushover app)', { exact: true }).fill('stored-token-5521');
    await field.getByRole('button', { name: 'Save secret' }).click();
    await expect(field).toHaveAttribute('data-mode', 'set');
    await page.getByRole('button', { name: 'Check' }).click();
    await page.getByRole('button', { name: 'Apply' }).click();
    const row = dests.getByTestId('entry-row').filter({ hasText: 'ui-ntfy-stored' });
    await row.getByRole('button', { name: 'Send test' }).click();
    await expect(dests.getByTestId('row-action-result')).toContainText('sent');
    expect(got.some((g) => g.auth === 'Bearer stored-token-5521')).toBe(true);
    await row.getByRole('button', { name: 'Remove' }).click();
    await expect(row).toHaveCount(0);
    const r = page.request;
    const del = await r.delete('/api/v1/secrets/alert.ui-ntfy-stored.token', { headers: { 'x-csrf-token': await csrfOf(r) } });
    expect(del.status()).toBe(200);
  } finally {
    ntfy.close();
  }
});

// REQ: OBS-010, API-015 (T24.43) - a Pushover destination: both secrets are stored write-only,
// Send test posts the form to a fake Pushover (never api.pushover.net), and a refusal shows
// Pushover's reason without the secrets.
test('obs_010 pushover destination: two write-only secrets and Send test', async () => {
  const { createServer } = await import('node:http');
  const got: { type?: string; body: string }[] = [];
  let refuse = false;
  const fake = createServer((req, res) => {
    let b = '';
    req.on('data', (c) => (b += c));
    req.on('end', () => {
      got.push({ type: req.headers['content-type'], body: b });
      res.setHeader('content-type', 'application/json');
      if (refuse) {
        res.statusCode = 400;
        res.end('{"user":"invalid","errors":["user identifier is invalid"],"status":0,"request":"x"}');
      } else {
        res.end('{"status":1,"request":"x"}');
      }
    });
  });
  await new Promise<void>((r) => fake.listen(PORTS.ntfy, '127.0.0.1', () => r()));
  const r = page.request;
  try {
    await page.setViewportSize({ width: 1280, height: 800 });
    await page.goto('/#/alerts');
    await page.getByRole('button', { name: 'Advanced', exact: true }).click();
    const dests = page.getByTestId('editor-alert_destination');
    await dests.getByRole('button', { name: 'Add destination' }).click();
    await page.getByRole('textbox', { name: 'Name', exact: true }).fill('ui-pushover');
    await page.getByLabel('Type', { exact: true }).selectOption('pushover');
    await page.getByRole('textbox', { name: 'Address', exact: true }).fill(`http://127.0.0.1:${PORTS.ntfy}/1/messages.json`);
    const token = page.getByTestId('secret-token_ref');
    const user = page.getByTestId('secret-user_key_ref');
    await expect(user).toHaveAttribute('data-mode', 'unset');
    await token.getByLabel('Token (ntfy, Gotify, Pushover app)', { exact: true }).fill('po-app-token-8812');
    await noAnswerCarries('po-app-token-8812', async () => {
      await token.getByRole('button', { name: 'Save secret' }).click();
      await expect(token).toHaveAttribute('data-mode', 'set');
    });
    await user.getByLabel('User or group key (Pushover)', { exact: true }).fill('po-user-key-3377');
    await noAnswerCarries('po-user-key-3377', async () => {
      await user.getByRole('button', { name: 'Save secret' }).click();
      await expect(user).toHaveAttribute('data-mode', 'set');
    });
    await expect(user.getByTestId('secret-status')).toContainText('alert.ui-pushover.user_key');
    // Never shown again: not in a field, not in the page.
    await expect(user.getByLabel('User or group key (Pushover)', { exact: true })).toHaveCount(0);
    await expect(token.getByLabel('Token (ntfy, Gotify, Pushover app)', { exact: true })).toHaveCount(0);
    const html = await page.content();
    expect(html).not.toContain('po-app-token-8812');
    expect(html).not.toContain('po-user-key-3377');
    await page.getByLabel('Device (Pushover)', { exact: true }).fill('phone');
    await page.getByLabel('Sound (Pushover)', { exact: true }).fill('siren');
    await page.getByLabel('Priority when firing (Pushover)', { exact: true }).fill('1');
    await page.getByRole('button', { name: 'Help: Pushover keys' }).click();
    await expect(page.getByTestId('help-panel')).toBeVisible();
    await page.getByRole('dialog', { name: 'Pushover keys' }).getByRole('button', { name: 'Close' }).click();
    await expect(page.getByTestId('help-panel')).toHaveCount(0);
    await page.getByRole('button', { name: 'Check' }).click();
    await page.getByRole('button', { name: 'Apply' }).click();
    const row = dests.getByTestId('entry-row').filter({ hasText: 'ui-pushover' });
    await expect(row).toContainText('pushover:');
    // The saved entry carries references only.
    const entries = await (await r.get('/api/v1/config/entries?kind=alert_destination')).text();
    expect(entries).toContain('alert.ui-pushover.user_key');
    expect(entries).not.toContain('po-app-token-8812');
    expect(entries).not.toContain('po-user-key-3377');

    await row.getByRole('button', { name: 'Send test' }).click();
    await expect(dests.getByTestId('row-action-result')).toContainText('sent');
    expect(got).toHaveLength(1);
    expect(got[0].type).toBe('application/x-www-form-urlencoded');
    const f = new URLSearchParams(got[0].body);
    expect([f.get('token'), f.get('user'), f.get('device'), f.get('sound'), f.get('priority')]).toEqual(['po-app-token-8812', 'po-user-key-3377', 'phone', 'siren', '1']);
    expect(f.get('title')).toBe('Test: test');
    expect(f.get('message')).toContain('This is a test alert');

    // A refusal: Pushover's reason shows, the secrets do not.
    refuse = true;
    await row.getByRole('button', { name: 'Send test' }).click();
    const result = dests.getByTestId('row-action-result');
    await expect(result).toContainText('user identifier is invalid');
    await expect(result).not.toContainText('po-app-token-8812');
    await expect(result).not.toContainText('po-user-key-3377');

    await row.getByRole('button', { name: 'Remove' }).click();
    await expect(row).toHaveCount(0);
  } finally {
    fake.close();
    const csrf = { 'x-csrf-token': await csrfOf(r) };
    await r.delete('/api/v1/alerts/destinations/ui-pushover', { headers: csrf });
    await r.delete('/api/v1/secrets/alert.ui-pushover.token', { headers: csrf });
    await r.delete('/api/v1/secrets/alert.ui-pushover.user_key', { headers: csrf });
  }
});

test('api_015 delete of a secret in use names its users', async () => {
  const r = page.request;
  const h = { 'x-csrf-token': await csrfOf(r) };
  expect((await r.put('/api/v1/secrets/ui-in-use', { headers: h, data: { value: 'in-use-value-3311', kind: 'text' } })).status()).toBe(200);
  const used = await r.put('/api/v1/alerts/destinations/ui-used', {
    headers: h,
    data: { type: 'ntfy', url: `http://127.0.0.1:${PORTS.ntfy}/used`, token_ref: 'ui-in-use' },
  });
  expect(used.status(), await used.text()).toBe(200);
  try {
    await page.goto('/#/settings?tab=secrets');
    const row = page.getByTestId('secret-row').filter({ hasText: 'ui-in-use' });
    await expect(row).toContainText('ui-used');
    await row.getByRole('button', { name: 'Delete' }).click();
    await expect(page.getByTestId('secrets-stored').getByRole('alert')).toContainText('ui-used');
    await expect(row).toBeVisible();
    // The refusal is the point of this test: its 409 is expected, nothing else is.
    for (let i = problems.length - 1; i >= 0; i--) if (/status of 409/.test(problems[i])) problems.splice(i, 1);
  } finally {
    await r.delete('/api/v1/alerts/destinations/ui-used', { headers: h });
    await r.delete('/api/v1/secrets/ui-in-use', { headers: h });
  }
});

// REQ: API-015 (T23.6, ADR-903 §9, ADR-919) — on the secrets page a typed name that's stored is a
// replacement: the name stays editable and the value goes under it.
test('api_015 the secrets form keeps its name and replaces a stored one', async () => {
  const r = page.request;
  const h = { 'x-csrf-token': await csrfOf(r) };
  expect((await r.put('/api/v1/secrets/ui-form-replace', { headers: h, data: { value: 'first-value-8821', kind: 'text' } })).status()).toBe(200);
  try {
    await page.goto('/#/settings?tab=secrets');
    const form = page.getByTestId('secret-form');
    await form.getByLabel('Secret name', { exact: true }).fill('ui-form-replace');
    await expect(form).toHaveAttribute('data-mode', 'replace');
    await expect(form.getByLabel('Secret name', { exact: true })).toBeVisible();
    await expect(form.getByRole('button', { name: 'Save new value' })).toBeVisible();
    await form.getByLabel('Value', { exact: true }).fill('second-value-8822');
    await noAnswerCarries('second-value-8822', async () => {
      await form.getByRole('button', { name: 'Save new value' }).click();
      // Saved: the form is cleared for the next secret (its name went with the replacement).
      await expect(form.getByLabel('Secret name', { exact: true })).toHaveValue('');
    });
    expect(await page.content()).not.toContain('second-value-8822');
  } finally {
    await r.delete('/api/v1/secrets/ui-form-replace', { headers: h });
  }
});

// REQ: CLD-920, DSC-908 (owner decision 2026-11-26) — an admin stores a PEM secret from the secrets
// page, pasted or read from a file: kept as kind `pem`, never shown or returned again, the form is
// cleared on a save and on a refusal; a gate refusal is said in plain words naming the node; a name
// the certificate issuer keeps is refused by the server and the page says so.
test('cld_920 an admin stores a PEM secret and the key is never shown again', async () => {
  const KEY = 'MC4CAQAwBQYDK2VwBCIEIuiPlantedPemKeyBytes7731abcdef';
  const PEM = `-----BEGIN PRIVATE KEY-----\n${KEY}\n-----END PRIVATE KEY-----`;
  const r = page.request;
  const h = { 'x-csrf-token': await csrfOf(r) };
  try {
    // The page must read the secrets head fresh (a same-hash goto does not reload).
    await page.goto('/#/settings?tab=secrets');
    await page.reload();
    await expect(page.getByTestId('secrets-store')).toBeVisible();
    await page.getByTestId('secret-kind').selectOption('pem');
    const form = page.getByTestId('pem-form');
    // Pasted.
    await form.getByLabel('PEM secret name').fill('ui-pem-pasted');
    await form.getByLabel('PEM text').fill(PEM);
    await noAnswerCarries(KEY, async () => {
      await form.getByRole('button', { name: 'Save PEM secret' }).click();
      await expect(page.getByTestId('secret-row').filter({ hasText: 'ui-pem-pasted' })).toContainText('pem');
    });
    await expect(form.getByLabel('PEM text')).toHaveValue('');
    expect(await page.content()).not.toContain(KEY);
    expect(await (await r.get('/api/v1/secrets')).text()).not.toContain(KEY);
    // Read from a file.
    await form.getByLabel('PEM secret name').fill('ui-pem-file');
    await form.getByLabel('PEM file').setInputFiles({ name: 'key.pem', mimeType: 'text/plain', buffer: Buffer.from(PEM) });
    await expect(form.getByLabel('PEM text')).toHaveValue(PEM);
    await form.getByRole('button', { name: 'Save PEM secret' }).click();
    await expect(page.getByTestId('secret-row').filter({ hasText: 'ui-pem-file' })).toBeVisible();
    // Not PEM: the server's reason, and the field is cleared.
    await form.getByLabel('PEM secret name').fill('ui-pem-bad');
    await form.getByLabel('PEM text').fill('just a token');
    await form.getByRole('button', { name: 'Save PEM secret' }).click();
    await expect(form.getByRole('alert')).toContainText('PEM blocks only');
    await expect(form.getByLabel('PEM text')).toHaveValue('');
    // A name the issuer keeps: refused (409), and said.
    await form.getByLabel('PEM secret name').fill('cert.home.key');
    await form.getByLabel('PEM text').fill(PEM);
    await form.getByRole('button', { name: 'Save PEM secret' }).click();
    await expect(form.getByRole('alert')).toContainText('certificate issuer keeps for itself');
    expect((await r.get('/api/v1/secrets')).status()).toBe(200);
    for (let i = problems.length - 1; i >= 0; i--) if (/status of (400|409)/.test(problems[i])) problems.splice(i, 1);
  } finally {
    // The page keeps its state across a same-hash goto: leave the form on the text kind the next tests expect.
    await page.getByTestId('secret-kind').selectOption('text');
    for (const n of ['ui-pem-pasted', 'ui-pem-file']) await r.delete(`/api/v1/secrets/${n}`, { headers: h });
  }
});

// REQ: DSC-908 — the compatibility gate's refusal (a member's build does not know PEM secrets) reads in
// plain words and names the node. The refusal is stubbed (the e2e node is alone); the server's own
// answer is covered by `dsc_908_pem_secret_waits_for_every_members_build`.
test('dsc_908 a PEM secret held back by the gate says which node to upgrade', async () => {
  await page.route('**/api/v1/secrets/ui-pem-gated', (route) =>
    route.fulfill({
      status: 409,
      contentType: 'application/problem+json',
      json: {
        type: 'https://wrendns.com/problems/upgrade_required',
        title: 'Upgrade required',
        status: 409,
        code: 'upgrade_required',
        detail: 'node pi-b runs version 1.0.0, which does not know secrets of the `pem` kind; upgrade it first',
      },
    }),
  );
  try {
    // Same-hash navigation does not reload: go elsewhere first, then reload with the stub in place.
    await page.goto('/#/settings?tab=secrets');
    await page.reload();
    await expect(page.getByTestId('secrets-store')).toBeVisible();
    await page.getByTestId('secret-kind').selectOption('pem');
    const form = page.getByTestId('pem-form');
    await form.getByLabel('PEM secret name').fill('ui-pem-gated');
    await form.getByLabel('PEM text').fill('-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----');
    await form.getByRole('button', { name: 'Save PEM secret' }).click();
    await expect(form.getByRole('alert')).toContainText('node pi-b does not know PEM secrets yet; upgrade it first');
    for (let i = problems.length - 1; i >= 0; i--) if (/status of 409/.test(problems[i])) problems.splice(i, 1);
  } finally {
    await page.unroute('**/api/v1/secrets/ui-pem-gated');
    // The page keeps its state across a same-hash goto: leave the form on the text kind the next tests expect.
    await page.getByTestId('secret-kind').selectOption('text');
  }
});

// REQ: API-015 (ADR-903 §2) — a write carries the secrets head the page read (If-Match); a head that
// moved is refused, and the page says so and shows the list again.
test('api_015 a secret write sends the head it read, and a moved head is refused', async () => {
  let ifMatch: string | undefined;
  await page.route('**/api/v1/secrets/ui-moved', (route) => {
    ifMatch = route.request().headers()['if-match'];
    return route.fulfill({
      status: 412,
      contentType: 'application/problem+json',
      json: { type: 'https://wrendns.com/problems/precondition_failed', title: 'Precondition Failed', status: 412, code: 'precondition_failed', detail: 'the secrets head moved' },
    });
  });
  try {
    await page.goto('/#/settings?tab=secrets');
    await expect(page.getByTestId('secrets-store')).toBeVisible();
    const form = page.getByTestId('secret-form');
    await form.getByLabel('Secret name', { exact: true }).fill('ui-moved');
    await form.getByLabel('Value', { exact: true }).fill('moved-value-1');
    await form.getByRole('button', { name: 'Save secret' }).click();
    await expect(page.getByTestId('secrets-form').getByRole('alert')).toContainText('Someone else changed');
    expect(ifMatch).toMatch(/^"\d+\.\d+\./);
    // The refusal is the point of this test: its 412 is expected, nothing else is.
    for (let i = problems.length - 1; i >= 0; i--) if (/status of 412/.test(problems[i])) problems.splice(i, 1);
  } finally {
    await page.unroute('**/api/v1/secrets/ui-moved');
  }
});

// REQ: API-015 (T23.6) — the secrets tab fits a phone (two tables with four and five columns).
test('api_015 the secrets tab fits at phone width (360 px)', async () => {
  await page.setViewportSize({ width: 360, height: 740 });
  try {
    await page.goto('/#/settings?tab=secrets');
    await expect(page.getByTestId('secrets-store')).toBeVisible();
    const overflow = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
    expect(overflow).toBeLessThanOrEqual(0);
  } finally {
    await page.setViewportSize({ width: 1280, height: 800 });
  }
});

test('api_015 operator sees stored secrets, not the controls', async () => {
  const r = page.request;
  const h = { 'x-csrf-token': await csrfOf(r) };
  expect((await r.put('/api/v1/secrets/ui-visible', { headers: h, data: { value: 'operator-must-not-see-1', kind: 'text' } })).status()).toBe(200);
  const OPERATOR = { user: 'operator1', pass: 'operator long password' };
  const op = await page.context().browser()!.newContext({ baseURL: page.url().split('/#/')[0] });
  try {
    const p = await op.newPage();
    await p.goto('/#/settings?tab=secrets');
    await p.getByLabel('Username', { exact: true }).fill(OPERATOR.user);
    await p.getByLabel('Password', { exact: true }).fill(OPERATOR.pass);
    await p.getByRole('button', { name: 'Sign in' }).click();
    await expect(p.getByTestId('secrets-read-only')).toBeVisible({ timeout: 30_000 });
    const row = p.getByTestId('secret-row').filter({ hasText: 'ui-visible' });
    await expect(row).toBeVisible();
    await expect(p.getByRole('button', { name: 'Delete' })).toHaveCount(0);
    await expect(p.getByRole('button', { name: 'Replace' })).toHaveCount(0);
    await expect(p.getByTestId('secret-form')).toHaveCount(0);
    // REQ: CLD-920 — no PEM upload control either: it is an admin's.
    await expect(p.getByTestId('secret-kind')).toHaveCount(0);
    await expect(p.getByTestId('pem-form')).toHaveCount(0);
    expect(await p.content()).not.toContain('operator-must-not-see-1');
    const ocsrf = (await (await op.request.get('/api/v1/auth/status')).json()).csrfToken as string;
    const put = await op.request.put('/api/v1/secrets/ui-visible', {
      headers: { 'x-csrf-token': ocsrf },
      data: { value: 'changed-by-operator', kind: 'text' },
    });
    expect(put.status()).toBe(403);
  } finally {
    await op.close();
    await r.delete('/api/v1/secrets/ui-visible', { headers: h });
  }
});

test('api_015 plain HTTP refusal is explained', async () => {
  await page.route('**/api/v1/secrets/ui-refused', (route) =>
    route.fulfill({
      status: 403,
      contentType: 'application/problem+json',
      json: {
        type: 'https://wrendns.com/problems/insecure_transport',
        title: 'Forbidden',
        status: 403,
        code: 'insecure_transport',
        detail: 'secrets are taken only over HTTPS',
      },
    }),
  );
  try {
    await page.goto('/#/settings?tab=secrets');
    const form = page.getByTestId('secret-form');
    await form.getByLabel('Secret name', { exact: true }).fill('ui-refused');
    await form.getByLabel('Value', { exact: true }).fill('refused-value-1');
    await form.getByRole('button', { name: 'Save secret' }).click();
    await expect(page.getByTestId('secret-refused')).toContainText('HTTPS');
    await expect(page.getByTestId('secret-refused')).toContainText('allow_secrets_over_http');
  } finally {
    await page.unroute('**/api/v1/secrets/ui-refused');
  }
});

test('api_015 locked store links to the secrets tab', async () => {
  await page.route('**/api/v1/system/health', (route) =>
    route.fulfill({
      json: {
        level: 'degraded',
        checkedAt: '2026-10-08T12:00:00.000Z',
        reasons: [
          {
            level: 'degraded',
            code: 'secrets_locked',
            summary: "stored secrets can't be used on this node: no key (DNS is unaffected)",
            node: 'home-dns',
            link: '#/settings?tab=secrets',
          },
        ],
      },
    }),
  );
  try {
    await page.goto('/#/');
    await page.reload();
    const icon = page.getByTestId('health-icon');
    await expect(icon).toHaveAttribute('data-level', 'degraded');
    await icon.click();
    await page.getByTestId('health-panel').getByRole('link', { name: 'Look' }).first().click();
    await expect(page).toHaveURL(/tab=secrets/);
    await expect(page.getByRole('tab', { name: 'Integrations & secrets' })).toHaveAttribute('aria-selected', 'true');
  } finally {
    await page.unroute('**/api/v1/system/health');
  }
});

// REQ: API-005 (T23.6, AGT-004) — the Home Assistant scope preset fills an agent token's scopes
// with the README's list; the token is then revoked.
test('api_005 the Home Assistant preset fills the agent scopes', async () => {
  await page.goto('/#/settings?tab=tokens');
  await page.getByLabel('Kind', { exact: true }).selectOption('agent');
  await page.getByLabel('Scope preset').selectOption('home-assistant');
  await expect(page.getByLabel('Token name')).toHaveValue('home-assistant');
  for (const id of ['analytics:read', 'config:read', 'ops:pause', 'ops:anomalies', 'config:write:clients']) {
    await expect(page.locator(`fieldset.agent-scopes input[value="${id}"]`)).toBeChecked();
  }
  await expect(page.locator('fieldset.agent-scopes input[value="querylog:read"]')).not.toBeChecked();
  await page.getByRole('button', { name: 'Create token' }).click();
  await expect(page.locator('code.token')).toContainText('tt_');
  const row = page.getByRole('row').filter({ hasText: 'home-assistant' });
  await expect(row).toContainText('ops:pause');
  await row.getByRole('button', { name: 'Revoke' }).click();
  await expect(row).toHaveCount(0);
});

// REQ: FLT-010 (T9.7) — schedules from the UI: a bad window is explained, a good one saved;
// a group follows it (on now), then both are undone.
test('flt_010 schedules are edited from the UI', async () => {
  await page.setViewportSize({ width: 1280, height: 800 });
  await page.goto('/#/groups');
  const sched = page.getByTestId('editor-schedule');
  await sched.getByRole('button', { name: 'Add schedule' }).click();
  await page.getByRole('textbox', { name: 'Name', exact: true }).fill('ui-bedtime');
  const windows = page.getByRole('textbox', { name: 'Windows (one per line)' });
  await windows.fill('sometimes');
  await page.getByRole('button', { name: 'Check' }).click();
  await expect(page.getByRole('alert')).toContainText('weekdays 21:00-07:00');
  await windows.fill('daily 00:00-24:00');
  await page.getByRole('button', { name: 'Check' }).click();
  await expect(page.getByTestId('entry-preview')).toBeVisible();
  await page.getByRole('button', { name: 'Apply' }).click();
  const row = sched.getByTestId('entry-row').filter({ hasText: 'ui-bedtime' });
  await expect(row).toContainText('block_all: daily 00:00-24:00');

  // The test-only group follows it (an override of the files' group).
  await page.reload();
  const groups = page.getByTestId('editor-group');
  const g = groups.getByTestId('entry-row').filter({ hasText: 'ipv6only' });
  await g.getByRole('button', { name: 'Edit' }).click();
  await pick(page.locator('body'), 'Schedules', 'ui-bedtime');
  await page.getByRole('button', { name: 'Check', exact: true }).click();
  await page.getByRole('button', { name: 'Apply' }).click();
  const card = page.getByTestId('group-card').filter({ hasText: 'ipv6only' });
  await expect(async () => {
    await page.reload();
    await expect(card.getByTestId('group-schedules')).toContainText('on now', { timeout: 2000 });
  }).toPass({ timeout: 30_000 });

  await g.getByRole('button', { name: 'Revert to the file' }).click();
  await expect(g).toContainText('config file');
  await row.getByRole('button', { name: 'Remove' }).click();
  await expect(row).toHaveCount(0);
});

// REQ: FLT-014 (T27.4, API-901) — a rewrite added in the Groups form answers the group's devices
// (every test query comes from 127.0.0.1, so the lab group), Explain shows it, and removing it
// stops it. The group goes back to the file at the end.
test('flt_014 add a rewrite to a group', async () => {
  // Two DNS waits and a reload of Explain: longer than the default 30 s.
  test.setTimeout(90_000);
  await page.setViewportSize({ width: 1280, height: 800 });
  await page.goto('/#/groups');
  const lab = page.getByTestId('editor-group').getByTestId('entry-row').filter({ has: page.getByText('lab', { exact: true }) });
  await lab.getByRole('button', { name: 'Edit' }).click();
  const rewrites = page.getByRole('textbox', { name: 'Rewrites', exact: true });
  // A malformed line stops Check with the line named.
  await rewrites.fill('rw.e2e.test');
  await page.getByRole('button', { name: 'Check', exact: true }).click();
  await expect(page.getByRole('alert')).toContainText('write the name and the answer');
  // An answer that is neither an address nor a domain is named; `::::` is not an IPv6 address.
  await rewrites.fill('rw.e2e.test ::::');
  await page.getByRole('button', { name: 'Check', exact: true }).click();
  await expect(page.getByRole('alert')).toContainText('an IP address or a domain');
  await rewrites.fill('rw.e2e.test 192.0.2.88\nrw.e2e.test 192.0.2.89');
  await page.getByRole('button', { name: 'Check', exact: true }).click();
  await expect(page.getByRole('alert')).toContainText('rewritten twice');
  // A wildcard (*.domain) and a CNAME-style answer (a name) are accepted with the address rewrite.
  await rewrites.fill('rw.e2e.test 192.0.2.88\n*.rw-wild.e2e.test 192.0.2.90\nalias.e2e.test rw.e2e.test');
  await page.getByRole('button', { name: 'Check', exact: true }).click();
  await expect(page.getByTestId('entry-preview')).toBeVisible();
  await page.getByRole('button', { name: 'Apply' }).click();
  await expect(lab).toContainText('overrides the file');

  // The DNS answer is the rewrite (a query from 127.0.0.1 is in the lab group).
  await expect
    .poll(async () => (await queryDetail('rw.e2e.test')).address, { timeout: 20_000 })
    .toBe('192.0.2.88');
  // A name under the wildcard gets its address.
  await expect
    .poll(async () => (await queryDetail('host.rw-wild.e2e.test')).address, { timeout: 20_000 })
    .toBe('192.0.2.90');
  await page.goto('/#/explain?name=rw.e2e.test&client=127.0.0.1');
  await expect(page.locator('.explain')).toContainText('rewritten to 192.0.2.88', { timeout: 30_000 });

  // Removed: the rewrite is gone from the group and from Explain.
  await page.goto('/#/groups');
  await lab.getByRole('button', { name: 'Edit' }).click();
  await rewrites.fill('');
  await page.getByRole('button', { name: 'Check', exact: true }).click();
  await expect(page.getByTestId('entry-preview')).toBeVisible();
  await page.getByRole('button', { name: 'Apply' }).click();
  await expect
    .poll(async () => JSON.stringify(await (await page.request.get('/api/v1/explain?name=rw.e2e.test&client=127.0.0.1')).json()), {
      timeout: 20_000,
    })
    .not.toContain('rewritten to');
  await lab.getByRole('button', { name: 'Revert to the file' }).click();
  await expect(lab).toContainText('config file');
});

// REQ: FLT-008 (T27.4, API-901) — the block TTL and Extended DNS Error fields of a group: a blocked
// name's answer carries the TTL and the EDE code the form chose, and no list name when the text is off.
test('flt_014 group block ttl and ede', async () => {
  // Two DNS waits and a reload of Explain: longer than the default 30 s.
  test.setTimeout(90_000);
  await page.setViewportSize({ width: 1280, height: 800 });
  await page.goto('/#/groups');
  const lab = page.getByTestId('editor-group').getByTestId('entry-row').filter({ has: page.getByText('lab', { exact: true }) });
  await lab.getByRole('button', { name: 'Edit' }).click();
  // The server's limit is checked by the form first: 86401 is refused before Check.
  const ttl = page.getByRole('spinbutton', { name: 'Block TTL (seconds)' });
  await ttl.fill('86401');
  expect(await ttl.evaluate((el: HTMLInputElement) => el.validity.valid)).toBe(false);
  await ttl.fill('120');
  // REQ: FLT-008 (T27.4) — the block addresses apply only to Blocked answer = custom_ip: the field
  // is disabled otherwise and left out of the saved entry.
  const blockMode = page.getByRole('combobox', { name: 'Blocked answer' });
  const addrs = page.getByRole('textbox', { name: 'Block addresses (custom_ip)' });
  await blockMode.selectOption('custom_ip');
  await expect(addrs).toBeEnabled();
  await blockMode.selectOption('null_ip');
  await expect(addrs).toBeDisabled();
  await page.getByRole('combobox', { name: 'Extended DNS Error' }).selectOption('filtered');
  await page.getByRole('switch', { name: 'Name the list in the error' }).uncheck();
  await page.getByRole('button', { name: 'Check', exact: true }).click();
  await expect(page.getByTestId('entry-preview')).toBeVisible();
  await page.getByRole('button', { name: 'Apply' }).click();
  await expect(lab).toContainText('overrides the file');

  // ads.e2e.test is on a list every test group uses: blocked, with the group's TTL and EDE code.
  await expect
    .poll(async () => {
      const a = await queryDetail('ads.e2e.test');
      return `${a.address} ${a.ttl} ${a.ede.map((e) => e.code).join(',')} ${a.ede.map((e) => e.text).join('|')}`;
    }, { timeout: 20_000 })
    .toBe('0.0.0.0 120 17 ');

  // The form shows what was saved.
  await lab.getByRole('button', { name: 'Edit' }).click();
  await expect(page.getByRole('spinbutton', { name: 'Block TTL (seconds)' })).toHaveValue('120');
  await expect(page.getByRole('combobox', { name: 'Extended DNS Error' })).toHaveValue('filtered');
  await expect(page.getByRole('switch', { name: 'Name the list in the error' })).not.toBeChecked();
  await page.getByRole('dialog').getByRole('button', { name: 'Close', exact: true }).click();
  await lab.getByRole('button', { name: 'Revert to the file' }).click();
  await expect(lab).toContainText('config file');
});

// REQ: DNS-014 (review 01 q1) — the per-client rate limit is adjusted from Settings → System
// (checked first, then applied) and reverted to the config file's.
test('dns_014 the rate limit is adjusted from the UI and reverted', async () => {
  await page.setViewportSize({ width: 1280, height: 800 });
  await page.goto('/#/settings?tab=queries');
  const editor = page.getByTestId('editor-ratelimit');
  const row = editor.getByTestId('entry-row');
  await expect(row).toContainText('config file');
  await expect(row).toContainText('1000 queries per 60 s');
  await expect(editor.getByRole('button', { name: 'Add rate limit' })).toHaveCount(0);
  await expect(row.getByRole('button', { name: 'Remove' })).toHaveCount(0);

  await row.getByRole('button', { name: 'Edit' }).click();
  const queries = page.getByRole('spinbutton', { name: 'Queries allowed per window' });
  await queries.fill('0');
  await page.getByRole('button', { name: 'Check', exact: true }).click();
  await expect(page.getByRole('alert')).toContainText('queries');
  // The refusal above is expected: not a page problem.
  for (let i = problems.length - 1; i >= 0; i--) if (problems[i].includes('status of 422')) problems.splice(i, 1);
  await queries.fill('5000');
  await page.getByRole('button', { name: 'Check', exact: true }).click();
  await expect(page.getByTestId('entry-preview')).toContainText('count starts over');
  await page.getByRole('button', { name: 'Apply' }).click();
  await expect(row).toContainText('5000 queries per 60 s');
  await expect(row).toContainText('overrides the file');

  await row.getByRole('button', { name: 'Revert to the file' }).click();
  await expect(row).toContainText('config file');
  await expect(row).toContainText('1000 queries per 60 s');
});

// REQ: DNS-019 (T24.12, ADR-904, ADR-914) — Settings → Query handling → Special names: the
// switch is changed and applied with no restart (mask.icloud.com is no longer a special answer
// in Explain), and reverted to the file.
test('dns_019 special names card switches private relay off', async () => {
  await page.setViewportSize({ width: 1280, height: 800 });
  await page.goto('/#/settings?tab=queries');
  const editor = page.getByTestId('editor-special');
  const row = editor.getByTestId('entry-row');
  await expect(row).toContainText('Private Relay blocked');
  await expect(row).toContainText('config file');
  await row.getByRole('button', { name: 'Edit' }).click();
  await page.getByRole('switch', { name: 'Block iCloud Private Relay names' }).uncheck();
  await page.getByRole('button', { name: 'Check', exact: true }).click();
  await expect(page.getByTestId('entry-preview')).toContainText('next query');
  await page.getByRole('button', { name: 'Apply' }).click();
  await expect(row).toContainText('Private Relay allowed');
  await expect(row).toContainText('overrides the file');
  await page.goto('/#/explain?name=mask.icloud.com&client=127.0.0.1');
  await expect(page.getByTestId('explain-flow')).toBeVisible({ timeout: 30_000 });
  await expect(page.getByTestId('explain-special')).toHaveCount(0);
  await page.goto('/#/settings?tab=queries');
  await row.getByRole('button', { name: 'Revert to the file' }).click();
  await expect(row).toContainText('Private Relay blocked');
  await expect(row).toContainText('config file');
  await page.goto('/#/explain?name=mask.icloud.com&client=127.0.0.1');
  await expect(page.getByTestId('explain-special')).toContainText('Block iCloud Private Relay names', { timeout: 30_000 });
});

// REQ: DNS-019 (T24.12, ADR-914) — a listener's certificate that doesn't cover the DDR name
// is said so in the card's hint (the listener checks' results are mocked here).
test('dns_019 ddr name warns when not on the certificate', async () => {
  const probe = (proto: string, certNames: string[]) => ({
    listener: true, proto, node: 'home-dns', ok: true, target: `127.0.0.1:${proto === 'dot' ? 853 : 443}`,
    certNames, checkedUnixSeconds: 1_800_000_000, consecutiveFailures: 0, latencyMs: 2, lastOkUnixSeconds: 1_800_000_000,
  });
  await page.route('**/api/v1/system/probes', (route) =>
    route.fulfill({ json: { items: [probe('dot', ['dns.home.arpa', '127.0.0.1']), probe('doh', ['dns.home.arpa'])] } }),
  );
  try {
    await page.setViewportSize({ width: 1280, height: 800 });
    await page.goto('/#/settings?tab=queries');
    const row = page.getByTestId('editor-special').getByTestId('entry-row');
    await row.getByRole('button', { name: 'Edit' }).click();
    const note = page.getByTestId('editor-note');
    await page.getByRole('textbox', { name: 'Encrypted DNS name (DDR)' }).fill('dns.home.arpa');
    await expect(note).toContainText('covers dns.home.arpa');
    await page.getByRole('textbox', { name: 'Encrypted DNS name (DDR)' }).fill('dns.example.com');
    await expect(note).toContainText('Not on the certificate of home-dns dot, home-dns doh');
    await expect(note).toContainText('would refuse it');
    await page.getByRole('button', { name: 'Close' }).click();
  } finally {
    await page.unroute('**/api/v1/system/probes');
  }
});

// REQ: DNS-019 (T24.12, ADR-914) — an operator sees the DDR name read-only, and the server
// refuses an operator's change to it by name (403), while the other switches stay theirs.
test('dns_019 operator sees ddr_name read-only', async () => {
  const r = page.request;
  const csrf = (await (await r.get('/api/v1/auth/status')).json()).csrfToken as string;
  const OPERATOR = { user: 'operator1', pass: 'operator long password' };
  const made = await r.post('/api/v1/users', { headers: { 'x-csrf-token': csrf }, data: { username: OPERATOR.user, password: OPERATOR.pass, role: 'operator' } });
  expect([200, 201, 409]).toContain(made.status());
  const op = await page.context().browser()!.newContext({ baseURL: page.url().split('/#')[0] });
  try {
    const p = await op.newPage();
    await p.goto('/#/settings?tab=queries');
    await p.getByLabel('Username', { exact: true }).fill(OPERATOR.user);
    await p.getByLabel('Password', { exact: true }).fill(OPERATOR.pass);
    await p.getByRole('button', { name: 'Sign in' }).click();
    await expect(p.getByTestId('editor-special')).toBeVisible({ timeout: 30_000 });
    const row = p.getByTestId('editor-special').getByTestId('entry-row');
    await row.getByRole('button', { name: 'Edit' }).click();
    await expect(p.getByRole('textbox', { name: 'Encrypted DNS name (DDR)' })).toHaveAttribute('readonly', '');
    await expect(p.getByTestId('admin-only').first()).toContainText('Only an admin can change this.');
    await p.getByRole('button', { name: 'Close' }).click();
    // The server says no whatever the form does.
    const ocsrf = (await (await op.request.get('/api/v1/auth/status')).json()).csrfToken as string;
    const moved = await op.request.put('/api/v1/special-names/default', {
      headers: { 'x-csrf-token': ocsrf },
      data: { ddr_name: 'dns.example.com' },
    });
    expect(moved.status()).toBe(403);
    expect(await moved.text()).toContain('ddr_name');
  } finally {
    await op.close();
  }
});

// REQ: DNS-019 (T24.12, ADR-914) — a viewer sees the special names, read-only.
test('dns_019 viewer sees special names read-only', async () => {
  const r = page.request;
  const csrf = (await (await r.get('/api/v1/auth/status')).json()).csrfToken as string;
  const made = await r.post('/api/v1/users', { headers: { 'x-csrf-token': csrf }, data: { username: VIEWER.user, password: VIEWER.pass, role: 'viewer' } });
  expect([200, 201, 409]).toContain(made.status());
  const v = await page.context().browser()!.newContext({ baseURL: page.url().split('/#')[0] });
  try {
    const p = await v.newPage();
    await p.goto('/#/settings?tab=queries');
    await p.getByLabel('Username', { exact: true }).fill(VIEWER.user);
    await p.getByLabel('Password', { exact: true }).fill(VIEWER.pass);
    await p.getByRole('button', { name: 'Sign in' }).click();
    const row = p.getByTestId('editor-special').getByTestId('entry-row');
    await expect(row).toContainText('Private Relay blocked', { timeout: 30_000 });
    await expect(row.getByRole('button', { name: 'Edit' })).toHaveCount(0);
    await expect(row.getByRole('button', { name: 'Revert to the file' })).toHaveCount(0);
  } finally {
    await v.close();
  }
});

// REQ: DNS-023 (T24.13, ADR-901, ADR-914) — Local DNS → Device names in DNS: a domain turns
// device names on (`local` is refused, the server says why), and it's reverted to the file.
test('dns_023 turn on device names from the local DNS page', async () => {
  await page.setViewportSize({ width: 1280, height: 800 });
  await page.goto('/#/local-dns');
  const card = page.getByTestId('device-names-card');
  await expect(card.getByTestId('device-domain')).toContainText('off');
  await card.getByTestId('device-names-edit').click();
  const domain = card.getByRole('textbox', { name: 'Domain' });
  await domain.fill('local');
  await card.getByRole('button', { name: 'Check', exact: true }).click();
  await expect(page.getByRole('alert')).toContainText('local');
  // The refusal above is expected: not a page problem.
  for (let i = problems.length - 1; i >= 0; i--) if (problems[i].includes('status of 422')) problems.splice(i, 1);
  await domain.fill('home.arpa');
  await card.getByRole('button', { name: 'Check', exact: true }).click();
  await expect(card.getByTestId('device-names-preview')).toContainText('within about 10 seconds');
  await card.getByRole('button', { name: 'Apply' }).click();
  await expect(card.getByTestId('device-domain')).toContainText('home.arpa');
  await expect(card.getByTestId('device-names-count')).toBeVisible();
  await card.getByRole('button', { name: 'Revert to the file' }).click();
  await expect(card.getByTestId('device-domain')).toContainText('off');
});

// The e2e server sets `[clients] mdns = true` in its file (T8.6 needs it), so the real server
// shows that field as "set by file". The tests of the switch's own states answer the
// `clients` entry from page.route (ADR: the e2e server has no such source), and the rest check
// what the real server does.
const clientsEntry = (mdns: boolean, setByFile: string[] = []) => ({
  items: [{ kind: 'clients', name: 'default', source: 'file', definition: { mdns, mdns_port: MDNS_PORT }, redacted: [], credentialIssues: [], setByFile }],
});

// REQ: DNS-023 (T24.13, ADR-914) — the mDNS switch for names is disabled, and says why, while
// `[clients] mdns` is off.
test('dns_023 mdns switch needs clients mdns', async () => {
  await page.route(/\/api\/v1\/config\/entries\?kind=clients/, (route) => route.fulfill({ json: clientsEntry(false) }));
  try {
    // The card is already mounted from the test before: leave the page and come back, so it reads the mocked entry.
    await page.goto('/#/settings?tab=queries');
    await page.goto('/#/local-dns');
    const card = page.getByTestId('device-names-card');
    await card.getByTestId('device-names-edit').click();
    await expect(card.getByRole('switch', { name: 'Name devices by their mDNS names' })).toBeDisabled();
    await expect(card.getByTestId('mdns-needed')).toContainText('Off until mDNS listening is on');
    await card.getByRole('button', { name: 'Cancel' }).click();
  } finally {
    await page.unroute(/\/api\/v1\/config\/entries\?kind=clients/);
  }
});

// REQ: DNS-019, DNS-023 (M4, ADR-914) — every device-name field the files set is locked and
// labelled, and the request leaves those fields out (the files' values apply). The entries are
// mocked: the e2e file sets none of them. `mdns_port` is marked set by file too.
test('dns_023 device-name fields set by file are locked', async () => {
  const setByFile = ['device_domain', 'device_ttl', 'auto_ptr', 'default_ttl', 'device_mdns'];
  const local = {
    items: [{
      kind: 'local', name: 'default', source: 'file',
      definition: { device_domain: 'home.arpa', device_ttl: 60, auto_ptr: true, default_ttl: 300, device_mdns: true, hosts_files: [] },
      redacted: [], credentialIssues: [], setByFile, answering: 3,
    }],
  };
  await page.route(/\/api\/v1\/config\/entries\?kind=local/, (route) => route.fulfill({ json: local }));
  await page.route(/\/api\/v1\/config\/entries\?kind=clients/, (route) => route.fulfill({ json: clientsEntry(true, ['mdns_port']) }));
  let sent = null as Record<string, unknown> | null;
  await page.route(/\/api\/v1\/local-settings\/default/, async (route) => {
    if (route.request().method() !== 'PUT') return route.fallback();
    sent = route.request().postDataJSON() as Record<string, unknown>;
    await route.fulfill({
      json: { applied: false, configVersion: 1, before: {}, after: {}, recentQueries: 0, impact: 'Device names in DNS change within about 10 seconds on every node, with no restart.', warnings: [] },
    });
  });
  try {
    await page.goto('/#/settings?tab=queries');
    await page.goto('/#/local-dns');
    const card = page.getByTestId('device-names-card');
    await expect(card.getByTestId('device-domain')).toContainText('home.arpa');
    await card.getByTestId('device-names-edit').click();
    for (const label of ['Domain', 'TTL of device names (seconds)', 'TTL of other local names (seconds)']) {
      await expect(card.getByLabel(label, { exact: true })).toHaveAttribute('readonly', '');
    }
    await expect(card.getByLabel('Reverse names for local addresses')).toBeDisabled();
    await expect(card.getByRole('switch', { name: 'Name devices by their mDNS names' })).toBeDisabled();
    await expect(card.getByTestId('set-by-file')).toHaveCount(5);
    await expect(page.getByTestId('clients-mdns')).toContainText('(set by file)');
    await card.getByRole('button', { name: 'Check', exact: true }).click();
    await expect(card.getByTestId('device-names-preview')).toBeVisible();
    expect(sent).not.toBeNull();
    for (const k of setByFile) expect(sent).not.toHaveProperty(k);
  } finally {
    await page.unroute(/\/api\/v1\/config\/entries\?kind=local/).catch(() => {});
    await page.unroute(/\/api\/v1\/config\/entries\?kind=clients/).catch(() => {});
    await page.unroute(/\/api\/v1\/local-settings\/default/).catch(() => {});
  }
});

// REQ: DNS-023 (T24.13, ADR-914) — an admin turns on `[clients] mdns`: the switch names the
// setting, is checked (a dry run) before it's applied, and sends `mdns: true`. The entry is
// answered from a mock (the e2e file sets it), so only the UI's part is checked here.
test('dns_023 admin turns on clients mdns', async () => {
  let mdns = false;
  await page.route(/\/api\/v1\/config\/entries\?kind=clients/, (route) => route.fulfill({ json: clientsEntry(mdns) }));
  const change = (applied: boolean) => ({
    applied, configVersion: 1, before: { mdns: false }, after: { mdns: true }, recentQueries: 0,
    impact: 'Applies on every node after the reload. mDNS names are only heard on the LAN, so this needs a listener there.', warnings: [],
  });
  await page.route(/\/api\/v1\/clients-settings\/default/, async (route) => {
    if (route.request().method() !== 'PUT') return route.fallback();
    const dry = route.request().url().includes('dryRun=true');
    if (!dry) mdns = true;
    await route.fulfill({ json: change(!dry) });
  });
  try {
    await page.goto('/#/settings?tab=queries');
    await page.goto('/#/local-dns');
    const mdnsSection = page.getByTestId('clients-mdns');
    await mdnsSection.getByRole('switch', { name: 'Listen for mDNS announcements' }).check();
    const applied = page.waitForRequest((r) => r.method() === 'PUT' && r.url().includes('/clients-settings/default') && !r.url().includes('dryRun') && r.postData()?.includes('"mdns":true') === true);
    await mdnsSection.getByRole('button', { name: 'Check' }).click({ force: true });
    await expect(page.getByTestId('mdns-preview')).toContainText('mDNS');
    await mdnsSection.getByRole('button', { name: 'Apply' }).click({ force: true });
    await applied;
    await page.unroute(/\/api\/v1\/config\/entries\?kind=clients/);
    await page.reload();
    await expect(page.getByTestId('clients-mdns')).toBeVisible();
  } finally {
    await page.unroute(/\/api\/v1\/clients-settings\/default/).catch(() => {});
    await page.unroute(/\/api\/v1\/config\/entries\?kind=clients/).catch(() => {});
  }
});

// REQ: DNS-023 (T24.13, ADR-914) — an operator can't change `[clients] mdns`: the real server
// says the file sets it (409 set_by_file, naming the field), and the card shows it as set by file.
test('dns_023 operator sees clients mdns read-only', async () => {
  const r = page.request;
  const csrf = (await (await r.get('/api/v1/auth/status')).json()).csrfToken as string;
  const OPERATOR = { user: 'operator1', pass: 'operator long password' };
  await r.post('/api/v1/users', { headers: { 'x-csrf-token': csrf }, data: { username: OPERATOR.user, password: OPERATOR.pass, role: 'operator' } });
  const op = await page.context().browser()!.newContext({ baseURL: page.url().split('/#')[0] });
  try {
    const p = await op.newPage();
    await p.goto('/#/local-dns');
    await p.getByLabel('Username', { exact: true }).fill(OPERATOR.user);
    await p.getByLabel('Password', { exact: true }).fill(OPERATOR.pass);
    await p.getByRole('button', { name: 'Sign in' }).click();
    const mdns = p.getByTestId('clients-mdns');
    await expect(mdns.getByTestId('mdns-set-by-file')).toBeVisible({ timeout: 30_000 });
    await expect(mdns.getByRole('switch', { name: 'Listen for mDNS announcements' })).toHaveCount(0);
    const ocsrf = (await (await op.request.get('/api/v1/auth/status')).json()).csrfToken as string;
    const moved = await op.request.put('/api/v1/clients-settings/default', { headers: { 'x-csrf-token': ocsrf }, data: { mdns: false } });
    expect(moved.status()).toBe(409);
    expect(await moved.text()).toContain('mdns');
  } finally {
    await op.close();
  }
});

// REQ: DNS-023 (T24.13, ADR-901) — a viewer sees the device-name settings, read-only. The viewer
// is made here (not by an earlier test), so this test runs on its own.
test('dns_023 viewer sees device-name settings read-only', async () => {
  const csrf = (await (await page.request.get('/api/v1/auth/status')).json()).csrfToken as string;
  const made = await page.request.post('/api/v1/users', { headers: { 'x-csrf-token': csrf }, data: { username: VIEWER.user, password: VIEWER.pass, role: 'viewer' } });
  expect([200, 201, 409]).toContain(made.status());
  const v = await page.context().browser()!.newContext({ baseURL: page.url().split('/#')[0] });
  try {
    const p = await v.newPage();
    await p.goto('/#/local-dns');
    await p.getByLabel('Username', { exact: true }).fill(VIEWER.user);
    await p.getByLabel('Password', { exact: true }).fill(VIEWER.pass);
    await p.getByRole('button', { name: 'Sign in' }).click();
    const card = p.getByTestId('device-names-card');
    await expect(card.getByTestId('device-domain')).toContainText('off', { timeout: 30_000 });
    await expect(card.getByTestId('device-names-edit')).toHaveCount(0);
    await expect(p.getByTestId('clients-mdns').getByTestId('mdns-set-by-file')).toBeVisible();
  } finally {
    await v.close();
  }
});

// REQ: DNS-010 (T27.7, ADR-1007) — a record's TTL and node-only flag from the local DNS page: the
// answer on the wire carries the TTL, and the node-only name shows as such in the list.
test('dns_010 record ttl', async () => {
  await page.setViewportSize({ width: 1280, height: 800 });
  await page.goto('/#/local-dns');
  await page.getByRole('button', { name: 'Add a name' }).click();
  const form = page.locator('form').filter({ has: page.getByLabel('TTL in seconds (optional)') });
  await form.getByLabel('Name', { exact: true }).fill('ttl010.home.arpa');
  await form.getByLabel('Address', { exact: true }).fill('192.0.2.10');
  await form.getByLabel('TTL in seconds (optional)').fill('60');
  await form.getByLabel('Only on this node (the cluster doesn\'t share it)').check();
  await form.getByRole('button', { name: 'Save' }).click();
  await expect(page.getByRole('status').filter({ hasText: 'Saved.' })).toBeVisible();
  await page.getByRole('dialog').getByRole('button', { name: 'Close' }).click();
  const row = page.locator('tr').filter({ hasText: 'ttl010.home.arpa' });
  await expect(row).toContainText('60');
  await expect(row).toContainText('this node only');
  const answer = await queryDetail('ttl010.home.arpa');
  expect(answer.address).toBe('192.0.2.10');
  expect(answer.ttl).toBe(60);
  await row.getByRole('button', { name: 'Remove ttl010.home.arpa' }).click();
  await expect(page.locator('tr').filter({ hasText: 'ttl010.home.arpa' })).toHaveCount(0);
});

// REQ: DNS-010 (T27.7, ADR-1007) — a conditional-forwarding route limited to a client group and a
// query type, with the trust anchor and node-only choices, shown in the preview and the list.
test('dns_010 route by group and type', async () => {
  await page.goto('/#/local-dns');
  await page.getByRole('button', { name: 'Send a domain to another server', exact: true }).click();
  const form = page.locator('form').filter({ has: page.getByLabel('Only for these query types (optional)') });
  await form.getByLabel('Domain', { exact: true }).fill('routed010.example');
  await form.getByLabel('Server address', { exact: true }).fill('10.10.10.53');
  await form.getByLabel('Only for the devices in these groups (optional)').fill('lab');
  await form.getByLabel('Only for these query types (optional)').fill('ptr');
  await expect(form.getByText('for the devices in lab')).toBeVisible();
  await form.getByLabel('Only on this node (the cluster doesn\'t share it)').check();
  await form.getByRole('button', { name: 'Save' }).click();
  await expect(page.getByRole('status').filter({ hasText: 'routed010.example for the devices in lab' })).toBeVisible();
  await page.getByRole('dialog').getByRole('button', { name: 'Close' }).click();
  const row = page.locator('tr').filter({ hasText: 'routed010.example' });
  await expect(row).toContainText('for lab');
  await expect(row).toContainText('PTR');
  await expect(row).toContainText('this node only');
  await row.getByRole('button', { name: 'Stop sending routed010.example' }).click();
  await expect(page.locator('tr').filter({ hasText: 'routed010.example' })).toHaveCount(0);
});

// REQ: DNS-010 (T27.7, ADR-1007) — an authoritative zone made from the local DNS page answers its
// names itself and gives "no such name" for a name the zone doesn't have.
test('dns_010 add a zone', async () => {
  await page.goto('/#/local-dns');
  await page.getByTestId('zone-add').click();
  const form = page.getByTestId('zone-form');
  await form.getByLabel('Zone (its domain)').fill('zone010.e2e.test');
  await form.getByLabel('Record 1 name').fill('printer.zone010.e2e.test');
  await form.getByLabel('Record 1 type').selectOption('A');
  await form.getByLabel('Record 1 value').fill('192.168.11.20');
  await form.getByLabel('Record 1 TTL').fill('120');
  await form.getByRole('button', { name: 'Save' }).click();
  await expect(page.getByRole('status').filter({ hasText: 'zone010.e2e.test' })).toBeVisible();
  await page.getByRole('dialog').getByRole('button', { name: 'Close' }).click();
  const zoneRow = page.getByTestId('zone-row').filter({ hasText: 'zone010.e2e.test' });
  await expect(zoneRow).toContainText('the UI / API');
  const answer = await queryDetail('printer.zone010.e2e.test');
  expect(answer.address).toBe('192.168.11.20');
  expect(answer.ttl).toBe(120);
  // The refusal for a name it doesn't have is expected: the zone answers it itself.
  expect(await query('ghost.zone010.e2e.test')).toBe(3);
  // REQ: DNS-010 (T27.7) — an API zone is edited in place: the new address is answered at once.
  await zoneRow.getByRole('button', { name: 'Edit zone zone010.e2e.test' }).click();
  await page.getByTestId('zone-form').getByLabel('Record 1 value').fill('192.168.11.21');
  await page.getByTestId('zone-form').getByRole('button', { name: 'Save' }).click();
  await expect(page.getByRole('status').filter({ hasText: 'zone010.e2e.test' })).toBeVisible();
  await page.getByRole('dialog').getByRole('button', { name: 'Close' }).click();
  expect((await queryDetail('printer.zone010.e2e.test')).address).toBe('192.168.11.21');
  await zoneRow.getByRole('button', { name: 'Remove zone zone010.e2e.test' }).click();
  await expect(page.getByTestId('zone-row').filter({ hasText: 'zone010.e2e.test' })).toHaveCount(0);
});

// REQ: OBS-020 (T27.5, ADR-1007) — the listener checks' interval is changed from Settings → System,
// applied with no restart (the card reads it back), and reverted to the file.
test('obs_020 change probe interval', async () => {
  await page.setViewportSize({ width: 1280, height: 800 });
  await page.goto('/#/settings?tab=system');
  const tuning = page.getByTestId('tuning-probe');
  await tuning.locator('summary').click();
  const editor = page.getByTestId('editor-probe');
  const row = editor.getByTestId('entry-row');
  await expect(row).toContainText('Every 30 s');
  await row.getByRole('button', { name: 'Edit' }).click();
  await page.getByRole('spinbutton', { name: 'Seconds between rounds' }).fill('45');
  await page.getByRole('button', { name: 'Check', exact: true }).click();
  await page.getByRole('button', { name: 'Apply' }).click();
  await expect(row).toContainText('Every 45 s');
  await expect(row).toContainText('overrides the file');
  await row.getByRole('button', { name: 'Revert to the file' }).click();
  await expect(row).toContainText('Every 30 s');
});

// REQ: OBS-003 (T27.5, ADR-1007) — the query log's store is an admin's: an operator sees the
// settings read-only, and the server refuses the privacy level from an operator (403).
test('obs_003 operator cannot change privacy level', async () => {
  const csrf = (await (await page.request.get('/api/v1/auth/status')).json()).csrfToken as string;
  const made = await page.request.post('/api/v1/users', { headers: { 'x-csrf-token': csrf }, data: { username: 'olive', password: 'an operator password', role: 'operator' } });
  expect([200, 201, 409]).toContain(made.status());
  const o = await page.context().browser()!.newContext({ baseURL: page.url().split('/#')[0] });
  try {
    const p = await o.newPage();
    await p.goto('/#/queries');
    await p.getByLabel('Username', { exact: true }).fill('olive');
    await p.getByLabel('Password', { exact: true }).fill('an operator password');
    await p.getByRole('button', { name: 'Sign in' }).click();
    await p.goto('/#/queries');
    await p.getByTestId('tuning-qlog').locator('summary').click();
    const row = p.getByTestId('editor-qlog_settings').getByTestId('entry-row');
    await expect(row).toContainText('Privacy level', { timeout: 30_000 });
    await expect(row.getByRole('button', { name: 'Edit' })).toHaveCount(0);
    const token = (await (await o.request.get('/api/v1/auth/status')).json()).csrfToken as string;
    const refused = await o.request.put('/api/v1/qlog-settings/default', {
      headers: { 'x-csrf-token': token, 'content-type': 'application/json' },
      data: { privacy_level: 2 },
    });
    expect(refused.status()).toBe(403);
  } finally {
    await o.close();
  }
});

// REQ: OBS-020 (T27.5, API-901) — the form refuses a probe timeout the server would refuse (a timeout
// of whole seconds at or above the interval) before it asks the server, and says why.
test('obs_020 form refuses a timeout longer than the interval', async () => {
  await page.setViewportSize({ width: 1280, height: 800 });
  // The page may already be on this URL (a hash change does not reload it): reload, so the
  // disclosure starts closed and the click opens it.
  await page.goto('/#/settings?tab=system');
  await page.reload();
  await page.getByTestId('tuning-probe').locator('summary').click();
  const row = page.getByTestId('editor-probe').getByTestId('entry-row');
  await expect(row).toContainText('Every 30 s');
  await row.getByRole('button', { name: 'Edit' }).click();
  await page.getByRole('spinbutton', { name: 'Seconds between rounds' }).fill('5');
  await page.getByRole('spinbutton', { name: 'Timeout per check (ms)' }).fill('6000');
  await page.getByRole('button', { name: 'Check', exact: true }).click();
  await expect(page.getByText('The timeout must be shorter than the interval')).toBeVisible();
  await expect(row).not.toContainText('Every 5 s');
});

// REQ: OBS-003 (T27.5, API-901) — the query log's size is checked in the form: a size the server
// can't read (`2 gigs`) is refused with the accepted units, not sent.
test('obs_003 form refuses a size it cannot read', async () => {
  await page.setViewportSize({ width: 1280, height: 800 });
  await page.goto('/#/queries');
  await page.getByTestId('tuning-qlog').locator('summary').click();
  const row = page.getByTestId('editor-qlog_settings').getByTestId('entry-row');
  await expect(row).toContainText('Privacy level');
  await row.getByRole('button', { name: 'Edit' }).click();
  await page.getByRole('textbox', { name: 'Keep at most (size)' }).fill('2 gigs');
  await page.getByRole('button', { name: 'Check', exact: true }).click();
  await expect(page.getByText('Keep at most: a size such as 500MiB or 2GiB')).toBeVisible();
});

// REQ: UPS-007 (T9.25) — a group's upstream servers are chosen in the Groups editor.
test('ups_007 a group picks its upstream group from the UI', async () => {
  await page.goto('/#/groups');
  const g = page.getByTestId('editor-group').getByTestId('entry-row').filter({ hasText: 'ipv6only' });
  await g.getByRole('button', { name: 'Edit' }).click();
  await page.getByLabel('Upstream servers').selectOption('router');
  await page.getByRole('button', { name: 'Check' }).click();
  await page.getByRole('button', { name: 'Apply' }).click();
  const card = page.getByTestId('group-card').filter({ hasText: 'ipv6only' });
  await expect(async () => {
    await page.reload();
    await expect(card.getByTestId('group-upstreams')).toContainText('router', { timeout: 2000 });
  }).toPass({ timeout: 30_000 });
  await g.getByRole('button', { name: 'Revert to the file' }).click();
  await expect(g).toContainText('config file');
});

// REQ: OBS-022 (T12.1) — Settings → System keeps a name out of the log: it's still answered,
// but only the other name is logged; then back to the file's (nothing excluded). Near the end:
// its names get cached (the cache test counts what's cached).
test('obs_022 exclusions from Settings', async () => {
  await page.setViewportSize({ width: 1280, height: 800 });
  await page.goto('/#/settings?tab=queries');
  const editor = page.getByTestId('editor-exclusions');
  const row = editor.getByTestId('entry-row');
  await expect(row).toContainText('nothing excluded');
  await row.getByRole('button', { name: 'Edit' }).click();
  await page.getByRole('textbox', { name: 'Names', exact: true }).fill('quiet.cache.e2e.test');
  await page.getByRole('button', { name: 'Check', exact: true }).click();
  await expect(page.getByTestId('entry-preview')).toBeVisible();
  await page.getByRole('button', { name: 'Apply' }).click();
  await expect(row).toContainText('1 names, 0 devices');
  await expect(row).toContainText('overrides the file');
  expect(await query('quiet.cache.e2e.test')).toBe(0);
  expect(await query('loud.cache.e2e.test')).toBe(0);
  const logged = async () =>
    ((await (await page.request.get('/api/v1/queries?name=.cache.e2e.test&from=-10m')).json()).items as { name: string }[]).map(
      (r) => r.name,
    );
  await expect.poll(logged, { timeout: 20_000 }).toContain('loud.cache.e2e.test');
  expect(await logged()).not.toContain('quiet.cache.e2e.test');
  await row.getByRole('button', { name: 'Revert to the file' }).click();
  await expect(row).toContainText('nothing excluded');
  await expect(row).toContainText('config file');
});

// REQ: OBS-903 (T24.35, ADR-1014) — Settings → Query handling → "Log only" leaves a domain out of
// the query log while it is still answered and counted (the log-excluded counter); then back to
// the file's (nothing excluded). The node's-own-lookups switch is there, off.
test('obs_903 log-only exclusions from Settings', async () => {
  await page.setViewportSize({ width: 1280, height: 800 });
  await page.goto('/#/settings?tab=queries');
  const editor = page.getByTestId('editor-exclusions');
  const row = editor.getByTestId('entry-row');
  await expect(row).toContainText('nothing excluded');
  await row.getByRole('button', { name: 'Edit' }).click();
  const own = page.getByRole('switch', { name: "Leave this node's own lookups out of the query log" });
  await expect(own).not.toBeChecked();
  await page.getByRole('textbox', { name: 'Log only: domains', exact: true }).fill('hushed.cache.e2e.test');
  await page.getByRole('button', { name: 'Check', exact: true }).click();
  await expect(page.getByTestId('entry-preview')).toBeVisible();
  await page.getByRole('button', { name: 'Apply' }).click();
  await expect(row).toContainText('log only: 1 domains');
  expect(await query('hushed.cache.e2e.test')).toBe(0);
  expect(await query('audible.cache.e2e.test')).toBe(0);
  const logged = async () =>
    ((await (await page.request.get('/api/v1/queries?name=.cache.e2e.test&from=-10m')).json()).items as { name: string }[]).map(
      (r) => r.name,
    );
  await expect.poll(logged, { timeout: 20_000 }).toContain('audible.cache.e2e.test');
  expect(await logged()).not.toContain('hushed.cache.e2e.test');
  // Answered and counted, only not logged: the counter says how many the log skipped.
  await expect
    .poll(async () => (await (await page.request.get('/metrics')).text()).match(/wrendns_queries_log_excluded_total (\d+)/)?.[1], {
      timeout: 20_000,
    })
    .not.toBe('0');
  // Its help topic opens beside the form.
  await page.getByRole('button', { name: 'Help: Kept out of the query log only' }).click();
  await expect(page.getByTestId('help-panel')).toContainText('never written to the query log');
  await page.keyboard.press('Escape');
  await row.getByRole('button', { name: 'Revert to the file' }).click();
  await expect(row).toContainText('nothing excluded');
});

// REQ: OPS-901 (T24.35, ADR-1014) — /readyz answers 200 only while the node's own listener answers
// a DNS query, with nothing about the configuration in the body, and what it asks is never logged.
test('ops_901 readyz asks the listener and is never logged', async () => {
  for (let i = 0; i < 3; i++) {
    const r = await page.request.get('/readyz');
    expect(r.status()).toBe(200);
    expect(await r.text()).toBe('{"ready":true}\n');
    await page.waitForTimeout(1100);
  }
  const probes = ((await (await page.request.get('/api/v1/queries?name=probe.wrendns.invalid&from=-10m')).json()).items as unknown[])
    .length;
  expect(probes).toBe(0);
});

// REQ: OBS-024 (T13.1) — "What would this have done?" on a quick block rule counts the queries
// this test makes (nothing is saved); Settings → System → Change simulation turns
// plans_by_default on, and it's reverted to the file.
test('obs_024 simulate a quick rule, and the simulation settings', async () => {
  await page.setViewportSize({ width: 1280, height: 800 });
  for (let i = 0; i < 7; i++) expect(await query('sim.cache.e2e.test')).toBe(0);
  const logged = async () =>
    ((await (await page.request.get('/api/v1/queries?name=sim.cache.e2e.test&match=exact&from=-10m')).json()).items as unknown[])
      .length;
  await expect.poll(logged, { timeout: 20_000 }).toBe(7);
  await page.goto('/#/rules');
  const form = page.getByTestId('quick-rule-form');
  await form.getByRole('button', { name: 'Block' }).click();
  await form.getByRole('textbox', { name: 'Domain' }).fill('sim.cache.e2e.test');
  await form.getByRole('combobox', { name: 'Applies to' }).selectOption('everyone');
  await form.getByTestId('simulate-button').click();
  const card = form.getByTestId('simulation-card');
  await expect(card).toBeVisible({ timeout: 30_000 });
  await expect(card.getByTestId('sim-newlyBlocked').locator('.num')).toHaveText('7');
  await expect(card.getByTestId('sim-newlyAllowed').locator('.num')).toHaveText('0');
  await expect(card).toContainText('sim.cache.e2e.test');
  await expect(card).toContainText('quick rule: sim.cache.e2e.test');
  // Only a preview: DNS still answers it.
  expect(await query('sim.cache.e2e.test')).toBe(0);

  await page.goto('/#/settings?tab=queries');
  const editor = page.getByTestId('editor-simulate');
  const row = editor.getByTestId('entry-row');
  await expect(row).toContainText('simulate when asked');
  await row.getByRole('button', { name: 'Edit' }).click();
  const box = page.getByRole('switch', { name: "Agents' plans simulate by default" });
  await box.check();
  await expect(box).toBeChecked();
  await page.getByRole('button', { name: 'Check', exact: true }).click();
  await expect(page.getByTestId('entry-preview')).toContainText('next simulation');
  await page.getByRole('button', { name: 'Apply' }).click();
  await expect(row).toContainText('always simulate');
  await expect(row).toContainText('overrides the file');
  await row.getByRole('button', { name: 'Revert to the file' }).click();
  await expect(row).toContainText('simulate when asked');
  await expect(row).toContainText('config file');
});

// REQ: CLU-013 (T13.2) — Settings → Cluster → Staged rollouts: pick a node as a canary (the
// sentence says who gets changes first), apply it, and revert to the file. The cluster view is
// an example (this server runs alone); the settings are this server's own.
test('clu_013 staged rollouts: pick a canary in Settings', async () => {
  await page.setViewportSize({ width: 1280, height: 800 });
  const node = (o: Record<string, unknown>) => ({
    ephemeral: false, witness: false, protocol: 4, role: 'replica', thisNode: false, eligible: true, version: '0.4.0',
    up: true, connected: true, link: 'inbound', lastSeenSecondsAgo: 1, rttMs: 3, configSeq: 9, configLag: 0, ready: true,
    qps: 10, servfailPercent: 0, upstreamP90Ms: 12, uptimeSeconds: 3600, restarts: 0, ...o,
  });
  await page.route('**/api/v1/cluster', (route) =>
    route.fulfill({
      json: {
        enabled: true, clusterId: 'c1', name: 'home', thisNode: 'aaaa1111', newestConfigSeq: 9, healthy: true, checks: [],
        events: [], conflicts: [], authority: 'api',
        nodes: [
          node({ nodeId: 'aaaa1111', site: 'k8s', role: 'primary', thisNode: true, link: 'self' }),
          node({ nodeId: 'bbbb2222', site: 'pi' }),
        ],
      },
    }),
  );
  await page.goto('/#/settings?tab=cluster');
  const editor = page.getByTestId('editor-rollout');
  const row = editor.getByTestId('entry-row');
  await expect(row).toContainText('off: changes reach every node at once');
  await row.getByRole('button', { name: 'Edit' }).click();
  await pick(page.locator('body'), 'Canary nodes', 'pi (bbbb2222)');
  await expect(page.getByTestId('editor-note')).toContainText('Changes reach pi (bbbb2222) (and the primary) first');
  await page.getByRole('button', { name: 'Check', exact: true }).click();
  await expect(page.getByTestId('entry-preview')).toBeVisible();
  await page.getByRole('button', { name: 'Apply' }).click();
  await expect(row).toContainText('1 canary entry');
  await expect(row).toContainText('overrides the file');
  const entries = await (await page.request.get('/api/v1/config/entries?kind=rollout')).json();
  expect(JSON.stringify(entries)).toContain('bbbb2222');
  await row.getByRole('button', { name: 'Revert to the file' }).click();
  await expect(row).toContainText('off: changes reach every node at once');
  await page.unroute('**/api/v1/cluster');
});

// REQ: CLU-013 — the Cluster page: a pin banner (what's held back; Unpin), the kept versions
// with Pin (a dry run lists the changes first), and a version baking (canaries, time left, the
// guard's readings; dashed canaries in the topology). The data is an example.
test('clu_013 the cluster page shows the pin, the versions, and the bake', async () => {
  await page.setViewportSize({ width: 1280, height: 900 });
  const node = (o: Record<string, unknown>) => ({
    ephemeral: false, witness: false, protocol: 4, role: 'replica', thisNode: false, eligible: true, version: '0.4.0',
    up: true, connected: true, link: 'inbound', lastSeenSecondsAgo: 1, rttMs: 3, configSeq: 9, configLag: 0, ready: true,
    qps: 10, servfailPercent: 0, upstreamP90Ms: 12, uptimeSeconds: 3600, restarts: 0, ...o,
  });
  let baking = false;
  const view = () => ({
    enabled: true, clusterId: 'c1', name: 'home', thisNode: 'aaaa1111', newestConfigSeq: 12, healthy: true, checks: [],
    events: [], conflicts: [], authority: 'api',
    nodes: [
      node({ nodeId: 'aaaa1111', site: 'k8s', role: 'primary', thisNode: true, link: 'self', configSeq: 12 }),
      node({ nodeId: 'bbbb2222', site: 'canary-box', configSeq: baking ? 12 : 11 }),
      node({ nodeId: 'cccc3333', site: 'pi', configSeq: 11 }),
    ],
    rollout: baking
      ? { stage: 'canary', version: '1.12', canaries: ['bbbb2222'] }
      : { stage: 'pinned', pinned: { to: '1.10', since: '2026-10-10T12:00:00Z', by: 'the guard', reason: 'SERVFAIL 28.0% on the canaries' } },
  });
  const pinned = {
    fromPrimary: true, canaries: ['site:canary-box'], bakeSecs: 300, stable: '1.11', stage: 'pinned', nodes: [],
    pinned: { to: '1.10', since: '2026-10-10T12:00:00Z', by: 'the guard', reason: 'SERVFAIL 28.0% on the canaries during the bake (limit 5.0%)', changes: ['upstream: changed'] },
  };
  const bakingStatus = {
    fromPrimary: true, canaries: ['site:canary-box'], bakeSecs: 300, stable: '1.11', stage: 'canary', version: '1.12',
    started: '2026-10-10T12:00:00Z', bakeEnds: '2026-10-10T12:05:00Z', secondsLeft: 125, rolloutCanaries: ['bbbb2222'],
    readings: { beforePercent: 1.0, afterPercent: 1.2, answers: 640 },
    nodes: [
      { node: 'aaaa1111', site: 'k8s', canary: false, appliedSeq: 12, ready: true, connected: true, servfailPercent: 1.1 },
      { node: 'bbbb2222', site: 'canary-box', canary: true, appliedSeq: 12, ready: true, connected: true, servfailPercent: 1.2 },
      { node: 'cccc3333', site: 'pi', canary: false, appliedSeq: 11, ready: true, connected: true, servfailPercent: 0.9 },
    ],
  };
  const versions = {
    history: 20,
    items: [
      { version: '1.11', created: '2026-10-10T12:00:10Z', by: 'this node\'s configuration', outcome: 'pinned_to', pinnedTo: '1.10', reason: 'the guard', current: true, pinnable: true },
      { version: '1.10', created: '2026-10-10T11:00:00Z', by: 'this node\'s configuration', outcome: 'canary_failed', current: false, pinnable: true, readings: { beforePercent: 1, afterPercent: 28, answers: 900, reason: 'SERVFAIL 28.0%' } },
      { version: '1.9', created: '2026-10-10T10:00:00Z', by: 'this node\'s configuration', outcome: 'canary_promoted', current: false, pinnable: true },
    ],
  };
  const pinCalls: string[] = [];
  await page.route('**/api/v1/cluster', (route) => route.fulfill({ json: view() }));
  await page.route('**/api/v1/cluster/rollout', (route) => route.fulfill({ json: baking ? bakingStatus : pinned }));
  await page.route('**/api/v1/cluster/versions', (route) => route.fulfill({ json: versions }));
  await page.route('**/api/v1/cluster/versions/*/pin**', (route) => {
    const dry = route.request().url().includes('dryRun=true');
    pinCalls.push(`${route.request().url().split('/api/v1/')[1]} ${route.request().postData()}`);
    return route.fulfill({
      json: { done: dry ? 'would pin the cluster to version 1.9' : 'pinned to version 1.9 (published as 13)', dryRun: dry, changes: ['list: changed'], diff: [], configVersion: 7 },
    });
  });
  // ADR-121 — a pin shows on every tab, and the Rollouts tab says so; the full banner is there.
  await page.goto('/#/cluster');
  await expect(page.getByTestId('pin-note')).toContainText('pinned to version 1.10');
  await expect(page.getByTestId('tab-rollouts')).toContainText('pinned');
  await page.getByTestId('tab-rollouts').click();
  await expect(page).toHaveURL(/#\/cluster\?tab=rollouts$/);
  await expect(page.getByTestId('pin-note')).toHaveCount(0);
  const banner = page.getByTestId('pin-banner');
  await expect(banner).toContainText('pinned to version 1.10');
  await expect(banner).toContainText('the guard');
  await expect(page.getByTestId('pin-changes')).toContainText('upstream: changed');
  await expect(banner.getByTestId('unpin')).toBeVisible();

  const rows = page.getByTestId('version-row');
  await expect(rows).toHaveCount(3);
  await expect(rows.nth(1)).toContainText('failed');
  await rows.nth(2).getByTestId('pin-open').click();
  const form = page.getByTestId('pin-form');
  await form.getByRole('textbox', { name: 'Reason' }).fill('e2e: back to 1.9');
  await form.getByTestId('pin-check').click();
  await expect(form.getByTestId('pin-preview')).toContainText('list: changed');
  await form.getByTestId('pin-confirm').click();
  await expect(page.getByTestId('rollout-done')).toContainText('pinned to version 1.9');
  expect(pinCalls[0]).toMatch(/^cluster\/versions\/1\.9\/pin\?dryRun=true .*e2e: back to 1\.9/);
  expect(pinCalls[1]).toMatch(/^cluster\/versions\/1\.9\/pin .*e2e: back to 1\.9/);

  // A version baking: the canaries and the time left, Promote and Abort, dashed in the topology.
  baking = true;
  await page.reload();
  const bake = page.getByTestId('rollout-baking');
  await expect(bake).toContainText('Version 1.12 runs on canary-box and the primary');
  await expect(bake).toContainText('2m left');
  await expect(page.getByTestId('rollout-readings')).toContainText('640 answers');
  await expect(bake.getByTestId('rollout-promote')).toBeVisible();
  await expect(bake.getByTestId('rollout-abort')).toContainText('pin to 1.11');
  await expect(page.getByTestId('pin-banner')).toHaveCount(0);
  await expect(page.getByTestId('tab-rollouts')).toContainText('baking');
  // Arrow keys move between tabs (WAI-ARIA): left from Rollouts is Health, then Nodes.
  await page.getByTestId('tab-rollouts').focus();
  await page.keyboard.press('ArrowLeft');
  await expect(page.getByTestId('tab-health')).toBeFocused();
  await expect(page.getByTestId('tab-health')).toHaveAttribute('aria-selected', 'true');
  await page.keyboard.press('Home');
  await expect(page).toHaveURL(/tab=nodes$/);
  await expect(page.getByTestId('cluster-topology').locator('.chip.canary')).toHaveCount(2); // the canary and the primary
  await expect(page.locator('#node-id-bbbb2222, #node-bbbb2222').getByTestId('cluster-node-canary')).toBeVisible();
  for (const p of ['**/api/v1/cluster', '**/api/v1/cluster/rollout', '**/api/v1/cluster/versions', '**/api/v1/cluster/versions/*/pin**'])
    await page.unroute(p);
});

// REQ: OBS-025 (T13.3) — a "device" (its own loopback address) that asks Roku's names shows
// as a Roku player on Clients, with the evidence, and the naming form suggests the name.
test('obs_025 a device that talks to roku.com looks like a Roku player', async () => {
  test.setTimeout(120_000);
  await page.setViewportSize({ width: 1280, height: 800 });
  const roku = '127.0.0.77';
  // Their upstream is unreachable in this test: the answers don't matter, the questions do.
  await Promise.all(
    ['api.roku.com', 'time.rokutime.com', 'ads.ravm.tv', 'scribe.roku.com'].map((n) => query(n, 1, DNS_PORT, roku).catch(() => -1)),
  );
  // Identities refresh when asked for and over 15 s old (the first right away).
  await page.goto('/#/clients');
  const row = page.getByRole('row').filter({ hasText: roku });
  await expect
    .poll(
      async () => {
        await page.reload();
        const line = await row.getByTestId('identity-line').first().innerText({ timeout: 1_000 }).catch(() => '');
        // On failure, the API's answer shows what went wrong.
        const api = await (await page.request.get(`/api/v1/clients/${roku}/identity`)).text();
        return `${line} | ${api}`;
      },
      { timeout: 90_000, intervals: [2_000] },
    )
    .toContain('Looks like a Roku player');
  await row.getByTestId('identity-line').first().getByRole('button', { name: 'Why?' }).click();
  await expect(row).toContainText('roku.com');
  await row.getByRole('button', { name: roku }).first().click();
  await page.getByRole('menuitem', { name: 'Name this device…' }).click();
  await expect(page.getByRole('textbox', { name: 'device-name' }).or(page.locator('input[name="device-name"]'))).toHaveValue(
    'Roku player',
  );
  await expect(page.getByTestId('identity-suggestion')).toContainText('Roku player');
  await page.keyboard.press('Escape');
});

// REQ: OBS-018 — a list in shadow mode never blocks: its name is answered (by the stub
// upstream) and counted under "Would have blocked"; the list carries a shadow badge.
// Last, because it caches a name (the cache test counts what's cached).
test('obs_018 shadow list and over-blocking', async () => {
  for (let i = 0; i < 2; i++) expect(await query('shadow.cache.e2e.test')).toBe(0);
  await page.goto('/#/lists');
  // The lists table comes first; the "Would have blocked" card also names the list.
  const row = page.locator('tr', { hasText: 'e2e-shadow' }).first();
  // Last in the suite: the earlier config changes can keep the first load busy for a while.
  await expect(row.locator('.badge', { hasText: 'shadow' })).toBeVisible({ timeout: 15_000 });
  // The page reads the counts once; the telemetry thread counts the queries moments later.
  const card = page.getByTestId('shadow-lists');
  await expect(async () => {
    await page.reload();
    await expect(card).toContainText('shadow.cache.e2e.test', { timeout: 2000 });
  }).toPass({ timeout: 20_000 });
  await expect(card).toContainText('2 queries from 1 device');
  await page.route('**/api/v1/analytics/overblocking*', (route) =>
    route.fulfill({
      json: {
        items: [{ name: 'login.bank.example', lists: ['e2e-block'], devices: 1, retryBursts: 0, allowedAfterBlock: 2, lastSeen: new Date().toISOString() }],
      },
    }),
  );
  await page.reload();
  const ob = page.getByTestId('overblocking');
  await expect(ob).toContainText('login.bank.example');
  await expect(ob).toContainText('e2e-block');
  await page.unroute('**/api/v1/analytics/overblocking*');
});

// REQ: OBS-033 (T14.7) — change markers: a configuration change made through the API is a
// marker on the dashboard's Queries chart whose hover names its version; the Changes toggle
// hides it; Settings → System lists it; the "Note…" form adds a marker that names its author.
// Notes are checked and append-only.
test('obs_033 change markers', async () => {
  await page.setViewportSize({ width: 1280, height: 800 });
  const r = page.request;
  const csrf = (await (await r.get('/api/v1/auth/status')).json()).csrfToken as string;
  const h = { 'x-csrf-token': csrf };
  const put = await r.put('/api/v1/records/marker.e2e.test', { headers: h, data: { records: [{ type: 'A', value: '192.0.2.33' }] } });
  expect(put.status()).toBe(200);
  const seq = (await put.json()).configVersion as number;
  const applied = `configuration ${seq} applied`;
  await expect
    .poll(async () => ((await (await r.get('/api/v1/annotations?kinds=config.applied')).json()).items as { summary: string }[]).map((a) => a.summary), {
      timeout: 15_000,
    })
    .toContainEqual(expect.stringContaining(applied));

  await page.goto('/#/');
  const chart = page.getByTestId('dashboard-chart');
  const marker = chart.getByTestId('chart-markers').getByRole('button', { name: new RegExp(applied) });
  await expect(marker).toBeVisible({ timeout: 20_000 });
  await marker.hover();
  await expect(chart.getByTestId('marker-tip')).toContainText(applied);
  await expect(chart.getByTestId('marker-tip')).toContainText('admin');
  // The toggle hides every marker (and is remembered).
  await page.getByTestId('changes-toggle').uncheck();
  await expect(chart.getByTestId('chart-markers')).toHaveCount(0);
  await page.reload();
  await expect(page.getByTestId('changes-toggle')).not.toBeChecked();
  await page.getByTestId('changes-toggle').check();
  await expect(marker).toBeVisible();

  // Settings → System lists it, with who.
  await page.goto('/#/settings?tab=system');
  const list = page.getByTestId('changes-list');
  await expect(list).toContainText(applied);
  await expect(list.getByRole('row').filter({ hasText: applied })).toContainText('admin');

  // A note from the dashboard: a marker of its own that names its author.
  await page.goto('/#/');
  await page.getByTestId('note-open').click();
  await page.getByTestId('note-text').fill('moved the access point to the hallway');
  await page.getByRole('button', { name: 'Add note' }).click();
  const note = chart.getByTestId('chart-markers').getByRole('button', { name: /moved the access point to the hallway \(admin\)/ });
  await expect(note).toBeVisible();
  await note.hover();
  await expect(chart.getByTestId('marker-tip')).toContainText('admin');

  // Checked and append-only (API).
  const long = await r.post('/api/v1/annotations', { headers: h, data: { text: 'x'.repeat(201) } });
  expect(long.status()).toBe(422);
  expect((await long.json()).code).toBe('annotation_text');
  const ahead = await r.post('/api/v1/annotations', { headers: h, data: { text: 'later', time: new Date(Date.now() + 3_600_000).toISOString() } });
  expect(ahead.status()).toBe(422);
  expect((await ahead.json()).code).toBe('annotation_time');
  for (const m of ['put', 'delete'] as const) {
    const res = await r[m]('/api/v1/annotations', { headers: h });
    expect(res.status(), m).toBe(405);
  }
  const audit = (await (await r.get('/api/v1/audit?action=annotation.note')).json()).items;
  expect(audit[0]).toMatchObject({ action: 'annotation.note', actor: 'admin' });
  // The refusals above are expected: not page problems.
  for (let i = problems.length - 1; i >= 0; i--) if (/status of 4(05|22)/.test(problems[i])) problems.splice(i, 1);
  expect((await r.delete('/api/v1/records/marker.e2e.test', { headers: h })).status()).toBe(200);
});

// REQ: OBS-027 (T14.1) — "Who spent it?": the card's link opens Analyze → Error budget with the
// real server's numbers; then a stubbed attribution: the bars, a row's link to the query log
// filtered to its bad answers, the table view, and the partial-node note.
test('obs_027 budget attribution', async () => {
  await page.setViewportSize({ width: 1280, height: 800 });
  await page.goto('/#/');
  await page.getByRole('button', { name: 'Advanced', exact: true }).click();
  await page.getByTestId('slo-who-availability').click();
  await expect(page).toHaveURL(/#\/analyze\?.*tab=budget/);
  const tab = page.getByTestId('budget-attribution');
  await expect(tab.getByTestId('budget-summary')).toContainText('bad of');
  const row = (key: string, bad: number, exact: boolean) => ({ key, bad, sharePct: Math.round((bad / 13) * 1000) / 10, exact, ...(exact ? {} : { errorMax: 0 }) });
  await page.route('**/api/v1/stats/slo/attribution*', (route) =>
    route.fulfill({
      json: {
        objective: 'availability', from: '2026-09-16T00:00:00.000Z', to: '2026-10-16T00:00:00.000Z', step: 'day',
        budget: { targetPct: 99.9, answered: 10000, allowedBad: 10, bad: 13, remainingPct: -30 },
        timeline: [
          { start: '2026-10-14T00:00:00.000Z', startUnixSeconds: 1792022400, node: 'pi', answered: 5000, bad: 10, budgetSpentPct: 100 },
          { start: '2026-10-15T00:00:00.000Z', startUnixSeconds: 1792108800, node: 'pi', answered: 5000, bad: 3, budgetSpentPct: 30 },
        ],
        byClient: [{ ...row('192.0.2.185', 10, false), name: 'laptop' }, row('192.0.2.20', 3, false)],
        byName: [row('247.73.85.170.in-addr.arpa', 10, false)],
        byStatus: [row('refreshed', 10, true), row('forwarded', 3, true)],
        byUpstream: [row('none', 10, true), row('quad9-2', 3, true)],
        byRcode: [row('SERVFAIL', 13, true)],
        byNode: [row('pi', 13, true)],
        coverage: { topListsFromHours: 720, approximate: true, partialNodes: ['old-pod'] },
      },
    }),
  );
  await page.reload();
  await expect(tab.getByTestId('budget-summary')).toContainText('overspent');
  await expect(tab.getByTestId('partial-nodes')).toContainText('old-pod');
  const clients = tab.getByTestId('by-client');
  await expect(clients).toContainText('laptop (192.0.2.185)');
  await expect(tab.getByTestId('by-upstream')).toContainText('none');
  await clients.getByRole('button', { name: 'Table' }).click();
  await expect(clients.getByRole('table')).toContainText('76.9%');
  await clients.getByRole('link', { name: /laptop/ }).click();
  await expect(page).toHaveURL(/#\/queries\?.*client=192\.0\.2\.185/);
  await expect(page).toHaveURL(/rcode=SERVFAIL/);
  await page.unroute('**/api/v1/stats/slo/attribution*');
});

// REQ: OBS-029 (T14.3) — the heatmap: the network grid from the real server; then a stubbed
// device whose first hour was below the list: the keyboard moves the focus and the tooltip
// says so, the typical week averages, the table view toggles, and a cell opens the query log.
test('obs_029 heatmap', async () => {
  await page.setViewportSize({ width: 1280, height: 800 });
  await page.goto('/#/heatmap');
  await expect(page.getByRole('heading', { name: /^Heatmap/ })).toBeVisible();
  await expect(page.getByTestId('heatmap-canvas')).toBeVisible();
  const day = new Date();
  day.setHours(0, 0, 0, 0);
  const day0 = Math.floor(day.getTime() / 1000) - 86_400;
  const starts = Array.from({ length: 48 }, (_, i) => day0 + i * 3600);
  await page.route('**/api/v1/stats/heatmap*', (route) =>
    route.fulfill({
      json: {
        from: new Date(day0 * 1000).toISOString(), to: new Date((day0 + 48 * 3600) * 1000).toISOString(),
        grain: 'hour', slotSeconds: 3600, kind: 'client', key: '10.20.2.14', measure: 'queries',
        starts, values: starts.map((_, i) => (i === 0 ? 0 : 100 + i)), covered: starts.map((_, i) => i !== 0),
        precision: 'topList',
      },
    }),
  );
  await page.getByRole('button', { name: 'Device', exact: true }).click();
  await page.getByTestId('heatmap-key').fill('10.20.2.14');
  await page.getByRole('button', { name: 'Show', exact: true }).click();
  const canvas = page.getByTestId('heatmap-canvas');
  await expect(canvas).toBeVisible();
  // The grid ignores keys until its data and measured width have both landed (keydown returns
  // early without a grid or geometry), which can trail the canvas becoming visible by a frame.
  // The first press starts from no focus cell, as a person's would; a retry presses Home first, so
  // ArrowRight lands on the same cell however often it is repeated.
  let presses = 0;
  await expect(async () => {
    await canvas.focus();
    if (presses++ > 0) await page.keyboard.press('Home');
    await page.keyboard.press('ArrowRight');
    await expect(page.getByTestId('heatmap-tip')).toContainText('101 queries', { timeout: 1000 });
  }).toPass({ timeout: 15_000 });
  await page.keyboard.press('ArrowLeft');
  await expect(page.getByTestId('heatmap-tip')).toContainText("below this hour's top list");
  // A typical week: each weekday's hour is the mean of its days (one day each here).
  await page.getByTestId('heatmap-fold').check();
  await canvas.focus();
  // The first day's weekday row (Monday first), then its second hour.
  const weekday = (new Date(day0 * 1000).getDay() + 6) % 7;
  for (let i = 0; i < weekday; i++) await page.keyboard.press('ArrowDown');
  await page.keyboard.press('ArrowRight');
  await expect(page.getByTestId('heatmap-tip')).toContainText('101 queries on average over 1 day');
  await page.getByTestId('heatmap-fold').uncheck();
  await page.getByRole('button', { name: 'Table', exact: true }).click();
  await expect(page.getByTestId('heatmap-table')).toContainText('125');
  await page.getByRole('button', { name: 'Grid', exact: true }).click();
  // Two days fill the window's height (rows up to 64 px), not 26 px rows.
  expect((await canvas.boundingBox())!.height).toBeGreaterThan(130);
  // A link to the page it's on (or Back) changes what it shows.
  await page.goto('/#/heatmap?kind=client&key=10.20.2.14&window=30d');
  await expect(page.getByRole('button', { name: '30 d', exact: true })).toHaveAttribute('aria-pressed', 'true');
  await expect(page.getByTestId('heatmap-key')).toHaveValue('10.20.2.14');
  await canvas.click({ position: { x: 112, y: 26 } });
  await expect(page).toHaveURL(/#\/queries\?.*client=10\.20\.2\.14/);
  await page.unroute('**/api/v1/stats/heatmap*');
});

// REQ: OBS-029 — a refused grain doesn't loop: hiding the grid after an error once flipped the
// grain to hours (its width read 0), which succeeded, showed the grid, flipped back and failed
// again, endlessly. Now one request, the error alone, and the prompt comes back for a device.
test('obs_029 heatmap error does not loop', async () => {
  await page.setViewportSize({ width: 1280, height: 800 });
  const grains: string[] = [];
  await page.route('**/api/v1/stats/heatmap*', (route) => {
    const grain = new URL(route.request().url()).searchParams.get('grain') ?? '';
    grains.push(grain);
    if (grain === 'minute') {
      return route.fulfill({ status: 422, json: { type: 'about:blank', title: 'too many slots', status: 422, detail: 'too many slots', code: 'heatmap_window' } });
    }
    return route.fulfill({
      json: { from: new Date().toISOString(), to: new Date().toISOString(), grain, slotSeconds: grain === 'hour' ? 3600 : 900, kind: 'network', measure: 'queries', starts: [], values: [], precision: 'exact' },
    });
  });
  await page.goto('/#/heatmap?grain=minute');
  await expect(page.getByRole('alert')).toBeVisible();
  await page.waitForTimeout(1000);
  expect(grains).toEqual(['minute']);
  await expect(page.getByText('Loading…')).toHaveCount(0);
  await page.getByRole('button', { name: 'Device', exact: true }).click();
  await expect(page.getByText('Enter one above.')).toBeVisible();
  await expect(page.getByRole('alert')).toHaveCount(0);
  await page.unroute('**/api/v1/stats/heatmap*');
  // The refusal above is expected: not a page problem.
  for (let i = problems.length - 1; i >= 0; i--) if (problems[i].includes('status of 422')) problems.splice(i, 1);
});

// REQ: OBS-030 (T14.4) — the latency heatmap: the Dashboard's tab draws the grid from the real
// server; then stubbed bands and one exemplar: the dot opens its query by trace ID, the
// objective's line is named, and the table view toggles.
test('obs_030 latency heatmap', async () => {
  await page.setViewportSize({ width: 1280, height: 800 });
  await page.goto('/#/');
  await page.getByRole('button', { name: 'Advanced', exact: true }).click();
  await page.getByTestId('time-heatmap-tab').click();
  const lh = page.getByTestId('latency-heatmap');
  await expect(lh.getByTestId('latency-heatmap-canvas')).toBeVisible();
  const now = Math.floor(Date.now() / 1000);
  const start = now - (now % 60) - 120;
  const row = (i: number, n: number) => Array.from({ length: 17 }, (_, j) => (j === i ? n : 0));
  await page.route('**/api/v1/stats/latency/heatmap*', (route) =>
    route.fulfill({
      json: {
        from: new Date((start - 3600) * 1000).toISOString(), to: new Date(now * 1000).toISOString(), step: 'minute', by: 'path',
        boundsUs: [50, 100, 250, 500, 1000, 2500, 5000, 10000, 25000, 50000, 100000, 250000, 500000, 1000000, 2500000, 5000000],
        starts: [start, start + 60, start + 120],
        series: { cache: [row(0, 900), row(0, 880), row(0, 910)], upstream: [row(9, 90), row(12, 10), row(9, 85)] },
        partial: false,
      },
    }),
  );
  const trace = '0123456789abcdef0123456789abcdef';
  await page.route('**/api/v1/stats/latency/exemplars*', (route) =>
    route.fulfill({
      json: {
        items: [{ traceId: trace, time: new Date((start + 60) * 1000).toISOString(), tsUnixMicros: (start + 61) * 1_000_000, latencyUs: 400000, path: 'upstream', upstream: 'quad9-1' }],
      },
    }),
  );
  await lh.getByRole('button', { name: '1 h', exact: true }).click();
  await expect(lh).toContainText('the latency objective (250 ms)');
  await lh.getByRole('button', { name: 'Table', exact: true }).click();
  await expect(lh.getByTestId('latency-heatmap-table')).toContainText('900');
  await lh.getByRole('button', { name: 'Grid', exact: true }).click();
  const dot = lh.getByTestId('exemplar');
  await expect(dot).toHaveCount(1);
  await expect(dot).toHaveAttribute('aria-label', /400 ms upstream via quad9-1/);
  await dot.click();
  await expect(page).toHaveURL(new RegExp(`#/queries\\?trace=${trace}`));
  await page.unroute('**/api/v1/stats/latency/heatmap*');
  await page.unroute('**/api/v1/stats/latency/exemplars*');
  await page.goto('/#/');
  await page.getByRole('button', { name: 'Simple', exact: true }).click();
});

// REQ: OBS-032 (T14.6) — the query flow: the real server's answer draws; then a stubbed flow:
// four stages; the layout's invariants on the drawn SVG (each full column's nodes add up to
// the total on one scale, nodes don't overlap, bands stay within their nodes); a band's hover
// shows its share; `blocked` opens Lists; small nodes fold; the table view; the phone layout
// stacks; a device's truncated read is said.
test('obs_032 flow', async () => {
  await page.setViewportSize({ width: 1280, height: 800 });
  await page.goto('/#/flow');
  await expect(page.getByRole('heading', { name: /^Flow/ })).toBeVisible();
  await expect(page.getByTestId('flow')).not.toContainText('Loading');
  const node = (id: string, stage: string, name: string, count: number, deadEnd = 0) => ({ id, stage, name, count, deadEnd });
  const link = (source: string, target: string, count: number, failure = false) => ({ source, target, count, failure });
  const flow = (client?: string, truncated = false) => ({
    from: new Date(Date.now() - 3_600_000).toISOString(), to: new Date().toISOString(), client,
    source: client ? 'querylog' : 'buckets', total: 1000, partial: false, truncated,
    nodes: [
      node('group:default', 'group', 'default', 630), node('group:kids', 'group', 'kids', 368), node('group:guests', 'group', 'guests', 2),
      node('status:cached', 'status', 'cached', 500), node('status:forwarded', 'status', 'forwarded', 250),
      node('status:blocked', 'status', 'blocked', 200), node('status:servfail', 'status', 'servfail', 40), node('status:dropped', 'status', 'dropped', 10, 10),
      node('upstream:quad9-1', 'upstream', 'quad9-1', 200), node('upstream:quad9-2', 'upstream', 'quad9-2', 90),
      node('rcode:NOERROR', 'rcode', 'NOERROR', 750), node('rcode:NXDOMAIN', 'rcode', 'NXDOMAIN', 200), node('rcode:SERVFAIL', 'rcode', 'SERVFAIL', 40),
    ],
    links: [
      link('group:default', 'status:cached', 400), link('group:kids', 'status:cached', 100), link('group:default', 'status:forwarded', 80),
      link('group:kids', 'status:forwarded', 168), link('group:guests', 'status:forwarded', 2), link('group:kids', 'status:blocked', 100),
      link('group:default', 'status:blocked', 100), link('group:default', 'status:servfail', 40, true), link('group:default', 'status:dropped', 10),
      link('status:cached', 'rcode:NOERROR', 500), link('status:blocked', 'rcode:NXDOMAIN', 200),
      link('status:forwarded', 'upstream:quad9-1', 160), link('status:forwarded', 'upstream:quad9-2', 90), link('status:servfail', 'upstream:quad9-1', 40),
      link('upstream:quad9-1', 'rcode:NOERROR', 160), link('upstream:quad9-1', 'rcode:SERVFAIL', 40, true), link('upstream:quad9-2', 'rcode:NOERROR', 90),
    ],
  });
  await page.route('**/api/v1/stats/flow*', (route) => {
    const client = new URL(route.request().url()).searchParams.get('client') ?? undefined;
    return route.fulfill({ json: flow(client, !!client) });
  });
  await page.getByRole('button', { name: '6 h', exact: true }).click();
  const svg = page.getByTestId('flow-svg');
  await expect(svg).toBeVisible();
  await expect(page.getByTestId('flow')).toContainText('1,000 answers');
  const nodes = () =>
    svg.getByTestId('flow-node').evaluateAll((els) =>
      els.map((e) => ({ id: e.dataset.id ?? '', col: Number(e.dataset.col), x: Number(e.dataset.x), y: Number(e.dataset.y), w: Number(e.dataset.w), h: Number(e.dataset.h) })),
    );
  let ns = await nodes();
  expect(new Set(ns.map((n) => n.col))).toEqual(new Set([0, 1, 2, 3]));
  // guests (0.2 %) folds into "other": one small node in its stage stays itself.
  expect(ns.some((n) => n.id === 'group:guests')).toBe(true);
  const scale = Number(await svg.getAttribute('data-scale'));
  for (const col of [0, 1]) {
    const sum = ns.filter((n) => n.col === col).reduce((a, n) => a + n.h, 0);
    expect(Math.abs(sum - 1000 * scale)).toBeLessThan(0.01);
  }
  for (const col of [0, 1, 2, 3]) {
    const c = ns.filter((n) => n.col === col).sort((a, b) => a.y - b.y);
    for (let i = 1; i < c.length; i++) expect(c[i].y).toBeGreaterThanOrEqual(c[i - 1].y + c[i - 1].h - 0.01);
  }
  // The upstreams sit level with what feeds them (forwarded, servfail), not at the top; and the
  // diagram takes the window's height (800 px here), not the 320 px minimum.
  const fwd = ns.find((n) => n.id === 'status:forwarded')!;
  expect(Math.min(...ns.filter((n) => n.col === 2).map((n) => n.y))).toBeGreaterThanOrEqual(fwd.y - 0.01);
  expect(Number(await svg.getAttribute('height'))).toBeGreaterThan(340);
  const links = await svg.getByTestId('flow-link').evaluateAll((els) =>
    els.map((e) => ({ s: e.dataset.source ?? '', t: e.dataset.target ?? '', w: Number(e.dataset.width), y0: Number(e.dataset.y0), y1: Number(e.dataset.y1) })),
  );
  expect(links.length).toBe(17);
  const byId = new Map(ns.map((n) => [n.id, n]));
  for (const l of links) {
    const s = byId.get(l.s)!;
    const t = byId.get(l.t)!;
    expect(l.y0 - l.w / 2).toBeGreaterThanOrEqual(s.y - 0.01);
    expect(l.y0 + l.w / 2).toBeLessThanOrEqual(s.y + s.h + 0.01);
    expect(l.y1 - l.w / 2).toBeGreaterThanOrEqual(t.y - 0.01);
    expect(l.y1 + l.w / 2).toBeLessThanOrEqual(t.y + t.h + 0.01);
  }
  // A band's share: of every answer and of its source.
  await svg.locator('[data-source="upstream:quad9-1"][data-target="rcode:SERVFAIL"]').focus();
  await expect(page.getByTestId('flow-tip')).toContainText('quad9-1 → SERVFAIL: 40 (4.0 % of all · 20.0 % of quad9-1)');
  // REQ: UI-*, T33.6 — the focused band's ring: 2px of focus-ring, 2px outside the band (a gap of
  // the surface, then the ring), under it.
  const ringed = await svg.evaluate((s) => {
    const probe = document.createElement('div');
    probe.style.color = 'var(--focus)';
    document.body.append(probe);
    const want = getComputedStyle(probe).color;
    probe.remove();
    const band = document.activeElement as SVGPathElement;
    const ring = s.querySelector('[data-testid="flow-focus-ring"]') as SVGPathElement | null;
    const gap = ring?.nextElementSibling as SVGPathElement | null;
    const w = (e: Element | null | undefined) => (e ? parseFloat(getComputedStyle(e).strokeWidth) : NaN);
    return { want, stroke: ring ? getComputedStyle(ring).stroke : '', same: ring?.getAttribute('d') === band.getAttribute('d'), out: [w(ring) - w(band), w(gap) - w(band)].map((x) => Math.round(x * 100) / 100) };
  });
  expect(ringed).toEqual({ want: ringed.want, stroke: ringed.want, same: true, out: [8, 4] });
  // Show small keeps everything; a link opens the page behind a node.
  await page.getByTestId('flow-small').check();
  ns = await nodes();
  expect(ns.length).toBe(13);
  // A click on a band shows its tip without focusing it (no focus box, the tip stays put).
  const band = svg.locator('[data-source="upstream:quad9-1"][data-target="rcode:SERVFAIL"]');
  await band.evaluate((el) => (el as SVGElement).blur());
  const pt = await band.evaluate((el) => {
    const p = el as SVGPathElement;
    const q = p.getPointAtLength(p.getTotalLength() / 2);
    const m = p.getScreenCTM()!;
    return { x: q.x * m.a + m.e, y: q.y * m.d + m.f };
  });
  await page.mouse.click(pt.x, pt.y);
  await expect(page.getByTestId('flow-tip')).toBeVisible();
  expect(await page.evaluate(() => document.activeElement?.getAttribute('data-testid'))).not.toBe('flow-link');
  // Live says when it last read the numbers.
  await expect(page.getByTestId('flow-updated')).toHaveCount(0);
  await page.getByTestId('flow-live').check();
  await expect(page.getByTestId('flow-updated')).toContainText('every 15 s');
  await page.getByTestId('flow-live').uncheck();
  await page.getByRole('button', { name: 'Table', exact: true }).click();
  await expect(page.getByTestId('flow-table')).toContainText('Upstream quad9-1');
  await expect(page.getByTestId('flow-table').locator('tr.fail')).toHaveCount(2);
  await page.getByRole('button', { name: 'Diagram', exact: true }).click();
  // A link to the page it's on (or Back) changes what it shows.
  await page.goto('/#/flow?window=24h');
  await expect(page.getByRole('button', { name: '24 h', exact: true })).toHaveAttribute('aria-pressed', 'true');
  await expect(svg).toBeVisible();
  await svg.locator('[data-id="status:blocked"]').click();
  await expect(page).toHaveURL(/#\/lists/);
  // The phone layout: stages top to bottom.
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto('/#/flow');
  await expect(page.getByTestId('flow-svg')).toHaveAttribute('data-vertical', '1');
  ns = await nodes();
  expect(new Set(ns.filter((n) => n.col === 0).map((n) => n.y)).size).toBe(1);
  expect(Math.max(...ns.filter((n) => n.col === 3).map((n) => n.y))).toBeGreaterThan(ns[0].y);
  // A device: from the query log; a capped read is said.
  await page.setViewportSize({ width: 1280, height: 800 });
  await page.getByRole('button', { name: 'Device', exact: true }).click();
  await page.getByTestId('flow-client').fill('10.20.2.14');
  await page.getByRole('button', { name: 'Show', exact: true }).click();
  await expect(page.getByTestId('flow')).toContainText('from the query log');
  await expect(page.getByTestId('flow-truncated')).toBeVisible();
  await page.unroute('**/api/v1/stats/flow*');
});

// REQ: OBS-028 (ADR-128) — Cluster → Compare: the tab says a node is odd, the odd cell is
// outlined with its finding, a smaller base is a grey note, the table shows the intervals, a
// phone shows one metric at a time, and one node has nothing to compare.
test('obs_028 node compare', async () => {
  await page.setViewportSize({ width: 1280, height: 800 });
  const member = (nodeId: string, site: string, o: Record<string, unknown> = {}) => ({
    nodeId, site, ephemeral: false, witness: false, protocol: 4, role: 'replica', thisNode: false, eligible: true, version: '0.5.0',
    up: true, connected: true, link: 'inbound', lastSeenSecondsAgo: 1, rttMs: 3, configSeq: 9, configLag: 0, ready: true,
    qps: 10, servfailPercent: 0, upstreamP90Ms: 12, uptimeSeconds: 3600, ...o,
  });
  const view = {
    enabled: true, clusterId: 'c1', name: 'home', thisNode: 'id-a', newestConfigSeq: 9, healthy: true, checks: [],
    events: [], conflicts: [], authority: 'primary',
    nodes: [member('id-a', 'a', { role: 'primary', thisNode: true, link: 'self', rttMs: null }), member('id-b', 'b'), member('id-c', 'c')],
  };
  const series = (v: number) => ({
    start: [0, 360, 720], servfailPct: [v, v, null], slowPct: [0, 0, 0], fromCachePct: [60, 61, 62], upstreamFailPct: [1, 1, 1],
    qps: [20, 21, 22], p99Us: [4000, 4100, null],
  });
  const numbers = (id: string, label: string, servfail: number, o: Record<string, unknown> = {}) => ({
    nodeId: id, label, thisNode: id === 'id-a', answered: 2_880_000, servfail: 0, slow: 0, fromCache: 0, upstreamQueries: 1000,
    upstreamFailures: 10, qps: 33.3, servfailPct: servfail, slowPct: 0, fromCachePct: 61, upstreamFailPct: 1,
    intervals: { servfailPct: [servfail - 0.05, servfail + 0.05] }, p50Us: 900, p99Us: 4100, series: series(servfail), ...o,
  });
  const compare = (single = false) => ({
    from: new Date(Date.now() - 86_400_000).toISOString(), to: new Date().toISOString(), step: 'minute', partial: false,
    nodes: single ? [numbers('id-a', 'a', 0.05)] : [numbers('id-a', 'a', 0.05), numbers('id-b', 'b', 0.3, { answered: 38_000 }), numbers('id-c', 'c', 0.75)],
    findings: single
      ? []
      : [
          { metric: 'servfailPct', nodeId: 'id-c', label: 'c', level: 'odd', observed: 0.75, others: 0.05, spread: 0.074,
            oddSince: '2026-10-16T15:00:00.000Z', detail: 'c SERVFAIL share is 0.75 %, higher than the others\' 0.050 %, since 2026-10-16T15:00:00.000Z' },
          { metric: 'servfailPct', nodeId: 'id-b', label: 'b', level: 'note', observed: 0.3, others: 0.05, spread: 0.074,
            detail: 'same bad count as the others (15 vs 14) on 13 % of the traffic: a smaller base, not more failures' },
        ],
  });
  let single = false;
  const asked: string[] = [];
  await page.route('**/api/v1/cluster', (route) => route.fulfill({ json: view }));
  await page.route('**/api/v1/cluster/rollout', (route) => route.fulfill({ json: { fromPrimary: true, canaries: [], bakeSecs: 300, stable: '0.5.0', stage: 'none', nodes: [] } }));
  await page.route('**/api/v1/cluster/versions', (route) => route.fulfill({ json: { items: [], history: 20 } }));
  await page.route('**/api/v1/cluster/compare*', (route) => {
    asked.push(new URL(route.request().url()).searchParams.get('from') ?? '');
    return route.fulfill({ json: compare(single) });
  });
  await page.goto('/#/cluster');
  // The tab says so from any tab.
  await expect(page.getByTestId('tab-compare')).toContainText('1 odd');
  await expect(page.getByTestId('tab-compare').locator('.count.alert')).toBeVisible();
  await page.getByTestId('tab-compare').click();
  const grid = page.getByTestId('compare-grid');
  await expect(grid).toBeVisible();
  await expect(grid.getByTestId('compare-cell')).toHaveCount(21); // 7 metrics × 3 nodes
  const odd = grid.locator('[data-testid="compare-cell"][data-node="c"][data-metric="servfailPct"]');
  await expect(odd).toHaveClass(/odd/);
  await expect(odd).toContainText('0.75 %');
  await expect(odd.getByTestId('compare-finding')).toContainText('higher than the others');
  await expect(grid.locator('.cell.odd')).toHaveCount(1);
  const note = grid.locator('[data-testid="compare-cell"][data-node="b"][data-metric="servfailPct"]');
  await expect(note).not.toHaveClass(/odd/);
  await expect(note.locator('.finding.note')).toContainText('smaller base');
  // The window is remembered and asked for.
  await page.getByRole('button', { name: '7 d', exact: true }).click();
  await expect.poll(() => asked.at(-1)).toBe('-7d');
  // The table, with the intervals.
  await page.getByTestId('compare-table-toggle').check();
  const table = page.getByTestId('compare-table');
  await expect(table.locator('tbody tr')).toHaveCount(3);
  await expect(table.locator('td.odd')).toHaveCount(1);
  await expect(table.locator('td.odd')).toContainText('0.75 % (0.70–0.80 %)');
  await page.getByTestId('compare-table-toggle').uncheck();
  // A phone: one metric at a time, nodes as cards.
  await page.setViewportSize({ width: 390, height: 800 });
  await expect(page.getByTestId('compare-metric')).toBeVisible();
  await expect(grid.getByTestId('compare-cell')).toHaveCount(3);
  await page.getByTestId('compare-metric').selectOption('p99Us');
  await expect(grid.getByTestId('compare-cell').first()).toHaveAttribute('data-metric', 'p99Us');
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1)).toBe(true);
  await page.setViewportSize({ width: 1280, height: 800 });
  // One node reporting: nothing to compare.
  single = true;
  await page.getByRole('button', { name: '1 h', exact: true }).click();
  await expect(page.getByTestId('compare-single')).toContainText('One node; nothing to compare');
  await page.getByRole('button', { name: '24 h', exact: true }).click();
  await page.unroute('**/api/v1/cluster');
  await page.unroute('**/api/v1/cluster/rollout');
  await page.unroute('**/api/v1/cluster/versions');
  await page.unroute('**/api/v1/cluster/compare*');
});

// REQ: OBS-031 (ADR-131) — the rhythm strip: a device's drawer shows a time-sync loop as one
// outlined bin with "every 2.5 s", a row opens the query log, a table view, both themes; a
// beacon finding carries its strip.
test('obs_031 rhythm strip', async () => {
  await page.setViewportSize({ width: 1280, height: 800 });
  const bins = (at: number, n: number, smear = false) =>
    Array.from({ length: 24 }, (_, i) => (smear ? (i >= 2 && i <= 12 ? 30 : 0) : i === at ? n : i === at + 1 ? Math.round(n / 50) : 0));
  await page.route('**/api/v1/stats/top?*', (route) => {
    const kind = new URL(route.request().url()).searchParams.get('kind');
    return kind === 'clients' ? route.fulfill({ json: { items: [{ key: '10.20.2.14', count: 1440, groups: ['default'] }] } }) : route.fallback();
  });
  await page.route('**/api/v1/clients/*/rhythm', (route) =>
    route.fulfill({
      json: {
        client: '10.20.2.14', available: true, binsS: [1, 1.5, 2.2, 3.3, 5, 7.5, 11, 17, 25, 38, 56, 84, 126, 190, 285, 427, 640, 960, 1440, 2160, 3240, 4860, 7290],
        domains: [
          { domain: 'ntp.org', hour: bins(3, 1400), recent: bins(3, 2100), dominantBin: 3, dominantSharePct: 98, period: 'every 2.5 s', regularHours: 0, knownPeriodic: true, meanPerHour: 1440 },
          { domain: 'example.com', hour: bins(0, 0, true), recent: bins(0, 0, true), dominantBin: 2, dominantSharePct: 9.1, regularHours: 0, knownPeriodic: false, meanPerHour: 300 },
        ],
      },
    }),
  );
  await page.goto('/#/clients');
  await page.getByTestId('open-rhythm').first().click();
  const strip = page.getByTestId('rhythm');
  await expect(strip.getByTestId('rhythm-row')).toHaveCount(2);
  await expect(strip.getByTestId('rhythm-period')).toHaveText('every 2.5 s');
  await expect(strip.locator('rect.dominant')).toHaveCount(1);
  await expect(strip.locator('rect.dominant')).toHaveAttribute('data-bin', '3');
  await expect(strip).toContainText('usual');
  // This hour and recent switch the arrays.
  await strip.getByRole('button', { name: 'This hour' }).click();
  await expect(strip.locator('rect.dominant')).toHaveAttribute('data-n', '1400');
  // The table: the bins as numbers.
  await strip.getByTestId('rhythm-table-toggle').check();
  await expect(strip.getByTestId('rhythm-table').locator('tbody tr')).toHaveCount(2);
  await expect(strip.getByTestId('rhythm-table').locator('tbody tr').first()).toContainText('1,400');
  await strip.getByTestId('rhythm-table-toggle').uncheck();
  // Both themes draw it.
  for (const theme of ['dark', 'light']) {
    await page.evaluate((t) => (document.documentElement.dataset.theme = t), theme);
    await expect(strip.locator('rect.dominant')).toBeVisible();
  }
  // A row opens that device's queries for the name.
  await strip.getByTestId('rhythm-row').first().click();
  await expect(page).toHaveURL(/#\/queries\?.*client=10\.20\.2\.14.*name=ntp\.org/);
  await page.unroute('**/api/v1/stats/top?*');
  await page.unroute('**/api/v1/clients/*/rhythm');

  // A beacon finding shows its strip inline.
  await page.route('**/api/v1/analytics/anomalies?*', (route) =>
    route.fulfill({
      json: {
        items: [{
          id: '6a2c0e00b1b2c3d4', kind: 'beacon', client: '192.168.1.40', domain: 'c2.example', windowStart: '2026-10-08T10:00:00.000Z',
          windowSeconds: 14400, observed: 300, baseline: 0, spread: 1.2, threshold: 15, detail: 'every 300 s ± 1.2 s for 4 hours; it wasn\'t periodic before',
          rhythm: bins(15, 48),
        }],
      },
    }),
  );
  await page.goto('/#/anomalies');
  await expect(page.getByTestId('anomaly').getByTestId('rhythm').locator('rect.dominant')).toHaveAttribute('data-bin', '15');
  await page.unroute('**/api/v1/analytics/anomalies?*');
  await page.evaluate(() => delete document.documentElement.dataset.theme);
});

// REQ: OBS-034 (ADR-134) — a device's day: the Timeline tab draws the lanes, an event opens its
// page, a lane label opens the query log, the table view, both themes, and the deep link from a
// finding.
test('obs_034 device timeline', async () => {
  await page.setViewportSize({ width: 1280, height: 800 });
  const day = Math.floor(Date.now() / 1000 / 86_400) * 86_400 - 86_400;
  const bins = Array.from({ length: 288 }, (_, i) => day + i * 300);
  const counts = (f: (i: number) => number) => bins.map((_, i) => f(i));
  const zero = counts(() => 0);
  const timeline = {
    client: '10.20.2.14', from: new Date(day * 1000).toISOString(), to: new Date((day + 86_400) * 1000).toISOString(), binSeconds: 300, bins,
    lanes: [
      { domain: 'ntp.org', counts: counts((i) => (i >= 168 && i < 222 ? 120 : 0)), blocked: zero, slow: zero, total: 6480, blockedTotal: 0, firstSeenTime: new Date((day + 168 * 300) * 1000).toISOString() },
      { domain: 'example.com', counts: counts((i) => (i % 12 === 0 ? 10 : 0)), blocked: zero, slow: counts((i) => (i === 2 ? 2 : 0)), total: 240, blockedTotal: 0 },
      { domain: 'ads.example', counts: counts((i) => ([30, 100, 200].includes(i) ? 12 : 0)), blocked: counts((i) => ([30, 100, 200].includes(i) ? 12 : 0)), slow: zero, total: 36, blockedTotal: 36 },
    ],
    queries: counts((i) => (i >= 168 && i < 222 ? 120 : 0) + (i % 12 === 0 ? 10 : 0)),
    p99Ms: counts((i) => (i % 12 === 0 ? 14 : 0)).map((v) => (v ? v : null)),
    events: [
      { time: new Date((day + 168 * 300) * 1000).toISOString(), timeUnixSeconds: day + 168 * 300, kind: 'firstSeen', summary: 'first query to ntp.org', href: '#/queries?client=10.20.2.14&name=ntp.org&match=suffix', domain: 'ntp.org' },
      ...[30, 100, 200].map((i) => ({ time: new Date((day + i * 300) * 1000).toISOString(), timeUnixSeconds: day + i * 300, kind: 'blockedBurst', summary: '12 blocked in 5 min, mostly ads.example', href: '#/queries?client=10.20.2.14&status=blocked', domain: 'ads.example' })),
      // REQ: OBS-034 (T14.12) — the device's identity changed.
      { time: new Date((day + 170 * 300) * 1000).toISOString(), timeUnixSeconds: day + 170 * 300, kind: 'identity', summary: 'now looks like Roku player (was unknown)', href: '#/clients?device=10.20.2.14&view=rhythm' },
    ],
    markers: [{ t: new Date((day + 3600) * 1000).toISOString(), tUnixMs: (day + 3600) * 1000, kind: 'config.applied', summary: 'configuration 312 applied' }],
    source: 'querylog', truncated: false,
  };
  const asked: string[] = [];
  await page.route('**/api/v1/clients/*/timeline*', (route) => {
    asked.push(new URL(route.request().url()).searchParams.get('from') ?? '');
    return route.fulfill({ json: timeline });
  });
  await page.route('**/api/v1/clients/*/rhythm', (route) => route.fulfill({ json: { client: '10.20.2.14', available: true, binsS: [], domains: [] } }));
  await page.goto('/#/clients?device=10.20.2.14&view=timeline');
  const tl = page.getByTestId('timeline');
  const cv = tl.getByTestId('timeline-canvas');
  await expect(cv).toHaveAttribute('data-lanes', '3');
  await expect(cv).toHaveAttribute('data-bins', '288');
  await expect(tl.getByTestId('timeline-lane')).toHaveCount(3);
  await expect(tl.getByTestId('timeline-event')).toHaveCount(5);
  await expect(tl.locator('[data-testid="timeline-event"][data-kind="identity"]')).toHaveClass(/diamond/);
  await expect(tl.locator('[data-testid="timeline-event"][data-kind="blockedBurst"]')).toHaveCount(3);
  await expect(tl.getByTestId('timeline-marker')).toHaveCount(1);
  await expect(tl.getByTestId('timeline-new')).toHaveCount(1);
  // Drawn, in both themes.
  const inked = () =>
    cv.evaluate((c: HTMLCanvasElement) => {
      const d = c.getContext('2d')!.getImageData(0, 0, c.width, c.height).data;
      let n = 0;
      for (let i = 3; i < d.length; i += 4) if (d[i] > 0) n++;
      return n;
    });
  for (const theme of ['dark', 'light']) {
    await page.evaluate((t) => (document.documentElement.dataset.theme = t), theme);
    await expect.poll(inked).toBeGreaterThan(500);
  }
  await page.evaluate(() => delete document.documentElement.dataset.theme);
  // Hover a cell in ntp.org's lane.
  const box = (await cv.boundingBox())!;
  await page.mouse.move(box.x + (180.5 / 288) * box.width, box.y + 9);
  await expect(tl.getByTestId('timeline-tip')).toContainText('ntp.org · 120 queries, 0 blocked');
  // The window is asked for.
  await tl.getByRole('button', { name: '7 d', exact: true }).click();
  await expect.poll(() => asked.at(-1)).toBe('-7d');
  // The table.
  await tl.getByTestId('timeline-table-toggle').check();
  await expect(tl.getByTestId('timeline-table').locator('tbody tr')).toHaveCount(4);
  await tl.getByTestId('timeline-table-toggle').uncheck();
  // A lane label opens the query log for the device and the name.
  await tl.getByTestId('timeline-lane').first().click();
  await expect(page).toHaveURL(/#\/queries\?.*client=10\.20\.2\.14.*name=ntp\.org/);
  // An event opens its page.
  await page.goto('/#/clients?device=10.20.2.14&view=timeline');
  await tl.locator('[data-testid="timeline-event"][data-kind="blockedBurst"]').first().click();
  await expect(page).toHaveURL(/#\/queries\?client=10\.20\.2\.14&status=blocked/);
  // A finding links to the device's day.
  await page.route('**/api/v1/analytics/anomalies?*', (route) =>
    route.fulfill({ json: { items: [{ id: '6a2c0e00c1b2c3d4', kind: 'rate_spike', client: '10.20.2.14', windowStart: new Date(day * 1000).toISOString(), windowSeconds: 3600, observed: 4000, baseline: 100, spread: 20, threshold: 300, detail: '4000 queries in an hour' }] } }),
  );
  await page.goto('/#/anomalies');
  await page.getByTestId('see-the-day').click();
  await expect(page).toHaveURL(/#\/clients\?device=10\.20\.2\.14&view=timeline/);
  await expect(page.getByTestId('timeline-canvas')).toBeVisible();
  await page.unroute('**/api/v1/analytics/anomalies?*');
  await page.unroute('**/api/v1/clients/*/timeline*');
  await page.unroute('**/api/v1/clients/*/rhythm');
});

// REQ: OBS-035 (ADR-135) — the wall's moving parts, checked directly: tweens land exactly on
// both layouts, the flow never carries more than 60 particles, the ticker keeps the newest 50,
// and the animation loop stops while the tab is hidden.
test('obs_035 wall helpers', async () => {
  expect(parsePanels('slo,flow,nope,slo')).toEqual(['slo', 'flow']);
  expect(parsePanels(null)).toEqual(['map', 'flow', 'slo', 'latency', 'heat', 'kpi']);
  expect([parseEvery('5'), parseEvery('1'), parseEvery(null), parseEvery('9999')]).toEqual([5, 5, 20, 600]);
  expect([motionAllowed(null, false), motionAllowed('off', false), motionAllowed(null, true)]).toEqual([true, false, false]);
  const a = new Map<string, Box>([['x', { x: 0, y: 0, w: 10, h: 10 }], ['y', { x: 10, y: 0, w: 5, h: 10 }]]);
  const b = new Map<string, Box>([['x', { x: 2, y: 3, w: 8, h: 7 }], ['z', { x: 20, y: 20, w: 4, h: 4 }]]);
  expect(lerpBoxes(a, b, 1)).toEqual(b);
  const t0 = lerpBoxes(a, b, 0);
  expect(t0.get('x')).toEqual(a.get('x'));
  expect(t0.get('z')).toEqual({ x: 22, y: 22, w: 0, h: 0 });
  expect(t0.has('y')).toBe(false);
  const counts = Array.from({ length: 200 }, (_, i) => 1 + (i % 7) * 100);
  expect(dotBudget(counts).reduce((x, y) => x + y, 0)).toBeLessThanOrEqual(60);
  const p = new Particles();
  p.plan(counts);
  for (let i = 0; i < 100; i++) p.step(0.016);
  expect(p.dots.length).toBeLessThanOrEqual(60);
  expect(p.dots.every((d) => d.t >= 0 && d.t < 1)).toBe(true);
  const ticker = new Ticker<number>(50);
  for (let s = 0; s < 10; s++) ticker.push(Array.from({ length: 1000 }, (_, i) => s * 1000 + i));
  expect(ticker.items.length).toBe(50);
  expect(ticker.items[0]).toBe(9999);
  expect(ticker.items[49]).toBe(9950);
  // The loop: hidden stops it within the frame, visible resumes it.
  let hidden = false;
  let frames = 0;
  const queue = new Map<number, (t: number) => void>();
  let next = 1;
  const loop = new Loop(() => frames++, {
    request: (cb) => (queue.set(next, cb), next++),
    cancel: (id) => void queue.delete(id),
    hidden: () => hidden,
  });
  const run = (t: number) => {
    const cbs = [...queue.entries()];
    queue.clear();
    for (const [, cb] of cbs) cb(t);
  };
  loop.start();
  run(16);
  run(32);
  expect(frames).toBe(2);
  hidden = true;
  loop.visibility();
  expect(loop.running).toBe(false);
  run(48);
  expect(frames).toBe(2);
  hidden = false;
  loop.visibility();
  run(64);
  expect(frames).toBe(3);
  loop.stop();
  expect(loop.running).toBe(false);

  // REQ: OBS-035 (T14.15) — layouts for the screen: the class, then slots that each fit their
  // panel, never overlap, stay inside the area, and fill most of it; a large screen shows all six
  // at once; a phone rotates one.
  expect([screenClass(390, 844), screenClass(1080, 1920), screenClass(1920, 1080), screenClass(2560, 1080), screenClass(2560, 1440)]).toEqual(
    ['compact', 'portrait', 'standard', 'ultrawide', 'large'],
  );
  expect(screenClass(2250, 1100)).toBe('standard');
  expect(screenClassStable(2250, 1100, 'ultrawide')).toBe('ultrawide'); // just under 2.1 × as wide: kept
  expect(screenClassStable(1800, 1100, 'ultrawide')).toBe('standard');
  expect(parseLayout('grid')).toBe('grid');
  expect(parseLayout('nope')).toBe('auto');
  const all = parsePanels(null);
  for (const [w, h, slots] of [[390, 760, 1], [1080, 1700, 2], [1840, 900, 3], [2480, 900, 5], [1950, 1300, 3], [3800, 2000, 6]] as const) {
    const l = chooseLayout(w, h, all);
    expect(l.slots.length, `${w}x${h}`).toBe(slots);
    let area = 0;
    l.slots.forEach((a, i) => {
      area += a.w * a.h;
      expect(a.x >= 0 && a.y >= 0 && a.x + a.w <= w + 0.5 && a.y + a.h <= h + 0.5).toBe(true);
      for (const p of a.panels) if (l.slots.length > 1 && a.panels.length === 1) expect(a.w >= PANEL_MIN[p].w && a.h >= PANEL_MIN[p].h).toBe(true);
      l.slots.slice(i + 1).forEach((b) => {
        const overlap = Math.max(0, Math.min(a.x + a.w, b.x + b.w) - Math.max(a.x, b.x)) * Math.max(0, Math.min(a.y + a.h, b.y + b.h) - Math.max(a.y, b.y));
        expect(overlap, `${w}x${h} slots ${i}`).toBeLessThan(1);
      });
    });
    expect(area / (w * h), `${w}x${h} fill`).toBeGreaterThan(0.99);
    // Every panel is somewhere.
    expect(new Set(l.slots.flatMap((x) => x.panels)).size).toBe(all.length);
  }
  const large = chooseLayout(2000, 1300, all, 'large');
  expect(large.slots.length).toBe(6);
  expect(large.slots.every((x) => x.panels.length === 1)).toBe(true);
  expect(large.tailSide).toBe(true);
  // A TV: the map leads, the small panels take the side.
  const tv = chooseLayout(1840, 900, all);
  expect(tv.slots[0].panels[0]).toBe('map');
  expect(tv.slots.slice(1).map((x) => x.panels[0]).sort()).toEqual(['kpi', 'slo']);
  // Portrait: the big lower slot takes a big panel, not a small one.
  expect(chooseLayout(1080, 1700, all).slots[1].panels[0]).toBe('flow');
  expect(chooseLayout(1840, 900, all, 'single').slots.length).toBe(1);
  // One loop for every panel.
  const q2 = new Map<number, (t: number) => void>();
  let n2 = 1;
  const hub = new FrameHub({ request: (cb) => (q2.set(n2, cb), n2++), cancel: (id) => void q2.delete(id), hidden: () => false });
  let ca = 0;
  let cb = 0;
  const offA = hub.add(() => ca++);
  const offB = hub.add(() => cb++);
  const run2 = (t: number) => {
    const fns = [...q2.values()];
    q2.clear();
    for (const fn of fns) fn(t);
  };
  run2(16);
  expect([ca, cb, q2.size]).toEqual([1, 1, 1]);
  offA();
  run2(32);
  expect([ca, cb]).toEqual([1, 2]);
  offB();
  expect(hub.running).toBe(false);
});

// REQ: OBS-035 (ADR-135) — the wall display: no navigation, the panels the URL names in its
// order, rotation on the timer, every panel renders, Space pauses, motion=off animates nothing,
// Esc goes back to the dashboard.
test('obs_035 wall', async () => {
  await page.setViewportSize({ width: 1280, height: 800 });
  await page.goto('/#/wall?panels=slo,flow&every=5');
  const wall = page.getByTestId('wall');
  await expect(wall).toBeVisible();
  await expect(page.locator('nav.side')).toHaveCount(0);
  await expect(page.locator('header.top')).toHaveCount(0);
  await expect(page.getByTestId('wall-order').locator('li')).toHaveCount(2);
  expect(await page.getByTestId('wall-order').locator('li').evaluateAll((els) => els.map((e) => (e as HTMLElement).dataset.panel))).toEqual(['slo', 'flow']);
  await expect(page.getByTestId('wall-panel-slo')).toBeVisible();
  await expect(page.getByTestId('wall-tail')).toBeVisible();
  // Rotates after 5 s.
  await expect(page.getByTestId('wall-panel-flow')).toBeVisible({ timeout: 9000 });
  // Every panel renders.
  // One at a time (`layout=single`): every panel renders in turn.
  await page.goto('/#/wall?layout=single');
  // Wait for the first measure of the area before moving, then assert the panel after each key.
  await expect.poll(async () => (await page.getByTestId('wall-area').boundingBox())?.height ?? 0).toBeGreaterThan(0);
  const order = ['map', 'flow', 'slo', 'latency', 'heat', 'kpi'];
  for (const [i, id] of order.entries()) {
    await expect(page.getByTestId('wall-slot')).toHaveAttribute('data-panel', id);
    await expect(page.getByTestId(`wall-panel-${id}`)).toBeVisible();
    await expect(page.getByTestId(`wall-${id}`)).toBeAttached();
    await page.keyboard.press('ArrowRight');
    await expect(page.getByTestId('wall-slot')).toHaveAttribute('data-panel', order[(i + 1) % order.length]);
  }
  await expect(page.getByTestId('wall-panel-map')).toBeVisible();
  // The latency heatmap's controls are hidden on the wall.
  for (let i = 0; i < 3; i++) await page.keyboard.press('ArrowLeft');
  await expect(page.getByTestId('wall-latency').locator('.controls')).toHaveCount(0);
  // Space pauses.
  await page.keyboard.press(' ');
  await expect(page.getByTestId('wall-paused')).toBeVisible();
  await expect(page.getByTestId('wall-progress')).toHaveCount(0);
  // No motion: no animation classes.
  await page.goto('/#/wall?motion=off&panels=map,flow');
  await expect(wall).toHaveAttribute('data-motion', 'off');
  await expect(wall).not.toHaveClass(/motion/);
  await expect(page.locator('.progress.run, .pulse')).toHaveCount(0);
  await expect(page.getByTestId('wall-flow').locator('circle.dot')).toHaveCount(0);
  // Esc: back to the dashboard.
  await page.keyboard.press('Escape');
  await expect(page).toHaveURL(/#\/$/);
  await expect(page.locator('nav.side')).toBeVisible();
});

// REQ: OBS-035 (upstream #69) — a panel the viewer moved to stays put while the wall is measured
// or resized: the area's size is read after the first render (and again when the layout
// changes), and that must not send the rotation back to the first panel.
test('obs_035 wall keeps its place when remeasured', async () => {
  await page.setViewportSize({ width: 1280, height: 800 });
  await page.goto('/#/wall?layout=single&every=600');
  const slot = page.getByTestId('wall-slot');
  await expect(slot).toHaveAttribute('data-panel', 'map');
  await page.keyboard.press('ArrowRight');
  await expect(slot).toHaveAttribute('data-panel', 'flow');
  // Each resize changes the panel area's size, so the layout is computed again.
  for (const [width, height] of [[1100, 700], [1280, 800], [1200, 760]]) {
    await page.setViewportSize({ width, height });
    await page.evaluate(() => new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(r))));
    await expect(slot).toHaveAttribute('data-panel', 'flow');
  }
  await page.keyboard.press('ArrowRight');
  await expect(slot).toHaveAttribute('data-panel', 'slo');
});

// REQ: OBS-036 — a chatty loop is shown with its strip and marked informational, and the
// sidebar badge doesn't count it.
test('obs_036 chatty loop', async () => {
  const strip = Array.from({ length: 24 }, (_, i) => (i === 3 ? 1400 : i === 4 ? 20 : 0));
  const f = (id: string, kind: string, informational: boolean) => ({
    id, kind, client: '10.20.2.14', domain: 'ntp.org', windowStart: '2026-10-17T03:00:00.000Z', windowSeconds: 3600,
    observed: 1440, baseline: 2.5, spread: 98, threshold: 120, detail: 'asked every 2.5 s: 1440 queries this hour (informational)',
    rhythm: strip, ...(informational ? { informational: true } : {}),
  });
  let items = [f('6a2c0e00d1b2c3d4', 'chatty_loop', true)];
  await page.route('**/api/v1/analytics/anomalies?*', (route) => route.fulfill({ json: { items } }));
  await page.goto('/#/anomalies');
  await page.reload(); // the sidebar badge loads at start
  const card = page.getByTestId('anomaly');
  await expect(card).toContainText('Chatty loop');
  await expect(card.getByTestId('informational')).toBeVisible();
  await expect(card.getByTestId('rhythm').locator('rect.dominant')).toHaveAttribute('data-bin', '3');
  await expect(page.locator('a.nav[href="#/anomalies"] .count')).toHaveCount(0);
  // A real anomaly beside it is counted.
  items = [...items, f('6a2c0e00e1b2c3d4', 'beacon', false)];
  await page.reload();
  await expect(page.locator('a.nav[href="#/anomalies"] .count')).toHaveText('1');
  await page.unroute('**/api/v1/analytics/anomalies?*');
});

// REQ: OBS-035 — the Wall button sits in the header between pause and theme, styled like them
// (Advanced view), and opens the wall.
test('obs_035 wall button in the header', async () => {
  await page.setViewportSize({ width: 1280, height: 800 });
  await page.goto('/#/');
  await page.getByRole('button', { name: 'Advanced', exact: true }).click();
  const wall = page.getByTestId('open-wall');
  await expect(wall).toHaveClass(/icon-btn/);
  const order = await page.locator('header.top .icon-btn').evaluateAll((els) => els.map((e) => e.getAttribute('aria-label') ?? ''));
  const i = order.indexOf('Wall display');
  expect(order[i - 1]).toBe('Pause blocking');
  expect(order[i + 1]).toMatch(/^Theme:/);
  const [w, t] = [await wall.boundingBox(), await page.getByRole('button', { name: /^Theme:/ }).boundingBox()];
  expect(Math.abs(w!.y - t!.y)).toBeLessThan(2);
  expect(Math.abs(w!.height - t!.height)).toBeLessThan(2);
  await wall.click();
  await expect(page.getByTestId('wall')).toBeVisible();
  await page.keyboard.press('Escape');
  await page.getByRole('button', { name: 'Simple', exact: true }).click();
  await expect(page.getByTestId('open-wall')).toHaveCount(0);
});

// REQ: OBS-035 (T14.13, ADR-140) — a wall display: an admin makes a link, a fresh browser opens
// it and sees only the wall (other pages and changes refused), and revoking it signs the
// screen out.
test('obs_035 wall display link', async () => {
  await page.setViewportSize({ width: 1280, height: 800 });
  await page.goto('/#/settings?tab=users');
  const card = page.getByTestId('wall-displays');
  await card.getByTestId('display-name').fill('hallway');
  await card.getByTestId('display-create').click();
  const shown = card.getByTestId('display-link');
  await expect(shown).toContainText('#/display?code=tt_');
  const link = (await shown.locator('.link').textContent())!.trim();
  await expect(card.getByTestId('display-row')).toHaveCount(1);
  // The API never lists it among the user's tokens.
  const tokens = await (await page.request.get('/api/v1/tokens')).json();
  expect(tokens.items.some((t: { name: string }) => t.name === 'hallway')).toBe(false);

  const ctx = await page.context().browser()!.newContext();
  const wall = await ctx.newPage();
  await wall.goto(link + '&panels=slo');
  await expect(wall.getByTestId('wall')).toBeVisible();
  await expect(wall.getByTestId('wall-panel-slo')).toBeVisible();
  expect(wall.url()).not.toContain('code=');
  // Only the wall: another page still shows the wall, Esc stays.
  await wall.goto(new URL('/#/settings', wall.url()).toString());
  await expect(wall.getByTestId('wall')).toBeVisible();
  await wall.keyboard.press('Escape');
  await expect(wall.getByTestId('wall')).toBeVisible();
  // Its session reads the wall's data and nothing else.
  expect((await wall.request.get('/api/v1/stats/slo')).status()).toBe(200);
  expect((await wall.request.get('/api/v1/clients')).status()).toBe(403);
  expect((await wall.request.get('/api/v1/tokens')).status()).toBe(403);
  const me = await (await wall.request.get('/api/v1/auth/me')).json();
  expect(me.display).toBe('hallway');
  // The code is no API token.
  const code = new URL(link.replace('#/display', '/display')).searchParams.get('code')!;
  expect((await wall.request.get('/api/v1/stats/slo', { headers: { authorization: `Bearer ${code}` } })).status()).toBe(401);

  // Revoked: the screen is signed out.
  await card.getByTestId('display-revoke').click();
  await expect(card.getByTestId('display-row')).toHaveCount(0);
  expect((await wall.request.get('/api/v1/stats/slo')).status()).toBe(401);
  await wall.reload();
  await expect(wall.getByTestId('wall')).toHaveCount(0);
  await ctx.close();
});

// REQ: OBS-035 (T14.15, ADR-141) — the wall fits the screen: one panel on a phone, two stacked on
// a portrait screen, a hero and two side panels on a TV, five on an ultrawide, all six at once on
// a large screen (the tail beside them), never a scrollbar.
test('obs_035 wall layouts', async () => {
  for (const [w, h, cls, slots] of [
    [390, 844, 'compact', 1],
    [1080, 1700, 'portrait', 2],
    [1920, 1080, 'standard', 3],
    [2560, 1080, 'ultrawide', 5],
    [2600, 1440, 'large', 6],
  ] as const) {
    await page.setViewportSize({ width: w, height: h });
    await page.goto('/#/wall?motion=off');
    const wall = page.getByTestId('wall');
    await expect(wall).toHaveAttribute('data-class', cls);
    await expect(wall).toHaveAttribute('data-slots', String(slots));
    await expect(page.getByTestId('wall-slot')).toHaveCount(slots);
    const fits = await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1 && document.documentElement.scrollHeight <= innerHeight + 1);
    expect(fits, `${w}x${h} scrolls`).toBe(true);
    if (cls === 'large') {
      await expect(page.locator('[data-testid="wall-slot"][data-rotates="yes"]')).toHaveCount(0);
      await expect(page.getByTestId('wall-tail')).toHaveAttribute('data-side', 'yes');
      await expect(page.getByTestId('wall-kpi')).toBeVisible();
    }
    if (cls === 'standard') {
      const side = await page.locator('[data-testid="wall-slot"]').evaluateAll((els) => els.slice(1).map((e) => (e as HTMLElement).dataset.panel).sort());
      expect(side).toEqual(['kpi', 'slo']);
    }
  }
  // Forced: `layout=single` on a big screen shows one panel.
  await page.goto('/#/wall?layout=single&motion=off');
  await expect(page.getByTestId('wall')).toHaveAttribute('data-slots', '1');
  await page.setViewportSize({ width: 1280, height: 800 });
  await page.goto('/#/');
});

// REQ: CLU-002 — the sidebar's footer says which kind of node this UI belongs to, in a cluster
// only (stubbed: the e2e server runs alone).
test('clu_002 the footer names the node and its role', async () => {
  await page.setViewportSize({ width: 1280, height: 800 });
  await page.goto('/#/');
  await expect(page.getByTestId('build-footer')).toBeVisible();
  await expect(page.getByTestId('node-role')).toHaveCount(0);
  const cluster = (primary: boolean) => ({
    clusterId: 'c1', name: 'home', nodeId: 'id-a', site: primary ? 'k8s' : 'home-pi', primary,
    certExpiresAt: '2027-01-01T00:00:00Z', configSeq: 9, configCreatedAt: null, configAppliedAt: null,
    lastSyncFetched: 0, lastSyncMs: 0, syncError: null, peers: [],
  });
  for (const primary of [false, true]) {
    await page.route('**/api/v1/system/info', async (route) => {
      const res = await route.fetch();
      const info = await res.json();
      await route.fulfill({ response: res, json: { ...info, cluster: cluster(primary) } });
    });
    await page.reload();
    const role = page.getByTestId('node-role');
    await expect(role).toHaveText(primary ? 'primary' : 'replica');
    await expect(role).toHaveAttribute('title', primary ? /the primary of cluster home/ : /sent to the primary/);
    await page.unroute('**/api/v1/system/info');
  }
  await page.reload();
});

// REQ: FLT-017 (T15.1, AC 7) — Kubernetes workloads as devices, from the server's fixture (no
// API server): the Workloads tab with each group's origin, the chip's glyph and pod, and "Add
// to group…" writing a rule (dry run first) that the workload's next query follows.
test('flt_017 workloads', async () => {
  test.setTimeout(90_000);
  await page.setViewportSize({ width: 1280, height: 800 });
  for (const ip of ['127.0.0.81', '127.0.0.82', '127.0.0.83']) await query('nas.e2e.test', 1, DNS_PORT, ip);
  await page.goto('/#/clients?tab=workloads');
  const rows = page.getByTestId('workload-row');
  await expect(rows).toHaveCount(3);
  const jellyfin = rows.filter({ hasText: 'media/deploy/jellyfin' });
  await expect(jellyfin.getByTestId('group-from')).toHaveText('network group');
  await expect(rows.filter({ hasText: 'db/sts/postgres' }).getByTestId('group-from')).toHaveText('pod label');
  await expect(rows.filter({ hasText: 'kube-system/ds/cilium' }).getByTestId('group-from')).toHaveText('namespace label');
  await expect(jellyfin.locator('td').first()).toHaveAttribute('title', 'Deployment');
  // Filter by namespace.
  await page.getByTestId('workload-namespace').selectOption('db');
  await expect(rows).toHaveCount(1);
  await page.getByTestId('workload-namespace').selectOption('');
  // In the query log: the pod's address, named by its workload, with the glyph and the pod.
  await page.goto('/#/queries?client=127.0.0.81');
  const chip = page.getByTestId('workload-chip').first();
  await expect(chip).toContainText('media/deploy/jellyfin');
  await expect(chip.getByLabel('Kubernetes workload')).toBeVisible();
  await expect(chip).toHaveAttribute('title', /pod jellyfin-6c9f7b-abcde/);
  // Kubernetes names it; "Add to group…" previews, then writes a rule.
  await chip.click();
  await expect(page.getByRole('menuitem', { name: /Name this device/ })).toBeDisabled();
  await page.getByRole('menuitem', { name: 'Add to group…' }).click();
  const form = page.getByTestId('workload-group-form');
  await pick(form, 'Group', 'ipv6only');
  await expect(form.getByRole('button', { name: 'Save' })).toHaveCount(0);
  await form.getByRole('button', { name: 'Preview' }).click();
  await expect(form.getByTestId('workload-dry-run')).toContainText('next query');
  await form.getByRole('button', { name: 'Save' }).click();
  await expect(form.getByRole('status')).toContainText('Saved');
  await page.keyboard.press('Escape');
  // A query from any of its pods is then in that group (each try asks again: the table is
  // rebuilt right after the reload, a few milliseconds after the API answers).
  await expect
    .poll(
      async () => {
        await query('flt017.nas.e2e.test', 1, DNS_PORT, '127.0.0.82').catch(() => -1);
        const r = await page.request.get('/api/v1/queries?name=flt017.nas.e2e.test&match=exact&limit=1');
        const row = (await r.json()).items?.[0];
        return row ? `${row.group} ${row.clientName}` : '';
      },
      { timeout: 20_000 },
    )
    .toBe('ipv6only media/deploy/jellyfin');
  await page.goto('/#/clients?tab=workloads');
  await expect(page.getByTestId('workload-row').filter({ hasText: 'media/deploy/jellyfin' }).getByTestId('group-from')).toHaveText('rule');
  // The Groups page lists it under its new group.
  await page.goto('/#/groups');
  await expect(page.getByTestId('group-card').filter({ hasText: 'ipv6only' }).getByTestId('group-workloads')).toContainText(
    'media/deploy/jellyfin',
  );
  // Explain says so.
  const e = await (await page.request.get('/api/v1/explain?name=example.org&client=media/deploy/jellyfin')).json();
  expect(e.client.identifiedBy).toBe('kubernetes');
  expect(e.client.workload).toMatchObject({ name: 'media/deploy/jellyfin', groupFrom: 'map' });
});
test("clu_015 cluster page shows each member's secret state", async () => {
  // REQ: CLU-015 (ADR-903 §6) — the Nodes table's Secrets column: each member's head, what it has
  // applied, its unreadable and held counts, and whether it's in sync with the primary.
  await page.setViewportSize({ width: 1280, height: 900 });
  const node = (o: Record<string, unknown>) => ({
    ephemeral: false, witness: false, protocol: 4, role: 'replica', thisNode: false, eligible: true, version: '0.8.0',
    up: true, connected: true, link: 'inbound', lastSeenSecondsAgo: 1, rttMs: 3, configSeq: 12, configLag: 0, ready: true,
    qps: 10, servfailPercent: 0, upstreamP90Ms: 12, uptimeSeconds: 3600, restarts: 0, ...o,
  });
  const view = {
    enabled: true, clusterId: 'c1', name: 'home', thisNode: 'aaaa1111', newestConfigSeq: 12, healthy: true, checks: [],
    events: [], conflicts: [], authority: 'api',
    nodes: [
      node({ nodeId: 'aaaa1111', site: 'k8s', role: 'primary', thisNode: true, link: 'self',
        secrets: { head: '2.14', applied: '2.14', inSync: true, unreadable: 0, held: 0 } }),
      node({ nodeId: 'bbbb2222', site: 'pi',
        secrets: { head: '2.14', applied: '2.14', inSync: true, unreadable: 0, held: 0 } }),
      node({ nodeId: 'cccc3333', site: 'canary-box',
        secrets: { head: '2.14', applied: '2.9', inSync: false, unreadable: 1, held: 2 } }),
    ],
  };
  await page.route('**/api/v1/cluster', (route) => route.fulfill({ json: view }));
  await page.goto('/#/cluster?tab=nodes');
  const rows = page.getByTestId('cluster-node');
  await expect(rows).toHaveCount(3);
  await expect(rows.nth(0).getByTestId('cluster-node-secrets-state')).toHaveText('primary');
  await expect(rows.nth(0).getByTestId('cluster-node-secrets')).toContainText('head 2.14 · applied 2.14');
  await expect(rows.nth(1).getByTestId('cluster-node-secrets-state')).toHaveText('in sync');
  await expect(rows.nth(2).getByTestId('cluster-node-secrets-state')).toHaveText('behind');
  await expect(rows.nth(2).getByTestId('cluster-node-secrets')).toContainText('applied 2.9');
  await expect(rows.nth(2).getByTestId('cluster-node-unreadable')).toContainText('1 unreadable here');
  await expect(rows.nth(2).getByTestId('cluster-node-held')).toContainText('2 held by the primary');
  // The help topic for the column is there.
  await expect(page.locator('th', { hasText: 'Secrets' }).getByRole('button')).toBeVisible();
  // Drop the mock and reload: the next test's `goto` only changes the hash, so it would keep this view.
  await page.unroute('**/api/v1/cluster');
  await page.reload();
});

// REQ: OBS-010 (T24.5, fork #2) — a replica that hasn't reached its primary shows on the Cluster
// page (cluster mocked): the replica's row says how long, with the help button; the primary and
// the replica that reaches it don't; the Alerts form offers the condition with its threshold.
test('clu_004 primary unreachable shows on the cluster page', async () => {
  await page.setViewportSize({ width: 1280, height: 900 });
  const node = (o: Record<string, unknown>) => ({
    ephemeral: false, witness: false, protocol: 4, role: 'replica', thisNode: false, eligible: true, version: '0.8.0',
    up: true, connected: true, link: 'inbound', lastSeenSecondsAgo: 1, rttMs: 3, configSeq: 12, configLag: 0, ready: true,
    qps: 10, servfailPercent: 0, upstreamP90Ms: 12, uptimeSeconds: 3600, restarts: 0, ...o,
  });
  const view = {
    enabled: true, clusterId: 'c1', name: 'home', thisNode: 'aaaa1111', newestConfigSeq: 12, healthy: true, checks: [],
    events: [], conflicts: [], authority: 'api',
    nodes: [
      node({ nodeId: 'aaaa1111', site: 'k8s', role: 'primary', thisNode: true, link: 'self' }),
      node({ nodeId: 'bbbb2222', site: 'pi', primarySilentSeconds: 95 }),
      node({ nodeId: 'cccc3333', site: 'canary-box' }),
    ],
  };
  await page.route('**/api/v1/cluster', (route) => route.fulfill({ json: view }));
  // Leave the page first: a hash-only goto to the page already shown keeps its old data until the next poll.
  await page.goto('/#/alerts');
  await page.goto('/#/cluster?tab=nodes');
  const rows = page.getByTestId('cluster-node');
  await expect(rows).toHaveCount(3);
  const silent = rows.nth(1).getByTestId('cluster-node-primary-silent');
  await expect(silent).toContainText('no contact with the primary');
  await expect(silent).toContainText('for 1m');
  await expect(silent.getByRole('button')).toBeVisible(); // the primary-unreachable help topic
  await expect(rows.nth(0).getByTestId('cluster-node-primary-silent')).toHaveCount(0);
  await expect(rows.nth(2).getByTestId('cluster-node-primary-silent')).toHaveCount(0);
  // The alert condition is offered in the Alerts form (selecting it fails if it isn't).
  await page.unroute('**/api/v1/cluster');
  await page.goto('/#/alerts');
  const rules = page.getByTestId('editor-alert_rule');
  await rules.getByRole('button', { name: 'Add rule' }).click();
  await page.getByLabel('When', { exact: true }).selectOption('primary_unreachable');
  // Drop the form and the mock: the next test's `goto` only changes the hash.
  await page.reload();
});

// REQ: CLU-014 (T15.2, AC 8) — failover drills from the Cluster page (a stubbed two-node
// cluster): Drill… on the replica, the preview with every check and what it does to devices,
// Start, the live counters on the Drills tab, the report (verdicts, time to failover, came back),
// and the drill marker on the dashboard; the real single node refuses a drill (no other node);
// the affinity column in the Advanced view with its help.
test('clu_014 drill', async () => {
  test.setTimeout(90_000);
  await page.setViewportSize({ width: 1280, height: 800 });
  const r = page.request;
  const csrf = (await (await r.get('/api/v1/auth/status')).json()).csrfToken as string;
  // The real node runs alone: a dry run says so, a start is refused.
  const dry = await r.post('/api/v1/nodes/local/drill?dryRun=true', {
    headers: { 'x-csrf-token': csrf },
    data: { forSecs: 30, targets: 'all', reason: 'e2e' },
  });
  expect(dry.status()).toBe(200);
  expect((await dry.json()).checks.find((c: { name: string }) => c.name === 'other_node').ok).toBe(false);
  const refused = await r.post('/api/v1/nodes/local/drill', { headers: { 'x-csrf-token': csrf }, data: { forSecs: 30, targets: 'all', reason: 'e2e' } });
  expect(refused.status()).toBe(409);
  expect((await refused.json()).code).toBe('drill_refused');

  const member = (nodeId: string, site: string, o: Record<string, unknown> = {}) => ({
    nodeId, site, ephemeral: false, witness: false, protocol: 4, role: 'replica', thisNode: false, eligible: true, version: '0.6.0',
    up: true, connected: true, link: 'inbound', lastSeenSecondsAgo: 1, rttMs: 3, configSeq: 9, configLag: 0, ready: true,
    qps: 10, servfailPercent: 0, upstreamP90Ms: 12, uptimeSeconds: 3600, ...o,
  });
  let drilling = false;
  const view = () => ({
    enabled: true, clusterId: 'c1', name: 'home', thisNode: 'id-a', newestConfigSeq: 9, healthy: true, checks: [],
    events: [], conflicts: [], authority: 'primary',
    nodes: [
      member('id-a', 'k8s', { role: 'primary', thisNode: true, link: 'self', rttMs: null }),
      member(
        'id-b',
        'pi',
        drilling
          ? { ready: false, maintenance: { until: new Date(Date.now() + 15_000).toISOString(), since: new Date().toISOString(), reason: 'failover drill: e2e', by: 'admin', secondsLeft: 15 } }
          : {},
      ),
    ],
  });
  const since = new Date(Date.now() - 60_000).toISOString();
  const done = (status: string) => status === 'complete';
  const summary = (status: string) => ({
    id: 'd1-e2e', node: 'pi', since, until: new Date(Date.now() - 45_000).toISOString(), targets: 'group home', reason: 'e2e',
    by: 'admin', status, followed: done(status) ? 1 : 0, stuck: done(status) ? 1 : 0, quiet: 0, elsewhere: 0,
    coveragePercent: done(status) ? 50 : undefined, medianFailoverMs: done(status) ? 1100 : undefined,
    p90FailoverMs: done(status) ? 1100 : undefined, viaBalancer: false, missingNodes: [],
  });
  let state = 'none';
  const checks = [
    { name: 'other_node', ok: true, detail: 'k8s can answer meanwhile.' },
    { name: 'maintenance', ok: true, detail: 'Not in maintenance.' },
    { name: 'recent_drill', ok: true, detail: 'No drill in the last 10 minutes.' },
    { name: 'rollout', ok: true, detail: 'No rollout is baking and the cluster is not pinned.' },
    { name: 'health', ok: true, detail: 'Health is healthy.' },
  ];
  await page.route('**/api/v1/cluster', (route) => route.fulfill({ json: view() }));
  await page.route('**/api/v1/cluster/rollout', (route) =>
    route.fulfill({ json: { fromPrimary: true, canaries: [], bakeSecs: 300, stable: '0.6.0', stage: 'none', nodes: [] } }),
  );
  await page.route('**/api/v1/cluster/versions', (route) => route.fulfill({ json: { items: [], history: 20 } }));
  await page.route('**/api/v1/nodes/id-b/drill**', (route) => {
    const dryRun = route.request().url().includes('dryRun=true');
    if (!dryRun) {
      drilling = true;
      state = 'running';
    }
    return route.fulfill({
      status: dryRun ? 200 : 201,
      json: {
        id: dryRun ? '' : 'd1-e2e', node: 'pi', dryRun, since, until: new Date(Date.now() + 15_000).toISOString(), targets: 'group home',
        targetsResolved: 2, baseline: 5, handover: 'not_needed', checks,
        preview: 'For 15 seconds this node will not answer 2 devices. Devices with a second DNS server switch to it within a few seconds; devices without one lose DNS until the drill ends.',
        devices: dryRun ? [{ client: '192.168.1.20', name: 'laptop' }, { client: '192.168.1.30', name: 'tv' }] : [],
      },
    });
  });
  await page.route('**/api/v1/nodes/pi/drill', (route) =>
    route.fulfill({
      json: { id: 'd1-e2e', node: 'pi', since, until: new Date(Date.now() + 9000).toISOString(), secondsLeft: 9, targets: 'group home', reason: 'e2e', by: 'admin', dropped: 7, devicesDropped: 2 },
    }),
  );
  await page.route('**/api/v1/drills?**', (route) => route.fulfill({ json: { items: state === 'none' ? [] : [summary(state)], missingNodes: [] } }));
  await page.route('**/api/v1/drills/d1-e2e', (route) =>
    route.fulfill({
      json: {
        ...summary('complete'), baseline: 5, overflow: 0, returnedChecked: true,
        nodes: [{ node: 'pi', queries: 40, devices: 4 }, { node: 'k8s', queries: 25, devices: 3 }],
        devices: [
          { client: '192.168.1.30', name: 'tv', group: 'home', verdict: 'stuck', dropped: 12, queriesElsewhere: 0, nodes: [] },
          { client: '192.168.1.20', name: 'laptop', group: 'home', verdict: 'followed', dropped: 3, queriesElsewhere: 9, timeToFailoverMs: 1100, returned: true, nodes: ['k8s'] },
        ],
      },
    }),
  );
  await page.goto('/#/cluster');
  const row = page.getByTestId('cluster-node').filter({ hasText: 'pi' });
  await row.getByTestId('drill-open-form').click();
  const form = page.getByTestId('drill-form');
  await form.getByRole('radio', { name: '15 s' }).check();
  await form.getByRole('radio', { name: 'a group' }).check();
  await form.getByTestId('drill-group').getByRole('combobox').click();
  await form.getByTestId('drill-group').getByRole('option').first().click();
  await form.getByTestId('drill-reason').fill('e2e');
  await expect(form.getByTestId('drill-start')).toHaveCount(0);
  await form.getByTestId('drill-preview-button').click();
  const preview = form.getByTestId('drill-preview');
  await expect(preview).toContainText('will not answer 2 devices');
  await expect(preview).toContainText('k8s can answer meanwhile');
  await expect(preview).toContainText('laptop, tv');
  await form.getByTestId('drill-start').click();
  await expect(page.getByTestId('drill-note')).toContainText('The report follows');
  // The Drills tab: the running drill, live.
  await page.getByTestId('tab-drills').click();
  await expect(page.getByTestId('drill-counters')).toContainText('7 queries unanswered from 2 devices');
  // Done: the report.
  state = 'complete';
  drilling = false;
  await expect(page.getByTestId('drill-row').first()).toContainText('50', { timeout: 20_000 });
  await page.getByTestId('drill-open').first().click();
  const report = page.getByTestId('drill-report');
  await expect(report.getByTestId('drill-device')).toHaveCount(2);
  await expect(report.getByTestId('drill-device').first()).toContainText('stuck');
  await expect(report.getByTestId('drill-device').nth(1)).toContainText('1.1 s');
  await expect(report.getByTestId('drill-device').nth(1)).toContainText('came back');
  await page.keyboard.press('Escape');
  for (const p of [
    '**/api/v1/cluster',
    '**/api/v1/cluster/rollout',
    '**/api/v1/cluster/versions',
    '**/api/v1/nodes/id-b/drill**',
    '**/api/v1/nodes/pi/drill',
    '**/api/v1/drills?**',
    '**/api/v1/drills/d1-e2e',
  ]) {
    await page.unroute(p);
  }
  // The marker a drill leaves on the dashboard (a stubbed one: this node can't drill).
  const t = new Date(Date.now() - 120_000);
  await page.route('**/api/v1/annotations?**', (route) =>
    route.fulfill({
      json: {
        items: [{ t: t.toISOString(), tUnixMs: t.getTime(), kind: 'drill.ended', summary: 'failover drill on pi: 1 followed, 1 stuck, 0 quiet (50 % coverage)' }],
        truncated: false,
        missingNodes: [],
      },
    }),
  );
  // A reload: the markers are fetched at most once a minute, and the app kept the real ones.
  await page.goto('/#/');
  await page.reload();
  const chart = page.getByTestId('dashboard-chart');
  await expect(chart.getByTestId('chart-markers').getByRole('button', { name: /failover drill on pi/ })).toBeVisible({ timeout: 20_000 });
  await page.unroute('**/api/v1/annotations?**');
  // The affinity column: Advanced view, with its caveat in the help (stubbed: two nodes).
  await page.route('**/api/v1/clients/affinity**', (route) =>
    route.fulfill({
      json: {
        windowDays: 7, missingNodes: [], caveat: 'Run a drill to find out.',
        items: [{ client: '127.0.0.1', queries: 10, nodes: [{ node: 'pi', queries: 10 }, { node: 'k8s', queries: 0 }], topNode: 'pi', topSharePercent: 100, label: 'mostly pi' }],
      },
    }),
  );
  await page.goto('/#/clients?tab=seen');
  await page.getByRole('button', { name: 'Advanced', exact: true }).click();
  await expect(page.getByTestId('affinity-head')).toBeVisible();
  await expect(page.getByTestId('affinity').first()).toContainText('mostly pi');
  await page.getByTestId('affinity-head').getByRole('button').click();
  await expect(page.getByTestId('help-panel')).toContainText('may still have a second one configured');
  await page.keyboard.press('Escape');
  await page.getByRole('button', { name: 'Simple', exact: true }).click();
  await page.unroute('**/api/v1/clients/affinity**');
  for (let i = problems.length - 1; i >= 0; i--) if (/status of 409/.test(problems[i])) problems.splice(i, 1);
});

// REQ: CLU-001 (ADR-155, issue #5) — a node is removed from the Cluster page (a stubbed cluster
// of five): no Remove on the primary or this node; a down node is checked (the notes the
// primary gives, the voters left) and removed without force; a node that is up needs the box
// ticked, and the request then carries force; a node the page shows down but the primary says
// is up (409 node_is_up) gets the box too.
test('clu_001 a stale node can be removed from the Cluster page', async () => {
  await page.setViewportSize({ width: 1280, height: 800 });
  const member = (nodeId: string, site: string, o: Record<string, unknown> = {}) => ({
    nodeId, site, ephemeral: false, witness: false, protocol: 4, role: 'replica', thisNode: false, eligible: true, version: '0.7.0',
    up: true, connected: true, link: 'inbound', lastSeenSecondsAgo: 1, rttMs: 3, configSeq: 9, configLag: 0, ready: true,
    qps: 10, servfailPercent: 0, upstreamP90Ms: 12, uptimeSeconds: 3600, ...o,
  });
  const gone = { up: false, connected: false, ready: false, link: 'none', lastSeenSecondsAgo: 86_400 };
  let nodes = [
    member('id-k8s', 'k8s', { role: 'primary' }),
    member('id-pi', 'home-pi', { thisNode: true, link: 'self', rttMs: null }),
    member('id-old', 'old-pi', gone),
    member('id-nas', 'nas-box'),
    member('id-lab', 'lab-box', gone),
  ];
  // What the primary knows: the node ID, its site, whether it is up, and the voters left.
  const truth: Record<string, { site: string; up: boolean; after: number }> = {
    'id-old': { site: 'old-pi', up: false, after: 4 },
    'id-nas': { site: 'nas-box', up: true, after: 2 },
    'id-lab': { site: 'lab-box', up: true, after: 2 },
  };
  const key =
    'It was an eligible node, so it holds a copy of the cluster key. If it is lost or cannot be trusted, rotate the cluster CA (wrendns cluster rotate-ca).';
  const problem = (status: number, code: string, detail: string) => ({
    type: `https://wrendns.com/problems/${code}`, title: code, status, code, detail, hint: 'Stop it first, or tick the box.',
  });
  const calls: string[] = [];
  const isRemoval = (url: URL) => url.pathname.startsWith('/api/v1/cluster/nodes/');
  const onRemoval = (route: Route) => {
    const req = route.request();
    const u = new URL(req.url());
    const id = decodeURIComponent(u.pathname.split('/').pop() ?? '');
    calls.push(`${req.method()} ${id}${u.search}`);
    const t = truth[id];
    if (!t || req.method() !== 'DELETE') return route.fulfill({ status: 404, json: problem(404, 'node_unknown', `no cluster member has the ID ${id}`) });
    if (t.up && u.searchParams.get('force') !== 'true') return route.fulfill({ status: 409, json: problem(409, 'node_is_up', `${id} is up`) });
    const dry = u.searchParams.get('dryRun') === 'true';
    if (!dry) nodes = nodes.filter((n) => n.nodeId !== id);
    return route.fulfill({
      json: {
        nodeId: id, site: t.site, up: t.up, eligible: true, witness: false, ephemeral: false, heldClusterKey: true,
        votersAfter: t.after, automaticFailoverAfter: t.after >= 3, removed: !dry,
        notes: t.after >= 3 ? [key] : [key, 'Automatic failover needs three voters, so it turns into manual.'],
      },
    });
  };
  const isCluster = (url: URL) => url.pathname === '/api/v1/cluster';
  const onCluster = (route: Route) =>
    route.fulfill({
      json: {
        enabled: true, clusterId: 'c1', name: 'home', thisNode: 'id-pi', newestConfigSeq: 9, healthy: true, checks: [],
        events: [], conflicts: [], authority: 'primary', nodes,
        failover: { mode: 'auto', active: true, voters: 5, reachableVoters: 3, leaseHeld: false, votedEpoch: 0 },
      },
    });
  await page.route(isCluster, onCluster);
  await page.route('**/api/v1/cluster/rollout', (route) =>
    route.fulfill({ json: { fromPrimary: true, canaries: [], bakeSecs: 300, stable: '0.7.0', stage: 'none', nodes: [] } }),
  );
  await page.route('**/api/v1/cluster/versions', (route) => route.fulfill({ json: { items: [], history: 20 } }));
  await page.route(isRemoval, onRemoval);
  try {
    await page.goto('/#/cluster');
    const row = (site: string) => page.getByTestId('cluster-node').filter({ hasText: site });
    const form = page.getByTestId('node-remove-form');
    const confirm = form.getByTestId('node-remove-confirm');
    await expect(row('lab-box')).toBeVisible();
    // Never on the primary, and never on the node serving this page.
    await expect(row('k8s').getByTestId('node-remove-open')).toHaveCount(0);
    await expect(row('home-pi').getByTestId('node-remove-open')).toHaveCount(0);

    // A node that is down: the dry run's notes first, no box, removed without force.
    await row('old-pi').getByTestId('node-remove-open').click();
    await expect(form).toContainText('Remove old-pi from the cluster?');
    await expect(form.getByTestId('node-remove-id')).toHaveText('id-old');
    const preview = form.getByTestId('node-remove-preview');
    await expect(preview).toContainText('4 voters left; automatic failover stays on.');
    await expect(preview).toContainText('holds a copy of the cluster key');
    await expect(form.getByTestId('node-remove-force')).toHaveCount(0);
    await expect(confirm).toBeEnabled();
    await confirm.click();
    await expect(page.getByTestId('node-remove-note')).toContainText('old-pi (id-old) was removed from the cluster.');
    await expect(page.getByTestId('node-remove-note')).toContainText('rotate the cluster CA');
    await expect(form).toHaveCount(0);
    await expect(row('old-pi')).toHaveCount(0);
    expect(calls).toEqual(['DELETE id-old?dryRun=true', 'DELETE id-old']);

    // A node that is up: the box must be ticked, and the request carries force.
    calls.length = 0;
    await row('nas-box').getByTestId('node-remove-open').click();
    await expect(form.getByTestId('node-remove-preview')).toContainText('2 voters left; automatic failover turns into manual.');
    await expect(form.getByTestId('node-remove-preview')).toContainText('needs three voters');
    await expect(confirm).toBeDisabled();
    await form.getByTestId('node-remove-force').check();
    await expect(confirm).toBeEnabled();
    await confirm.click();
    await expect(page.getByTestId('node-remove-note')).toContainText('nas-box (id-nas) was removed from the cluster.');
    await expect(row('nas-box')).toHaveCount(0);
    expect(calls).toEqual(['DELETE id-nas?dryRun=true&force=true', 'DELETE id-nas?force=true']);

    // Shown down, but the primary says up (409 node_is_up): the box appears, Cancel changes nothing.
    calls.length = 0;
    await row('lab-box').getByTestId('node-remove-open').click();
    await expect(form.getByTestId('node-remove-force')).toBeVisible();
    await expect(form.getByTestId('node-remove-preview')).toContainText('2 voters left');
    await expect(confirm).toBeDisabled();
    await form.getByRole('button', { name: 'Cancel' }).click();
    await expect(form).toHaveCount(0);
    await expect(row('lab-box')).toBeVisible();
    expect(calls).toEqual(['DELETE id-lab?dryRun=true', 'DELETE id-lab?dryRun=true&force=true']);
  } finally {
    await page.unroute(isRemoval, onRemoval);
    await page.unroute('**/api/v1/cluster/rollout');
    await page.unroute('**/api/v1/cluster/versions');
    await page.unroute(isCluster, onCluster);
    for (let i = problems.length - 1; i >= 0; i--) if (/status of 409/.test(problems[i])) problems.splice(i, 1);
  }
});

// REQ: OBS-037 — internal names: reverse lookups of private addresses count under Top domains
// → Internal, not Internet.
test('obs_037 internal names', async () => {
  await page.setViewportSize({ width: 1280, height: 800 });
  for (let i = 0; i < 3; i++) await query('20.1.168.192.in-addr.arpa', 12).catch(() => -1);
  await page.goto('/#/');
  const card = listOf('Top domains');
  const ptr = card.getByRole('link', { name: '20.1.168.192.in-addr.arpa', exact: true });
  await expect(card.getByRole('button', { name: 'Internet', exact: true })).toHaveAttribute('aria-pressed', 'true');
  await expect(async () => {
    await page.reload();
    await card.getByTestId('domains-internal-tab').click();
    await expect(ptr).toBeVisible({ timeout: 2000 });
  }).toPass({ timeout: 20_000 });
  await card.getByRole('button', { name: 'Internet', exact: true }).click();
  await expect(ptr).toHaveCount(0);
});

// REQ: API-016 (T23.8, ADR-903 §9, ADR-120) — the Routers page: a UniFi console is added with its key
// stored (write-only: the value never reaches the page again), a Home Assistant and an OPNsense
// source too, a console's certificate is fetched and trusted, a check reports a wrong key without
// saving, a router the files define shows as set by file, an operator reads the cards, and a
// router is removed. Checks and certificates are mocked: the e2e server has no router to ask.
const ROUTER_CERT = {
  names: ['unifi.local', 'localhost'],
  fingerprintSha256: 'AB:CD:EF',
  // A PEM body the server decodes: a bare marker, or a body that isn't base64, is refused (API-016).
  pem: '-----BEGIN CERTIFICATE-----\nMAMCAQU=\n-----END CERTIFICATE-----\n',
  suggestedTlsServerName: 'unifi.local',
};

// REQ: API-015 (T24.16) — a credential typed into a router's secret field and not saved holds Save the
// router: the router is never saved without the credential the admin typed.
test('api_015 a typed router credential holds Save the router', async () => {
  await page.setViewportSize({ width: 1280, height: 900 });
  await page.goto('/#/routers');
  await expect(page.locator('h1', { hasText: 'Routers' })).toBeVisible({ timeout: 20_000 });
  await page.getByTestId('routers-add').click();
  await page.getByRole('textbox', { name: 'Name', exact: true }).fill('lab-dirty');
  await page.getByRole('textbox', { name: 'Address', exact: true }).fill('https://127.0.0.1:9');
  const field = page.getByTestId('router-secret-api_key');
  await field.getByLabel('API key', { exact: true }).fill('typed-not-saved-4410');
  await expect(page.getByTestId('routers-secret-unsaved')).toBeVisible();
  await expect(page.getByTestId('routers-save')).toBeDisabled();
  await expect(page.locator('body')).not.toContainText('typed-not-saved-4410');
  // Discarding the typed value (clearing the field) lets the router be saved again.
  await field.getByLabel('API key', { exact: true }).fill('');
  await expect(page.getByTestId('routers-secret-unsaved')).toHaveCount(0);
  await expect(page.getByTestId('routers-save')).toBeEnabled();
  await page.getByRole('button', { name: 'Cancel', exact: true }).click();
});

// REQ: API-015 (T24.16) — a router's credential goes through SecretField: the value is typed into the
// field, saved as a stored secret, and the field then says it is set (never the value).
async function fillCredential(label: string, value: string) {
  const field = page.getByTestId(`router-secret-${({ 'API key': 'api_key', 'Long-lived access token': 'api_key', 'API secret': 'api_secret', Password: 'password' } as Record<string, string>)[label]}`);
  await field.getByLabel(label, { exact: true }).fill(value);
  await field.getByRole('button', { name: 'Save secret' }).click();
  await expect(field).toHaveAttribute('data-mode', 'set', { timeout: 10_000 });
}

test('api_016 add a UniFi router from the UI', async () => {
  await page.setViewportSize({ width: 1280, height: 900 });
  await page.goto('/#/routers');
  await expect(page.locator('h1', { hasText: 'Routers' })).toBeVisible({ timeout: 20_000 });
  await page.getByTestId('routers-add').click();
  await page.getByRole('textbox', { name: 'Name', exact: true }).fill('lab-udm');
  await page.getByRole('textbox', { name: 'Address', exact: true }).fill('https://127.0.0.1:9');
  await fillCredential('API key', 'unifi-e2e-key-7781');
  // Write-only: the value is never shown again, in the DOM or in the field.
  await expect(page.locator('body')).not.toContainText('unifi-e2e-key-7781');
  // Stored: the field says so, and offers no input for the value.
  await expect(page.getByTestId('router-secret-api_key')).toHaveAttribute('data-mode', 'set');
  await expect(page.getByTestId('router-secret-api_key').getByRole('textbox')).toHaveCount(0);
  await page.getByRole('button', { name: 'Save the router' }).click();
  const card = page.getByTestId('router-card').filter({ hasText: 'lab-udm' });
  await expect(card).toBeVisible({ timeout: 10_000 });
  await expect(card).toContainText('UniFi');
  await expect(card).toContainText('unifi.lab-udm.api_key');
  await expect(card.getByTestId('router-state')).toContainText(/Failing|Not read yet/);
});

test('api_016 trust the console certificate', async () => {
  await page.route('**/api/v1/checks/router-certificate', (route) => route.fulfill({ json: ROUTER_CERT }));
  await page.goto('/#/routers');
  await page.getByTestId('routers-add').click();
  await page.getByRole('combobox', { name: 'Kind' }).selectOption('unifi');
  await page.getByRole('textbox', { name: 'Name', exact: true }).fill('lab-cert');
  await page.getByRole('textbox', { name: 'Address', exact: true }).fill('https://127.0.0.1:9');
  await page.getByRole('button', { name: "Fetch the console's certificate" }).click();
  await expect(page.getByTestId('routers-cert')).toContainText('unifi.local');
  await page.getByRole('button', { name: 'Trust this certificate' }).click();
  await expect(page.getByRole('textbox', { name: 'Certificate (PEM)' })).toHaveValue(/BEGIN CERTIFICATE/);
  await expect(page.getByRole('textbox', { name: 'Name the certificate checks' })).toHaveValue('unifi.local');
  // A UniFi router needs a credential (its key, or a user and password): store one, as the form does.
  await fillCredential('API key', 'unifi-cert-key-5531');
  // Never offered: skipping verification isn't a choice on this page.
  await expect(page.getByText(/skip/i)).toHaveCount(0);
  const put = page.waitForRequest((r) => r.method() === 'PUT' && r.url().includes('/api/v1/routers/lab-cert'));
  await page.getByRole('button', { name: 'Save the router' }).click();
  const body = (await put).postDataJSON();
  expect(body.tls_ca_pem).toContain('BEGIN CERTIFICATE');
  expect(body.tls_insecure_skip_verify).toBeUndefined();
  await page.unroute('**/api/v1/checks/router-certificate');
});

test('api_016 check reports a wrong key without saving', async () => {
  await page.route('**/api/v1/checks/router', (route) =>
    route.fulfill({ json: { ok: false, devices: 0, networks: 0, error: 'https://127.0.0.1:9/proxy/network/api/s/default/stat/sta: HTTP 401 (check the API key)', credentialSent: true } }),
  );
  let saves = 0;
  const count = (r: { method(): string }) => {
    if (r.method() === 'PUT') saves++;
  };
  page.on('request', count);
  await page.goto('/#/routers');
  await page.getByTestId('routers-add').click();
  await page.getByRole('combobox', { name: 'Kind' }).selectOption('unifi');
  await page.getByRole('textbox', { name: 'Name', exact: true }).fill('lab-wrong');
  await page.getByRole('textbox', { name: 'Address', exact: true }).fill('https://127.0.0.1:9');
  await page.getByTestId('routers-check-button').click();
  await expect(page.getByTestId('routers-check')).toContainText('check the API key');
  await expect(page.getByTestId('routers-check')).toContainText('Nothing was saved.');
  page.off('request', count);
  expect(saves).toBe(0);
  await page.unroute('**/api/v1/checks/router');
  await page.getByRole('button', { name: 'Cancel' }).click();
});

test('api_016 file router shows set by file', async () => {
  await page.route('**/api/v1/routers', (route) =>
    route.fulfill({
      json: {
        items: [
          {
            name: 'filed-udm',
            kind: 'unifi',
            url: 'https://192.168.1.1',
            source: 'file',
            definition: { name: 'filed-udm', type: 'unifi', url: 'https://192.168.1.1', api_key_file: '/etc/wrendns/unifi-key' },
            setByFile: ['api_key_file'],
            credentials: [{ field: 'api_key', source: 'file', readable: true }],
            status: { polledBy: 'this node', state: 'ok', lastPoll: 1, devices: 4, networks: 2, intervalSecs: 300 },
          },
        ],
      },
    }),
  );
  // The page is already on this route (a hash change doesn't reload it): reload to take the answer.
  await page.goto('/#/routers');
  await page.reload();
  const card = page.getByTestId('router-card').filter({ hasText: 'filed-udm' });
  await expect(card.getByTestId('router-file')).toHaveText('Set by file');
  await expect(card.getByRole('button', { name: 'Change' })).toHaveCount(0);
  await expect(card).toContainText("The configuration file defines this router, so it's read-only here.");
  await page.unroute('**/api/v1/routers');
});

test('api_016 add a Home Assistant source from the UI', async () => {
  await page.goto('/#/routers');
  await page.getByTestId('routers-add').click();
  await page.getByRole('combobox', { name: 'Kind' }).selectOption('home_assistant');
  await page.getByRole('textbox', { name: 'Name', exact: true }).fill('ha-e2e');
  await page.getByRole('textbox', { name: 'Address', exact: true }).fill(`http://127.0.0.1:${PORTS.haAdd}`);
  await fillCredential('Long-lived access token', 'ha-e2e-token-5520');
  await page.getByRole('button', { name: 'Save the router' }).click();
  const card = page.getByTestId('router-card').filter({ hasText: 'ha-e2e' });
  await expect(card).toContainText('Home Assistant', { timeout: 10_000 });
  await expect(card).toContainText('home_assistant.ha-e2e.api_key');
});

test('api_016 add an OPNsense router from the UI', async () => {
  await page.goto('/#/routers');
  await page.getByTestId('routers-add').click();
  await page.getByRole('combobox', { name: 'Kind' }).selectOption('opnsense');
  await page.getByRole('textbox', { name: 'Name', exact: true }).fill('opn-e2e');
  await page.getByRole('textbox', { name: 'Address', exact: true }).fill('https://127.0.0.1:9');
  await fillCredential('API key', 'opn-e2e-key-1');
  await fillCredential('API secret', 'opn-e2e-secret-2');
  await page.getByRole('button', { name: 'Save the router' }).click();
  const card = page.getByTestId('router-card').filter({ hasText: 'opn-e2e' });
  await expect(card).toContainText('OPNsense', { timeout: 10_000 });
  await expect(card).toContainText('opnsense.opn-e2e.api_secret');
});

// REQ: API-016 (T23.8, ADR-922) — Change edits a router in place: the name is fixed, and Save sends the
// new interval.
test('api_016 change a router from the UI', async () => {
  await page.goto('/#/routers');
  await page.reload();
  const card = page.getByTestId('router-card').filter({ hasText: 'lab-udm' });
  await expect(card).toBeVisible({ timeout: 10_000 });
  await card.getByTestId('router-edit').click();
  const editor = page.getByTestId('routers-editor');
  await expect(editor.getByRole('heading', { name: 'Change lab-udm' })).toBeVisible();
  await expect(editor.getByRole('textbox', { name: 'Name', exact: true })).toBeDisabled();
  await editor.getByRole('spinbutton', { name: 'Read every (seconds)' }).fill('600');
  const put = page.waitForRequest((r) => r.method() === 'PUT' && r.url().includes('/api/v1/routers/lab-udm'));
  await page.getByRole('button', { name: 'Save the router' }).click();
  expect((await put).postDataJSON().interval_secs).toBe(600);
  await expect(page.getByTestId('routers-notice')).toContainText('Saved lab-udm');
  await expect(page.getByTestId('routers-editor')).toHaveCount(0);
});

// REQ: API-016 (review of T23.8) — Add never replaces a router: a name another router holds is refused
// before anything is stored, and Save stays off.
test('api_016 a name in use is refused when adding', async () => {
  await page.goto('/#/routers');
  await page.getByTestId('routers-add').click();
  await page.getByRole('textbox', { name: 'Name', exact: true }).fill('lab-udm');
  await expect(page.getByTestId('routers-name-taken')).toContainText('A router named lab-udm exists');
  await expect(page.getByRole('button', { name: 'Save the router' })).toBeDisabled();
  await expect(page.locator('[data-testid^="router-secret-"]')).toHaveCount(0);
  await page.getByRole('button', { name: 'Cancel' }).click();
  await expect(page.getByTestId('routers-editor')).toHaveCount(0);
});

// REQ: API-016 (review of T23.8, ADR-922) — a check that drops a stored credential says so.
test('api_016 a check says when a stored credential was not sent', async () => {
  await page.route('**/api/v1/checks/router', (route) =>
    route.fulfill({ json: { ok: false, devices: 0, networks: 0, error: 'HTTP 401 (check the long-lived access token)', credentialSent: false } }),
  );
  await page.goto('/#/routers');
  await page.getByTestId('routers-add').click();
  await page.getByRole('combobox', { name: 'Kind' }).selectOption('home_assistant');
  await page.getByRole('textbox', { name: 'Name', exact: true }).fill('ha-moved');
  await page.getByRole('textbox', { name: 'Address', exact: true }).fill(`http://127.0.0.1:${PORTS.haMoved}`);
  await page.getByTestId('routers-check-button').click();
  await expect(page.getByTestId('routers-check')).toContainText("A stored credential wasn't sent");
  await expect(page.getByTestId('routers-check')).toContainText('Nothing was saved.');
  await page.unroute('**/api/v1/checks/router');
  await page.getByRole('button', { name: 'Cancel' }).click();
});

test('api_016 operator sees routers read-only', async () => {
  const csrf = (await (await page.request.get('/api/v1/auth/status')).json()).csrfToken as string;
  const made = await page.request.post('/api/v1/users', {
    headers: { 'x-csrf-token': csrf },
    data: { username: 'routers-viewer', password: 'viewer routers password', role: 'operator' },
  });
  expect([200, 201, 409]).toContain(made.status());
  const op = await page.context().browser()!.newContext({ baseURL: page.url().split('/#/')[0] });
  try {
    const p = await op.newPage();
    await p.goto('/#/routers');
    await p.getByLabel('Username', { exact: true }).fill('routers-viewer');
    await p.getByLabel('Password', { exact: true }).fill('viewer routers password');
    await p.getByRole('button', { name: 'Sign in' }).click();
    const card = p.getByTestId('router-card').filter({ hasText: 'lab-udm' });
    await expect(card).toBeVisible({ timeout: 30_000 });
    await expect(p.getByTestId('routers-add')).toHaveCount(0);
    await expect(card.getByRole('button', { name: 'Change' })).toHaveCount(0);
    await expect(card.getByRole('button', { name: 'Remove' })).toHaveCount(0);
    await expect(card.getByTestId('router-state')).toBeVisible();
    // And the server says no to a write whatever the page does.
    const ocsrf = (await (await op.request.get('/api/v1/auth/status')).json()).csrfToken as string;
    const put = await op.request.put('/api/v1/routers/lab-udm', { headers: { 'x-csrf-token': ocsrf }, data: { type: 'unifi', url: 'https://127.0.0.1:9' } });
    expect(put.status()).toBe(403);
  } finally {
    await op.close();
  }
});

test('api_016 router with an unreadable credential shows the issue', async () => {
  await page.route('**/api/v1/routers', (route) =>
    route.fulfill({
      json: {
        items: [
          {
            name: 'lost-key',
            kind: 'unifi',
            url: 'https://192.168.1.2',
            source: 'api',
            definition: { name: 'lost-key', type: 'unifi', url: 'https://192.168.1.2', api_key_ref: 'unifi.lost-key.api_key' },
            setByFile: [],
            credentials: [{ field: 'api_key', source: 'stored', secret: 'unifi.lost-key.api_key', readable: false, issue: "secret `unifi.lost-key.api_key` can't be read on this node (no secret of that name is stored)" }],
            status: { polledBy: 'this node', state: 'failing', lastPoll: 1, error: 'https://192.168.1.2/proxy/network/api/s/default/stat/sta: HTTP 401', devices: 0, networks: 0, intervalSecs: 300 },
          },
        ],
      },
    }),
  );
  await page.goto('/#/routers');
  await page.reload();
  const card = page.getByTestId('router-card').filter({ hasText: 'lost-key' });
  await expect(card.getByTestId('router-credential-issue')).toContainText("can't be read on this node");
  await page.unroute('**/api/v1/routers');
});

test('api_016 delete a router from the UI', async () => {
  // The page's session (the admin signed in above), not a fresh request context.
  const request = page.request;
  const csrf = (await (await request.get('/api/v1/auth/status')).json()).csrfToken as string;
  const secret = await request.put('/api/v1/secrets/ha-e2e-token', { headers: { 'x-csrf-token': csrf }, data: { value: 'del-e2e-token-9', kind: 'text' } });
  expect(secret.status(), await secret.text()).toBe(200);
  const made = await request.put('/api/v1/routers/del-e2e', { headers: { 'x-csrf-token': csrf }, data: { type: 'home_assistant', url: `http://127.0.0.1:${PORTS.haDelete}`, api_key_ref: 'ha-e2e-token' } });
  expect(made.status(), await made.text()).toBe(200);
  // The page is already on this route, and a hash change keeps its last mocked list: reload.
  await page.goto('/#/routers');
  await page.reload();
  const card = page.getByTestId('router-card').filter({ hasText: 'del-e2e' });
  await expect(card).toBeVisible({ timeout: 10_000 });
  await card.getByTestId('router-delete').click();
  await card.getByTestId('router-delete-confirm').click();
  await expect(page.getByTestId('router-card').filter({ hasText: 'del-e2e' })).toHaveCount(0, { timeout: 10_000 });
});

// REQ: DNS-023 (T24.14) — a discovered device shows the DNS name it answers as, and the name is copyable.
test('dns_023 discovered devices show their DNS name', async () => {
  await page.context().grantPermissions(['clipboard-read', 'clipboard-write']);
  const items = [
    { ip: '10.20.2.31', mac: 'aa:bb:cc:dd:ee:31', hostname: 'kitchen-tablet', dnsName: 'kitchen-tablet.home.arpa', source: 'router', router: 'udm', expiresUnixSeconds: 0 },
    { ip: '10.20.2.32', mac: '', hostname: 'printer', source: 'mdns', expiresUnixSeconds: 0 },
  ];
  await page.route('**/api/v1/dhcp/leases', (route) => route.fulfill({ json: { items } }));
  try {
    await page.goto('/#/clients?tab=discovered');
    const row = page.getByRole('row').filter({ hasText: '10.20.2.31' });
    await expect(row.getByTestId('dns-name')).toContainText('kitchen-tablet.home.arpa');
    await expect(page.getByRole('row').filter({ hasText: '10.20.2.32' }).getByTestId('dns-name')).toContainText('none');
    await row.getByRole('button', { name: /^Copy/ }).click();
    await expect(row.getByTestId('copy-status')).toHaveText('Copied');
  } finally {
    await page.unroute('**/api/v1/dhcp/leases');
    await page.context().clearPermissions();
  }
});

// REQ: DNS-023 (T24.8, ADR-983) — a discovered device shows the IPv6 addresses its router reported (they answer AAAA and
// ip6.arpa PTR under its DNS name); a device without any says none; a network's device list shows them too.
test('dns_023 discovered device shows its ipv6 address', async () => {
  const items = [
    { ip: '10.20.2.41', mac: 'aa:bb:cc:dd:ee:41', hostname: 'kitchen-tablet', dnsName: 'kitchen-tablet.home.arpa', source: 'router', router: 'udm', expiresUnixSeconds: 0, ipv6: ['2001:db8:1::41', 'fd00:2::41'] },
    { ip: '10.20.2.42', mac: 'aa:bb:cc:dd:ee:42', hostname: 'printer', dnsName: 'printer.home.arpa', source: 'router', router: 'udm', expiresUnixSeconds: 0 },
  ];
  await page.route('**/api/v1/dhcp/leases', (route) => route.fulfill({ json: { items } }));
  await page.route('**/api/v1/networks', (route) => route.fulfill({ json: { items: NETWORKS } }));
  try {
    await page.goto('/#/');
    await page.goto('/#/clients?tab=discovered');
    const row = page.getByRole('row').filter({ hasText: '10.20.2.41' });
    await expect(row.getByTestId('dns-name')).toContainText('kitchen-tablet.home.arpa');
    await expect(row.getByTestId('ipv6')).toContainText('2001:db8:1::41');
    await expect(row.getByTestId('ipv6')).toContainText('fd00:2::41');
    await expect(page.getByRole('row').filter({ hasText: '10.20.2.42' }).getByTestId('ipv6')).toContainText('none');
    // The help topic opens from the column header.
    await page.getByRole('button', { name: "Help: See a device's IPv6 addresses" }).click();
    await expect(page.getByTestId('help-panel')).toContainText('ip6.arpa reverse name');
    await page.keyboard.press('Escape');
    // A network's device list shows them as well.
    await page.goto('/#/');
    await page.goto('/#/networks');
    await page.getByRole('row').filter({ hasText: '10.20.2.0/24' }).getByTestId('network-open').click();
    const dev = page.getByTestId('network-devices').getByRole('row').filter({ hasText: '10.20.2.41' });
    await expect(dev.getByTestId('network-ipv6')).toContainText('2001:db8:1::41, fd00:2::41');
  } finally {
    await page.unroute('**/api/v1/dhcp/leases');
    await page.unroute('**/api/v1/networks');
  }
});

// REQ: DNS-023 (T24.14) — without a clipboard (plain HTTP on the LAN) the Copy button says the name is selectable.
test('dns_023 copy falls back to select-to-copy when the clipboard is refused', async () => {
  const items = [{ ip: '10.20.2.33', mac: 'aa:bb:cc:dd:ee:33', hostname: 'hall', dnsName: 'hall.home.arpa', source: 'mdns', expiresUnixSeconds: 0 }];
  await page.route('**/api/v1/dhcp/leases', (route) => route.fulfill({ json: { items } }));
  try {
    // Leave the page first: a hash-only goto to the same URL doesn't re-fetch the leases.
    await page.goto('/#/');
    await page.goto('/#/clients?tab=discovered');
    await page.evaluate(() => {
      Object.defineProperty(navigator, 'clipboard', { value: { writeText: () => Promise.reject(new Error('denied')) }, configurable: true });
    });
    const row = page.getByRole('row').filter({ hasText: '10.20.2.33' });
    await row.getByRole('button', { name: /^Copy/ }).click();
    await expect(row.getByTestId('copy-status')).toHaveText('Select to copy');
  } finally {
    await page.unroute('**/api/v1/dhcp/leases');
    await page.evaluate(() => {
      Object.defineProperty(navigator, 'clipboard', { value: undefined, configurable: true });
    });
  }
});

// REQ: API-012 (T24.14) — the discovered table names the router that named each device, not the bare "router".
test('api_012 discovered devices name the router that named them', async () => {
  const items = [
    { ip: '10.20.2.41', mac: 'aa:bb:cc:dd:ee:41', hostname: 'hall-light', source: 'router', router: 'home-assistant', expiresUnixSeconds: 0 },
    { ip: '10.20.2.42', mac: 'aa:bb:cc:dd:ee:42', hostname: 'laptop', source: 'router', router: 'udm', expiresUnixSeconds: 0 },
    { ip: '10.20.2.43', mac: '', hostname: 'speaker', source: 'mdns', expiresUnixSeconds: 0 },
  ];
  await page.route('**/api/v1/dhcp/leases', (route) => route.fulfill({ json: { items } }));
  try {
    await page.goto('/#/');
    await page.goto('/#/clients?tab=discovered');
    await expect(page.getByRole('row').filter({ hasText: '10.20.2.41' }).getByTestId('named-by')).toHaveText('router: home-assistant');
    await expect(page.getByRole('row').filter({ hasText: '10.20.2.42' }).getByTestId('named-by')).toHaveText('router: udm');
    await expect(page.getByRole('row').filter({ hasText: '10.20.2.43' }).getByTestId('named-by')).toHaveText('mDNS');
    await expect(page.getByTestId('discovered')).toContainText('Home Assistant');
  } finally {
    await page.unroute('**/api/v1/dhcp/leases');
  }
});

// REQ: API-012 (T24.14, T23.7) — a router's name shows its type (UniFi, Home Assistant) once GET /routers says.
test('api_012 discovered devices name the type of their router', async () => {
  const items = [{ ip: '10.20.2.51', mac: 'aa:bb:cc:dd:ee:51', hostname: 'hall', source: 'router', router: 'udm', expiresUnixSeconds: 0 }];
  await page.route('**/api/v1/dhcp/leases', (route) => route.fulfill({ json: { items } }));
  await page.route('**/api/v1/routers', (route) => route.fulfill({ json: { items: [{ name: 'udm', kind: 'unifi' }] } }));
  try {
    await page.goto('/#/');
    await page.goto('/#/clients?tab=discovered');
    await expect(page.getByRole('row').filter({ hasText: '10.20.2.51' }).getByTestId('named-by')).toHaveText('router: udm (UniFi)');
  } finally {
    await page.unroute('**/api/v1/dhcp/leases');
    await page.unroute('**/api/v1/routers');
  }
});

// REQ: API-013 (T24.15) — the Networks page: each network's subnet, VLAN, DHCP pool, router, group,
// size, how full it is and its addresses outside the pool; a network only a group reports is badged.
const NETWORKS = [
  { name: 'Home', subnet: '10.20.2.0/24', gateway: '10.20.2.1', dhcpStart: '10.20.2.100', dhcpEnd: '10.20.2.200', domain: 'home.arpa', purpose: 'corporate', source: 'router', router: 'udm', group: 'lab', addresses: 254, devices: 60, usedPercent: 24, outsidePool: 4 },
  { name: 'IoT', subnet: '192.168.20.0/24', vlan: 20, gateway: '192.168.20.1', dhcpStart: '192.168.20.100', dhcpEnd: '192.168.20.200', purpose: 'iot', source: 'router', router: 'udm', addresses: 254, devices: 42, usedPercent: 17, outsidePool: 4 },
  { name: 'eth0.100', subnet: '198.51.100.0/24', vlan: 100, source: 'interface', addresses: 254, devices: 3, usedPercent: 1.2, outsidePool: 0 },
  { name: 'guests', subnet: '10.50.0.0/24', source: 'group', group: 'guests', addresses: 254, devices: 0, usedPercent: 0, outsidePool: 0 },
];
const DEVICES_ON_NETWORKS = [
  { ip: '192.168.20.31', mac: 'aa:bb:cc:dd:ee:31', hostname: 'plug', dnsName: 'plug.home.arpa', source: 'router', router: 'udm', expiresUnixSeconds: 0 },
  { ip: '10.20.2.31', mac: 'aa:bb:cc:dd:ee:32', hostname: 'laptop', dnsName: 'laptop.home.arpa', source: 'router', router: 'udm', expiresUnixSeconds: 0 },
];

test('api_013 networks page lists router networks', async () => {
  await page.route('**/api/v1/networks', (route) => route.fulfill({ json: { items: NETWORKS } }));
  await page.route('**/api/v1/dhcp/leases', (route) => route.fulfill({ json: { items: DEVICES_ON_NETWORKS } }));
  try {
    await page.goto('/#/');
    await page.goto('/#/networks');
    await expect(page.getByRole('heading', { name: /^Networks/ })).toBeVisible();
    const iot = page.getByRole('row').filter({ hasText: '192.168.20.0/24' });
    await expect(iot).toContainText('20');
    await expect(iot).toContainText('192.168.20.100 – 192.168.20.200');
    await expect(iot).toContainText('17%');
    await expect(iot.getByRole('img', { name: '17% used' })).toBeVisible();
    await expect(page.getByRole('row').filter({ hasText: '10.50.0.0/24' }).getByTestId('group-only')).toHaveText('group only');
    await expect(page.getByRole('row').filter({ hasText: '10.20.2.0/24' }).getByTestId('group-only')).toHaveCount(0);
    // REQ: API-013 (T24.32) — a network this node is directly on (a tagged VLAN interface) is badged, with its VLAN ID.
    const vlan = page.getByRole('row').filter({ hasText: '198.51.100.0/24' });
    await expect(vlan.getByTestId('this-node')).toHaveText('this node');
    await expect(vlan).toContainText('eth0.100');
    await expect(vlan).toContainText('100');
    await expect(page.getByRole('row').filter({ hasText: '192.168.20.0/24' }).getByTestId('this-node')).toHaveCount(0);
  } finally {
    await page.unroute('**/api/v1/networks');
    await page.unroute('**/api/v1/dhcp/leases');
  }
});

// REQ: API-013 (T24.15) — a row opens the devices on that network with their DNS names.
test('api_013 a network opens its devices with their DNS names', async () => {
  await page.route('**/api/v1/networks', (route) => route.fulfill({ json: { items: NETWORKS } }));
  await page.route('**/api/v1/dhcp/leases', (route) => route.fulfill({ json: { items: DEVICES_ON_NETWORKS } }));
  try {
    await page.goto('/#/');
    await page.goto('/#/networks');
    await page.getByRole('row').filter({ hasText: '192.168.20.0/24' }).getByTestId('network-open').click();
    const devices = page.getByTestId('network-devices');
    await expect(devices).toContainText('192.168.20.31');
    await expect(devices.getByTestId('network-dns-name')).toHaveText('plug.home.arpa');
    await expect(devices).not.toContainText('laptop.home.arpa');
  } finally {
    await page.unroute('**/api/v1/networks');
    await page.unroute('**/api/v1/dhcp/leases');
  }
});

// REQ: FLT-005 (T24.15) — "Make a group from this network" opens the Groups editor with the network filled in.
test('api_013 make a group from a network', async () => {
  await page.route('**/api/v1/networks', (route) => route.fulfill({ json: { items: NETWORKS } }));
  try {
    await page.goto('/#/');
    await page.goto('/#/networks');
    const iot = page.getByRole('row').filter({ hasText: '192.168.20.0/24' });
    await iot.getByTestId('make-group').click();
    await expect(page.getByRole('dialog', { name: 'Add group' })).toBeVisible();
    await expect(page.getByRole('textbox', { name: 'Networks', exact: true })).toHaveValue('192.168.20.0/24');
    await expect(page.getByRole('textbox', { name: 'Name', exact: true })).toHaveValue('iot');
    // A network a group already covers has no such action.
    await page.keyboard.press('Escape');
    await page.goto('/#/networks');
    await expect(page.getByRole('row').filter({ hasText: '10.20.2.0/24' }).getByTestId('make-group')).toHaveCount(0);
  } finally {
    await page.unroute('**/api/v1/networks');
  }
});

// REQ: API-013 (T24.15) — viewers read the networks; the make-a-group action is for operators.
test('api_013 viewer cannot make a group', async () => {
  const r = page.request;
  const csrf = (await (await r.get('/api/v1/auth/status')).json()).csrfToken as string;
  const made = await r.post('/api/v1/users', { headers: { 'x-csrf-token': csrf }, data: { username: VIEWER.user, password: VIEWER.pass, role: 'viewer' } });
  expect([200, 201, 409]).toContain(made.status());
  const view = await page.context().browser()!.newContext({ baseURL: page.url().split('/#')[0] });
  try {
    // No mock: the viewer's /networks comes from the real server (the node's group networks).
    const p = await view.newPage();
    await p.goto('/#/networks');
    await p.getByLabel('Username', { exact: true }).fill(VIEWER.user);
    await p.getByLabel('Password', { exact: true }).fill(VIEWER.pass);
    await p.getByRole('button', { name: 'Sign in' }).click();
    await expect(p.getByRole('row').filter({ hasText: '127.0.0.0/8' }).getByTestId('group-only')).toBeVisible({ timeout: 30_000 });
    await expect(p.getByTestId('make-group')).toHaveCount(0);
    // And the server refuses the write a viewer's form would send.
    const vcsrf = (await (await view.request.get('/api/v1/auth/status')).json()).csrfToken as string;
    const put = await view.request.put('/api/v1/groups/viewer-try', { headers: { 'x-csrf-token': vcsrf }, data: { networks: ['10.77.0.0/24'] } });
    expect(put.status()).toBe(403);
  } finally {
    await view.close();
  }
});

// REQ: API-013 (T24.15) — a node with no routers: the empty state says where networks come from.
test('api_013 networks page says where networks come from when there are none', async () => {
  await page.route('**/api/v1/networks', (route) => route.fulfill({ json: { items: [] } }));
  try {
    await page.goto('/#/');
    await page.goto('/#/networks');
    await expect(page.getByTestId('networks-empty')).toContainText('[[router]]');
  } finally {
    await page.unroute('**/api/v1/networks');
  }
});

// REQ: API-013, API-010, API-016 (T24.41) — what a replica answers when the primary reads the routers: the
// router's networks and their devices (no note), then the same page with the primary away (a note naming it).
test('api_013 a replica shows the primary router networks and says when the primary is away', async () => {
  const net = (name: string, subnet: string, vlan?: number) => ({
    name,
    subnet,
    vlan,
    gateway: subnet.replace('0/24', '1'),
    source: 'router',
    router: 'udm',
    addresses: 254,
    devices: 1,
    usedPercent: 0.4,
    outsidePool: 0,
  });
  const nets = [net('LAN', '192.168.1.0/24'), net('vlan-30', '192.168.30.0/24', 30), net('vlan-40', '192.168.40.0/24', 40)];
  const leases = [{ ip: '192.168.30.7', mac: 'aa:bb:cc:00:00:07', hostname: 'kids-tablet', source: 'router', router: 'udm', expiresUnixSeconds: 0, offline: false }];
  let missingNodes: string[] = [];
  await page.route('**/api/v1/networks', (route) => route.fulfill({ json: { items: nets, ...(missingNodes.length ? { missingNodes } : {}) } }));
  await page.route('**/api/v1/dhcp/leases', (route) => route.fulfill({ json: { items: leases } }));
  try {
    await page.goto('/#/');
    await page.goto('/#/networks');
    const row = page.getByRole('row').filter({ hasText: '192.168.30.0/24' });
    await expect(row).toContainText('vlan-30');
    await expect(row).toContainText('30');
    await expect(page.getByTestId('networks-missing')).toHaveCount(0);
    await row.getByTestId('network-open').click();
    await expect(page.getByTestId('network-devices')).toContainText('kids-tablet');
    await page.keyboard.press('Escape');
    missingNodes = ['node-a'];
    await page.reload();
    await expect(page.getByTestId('networks-missing')).toContainText('node-a');
  } finally {
    await page.unroute('**/api/v1/networks');
    await page.unroute('**/api/v1/dhcp/leases');
  }
});

// REQ: API-016 (T24.41) — a replica's Routers page shows the primary's status of a router only the primary reads,
// labelled as read by the primary; with the primary away it says so.
test('api_016 a replica shows the primary status of a router', async () => {
  const entry = (status: Record<string, unknown>) => ({
    name: 'udm',
    kind: 'unifi',
    url: 'https://192.168.1.1',
    source: 'api',
    definition: { name: 'udm', type: 'unifi', url: 'https://192.168.1.1', api_key_ref: 'udm' },
    setByFile: [],
    credentials: [{ field: 'api_key', source: 'stored', secret: 'udm', readable: true }],
    status,
  });
  let body: Record<string, unknown> = {
    items: [entry({ polledBy: 'the primary', state: 'ok', lastPoll: 1700000000, devices: 12, networks: 3, intervalSecs: 300, readBy: 'node-a' })],
  };
  await page.route('**/api/v1/routers', (route) => route.fulfill({ json: body }));
  try {
    await page.goto('/#/');
    await page.goto('/#/routers');
    const card = page.getByTestId('router-card').filter({ hasText: 'udm' });
    await expect(card.getByTestId('router-read-by')).toContainText('Read by the primary (node-a)');
    await expect(card.getByTestId('router-state')).toContainText('12 devices, 3 networks');
    await expect(page.getByTestId('routers-primary-missing')).toHaveCount(0);
    body = {
      items: [entry({ polledBy: 'the primary', state: 'skipped', devices: 0, networks: 0, intervalSecs: 300 })],
      missingNodes: ['node-a'],
    };
    await page.reload();
    await expect(page.getByTestId('routers-primary-missing')).toContainText('node-a');
    await expect(page.getByTestId('router-read-by')).toHaveCount(0);
  } finally {
    await page.unroute('**/api/v1/routers');
  }
});

// REQ: API-013 (T24.15) — the real node lists the networks its client groups name, as group only.
test('api_013 the node lists its group networks as group only', async () => {
  await page.goto('/#/');
  await page.goto('/#/networks');
  await expect(page.getByRole('row').filter({ hasText: '127.0.0.0/8' }).getByTestId('group-only')).toBeVisible({ timeout: 15_000 });
});

// REQ: API-013 (T24.15) — on a phone the secondary columns step aside and the page does not scroll sideways.
test('api_013 networks fit a phone width', async () => {
  const before = page.viewportSize();
  await page.route('**/api/v1/networks', (route) => route.fulfill({ json: { items: NETWORKS } }));
  try {
    await page.setViewportSize({ width: 390, height: 844 });
    await page.goto('/#/');
    await page.goto('/#/networks');
    await expect(page.getByTestId('network-open').first()).toBeVisible();
    const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
    expect(overflow).toBeLessThanOrEqual(0);
    await expect(page.getByRole('columnheader', { name: 'Gateway', exact: true })).toBeHidden();
    await expect(page.getByRole('columnheader', { name: 'Subnet', exact: true })).toBeVisible();
  } finally {
    await page.unroute('**/api/v1/networks');
    if (before) await page.setViewportSize(before);
  }
});

// REQ: API-013 (T24.15) — an IPv6 network's device list is IPv4 only, so the drawer says so rather than "no devices".
test('api_013 an IPv6 network says its device list is IPv4 only', async () => {
  const v6 = [{ name: 'v6-lan', subnet: 'fd00:1::/64', source: 'router', router: 'udm', addresses: 0, devices: 3, usedPercent: 0, outsidePool: 0 }];
  await page.route('**/api/v1/networks', (route) => route.fulfill({ json: { items: v6 } }));
  await page.route('**/api/v1/dhcp/leases', (route) => route.fulfill({ json: { items: DEVICES_ON_NETWORKS } }));
  try {
    await page.goto('/#/');
    await page.goto('/#/networks');
    await page.getByTestId('network-open').click();
    await expect(page.getByTestId('network-no-devices')).toContainText('IPv4 addresses only');
  } finally {
    await page.unroute('**/api/v1/networks');
    await page.unroute('**/api/v1/dhcp/leases');
  }
});

// REQ: FLT-005 (T24.15) — a group name already in use is not reused: the made group takes the next free name.
test('api_013 a made group takes a name no group uses', async () => {
  await page.route('**/api/v1/networks', (route) => route.fulfill({ json: { items: NETWORKS } }));
  await page.route(/\/api\/v1\/config\/entries/, (route) => {
    if (new URL(route.request().url()).searchParams.get('kind') !== 'group') return route.fallback();
    return route.fulfill({ json: { items: [{ kind: 'group', name: 'iot', source: 'file', definition: { networks: ['10.9.0.0/24'] } }] } });
  });
  try {
    await page.goto('/#/');
    await page.goto('/#/networks');
    await page.getByRole('row').filter({ hasText: '192.168.20.0/24' }).getByTestId('make-group').click();
    await expect(page.getByRole('textbox', { name: 'Name', exact: true })).toHaveValue('iot-2');
    await expect(page.getByRole('textbox', { name: 'Networks', exact: true })).toHaveValue('192.168.20.0/24');
  } finally {
    await page.unroute('**/api/v1/networks');
    await page.unroute(/\/api\/v1\/config\/entries/);
  }
});

// REQ: FLT-005 (T24.15) — the draft opens once: the URL is cleaned, so a reload does not reopen the editor.
test('api_013 a made group draft does not reopen on reload', async () => {
  await page.route('**/api/v1/networks', (route) => route.fulfill({ json: { items: NETWORKS } }));
  try {
    await page.goto('/#/');
    await page.goto('/#/networks');
    await page.getByRole('row').filter({ hasText: '192.168.20.0/24' }).getByTestId('make-group').click();
    await expect(page.getByRole('dialog', { name: 'Add group' })).toBeVisible();
    await expect(page).toHaveURL(/#\/groups$/);
    await page.reload();
    await expect(page.getByRole('heading', { name: /^Groups/ })).toBeVisible();
    await expect(page.getByRole('dialog', { name: 'Add group' })).toHaveCount(0);
  } finally {
    await page.unroute('**/api/v1/networks');
  }
});

// REQ: DSC-001 (T25.2, ADR-907, ADR-928) — the network inventory's settings are admin-only: an admin
// sees the controls; an operator sees them read-only, and the server refuses an operator's write.
test('dsc_001 network inventory settings are admin-only', async () => {
  await page.goto('/#/network-inventory');
  const settings = page.getByTestId('inventory-settings');
  await expect(settings.getByRole('switch', { name: 'Turn the network inventory on' })).toBeEnabled();
  await expect(settings.getByRole('button', { name: 'Check', exact: true })).toBeVisible();
  const OPERATOR = { user: 'operator2', pass: 'operator long password' };
  const csrf = await csrfOf(page.request);
  await page.request.post('/api/v1/users', { headers: { 'x-csrf-token': csrf }, data: { username: OPERATOR.user, password: OPERATOR.pass, role: 'operator' } });
  const op = await page.context().browser()!.newContext({ baseURL: page.url().split('/#')[0] });
  try {
    const p = await op.newPage();
    await p.goto('/#/network-inventory');
    await p.getByLabel('Username', { exact: true }).fill(OPERATOR.user);
    await p.getByLabel('Password', { exact: true }).fill(OPERATOR.pass);
    await p.getByRole('button', { name: 'Sign in' }).click();
    const mine = p.getByTestId('inventory-settings');
    await expect(mine.getByText('Only an administrator can change the network inventory')).toBeVisible({ timeout: 30_000 });
    await expect(mine.getByRole('button', { name: 'Check', exact: true })).toHaveCount(0);
    await expect(mine.getByRole('switch', { name: 'Turn the network inventory on' })).toBeDisabled();
    // REQ: DSC-009 — the extra read switches are read-only for an operator too.
    for (const name of ['UniFi client fields', 'UniFi client history', 'UniFi devices and ports', 'Home Assistant devices without entities']) {
      await expect(mine.getByRole('switch', { name })).toBeDisabled();
    }
    const ocsrf = await csrfOf(op.request);
    const moved = await op.request.put('/api/v1/discovery-settings/default', { headers: { 'x-csrf-token': ocsrf }, data: { enabled: true, worker_memory_mib: 64 } });
    expect(moved.status()).toBe(403);
    expect(await moved.text()).toContain('enabled');
  } finally {
    await op.close();
  }
});

// REQ: DSC-001 (T25.2, ADR-914) — a field the configuration files set is locked, and labelled as set
// by file; the fields the files leave alone stay editable.
test('dsc_001 file-set discovery shows set by file', async () => {
  const entry = {
    items: [{
      kind: 'discovery', name: 'default', source: 'file',
      definition: { enabled: true, node: null, worker_memory_mib: 64, subnet: [{ cidr: '192.168.1.0/24' }] },
      redacted: [], credentialIssues: [], setByFile: ['enabled', 'subnet'], answering: null,
    }],
  };
  await page.route(/\/api\/v1\/config\/entries\?kind=discovery/, (route) => route.fulfill({ json: entry }));
  try {
    // Leave the page first, so the page mounts again and reads the mocked entry.
    await page.goto('/#/');
    await page.goto('/#/network-inventory');
    const settings = page.getByTestId('inventory-settings');
    await expect(settings.getByTestId('set-by-file')).toHaveCount(2);
    await expect(settings.getByRole('switch', { name: 'Turn the network inventory on' })).toBeDisabled();
    await expect(settings.getByLabel('Subnets it may read')).toBeDisabled();
    await expect(settings.getByLabel('Designated node')).toBeEnabled();
  } finally {
    await page.unroute(/\/api\/v1\/config\/entries\?kind=discovery/).catch(() => {});
  }
});

// REQ: DSC-002 (T25.3, DSC-014, ADR-908) — a discovery worker that keeps stopping shows on the
// network inventory page, with its restarts, and DNS is not mentioned as affected.
test('dsc_002 failing worker shows on the inventory page', async () => {
  const status = {
    enabled: true, designated: true, node: null,
    workers: [{
      worker: 'snmp', up: false, restarts: 4, versionMismatch: false, failing: true,
      lastError: 'the worker exited (signal: 6)', dataLimitMib: null, dumpable: false, oomScoreAdj: 1000,
    }],
  };
  await page.route(/\/api\/v1\/discovery\/status/, (route) => route.fulfill({ json: status }));
  try {
    await page.goto('/#/');
    await page.goto('/#/network-inventory');
    await expect(page.getByTestId('inventory-state')).toHaveText('Runs on this node');
    const row = page.getByTestId('worker-snmp');
    await expect(row.getByTestId('worker-failing')).toHaveText('failing');
    await expect(row).toContainText('4');
    await expect(page.getByTestId('inventory-status')).toContainText('the worker exited');
  } finally {
    await page.unroute(/\/api\/v1\/discovery\/status/).catch(() => {});
  }
});

// REQ: DSC-001 (T25.2, ADR-928) — an admin checks a change, applies exactly what was checked, and then
// drops the stored settings for the file's again. The real server answers every step.
test('dsc_001 admin checks then applies, then uses the file settings', async () => {
  await page.goto('/#/network-inventory');
  const settings = page.getByTestId('inventory-settings');
  await settings.getByLabel('Subnets it may read').fill('192.168.50.0/24');
  await settings.getByRole('button', { name: 'Check', exact: true }).click();
  await expect(page.getByTestId('inventory-preview')).toBeVisible();
  await settings.getByRole('button', { name: 'Apply', exact: true }).click();
  await expect(page.getByRole('status').filter({ hasText: 'Saved.' })).toBeVisible();
  await expect(settings.getByLabel('Subnets it may read')).toHaveValue('192.168.50.0/24');
  await settings.getByTestId('inventory-use-file').click();
  await expect(page.getByRole('status').filter({ hasText: "Back to the configuration file's settings." })).toBeVisible();
  await expect(settings.getByTestId('inventory-use-file')).toHaveCount(0);
});

// REQ: DSC-001 (T25.2, ADR-928) — a subnet outside RFC 1918 is refused with the server's message, and
// nothing is applied: the Apply button is not offered for a refused check.
test('dsc_001 a refused subnet shows the refusal', async () => {
  await page.goto('/#/network-inventory');
  const settings = page.getByTestId('inventory-settings');
  await settings.getByLabel('Subnets it may read').fill('8.8.8.0/24');
  await settings.getByRole('button', { name: 'Check', exact: true }).click();
  await expect(page.getByRole('alert').filter({ hasText: "isn't a private (RFC 1918) network" })).toBeVisible();
  await expect(settings.getByRole('button', { name: 'Apply', exact: true })).toHaveCount(0);
  // The refusal is expected: the browser logs the 422 as a console error, which the test removes.
  for (let i = problems.length - 1; i >= 0; i--) if (problems[i].includes('status of 422')) problems.splice(i, 1);
});

// REQ: DSC-001 (T25.2, ADR-928) — the first write is refused while a member is older than the release
// that carries `[discovery]`; the refusal's own message is shown (the members are mocked).
test('dsc_001 members too old is shown', async () => {
  const detail = "the network inventory can't be turned on while pi-b runs an older version than this one: it can't read `[discovery]`";
  await page.route(/\/api\/v1\/discovery-settings\/default/, (route) => {
    if (route.request().method() !== 'PUT') return route.fallback();
    return route.fulfill({ status: 409, json: { type: 'about:blank', title: 'Conflict', status: 409, detail, code: 'members_too_old' } });
  });
  try {
    await page.goto('/#/');
    await page.goto('/#/network-inventory');
    const settings = page.getByTestId('inventory-settings');
    await settings.getByLabel('Subnets it may read').fill('192.168.60.0/24');
    await settings.getByRole('button', { name: 'Check', exact: true }).click();
    await expect(page.getByRole('alert').filter({ hasText: 'pi-b runs an older version' })).toBeVisible();
    await expect(settings.getByRole('button', { name: 'Apply', exact: true })).toHaveCount(0);
    // The refusal is expected: the browser logs the 409 as a console error, which the test removes.
    for (let i = problems.length - 1; i >= 0; i--) if (/status of 409/.test(problems[i])) problems.splice(i, 1);
  } finally {
    await page.unroute(/\/api\/v1\/discovery-settings\/default/).catch(() => {});
    await page.goto('/#/network-inventory');
  }
});

// REQ: DSC-001 (T25.2, ADR-928) — a poll does not overwrite what an admin is typing: the form is
// refilled only while it still holds the stored settings.
test('dsc_001 a poll keeps unsaved edits', async () => {
  await page.goto('/#/network-inventory');
  const settings = page.getByTestId('inventory-settings');
  const node = settings.getByLabel('Designated node');
  await node.fill('pi-unsaved');
  // The page polls every 15 s; wait past one poll before looking again.
  await page.waitForTimeout(16_000);
  await expect(node).toHaveValue('pi-unsaved');
  await node.fill('');
});

// REQ: DSC-004, DSC-007 (T25.6, ADR-908, ADR-1001, ADR-1002) — an admin adds a credential and an agent,
// checks and applies them (the real server validates and stores them), then tests the saved agent.
// The test itself is mocked: the e2e node runs no SNMP poller (the inventory is off), so the real
// answer is `discovery_not_here`; the mock gives the dry run's OIDs, a capability record, and the
// 60-second cooldown refusal.
test('dsc_004 add an agent and test it', async () => {
  // Leave the page first, so it mounts again and reads the stored settings (an earlier test mocked them).
  await page.goto('/#/');
  await page.goto('/#/network-inventory');
  const settings = page.getByTestId('inventory-settings');
  // A credential: the form names files, and holds no secret field.
  await settings.getByTestId('credential-add').click();
  const cform = settings.getByTestId('credential-form');
  await cform.getByLabel('Credential name').fill('gw-v3');
  await cform.getByLabel('SNMP user').fill('wrendns');
  await cform.getByLabel('Authentication password file').fill('/run/secrets/snmp-auth');
  await cform.getByTestId('credential-keep').click();
  await expect(settings.getByTestId('credential-gw-v3')).toContainText('v3 authPriv');
  // The agent needs a credential and a private address; a bad name is refused in the form.
  await settings.getByTestId('agent-add').click();
  const aform = settings.getByTestId('agent-form');
  await aform.getByLabel('Agent name').fill('10.0.0.1');
  await aform.getByLabel('Agent address').fill('10.0.0.1');
  await aform.getByTestId('agent-keep').click();
  await expect(aform.getByRole('alert')).toContainText('is not an address');
  await aform.getByLabel('Agent name').fill('gateway');
  await aform.getByLabel('Agent credential').selectOption('gw-v3');
  await aform.getByTestId('agent-keep').click();
  await expect(settings.getByTestId('agent-gateway')).toContainText('10.0.0.1');
  // An unsaved agent can't be tested yet.
  await expect(settings.getByRole('button', { name: 'Test agent gateway' })).toBeDisabled();
  // The real server checks the whole change and stores exactly what was checked.
  await settings.getByRole('button', { name: 'Check', exact: true }).click();
  await expect(page.getByTestId('inventory-preview')).toBeVisible();
  await settings.getByRole('button', { name: 'Apply', exact: true }).click();
  await expect(page.getByRole('status').filter({ hasText: 'Saved.' })).toBeVisible();
  await expect(settings.getByTestId('agent-gateway')).toBeVisible();
  await expect(settings.getByRole('button', { name: 'Test agent gateway' })).toBeEnabled();

  let tests = 0;
  await page.route(/\/api\/v1\/discovery\/snmp\/test/, async (route) => {
    tests += 1;
    const body = route.request().postDataJSON() as { agent: string };
    expect(Object.keys(body)).toEqual(['agent']);
    const dry = route.request().url().includes('dryRun=true');
    const base = { agent: 'gateway', dryRun: dry, ok: true, node: 'e2e', durationMs: dry ? null : 412 };
    if (dry) {
      return route.fulfill({
        json: {
          ...base,
          note: 'Nothing was sent (dry run).',
          oids: [{ table: 'arp', part: 'arp', alternative: 'ipNetToPhysicalTable', probeOid: '1.3.6.1.2.1.4.35.1.4', columns: ['1.3.6.1.2.1.4.35.1.4'] }],
        },
      });
    }
    if (tests > 2) {
      return route.fulfill({
        status: 429,
        headers: { 'retry-after': '42' },
        json: { type: 'about:blank', title: 'Too many attempts', status: 429, code: 'rate_limited', detail: '`gateway` was tested less than a minute ago', hint: 'Try again in 42 seconds.' },
      });
    }
    return route.fulfill({
      json: {
        ...base,
        note: 'Capabilities updated.',
        oids: [],
        capability: {
          probedUnix: 1_800_000_000, level: 'authPriv', engineId: '80000009030011223344', sysObjectId: '1.3.6.1.4.1.8072.3.2.10',
          parts: [
            { table: 'arp', part: 'arp', source: 'ipNetToPhysicalTable' },
            { table: 'bridge', part: 'forwarding', source: null },
          ],
        },
      },
    });
  });
  try {
    await settings.getByRole('button', { name: 'Test agent gateway' }).click();
    const panel = page.getByTestId('snmp-test');
    await expect(panel).toContainText('Test gateway');
    await panel.getByTestId('test-dry').click();
    await expect(panel.getByTestId('test-result')).toContainText('ipNetToPhysicalTable');
    await expect(panel.getByTestId('test-result')).toContainText('1.3.6.1.2.1.4.35.1.4');
    await panel.getByTestId('test-now').click();
    await expect(panel.getByTestId('cap-level')).toHaveText('authPriv');
    await expect(panel.getByTestId('cap-parts')).toContainText('ipNetToPhysicalTable');
    await expect(panel.getByTestId('cap-parts')).toContainText('no alternative answered (skipped)');
    // The cooldown's refusal is shown in words, with its hint.
    await panel.getByTestId('test-now').click();
    await expect(panel.getByRole('alert')).toContainText('tested less than a minute ago');
    await expect(panel.getByRole('alert')).toContainText('Try again in 42 seconds');
    // The 429 is expected: the browser logs it as a console error, which the test removes.
    for (let i = problems.length - 1; i >= 0; i--) if (/status of 429/.test(problems[i])) problems.splice(i, 1);
  } finally {
    await page.unroute(/\/api\/v1\/discovery\/snmp\/test/).catch(() => {});
  }
  // Delete both again and apply, then use the file's settings (back to the e2e server's defaults).
  await settings.getByRole('button', { name: 'Delete agent gateway' }).click();
  await settings.getByRole('button', { name: 'Delete credential gw-v3' }).click();
  await expect(settings.getByTestId('agents-empty')).toBeVisible();
  await settings.getByRole('button', { name: 'Check', exact: true }).click();
  await settings.getByRole('button', { name: 'Apply', exact: true }).click();
  await expect(page.getByRole('status').filter({ hasText: 'Saved.' })).toBeVisible();
  await settings.getByTestId('inventory-use-file').click();
  await expect(page.getByRole('status').filter({ hasText: "Back to the configuration file's settings." })).toBeVisible();
});

// REQ: DSC-004 (T25.6) — an operator sees the agents and credentials read-only, with the poller's
// state; no control changes them or tests one, and the server refuses an operator's write and test.
test('dsc_004 operator sees agents read-only', async () => {
  const entry = {
    items: [{
      kind: 'discovery', name: 'default', source: 'override',
      definition: {
        enabled: true, node: null, worker_memory_mib: 64, subnet: [{ cidr: '192.168.1.0/24' }],
        snmp_credential: [{ name: 'gw-v3', role: 'infrastructure', version: 'v3', user: 'wrendns', auth_protocol: 'sha', auth_password_file: '/run/secrets/a', priv_protocol: 'aes-128' }],
        snmp_agent: [{ name: 'gateway', address: '192.168.1.1', port: 161, credential: 'gw-v3', interval_secs: 300, max_repetitions: 10, tables: ['arp', 'ifmib'] }],
      },
      redacted: [], credentialIssues: [], setByFile: [], answering: null,
    }],
  };
  const status = {
    enabled: true, designated: true, node: null, workers: [],
    agents: [{
      name: 'gateway', address: '192.168.1.1', credential: 'gw-v3', intervalSecs: 300, state: 'failing',
      lastPollUnix: 1_800_000_000, lastSuccessUnix: null, lastDurationMs: null, lastError: 'no reply (timeout)',
      consecutiveFailures: 3, polls: 3, failures: 3, lastRequests: 3, lastTimeouts: 3,
      tables: [{ table: 'arp', state: 'unprobed', rows: null, stop: null, error: null }, { table: 'ifmib', state: 'unprobed', rows: null, stop: null, error: null }],
      capability: null, lastCounts: null, lastTestUnix: null,
    }],
  };
  const mock = async (p: import('@playwright/test').Page) => {
    await p.route(/\/api\/v1\/config\/entries\?kind=discovery/, (route) => route.fulfill({ json: entry }));
    await p.route(/\/api\/v1\/discovery\/status/, (route) => route.fulfill({ json: status }));
  };
  const OPERATOR = { user: 'operator2', pass: 'operator long password' };
  const csrf = await csrfOf(page.request);
  await page.request.post('/api/v1/users', { headers: { 'x-csrf-token': csrf }, data: { username: OPERATOR.user, password: OPERATOR.pass, role: 'operator' } });
  // The admin sees every control on the same data.
  await mock(page);
  try {
    await page.goto('/#/');
    await page.goto('/#/network-inventory');
    const mine = page.getByTestId('inventory-settings');
    await expect(mine.getByTestId('agent-gateway').getByTestId('agent-state')).toHaveText('Failing');
    await expect(mine.getByTestId('agent-gateway').getByTestId('agent-error')).toHaveText('no reply (timeout)');
    await expect(mine.getByRole('button', { name: 'Edit agent gateway' })).toBeVisible();
    await expect(mine.getByRole('button', { name: 'Test agent gateway' })).toBeEnabled();
  } finally {
    await page.unroute(/\/api\/v1\/config\/entries\?kind=discovery/).catch(() => {});
    await page.unroute(/\/api\/v1\/discovery\/status/).catch(() => {});
  }
  const op = await page.context().browser()!.newContext({ baseURL: page.url().split('/#')[0] });
  try {
    const p = await op.newPage();
    await mock(p);
    await p.goto('/#/network-inventory');
    await p.getByLabel('Username', { exact: true }).fill(OPERATOR.user);
    await p.getByLabel('Password', { exact: true }).fill(OPERATOR.pass);
    await p.getByRole('button', { name: 'Sign in' }).click();
    const mine = p.getByTestId('inventory-settings');
    await expect(mine.getByTestId('agent-gateway')).toBeVisible({ timeout: 30_000 });
    await expect(mine.getByTestId('agent-gateway').getByTestId('agent-state')).toHaveText('Failing');
    await expect(mine.getByTestId('credential-gw-v3')).toContainText('v3 authPriv');
    for (const name of ['Edit agent gateway', 'Delete agent gateway', 'Test agent gateway', 'Edit credential gw-v3', 'Delete credential gw-v3']) {
      await expect(mine.getByRole('button', { name })).toHaveCount(0);
    }
    await expect(mine.getByTestId('agent-add')).toHaveCount(0);
    await expect(mine.getByTestId('credential-add')).toHaveCount(0);
    // The server refuses an operator's write and test too, whatever the page shows.
    const ocsrf = await csrfOf(op.request);
    const test = await op.request.post('/api/v1/discovery/snmp/test', { headers: { 'x-csrf-token': ocsrf }, data: { agent: 'gateway' } });
    expect(test.status()).toBe(403);
    const write = await op.request.put('/api/v1/discovery-settings/default', { headers: { 'x-csrf-token': ocsrf }, data: { snmp_credential: [{ name: 'c', community_file: '/run/secrets/c' }], snmp_agent: [{ name: 'x', address: '10.0.0.1', credential: 'c' }] } });
    expect(write.status()).toBe(403);
    expect(await write.text()).toContain('snmp_agent');
  } finally {
    await op.close();
  }
});

// REQ: DSC-004 (T25.6, ADR-914) — a list the configuration files set is locked, and labelled as set by
// file: the Add, Edit, Delete and Test controls are not offered for it.
test('dsc_004 file-set agents show set by file', async () => {
  const entry = {
    items: [{
      kind: 'discovery', name: 'default', source: 'file',
      definition: {
        enabled: true, node: null, worker_memory_mib: 64, subnet: [],
        snmp_credential: [{ name: 'gw', role: 'infrastructure', version: 'v2c', community_file: '/run/secrets/c' }],
        snmp_agent: [{ name: 'gateway', address: '192.168.1.1', port: 161, credential: 'gw', interval_secs: 300, max_repetitions: 10, tables: ['arp'] }],
      },
      redacted: [], credentialIssues: [], setByFile: ['snmp_agent', 'snmp_credential'], answering: null,
    }],
  };
  await page.route(/\/api\/v1\/config\/entries\?kind=discovery/, (route) => route.fulfill({ json: entry }));
  try {
    await page.goto('/#/');
    await page.goto('/#/network-inventory');
    const settings = page.getByTestId('inventory-settings');
    await expect(settings.getByTestId('agent-gateway')).toBeVisible();
    await expect(settings.getByTestId('inventory-agents').getByTestId('set-by-file')).toBeVisible();
    await expect(settings.getByTestId('inventory-credentials').getByTestId('set-by-file')).toBeVisible();
    await expect(settings.getByTestId('agent-add')).toHaveCount(0);
    await expect(settings.getByRole('button', { name: 'Edit agent gateway' })).toHaveCount(0);
    await expect(settings.getByRole('button', { name: 'Test agent gateway' })).toHaveCount(0);
    // A v2c credential is flagged: its community crosses the LAN in clear text.
    await expect(settings.getByTestId('credential-gw')).toContainText('clear text');
  } finally {
    await page.unroute(/\/api\/v1\/config\/entries\?kind=discovery/).catch(() => {});
  }
});

// REQ: DSC-007 (T25.6) — a credential names files, never a secret: the form has no password field, a
// v2c credential warns that its community is clear text, and the server refuses an inline secret
// (the key is unknown) without echoing it.
test('dsc_007 credential form names files and takes no secret', async () => {
  // Leave the page first, so it mounts again and reads the stored settings (an earlier test mocked them).
  await page.goto('/#/');
  await page.goto('/#/network-inventory');
  const settings = page.getByTestId('inventory-settings');
  await settings.getByTestId('credential-add').click();
  const form = settings.getByTestId('credential-form');
  await expect(form.getByLabel('Authentication password file')).toBeVisible();
  await expect(page.locator('input[type=password]')).toHaveCount(0);
  await form.getByLabel('SNMP version').selectOption('v2c');
  await expect(form.getByTestId('v2c-warning')).toContainText('clear text');
  await expect(form.getByLabel('Community file')).toBeVisible();
  // The protocols the client refuses are not on offer, and the form says why.
  await form.getByLabel('SNMP version').selectOption('v3');
  const auth = await form.getByLabel('Authentication protocol').locator('option').allTextContents();
  expect(auth.join(' ')).not.toMatch(/MD5|SHA-224/);
  await expect(form).toContainText('MD5, SHA-224, DES, AES-192, AES-256 and no authentication are refused');
  await form.getByRole('button', { name: 'Cancel' }).click();
  // An inline secret is not a key the server knows.
  const csrf = await csrfOf(page.request);
  const planted = 'planted-community-9d2f';
  const res = await page.request.put('/api/v1/discovery-settings/default', {
    headers: { 'x-csrf-token': csrf },
    params: { dryRun: 'true' },
    data: { snmp_credential: [{ name: 'c', community: planted }] },
  });
  expect(res.status()).toBe(422);
  expect(await res.text()).not.toContain(planted);
});

// REQ: DSC-009 (T25.10, ADR-912) — an admin turns on the extra UniFi reads, sets the history window and
// the Home Assistant switch, checks and applies; the server keeps them across a reload; a window out of
// range is refused with the server's message. UniFi's reads start off, Home Assistant's on.
test('dsc_009 unifi read toggles', async () => {
  await page.goto('/#/network-inventory');
  const settings = page.getByTestId('inventory-settings');
  const unifi = ['UniFi client fields', 'UniFi client history', 'UniFi devices and ports'];
  const ha = settings.getByRole('switch', { name: 'Home Assistant devices without entities' });
  const window_ = settings.getByLabel('History window in hours');
  for (const name of unifi) await expect(settings.getByRole('switch', { name })).not.toBeChecked();
  await expect(ha).toBeChecked();
  await expect(window_).toHaveValue('720');
  for (const name of unifi) await settings.getByRole('switch', { name }).check();
  await ha.uncheck();
  await window_.fill('48');
  await settings.getByRole('button', { name: 'Check', exact: true }).click();
  await expect(page.getByTestId('inventory-preview')).toBeVisible();
  await settings.getByRole('button', { name: 'Apply', exact: true }).click();
  await expect(page.getByRole('status').filter({ hasText: 'Saved.' })).toBeVisible();
  await page.reload();
  for (const name of unifi) await expect(settings.getByRole('switch', { name })).toBeChecked();
  await expect(settings.getByRole('switch', { name: 'Home Assistant devices without entities' })).not.toBeChecked();
  await expect(settings.getByLabel('History window in hours')).toHaveValue('48');
  // A window out of range is refused, and nothing is offered to apply.
  await settings.getByLabel('History window in hours').fill('0');
  await settings.getByRole('button', { name: 'Check', exact: true }).click();
  await expect(page.getByRole('alert').filter({ hasText: 'from 1 to 8,760' })).toBeVisible();
  await expect(settings.getByRole('button', { name: 'Apply', exact: true })).toHaveCount(0);
  // The refusal is expected: the browser logs the 422 as a console error, which the test removes.
  for (let i = problems.length - 1; i >= 0; i--) if (problems[i].includes('status of 422')) problems.splice(i, 1);
  // Back to the file's settings (the defaults here).
  await page.reload();
  await settings.getByTestId('inventory-use-file').click();
  await expect(page.getByRole('status').filter({ hasText: "Back to the configuration file's settings." })).toBeVisible();
  for (const name of unifi) await expect(settings.getByRole('switch', { name })).not.toBeChecked();
  await expect(settings.getByRole('switch', { name: 'Home Assistant devices without entities' })).toBeChecked();
});

// REQ: DSC-009 (ADR-912) — a read the console refuses shows in the status with its reason; the reads
// that work show their rows (and say when they were cut at the cap).
test('dsc_009 refused read shows on the inventory page', async () => {
  const status = {
    enabled: true, designated: true, node: null, workers: [],
    reads: [
      { router: 'udm', read: 'devices', state: 'refused', rows: 0, truncated: false, error: 'http://192.168.1.1/proxy/network/api/s/default/stat/device: HTTP 403 Forbidden (the key or user cannot read it)', at: 1 },
      { router: 'udm', read: 'all_users', state: 'ok', rows: 8192, truncated: true, error: null, at: 1 },
    ],
  };
  await page.route(/\/api\/v1\/discovery\/status/, (route) => route.fulfill({ json: status }));
  try {
    await page.goto('/#/');
    await page.goto('/#/network-inventory');
    const dev = page.getByTestId('read-udm-devices');
    await expect(dev.getByTestId('read-state')).toHaveText('refused');
    await expect(dev).toContainText('HTTP 403');
    const hist = page.getByTestId('read-udm-all_users');
    await expect(hist.getByTestId('read-state')).toHaveText('ok');
    await expect(hist).toContainText('8192');
    await expect(hist).toContainText('cut at 8,192');
  } finally {
    await page.unroute(/\/api\/v1\/discovery\/status/).catch(() => {});
  }
});

// REQ: OBS-039 (ADR-167) — domain icons: a brand tile for a name the map knows (Netflix), a monogram
// or a house for the rest. The Domain icons card (Settings → Account) picks Brand and monogram,
// Monogram only (no brand tile) or Off, and Default (20 px) or Small (16 px); the choice is kept for
// this user in this browser. The glyphs are a lazy chunk: loading it must not trip the CSP.
test('obs_039 domain icons', async () => {
  await page.setViewportSize({ width: 1280, height: 800 });
  await query('www.netflix.com').catch(() => -1);
  const row = () => page.locator('tbody tr').filter({ hasText: 'www.netflix.com' }).first();
  const mark = () => row().getByTestId('domain-icon');
  await page.goto('/#/queries?name=www.netflix.com');
  await expect(async () => {
    await page.reload();
    await expect(mark()).toBeVisible({ timeout: 2000 });
  }).toPass({ timeout: 20_000 });
  await expect(mark()).toHaveAttribute('data-kind', 'brand');
  await expect(mark()).toHaveAttribute('data-size', '20');
  await expect(mark()).toHaveAttribute('title', 'Netflix');

  await page.goto('/#/settings?tab=account');
  const card = page.getByTestId('icons-card');
  const icons = card.getByTestId('domain-icon');
  await expect(icons).toHaveCount(3);
  await expect(icons.nth(0)).toHaveAttribute('data-kind', 'brand');
  await expect(icons.nth(1)).toHaveAttribute('data-kind', 'mono');
  await expect(icons.nth(2)).toHaveAttribute('data-kind', 'house');
  await card.getByRole('button', { name: 'Monogram only' }).click();
  await expect(icons.nth(0)).toHaveAttribute('data-kind', 'mono');
  await card.getByRole('button', { name: 'Small', exact: true }).click();
  for (let i = 0; i < 3; i++) await expect(icons.nth(i)).toHaveAttribute('data-size', '16');
  await card.getByRole('button', { name: 'Off', exact: true }).click();
  await expect(icons).toHaveCount(0);
  await expect(card.getByRole('button', { name: 'Small', exact: true })).toBeDisabled();

  // Kept for this user in this browser, and drawn nowhere while it is Off.
  await page.reload();
  await expect(card.getByRole('button', { name: 'Off', exact: true })).toHaveAttribute('aria-pressed', 'true');
  await page.goto('/#/queries?name=www.netflix.com');
  await expect(row()).toBeVisible();
  await expect(mark()).toHaveCount(0);

  // Back to the defaults, for whatever runs next.
  await page.goto('/#/settings?tab=account');
  await card.getByRole('button', { name: 'Brand and monogram', exact: true }).click();
  await card.getByRole('button', { name: 'Default', exact: true }).click();
  await expect(icons.nth(0)).toHaveAttribute('data-kind', 'brand');
  await expect(icons.nth(0)).toHaveAttribute('data-size', '20');
});

// REQ: API-005, NFR-001 (ADR-168) — the UI is embedded gzipped only: a browser gets the stored
// file with `Content-Encoding: gzip`, and a client that doesn't accept gzip gets the same file
// inflated. Both are the page, and the page's script comes either way.
test('api_005 the UI is served gzipped, and plain to a client that does not accept gzip', async () => {
  const r = page.request;
  const gz = await r.get('/', { headers: { 'accept-encoding': 'gzip' } });
  expect(gz.status()).toBe(200);
  expect(gz.headers()['content-encoding']).toBe('gzip');
  const plain = await r.get('/', { headers: { 'accept-encoding': 'identity' } });
  expect(plain.status()).toBe(200);
  expect(plain.headers()['content-encoding']).toBeUndefined();
  const html = await plain.text();
  expect(html).toContain('<title>WrenDNS');
  expect(await gz.text()).toBe(html);
  const src = /src="(\/assets\/[^"]+\.js)"/.exec(html)?.[1];
  expect(src, 'index.html names its script').toBeTruthy();
  const js = await r.get(src as string, { headers: { 'accept-encoding': 'identity' } });
  expect(js.status()).toBe(200);
  expect(js.headers()['content-encoding']).toBeUndefined();
  expect(js.headers()['content-type']).toContain('javascript');
  expect((await js.body()).length).toBeGreaterThan(100_000);
});

// REQ: T8.2 (ADR-166) — a UniFi router's offline window is on its form: 30 days by default, a value
// past a year is refused, and the value saved is the value reopened (0 keeps connected clients only).
test('t8_2 offline clients days in the UniFi form', async () => {
  await page.setViewportSize({ width: 1280, height: 900 });
  await page.goto('/#/routers');
  await expect(page.locator('h1', { hasText: 'Routers' })).toBeVisible({ timeout: 20_000 });
  await page.getByTestId('routers-add').click();
  await page.getByRole('combobox', { name: 'Kind' }).selectOption('unifi');
  await page.getByRole('textbox', { name: 'Name', exact: true }).fill('lab-offline');
  await page.getByRole('textbox', { name: 'Address', exact: true }).fill('https://127.0.0.1:9');
  await fillCredential('API key', 'unifi-e2e-key-7782');
  const days = page.getByRole('spinbutton', { name: "Keep offline clients' names (days)", exact: true });
  await expect(days).toHaveValue('30');
  await days.fill('400');
  await page.getByRole('button', { name: 'Save the router' }).click();
  await expect(page.getByRole('alert')).toContainText('Keep offline clients for 0 to 365 days');
  await days.fill('0');
  const put = page.waitForRequest((r) => r.method() === 'PUT' && r.url().includes('/api/v1/routers/lab-offline'));
  await page.getByRole('button', { name: 'Save the router' }).click();
  expect((await put).postDataJSON().offline_days).toBe(0);
  const card = page.getByTestId('router-card').filter({ hasText: 'lab-offline' });
  await expect(card).toBeVisible({ timeout: 10_000 });
  await card.getByTestId('router-edit').click();
  await expect(page.getByRole('spinbutton', { name: "Keep offline clients' names (days)", exact: true })).toHaveValue('0');
  await page.getByRole('button', { name: 'Cancel', exact: true }).click();
  await card.getByTestId('router-delete').click();
  await card.getByTestId('router-delete-confirm').click();
  await expect(page.getByTestId('router-card').filter({ hasText: 'lab-offline' })).toHaveCount(0);
});

// REQ: T8.2 (ADR-942) — the leases list an offline client, marked offline, with no DNS name; the
// Discovered list and a network's device list show the marker (the e2e node has no router, so the
// leases are mocked with page.route).
test('t8_2 offline leases show the marker', async () => {
  const lease = (ip: string, offline: boolean, extra: Record<string, unknown>) => ({
    mac: `02:00:00:00:00:${ip.endsWith('53') ? '04' : '02'}`,
    ip,
    expiresUnixSeconds: 0,
    source: 'router',
    router: 'udm',
    offline,
    ...extra,
  });
  const items = [
    lease('192.168.1.31', false, { hostname: 'Living room Roku', dnsName: 'living-room-roku.home.arpa' }),
    lease('192.168.1.53', true, { hostname: 'Old iPad' }),
  ];
  const network = {
    name: 'Home',
    subnet: '192.168.1.0/24',
    addresses: 254,
    devices: 2,
    outsidePool: 0,
    source: 'router',
    router: 'udm',
    usedPercent: 1,
  };
  await page.route('**/api/v1/dhcp/leases', (route) => route.fulfill({ json: { items } }));
  await page.route('**/api/v1/networks', (route) => route.fulfill({ json: { items: [network] } }));
  try {
    await page.setViewportSize({ width: 1280, height: 900 });
    await page.goto('/#/clients?tab=discovered');
    const section = page.getByTestId('discovered');
    await expect(section).toBeVisible({ timeout: 20_000 });
    const offlineRow = section.locator('tr').filter({ hasText: '192.168.1.53' });
    await expect(offlineRow.getByTestId('offline-badge')).toHaveText('offline');
    await expect(offlineRow.getByTestId('dns-name')).toContainText('none');
    const connectedRow = section.locator('tr').filter({ hasText: '192.168.1.31' });
    await expect(connectedRow.getByTestId('offline-badge')).toHaveCount(0);
    await expect(connectedRow.getByTestId('dns-name')).toContainText('living-room-roku.home.arpa');

    await page.goto('/#/networks');
    await page.getByTestId('network-open').filter({ hasText: 'Home' }).click();
    const devices = page.getByTestId('network-devices');
    await expect(devices).toBeVisible({ timeout: 20_000 });
    await expect(devices.locator('tr').filter({ hasText: '192.168.1.53' }).getByTestId('offline-badge')).toHaveText('offline');
    await expect(devices.locator('tr').filter({ hasText: '192.168.1.31' }).getByTestId('offline-badge')).toHaveCount(0);
  } finally {
    await page.unroute('**/api/v1/dhcp/leases');
    await page.unroute('**/api/v1/networks');
  }
});

// REQ: API-007 (T24.18, ADR-940) — importing a Pi-hole export from the admin page: the preview
// lists what would change and writes nothing; applying needs the typed confirmation, writes the plan,
// and is undone here by deleting what it added. The fixture is a small Teleporter (v5) archive.
const PIHOLE_FIXTURE = resolve(import.meta.dirname, 'fixtures/pihole-v5-teleporter.tar.gz');

// The same predicate must be passed to route and unroute: Playwright removes only the route that it matches.
const PREVIEW_ROUTE = (url: URL) => url.pathname === '/api/v1/import/pihole';
const STALE_APPLY_ROUTE = (url: URL) => url.pathname === '/api/v1/import/pihole/plans/stale-plan/apply';

// A fresh load of the Import tab: a hash change alone keeps the page's state (a preview from an earlier test).
async function openImport() {
  await page.goto('/');
  await page.goto('/#/settings?tab=pihole');
  await expect(page.getByTestId('pihole-import')).toBeVisible({ timeout: 20_000 });
}

test('api_007 import from pi-hole with preview', async () => {
  const r = page.request;
  await openImport();
  const panel = page.getByTestId('pihole-import');
  await expect(panel.getByRole('heading', { name: 'Import from Pi-hole' })).toBeVisible();
  await panel.getByTestId('pihole-file').setInputFiles(PIHOLE_FIXTURE);
  await panel.getByTestId('pihole-preview').click();
  await expect(panel.getByTestId('pihole-summary')).toContainText('to add', { timeout: 20_000 });
  // The upstream, the local name and the deny entry are listed as adds; nothing is written yet.
  const items = panel.getByTestId('pihole-item');
  await expect(items.filter({ hasText: 'pihole-1' }).first()).toContainText('add');
  await expect(items.filter({ hasText: 'import-test.lan' }).first()).toContainText('add');
  const before = await r.get('/api/v1/config/entries?kind=upstream');
  expect(JSON.stringify(await before.json())).not.toContain('pihole-1');

  // Applying needs the typed confirmation.
  await expect(panel.getByTestId('pihole-apply')).toBeDisabled();
  await panel.getByTestId('pihole-confirm').fill('IMPORT');
  await panel.getByTestId('pihole-apply').click();
  await expect(panel.getByTestId('pihole-applied')).toContainText('Applied:', { timeout: 20_000 });

  try {
    const after = await r.get('/api/v1/config/entries?kind=upstream');
    expect(JSON.stringify(await after.json())).toContain('pihole-1');
  } finally {
    // Undo what the import added: the default groups' overrides first, so nothing still uses the rest.
    const h = { 'x-csrf-token': await csrfOf(r) };
    await r.delete('/api/v1/groups/default', { headers: h });
    await r.delete('/api/v1/upstream-groups/default', { headers: h });
    await r.delete('/api/v1/lists/pihole-deny-exact', { headers: h });
    await r.delete('/api/v1/upstreams/pihole-1', { headers: h });
    await r.delete('/api/v1/records/import-test.lan', { headers: h });
  }
});

// REQ: API-007 (T24.18) — an operator can't see the import tab at all.
test('api_007 operator cannot see the import page', async () => {
  const op = await operatorPage('operator1', 'operator long password');
  try {
    await op.p.goto('/#/settings?tab=pihole');
    await expect(op.p.getByRole('tab', { name: 'Users' })).toHaveCount(0);
    await expect(op.p.getByRole('tab', { name: 'Pi-hole' })).toHaveCount(0);
    await expect(op.p.getByTestId('pihole-import')).toHaveCount(0);
    // The API says the same: an operator's upload is refused (admins only).
    // The request runs in the operator's page, so it carries the operator's session cookie.
    await expect(op.p.getByRole('tab', { name: 'Account' })).toBeVisible();
    const post = await op.p.evaluate(async () => {
      const st = await (await fetch('/api/v1/auth/status', { credentials: 'same-origin' })).json();
      const res = await fetch('/api/v1/import/pihole', {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'x-csrf-token': st.csrfToken, 'content-type': 'application/octet-stream' },
        body: 'not a file',
      });
      return res.status;
    });
    expect(post).toBe(403);
  } finally {
    await op.close();
  }
});

// REQ: API-005 (T24.10, ADR-961) — the Pi-hole compatible API: off until an admin turns it on in
// Settings → Pi-hole; turning it on makes a token that is shown once; with it, a Pi-hole v6 client
// signs in, reads the summary and turns blocking off and on; v5 answers too; a new token ends the old
// one; turning it off makes the paths 404 again.
test('api_005 pihole compatible api: off by default, a token shown once, v6 and v5, rotation', async () => {
  const r = page.request;
  await page.goto('/');
  await page.goto('/#/settings?tab=pihole');
  const card = page.getByTestId('pihole-api');
  await expect(card).toBeVisible({ timeout: 20_000 });
  const toggle = card.getByTestId('pihole-api-toggle');
  await expect(toggle).not.toBeChecked();
  await expect(card.getByTestId('pihole-api-state')).toContainText('No token yet');
  // Off: Pi-hole's paths are the API's ordinary 404.
  expect((await r.post('/api/auth', { data: { password: 'x' } })).status()).toBe(404);
  // (v5's path answers as any unknown page does, the web UI, so it can't be told from one.)
  expect((await r.get('/admin/api.php?summaryRaw&auth=x')).status()).toBe((await r.get('/admin/nothing.php')).status());
  await expect(card.getByTestId('pihole-api-node')).toContainText('This node');

  // On: the token appears once.
  await toggle.check();
  await expect(card.getByTestId('pihole-api-token')).toBeVisible();
  const token = ((await card.getByTestId('pihole-api-token-text').textContent()) ?? '').trim();
  expect(token.length).toBeGreaterThan(30);
  await expect(toggle).toBeChecked();
  await expect(card.getByTestId('pihole-api-how')).toContainText('location');
  expect(await page.content()).not.toContain('"tokenHash"');

  // A v6 client: sign in with the token, read the summary, switch blocking off and on.
  const bad = await r.post('/api/auth', { data: { password: 'wrong' } });
  expect(bad.status()).toBe(401);
  const login = await r.post('/api/auth', { data: { password: token } });
  expect(login.status()).toBe(200);
  const sid = (await login.json()).session.sid as string;
  const h = { 'x-ftl-sid': sid };
  const sum = await r.get('/api/stats/summary', { headers: h });
  expect(sum.status()).toBe(200);
  expect(typeof (await sum.json()).queries.total).toBe('number');
  expect((await r.get('/api/stats/summary')).status()).toBe(401);
  const off = await r.post('/api/dns/blocking', { headers: h, data: { blocking: false, timer: 120 } });
  expect(off.status()).toBe(200);
  expect(await off.json()).toMatchObject({ blocking: 'disabled' });
  const ours = await (await r.get('/api/v1/blocking')).json();
  expect(ours.items[0].pauses[0].group ?? null).toBeNull();
  // The same pause shows in the UI (the pause pill) ...
  await page.goto('/#/');
  await page.reload();
  await expect(page.getByTestId('blocking-paused')).toContainText(/Blocking paused · [12] min left/, { timeout: 20_000 });
  const on = await r.post('/api/dns/blocking', { headers: h, data: { blocking: true } });
  expect(await on.json()).toMatchObject({ blocking: 'enabled' });
  await page.reload();
  await expect(page.getByTestId('blocking-paused')).toHaveCount(0);
  // ... and in the audit log, by the token's name.
  const paused = JSON.stringify(await (await r.get('/api/v1/audit?action=blocking.')).json());
  expect(paused).toContain('token:pihole-api');
  await page.goto('/#/settings?tab=pihole');
  await expect(card).toBeVisible();
  // v5: a wrong token reads [], the right one reads the totals.
  expect(await (await r.get('/admin/api.php?summaryRaw&auth=wrong')).json()).toEqual([]);
  const v5 = await r.get(`/admin/api.php?summaryRaw&auth=${encodeURIComponent(token)}`);
  expect(typeof (await v5.json()).dns_queries_today).toBe('number');

  // A new token ends the old one, and it is shown once (not after a reload).
  await card.getByTestId('pihole-api-rotate').click();
  await card.getByTestId('pihole-api-rotate').click();
  await expect(card.getByTestId('pihole-api-token-text')).not.toHaveText(token);
  const next = ((await card.getByTestId('pihole-api-token-text').textContent()) ?? '').trim();
  expect((await r.post('/api/auth', { data: { password: token } })).status()).toBe(401);
  expect((await r.get('/api/stats/summary', { headers: h })).status()).toBe(401);
  expect((await r.post('/api/auth', { data: { password: next } })).status()).toBe(200);
  await page.reload();
  await expect(card.getByTestId('pihole-api-token')).toHaveCount(0);
  await expect(card.getByTestId('pihole-api-state')).toContainText('Token made');

  // The longest pause is a setting.
  await card.getByTestId('pihole-api-max').fill('90');
  await card.getByTestId('pihole-api-max-save').click();
  await expect(card.getByTestId('pihole-api-max-save')).toBeDisabled();
  expect((await (await r.get('/api/v1/pihole-api')).json()).maxPauseMinutes).toBe(90);

  // Remove the token: two clicks, then it is off, and the paths are 404 again.
  await card.getByTestId('pihole-api-revoke').click();
  await card.getByTestId('pihole-api-revoke').click();
  await expect(toggle).not.toBeChecked();
  expect((await r.post('/api/auth', { data: { password: next } })).status()).toBe(404);
  await expect(card.getByTestId('pihole-api-state')).toContainText('No token yet');
  // On again (a new token), then off again: 404, and the audit log has the changes.
  await toggle.check();
  await expect(card.getByTestId('pihole-api-token')).toBeVisible();
  await toggle.uncheck();
  await expect(toggle).not.toBeChecked();
  expect((await r.post('/api/auth', { data: { password: next } })).status()).toBe(404);
  const audit = JSON.stringify(await (await r.get('/api/v1/audit?action=pihole_api.')).json());
  expect(audit).toContain('pihole_api.enable');
  expect(audit).toContain('pihole_api.disable');
  expect(audit).toContain('pihole_api.token_rotate');
  expect(audit).toContain('pihole_api.token_revoke');
  expect(audit).not.toContain(next);
});

// REQ: API-007 (ADR-941) — the comparison's result, with the Pi-hole address given; the answers are mocked
// because the e2e server has no Pi-hole to ask.
test('api_007 compare shows the differences', async () => {
  await page.route(PREVIEW_ROUTE, async (route) => {
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        planId: 'mocked-plan',
        expiresUnixSeconds: Math.floor(Date.now() / 1000) + 600,
        configVersion: 0,
        source: 'v5',
        counts: '1 upstreams, 0 forwarded domains, 1 records, 1 lists, 1 groups, 0 devices',
        summary: { add: 2, change: 0, skip: 0, samples: 3 },
        items: [{ kind: 'upstream', name: 'pihole-1', action: 'add', reason: '' }],
        itemsTotal: 1,
        notes: [],
        compare: {
          names: 3,
          agree: 2,
          differences: [
            { name: 'nas.lan', qtype: 'A', pihole: { rcode: 'NOERROR', values: ['192.168.1.10'] }, wrendns: { rcode: 'NXDOMAIN', values: [] } },
          ],
          errors: [],
        },
      }),
    });
  });
  try {
    await openImport();
    const panel = page.getByTestId('pihole-import');
    await panel.getByTestId('pihole-file').setInputFiles(PIHOLE_FIXTURE);
    await panel.getByTestId('pihole-compare-toggle').check();
    await panel.getByTestId('pihole-address').fill('192.168.1.251');
    await panel.getByTestId('pihole-preview').click();
    await expect(panel.getByTestId('pihole-compare-summary')).toContainText('Compared 3 names: 2 agree, 1 differ.');
    await expect(panel.getByTestId('pihole-compare-result')).toContainText('NXDOMAIN');
  } finally {
    await page.unroute(PREVIEW_ROUTE);
  }
});

// REQ: API-007 (T24.18, ADR-940) — a preview the configuration has outrun is refused, and says so.
test('api_007 a stale preview is refused', async () => {
  await page.route(PREVIEW_ROUTE, async (route) => {
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        planId: 'stale-plan',
        expiresUnixSeconds: Math.floor(Date.now() / 1000) + 600,
        configVersion: 1,
        source: 'v5',
        counts: '1 upstreams',
        summary: { add: 1, change: 0, skip: 0, samples: 0 },
        items: [{ kind: 'upstream', name: 'pihole-1', action: 'add', reason: '' }],
        itemsTotal: 1,
        notes: [],
        compare: null,
      }),
    });
  });
  await page.route(STALE_APPLY_ROUTE, async (route) => {
    await route.fulfill({
      status: 409,
      contentType: 'application/problem+json',
      body: JSON.stringify({
        type: 'https://wrendns.com/problems/conflict',
        title: 'Conflict',
        status: 409,
        code: 'conflict',
        detail: 'the configuration changed since the preview: preview the import again',
      }),
    });
  });
  try {
    await openImport();
    const panel = page.getByTestId('pihole-import');
    await panel.getByTestId('pihole-file').setInputFiles(PIHOLE_FIXTURE);
    await panel.getByTestId('pihole-preview').click();
    await expect(panel.getByTestId('pihole-summary')).toContainText('to add');
    await panel.getByTestId('pihole-confirm').fill('IMPORT');
    await panel.getByTestId('pihole-apply').click();
    await expect(panel.getByRole('alert')).toContainText('the configuration changed since the preview');
    // The refusal is the expected answer: the browser logs its 409, and the test removes that entry.
    for (let i = problems.length - 1; i >= 0; i--) if (/status of 409/.test(problems[i])) problems.splice(i, 1);
  } finally {
    await page.unroute(STALE_APPLY_ROUTE);
    await page.unroute(PREVIEW_ROUTE);
  }
});

// REQ: API-007 (T24.18, ADR-939) — a damaged export is refused with the reason, by the real import worker;
// the server keeps answering (the worker is a child process, so a bad file can't reach DNS).
test('api_007 a damaged export is refused with a reason', async () => {
  const panel = page.getByTestId('pihole-import');
  await openImport();
  await panel.getByTestId('pihole-file').setInputFiles({ name: 'damaged.zip', mimeType: 'application/zip', buffer: Buffer.from('PK\x03\x04 not really a zip') });
  await panel.getByTestId('pihole-preview').click();
  await expect(panel.getByRole('alert')).toContainText("this isn't a Pi-hole export the import can read", { timeout: 20_000 });
  await expect(panel.getByTestId('pihole-preview-result')).toHaveCount(0);
  // The refusal is the expected answer: the browser logs its 422, and the test removes that entry.
  for (let i = problems.length - 1; i >= 0; i--) if (/status of 422/.test(problems[i])) problems.splice(i, 1);
  // The server still answers, and DNS still answers a local name (the worker is a child process).
  expect((await page.request.get('/livez')).status()).toBe(200);
  expect(await query('nas.e2e.test')).toBe(0);
});

// REQ: API-007 (T24.18) — Discard forgets the preview: the plan is gone from the server, so applying
// it is a 404, and nothing was written.
test('api_007 discard forgets the preview', async () => {
  const r = page.request;
  await openImport();
  const panel = page.getByTestId('pihole-import');
  await panel.getByTestId('pihole-file').setInputFiles(PIHOLE_FIXTURE);
  // The plan's ID is read from the answer: the route fetches it, reads it, and hands it to the page.
  const planIds: string[] = [];
  await page.route(PREVIEW_ROUTE, async (route) => {
    const resp = await route.fetch();
    planIds.push(JSON.parse(await resp.text()).planId as string);
    await route.fulfill({ response: resp });
  });
  try {
    await panel.getByTestId('pihole-preview').click();
    await expect(panel.getByTestId('pihole-summary')).toContainText('to add', { timeout: 20_000 });
    await expect.poll(() => planIds.length).toBe(1);
  } finally {
    await page.unroute(PREVIEW_ROUTE);
  }
  const planId = planIds[0];
  await panel.getByTestId('pihole-discard').click();
  await expect(panel.getByTestId('pihole-preview-result')).toHaveCount(0);
  const h = { 'x-csrf-token': await csrfOf(r) };
  const gone = await r.post(`/api/v1/import/pihole/plans/${encodeURIComponent(planId)}/apply`, { headers: h });
  expect(gone.status()).toBe(404);
  const after = await r.get('/api/v1/config/entries?kind=upstream');
  expect(JSON.stringify(await after.json())).not.toContain('pihole-1');
});

// REQ: API-007 (ADR-941, T24.18) — the comparison's options reach the request: the Pi-hole, this
// node's resolver, and the extra names. The answer is mocked (the e2e server has no Pi-hole to ask),
// and it shows where an entry points.
test('api_007 comparison options reach the request', async () => {
  let asked = '';
  await page.route(PREVIEW_ROUTE, async (route) => {
    asked = route.request().url();
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        planId: 'options-plan',
        expiresUnixSeconds: Math.floor(Date.now() / 1000) + 600,
        configVersion: 0,
        source: 'v5',
        counts: '1 upstreams',
        summary: { add: 1, change: 0, skip: 0, samples: 2 },
        items: [{ kind: 'upstream', name: 'pihole-1', action: 'add', reason: '', detail: 'udp://9.9.9.9:53' }],
        itemsTotal: 1,
        notes: [],
        compare: { names: 2, agree: 2, differences: [], errors: [] },
      }),
    });
  });
  try {
    await openImport();
    const panel = page.getByTestId('pihole-import');
    await panel.getByTestId('pihole-file').setInputFiles(PIHOLE_FIXTURE);
    await panel.getByTestId('pihole-compare-toggle').check();
    await panel.getByTestId('pihole-address').fill('192.168.1.251');
    await panel.getByTestId('pihole-wrendns-address').fill(`127.0.0.1:${DNS_PORT}`);
    await panel.getByTestId('pihole-samples').fill('example.com, nas.home');
    await panel.getByTestId('pihole-preview').click();
    await expect(panel.getByTestId('pihole-compare-summary')).toContainText('Compared 2 names');
    const q = new URL(asked).searchParams;
    expect(q.get('compare')).toBe('192.168.1.251');
    expect(q.get('wrendns')).toBe(`127.0.0.1:${DNS_PORT}`);
    expect(q.get('samples')).toBe('example.com, nas.home');
    await expect(panel.getByTestId('pihole-detail').first()).toHaveText('udp://9.9.9.9:53');
  } finally {
    await page.unroute(PREVIEW_ROUTE);
  }
});

// REQ: API-007, OPS-014 (T23.9, ADR-903 §8) — Settings → System → Backup: without a passphrase a
// backup leaves the stored secrets out and says how many; with one, the passphrase is confirmed
// (12 characters, typed twice), a 403 `reauth_required` opens the recent-sign-in prompt (the
// request waits for it), and the secrets go into the file encrypted: the planted value is nowhere
// in the downloaded bytes. `secrets_exported` is offered as an alert condition.
test('api_007 passphrase backup from settings', async () => {
  test.setTimeout(90_000);
  await page.setViewportSize({ width: 1280, height: 800 });
  const r = page.request;
  const h = { 'x-csrf-token': await csrfOf(r) };
  const PLANTED = 'planted-backup-ui-value-5f3a19';
  const PASSPHRASE = 'a long passphrase for the backup';
  expect((await r.put('/api/v1/secrets/backup-ui-test', { headers: h, data: { value: PLANTED, kind: 'text' } })).status()).toBe(200);
  try {
    await page.goto('/#/settings?tab=system');
    const card = page.getByTestId('backup-card');
    await expect(card).toBeVisible();
    await expect(card.getByTestId('backup-make')).toHaveText('Download a backup');

    // Without a passphrase: a file, and the omitted-secrets notice.
    const [plain] = await Promise.all([page.waitForEvent('download'), card.getByTestId('backup-make').click()]);
    expect(plain.suggestedFilename()).toMatch(/\.ttbk$/);
    await expect(card.getByTestId('backup-secrets-omitted')).toContainText(/stored secrets? (was|were) left out/);
    await expect(card.getByTestId('backup-secrets-included')).toHaveCount(0);

    // With a passphrase: it must be long enough and typed twice.
    await card.getByTestId('backup-with-secrets').check();
    await expect(card.getByTestId('backup-make')).toBeDisabled();
    await card.getByLabel('Backup passphrase', { exact: true }).fill('short');
    await expect(card.getByTestId('backup-short')).toBeVisible();
    await card.getByLabel('Backup passphrase', { exact: true }).fill(PASSPHRASE);
    await card.getByLabel('Repeat the backup passphrase').fill('another long passphrase');
    await expect(card.getByTestId('backup-mismatch')).toBeVisible();
    await expect(card.getByTestId('backup-make')).toBeDisabled();
    await card.getByLabel('Repeat the backup passphrase').fill(PASSPHRASE);
    await expect(card.getByTestId('backup-mismatch')).toHaveCount(0);
    await expect(card.getByTestId('backup-make')).toBeEnabled();
    await expect(card.getByTestId('backup-make')).toHaveText('Download a backup with secrets');

    // A refusal that isn't the recent-sign-in one (here a 429): nothing typed stays in the fields.
    await page.route('**/api/v1/backup', async (route) => {
      await route.fulfill({
        status: 429,
        contentType: 'application/problem+json',
        headers: { 'retry-after': '2' },
        body: JSON.stringify({
          type: 'https://wrendns.com/problems/rate_limited',
          title: 'Too many requests',
          status: 429,
          code: 'rate_limited',
          detail: 'another backup with a passphrase is running on this node',
        }),
      });
    });
    try {
      await card.getByTestId('backup-make').click();
      await expect(card).toContainText('another backup with a passphrase is running');
      await expect(card.getByLabel('Backup passphrase', { exact: true })).toHaveValue('');
      await expect(card.getByLabel('Repeat the backup passphrase')).toHaveValue('');
      // The refusal is the point of this case: its 429 is expected, nothing else is.
      for (let i = problems.length - 1; i >= 0; i--) if (/status of 429/.test(problems[i])) problems.splice(i, 1);
    } finally {
      await page.unroute('**/api/v1/backup');
    }
    await card.getByLabel('Backup passphrase', { exact: true }).fill(PASSPHRASE);
    await card.getByLabel('Repeat the backup passphrase').fill(PASSPHRASE);

    // The server asks for a recent sign-in once; the prompt keeps the request until the password
    // is given, then the backup is made for real.
    let refused = 0;
    const bodies: string[] = [];
    await page.route('**/api/v1/backup', async (route) => {
      const req = route.request();
      if (req.method() === 'POST') bodies.push(req.postData() ?? '');
      if (req.method() === 'POST' && refused === 0) {
        refused++;
        await route.fulfill({
          status: 403,
          contentType: 'application/problem+json',
          body: JSON.stringify({
            type: 'https://wrendns.com/problems/reauth_required',
            title: 'Recent sign-in needed',
            status: 403,
            code: 'reauth_required',
            detail: 'this needs a sign-in within the last 10 minutes; yours is older',
            hint: 'Sign in again (POST /api/v1/auth/login), then retry.',
          }),
        });
      } else {
        await route.continue();
      }
    });
    try {
      await card.getByTestId('backup-make').click();
      const prompt = card.getByTestId('backup-reauth');
      await expect(prompt).toBeVisible();
      await expect(prompt).toContainText("Confirm it's you");
      await expect(card.getByTestId('backup-make')).toHaveCount(0);
      await expect(prompt.getByTestId('backup-reauth-go')).toBeDisabled();
      await prompt.getByLabel('Your password').fill(ADMIN.pass);
      const [enc] = await Promise.all([page.waitForEvent('download'), prompt.getByTestId('backup-reauth-go').click()]);
      await expect(card.getByTestId('backup-secrets-included')).toContainText('encrypted with your passphrase');
      await expect(card.getByTestId('backup-reauth')).toHaveCount(0);
      // The fields are cleared once the backup is made.
      await expect(card.getByLabel('Backup passphrase', { exact: true })).toHaveValue('');
      // The passphrase went in the request body only, twice (the refused try and the retry).
      expect(bodies).toHaveLength(2);
      expect(bodies.every((b) => b.includes(PASSPHRASE))).toBe(true);
      // The file holds the secret only encrypted: checked on the decompressed tar (the file is
      // zstd, where a plaintext value would hide), with the encrypted entry as the control.
      const path = await enc.path();
      const file = readFileSync(path);
      expect(file.length).toBeGreaterThan(1000);
      const tar = zstdDecompressSync(file);
      expect(tar.includes(Buffer.from('data/secrets.enc'))).toBe(true);
      expect(tar.includes(Buffer.from('manifest.json'))).toBe(true);
      expect(tar.includes(Buffer.from(PLANTED))).toBe(false);
      expect(tar.includes(Buffer.from(PASSPHRASE))).toBe(false);
      expect(file.includes(Buffer.from(PLANTED))).toBe(false);
    } finally {
      await page.unroute('**/api/v1/backup');
    }
    // Making it is audited, without the passphrase.
    const audit = await (await r.get('/api/v1/audit')).text();
    expect(audit).toContain('secretsIncluded');
    expect(audit).not.toContain(PASSPHRASE);

    // The alert condition is offered (selecting it fails if it isn't).
    await page.goto('/#/alerts');
    await page.getByRole('button', { name: 'Advanced', exact: true }).click();
    await page.getByTestId('editor-alert_rule').getByRole('button', { name: 'Add rule' }).click();
    await page.getByLabel('When', { exact: true }).selectOption('secrets_exported');
    await page.reload();
  } finally {
    await r.delete('/api/v1/secrets/backup-ui-test', { headers: h });
  }
});

// REQ: UI-901, OBS-003 (T24.34, ADR-1013) — the picker: search over names and addresses, several
// devices, Select all on the filtered results, the keyboard, and 5,000 items without a stall.
test('ui_901 the query log picks devices by name: search, several, keyboard, 5,000 items', async () => {
  const items = Array.from({ length: 5000 }, (_, i) => ({
    name: `device-${String(i).padStart(4, '0')}`,
    match: [`10.${(i >> 8) & 255}.${i & 255}.7`, `aa:bb:cc:00:${(i >> 8).toString(16).padStart(2, '0')}:${(i & 255).toString(16).padStart(2, '0')}`],
    groups: ['default'],
    source: 'api',
    effectiveGroups: ['default'],
    groupsFrom: 'default',
  }));
  await page.route('**/api/v1/clients', (r) => (r.request().method() === 'GET' ? r.fulfill({ json: { items } }) : r.fallback()));
  try {
    await page.goto('/#/queries');
    const group = page.getByRole('group', { name: 'Client', exact: true });
    const box = group.getByRole('combobox');
    await box.click();
    await expect(box).toHaveAttribute('aria-expanded', 'true');
    await expect(group.getByTestId('picker-count')).toContainText('of 5');
    // Only a window of the 5,000 rows is in the page.
    expect(await group.getByRole('option').count()).toBeLessThan(60);
    // Search by name, and by address.
    const t0 = Date.now();
    await box.fill('device-04');
    await expect(group.getByTestId('picker-count')).toContainText('100 of');
    expect(Date.now() - t0).toBeLessThan(2000);
    await box.fill('10.3.9.7');
    await expect(group.getByRole('option').first()).toContainText('device-0777');
    await box.fill('device-04');
    // Keyboard: arrows move, Enter picks, Backspace takes the last chip off.
    await box.press('ArrowDown');
    await box.press('Enter');
    await box.press('ArrowDown');
    await box.press('Enter');
    await expect(group.getByTestId('picker-chip')).toHaveCount(2);
    await box.fill('');
    await box.press('Backspace');
    await expect(group.getByTestId('picker-chip')).toHaveCount(1);
    // Select all and Deselect all act on the filtered results (100 of them), with "+N" for the rest.
    await box.fill('device-04');
    await group.getByTestId('picker-all').click();
    await expect(group.getByTestId('picker-count')).toContainText('100 selected');
    await expect(group.getByTestId('picker-more')).toContainText('+97');
    await group.getByTestId('picker-none').click();
    await expect(group.getByTestId('picker-count')).not.toContainText('selected');
    // Escape closes without clearing; two devices are searched together, by their addresses.
    await box.fill('device-0003');
    await box.press('Enter');
    await box.fill('device-0005');
    await box.press('Enter');
    await box.press('Escape');
    await expect(box).toHaveAttribute('aria-expanded', 'false');
    // Focus moving out of the picker (Tab past its buttons) closes the open list (it doesn't stay over the next controls).
    await box.click();
    await expect(box).toHaveAttribute('aria-expanded', 'true');
    await page.getByRole('button', { name: 'Search', exact: true }).focus();
    await expect(box).toHaveAttribute('aria-expanded', 'false');
    const sent = page.waitForRequest((r) => r.url().includes('/api/v1/queries') && decodeURIComponent(r.url()).includes('client=10.0.3.7,10.0.5.7'));
    await page.getByRole('button', { name: 'Search', exact: true }).click();
    await sent;
  } finally {
    await page.unroute('**/api/v1/clients');
  }
});

test('ui_901 the rows are exactly the picked devices, and "not" shows every other client', async () => {
  const all = await (await page.context().request.get('/api/v1/queries?limit=1000')).json();
  const ips = [...new Set<string>(all.items.map((x: { client: string }) => x.client))];
  expect(ips.length).toBeGreaterThan(0);
  const picked = ips.slice(0, 2);
  await page.goto('/#/queries');
  const group = page.getByRole('group', { name: 'Client', exact: true });
  const box = group.getByRole('combobox');
  for (const ip of picked) {
    await box.fill(ip);
    await box.press('Enter');
  }
  await expect(group.getByTestId('picker-chip')).toHaveCount(picked.length);
  await box.press('Escape');
  const search = async () => {
    const res = page.waitForResponse((r) => r.url().includes('/api/v1/queries?') && r.request().method() === 'GET');
    await page.getByRole('button', { name: 'Search', exact: true }).click();
    return (await (await res).json()) as { items: { client: string }[] };
  };
  const inSet = await search();
  expect(inSet.items.length).toBeGreaterThan(0);
  expect(inSet.items.every((x) => picked.includes(x.client))).toBe(true);
  await expect(page.locator('table.log tbody tr').first()).toBeVisible();
  // "not" goes with the set: no row is from it.
  await page.getByRole('checkbox', { name: 'not', exact: true }).first().check();
  const rest = await search();
  expect(rest.items.every((x) => !picked.includes(x.client))).toBe(true);
});

test('ui_901 the API takes several clients and the not option works with them', async () => {
  const r = page.context().request;
  const all = await (await r.get('/api/v1/queries?limit=1000')).json();
  const ips = [...new Set<string>(all.items.map((x: { client: string }) => x.client))];
  expect(ips.length).toBeGreaterThan(0);
  const one = ips[0];
  const some = await (await r.get(`/api/v1/queries?limit=1000&client=${encodeURIComponent(`${one},10.99.99.99`)}`)).json();
  expect(some.items.length).toBeGreaterThan(0);
  expect(some.items.every((x: { client: string }) => x.client === one)).toBe(true);
  const rest = await (await r.get(`/api/v1/queries?limit=1000&clientNot=true&client=${encodeURIComponent(`${one},10.99.99.99`)}`)).json();
  expect(rest.items.every((x: { client: string }) => x.client !== one)).toBe(true);
  expect(some.items.length + rest.items.length).toBe(all.items.length);
  const bad = await r.get('/api/v1/queries?client=' + encodeURIComponent(`${one},nope`));
  expect(bad.status()).toBe(400);
  // A router name nobody holds matches nothing (and "not" everything); a name and an address mix;
  // a trailing comma is still one address.
  const none = await (await r.get('/api/v1/queries?limit=1000&client=hostname:nobody-here')).json();
  expect(none.items.length).toBe(0);
  const notNone = await (await r.get('/api/v1/queries?limit=1000&clientNot=true&client=hostname:nobody-here')).json();
  expect(notNone.items.length).toBe(all.items.length);
  const mix = await (await r.get(`/api/v1/queries?limit=1000&client=${encodeURIComponent(`hostname:nobody-here,${one}`)}`)).json();
  expect(mix.items.length).toBe(some.items.length);
  const comma = await (await r.get(`/api/v1/queries?limit=1000&client=${encodeURIComponent(`${one},`)}`)).json();
  expect(comma.items.length).toBe(some.items.length);
});

// REQ: CLU-005 (T24.26) — the Events tab names a lapsed lease and its renewal in words: "Lease
// lapsed" in the bad colour, "Lease renewed" in the ok one (the e2e server cannot lapse a lease,
// so the cluster view is a stub).
test('clu_005 lease lapse and renewal events have labels', async () => {
  await page.setViewportSize({ width: 1280, height: 800 });
  const at = (s: number) => new Date(Date.now() - s * 1000).toISOString();
  const view = {
    enabled: true, clusterId: 'c1', name: 'home', thisNode: 'id-p', newestConfigSeq: 9, healthy: true,
    checks: [{ id: 'peers_up', ok: true, summary: 'All 1 node is up' }],
    events: [
      { at: at(60), kind: 'lease_lost', nodeId: 'id-p', detail: 'publishing paused until a majority renews the lease' },
      { at: at(30), kind: 'lease_renewed', nodeId: 'id-p', detail: 'publishing resumed after 4200 ms' },
    ],
    conflicts: [], authority: 'primary',
    failover: { mode: 'auto', active: true, voters: 3, reachableVoters: 3, leaseHeld: true, leaseSecondsLeft: 11, votedEpoch: 1, votedFor: 'id-p' },
    nodes: [{
      nodeId: 'id-p', site: 'primary', ephemeral: false, witness: false, protocol: 1, role: 'primary', thisNode: true, eligible: true,
      version: '0.8.0', up: true, connected: true, link: 'self', lastSeenSecondsAgo: 1, rttMs: null, configSeq: 9, configLag: 0, ready: true,
      qps: 1, servfailPercent: 0, upstreamP90Ms: 12, uptimeSeconds: 3600, restarts: 0, cacheEntries: 5, cacheHitPercent: 80, querySharePercent: 10,
    }],
  };
  await page.route('**/api/v1/cluster', (route) => route.fulfill({ json: view }));
  await page.route('**/api/v1/cluster/rollout', (route) => route.fulfill({ json: { fromPrimary: true, canaries: [], bakeSecs: 300, stable: '1.9', stage: 'none', nodes: [] } }));
  await page.route('**/api/v1/cluster/versions', (route) => route.fulfill({ json: { items: [], history: 20 } }));
  try {
    await page.goto('/#/cluster?tab=events');
    const items = page.locator('ol.events li');
    await expect(items).toHaveCount(2);
    await expect(items.nth(0).locator('.badge')).toHaveText('Lease lapsed');
    await expect(items.nth(0).locator('.badge')).toHaveClass(/bad/);
    await expect(items.nth(1).locator('.badge')).toHaveText('Lease renewed');
    await expect(items.nth(1).locator('.badge')).toHaveClass(/ok/);
  } finally {
    await page.unroute('**/api/v1/cluster');
    await page.unroute('**/api/v1/cluster/rollout');
    await page.unroute('**/api/v1/cluster/versions');
  }
});

// REQ: UI-901 (T24.34, fork #26) - the single-choice mode of the one picker: the Query log's Group filter
// searches by typing, picks with the keyboard, has help text for assistive tech, and clears.
test('ui_901 a single-choice picker: search, keyboard, help text, clear (Query log group)', async () => {
  await page.route('**/api/v1/groups', (r) =>
    r.request().method() === 'GET'
      ? r.fulfill({ json: { items: ['default', 'lab', 'kids', 'guests'].map((name) => ({ name, members: 0 })) } })
      : r.fallback(),
  );
  // The groups above are made up, and the server answers 400 for a group it does not have; so the
  // log request is answered here and recorded, which also shows what the picker asks for.
  const asked: string[] = [];
  const logRoute = /\/api\/v1\/queries(\?|$)/;
  await page.route(logRoute, (r) => {
    asked.push(decodeURIComponent(r.request().url()));
    return r.fulfill({ json: { items: [], scanned: { blocksRead: 0, blocksTotal: 0, rowsScanned: 0, segments: 0 } } });
  });
  try {
    await page.goto('/#/queries');
    const group = page.getByTestId('group-picker');
    const box = group.getByRole('combobox');
    await expect(box).toHaveAccessibleDescription(/Type to search/);
    await box.click();
    await box.fill('ki');
    await expect(group.getByRole('option')).toHaveCount(1);
    await box.press('Enter');
    await expect(box).toHaveAttribute('aria-expanded', 'false');
    await expect(group).toContainText('kids');
    await expect(group.getByTestId('picker-chip')).toHaveCount(0);
    // Only the chosen group is asked for: never the search text, and one request for the choice.
    await expect.poll(() => asked.at(-1) ?? '').toContain('group=kids');
    expect(asked.filter((u) => u.includes('group=')).every((u) => u.includes('group=kids'))).toBe(true);
    await group.getByTestId('picker-clear').click();
    await expect(group).not.toContainText('kids');
    // Cleared: the parameter is left out, not sent empty.
    await expect.poll(() => asked.at(-1) ?? '').not.toContain('group');
    await box.click();
    await expect(group.getByRole('listbox')).not.toHaveAttribute('aria-multiselectable', 'true');
    await box.press('Escape');
  } finally {
    await page.unroute('**/api/v1/groups');
    await page.unroute(logRoute);
  }
});

// REQ: DNS-014, API-901 (T27.14h) — Settings → System → Allowed networks: an admin adds a network and
// the check (before anything is saved) warns for a public range and not for a private one, a list that
// leaves out the admin's own address is refused, and the Listener access card shows the list read-only
// with a link to the card. Nothing is applied: the e2e node keeps its list.
test('dns_014 allowed networks public range warns', async () => {
  await page.goto('/#/settings?tab=system');
  await page.reload(); // a same-hash goto does not reload
  const card = page.getByTestId('allowed-networks-card');
  await expect(card).toContainText('Allowed networks');
  await expect(card.getByTestId('allowed-networks-list')).toContainText('127.0.0.0/8');
  await card.getByTestId('allowed-networks-edit').click();
  try {
    const form = card.getByTestId('allowed-networks-form');
    // A private range: the check says what it does and does not warn.
    await form.getByTestId('allowed-networks-input').fill('10.20.0.0/24');
    await form.getByTestId('allowed-networks-check').click();
    await expect(card.getByTestId('allowed-networks-preview')).toContainText('What this will do');
    await expect(card.getByTestId('allowed-networks-warning')).toHaveCount(0);
    await card.getByRole('button', { name: 'Change it' }).click();
    // A public range: the warning names it, and says plain DNS carries no device key.
    await form.getByTestId('allowed-networks-input').fill('203.0.113.0/24');
    await form.getByTestId('allowed-networks-check').click();
    const warning = card.getByTestId('allowed-networks-warning');
    await expect(warning).toHaveCount(1);
    await expect(warning).toContainText('203.0.113.0/24');
    await expect(warning).toContainText('no device key');
    await card.getByRole('button', { name: 'Change it' }).click();
    // A list without the browser's own address is refused (409), and nothing is saved.
    for (const n of ['127.0.0.0/8', '::1/128', '169.254.0.0/16']) {
      const rm = form.getByRole('button', { name: `Remove ${n}` });
      if (await rm.count()) await rm.click();
    }
    await form.getByTestId('allowed-networks-input').fill('');
    await form.getByTestId('allowed-networks-check').click();
    await expect(form).toContainText(/leaves out your own address/);
    await expect.poll(() => problems.some((m) => /status of 409/.test(m))).toBe(true);
    for (let i = problems.length - 1; i >= 0; i--) if (/status of 409/.test(problems[i])) problems.splice(i, 1);
  } finally {
    const cancel = card.getByRole('button', { name: 'Cancel' });
    if (await cancel.count()) await cancel.click();
  }
  await expect(card.getByTestId('allowed-networks-list')).toContainText('127.0.0.0/8');
  // The Listener access card shows it read-only and links to this card (the section shows when a
  // listener is listed: stubbed, as the e2e server binds one loopback UDP listener).
  await page.route('**/api/v1/system/info', async (route) => {
    const res = await route.fetch();
    const info = await res.json();
    info.listenerAccess = [
      { listener: 'dot://203.0.113.5:853', requireClientId: true, publicAddress: true, gatedByDefault: false, wildcardBind: false, canCarryKey: true, setting: 'true', defaultOn: false, defaultReason: 'off', publicExposure: false },
    ];
    await route.fulfill({ response: res, json: info });
  });
  try {
    await page.reload();
    const summary = page.getByTestId('allowed-networks-summary');
    await expect(summary).toBeVisible();
    await expect(summary).toContainText('127.0.0.0/8');
    await summary.getByTestId('allowed-networks-link').click();
    await expect(page.locator('#allowed-networks')).toBeInViewport();
  } finally {
    await page.unroute('**/api/v1/system/info');
  }
});

// REQ: DNS-014, API-901 (T27.14h, review) — a list that holds a network twice (a file may) still renders:
// the rows are keyed by position, not by the network.
test('dns_014 allowed networks list with a repeated entry renders', async () => {
  await page.route('**/api/v1/config/entries?kind=access', (route) =>
    route.fulfill({
      json: { items: [{ name: 'default', source: 'override', setByFile: [], definition: { allowed_networks: ['10.0.0.0/8', '10.0.0.0/8'] } }] },
    }),
  );
  try {
    await page.goto('/#/settings?tab=system');
    await page.reload();
    const card = page.getByTestId('allowed-networks-card');
    await expect(card.getByTestId('allowed-networks-row')).toHaveCount(2);
    await card.getByTestId('allowed-networks-edit').click();
    await expect(card.getByTestId('allowed-networks-draft-row')).toHaveCount(2);
    await card.getByRole('button', { name: 'Cancel' }).click();
  } finally {
    await page.unroute('**/api/v1/config/entries?kind=access');
  }
});

// REQ: DNS-014, API-901 (T27.14h review) — removing one of two equal rows removes that row only.
test('dns_014 allowed networks removes one of two equal rows', async () => {
  await page.route('**/api/v1/config/entries?kind=access', (route) =>
    route.fulfill({
      json: { items: [{ name: 'default', source: 'override', setByFile: [], definition: { allowed_networks: ['10.0.0.0/8', '10.0.0.0/8'] } }] },
    }),
  );
  try {
    await page.goto('/#/settings?tab=system');
    await page.reload();
    const card = page.getByTestId('allowed-networks-card');
    await card.getByTestId('allowed-networks-edit').click();
    await expect(card.getByTestId('allowed-networks-draft-row')).toHaveCount(2);
    await card.getByTestId('allowed-networks-draft-row').first().getByRole('button', { name: 'Remove 10.0.0.0/8' }).click();
    await expect(card.getByTestId('allowed-networks-draft-row')).toHaveCount(1);
    await card.getByRole('button', { name: 'Cancel' }).click();
  } finally {
    await page.unroute('**/api/v1/config/entries?kind=access');
  }
});

// REQ: DNS-014, API-901 (T27.14h) — an operator and a viewer see the list and no control, and the API
// refuses their write.
test('dns_014 operator sees allowed networks read only', async () => {
  for (const [user, pass, role] of [
    ['operator1', 'operator long password', 'operator'],
    [VIEWER.user, VIEWER.pass, 'viewer'],
  ] as const) {
    const who = await operatorPage(user, pass, role);
    try {
      await expect(who.p.getByRole('heading', { name: 'Sign in' })).toHaveCount(0); // signed in before the page moves
      await who.p.goto('/#/settings?tab=system');
      await who.p.reload();
      const card = who.p.getByTestId('allowed-networks-card');
      await expect(card.getByTestId('allowed-networks-list')).toContainText('127.0.0.0/8');
      await expect(card.getByTestId('allowed-networks-edit')).toHaveCount(0);
      await expect(card.getByTestId('allowed-networks-revert')).toHaveCount(0);
      const put = await who.p.request.put('/api/v1/access-settings/default', {
        headers: { 'x-csrf-token': await csrfOf(who.p.request) },
        data: { allowed_networks: ['127.0.0.0/8', '198.18.0.0/15'] },
      });
      expect(put.status()).toBe(403);
      for (let i = problems.length - 1; i >= 0; i--) if (/status of 403 \(/.test(problems[i])) problems.splice(i, 1);
    } finally {
      await who.close();
    }
  }
});
