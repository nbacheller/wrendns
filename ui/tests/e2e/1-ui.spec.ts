// REQ: API-003, API-005 — the UI end to end against a real server: first-run setup, the
// dashboard, the query log and "Why?", explain, tokens, users and roles, sign-out/in, and a
// phone-width layout, and the masked-client-IP banner. Any CSP violation or page error fails the suite.
import { expect, test, type Page, type Route } from '@playwright/test';
import { readFileSync } from 'node:fs';
import { zstdDecompressSync } from 'node:zlib';
import { BASE_URL, DNS_PORT, E2E_ROOT, MDNS_PORT, PORTS } from './ports';
import { resolve } from 'node:path';
import { query } from './dns';
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
  const welcome = page.getByRole('heading', { name: 'Welcome to TelltaleDNS' });
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
  await expect(drawer).toContainText('★');
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
    const m = text.match(/telltale_query_duration_seconds_bucket\{path="local",le="[^"]+"\} \d+ # \{trace_id="([0-9a-f]{32})"\}/);
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
  const gh = page.getByRole('link', { name: 'TelltaleDNS on GitHub' });
  await expect(gh).toHaveAttribute('href', 'https://github.com/paimonsoror/telltaledns');
  await expect(gh).toHaveAttribute('target', '_blank');
  await expect(page.getByRole('link', { name: 'Project site and guides' })).toHaveAttribute(
    'href',
    'https://paimonsoror.github.io/telltaledns/',
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
  const [h, gh] = [await icon.boundingBox(), await page.getByRole('link', { name: 'TelltaleDNS on GitHub' }).boundingBox()];
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
  await page.getByLabel('Group').selectOption('lab');
  await groupOnly;
  await expect(listOf('Top domains')).toContainText('this hour');
  await page.getByLabel('Group').selectOption('');
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
    (await fetch('/api/v1/queries?name=probe.telltale.invalid&limit=5')).json(),
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
  await expect(form.getByRole('checkbox', { name: 'Burst of failed lookups' })).toBeChecked();
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
  expect(pkg.suggestedFilename()).toMatch(/^telltale-support-.+\.tar\.gz$/);
  const bytes = readFileSync(await pkg.path());
  expect([bytes[0], bytes[1]]).toEqual([0x1f, 0x8b]);
  await expect(card.getByTestId('support-made')).toContainText('telltale-support-');
  await expect(files.filter({ hasText: 'MANIFEST' })).toHaveCount(0);
  await expect(files.filter({ hasText: 'config/effective.json' })).toBeVisible();
  const [map] = await Promise.all([page.waitForEvent('download'), card.getByTestId('support-map').click()]);
  expect(map.suggestedFilename()).toBe('telltale-support-map.txt');
  await expect(card.getByTestId('support-map')).toBeDisabled();
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
  await expect(groupsView).toHaveCount(0);
  await page.getByRole('button', { name: 'Advanced', exact: true }).click();
  await groupsView.click();
  await expect(page.getByRole('figure', { name: 'Traffic by group' })).toBeVisible();
  await page.getByRole('button', { name: 'Simple', exact: true }).click();
  await page.getByLabel('Group').selectOption('lab');
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
  await expect(page.getByTestId('cluster-standalone')).toContainText('telltale cluster init');
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
  await page.locator('select[name="client-by"]').selectOption('router');
  await page.locator('input[name="client"]').fill('kitchen-tablet');
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
test('api_011 names on my network: wizards, DNS, and the API', async () => {
  await page.setViewportSize({ width: 1280, height: 800 });
  await page.goto('/#/local-dns');
  await expect(page.getByRole('heading', { name: 'Names on my network' })).toBeVisible();

  await page.getByRole('button', { name: 'Set up my home domain', exact: true }).click();
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
    node({ nodeId: `id-${name}`, site: 'k8s', ephemeral: true, pod: `telltale-resolver-${name}`, kubeNode: kube, ...o });
  const view = (pods: ReturnType<typeof node>[]) => ({
    enabled: true, clusterId: 'c1', name: 'home', thisNode: 'id-ctl', newestConfigSeq: 9, healthy: true, checks: [],
    events: [], conflicts: [], authority: 'primary',
    nodes: [
      node({ nodeId: 'id-ctl', site: 'k8s', role: 'primary', thisNode: true, link: 'self', rttMs: null, pod: 'telltaledns-756965cdc7-8j9h9', kubeNode: 'k3s-node-with-a-long-name-1', qps: 40, querySharePercent: 40 }),
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
  await expect(topo.getByTestId('topology-node').first()).toContainText(/tellta.*….*-8j9h9/);
  // The primary is marked as such; the Pi is a replica.
  await expect(topo.getByTestId('topology-node').first().getByTestId('topology-role')).toHaveText('PRIMARY');
  await expect(topo.getByTestId('topology-node').nth(1).getByTestId('topology-role')).toHaveText('replica');
  await expect(topo.getByTestId('topology-site').nth(1).locator('text').first()).toHaveText(/^home-.*….*closet$/);
  await expect(topo.locator('.pod.bad')).toHaveCount(1);
  await expect(topo.locator('path.link.bad')).toHaveCount(1); // the k3s-2 group has a pod down

  // Selecting a pod opens its site in the table and highlights its row.
  await topo.getByRole('button', { name: /telltale-resolver-bbbbb/ }).click();
  const row = page.locator('#node-id-bbbbb');
  await expect(row).toHaveClass(/selected/);
  await expect(row).toContainText('telltale-resolver-bbbbb on k3s-2');
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
    // `telltale cluster set-failover auto` on the primary: no restart anywhere.
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
  const pods = Array.from({ length: 8 }, (_, i) => `telltale-resolver-${i}`);
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
  await expect(top.locator('tr.detail')).toContainText('telltale-resolver-7');
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
    await page.getByRole('group', { name: 'Send to' }).getByRole('checkbox', { name: 'ui-hook', exact: true }).check();
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
    await page.getByRole('button', { name: 'Simple', exact: true }).click().catch(() => {});
    hook.close();
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
    const row = page.getByTestId('editor-upstream').getByTestId('entry-row').filter({ hasText: 'ui-hdr-up' });
    await row.getByRole('button', { name: 'Edit' }).click();
    await page.getByRole('textbox', { name: 'Address', exact: true }).fill('https://other.e2e.test/dns-query');
    await page.getByRole('button', { name: 'Check', exact: true }).click();
    const alert = page.getByRole('alert').filter({ hasText: "isn't kept" });
    await expect(alert).toContainText('headers.Authorization');
    await expect(alert).toContainText('telltale ctl');
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
    [422, 'path_not_allowed', '`token_file`: under /proc, which TelltaleDNS never reads', /can't be used/],
    [409, 'set_by_file', '`url` is set by the configuration file', /The configuration file sets/],
    [422, 'credential_reentry_required', '`headers.Authorization` is `<redacted>`, and there is no stored value to keep', /has no value to keep\. This form can't enter it: change it with telltale ctl/],
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
  await field.getByLabel('Token (ntfy, Gotify)', { exact: true }).fill('write-only-token-7731');
  await noAnswerCarries('write-only-token-7731', async () => {
    await field.getByRole('button', { name: 'Save secret' }).click();
    await expect(field).toHaveAttribute('data-mode', 'set');
  });
  await expect(field.getByTestId('secret-status')).toContainText('alert.ui-stored.token');
  // Never pre-filled, and never in the page after the save.
  await expect(field.getByLabel('Token (ntfy, Gotify)', { exact: true })).toHaveCount(0);
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
  await field.getByLabel('Token (ntfy, Gotify)', { exact: true }).fill('replaced-token-9914');
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
  await field.getByLabel('Token (ntfy, Gotify)', { exact: true }).fill('typed-unsaved-4410');
  await expect(page.getByRole('button', { name: 'Check' })).toBeDisabled();
  await expect(page.getByTestId('secret-unsaved')).toContainText('Save or discard the secret');
  await field.getByRole('button', { name: 'Discard' }).click();
  await expect(page.getByRole('button', { name: 'Check' })).toBeEnabled();
  await expect(page.getByTestId('secret-unsaved')).toHaveCount(0);
  await field.getByLabel('Token (ntfy, Gotify)', { exact: true }).fill('typed-saved-4411');
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
    await field.getByLabel('Token (ntfy, Gotify)', { exact: true }).fill('stored-token-5521');
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

// REQ: API-015 (ADR-903 §2) — a write carries the secrets head the page read (If-Match); a head that
// moved is refused, and the page says so and shows the list again.
test('api_015 a secret write sends the head it read, and a moved head is refused', async () => {
  let ifMatch: string | undefined;
  await page.route('**/api/v1/secrets/ui-moved', (route) => {
    ifMatch = route.request().headers()['if-match'];
    return route.fulfill({
      status: 412,
      contentType: 'application/problem+json',
      json: { type: 'https://telltaledns.dev/problems/precondition_failed', title: 'Precondition Failed', status: 412, code: 'precondition_failed', detail: 'the secrets head moved' },
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
        type: 'https://telltaledns.dev/problems/insecure_transport',
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
  await page.getByRole('group', { name: 'Schedules' }).getByLabel('ui-bedtime').check();
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
  const pi = page.getByRole('checkbox', { name: 'pi (bbbb2222)' });
  await pi.check();
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
  await canvas.focus();
  await page.keyboard.press('ArrowRight');
  await expect(page.getByTestId('heatmap-tip')).toContainText('101 queries');
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
  for (const id of ['map', 'flow', 'slo', 'latency', 'heat', 'kpi']) {
    await expect(page.getByTestId(`wall-panel-${id}`)).toBeVisible();
    await expect(page.getByTestId(`wall-${id}`)).toBeAttached();
    await page.keyboard.press('ArrowRight');
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
  await form.getByLabel('Group').selectOption('ipv6only');
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
  await form.getByTestId('drill-group').selectOption({ index: 1 });
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
    'It was an eligible node, so it holds a copy of the cluster key. If it is lost or cannot be trusted, rotate the cluster CA (telltale cluster rotate-ca).';
  const problem = (status: number, code: string, detail: string) => ({
    type: `https://telltaledns.dev/problems/${code}`, title: code, status, code, detail, hint: 'Stop it first, or tick the box.',
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
            definition: { name: 'filed-udm', type: 'unifi', url: 'https://192.168.1.1', api_key_file: '/etc/telltale/unifi-key' },
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
  expect(html).toContain('<title>TelltaleDNS');
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
            { name: 'nas.lan', qtype: 'A', pihole: { rcode: 'NOERROR', values: ['192.168.1.10'] }, telltale: { rcode: 'NXDOMAIN', values: [] } },
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
        type: 'https://telltaledns.dev/problems/conflict',
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
    await panel.getByTestId('pihole-telltale-address').fill(`127.0.0.1:${DNS_PORT}`);
    await panel.getByTestId('pihole-samples').fill('example.com, nas.home');
    await panel.getByTestId('pihole-preview').click();
    await expect(panel.getByTestId('pihole-compare-summary')).toContainText('Compared 2 names');
    const q = new URL(asked).searchParams;
    expect(q.get('compare')).toBe('192.168.1.251');
    expect(q.get('telltale')).toBe(`127.0.0.1:${DNS_PORT}`);
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
          type: 'https://telltaledns.dev/problems/rate_limited',
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
            type: 'https://telltaledns.dev/problems/reauth_required',
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
