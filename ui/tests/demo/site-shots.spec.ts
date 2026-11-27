// SPDX-License-Identifier: AGPL-3.0-or-later
// REQ: DOC-002 — the rest of the site's pictures (site/assets/shots/<page>-light.jpg and -dark.jpg,
// 1280x860, JPEG quality 80), taken on the made-up network of demo.toml after run.sh has sent it
// synthetic traffic: the pages the older pictures took from the e2e server (its test leftovers)
// and the newer pages (Locations, Listeners, allowed networks, the lookup trace, cache flush).
// Not part of the e2e suite. Everything shown is invented: devices, names, locations, a cluster.
import { test, type Page } from '@playwright/test';
import { resolve } from 'node:path';
import { capture } from './capture';

const repo = resolve(import.meta.dirname, '../../..');

const siteShot = (page: Page, name: string, theme: 'light' | 'dark') =>
  page.screenshot({ path: `${repo}/site/assets/shots/${name}-${theme}.jpg`, type: 'jpeg', quality: 80 });

/** Starts the picture at the top of a card: it frames the card, not the head of the page. */
async function toCard(page: Page, selector: string) {
  await page.locator(selector).first().evaluate((el) => el.scrollIntoView({ block: 'start' }));
  await page.evaluate(() => window.scrollBy(0, -80));
  await page.mouse.move(0, 0);
  await page.waitForTimeout(400);
}

/** Made-up locations (one private), written through the API like an operator would. */
async function seedLocations(page: Page) {
  const login = await page.request.post('/api/v1/auth/login', {
    data: { username: 'admin', password: 'correct horse battery' },
  });
  const csrf = (await login.json()).csrfToken as string;
  const put = (slug: string, body: object) =>
    page.request.put(`/api/v1/locations/${slug}`, {
      data: body,
      headers: { 'x-csrf-token': csrf, 'idempotency-key': `shots-${slug}` },
    });
  await put('home', { label: 'Home', domain: 'home.arpa', visibility: 'shared', networks: ['127.0.1.0/24', '127.0.2.0/24'], nodes: [], flatNames: true });
  await put('office', { label: 'Office', domain: 'office.home.arpa', visibility: 'private', networks: ['127.0.4.0/24'], nodes: [], flatNames: false });
  await put('iot', { label: 'Smart home', domain: 'iot.home.arpa', visibility: 'shared', networks: ['127.0.3.0/24'], nodes: [], flatNames: true });
}

for (const theme of ['light', 'dark'] as const) {
  test(`lists ${theme}`, async ({ browser }) => {
    const { page, context } = await capture(browser, theme, 1280, 860, 1);
    // The locations are made now (the first test), so the Locations page has counted its devices by its turn.
    if (theme === 'light') await seedLocations(page);
    await page.goto('/#/lists');
    await page.getByRole('heading', { name: 'Lists' }).first().waitFor();
    await page.waitForTimeout(1500);
    await page.mouse.move(0, 0);
    await siteShot(page, 'lists', theme);
    await context.close();
  });

  test(`api tokens ${theme}`, async ({ browser }) => {
    const { page, context } = await capture(browser, theme, 1280, 860, 1);
    await page.goto('/#/settings?tab=tokens');
    await page.waitForTimeout(1500);
    // One made-up token. Its secret shows once, so the page is loaded again after it is made.
    if ((await page.getByText('grafana', { exact: true }).count()) === 0) {
      await page.getByPlaceholder('name, e.g. grafana').fill('grafana');
      await page.getByRole('button', { name: 'Create token' }).click();
      await page.waitForTimeout(800);
    }
    await page.reload();
    await page.getByText('grafana', { exact: true }).first().waitFor();
    await page.waitForTimeout(600);
    await page.mouse.move(0, 0);
    await siteShot(page, 'settings', theme);
    await context.close();
  });

  test(`cache ${theme}`, async ({ browser }) => {
    const { page, context } = await capture(browser, theme, 1280, 860, 1);
    await page.goto('/#/cache');
    await page.getByRole('heading', { name: 'Cache' }).first().waitFor();
    await page.waitForTimeout(1500);
    // The chart legend under the cards adds up the nodes' percentages ("6111.6%"), which says nothing:
    // the picture leaves that row out until the page is fixed.
    await page.locator('.u-legend').evaluateAll((els) => els.forEach((el) => (el as HTMLElement).style.setProperty('visibility', 'hidden')));
    await page.mouse.move(0, 0);
    await siteShot(page, 'cache', theme);
    // The look-up and flush controls.
    await toCard(page, 'text=Look up and flush');
    await siteShot(page, 'cache-flush', theme);
    await context.close();
  });

  // The cluster as the site shows it: a controller, three resolver pods on two Kubernetes nodes and
  // a Pi, and the caption says it is an example. (The README's picture is the demo's own three
  // nodes: cluster-day and cluster-night.)
  test(`cluster example ${theme}`, async ({ browser }) => {
    const { page, context } = await capture(browser, theme, 1280, 860, 1);
    await page.route('**/api/v1/cluster', (route) => route.fulfill({ json: exampleCluster() }));
    await page.route('**/api/v1/cluster/rollout', (route) =>
      route.fulfill({ json: { fromPrimary: true, canaries: ['ephemeral'], bakeSecs: 300, stable: '1.42', stage: 'none', nodes: [] } }),
    );
    await page.route('**/api/v1/cluster/versions', (route) => route.fulfill({ json: { items: [], history: 20 } }));
    await page.goto('/#/cluster');
    await page.getByRole('heading', { name: 'Cluster' }).first().waitFor();
    await page.waitForTimeout(1200);
    await page.mouse.move(0, 0);
    await siteShot(page, 'cluster', theme);
    await context.close();
  });

  // REQ: DSC-914 — the Locations page.
  test(`locations ${theme}`, async ({ browser }) => {
    const { page, context } = await capture(browser, theme, 1280, 860, 1);
    await page.goto('/#/locations');
    await page.getByRole('heading', { name: 'Locations' }).first().waitFor();
    await page.waitForTimeout(1800);
    await page.mouse.move(0, 0);
    await siteShot(page, 'locations', theme);
    await context.close();
  });

  // REQ: API-902, DNS-001 — the Listeners card with a change in the draft, not yet reviewed.
  test(`listeners ${theme}`, async ({ browser }) => {
    const { page, context } = await capture(browser, theme, 1280, 860, 1);
    // The demo's listener comes from its file, which locks the card, and a change would move a
    // port the cluster uses. So the card shows an example node: two listeners on 192.168.1.2, the
    // guarded settings say the file leaves them alone, and the review of the change is an example.
    const base = { gatedByDefault: false, wildcardBind: false, canCarryKey: false, setting: 'unset', publicAddress: false, requireClientId: false, defaultOn: false, defaultReason: 'off, because the address is not public', publicExposure: false, proxyProtocol: false };
    await page.route('**/api/v1/system/info', async (route) => {
      const res = await route.fetch();
      const info = await res.json();
      delete info.clientIpsMasked;
      info.listenerAccess = [
        { ...base, listener: 'udp://192.168.1.2:53' },
        { ...base, listener: 'tcp://192.168.1.2:53' },
      ];
      await route.fulfill({ response: res, json: info });
    });
    const probe = (target: string, proto: string) => ({ target, proto, listener: true, ok: true, latencyMs: 1.4, consecutiveFailures: 0, checkedUnixSeconds: Math.floor(Date.now() / 1000) });
    await page.route('**/api/v1/system/probes', (route) =>
      route.fulfill({ json: { items: [probe('udp://192.168.1.2:53', 'udp'), probe('tcp://192.168.1.2:53', 'tcp')] } }),
    );
    await page.route('**/api/v1/guarded', async (route) => {
      const res = await route.fetch();
      const j = await res.json();
      const st = j.nodes[0].settings.find((x: { id: string }) => x.id === 'listen');
      if (st) st.setByFile = false;
      await route.fulfill({ response: res, json: j });
    });
    await page.route('**/api/v1/guarded/listen/preview', async (route) => {
      const sent = route.request().postDataJSON() as { value?: { listeners?: Array<{ proto: string; addr: string }> } };
      const listeners = (sent.value?.listeners ?? []).map((l) => ({
        change: l.proto === 'dot' ? 'added' : 'kept',
        listener: `${l.proto}://${l.addr}`,
      }));
      await route.fulfill({
        json: {
          previewId: 'example', setting: 'listen', node: 'home-dns', nodes: ['home-dns'], mode: 'window', phrase: 'home-dns listen',
          effect: 'Adds a listener.', weakening: false, needsRecentSignIn: false, restartRequired: false, setByFile: false,
          windowSecs: 30, checks: [], listeners, warnings: [],
        },
      });
    });
    await page.goto('/#/settings?tab=system');
    await page.reload();
    const box = page.getByTestId('listeners-card');
    await box.waitFor();
    await box.getByTestId('listeners-add').click();
    const last = box.getByTestId('listeners-row').last();
    await last.getByTestId('listeners-proto').selectOption('dot');
    await last.getByTestId('listeners-addr').fill('192.168.1.2:853');
    await last.getByLabel('Certificate path').fill('/etc/wrendns/tls/home.pem');
    await last.getByLabel('Key path').fill('/etc/wrendns/tls/home.key');
    await box.getByTestId('guarded-start-listen').click();
    await box.getByTestId('guarded-phrase-input').waitFor();
    await page.waitForTimeout(500);
    await toCard(page, '[data-testid="listeners-card"]');
    await siteShot(page, 'listeners', theme);
    await context.close();
  });

  // REQ: DNS-014, API-901 — the allowed networks, with a change checked and not yet applied.
  test(`allowed networks ${theme}`, async ({ browser }) => {
    const { page, context } = await capture(browser, theme, 1280, 860, 1);
    await page.goto('/#/settings?tab=system');
    await page.getByTestId('allowed-networks-card').waitFor();
    await page.getByTestId('allowed-networks-edit').click();
    await page.getByTestId('allowed-networks-input').fill('192.168.20.0/24');
    await page.getByTestId('allowed-networks-add').click();
    await page.getByTestId('allowed-networks-check').click();
    await page.getByTestId('allowed-networks-preview').waitFor();
    await toCard(page, '[data-testid="allowed-networks-card"]');
    await siteShot(page, 'allowed-networks', theme);
    await context.close();
  });

  // REQ: DNS-904 — "Why?" with the lookup trace. The demo's upstreams are stubs that do not resolve
  // by themselves, so the trace request is answered with an example walk of the built-in resolver.
  test(`why trace ${theme}`, async ({ browser }) => {
    const { page, context } = await capture(browser, theme, 1280, 860, 1);
    await page.route('**/api/v1/recursor/trace*', (route) => {
      const q = (server: string, qname: string, zone: string, outcome: string, detail: string, micros: number) => ({
        kind: 'query', zone, server, qname, qtype: 'A', outcome, detail, transport: 'udp', micros,
      });
      return route.fulfill({
        json: {
          name: 'www.example.com', qtype: 'A', upstream: 'recursive://', rcode: 'NOERROR', answers: 2, totalMicros: 61_400,
          steps: [
            { kind: 'start', zone: '.', qname: 'www.example.com.', qtype: 'A', outcome: 'root', detail: '13 servers', transport: '', micros: 0 },
            q('198.41.0.4', 'com.', '.', 'referral', 'com.', 14_200),
            q('192.5.6.30', 'example.com.', 'com.', 'referral', 'example.com.', 18_900),
            q('199.43.135.53', 'www.example.com.', 'example.com.', 'answer', '', 28_300),
          ],
        },
      });
    });
    await page.goto('/#/explain?name=www.example.com&client=127.0.3.20');
    await page.getByTestId('trace-run').click();
    await page.getByTestId('trace-summary').waitFor();
    await toCard(page, '[data-testid="recursor-trace"]');
    await siteShot(page, 'why-trace', theme);
    await context.close();
  });
}

/** An example cluster for the site's picture: not a real deployment. */
function exampleCluster() {
  const node = (o: Record<string, unknown>) => ({
    ephemeral: false, witness: false, protocol: 4, role: 'replica', thisNode: false, eligible: true,
    version: '1.0.0', up: true, connected: true, link: 'inbound', lastSeenSecondsAgo: 2, rttMs: 1,
    configSeq: 41, configLag: 0, ready: true, qps: 12, servfailPercent: 0.1, upstreamP90Ms: 18,
    uptimeSeconds: 86_400, restarts: 0, cacheEntries: 3_200, cacheHitPercent: 71, querySharePercent: 20,
    configSource: 'gitops', ...o,
  });
  const pod = (name: string, kube: string, o: Record<string, unknown> = {}) =>
    node({ nodeId: `id-${name}`, site: 'k8s', ephemeral: true, pod: `wrendns-resolver-${name}`, kubeNode: kube,
      eligible: false, configSource: undefined, uptimeSeconds: 7_200, ...o });
  const at = (minAgo: number) => new Date(Date.now() - minAgo * 60_000).toISOString();
  return {
    enabled: true, clusterId: 'example', name: 'home', thisNode: '3f9a1c07d2e84b16', newestConfigSeq: 41, healthy: true,
    authority: 'gitops', conflicts: [],
    checks: [
      { id: 'peers_up', ok: true, summary: 'All 4 peers are up' },
      { id: 'in_sync', ok: true, summary: 'Every node serves configuration version 41' },
      { id: 'serving', ok: true, summary: 'Every node is serving DNS' },
      { id: 'load_balance', ok: true, summary: "Queries are spread evenly over each site's pods" },
    ],
    nodes: [
      node({ nodeId: '3f9a1c07d2e84b16', site: 'k8s', role: 'primary', thisNode: true, link: 'self', rttMs: null,
        pod: 'wrendns-0', kubeNode: 'node-a', qps: 14, querySharePercent: 22 }),
      pod('6c9f-2xk4p', 'node-a', { qps: 13, querySharePercent: 21 }),
      pod('6c9f-8hq7d', 'node-b', { qps: 12, querySharePercent: 19 }),
      pod('6c9f-k2m9w', 'node-b', { qps: 12, querySharePercent: 19, ready: false, configLag: 1 }),
      node({ nodeId: 'b81e5d2a90c4f377', site: 'home-pi', rttMs: 4, qps: 12, querySharePercent: 19, configSource: 'file',
        cacheHitPercent: 76 }),
    ],
    events: [
      { at: at(2), kind: 'joined', nodeId: 'id-6c9f-k2m9w', detail: 'a new resolver pod' },
      { at: at(3), kind: 'left', nodeId: 'id-6c9f-r5t1z', detail: 'shut down (scaled in, replaced, or deleted)' },
      { at: at(9), kind: 'published', nodeId: '3f9a1c07d2e84b16', detail: 'version 41' },
      { at: at(9), kind: 'applied', nodeId: 'b81e5d2a90c4f377', detail: 'version 41: 1 blob(s) fetched, 38 ms' },
    ],
  };
}
