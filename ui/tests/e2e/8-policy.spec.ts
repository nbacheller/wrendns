// REQ: FLT-006, API-010, AGT-001 (T24.30, ADR-996) — a device's effective policy against a real
// server: the Clients panel names the group and the key that matched (a MAC, a network), lists what
// applies with links to where it is set, agrees with Explain, and is linked from Explain and Flow.
// These tests sign in as the admin `1-ui.spec.ts` created, so run the whole suite, not this file
// alone. The file is named `8-` so what it creates (a device, a quick rule) is gone before it ends
// and no earlier test sees it.
import { expect, test, type BrowserContext, type Page } from '@playwright/test';

test.describe.configure({ mode: 'serial' });

const ADMIN = { user: 'admin', pass: 'correct horse battery' };
const MAC = 'aa:bb:cc:dd:ee:77';
const DEVICE = 'Policy phone';

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

test('flt_006 the Policy panel names the group and the key that matched, for a MAC and for a network', async () => {
  const r = page.request;
  // A device matched by its MAC, in a group with a rewrite, with a quick rule of its own.
  const put = await r.put(`/api/v1/clients/${encodeURIComponent(DEVICE)}`, { headers: h(), data: { match: [MAC], groups: ['ipv6only'] } });
  expect(put.status()).toBe(200);
  const rule = await r.put('/api/v1/rules/e2e-policy', {
    headers: h(),
    data: { action: 'block', domain: 'game.e2e.test', devices: [DEVICE], forMinutes: 60, note: 'homework' },
  });
  expect(rule.status()).toBe(200);

  // From the Devices tab: the Policy button opens the panel.
  await page.goto('/#/clients?tab=devices');
  await page.getByRole('row', { name: new RegExp(DEVICE) }).getByTestId('open-policy').click();
  const panel = page.getByTestId('policy-panel');
  await expect(panel).toBeVisible();
  await expect(panel.getByTestId('policy-group')).toContainText('ipv6only');
  await expect(panel.getByTestId('policy-group-from')).toContainText("device's own groups");
  await expect(panel.getByTestId('policy-matched-key')).toHaveText(MAC);
  await expect(panel.getByTestId('policy-key')).toContainText('MAC');
  // The ladder marks the rung that decided, in words.
  await expect(panel.getByTestId('policy-ladder').locator('li.matched')).toContainText('MAC from the neighbor table');
  await expect(panel.getByTestId('policy-ladder').locator('li.matched')).toContainText('decided');
  // The group's rewrite, with a link to the group it comes from.
  const rewrites = panel.getByTestId('policy-section-rewrites');
  await expect(rewrites).toContainText('tv.e2e.test');
  await expect(rewrites).toContainText('192.168.1.30');
  await expect(rewrites.getByTestId('policy-item').first()).toContainText('group ipv6only');
  // The device's quick rule: in effect, with its end time, the note and a link to Quick rules.
  const rules = panel.getByTestId('policy-section-rules');
  const own = rules.getByTestId('policy-item').filter({ hasText: 'game.e2e.test' });
  await expect(own).toContainText('block game.e2e.test');
  await expect(own).toContainText('in effect now');
  await expect(own).toContainText('until');
  await expect(own).toContainText('homework');
  await expect(own).toContainText('this device');
  await expect(own.getByTestId('policy-link')).toHaveAttribute('href', /#\/rules\?rule=e2e-policy/);
  // A device never seen at an address is read at a stand-in: the panel says so.
  await expect(panel.getByTestId('policy-note').first()).toContainText('no single address');
  // The upstream group.
  await expect(panel.getByTestId('policy-section-upstream')).toContainText('default');

  // The API says the same as the panel and as Explain (a query from a device with this MAC).
  const api = await (await r.get(`/api/v1/clients/${encodeURIComponent(DEVICE)}/policy`)).json();
  expect(api).toMatchObject({ group: 'ipv6only', identifiedBy: 'neighbor_mac', matchedKey: MAC, groupFrom: 'device' });
  const ex = await (await r.get(`/api/v1/explain?name=tv.e2e.test&client=10.99.0.5&mac=${MAC}`)).json();
  expect(ex.client).toMatchObject({ group: api.group, identifiedBy: api.identifiedBy, matchedKey: api.matchedKey, groupFrom: api.groupFrom, device: DEVICE });
  expect(ex.client.groups).toEqual(api.groups);

  // A device with no configuration of its own is matched by its network: the group's network is the key.
  await page.goto('/#/clients?device=127.0.0.1&view=policy');
  const net = page.getByTestId('policy-panel');
  await expect(net.getByTestId('policy-group')).toContainText('lab');
  await expect(net.getByTestId('policy-group-from')).toContainText('its network');
  await expect(net.getByTestId('policy-group-from')).toContainText('127.0.0.0/8');
  // The lists it meets link to the Lists page.
  const link = net.getByTestId('policy-section-lists').getByTestId('policy-link').filter({ hasText: 'e2e-block' });
  await expect(link).toHaveAttribute('href', /#\/lists\?list=e2e-block/);
  await link.click();
  await expect(page).toHaveURL(/#\/lists\?list=e2e-block/);
  await expect(page.getByRole('heading', { level: 1, name: /^Lists/ })).toBeVisible();
  const netApi = await (await r.get('/api/v1/clients/127.0.0.1/policy')).json();
  expect(netApi).toMatchObject({ group: 'lab', groupFrom: 'network', groupKey: '127.0.0.0/8' });
  const netEx = await (await r.get('/api/v1/explain?name=ads.e2e.test&client=127.0.0.1')).json();
  expect(netEx.client).toMatchObject({ group: 'lab', groupFrom: 'network', groupKey: '127.0.0.0/8', identifiedBy: netApi.identifiedBy });
  expect(netEx.client.groups).toEqual(netApi.groups);
});

test('flt_006 Explain and Flow name the group and the key and link to the Policy panel', async () => {
  // Explain: the policy step under the client.
  await page.goto('/#/explain?name=ads.e2e.test&client=127.0.0.1');
  const line = page.locator('.explain').getByTestId('policy-line');
  await expect(line).toBeVisible();
  await expect(line.getByTestId('policy-line-group')).toHaveText('lab');
  await expect(line.getByTestId('policy-line-from')).toContainText('127.0.0.0/8');
  await expect(line.locator('[data-help="device-policy"]')).toBeVisible();
  await line.getByTestId('policy-line-link').click();
  // The link carries the explained address, so the panel reads what Explain read.
  await expect(page).toHaveURL(/#\/clients\?device=127\.0\.0\.1&view=policy/);
  await expect(page.getByTestId('policy-panel').getByTestId('policy-group')).toContainText('lab');

  // Flow: with a device chosen, the same line above the diagram.
  await page.goto('/#/flow?client=127.0.0.1&window=1h');
  const flow = page.getByTestId('policy-line');
  await expect(flow).toBeVisible();
  await expect(flow.getByTestId('policy-line-group')).toHaveText('lab');
  await expect(flow.getByTestId('policy-line-from')).toContainText('its network');
  await flow.getByTestId('policy-line-link').click();
  await expect(page).toHaveURL(/#\/clients\?device=127\.0\.0\.1&view=policy/);
  await expect(page.getByTestId('policy-panel')).toBeVisible();

  // Clean up what this file made, so nothing after it sees them.
  const r = page.request;
  expect((await r.delete('/api/v1/rules/e2e-policy', { headers: h() })).status()).toBe(200);
  expect((await r.delete(`/api/v1/clients/${encodeURIComponent(DEVICE)}`, { headers: h() })).status()).toBe(200);
});
