// REQ: FLT-901, FLT-902, API-010, AGT-001 (T24.29, ADR-994, ADR-995) — content categories and filter profiles
// against a real server: the Categories view (groups with "n of m", the group checkbox and its indeterminate
// state, search then Select all, the info popover, heavy confirmation, sources and licences, not available),
// the profile list and editor (Source picker with a private-address warning, Add device, Ad Block, Safe Search per
// engine, Filtering levels, round trip through the API), the lists the categories own (owned chip, refresh,
// shadow), the Settings Filtering controls and the `category-budget` help topic, and the device policy panel.
// The category lists come from a fake host on `PORTS.catalog` (the server is built with the `e2e` feature),
// so nothing here reaches the internet. These tests sign in as the admin `1-ui.spec.ts` created; the file is named
// `9-` so what it makes (a profile, two devices) is gone before it ends.
import { expect, test, type BrowserContext, type Locator, type Page } from '@playwright/test';
import { createServer, type Server } from 'node:http';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { E2E_ROOT, PORTS } from './ports';
import { queryDetail } from './dns';
import { pick } from './picker';

test.describe.configure({ mode: 'serial' });

const ADMIN = { user: 'admin', pass: 'correct horse battery' };
const PROFILE = 'kids';
const DEVICE = "Maya's iPad";
const PRIVATE_MAC = 'da:a1:19:00:00:01';
const CONFIGURED = 'Cat Console';

let ctx: BrowserContext;
let page: Page;
let csrf = '';
let source: Server;
const requested: string[] = [];
const problems: string[] = [];

test.beforeAll(async ({ browser }) => {
  // The fake host the category lists come from: every path answers one small domains list.
  source = createServer((req, res) => {
    requested.push(req.url ?? '');
    res.writeHead(200, { 'content-type': 'text/plain' });
    res.end('# Title: a fake list for the categories test\n# Number of entries: 2\nx.blocked-by-category.e2e.test\nother.blocked-by-category.e2e.test\n');
  });
  await new Promise<void>((ok) => source.listen(PORTS.catalog, '127.0.0.1', ok));
  ctx = await browser.newContext();
  page = await ctx.newPage();
  page.on('pageerror', (e) => problems.push(`page error: ${e.message}`));
  page.on('console', (m) => {
    if (m.type() === 'error' && !/status of (40[0134]|409|422|429) \(/.test(m.text())) problems.push(`console: ${m.text()} ${m.location().url}`);
  });
  await page.goto('/');
  // On its own the first sign-in may have to create the admin (the whole suite has one already).
  const welcome = page.getByRole('heading', { name: 'Welcome to WrenDNS' });
  const signInHeading = page.getByRole('heading', { name: 'Sign in' });
  await expect(welcome.or(signInHeading)).toBeVisible();
  if (await welcome.isVisible()) {
    const token = readFileSync(resolve(E2E_ROOT, 'data/setup-token'), 'utf8').trim();
    await page.getByLabel('Setup token').fill(token);
    await page.getByLabel('Admin username').fill(ADMIN.user);
    await page.getByLabel('Password (at least 10 characters)').fill(ADMIN.pass);
    await page.getByLabel('Repeat password').fill(ADMIN.pass);
    await page.getByRole('button', { name: 'Create admin and sign in' }).click();
  } else {
    await page.getByLabel('Username', { exact: true }).fill(ADMIN.user);
    await page.getByLabel('Password', { exact: true }).fill(ADMIN.pass);
    await page.getByRole('button', { name: 'Sign in' }).click();
  }
  await expect(page.getByRole('heading', { name: 'Dashboard' })).toBeVisible({ timeout: 30_000 });
  csrf = (await (await page.request.get('/api/v1/auth/status')).json()).csrfToken as string;
});

test.afterEach(() => {
  expect(problems, 'no page errors or CSP violations').toEqual([]);
});

test.afterAll(async () => {
  await ctx.close();
  await new Promise<void>((ok) => source.close(() => ok()));
});

const h = () => ({ 'x-csrf-token': csrf });

/** The categories view's row for a category (by its id). */
const row = (id: string): Locator => page.locator(`[data-testid="cat-row"][data-category="${id}"]`);
const group = (id: string): Locator => page.locator(`[data-testid="cat-group"][data-group="${id}"]`);

test('flt_901 the Categories tab: groups with "n of m", the info popover, sources and licences, and not available', async () => {
  await page.goto('/#/lists?tab=categories');
  const view = page.getByTestId('categories-view');
  await expect(view).toBeVisible();
  // The groups as UniFi names them, each with its "n of m" count (nothing is selected on a new install).
  await expect(group('adult').getByTestId('cat-group-count')).toHaveText('0 of 4');
  await expect(group('security').getByTestId('cat-group-count')).toHaveText('0 of 3');
  // The catalog browser is read-only: no box can be ticked here.
  await expect(row('adult').getByTestId('cat-check')).toBeDisabled();
  // Each row names its source and licence; the info icon opens what the category is and how big.
  await expect(row('adult').getByTestId('cat-source')).toContainText('HaGeZi NSFW, GPL-3.0');
  await row('adult').getByTestId('cat-info').click();
  const pop = row('adult').getByTestId('cat-popover');
  await expect(pop).toContainText('Pornography');
  await expect(pop).toContainText('85,282 entries');
  // A heavy category says so, with its size.
  await expect(row('nrd').getByTestId('cat-heavy')).toContainText('Heavy: about 27.9 MiB');
  // Sources and licences: every source with its licence link, and the CC BY-SA attribution.
  await page.getByTestId('cat-licences-open').click();
  const lic = page.getByTestId('cat-licences');
  await expect(lic.getByTestId('cat-attribution')).toContainText('Licensed CC BY-SA 4.0, (c) Bon-Appetit contributors');
  const ba = lic.locator('[data-testid="cat-licence-row"][data-source="bonappetit-porn"]');
  await expect(ba).toContainText('CC-BY-SA-4.0');
  await expect(ba.getByRole('link', { name: 'CC-BY-SA-4.0' })).toHaveAttribute('href', /Bon-Appetit\/porn-domains/);
  await expect(lic.locator('[data-source="hagezi-nsfw"]').getByRole('link', { name: 'GPL-3.0' })).toBeVisible();
  await page.keyboard.press('Escape');
  // Not available: collapsed, with the reason for each.
  const na = page.getByTestId('cat-not-available');
  await expect(na).not.toHaveAttribute('open', '');
  await na.locator('summary').click();
  await expect(na).toContainText('Alcohol and tobacco');
  await expect(na).toContainText('No open maintained list is known');
  // The help topics.
  await page.locator('[data-help="categories"]').first().click();
  await expect(page.getByTestId('help-panel')).toContainText('DNS block');
  await page.keyboard.press('Escape');
});

/** Opens the profile editor for a new profile named `name`. */
async function newProfile(name: string) {
  await page.goto('/#/groups');
  await page.getByTestId('profile-new').click();
  const ed = page.getByTestId('profile-editor');
  await expect(ed).toBeVisible();
  await ed.getByTestId('profile-name').fill(name);
  return ed;
}

test('flt_902 the profile editor: group and indeterminate checkboxes, search then Select all, heavy confirmation', async () => {
  const ed = await newProfile(PROFILE);
  await ed.getByTestId('level-enhanced').check();
  const view = ed.getByTestId('categories-view');
  await expect(view).toBeVisible();

  // The group checkbox selects every category of its group; one cleared leaves it indeterminate.
  const net = group('network');
  await net.getByTestId('cat-group-check').check();
  await expect(net.getByTestId('cat-group-count')).toHaveText('4 of 4');
  await net.locator('[data-category="hosting"]').getByTestId('cat-check').uncheck();
  await expect(net.getByTestId('cat-group-count')).toHaveText('3 of 4');
  await expect(net.getByTestId('cat-group-check')).toHaveJSProperty('indeterminate', true);
  await net.getByTestId('cat-group-check').check();
  await expect(net.getByTestId('cat-group-count')).toHaveText('4 of 4');
  await net.getByTestId('cat-group-check').uncheck();
  await expect(net.getByTestId('cat-group-count')).toHaveText('0 of 4');

  // Search, then Select all: only the matches. "fake" is in two categories, in two groups.
  const search = view.getByRole('group', { name: 'Search categories', exact: true });
  await search.getByRole('combobox').fill('fake');
  await search.getByTestId('picker-all').click();
  await search.getByRole('combobox').press('Escape');
  await expect(row('fakenews').getByTestId('cat-check')).toBeChecked();
  await expect(row('fake-stores').getByTestId('cat-check')).toBeChecked();
  await expect(row('adult').getByTestId('cat-check')).not.toBeChecked();
  await expect(group('culture').getByTestId('cat-group-count')).toHaveText('1 of 6');
  await expect(group('risky').getByTestId('cat-group-count')).toHaveText('1 of 4');
  // Deselect all (on a search) clears the matches only.
  await search.getByRole('combobox').click();
  await search.getByRole('combobox').fill('fake');
  await search.getByTestId('picker-none').click();
  await search.getByRole('combobox').press('Escape');
  await expect(row('fakenews').getByTestId('cat-check')).not.toBeChecked();

  // A heavy category asks first, and states the daily download.
  await row('nrd').getByTestId('cat-check').click();
  const confirm = ed.getByTestId('cat-heavy-confirm');
  await expect(confirm).toBeVisible();
  await expect(confirm).toContainText('every day');
  await expect(confirm).toContainText('MiB');
  await expect(row('nrd').getByTestId('cat-check')).not.toBeChecked();
  await confirm.getByTestId('cat-heavy-no').click();
  await expect(confirm).toBeHidden();
  await expect(row('nrd').getByTestId('cat-check')).not.toBeChecked();
  // The running total follows the selection.
  await row('adult').getByTestId('cat-check').check();
  await expect(ed.getByTestId('cat-total')).toContainText('85,282 entries');
  await ed.getByRole('button', { name: 'Cancel' }).click();
  await expect(ed).toBeHidden();
});

test('flt_902 a device with a private address warns; one selected by address or name does not; Add device creates it', async () => {
  const r = page.request;
  // A configured device with a private MAC and an address: selectable by either.
  const put = await r.put(`/api/v1/clients/${encodeURIComponent(CONFIGURED)}`, { headers: h(), data: { match: ['da:a1:19:00:00:02', '10.77.0.5'], groups: ['default'] } });
  expect(put.status()).toBe(200);
  const ed = await newProfile(PROFILE);
  const picker = ed.getByRole('group', { name: 'Source', exact: true });
  await picker.getByRole('combobox').click();
  await picker.getByRole('option', { name: new RegExp(CONFIGURED) }).click();
  await picker.getByRole('combobox').press('Escape');
  const dev = ed.getByTestId('profile-device').filter({ hasText: CONFIGURED });
  // Keyed by its MAC (private) the warning shows; by its address it does not.
  await expect(dev.getByTestId('private-mac-warning')).toBeVisible();
  await expect(ed.getByTestId('private-mac-notice')).toContainText('private Wi-Fi address');
  await dev.getByTestId('profile-device-key').selectOption({ label: 'Address 10.77.0.5' });
  await expect(dev.getByTestId('private-mac-warning')).toHaveCount(0);
  await expect(ed.getByTestId('private-mac-notice')).toHaveCount(0);
  await dev.getByTestId('profile-device-key').selectOption({ index: 0 });
  await expect(dev.getByTestId('private-mac-warning')).toBeVisible();

  // Add device: a new device from a name and its private MAC; the warning follows.
  await ed.getByTestId('profile-add-device').click();
  await ed.getByTestId('profile-add-name').fill(DEVICE);
  await ed.getByTestId('profile-add-key').fill(PRIVATE_MAC);
  await ed.getByTestId('profile-add-confirm').click();
  const added = ed.getByTestId('profile-device').filter({ hasText: DEVICE });
  await expect(added).toBeVisible();
  await expect(added.getByTestId('private-mac-warning')).toBeVisible();
  // A MAC with the private bit clear shows no warning.
  await ed.getByTestId('profile-add-device').click();
  await ed.getByTestId('profile-add-name').fill('Plain Pi');
  await ed.getByTestId('profile-add-key').fill('b8:27:eb:00:00:09');
  await ed.getByTestId('profile-add-confirm').click();
  await expect(ed.getByTestId('profile-device').filter({ hasText: 'Plain Pi' }).getByTestId('private-mac-warning')).toHaveCount(0);

  // The rest of the profile: Ad Block, Safe Search for two engines, Basic filtering.
  await ed.getByTestId('profile-ads').check();
  await ed.getByTestId('engine-google').check();
  await ed.getByTestId('engine-youtube').check();
  await ed.getByTestId('level-basic').check();
  await expect(ed.getByTestId('profile-basic-note')).toContainText('adult content, malware, phishing and scams');
  await ed.getByTestId('profile-save').click();
  await expect(ed).toBeHidden();

  // The profile list: five columns, the first two sources as chips and "+N" for the rest.
  const rowEl = page.locator('[data-testid="profile-row"][data-profile="kids"]');
  await expect(rowEl).toBeVisible();
  await expect(rowEl.locator('[data-col="source"]').getByTestId('chip')).toHaveCount(2);
  await expect(rowEl.locator('[data-col="source"]').getByTestId('chip-more')).toHaveText('+1');
  await expect(rowEl.locator('[data-col="source"]').getByTestId('chip-private').first()).toBeVisible();
  await expect(rowEl.locator('[data-col="scope"]')).toHaveText('Basic, Ad block');
  await expect(rowEl.locator('[data-col="safe"]')).toContainText('Google');
  await expect(rowEl.locator('[data-col="safe"]')).toContainText('YouTube');
  const head = page.getByTestId('profile-table').locator('thead th');
  await expect(head).toHaveText(['Name', 'Source', 'Filter Scope', 'Safe Search', 'Schedule', 'Edit']);

  // The device added from the editor is a named device in the profile (AC12) ...
  const clients = await (await r.get('/api/v1/clients')).json();
  const maya = clients.items.find((c: { name: string }) => c.name === DEVICE);
  expect(maya, 'the added device exists').toBeTruthy();
  expect(maya.groups).toEqual([PROFILE]);
  expect(maya.match).toEqual([PRIVATE_MAC]);
  // ... and shows on the Clients page.
  await page.goto('/#/clients?tab=devices');
  await expect(page.getByRole('row', { name: new RegExp(DEVICE) })).toContainText(PROFILE);

  // Round trip: the API and the configuration hold every field the editor set.
  const g = (await (await r.get('/api/v1/groups')).json()).items.find((x: { name: string }) => x.name === PROFILE);
  expect(g.content).toMatchObject({ level: 'basic', ads: true });
  expect(g.safeSearchEngines).toEqual(['google', 'youtube']);
  expect(g.filterScope).toBe('Basic, Ad block');
  expect(g.sources.map((s: { label: string }) => s.label).sort()).toEqual([CONFIGURED, DEVICE, 'Plain Pi']);
  const entry = (await (await r.get('/api/v1/config/entries?kind=group')).json()).items.find((x: { name: string }) => x.name === PROFILE);
  expect(entry.definition.content).toMatchObject({ level: 'basic', ads: true });
  expect(entry.definition.safe_search_engines).toEqual(['google', 'youtube']);
  // Reopened, the editor shows what was saved.
  await page.goto('/#/groups');
  await rowEl.getByTestId('profile-edit').click();
  const again = page.getByTestId('profile-editor');
  await expect(again.getByTestId('profile-ads')).toBeChecked();
  await expect(again.getByTestId('engine-google')).toBeChecked();
  await expect(again.getByTestId('engine-bing')).not.toBeChecked();
  await expect(again.getByTestId('level-basic')).toBeChecked();
  await expect(again.getByTestId('profile-device')).toHaveCount(3);
  await again.getByRole('button', { name: 'Cancel' }).click();
});

test('flt_901 a category on a profile makes an owned list the node downloads once; Explain names the category; refresh and shadow work', async () => {
  const r = page.request;
  // The default profile `lab` (every e2e query is from 127.0.0.1) takes the Adult content category.
  await page.goto('/#/groups');
  await page.locator('[data-testid="profile-row"][data-profile="lab"]').getByTestId('profile-edit').click();
  const ed = page.getByTestId('profile-editor');
  await ed.getByTestId('level-enhanced').check();
  await row('adult').getByTestId('cat-check').check();
  await expect(group('adult').getByTestId('cat-group-count')).toHaveText('1 of 4');
  await ed.getByTestId('profile-save').click();
  await expect(ed).toBeHidden();
  // The Lists page: the category's list, owned and read-only, downloaded once.
  await page.goto('/#/lists');
  const owned = page.locator('tr', { hasText: 'cat-hagezi-nsfw' });
  await expect(owned.getByTestId('list-owner')).toContainText('Owned by category: Adult content');
  await expect(owned.getByText('ok', { exact: true })).toBeVisible({ timeout: 30_000 });
  // The kids profile (Basic) and the lab profile (Adult content) share the source: it was downloaded once.
  expect(requested.filter((u) => u.includes('nsfw-onlydomains')).length).toBe(1);
  // Only the categories' lists, with the chip.
  await page.getByTestId('lists-filter-categories').click();
  const only = page.locator('table').first().locator('tbody tr');
  // The three category lists (Adult content, the threat feed Basic uses, and Ad block), no others.
  await expect(only).toHaveCount(3);
  await expect(only.getByTestId('list-owner').first()).toBeVisible();
  await page.getByTestId('lists-filter-all').click();
  // The list's own definition can't be edited or deleted (409), but refreshing works.
  const edit = await r.put('/api/v1/lists/cat-hagezi-nsfw', { headers: h(), data: { url: 'https://example.com/x.txt' } });
  expect(edit.status()).toBe(409);
  expect((await edit.json()).code).toBe('owned_by_category');
  const del = await r.delete('/api/v1/lists/cat-hagezi-nsfw', { headers: h() });
  expect(del.status()).toBe(409);
  await owned.getByTestId('list-update-now').click();
  await expect(owned.getByTestId('list-update-now')).toBeEnabled({ timeout: 30_000 });
  // Shadow mode and back.
  await owned.getByTestId('list-shadow-toggle').click();
  await expect(page.locator('tr', { hasText: 'cat-hagezi-nsfw' }).getByText('shadow', { exact: true })).toBeVisible();
  await page.locator('tr', { hasText: 'cat-hagezi-nsfw' }).getByTestId('list-shadow-toggle').click();
  await expect(page.locator('tr', { hasText: 'cat-hagezi-nsfw' }).getByText('shadow', { exact: true })).toHaveCount(0);
  // The name in the list is blocked for the lab profile, and Explain names the category.
  await expect
    .poll(async () => (await queryDetail('x.blocked-by-category.e2e.test')).address, { timeout: 30_000 })
    .toBe('0.0.0.0');
  const answer = await queryDetail('x.blocked-by-category.e2e.test');
  expect(answer.ede.map((e) => e.text).join(' ')).toContain('blocked by category Adult content (list cat-hagezi-nsfw)');
  const ex = await (await r.get('/api/v1/explain?name=x.blocked-by-category.e2e.test&client=127.0.0.1')).json();
  expect(ex.block).toMatchObject({ list: 'cat-hagezi-nsfw', category: 'Adult content' });
  // The Categories tab shows the source as downloaded.
  await page.goto('/#/lists?tab=categories');
  await expect(row('adult')).toBeVisible();
  // REQ: FLT-004 (T24.28): how much of the source the lists already in use cover.
  await row('adult').getByTestId('cat-info').click();
  await expect(row('adult').getByTestId('cat-overlap').first()).toContainText(/2 entries, \d+ also in the lists you already use/);
  await page.getByTestId('cat-licences-open').click();
  await expect(page.getByTestId('cat-licences').locator('[data-source="hagezi-nsfw"]').getByTestId('cat-licence-overlap')).toContainText('also in the lists you already use');
  await page.keyboard.press('Escape');
  // A device of the lab profile shows the category in the policy panel.
  const pol = await (await r.get('/api/v1/clients/127.0.0.1/policy')).json();
  const cats = pol.sections.find((s: { id: string }) => s.id === 'categories');
  expect(cats.items.map((i: { label: string }) => i.label)).toEqual(['Adult content']);
  await page.goto('/#/clients?device=127.0.0.1&view=policy');
  await expect(page.getByTestId('policy-section-categories')).toContainText('Adult content');
  // Put lab back as it was.
  await page.goto('/#/groups');
  await page.locator('[data-testid="profile-row"][data-profile="lab"]').getByTestId('profile-edit').click();
  await page.getByTestId('level-off').check();
  await page.getByTestId('profile-save').click();
  await expect(page.getByTestId('profile-editor')).toBeHidden();
  await expect.poll(async () => (await queryDetail('x.blocked-by-category.e2e.test')).address, { timeout: 30_000 }).not.toBe('0.0.0.0');
});

test('flt_901 the list settings card: the entry budget and the ad block size, with the category-budget help topic', async () => {
  await page.setViewportSize({ width: 1280, height: 800 });
  await page.goto('/#/lists');
  const card = page.getByTestId('filter-settings-card');
  await expect(card.getByTestId('filter-entry-budget')).toContainText('1,000,000');
  await expect(card.getByTestId('filter-ads-tier')).toHaveText('pro');
  await card.locator('[data-help="category-budget"]').first().click();
  await expect(page.getByTestId('help-panel')).toContainText('about 12 bytes');
  await page.keyboard.press('Escape');
  await card.getByTestId('filter-settings-edit').click();
  await page.getByRole('spinbutton', { name: 'Entry budget' }).fill('2000000');
  await page.getByLabel('Ad block size').selectOption('ultimate');
  await page.getByRole('button', { name: 'Check', exact: true }).click();
  await expect(card.getByTestId('filter-settings-preview')).toBeVisible();
  await page.getByRole('button', { name: 'Apply' }).click();
  await expect(card.getByTestId('filter-entry-budget')).toContainText('2,000,000');
  await expect(card.getByTestId('filter-ads-tier')).toHaveText('ultimate');
  const view = await (await page.request.get('/api/v1/categories')).json();
  expect(view.node).toMatchObject({ entryBudget: 2_000_000, adsTier: 'ultimate' });
  // Back to the file's values (the card has no revert; the API does).
  expect((await page.request.delete('/api/v1/filter-settings/default', { headers: h() })).status()).toBe(200);
  await page.reload();
  await expect(page.getByTestId('filter-settings-card').getByTestId('filter-entry-budget')).toContainText('1,000,000');
});

test('flt_902 saving a profile writes its content only when it changed, and a refused new profile leaves no group', async () => {
  const writes: string[] = [];
  const onRequest = (rq: { method: () => string; url: () => string }) => {
    if (rq.method() === 'PUT' && /\/api\/v1\/groups\//.test(rq.url())) writes.push(new URL(rq.url()).pathname);
  };
  page.on('request', onRequest);
  try {
    // The lab profile as it is: nothing changed, so the group is written and its content is not.
    await page.goto('/#/groups');
    await page.locator('[data-testid="profile-row"][data-profile="lab"]').getByTestId('profile-edit').click();
    const ed = page.getByTestId('profile-editor');
    await expect(ed.getByTestId('level-off')).toBeChecked();
    await ed.getByTestId('profile-save').click();
    await expect(ed).toBeHidden();
    expect(writes.filter((w) => w.endsWith('/content'))).toEqual([]);
    expect(writes.some((w) => w.endsWith('/groups/lab/sources'))).toBe(true);
    // A new profile whose heavy content waits for a confirmation is not left half-saved.
    const nu = await newProfile('half-saved');
    await nu.getByTestId('level-enhanced').check();
    await row('nrd').getByTestId('cat-check').click();
    await nu.getByTestId('cat-heavy-confirm').getByTestId('cat-heavy-yes').click();
    await nu.getByTestId('profile-save').click();
    await expect(nu.getByTestId('profile-confirm')).toBeVisible();
    const groups = await (await page.request.get('/api/v1/groups')).json();
    expect(groups.items.map((g: { name: string }) => g.name)).not.toContain('half-saved');
    await nu.getByRole('button', { name: 'Cancel' }).click();
    await expect(nu).toBeHidden();
  } finally {
    page.off('request', onRequest);
  }
});

test('flt_901 clean up: the profile and the devices go', async () => {
  const r = page.request;
  for (const d of [DEVICE, 'Plain Pi', CONFIGURED]) {
    expect((await r.delete(`/api/v1/clients/${encodeURIComponent(d)}`, { headers: h() })).status()).toBe(200);
  }
  expect((await r.delete(`/api/v1/groups/${PROFILE}`, { headers: h() })).status()).toBe(200);
  void pick;
});
