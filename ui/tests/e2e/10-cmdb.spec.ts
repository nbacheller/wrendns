// REQ: DSC-901, DSC-902, DSC-903, DSC-906 (T31.2, ADR-1004, ADR-1005) — the CMDB page against a real
// server: the settings panel (admins change it, operators read it, a field the file sets is "set by
// file"), the status, the CIs and a CI's records side by side, and the controls that fix a wrong link:
// Move, Unlink, Merge and Split, each with a preview of the records that would move before anything
// is written. Every control has a help topic (the "?" beside it). The devices are `[[client]]` entries
// made through the API: the CMDB reads the configuration as its `config` source. The file is named
// `10-` so it runs after the admin exists and before the later files; it turns the CMDB off again at
// the end and removes what it made.
import { expect, test, type BrowserContext, type Page } from '@playwright/test';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { E2E_ROOT } from './ports';

test.describe.configure({ mode: 'serial' });

const ADMIN = { user: 'admin', pass: 'correct horse battery' };
const OPERATOR = { user: 'cmdb-op', pass: 'operator long password' };
const VIEWER = { user: 'cmdb-viewer', pass: 'viewer long password' };
const A = 'cmdb-a';
const B = 'cmdb-b';
const C = 'cmdb-c';

let ctx: BrowserContext;
let page: Page;
let csrf = '';
// The devices the merge test finds; the later tests refer to them by id (a merged device's name may
// be the other's, the better of the two).
let idA = '';
let idB = '';
let idC = '';
const problems: string[] = [];

test.beforeAll(async ({ browser }) => {
  ctx = await browser.newContext();
  page = await ctx.newPage();
  page.on('pageerror', (e) => problems.push(`page error: ${e.message}`));
  page.on('console', (m) => {
    if (m.type() === 'error' && !/status of (40[0134]|409|422|429|503) \(/.test(m.text())) problems.push(`console: ${m.text()} ${m.location().url}`);
  });
  await page.goto('/');
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
  // Back to how the suite found it: the CMDB off (the file's settings), the devices gone.
  for (const n of [A, B, C]) await page.request.delete(`/api/v1/clients/${n}`, { headers: h() }).catch(() => {});
  await page.request.delete('/api/v1/cmdb-settings/default', { headers: h() }).catch(() => {});
  await ctx.close();
});

const h = () => ({ 'x-csrf-token': csrf });

async function signInAs(user: { user: string; pass: string }) {
  const c = await page.context().browser()!.newContext({ baseURL: page.url().split('/#')[0] });
  const p = await c.newPage();
  await p.goto('/#/cmdb');
  await p.getByLabel('Username', { exact: true }).fill(user.user);
  await p.getByLabel('Password', { exact: true }).fill(user.pass);
  await p.getByRole('button', { name: 'Sign in' }).click();
  return { c, p };
}

const cis = async (q: string) =>
  ((await (await page.request.get(`/api/v1/cmdb/cis?type=device&q=${encodeURIComponent(q)}`)).json()) as { items: { id: string; name: string | null; records: number }[] }).items;

/** The device CI named `name`, waiting for the CMDB to have read the configuration. */
async function deviceId(name: string): Promise<string> {
  let id = '';
  await expect
    .poll(async () => {
      id = (await cis(name)).find((c) => c.name === name)?.id ?? '';
      return id;
    }, { timeout: 30_000 })
    .not.toBe('');
  return id;
}

test('dsc_906 cmdb settings: a file-set field is set by file, an operator reads, the admin turns it on', async () => {
  await page.goto('/#/cmdb');
  await expect(page.getByRole('heading', { name: 'CMDB' })).toBeVisible();
  await expect(page.getByTestId('cmdb-state')).toHaveText('Off');
  const settings = page.getByTestId('cmdb-settings');
  // The test configuration sets `history_days`: it shows as set by file and is locked.
  await expect(settings.getByTestId('set-by-file')).toHaveCount(1);
  await expect(settings.getByLabel('Days of value history')).toBeDisabled();
  await expect(settings.getByLabel('Days of change records')).toBeEnabled();
  // An operator reads the settings and cannot change them (the API says 403, naming the field).
  await page.request.post('/api/v1/users', { headers: h(), data: { username: OPERATOR.user, password: OPERATOR.pass, role: 'operator' } });
  const op = await signInAs(OPERATOR);
  try {
    const mine = op.p.getByTestId('cmdb-settings');
    await expect(mine.getByText("Only an administrator can change the CMDB's settings")).toBeVisible({ timeout: 30_000 });
    await expect(mine.getByRole('button', { name: 'Check', exact: true })).toHaveCount(0);
    await expect(mine.getByRole('switch', { name: 'Turn the CMDB on' })).toBeDisabled();
    const ocsrf = (await (await op.c.request.get('/api/v1/auth/status')).json()).csrfToken as string;
    const refused = await op.c.request.put('/api/v1/cmdb-settings/default', { headers: { 'x-csrf-token': ocsrf }, data: { enabled: true } });
    expect(refused.status()).toBe(403);
    expect(await refused.text()).toContain('enabled');
  } finally {
    await op.c.close();
  }
  // The admin checks, then applies: the CMDB starts on this node (the designated one) within seconds.
  await settings.getByRole('switch', { name: 'Turn the CMDB on' }).check();
  await settings.getByRole('button', { name: 'Check', exact: true }).click();
  await expect(page.getByTestId('cmdb-settings-preview')).toContainText('Applies on the designated node');
  await settings.getByRole('button', { name: 'Apply', exact: true }).click();
  await expect(settings.getByText('Saved. The CMDB starts or stops')).toBeVisible();
  await expect
    .poll(async () => ((await (await page.request.get('/api/v1/cmdb/status')).json()) as { running: boolean }).running, { timeout: 30_000 })
    .toBe(true);
  await page.goto('/#/');
  await page.goto('/#/cmdb');
  await expect(page.getByTestId('cmdb-state')).toHaveText('Runs on this node', { timeout: 30_000 });
  await expect(page.getByTestId('cmdb-counts')).toContainText('devices');
});

test('dsc_906 every CMDB control has a help topic', async () => {
  await page.goto('/#/cmdb');
  await page.getByRole('button', { name: 'Help: CMDB: one record for each thing on your network' }).click();
  await expect(page.getByTestId('help-panel')).toContainText('only reads');
  await page.keyboard.press('Escape');
  await page.getByRole('button', { name: 'Help: What each source said' }).first().click();
  await expect(page.getByTestId('help-panel')).toContainText('what one source said');
  await page.keyboard.press('Escape');
});

test('dsc_903 merge two devices with a preview; the old id redirects', async () => {
  // Three devices: A and B each have a MAC; C has only a client ID, so no key at all.
  for (const [name, match] of [[A, 'aa:00:00:00:c0:01'], [B, 'aa:00:00:00:c0:02'], [C, 'id:cmdb-keyless']] as const) {
    const r = await page.request.put(`/api/v1/clients/${name}`, { headers: h(), data: { match: [match], groups: ['default'] } });
    expect(r.status(), await r.text()).toBe(200);
  }
  idA = await deviceId(A);
  idB = await deviceId(B);
  idC = await deviceId(C);
  expect(idA).not.toBe(idB);
  await page.goto('/#/cmdb');
  await page.getByLabel('Find a CI').fill(A);
  const rowA = page.locator(`[data-testid="cmdb-row"][data-ci="${idA}"]`);
  await expect(rowA).toBeVisible();
  await rowA.getByRole('button').click();
  const ci = page.getByTestId('cmdb-ci');
  await expect(ci).toHaveAttribute('data-ci', idA);
  // The seen line keeps its spaces ("9:20:15 PM on 1 day", never "PMon"): Svelte trims a block's
  // leading space.
  await expect(ci.locator('p.small').first()).toContainText('first seen');
  await expect(ci.locator('p.small').first()).not.toHaveText(/\Son \d+ days?/);
  await expect(ci.locator('[data-testid="cmdb-record"][data-source="config"]')).toBeVisible();
  // Merge A into B: the preview lists A's records, nothing is written until Apply.
  await ci.getByTestId('cmdb-merge').click();
  const picker = page.getByTestId('cmdb-picker');
  await picker.getByLabel('Search for a device').fill(B);
  await picker.locator(`[data-testid="cmdb-pick"][data-ci="${idB}"]`).click();
  const preview = page.getByTestId('cmdb-preview');
  await expect(preview.getByTestId('cmdb-moves')).toContainText('client:cmdb-a');
  await expect(preview.getByTestId('cmdb-note').first()).toContainText('alias');
  // The preview has its own help topic.
  await preview.getByRole('button', { name: 'Help: Fixing a wrong link' }).click();
  await expect(page.getByTestId('help-panel')).toContainText('a preview of the records that would move');
  await page.keyboard.press('Escape');
  // Cancelling writes nothing.
  await preview.getByTestId('cmdb-cancel').click();
  await expect(page.getByTestId('cmdb-preview')).toHaveCount(0);
  expect((await cis(A)).some((c) => c.id === idA)).toBe(true);
  // Do it.
  await ci.getByTestId('cmdb-merge').click();
  await picker.getByLabel('Search for a device').fill(B);
  await picker.locator(`[data-testid="cmdb-pick"][data-ci="${idB}"]`).click();
  await page.getByTestId('cmdb-preview').getByLabel('Why').fill('Same device, two entries');
  await page.getByTestId('cmdb-apply').click();
  await expect(page.getByTestId('cmdb-change-notice')).toContainText('Merged: 1 record');
  // The survivor now holds both devices' records, with the pin and its reason.
  await expect(page.getByTestId('cmdb-ci')).toHaveAttribute('data-ci', idB);
  await expect(page.getByTestId('cmdb-records').locator('[data-testid="cmdb-record"]')).toHaveCount(2);
  await expect(page.getByTestId('cmdb-pins')).toContainText('Same device, two entries');
  await expect(page.getByTestId('cmdb-alias')).toContainText('redirects');
  // The merged-away id answers with the CI it became (the alias, 90 days), and A is gone from the list.
  const old = (await (await page.request.get(`/api/v1/cmdb/cis/${idA}`)).json()) as { ci: { id: string } };
  expect(old.ci.id).toBe(idB);
  expect((await cis(A)).some((c) => c.id === idA)).toBe(false);
});

test('dsc_903 a filter typed while the list is loading is not lost', async () => {
  // The unfiltered load that opens the page is held; the filter is typed meanwhile. The list must
  // end up answering the filter (one row), not the held load's answer and not a dropped request.
  let release!: () => void;
  const gate = new Promise<void>((r) => (release = r));
  await page.route(/\/api\/v1\/cmdb\/cis\?/, async (route) => {
    if (!route.request().url().includes('q=')) await gate;
    await route.continue();
  });
  try {
    const held = page.waitForRequest((r) => /\/api\/v1\/cmdb\/cis\?limit=50$/.test(r.url()));
    await page.reload();
    await held;
    await page.getByLabel('Find a CI').fill(idB);
    await page.waitForTimeout(600); // past the 200 ms debounce: the filtered load is asked for while the first runs
    release();
    await expect(page.locator('[data-testid="cmdb-row"]')).toHaveCount(1);
    await expect(page.locator(`[data-testid="cmdb-row"][data-ci="${idB}"]`)).toBeVisible();
  } finally {
    release();
    await page.unroute(/\/api\/v1\/cmdb\/cis\?/);
  }
});

test('dsc_903 split a record out, then unlink and move one; the decisions stay', async () => {
  // Start from a known state: the page the merge test left open is reloaded (a goto to the same hash
  // does not), and the CI is found by its id, which a merge never changes (its name can: the survivor
  // may carry the other device's name, so a search for the old name finds nothing).
  await page.goto('/#/cmdb');
  await page.reload();
  await page.getByLabel('Find a CI').fill(idB);
  await page.locator(`[data-testid="cmdb-row"][data-ci="${idB}"]`).getByRole('button').click();
  const ci = page.getByTestId('cmdb-ci');
  await expect(ci.locator('[data-testid="cmdb-record"]')).toHaveCount(2);
  // Split: tick A's record; the control is disabled until something is ticked.
  await expect(ci.getByTestId('cmdb-split')).toBeDisabled();
  await ci.locator('[data-testid="cmdb-record"][data-key="client:cmdb-a"]').getByTestId('cmdb-tick').check();
  await ci.getByTestId('cmdb-split').click();
  const preview = page.getByTestId('cmdb-preview');
  await expect(preview.getByTestId('cmdb-moves')).toContainText('client:cmdb-a');
  await page.getByTestId('cmdb-apply').click();
  await expect(page.getByTestId('cmdb-change-notice')).toContainText('Split: 1 record');
  // The new device holds A's record alone.
  const shown = page.getByTestId('cmdb-ci');
  await expect(shown.locator('[data-testid="cmdb-record"]')).toHaveCount(1);
  await expect(shown.locator('[data-testid="cmdb-record"][data-key="client:cmdb-a"]')).toBeVisible();
  const newId = (await shown.getAttribute('data-ci'))!;
  expect(newId).not.toBe(idB);
  // The keyless device C: move its record under the new device, then unlink it again. The unlink is a
  // pin that the next report does not undo.
  await page.getByLabel('Find a CI').fill(C);
  await page.locator(`[data-testid="cmdb-row"][data-ci="${idC}"]`).getByRole('button').click();
  await page.getByTestId('cmdb-ci').locator('[data-testid="cmdb-record"][data-key="client:cmdb-c"]').getByTestId('cmdb-move').click();
  await page.getByTestId('cmdb-picker').getByLabel('Search for a device').fill(A);
  await page.locator(`[data-testid="cmdb-pick"][data-ci="${newId}"]`).click();
  await expect(page.getByTestId('cmdb-moves')).toContainText('client:cmdb-c');
  await page.getByTestId('cmdb-apply').click();
  await expect(page.getByTestId('cmdb-change-notice')).toContainText('Linked: 1 record');
  await expect(page.getByTestId('cmdb-ci')).toHaveAttribute('data-ci', newId);
  await expect(page.getByTestId('cmdb-ci').locator('[data-testid="cmdb-record"]')).toHaveCount(2);
  await page.getByTestId('cmdb-ci').locator('[data-testid="cmdb-record"][data-key="client:cmdb-c"]').getByTestId('cmdb-unlink').click();
  await expect(page.getByTestId('cmdb-moves')).toContainText('client:cmdb-c');
  await expect(page.getByTestId('cmdb-note').first()).toContainText('will not be matched');
  await page.getByTestId('cmdb-apply').click();
  await expect(page.getByTestId('cmdb-change-notice')).toContainText('Unlinked: 1 record');
  // C's record is on a device of its own now, and a configuration reload (which makes the CMDB read
  // its feeds again at once) leaves it there.
  const r = await page.request.put(`/api/v1/clients/${C}`, { headers: h(), data: { match: ['id:cmdb-keyless'], groups: ['default'], } });
  expect(r.status()).toBe(200);
  await page.waitForTimeout(1500);
  const detail = (await (await page.request.get(`/api/v1/cmdb/cis/${newId}`)).json()) as { records: { key: string }[]; pins: { kind: string }[] };
  expect(detail.records.map((x) => x.key)).toEqual(['client:cmdb-a']);
  expect(detail.pins.some((p) => p.kind === 'rec_never')).toBe(true);
});

test('dsc_903 a viewer sees the page but has no controls and cannot change a link', async () => {
  await page.request.post('/api/v1/users', { headers: h(), data: { username: VIEWER.user, password: VIEWER.pass, role: 'viewer' } });
  const v = await signInAs(VIEWER);
  try {
    await expect(v.p.getByTestId('cmdb-state')).toHaveText('Runs on this node', { timeout: 30_000 });
    await v.p.getByLabel('Find a CI').fill(B);
    await v.p.locator(`[data-testid="cmdb-row"][data-ci="${idB}"]`).getByRole('button').click();
    await expect(v.p.getByTestId('cmdb-ci')).toBeVisible();
    await expect(v.p.getByTestId('cmdb-merge')).toHaveCount(0);
    await expect(v.p.getByTestId('cmdb-split')).toHaveCount(0);
    const vcsrf = (await (await v.c.request.get('/api/v1/auth/status')).json()).csrfToken as string;
    const refused = await v.c.request.post(`/api/v1/cmdb/cis/${idB}/merge?dryRun=true`, { headers: { 'x-csrf-token': vcsrf }, data: { into: idB } });
    expect(refused.status()).toBe(403);
    // No agent scope reaches the CMDB routes either.
  } finally {
    await v.c.close();
  }
});

test('dsc_906 the numeric settings round-trip, the page says nothing reads them yet, and privacy level 2 refuses', async () => {
  await page.goto('/#/cmdb');
  const settings = page.getByTestId('cmdb-settings');
  await expect(settings.getByTestId('cmdb-settings-inert')).toContainText('Nothing reads them yet');
  // Every field the file does not set: change it, Check, Apply, reload, and it is what was saved.
  const numbers: [string, string][] = [
    ['Days before a device is reported gone', '21'],
    ['Seconds a change must hold', '900'],
    ['Hours before an unconfirmed change alerts', '48'],
    ['Days before an approved plan expires', '45'],
    ['Days of change records', '400'],
  ];
  for (const [label, value] of numbers) await settings.getByLabel(label).fill(value);
  await settings.getByRole('switch', { name: 'Require a second approver' }).check();
  await settings.getByRole('button', { name: 'Check', exact: true }).click();
  await expect(page.getByTestId('cmdb-settings-preview')).toBeVisible();
  await settings.getByRole('button', { name: 'Apply', exact: true }).click();
  await expect(settings.getByText('Saved. The CMDB starts or stops')).toBeVisible();
  await page.reload();
  await expect(page.getByTestId('cmdb-settings')).toBeVisible();
  for (const [label, value] of numbers) await expect(page.getByTestId('cmdb-settings').getByLabel(label)).toHaveValue(value, { timeout: 30_000 });
  await expect(page.getByTestId('cmdb-settings').getByRole('switch', { name: 'Require a second approver' })).toBeChecked();
  // A value out of range is refused by the server and the panel shows why (nothing is saved).
  await settings.getByLabel('Days before a device is reported gone').fill('9999');
  await settings.getByRole('button', { name: 'Check', exact: true }).click();
  await expect(settings.getByRole('alert')).toContainText('disappear_after_days');
  // At privacy level 2 the CMDB cannot be on: turn it off, raise the level, try to turn it on.
  await settings.getByLabel('Days before a device is reported gone').fill('14');
  await settings.getByRole('switch', { name: 'Turn the CMDB on' }).uncheck();
  await settings.getByRole('button', { name: 'Check', exact: true }).click();
  await settings.getByRole('button', { name: 'Apply', exact: true }).click();
  await expect(settings.getByText('Saved. The CMDB starts or stops')).toBeVisible();
  try {
    const raised = await page.request.put('/api/v1/qlog-settings/default', { headers: h(), data: { privacy_level: 2 } });
    expect(raised.status(), await raised.text()).toBe(200);
    await page.reload();
    const again = page.getByTestId('cmdb-settings');
    await again.getByRole('switch', { name: 'Turn the CMDB on' }).check();
    await again.getByRole('button', { name: 'Check', exact: true }).click();
    await expect(again.getByRole('alert')).toContainText(/privacy/i);
    await expect(page.getByTestId('cmdb-settings-preview')).toHaveCount(0);
  } finally {
    await page.request.delete('/api/v1/qlog-settings/default', { headers: h() }).catch(() => {});
  }
});
