// REQ: DNS-006, CLU-014, DNS-011, FLT-004, OPS-011, OPS-012, API-007 (T27.2, T27.11; ADR-1006) — the
// small and cache settings in the browser: the node's cache form (an operator changes it, the change
// shows as pending restart, a viewer reads it only), the drill schedule, the DNSSEC mode and trust
// anchors, the list limits, the support and update switches, and the backup's query-history choice.
// It runs after 1-ui.spec.ts (which creates the admin) and shares the e2e server.
import { expect, test, type Browser, type Page } from '@playwright/test';

test.describe.configure({ mode: 'serial' });

const ADMIN = { user: 'admin', pass: 'correct horse battery' };
const VIEWER = { user: 'settings-vw', pass: 'viewer long password' };

/** Signs in as `who` and opens the page at `hash`. */
async function signedIn(
  browser: Browser,
  who: { user: string; pass: string },
  hash: string,
  // Runs on the new page before it loads, so a route mock is in place for the first request.
  before?: (page: Page) => Promise<void>,
): Promise<Page> {
  const page = await browser.newPage();
  if (before) await before(page);
  await page.goto(`/#/${hash}`);
  await page.getByLabel('Username', { exact: true }).fill(who.user);
  await page.getByLabel('Password', { exact: true }).fill(who.pass);
  await page.getByRole('button', { name: 'Sign in' }).click();
  return page;
}

/** REQ: DNS-006 (T27.2) — the cache card of this node on the Cache page. */
async function cacheCard(page: Page) {
  const node = page.getByTestId('cache-node').first();
  await expect(node).toBeVisible({ timeout: 30_000 });
  return node;
}

test.describe('dns_006 cache settings', () => {
  test('dns_006 change cache size from the cache page', async ({ browser }) => {
    const page = await signedIn(browser, ADMIN, 'cache');
    try {
      const node = await cacheCard(page);
      await node.locator('summary', { hasText: 'Settings' }).click();
      await node.getByTestId('cache-settings-edit').click();
      await node.getByLabel('Memory budget (MiB)').fill('48');
      await node.getByRole('button', { name: 'Check' }).click();
      const preview = node.getByTestId('cache-settings-preview');
      await expect(preview).toContainText('after a restart');
      await node.getByRole('button', { name: 'Apply' }).click();
      await expect(node).toContainText('Saved. The new cache settings take effect when this node restarts.');
      await expect(node.getByTestId('cache-settings')).toContainText('48MiB');
    } finally {
      await page.context().close();
    }
  });

  test('dns_006 restart-only field says pending restart', async ({ browser }) => {
    const page = await signedIn(browser, ADMIN, 'cache');
    try {
      // This test makes its own change (it doesn't rely on the test before it), then reads the badge.
      const node = await cacheCard(page);
      await node.locator('summary', { hasText: 'Settings' }).click();
      await node.getByTestId('cache-settings-edit').click();
      await node.getByLabel('Memory budget (MiB)').fill('40');
      await node.getByRole('button', { name: 'Check' }).click();
      await expect(node.getByTestId('cache-settings-preview')).toContainText('after a restart');
      await node.getByRole('button', { name: 'Apply' }).click();
      await expect(node.getByTestId('cache-pending-restart')).toHaveText('pending restart');
      // Applying closes the form and the details with it; wait for that before reopening it.
      await expect(node.locator('details.settings')).not.toHaveAttribute('open');
      await node.locator('summary', { hasText: 'Settings' }).click();
      await node.getByTestId('cache-settings-edit').click();
      await expect(node.getByTestId('cache-settings-form')).toContainText('applies when this node restarts');
      await node.getByRole('button', { name: 'Cancel' }).click();
    } finally {
      await page.context().close();
    }
  });

  test('dns_006 server refuses a shortest TTL above the longest', async ({ browser }) => {
    // REQ: DNS-006 (T27.2) — the server checks what the form can't (cache.min_ttl must not exceed
    // cache.max_ttl); the Check shows the refusal and no preview.
    const page = await signedIn(browser, ADMIN, 'cache');
    try {
      const node = await cacheCard(page);
      await node.locator('summary', { hasText: 'Settings' }).click();
      await node.getByTestId('cache-settings-edit').click();
      await node.getByLabel('Shortest TTL served (seconds)').fill('7200');
      await node.getByLabel('Longest TTL served (seconds)').fill('300');
      await node.getByRole('button', { name: 'Check' }).click();
      await expect(node.getByRole('alert')).toBeVisible();
      await expect(node.getByTestId('cache-settings-preview')).toHaveCount(0);
      await node.getByRole('button', { name: 'Cancel' }).click();
    } finally {
      await page.context().close();
    }
  });

  test('dns_006 cache form refuses an empty or out-of-range value before the server', async ({ browser }) => {
    // REQ: DNS-006 (T27.2) — a cleared number is refused (never saved as 0), and the refresh share
    // of the TTL takes 1 to 99 (the server's range, when prefetch is on).
    const page = await signedIn(browser, ADMIN, 'cache');
    try {
      const node = await cacheCard(page);
      await node.locator('summary', { hasText: 'Settings' }).click();
      await node.getByTestId('cache-settings-edit').click();
      const threshold = node.getByLabel('Refresh when this share of the TTL is left (%)');
      await threshold.fill('100');
      await expect(threshold).toHaveJSProperty('validity.valid', false);
      await threshold.fill('50');
      await expect(threshold).toHaveJSProperty('validity.valid', true);
      const budget = node.getByLabel('Memory budget (MiB)');
      await budget.fill('');
      await node.getByRole('button', { name: 'Check' }).click();
      await expect(budget).toHaveJSProperty('validity.valueMissing', true);
      await expect(node.getByTestId('cache-settings-preview')).toHaveCount(0);
      await node.getByRole('button', { name: 'Cancel' }).click();
    } finally {
      await page.context().close();
    }
  });

  test('dns_006 viewer sees cache settings read-only', async ({ browser }) => {
    // The admin makes a viewer, then the viewer reads the card and can't change it.
    const admin = await signedIn(browser, ADMIN, 'cache');
    try {
      await cacheCard(admin);
      const csrf = (await (await admin.request.get('/api/v1/auth/status')).json()).csrfToken as string;
      const made = await admin.request.post('/api/v1/users', {
        headers: { 'x-csrf-token': csrf },
        data: { username: VIEWER.user, password: VIEWER.pass, role: 'viewer' },
      });
      expect([200, 201, 409]).toContain(made.status());
    } finally {
      await admin.context().close();
    }
    const page = await signedIn(browser, VIEWER, 'cache');
    try {
      const node = await cacheCard(page);
      await node.locator('summary', { hasText: 'Settings' }).click();
      await expect(node.getByTestId('cache-settings')).toContainText('Serve stale');
      await expect(node.getByTestId('cache-settings-edit')).toHaveCount(0);
      await expect(node.getByTestId('cache-settings-form')).toHaveCount(0);
    } finally {
      await page.context().close();
    }
  });
});

test.describe('settings from T27.11', () => {
  test('clu_014 drill schedule', async ({ browser }) => {
    // REQ: CLU-014 (T27.11) — the Cluster page's Drills tab: a monthly schedule on this node, checked then saved.
    const page = await signedIn(browser, ADMIN, 'cluster');
    try {
      const card = page.getByTestId('drill-schedule-card');
      await expect(card).toBeVisible({ timeout: 30_000 });
      await card.getByTestId('drill-schedule-edit').click();
      await card.getByLabel('Scheduled drills').selectOption('monthly');
      await card.getByLabel('Nodes that drill').fill('home-dns');
      await card.getByRole('button', { name: 'Check' }).click();
      await expect(card.getByTestId('drill-schedule-preview')).toBeVisible();
      await card.getByRole('button', { name: 'Apply' }).click();
      await expect(card.getByTestId('drill-schedule-values')).toContainText('once a month');
      await expect(card.getByTestId('drill-schedule-values')).toContainText('home-dns');
    } finally {
      await page.context().close();
    }
  });

  test('dns_906 the card lists the root trust anchors and a key in hold-down', async ({ browser }) => {
    // REQ: DNS-906 (T40.5) - every node's anchors with their RFC 5011 state; the answer is mocked (the
    // e2e server has validation off and no root to read).
    const day = 86_400;
    const now = Math.floor(Date.now() / 1000);
    // The mock goes in before the page loads and before the sign-in: a reload straight after the
    // sign-in click raced it and landed on the sign-in page.
    const mock = (p: Page) =>
      p.route('**/api/v1/dnssec/anchors', (r) =>
        r.fulfill({
          json: {
            items: [
              {
                node: 'pi-a',
                mode: 'following',
                lastReadingS: now - 3600,
                keys: [
                  { keyTag: 20326, algorithm: 8, flags: 257, state: 'valid' },
                  { keyTag: 38696, algorithm: 8, flags: 257, state: 'valid' },
                  { keyTag: 11111, algorithm: 8, flags: 257, state: 'add_pend', sinceS: now - 10 * day, trustedAtS: now + 20 * day },
                ],
              },
              { node: 'pi-b', mode: 'file', keys: [] },
              { node: 'pi-c', mode: 'unsupported', keys: [] },
            ],
          },
        }),
      );
    const page = await signedIn(browser, ADMIN, 'settings?tab=queries', mock);
    try {
      const card = page.getByTestId('dnssec-card');
      await expect(card).toBeVisible({ timeout: 30_000 });
      const nodes = card.getByTestId('anchors-node');
      await expect(nodes).toHaveCount(3);
      await expect(nodes.nth(0).getByTestId('anchor-key')).toHaveCount(3);
      const pending = nodes.nth(0).locator('[data-state="add_pend"]');
      await expect(pending).toContainText('11111');
      await expect(pending).toContainText('in hold-down');
      await expect(pending).toContainText('trusted from');
      await expect(nodes.nth(1)).toContainText('trust_anchors_file');
      await expect(nodes.nth(2)).toContainText('older build');
    } finally {
      await page.context().close();
    }
  });

  test('dns_011 add a negative trust anchor', async ({ browser }) => {
    // REQ: DNS-011 (T27.11) — DNSSEC on Settings → Query handling: a domain not validated, checked then saved.
    const page = await signedIn(browser, ADMIN, 'settings?tab=queries');
    try {
      const card = page.getByTestId('dnssec-card');
      await expect(card).toBeVisible({ timeout: 30_000 });
      await card.getByTestId('dnssec-edit').click();
      await card.getByLabel('Negative trust anchors').fill('lab.example');
      await card.getByRole('button', { name: 'Check' }).click();
      await expect(card.getByTestId('dnssec-preview')).toBeVisible();
      await card.getByRole('button', { name: 'Apply' }).click();
      await expect(card.getByTestId('dnssec-values')).toContainText('lab.example');
    } finally {
      await page.context().close();
    }
  });

  test('dns_011 change the DNSSEC validation mode', async ({ browser }) => {
    // REQ: DNS-011 (T27.11) — the validation mode is checked, applied, and then put back as it was.
    const page = await signedIn(browser, ADMIN, 'settings?tab=queries');
    try {
      const card = page.getByTestId('dnssec-card');
      await expect(card).toBeVisible({ timeout: 30_000 });
      await card.getByTestId('dnssec-edit').click();
      const validation = card.locator('select[aria-label="Validation"]');
      const original = await validation.inputValue();
      const next = original === 'permissive' ? 'validate' : 'permissive';
      await validation.selectOption(next);
      await card.getByRole('button', { name: 'Check' }).click();
      await expect(card.getByTestId('dnssec-preview')).toBeVisible();
      await card.getByRole('button', { name: 'Apply' }).click();
      await card.getByTestId('dnssec-edit').click();
      await expect(validation).toHaveValue(next);
      await validation.selectOption(original);
      await card.getByRole('button', { name: 'Check' }).click();
      await card.getByRole('button', { name: 'Apply' }).click();
      await expect(card.getByTestId('dnssec-edit')).toBeVisible();
    } finally {
      await page.context().close();
    }
  });

  test('flt_004 list stale age and refresh', async ({ browser }) => {
    // REQ: FLT-004 (T27.11) — the list settings on the Lists page: the stale age, checked then saved.
    // An unchanged refresh interval isn't sent, so a file's exact seconds are kept.
    const page = await signedIn(browser, ADMIN, 'lists');
    try {
      const card = page.getByTestId('filter-settings-card');
      await expect(card).toBeVisible({ timeout: 30_000 });
      await card.getByTestId('filter-settings-edit').click();
      await card.getByLabel('Flag a list as stale after (days)').fill('14');
      const check = page.waitForRequest((r) => r.url().includes('/filter-settings/default') && r.method() === 'PUT');
      await card.getByRole('button', { name: 'Check' }).click();
      expect((await check).postDataJSON()).not.toHaveProperty('refresh_secs');
      await expect(card.getByTestId('filter-settings-preview')).toBeVisible();
      await card.getByRole('button', { name: 'Apply' }).click();
      await expect(card.getByTestId('filter-settings-values')).toContainText('14 days');
    } finally {
      await page.context().close();
    }
  });

  test('flt_004 list size limit', async ({ browser }) => {
    // REQ: FLT-004 (T27.11) — a list's largest download is 1 KiB to 1 GiB: the server refuses a value
    // above it at Check, and a value inside the range previews and can be added and removed.
    const page = await signedIn(browser, ADMIN, 'lists');
    try {
      const lists = page.getByTestId('editor-list');
      await expect(lists).toBeVisible({ timeout: 30_000 });
      await lists.getByRole('button', { name: 'Add list' }).click();
      await page.getByRole('textbox', { name: 'Name', exact: true }).fill('size-limit-e2e');
      await page.getByRole('textbox', { name: 'Rules', exact: true }).fill('||size-limit.e2e.test^');
      await page.getByRole('textbox', { name: 'Largest download', exact: true }).fill('2GiB');
      await page.getByRole('button', { name: 'Check' }).click();
      await expect(page.getByRole('dialog', { name: 'Add list' }).getByRole('alert')).toContainText('1GiB');
      await expect(page.getByTestId('entry-preview')).toHaveCount(0);
      await page.getByRole('textbox', { name: 'Largest download', exact: true }).fill('512MiB');
      await page.getByRole('button', { name: 'Check' }).click();
      await expect(page.getByTestId('entry-preview')).toBeVisible();
      await page.getByRole('button', { name: 'Apply' }).click();
      const row = lists.getByTestId('entry-row').filter({ hasText: 'size-limit-e2e' });
      await expect(row).toContainText('added here');
      await row.getByRole('button', { name: 'Remove' }).click();
      await expect(row).toHaveCount(0);
    } finally {
      await page.context().close();
    }
  });

  test('api_007 backup with query history', async ({ browser }) => {
    // REQ: API-007 (T27.11) — the backup page's query-history choice is sent as includeQlog.
    const page = await signedIn(browser, ADMIN, 'settings?tab=system');
    try {
      await expect(page.getByTestId('backup-qlog')).toBeVisible({ timeout: 30_000 });
      await page.getByTestId('backup-qlog').check();
      await expect(page.getByTestId('backup-qlog')).toBeChecked();
      const request = page.waitForRequest((r) => r.url().includes('/api/v1/backup') && r.method() === 'POST');
      await page.getByTestId('backup-make').click();
      expect((await request).postDataJSON().includeQlog).toBe(true);
    } finally {
      await page.context().close();
    }
  });

  test('ops_011 keep support logs switch', async ({ browser }) => {
    // REQ: OPS-011 (T27.11) — Settings → System: the support-log switch, checked, saved, and pending a restart.
    const page = await signedIn(browser, ADMIN, 'settings?tab=system');
    try {
      const card = page.getByTestId('node-switches');
      await expect(card).toBeVisible({ timeout: 30_000 });
      await card.getByTestId('support-persist-logs').click();
      await expect(page.getByTestId('node-switches-preview')).toBeVisible();
      await page.getByTestId('node-switches-preview').getByRole('button', { name: 'Apply' }).click();
      await expect(card).toContainText('Saved. It takes effect when this node restarts.');
      await expect(card).toContainText('pending restart');
    } finally {
      await page.context().close();
    }
  });

  test('ops_012 update check switch', async ({ browser }) => {
    // REQ: OPS-012 (T27.11) — Settings → System: the update-check switch, checked and saved (an admin's).
    const page = await signedIn(browser, ADMIN, 'settings?tab=system');
    try {
      const card = page.getByTestId('node-switches');
      await expect(card).toBeVisible({ timeout: 30_000 });
      await card.getByTestId('updates-check').click();
      await expect(page.getByTestId('node-switches-preview')).toBeVisible();
      await page.getByTestId('node-switches-preview').getByRole('button', { name: 'Apply' }).click();
      await expect(card).toContainText('Saved. It takes effect when this node restarts.');
    } finally {
      await page.context().close();
    }
  });
});


// REQ: FLT-906 (T40.9, ADR-1110) - a list in the RPZ format is added on the Lists page: the form
// has a Format choice, the check reads the zone as a zone (a response-IP trigger is counted as not
// applied, not an error), the row says RPZ and how many records are not applied, and Explain names
// the record that decided.
test.describe('flt_906 rpz lists', () => {
  test('flt_906 an RPZ list is added on the Lists page', async ({ browser }) => {
    test.setTimeout(120_000);
    const page = await signedIn(browser, ADMIN, 'lists');
    try {
      const lists = page.getByTestId('editor-list');
      await expect(lists).toBeVisible({ timeout: 30_000 });
      await lists.getByRole('button', { name: 'Add list' }).click();
      await page.getByRole('textbox', { name: 'Name', exact: true }).fill('rpz-e2e');
      await page.getByRole('textbox', { name: 'Rules', exact: true }).fill(
        [
          'bad.rpz-e2e.test CNAME .',
          '*.sub.rpz-e2e.test CNAME *.',
          'ok.rpz-e2e.test CNAME rpz-passthru.',
          '32.1.2.0.192.rpz-ip CNAME .',
        ].join('\n'),
      );
      // The format choice, with its help; the form checks the zone as a zone.
      await expect(page.getByRole('combobox', { name: 'Format', exact: true })).toHaveValue('auto');
      await page.getByRole('combobox', { name: 'Format', exact: true }).selectOption('rpz');
      await page.getByRole('button', { name: 'Test it' }).click();
      await expect(page.getByTestId('form-action-result')).toContainText('Works: 3 rules from 4 lines (0 invalid, 1 unsupported)');
      await page.getByRole('button', { name: 'Check' }).click();
      await expect(page.getByTestId('entry-preview')).toBeVisible();
      await page.getByRole('button', { name: 'Apply' }).click();
      const row = lists.getByTestId('entry-row').filter({ hasText: 'rpz-e2e' });
      await expect(row).toContainText('added here');

      // The table marks the list and counts what is not applied (after the compile).
      await expect(async () => {
        await page.reload();
        const listRow = page.locator('tr').filter({ hasText: 'rpz-e2e' });
        await expect(listRow.getByTestId('list-format-rpz')).toBeVisible({ timeout: 3000 });
        await expect(listRow.getByTestId('list-unsupported')).toContainText('1 record not applied', { timeout: 3000 });
      }).toPass({ timeout: 60_000 });
      const items = (await (await page.request.get('/api/v1/lists')).json()).items as { name: string; format: string; unsupported: number }[];
      const item = items.find((l) => l.name === 'rpz-e2e')!;
      expect([item.format, item.unsupported]).toEqual(['rpz', 1]);

      // Explain names the list and the record; the passthru name is not rewritten.
      await expect
        .poll(async () => JSON.stringify(await (await page.request.get('/api/v1/explain?name=bad.rpz-e2e.test&client=127.0.0.1')).json()), {
          timeout: 40_000,
        })
        .toContain('bad.rpz-e2e.test CNAME .');
      const ex = await (await page.request.get('/api/v1/explain?name=bad.rpz-e2e.test&client=127.0.0.1')).json();
      expect(ex.summary).toContain('NXDOMAIN');
      const pass = await (await page.request.get('/api/v1/explain?name=ok.rpz-e2e.test&client=127.0.0.1')).json();
      expect(pass.summary).not.toContain('NXDOMAIN');

      await row.getByRole('button', { name: 'Remove' }).click();
      await expect(row).toHaveCount(0);
    } finally {
      await page.context().close();
    }
  });
});
