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
async function signedIn(browser: Browser, who: { user: string; pass: string }, hash: string): Promise<Page> {
  const page = await browser.newPage();
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
      const node = await cacheCard(page);
      // The change made by the test before shows until the node restarts: the badge is on the card
      // and the form says every field applies at start.
      await expect(node.getByTestId('cache-pending-restart')).toHaveText('pending restart');
      await node.locator('summary', { hasText: 'Settings' }).click();
      await node.getByTestId('cache-settings-edit').click();
      await expect(node.getByTestId('cache-settings-form')).toContainText('applies when this node restarts');
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

  test('flt_004 list size limit', async ({ browser }) => {
    // REQ: FLT-004 (T27.11) — the list settings on the Lists page: the stale age, checked then saved.
    const page = await signedIn(browser, ADMIN, 'lists');
    try {
      const card = page.getByTestId('filter-settings-card');
      await expect(card).toBeVisible({ timeout: 30_000 });
      await card.getByTestId('filter-settings-edit').click();
      await card.getByLabel('Flag a list as stale after (days)').fill('14');
      await card.getByRole('button', { name: 'Check' }).click();
      await expect(card.getByTestId('filter-settings-preview')).toBeVisible();
      await card.getByRole('button', { name: 'Apply' }).click();
      await expect(card.getByTestId('filter-settings-values')).toContainText('14 days');
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
