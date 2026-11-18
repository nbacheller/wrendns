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
