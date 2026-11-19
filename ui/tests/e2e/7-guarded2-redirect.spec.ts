// REQ: API-003, API-902 (T24.44, ADR-1053) — Settings -> System: the HTTP to HTTPS redirect field
// ([api] http_redirect) under the guarded-change flow: the dry run (what it opens, the port warning,
// the refusals), the typed phrase, the staged "pending restart" outcome, and the help topic. The e2e
// server has no [api] tls, which a real node requires: the end-to-end build only warns about it.
// A separate file, after 7-guarded.spec.ts, so its staged entry doesn't change that file's counts.
import { expect, test, type Browser, type Page } from '@playwright/test';

test.describe.configure({ mode: 'serial' });

const ADMIN = { user: 'admin', pass: 'correct horse battery' };
const NODE = 'home-dns';

async function adminPage(browser: Browser): Promise<Page> {
  const page = await browser.newPage();
  await page.goto('/#/settings?tab=system');
  await page.getByLabel('Username', { exact: true }).fill(ADMIN.user);
  await page.getByLabel('Password', { exact: true }).fill(ADMIN.pass);
  await page.getByRole('button', { name: 'Sign in' }).click();
  await expect(page.getByTestId('guarded-card')).toBeVisible({ timeout: 30_000 });
  return page;
}

test.describe('api_003 http redirect setting', () => {
  test('api_003 http redirect dry run', async ({ browser }) => {
    const page = await adminPage(browser);
    try {
      const box = page.getByTestId('guarded-http-redirect');
      await expect(box).toBeVisible();
      // The help topic opens from the field.
      await box.getByRole('button', { name: 'Help: Send port 80 to HTTPS' }).click();
      await expect(page.getByTestId('help-panel')).toContainText('plain-HTTP listener');
      await page.keyboard.press('Escape');
      await expect(page.getByTestId('help-panel')).toHaveCount(0);
      // A good address: what it opens, the port warning, and that nothing is applied yet.
      await box.getByLabel('HTTP redirect address').fill('0.0.0.0:80');
      await box.getByTestId('guarded-start-api-http-redirect').click();
      await expect(box.getByTestId('guarded-effect')).toContainText('0.0.0.0:80');
      await expect(box.getByTestId('guarded-effect')).toContainText('308');
      await expect(box.getByTestId('guarded-preview')).toContainText('CAP_NET_BIND_SERVICE');
      await expect(box.getByTestId('guarded-phrase')).toHaveText(`${NODE} api-http-redirect`);
      await expect(box.getByTestId('guarded-apply')).toBeDisabled();
      await box.getByTestId('guarded-back').click();
      // A bad address is refused by the server's dry run.
      await box.getByLabel('HTTP redirect address').fill('not-an-address');
      await box.getByTestId('guarded-start-api-http-redirect').click();
      await expect(box.getByRole('alert')).toContainText('0.0.0.0:80');
      await expect(box.getByTestId('guarded-preview')).toHaveCount(0);
      // Empty is off.
      await box.getByLabel('HTTP redirect address').fill('');
      await box.getByTestId('guarded-start-api-http-redirect').click();
      await expect(box.getByTestId('guarded-effect')).toContainText('off');
      await box.getByTestId('guarded-back').click();
    } finally {
      await page.close();
    }
  });

  test('api_003 http redirect guarded flow', async ({ browser }) => {
    const page = await adminPage(browser);
    try {
      const box = page.getByTestId('guarded-http-redirect');
      await box.getByLabel('HTTP redirect address').fill('0.0.0.0:8080');
      await box.getByTestId('guarded-start-api-http-redirect').click();
      await expect(box.getByTestId('guarded-preview')).toBeVisible();
      const phrase = (await box.getByTestId('guarded-phrase').innerText()).trim();
      await box.getByTestId('guarded-phrase-input').fill(phrase);
      await box.getByTestId('guarded-apply').click();
      // It is staged: it takes effect at the next start, and the card says so.
      await expect(box.getByTestId('guarded-pending-restart')).toBeVisible();
      await expect(page.getByTestId('guarded-restart-item')).toContainText('api-http-redirect');
      await expect(page.getByTestId('guarded-list')).toContainText('HTTP to HTTPS redirect');
      // The audit log has it, and the status listing carries no value.
      const audit = await page.request.get('/api/v1/audit?action=settings.guarded&limit=20');
      expect(JSON.stringify(await audit.json())).toContain('api-http-redirect');
      const listing = JSON.stringify(await (await page.request.get('/api/v1/guarded')).json());
      expect(listing).not.toContain('8080');
      // The simulated restart applies it, as for the other staged settings.
      const restart = page.getByTestId('guarded-restart-now');
      await restart.getByTestId('guarded-start-restart-now').click();
      await restart.getByTestId('guarded-phrase-input').fill(`${NODE} restart`);
      await restart.getByTestId('guarded-apply').click();
      await expect(restart.getByTestId('guarded-result')).toContainText('is back', { timeout: 30_000 });
      await expect(page.getByTestId('guarded-outcomes')).toContainText('api-http-redirect: applied');
      await restart.getByTestId('guarded-again').click();
    } finally {
      await page.close();
    }
  });
});
