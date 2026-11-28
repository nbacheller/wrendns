// SPDX-License-Identifier: AGPL-3.0-or-later
// REQ: CLD-904, DSC-908 (T36.10b steps 1 and 2; ADR-1084, ADR-1104) — Settings → DNS providers: the
// table stored and checked through the UI, the credential only ever a stored secret's name, the
// gate's refusal in the form's words, a viewer without the tab and a file-defined provider read-only.
// Runs against the suite's own server (after 1-ui.spec.ts, which creates the admin and the viewer): the
// e2e build serves an entry named fake-... with an in-memory provider (CLD-919, T36.10b step b3), so the
// Test, Records and Adopt controls run end to end with nothing reachable.
import { expect, test, type Browser, type Page } from '@playwright/test';

const ADMIN = { user: 'admin', pass: 'correct horse battery' };
const VIEWER = { user: 'viewer1', pass: 'another long password' };
const SECRET = 'dns-e2e-credential-7731';

// The secrets the tests store through the credential field (named dns.<provider>.credential). The
// server is shared with the other spec files, so each test deletes what it stored when it ends.
async function dropSecret(page: Page, name: string): Promise<void> {
  const status = await page.request.get('/api/v1/auth/status');
  const csrf = (await status.json()).csrfToken as string;
  const res = await page.request.delete(`/api/v1/secrets/${name}`, { headers: { 'x-csrf-token': csrf } });
  expect([200, 204, 404]).toContain(res.status());
}

async function signIn(browser: Browser, user: { user: string; pass: string }, wait = 'dnsproviders-tab'): Promise<Page> {
  const page = await browser.newPage();
  await page.goto('/#/settings?tab=dns-providers');
  await page.getByLabel('Username', { exact: true }).fill(user.user);
  await page.getByLabel('Password', { exact: true }).fill(user.pass);
  await page.getByRole('button', { name: 'Sign in' }).click();
  if (wait) await expect(page.getByTestId(wait)).toBeVisible({ timeout: 30_000 });
  return page;
}

test.describe('cld_904 DNS providers in the UI', () => {
  test.describe.configure({ mode: 'serial' });

  test('cld_904 an admin adds a provider and the secret is never shown again', async ({ browser }) => {
    const page = await signIn(browser, ADMIN);
    try {
      await expect(page.getByTestId('dnsproviders-intro')).toContainText('starts in dry run');
      await page.getByTestId('dnsproviders-add').click();
      await page.getByRole('textbox', { name: 'Name', exact: true }).fill('cf-e2e');
      await page.getByRole('textbox', { name: 'Zone', exact: true }).fill('example.net');
      // The scope instructions come before the secret field.
      await expect(page.getByTestId('dnsproviders-scope')).toContainText('Zone, DNS, Edit');
      await page.getByRole('combobox', { name: 'Kind', exact: true }).selectOption('azure_dns');
      await expect(page.getByTestId('dnsproviders-scope')).toContainText('az role assignment create');
      await page.getByRole('combobox', { name: 'Kind', exact: true }).selectOption('route53');
      await expect(page.getByTestId('dnsproviders-scope')).toContainText('route53:ChangeResourceRecordSets');
      await page.getByRole('combobox', { name: 'Kind', exact: true }).selectOption('rfc2136');
      await expect(page.getByTestId('dnsproviders-scope')).toContainText('update-policy');
      await page.getByRole('combobox', { name: 'Kind', exact: true }).selectOption('cloudflare');
      // The credential goes through SecretField: typed once, stored by name, never shown again.
      const secret = page.getByTestId('dnsproviders-secret');
      await secret.getByLabel('Credential', { exact: true }).fill(SECRET);
      await secret.getByRole('button', { name: 'Save secret' }).click();
      await expect(secret).toHaveAttribute('data-mode', 'set', { timeout: 10_000 });
      await expect(page.locator('body')).not.toContainText(SECRET);
      await expect(secret.getByRole('textbox')).toHaveCount(0);
      await page.getByTestId('dnsproviders-save').click();
      const card = page.getByTestId('dnsproviders-card').filter({ hasText: 'cf-e2e' });
      await expect(card).toBeVisible({ timeout: 10_000 });
      await expect(card).toContainText('From the UI');
      await expect(card).toContainText('Not used yet');
      await expect(card).toContainText('Dry run');
      await expect(card).toContainText('dns.cf-e2e.credential');
      await expect(page.getByTestId('dnsproviders-notice')).toContainText('starts in dry run');
      // The server stored a reference: the answer names the secret and never carries a value.
      const list = await page.request.get('/api/v1/dns-providers');
      expect(list.status()).toBe(200);
      const text = await list.text();
      expect(text).toContain('dns.cf-e2e.credential');
      expect(text).not.toContain(SECRET);
      // Reload: still there, still no value anywhere on the page.
      await page.reload();
      await expect(page.getByTestId('dnsproviders-card').filter({ hasText: 'cf-e2e' })).toBeVisible({ timeout: 10_000 });
      await expect(page.locator('body')).not.toContainText(SECRET);
      // Remove it; the secret it named is deleted in the finally below.
      await page.getByTestId('dnsproviders-card').filter({ hasText: 'cf-e2e' }).getByTestId('dnsproviders-delete').click();
      await page.getByTestId('dnsproviders-delete-confirm').click();
      await expect(page.getByTestId('dnsproviders-card').filter({ hasText: 'cf-e2e' })).toHaveCount(0, { timeout: 10_000 });
    } finally {
      await dropSecret(page, 'dns.cf-e2e.credential');
      await page.close();
    }
  });

  test('cld_904 test shows the scope and never the secret', async ({ browser }) => {
    const page = await signIn(browser, ADMIN);
    try {
      // The suite's server is the e2e build: an entry named fake-... is served by the in-memory test
      // provider, which holds one record set nobody owns (legacy.example.net).
      await page.getByTestId('dnsproviders-add').click();
      await page.getByRole('textbox', { name: 'Name', exact: true }).fill('fake-e2e');
      await page.getByRole('textbox', { name: 'Zone', exact: true }).fill('example.net');
      const secret = page.getByTestId('dnsproviders-secret');
      await secret.getByLabel('Credential', { exact: true }).fill(SECRET);
      await secret.getByRole('button', { name: 'Save secret' }).click();
      await expect(secret).toHaveAttribute('data-mode', 'set', { timeout: 10_000 });
      await page.getByTestId('dnsproviders-save').click();
      const card = page.getByTestId('dnsproviders-card').filter({ hasText: 'fake-e2e' });
      await expect(card).toBeVisible({ timeout: 10_000 });
      // A new entry is in dry run, and the card says so.
      await expect(card.getByTestId('dnsproviders-dry')).toBeVisible();
      await expect(card.getByTestId('dnsproviders-detail')).toContainText('until the first successful test');
      await card.getByTestId('dnsproviders-test').click();
      const result = card.getByTestId('dnsproviders-test-result');
      await expect(result).toContainText('The credential was accepted', { timeout: 10_000 });
      await expect(result).toContainText('Record types it may write');
      await expect(card.getByTestId('dnsproviders-broad')).toContainText('can change more than WrenDNS needs');
      // The first success ended dry run.
      await expect(card.getByTestId('dnsproviders-dry-ended')).toBeVisible();
      await expect(card.getByTestId('dnsproviders-dry')).toHaveCount(0, { timeout: 15_000 });
      await expect(card.getByTestId('dnsproviders-state')).toContainText('Ready');
      // The record sets with who owns each; the one nobody owns can be adopted.
      await card.getByTestId('dnsproviders-records').click();
      const row = card.getByTestId('dnsproviders-record').filter({ hasText: 'legacy.example.net' });
      await expect(row).toContainText('Not owned');
      await row.getByTestId('dnsproviders-adopt').click();
      await expect(card.getByTestId('dnsproviders-record').filter({ hasText: 'legacy.example.net' })).toContainText('Adopted by', { timeout: 10_000 });
      await expect(card.getByTestId('dnsproviders-adopt')).toHaveCount(0);
      // The secret is on no page and in no answer.
      await expect(page.locator('body')).not.toContainText(SECRET);
      for (const url of ['/api/v1/dns-providers', '/api/v1/dns-providers/fake-e2e/records']) {
        const res = await page.request.get(url);
        expect(res.status()).toBe(200);
        expect(await res.text()).not.toContain(SECRET);
      }
      const audit = await page.request.get('/api/v1/audit?limit=200');
      expect(await audit.text()).not.toContain(SECRET);
      // Remove it.
      await card.getByTestId('dnsproviders-delete').click();
      await page.getByTestId('dnsproviders-delete-confirm').click();
      await expect(page.getByTestId('dnsproviders-card').filter({ hasText: 'fake-e2e' })).toHaveCount(0, { timeout: 10_000 });
    } finally {
      await dropSecret(page, 'dns.fake-e2e.credential');
      await page.close();
    }
  });

  test('cld_904 a kind with no provider code yet says so when tested', async ({ browser }) => {
    const page = await signIn(browser, ADMIN);
    try {
      await page.getByTestId('dnsproviders-add').click();
      await page.getByRole('textbox', { name: 'Name', exact: true }).fill('cf-nocode');
      await page.getByRole('textbox', { name: 'Zone', exact: true }).fill('example.net');
      const secret = page.getByTestId('dnsproviders-secret');
      await secret.getByLabel('Credential', { exact: true }).fill(SECRET);
      await secret.getByRole('button', { name: 'Save secret' }).click();
      await expect(secret).toHaveAttribute('data-mode', 'set', { timeout: 10_000 });
      await page.getByTestId('dnsproviders-save').click();
      const card = page.getByTestId('dnsproviders-card').filter({ hasText: 'cf-nocode' });
      await expect(card).toBeVisible({ timeout: 10_000 });
      await card.getByTestId('dnsproviders-test').click();
      await expect(card.getByTestId('dnsproviders-test-error')).toContainText('no provider code for the `cloudflare` kind yet', { timeout: 10_000 });
      await expect(card.getByTestId('dnsproviders-dry')).toBeVisible();
      await expect(page.locator('body')).not.toContainText(SECRET);
      await card.getByTestId('dnsproviders-delete').click();
      await page.getByTestId('dnsproviders-delete-confirm').click();
      await expect(page.getByTestId('dnsproviders-card').filter({ hasText: 'cf-nocode' })).toHaveCount(0, { timeout: 10_000 });
    } finally {
      await dropSecret(page, 'dns.cf-nocode.credential');
      await page.close();
    }
  });

  test('cld_904 a provider held back by the gate says which node to upgrade', async ({ browser }) => {
    const page = await signIn(browser, ADMIN);
    try {
      // A cluster with a member that does not know the table: the write answers 409 upgrade_required.
      await page.route('**/api/v1/dns-providers/gated-e2e', (route) =>
        route.request().method() === 'PUT'
          ? route.fulfill({
              status: 409,
              contentType: 'application/problem+json',
              json: {
                type: 'about:blank',
                title: 'Conflict',
                status: 409,
                code: 'upgrade_required',
                detail: 'node pi-b runs version 1.0.0, which does not know DNS providers; upgrade it first',
              },
            })
          : route.continue(),
      );
      await page.getByTestId('dnsproviders-add').click();
      await page.getByRole('textbox', { name: 'Name', exact: true }).fill('gated-e2e');
      await page.getByRole('textbox', { name: 'Zone', exact: true }).fill('example.net');
      const secret = page.getByTestId('dnsproviders-secret');
      await secret.getByLabel('Credential', { exact: true }).fill(SECRET);
      await secret.getByRole('button', { name: 'Save secret' }).click();
      await expect(secret).toHaveAttribute('data-mode', 'set', { timeout: 10_000 });
      await page.getByTestId('dnsproviders-save').click();
      await expect(page.getByTestId('dnsproviders-form-error')).toContainText('node pi-b runs version 1.0.0', { timeout: 10_000 });
      await expect(page.getByTestId('dnsproviders-form-error')).toContainText('does not know DNS providers');
      await expect(page.getByTestId('dnsproviders-card').filter({ hasText: 'gated-e2e' })).toHaveCount(0);
      // The node holding providers out since start-up says so on the page.
      await page.route('**/api/v1/dns-providers', (route) =>
        route.request().method() === 'GET'
          ? route.fulfill({
              json: {
                held: true,
                heldReason: 'node pi-b runs version 1.0.0, which does not know DNS providers; upgrade it first',
                items: [
                  {
                    name: 'from-file', kind: 'cloudflare', zone: 'example.net', source: 'file', definition: { name: 'from-file', kind: 'cloudflare', zone: 'example.net', credential_ref: 'cf', dry_run: true },
                    dryRun: true, credentialSecret: 'cf', credentialPresent: true, state: 'not_used', detail: '', held: true,
                  },
                ],
              },
            })
          : route.continue(),
      );
      await page.reload();
      await expect(page.getByTestId('dnsproviders-held')).toContainText('node pi-b runs version 1.0.0', { timeout: 15_000 });
      // A provider the file defines is read-only: no change or remove control.
      const card = page.getByTestId('dnsproviders-card').filter({ hasText: 'from-file' });
      await expect(card.getByTestId('dnsproviders-file')).toBeVisible();
      await expect(card.getByTestId('dnsproviders-card-held')).toBeVisible();
      await expect(card.getByTestId('dnsproviders-edit')).toHaveCount(0);
      await expect(card.getByTestId('dnsproviders-delete')).toHaveCount(0);
      await page.unroute('**/api/v1/dns-providers');
      await page.unroute('**/api/v1/dns-providers/gated-e2e');
    } finally {
      await dropSecret(page, 'dns.gated-e2e.credential');
      await page.close();
    }
  });

  test('cld_904 a viewer sees no DNS providers tab and the API refuses a write', async ({ browser }) => {
    const page = await signIn(browser, VIEWER, '');
    try {
      // Signed in: the sign-in form is gone.
      await expect(page.getByLabel('Username', { exact: true })).toHaveCount(0, { timeout: 30_000 });
      await expect(page.getByTestId('dnsproviders-tab')).toHaveCount(0);
      await expect(page.getByRole('tab', { name: 'DNS providers' })).toHaveCount(0);
      // With a valid CSRF token the refusal is the role's: exactly 403, not a sign-in or token error.
      const csrf = ((await (await page.request.get('/api/v1/auth/status')).json()).csrfToken as string) ?? '';
      expect(csrf).not.toBe('');
      const put = await page.request.put('/api/v1/dns-providers/x', {
        headers: { 'x-csrf-token': csrf },
        data: { kind: 'cloudflare', zone: 'example.net', credential_ref: 'cf' },
      });
      expect(put.status()).toBe(403);
    } finally {
      await page.close();
    }
  });
});
