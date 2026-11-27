// SPDX-License-Identifier: AGPL-3.0-or-later
// REQ: API-902, API-901 (T27.14f; ADR-914, ADR-956, ADR-977 point 7 as amended 2026-11-27) — Settings -> System ->
// Web UI and API: the trusted proxies as a guarded `window` setting. The review marks an added proxy as weakening and
// says what the server sees the admin as; the apply asks for a recent sign-in; the confirm happens on the same page
// (no new address) and shows the address the server now sees; the list is live at once; a change that only removes
// an entry is not weakening, and a direct admin (whose address is in neither list) can confirm it. Operators never see
// the card or the `api` block. A separate file, after 7-guarded2-redirect.spec.ts, which needs the admin 1-ui.spec.ts
// creates. A third admin makes the requests, so the guarded limiter of the other files' admins is not shared.
import { expect, test, type Browser, type Page } from '@playwright/test';

test.describe.configure({ mode: 'serial' });

const FIRST = { user: 'admin', pass: 'correct horse battery' };
const THIRD = { user: 'guarded-ad3', pass: 'third admin long password' };
const OPERATOR = { user: 'proxies-op', pass: 'operator long password' };
const NODE = 'home-dns';
const PROXY = '192.0.2.7';

async function signedIn(browser: Browser, who: { user: string; pass: string }): Promise<Page> {
  const page = await browser.newPage();
  await page.goto('/#/settings?tab=system');
  await page.getByLabel('Username', { exact: true }).fill(who.user);
  await page.getByLabel('Password', { exact: true }).fill(who.pass);
  await page.getByRole('button', { name: 'Sign in' }).click();
  return page;
}

const csrfOf = async (page: Page) => (await (await page.request.get('/api/v1/auth/status')).json()).csrfToken as string;

async function makeUsers(browser: Browser) {
  const first = await signedIn(browser, FIRST);
  try {
    await expect(first.getByTestId('guarded-card')).toBeVisible({ timeout: 30_000 });
    for (const [u, role] of [[THIRD, 'admin'], [OPERATOR, 'operator']] as const) {
      const made = await first.request.post('/api/v1/users', {
        headers: { 'x-csrf-token': await csrfOf(first) },
        data: { username: u.user, password: u.pass, role },
      });
      expect([200, 201, 409]).toContain(made.status());
    }
  } finally {
    await first.close();
  }
}

async function adminPage(browser: Browser): Promise<Page> {
  const page = await signedIn(browser, THIRD);
  await expect(page.getByTestId('web-api-card')).toBeVisible({ timeout: 30_000 });
  await expect(page.getByTestId('trusted-proxies')).toBeVisible();
  return page;
}

const infoApi = (page: Page) =>
  page.evaluate(async () => ((await (await fetch('/api/v1/system/info')).json()) as { api?: { trustedProxies: string[] } }).api);

test.describe('api_902 trusted proxies', () => {
  test('api_902 trusted proxy users are made', async ({ browser }) => {
    await makeUsers(browser);
  });

  test('api_902 trusted proxy add asks for sign-in', async ({ browser }) => {
    test.setTimeout(180_000);
    const page = await adminPage(browser);
    try {
      const box = page.getByTestId('trusted-proxies');
      // Nothing is in force, and the help topic opens from the section.
      await expect(box.getByTestId('trusted-proxies-row')).toHaveCount(0);
      await box.getByRole('button', { name: 'Help: Trusted proxies' }).click();
      await expect(page.getByTestId('help-panel')).toContainText('X-Forwarded-For');
      await page.keyboard.press('Escape');
      await expect(page.getByTestId('help-panel')).toHaveCount(0);
      // A wrong entry is caught here, before the server sees it.
      await box.getByTestId('trusted-proxies-input').fill('not-an-address');
      await expect(box.getByTestId('trusted-proxies-bad')).toBeVisible();
      await expect(box.getByTestId('trusted-proxies-add')).toBeDisabled();
      await box.getByTestId('trusted-proxies-input').fill('10.0.0.0/33');
      await expect(box.getByTestId('trusted-proxies-add')).toBeDisabled();
      await box.getByTestId('trusted-proxies-input').fill(PROXY);
      await box.getByTestId('trusted-proxies-add').click();
      await expect(box.getByTestId('trusted-proxies-row')).toHaveText(new RegExp(PROXY));
      // The review: weakening, what the server sees today, the phrase; nothing applied yet.
      await box.getByTestId('guarded-start-trusted-proxies').click();
      await expect(box.getByTestId('guarded-preview')).toBeVisible();
      await expect(box.getByTestId('guarded-weakens')).toBeVisible();
      await expect(box.getByTestId('guarded-seen')).toContainText('127.0.0.1');
      await expect(box.getByTestId('guarded-phrase')).toHaveText(`${NODE} trusted-proxies`);
      await expect(box.getByTestId('guarded-apply')).toBeDisabled();
      expect((await infoApi(page))?.trustedProxies).toEqual([]);
      // The first apply is refused as the server refuses a stale sign-in; the retry is real.
      let refused = false;
      await page.route('**/api/v1/guarded/trusted-proxies', async (route) => {
        if (route.request().method() === 'POST' && !refused) {
          refused = true;
          await route.fulfill({
            status: 403,
            contentType: 'application/problem+json',
            body: JSON.stringify({
              type: 'https://wrendns.com/problems/reauth_required',
              title: 'Recent sign-in needed',
              status: 403,
              code: 'reauth_required',
              detail: 'this change weakens security: it needs a sign-in within the last 10 minutes',
            }),
          });
        } else {
          await route.continue();
        }
      });
      await box.getByTestId('guarded-phrase-input').fill(`${NODE} trusted-proxies`);
      await box.getByTestId('guarded-apply').click();
      await expect(box.getByTestId('guarded-reauth')).toBeVisible();
      await box.getByTestId('guarded-reauth-password').fill(THIRD.pass);
      await box.getByTestId('guarded-reauth-go').click();
      // Pending: no new address to open, so the admin confirms here; the list is not in force yet.
      await expect(box.getByTestId('guarded-pending')).toBeVisible({ timeout: 30_000 });
      await expect(box.getByTestId('guarded-confirm-link')).toHaveCount(0);
      expect((await infoApi(page))?.trustedProxies).toEqual([]);
      await box.getByTestId('guarded-confirm-here').click();
      await expect(box.getByTestId('guarded-result')).toContainText('now sees this request as coming from 127.0.0.1', { timeout: 30_000 });
      // The list is live at once, with no restart, and the card shows it.
      await expect.poll(async () => (await infoApi(page))?.trustedProxies).toEqual([`${PROXY}/32`]);
      await box.getByTestId('guarded-again').click();
      await expect(box.getByTestId('trusted-proxies-row')).toHaveText(new RegExp(PROXY));
      const audit = JSON.stringify(await (await page.request.get('/api/v1/audit?action=settings.guarded&limit=20')).json());
      expect(audit).toContain('trusted-proxies');
      expect(audit).toContain('weakening');
    } finally {
      await page.close();
    }
  });

  test('api_902 trusted proxy removal confirms from a direct request', async ({ browser }) => {
    test.setTimeout(180_000);
    const page = await adminPage(browser);
    try {
      const box = page.getByTestId('trusted-proxies');
      await expect(box.getByTestId('trusted-proxies-row')).toHaveText(new RegExp(PROXY));
      await box.getByTestId('trusted-proxies-remove').click();
      await box.getByTestId('guarded-start-trusted-proxies').click();
      await expect(box.getByTestId('guarded-preview')).toBeVisible();
      // Taking an entry out is not weakening.
      await expect(box.getByTestId('guarded-weakens')).toHaveCount(0);
      await box.getByTestId('guarded-phrase-input').fill(`${NODE} trusted-proxies`);
      await box.getByTestId('guarded-apply').click();
      await expect(box.getByTestId('guarded-pending')).toBeVisible({ timeout: 30_000 });
      // This request reached the node directly (its address is in neither list), so it confirms the removal.
      await box.getByTestId('guarded-confirm-here').click();
      await expect(box.getByTestId('guarded-result')).toContainText('now sees this request as coming from 127.0.0.1', { timeout: 30_000 });
      await expect.poll(async () => (await infoApi(page))?.trustedProxies).toEqual([]);
      await box.getByTestId('guarded-again').click();
      await expect(box.getByTestId('trusted-proxies-row')).toHaveCount(0);
    } finally {
      await page.close();
    }
  });

  // REQ: API-902 (T27.14f review fix) - a file that lists the same proxy twice gives the card a list with a
  // repeated entry; it still renders, one row for each entry.
  test('api_902 trusted proxy list with a repeated file entry renders', async ({ browser }) => {
    const page = await adminPage(browser);
    try {
      await page.route('**/api/v1/system/info', async (route) => {
        const res = await route.fetch();
        const body = await res.json();
        body.api = { ...(body.api ?? {}), trustedProxies: ['10.0.0.0/8', '10.0.0.0/8'] };
        await route.fulfill({ response: res, json: body });
      });
      await page.reload();
      const box = page.getByTestId('trusted-proxies');
      await expect(box.getByTestId('trusted-proxies-row')).toHaveCount(2, { timeout: 30_000 });
    } finally {
      await page.close();
    }
  });

  test('api_902 trusted proxy list is an admin only', async ({ browser }) => {
    const page = await signedIn(browser, OPERATOR);
    try {
      await expect(page.getByRole('heading', { name: 'System' }).first()).toBeVisible({ timeout: 30_000 });
      await expect(page.getByTestId('web-api-card')).toHaveCount(0);
      expect(await infoApi(page)).toBeUndefined();
    } finally {
      await page.close();
    }
  });
});
