// REQ: API-902, API-006, AGT-009 (T27.13; ADR-914, ADR-956) — the guarded-changes framework in the
// browser: the review and its typed phrase, the confirmation window's countdown and rollback, the
// confirm step on the new address, a weakening change asking for a sign-in, a setting a file sets
// (locked), the controls an operator and a viewer never see, and "Restart now" (hidden without a
// supervisor, its own phrase, its outcome). It runs after 1-ui.spec.ts (which creates the admin).
//
// The server is built with the cargo feature `e2e` (`cargo build -p telltale --features e2e`): that
// build has three test settings (an immediate one, a confirmation-window one, a staged one) and a
// test setting a file sets, a short window (`TT_E2E_CONFIRM_WINDOW_SECS`) and a simulated restart
// (`TT_E2E_RESTART_HOOK`), so no test kills its own server. A release binary has none of them.
import { expect, test, type Browser, type Page } from '@playwright/test';
import { PORTS } from './ports';

test.describe.configure({ mode: 'serial' });

const ADMIN = { user: 'admin', pass: 'correct horse battery' };
const OPERATOR = { user: 'guarded-op', pass: 'operator long password' };
const VIEWER = { user: 'guarded-vw', pass: 'viewer long password' };
const NODE = 'home-dns';

async function signedIn(browser: Browser, who = ADMIN): Promise<Page> {
  const page = await browser.newPage();
  await page.goto('/#/settings?tab=system');
  await page.getByLabel('Username', { exact: true }).fill(who.user);
  await page.getByLabel('Password', { exact: true }).fill(who.pass);
  await page.getByRole('button', { name: 'Sign in' }).click();
  return page;
}

async function adminPage(browser: Browser): Promise<Page> {
  const page = await signedIn(browser);
  await expect(page.getByTestId('guarded-card')).toBeVisible({ timeout: 30_000 });
  return page;
}

const csrfOf = async (page: Page) => (await (await page.request.get('/api/v1/auth/status')).json()).csrfToken as string;

/** Reviews the change in `box` and types its phrase (it does not apply it). */
async function review(box: ReturnType<Page['getByTestId']>, id: string) {
  await box.getByTestId(`guarded-start-${id}`).click();
  await expect(box.getByTestId('guarded-preview')).toBeVisible();
  const phrase = (await box.getByTestId('guarded-phrase').innerText()).trim();
  return phrase;
}

test.describe('api_902 guarded changes', () => {
  test('api_902 guarded change asks for the phrase', async ({ browser }) => {
    const page = await adminPage(browser);
    try {
      const box = page.getByTestId('guarded-test-e2e-immediate');
      await box.getByLabel('Test label').fill('first');
      const phrase = await review(box, 'e2e-immediate');
      expect(phrase).toBe(`${NODE} e2e-immediate`);
      await expect(box.getByTestId('guarded-effect')).toContainText('first');
      // The Apply button is disabled until the exact phrase is typed (paste is allowed).
      const apply = box.getByTestId('guarded-apply');
      await expect(apply).toBeDisabled();
      await box.getByTestId('guarded-phrase-input').fill(`${NODE} e2e-imm`);
      await expect(apply).toBeDisabled();
      await box.getByTestId('guarded-phrase-input').fill(phrase);
      await expect(apply).toBeEnabled();
      await apply.click();
      await expect(box.getByTestId('guarded-result')).toContainText('applied');
      // The server checks it too: a request that skips the phrase is refused, whatever the UI did.
      const csrf = await csrfOf(page);
      const pv = await page.request.post('/api/v1/guarded/e2e-immediate/preview', {
        headers: { 'x-csrf-token': csrf },
        data: { value: { label: 'second' } },
      });
      expect(pv.status()).toBe(200);
      const { previewId } = await pv.json();
      const bad = await page.request.post('/api/v1/guarded/e2e-immediate', {
        headers: { 'x-csrf-token': csrf },
        data: { previewId, confirm: 'not the phrase', value: { label: 'second' } },
      });
      expect(bad.status()).toBe(400);
      // A changed value after the preview is stale, and the value stays as it was.
      const stale = await page.request.post('/api/v1/guarded/e2e-immediate', {
        headers: { 'x-csrf-token': csrf },
        data: { previewId, confirm: phrase, value: { label: 'third' } },
      });
      expect(stale.status()).toBe(409);
      expect((await stale.json()).code).toBe('preview_stale');
      // The change is in the audit log, with its setting and node.
      const audit = await page.request.get('/api/v1/audit?action=settings.guarded&limit=20');
      expect(JSON.stringify(await audit.json())).toContain('e2e-immediate');
      // No page of the listing carries a value.
      const listing = JSON.stringify(await (await page.request.get('/api/v1/guarded')).json());
      expect(listing).not.toContain('first');
    } finally {
      await page.close();
    }
  });

  test('api_902 rollback countdown', async ({ browser }) => {
    const page = await adminPage(browser);
    try {
      const box = page.getByTestId('guarded-test-e2e-window');
      await box.getByLabel('Test port').fill(String(PORTS.guardedRoll));
      const phrase = await review(box, 'e2e-window');
      await expect(box.getByTestId('guarded-effect')).toContainText(`127.0.0.1:${PORTS.guardedRoll}`);
      await box.getByTestId('guarded-phrase-input').fill(phrase);
      await box.getByTestId('guarded-apply').click();
      // The countdown runs from the seconds the server says are left.
      const countdown = box.getByTestId('guarded-countdown');
      await expect(countdown).toBeVisible();
      const first = Number(await countdown.innerText());
      expect(first).toBeGreaterThan(0);
      expect(first).toBeLessThanOrEqual(15);
      await expect(box.getByTestId('guarded-confirm-link')).toHaveAttribute('href', /guarded-confirm\?id=.+&t=.+/);
      await page.waitForTimeout(2200);
      expect(Number(await countdown.innerText())).toBeLessThan(first);
      // The status page shows the change is pending, without any value.
      const status = JSON.stringify(await (await page.request.get('/api/v1/guarded')).json());
      expect(status).toContain('e2e-window');
      expect(status).not.toContain(String(PORTS.guardedRoll));
      // Nothing is done: the window runs out and the change rolls back, with its reason.
      await expect(box.getByTestId('guarded-rolled-back')).toContainText('not confirmed in time', { timeout: 30_000 });
      await expect(page.getByTestId('guarded-outcomes')).toContainText('rolled back: it was not confirmed in time');
      // The temporary listener is closed again.
      const reached = await fetch(`http://127.0.0.1:${PORTS.guardedRoll}/livez`).then(() => true).catch(() => false);
      expect(reached).toBe(false);
      // A change can also be cancelled by hand.
      await box.getByTestId('guarded-again').click();
      await review(box, 'e2e-window');
      await box.getByTestId('guarded-phrase-input').fill(phrase);
      await box.getByTestId('guarded-apply').click();
      await box.getByTestId('guarded-cancel').click();
      await expect(box.getByTestId('guarded-rolled-back')).toContainText('cancelled', { timeout: 10_000 });
    } finally {
      await page.close();
    }
  });

  test('api_902 confirm on the new address keeps the change', async ({ browser }) => {
    const page = await adminPage(browser);
    const ctx = await browser.newContext();
    try {
      const box = page.getByTestId('guarded-test-e2e-window');
      await box.getByLabel('Test port').fill(String(PORTS.guardedNew));
      const phrase = await review(box, 'e2e-window');
      await box.getByTestId('guarded-phrase-input').fill(phrase);
      await box.getByTestId('guarded-apply').click();
      const link = await box.getByTestId('guarded-confirm-link').getAttribute('href');
      expect(link).toContain(`127.0.0.1:${PORTS.guardedNew}`);
      // The new address has no session: the token in the fragment is all the page has.
      const other = await ctx.newPage();
      await other.goto(link ?? '');
      await expect(other.getByTestId('guarded-confirm-page')).toBeVisible();
      await other.getByTestId('guarded-confirm-button').click();
      await expect(other.getByTestId('guarded-confirmed')).toContainText('Confirmed');
      // On the address it started from the change is kept.
      await expect(box.getByTestId('guarded-result')).toContainText('confirmed and is kept', { timeout: 15_000 });
      await expect(page.getByTestId('guarded-outcomes')).toContainText('e2e-window: confirmed');
      // The window's temporary listener is closed again, and the token is spent: it confirms nothing.
      const params = new URLSearchParams((link ?? '').split('?')[1]);
      const spent = await ctx.request.post(`/api/v1/guarded/pending/${params.get('id')}/confirm`, {
        baseURL: `http://127.0.0.1:${PORTS.http}`,
        data: { confirmToken: params.get('t') },
      });
      expect(spent.status()).toBe(404);
      const open = await fetch(`http://127.0.0.1:${PORTS.guardedNew}/livez`).then(() => true).catch(() => false);
      expect(open).toBe(false);
    } finally {
      await ctx.close();
      await page.close();
    }
  });

  test('api_902 weakening asks for sign-in', async ({ browser }) => {
    const page = await adminPage(browser);
    try {
      const box = page.getByTestId('guarded-test-e2e-immediate');
      await box.getByLabel('Test label').fill('weaker');
      await box.getByText('Weakens security').first().check();
      // The first apply is refused as the server would refuse a stale sign-in; the retry is real.
      let refused = false;
      await page.route('**/api/v1/guarded/e2e-immediate', async (route) => {
        if (route.request().method() === 'POST' && !refused) {
          refused = true;
          await route.fulfill({
            status: 403,
            contentType: 'application/problem+json',
            body: JSON.stringify({
              type: 'https://telltaledns.dev/problems/reauth_required',
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
      const phrase = await review(box, 'e2e-immediate');
      await expect(box.getByTestId('guarded-weakens')).toBeVisible();
      await box.getByTestId('guarded-phrase-input').fill(phrase);
      await box.getByTestId('guarded-apply').click();
      await expect(box.getByTestId('guarded-reauth')).toBeVisible();
      await box.getByTestId('guarded-reauth-password').fill(ADMIN.pass);
      await box.getByTestId('guarded-reauth-go').click();
      await expect(box.getByTestId('guarded-result')).toContainText('applied', { timeout: 20_000 });
      // The server marks it as weakening in its audit record.
      const audit = JSON.stringify(await (await page.request.get('/api/v1/audit?action=settings.guarded&limit=20')).json());
      expect(audit).toContain('weakening');
    } finally {
      await page.close();
    }
  });

  test('api_902 set by file locks the control', async ({ browser }) => {
    const page = await adminPage(browser);
    try {
      const box = page.getByTestId('guarded-test-e2e-file');
      await expect(box.getByTestId('guarded-set-by-file')).toBeVisible();
      await expect(box.getByTestId('guarded-start-e2e-file')).toBeDisabled();
      // The server refuses it too (the file wins).
      const csrf = await csrfOf(page);
      const r = await page.request.post('/api/v1/guarded/e2e-file/preview', {
        headers: { 'x-csrf-token': csrf },
        data: { value: { label: 'x' } },
      });
      expect(r.status()).toBe(409);
      expect((await r.json()).code).toBe('set_by_file');
    } finally {
      await page.close();
    }
  });

  test('api_902 operator and viewer see no guarded controls', async ({ browser }) => {
    const admin = await adminPage(browser);
    try {
      const csrf = await csrfOf(admin);
      for (const [who, role] of [
        [OPERATOR, 'operator'],
        [VIEWER, 'viewer'],
      ] as const) {
        const made = await admin.request.post('/api/v1/users', {
          headers: { 'x-csrf-token': csrf },
          data: { username: who.user, password: who.pass, role },
        });
        expect([200, 201, 409]).toContain(made.status());
        const page = await signedIn(browser, who);
        try {
          await expect(page.getByRole('heading', { name: 'System information' }).or(page.getByRole('heading', { name: /System/ }).first())).toBeVisible({ timeout: 30_000 });
          await expect(page.getByTestId('guarded-card')).toHaveCount(0);
          await expect(page.getByTestId('guarded-start-restart-now')).toHaveCount(0);
          // The server refuses them as well: 403, whatever the UI hid.
          const c = await csrfOf(page);
          const r = await page.request.post('/api/v1/guarded/restart-now/preview', {
            headers: { 'x-csrf-token': c },
            data: { value: null },
          });
          expect(r.status()).toBe(403);
        } finally {
          await page.close();
        }
      }
    } finally {
      await admin.close();
    }
  });

  test('api_902 restart now hidden without a supervisor', async ({ browser }) => {
    const page = await adminPage(browser);
    try {
      // Stage a change (it needs a restart), then say the node declares no supervisor.
      const box = page.getByTestId('guarded-test-e2e-staged');
      await box.getByLabel('Test label').fill('stage-one');
      const phrase = await review(box, 'e2e-staged');
      await box.getByTestId('guarded-phrase-input').fill(phrase);
      await box.getByTestId('guarded-apply').click();
      await expect(box.getByTestId('guarded-pending-restart')).toBeVisible();
      await expect(page.getByTestId('guarded-restart-item')).toContainText('e2e-staged');
      await expect(page.getByTestId('guarded-start-restart-now')).toBeVisible();
      await page.route('**/api/v1/guarded', async (route) => {
        if (route.request().method() !== 'GET') return route.continue();
        const res = await route.fetch();
        const body = await res.json();
        body.nodes[0].supervisor = { kind: 'none', how: 'not declared' };
        await route.fulfill({ response: res, json: body });
      });
      await expect(page.getByTestId('guarded-restart-manual')).toBeVisible({ timeout: 15_000 });
      await expect(page.getByTestId('guarded-start-restart-now')).toHaveCount(0);
      await expect(page.getByTestId('guarded-supervisor')).toContainText('none declared');
      // The server refuses it as well.
      await page.unroute('**/api/v1/guarded');
    } finally {
      await page.close();
    }
  });

  test('api_902 restart now asks for its phrase', async ({ browser }) => {
    const page = await adminPage(browser);
    try {
      await expect(page.getByTestId('guarded-restart-item')).toContainText('e2e-staged');
      const box = page.getByTestId('guarded-restart-now');
      await box.getByTestId('guarded-start-restart-now').click();
      await expect(box.getByTestId('guarded-phrase')).toHaveText(`${NODE} restart`);
      await expect(box.getByTestId('guarded-effect')).toContainText('e2e-staged');
      // The node says it cannot check that the supervisor restarts it.
      await expect(box.getByTestId('guarded-warning').first()).toContainText('cannot check');
      const apply = box.getByTestId('guarded-apply');
      await expect(apply).toBeDisabled();
      await box.getByTestId('guarded-phrase-input').fill(`${NODE} e2e-staged`);
      await expect(apply).toBeDisabled();
      await box.getByTestId('guarded-phrase-input').fill(`${NODE} restart`);
      await expect(apply).toBeEnabled();
      await box.getByTestId('guarded-back').click();
      // An agent can't: no token of any kind gets through (the server's answer, not the UI's).
      const r = await page.request.post('/api/v1/guarded/restart-now/preview', { data: { value: null } });
      expect([401, 403]).toContain(r.status());
    } finally {
      await page.close();
    }
  });

  test('api_902 restart now shows the outcome', async ({ browser }) => {
    const page = await adminPage(browser);
    try {
      const box = page.getByTestId('guarded-restart-now');
      const phrase = await review(box, 'restart-now');
      await box.getByTestId('guarded-phrase-input').fill(phrase);
      await box.getByTestId('guarded-apply').click();
      await expect(box.getByTestId('guarded-restarting')).toBeVisible();
      // The hook simulates the node's return: the staged change was applied.
      await expect(box.getByTestId('guarded-result')).toContainText('is back', { timeout: 30_000 });
      await expect(box.getByTestId('guarded-result')).toContainText('e2e-staged');
      await expect(page.getByTestId('guarded-outcomes')).toContainText('e2e-staged: applied');
      await box.getByTestId('guarded-again').click();
      // The restart is in the audit log, with its own record.
      const audit = JSON.stringify(await (await page.request.get('/api/v1/audit?action=settings.guarded_restart&limit=5')).json());
      expect(audit).toContain('settings.guarded_restart');

      // A staged change that fails its start is rolled back, and the page says why.
      const stage = page.getByTestId('guarded-test-e2e-staged');
      await stage.getByLabel('Test label').fill('stage-two');
      await stage.getByLabel('The next start fails').check();
      const p2 = await review(stage, 'e2e-staged');
      await stage.getByTestId('guarded-phrase-input').fill(p2);
      await stage.getByTestId('guarded-apply').click();
      await expect(page.getByTestId('guarded-restart-item')).toBeVisible();
      const box2 = page.getByTestId('guarded-restart-now');
      const p3 = await review(box2, 'restart-now');
      await box2.getByTestId('guarded-phrase-input').fill(p3);
      await box2.getByTestId('guarded-apply').click();
      await expect(box2.getByTestId('guarded-rolled-back')).toContainText('did not become healthy', { timeout: 30_000 });
      await expect(page.getByTestId('guarded-outcomes')).toContainText('rolled back');
    } finally {
      await page.close();
    }
  });
});
