// REQ: API-004 — T3.6 acceptance: sign in through real Keycloak and Authentik (see
// ../oidc/compose.yml). Runs when OIDC_E2E lists the providers, after 1-ui.spec.ts (which
// creates the local admin). Each test uses a fresh browser context. REQ: API-016 (T23.10) — the
// last block (OIDC providers in the UI) needs no provider and always runs.
import { expect, test, type Page } from '@playwright/test';

// Without OIDC_E2E there are no real-provider tests (the loop below defines none).
const providers = (process.env.OIDC_E2E ?? '').split(',').filter(Boolean);
test.describe.configure({ mode: 'serial' });

const USERS = {
  alice: { pass: 'alice-password', role: 'admin' },
  bob: { pass: 'bob-password', role: 'viewer' },
  carol: { pass: 'carol-password', role: '' },
} as const;

async function providerLogin(page: Page, id: string, user: keyof typeof USERS) {
  const pass = USERS[user].pass;
  if (id === 'keycloak') {
    await page.locator('#username').fill(user);
    await page.locator('#password').fill(pass);
    await page.locator('#kc-login').click();
  } else {
    // Authentik: identification, then password (web components; Playwright pierces shadow DOM).
    await page.locator('input[name="uidField"]').fill(user);
    await page.getByRole('button', { name: /^(Continue|Log in)$/ }).click();
    const password = page.getByRole('textbox', { name: 'Password' });
    await password.waitFor({ state: 'visible' });
    await password.fill(pass);
    await page.getByRole('button', { name: 'Continue' }).click();
  }
}

async function signIn(page: Page, id: string, name: string, user: keyof typeof USERS) {
  await page.goto('/#/queries');
  await page.getByRole('link', { name: `Sign in with ${name}` }).click();
  await providerLogin(page, id, user);
}

for (const id of providers) {
  const name = id === 'keycloak' ? 'Keycloak' : 'Authentik';

  test(`${id}: a mapped admin signs in and lands where they started`, async ({ browser }) => {
    const page = await browser.newPage();
    await signIn(page, id, name, 'alice');
    await expect(page.getByRole('heading', { name: 'Query log' })).toBeVisible({ timeout: 20_000 });
    await expect(page.locator('header .who')).toContainText(/alice/);
    await expect(page.locator('header .who .role')).toHaveText('admin');
    // The account was created on first sign-in and is marked as provider-managed.
    await page.goto('/#/settings?tab=users');
    await expect(page.locator('main table')).toContainText(`signs in with ${id}`);
    // Signing out also signs out at the provider, which returns to WrenDNS.
    await page.getByRole('button', { name: 'Sign out' }).click();
    // Keycloak asks "Do you want to log out?" (no id_token_hint is sent; ADR-034).
    const confirm = page.getByRole('button', { name: /^(Logout|Log out)$/i });
    // Keycloak returns to WrenDNS; Authentik's default flow shows its own "logged out of
    // WrenDNS" page instead. Either way the WrenDNS session is over.
    const ended = page
      .getByRole('heading', { name: 'Sign in' })
      .or(page.getByRole('heading', { name: /logged out of WrenDNS/ }));
    // Wait for whichever page comes first (the question, or the end), not a fixed 8 s for the
    // question: on a busy machine the provider's page can take longer than that to draw, and
    // the end check would then run against the question page.
    await confirm.or(ended).first().waitFor({ state: 'visible', timeout: 30_000 });
    if (await confirm.isVisible()) await confirm.click();
    await expect(ended).toBeVisible({ timeout: 20_000 });
    await page.goto('/#/');
    await expect(page.getByRole('heading', { name: 'Sign in' })).toBeVisible();
    await page.close();
  });

  test(`${id}: groups decide the role`, async ({ browser }) => {
    const page = await browser.newPage();
    await signIn(page, id, name, 'bob');
    await expect(page.locator('header .who .role')).toHaveText('viewer', { timeout: 20_000 });
    await page.close();
  });

  test(`${id}: a user in no mapped group is refused with a reason`, async ({ browser }) => {
    const page = await browser.newPage();
    await signIn(page, id, name, 'carol');
    await expect(page.locator('.provider-error')).toContainText('group', { timeout: 20_000 });
    await expect(page.getByRole('heading', { name: 'Sign in' })).toBeVisible();
    await page.close();
  });
}


// ---- API-016 (T23.10, ADR-903 §6, ADR-967): OIDC providers added in the UI, applied without a restart.
// These run against the suite's own server (no identity provider needed): the e2e server has no
// `[auth.oidc] public_url`, so a provider added here is stored and shown, and is inactive on this node
// with the reason. The tests that need a node with a public_url mock the list.
const ADMIN = { user: 'admin', pass: 'correct horse battery' };

async function adminPage(browser: import('@playwright/test').Browser): Promise<Page> {
  const page = await browser.newPage();
  await page.goto('/#/settings?tab=signin');
  await page.getByLabel('Username', { exact: true }).fill(ADMIN.user);
  await page.getByLabel('Password', { exact: true }).fill(ADMIN.pass);
  await page.getByRole('button', { name: 'Sign in' }).click();
  await expect(page.getByTestId('signin-tab')).toBeVisible({ timeout: 30_000 });
  return page;
}

const csrfOf = async (page: Page) => (await (await page.request.get('/api/v1/auth/status')).json()).csrfToken as string;

test.describe('api_016 OIDC providers in the UI', () => {
  test.describe.configure({ mode: 'serial' });

  test('api_016 add an OIDC provider from the UI', async ({ browser }) => {
    const page = await adminPage(browser);
    try {
      await page.getByTestId('oidc-add').click();
      await page.getByRole('textbox', { name: 'ID', exact: true }).fill('lab-sso');
      await page.getByRole('textbox', { name: 'Button label' }).fill('Lab SSO');
      await page.getByRole('textbox', { name: 'Issuer', exact: true }).fill('http://127.0.0.1:9/realms/lab');
      await page.getByRole('textbox', { name: 'Client ID', exact: true }).fill('wrendns');
      // The client secret goes through SecretField: typed once, stored by name, never shown again.
      const secret = page.getByTestId('oidc-secret');
      await secret.getByLabel('Client secret', { exact: true }).fill('oidc-e2e-secret-4417');
      await secret.getByRole('button', { name: 'Save secret' }).click();
      await expect(secret).toHaveAttribute('data-mode', 'set', { timeout: 10_000 });
      await expect(page.locator('body')).not.toContainText('oidc-e2e-secret-4417');
      await expect(secret.getByRole('textbox')).toHaveCount(0);
      // A group to role rule and a role for everyone else.
      await page.getByTestId('oidc-add-rule').click();
      await page.getByRole('textbox', { name: 'Group 1' }).fill('dns-admins');
      await page.getByRole('combobox', { name: 'Role for group 1' }).selectOption('admin');
      await page.getByRole('combobox', { name: 'Role for everyone else' }).selectOption('viewer');
      await page.getByTestId('oidc-save').click();
      const card = page.getByTestId('oidc-card').filter({ hasText: 'lab-sso' });
      await expect(card).toBeVisible({ timeout: 10_000 });
      await expect(card).toContainText('Lab SSO');
      await expect(card).toContainText('From the UI');
      await expect(card).toContainText('oidc.lab-sso.client_secret');
      await expect(card).toContainText('dns-admins → admin');
      await expect(page.getByTestId('oidc-notice')).toContainText('no restart');
      // The server stored it as a reference: the answer names the secret and never carries a value.
      const list = await page.request.get('/api/v1/oidc-providers');
      expect(list.status()).toBe(200);
      const text = await list.text();
      expect(text).toContain('oidc.lab-sso.client_secret');
      expect(text).not.toContain('oidc-e2e-secret-4417');
    } finally {
      await page.close();
    }
  });

  test('api_016 provider without public_url shows inactive', async ({ browser }) => {
    const page = await adminPage(browser);
    try {
      // A node without public_url: the provider is stored, shown, and inactive. The list is
      // mocked, because a run with real providers (OIDC_E2E) gives the server a public_url.
      await page.route('**/api/v1/oidc-providers', (route) =>
        route.request().method() === 'GET'
          ? route.fulfill({
              json: {
                publicUrl: '',
                items: [
                  {
                    id: 'lab-sso', name: 'Lab SSO', issuer: 'https://lab.example', clientId: 'wrendns', source: 'api',
                    scopes: ['openid'], usernameClaim: 'preferred_username', groupsClaim: 'groups', roles: [],
                    requireVerifiedEmail: false, secretSource: 'stored', secret: 'oidc.lab-sso.client_secret',
                    secretReadable: true, active: false,
                    reason: 'this node has no public_url, so it cannot give the provider a redirect URI',
                    redirectUri: '',
                  },
                ],
              },
            })
          : route.continue(),
      );
      await page.goto('/#/settings?tab=signin');
      await page.reload();
      await expect(page.getByTestId('oidc-no-public-url')).toContainText('public_url');
      const card = page.getByTestId('oidc-card').filter({ hasText: 'lab-sso' });
      await expect(card.getByTestId('oidc-state')).toHaveText('Inactive on this node');
      await expect(card.getByTestId('oidc-reason')).toContainText('public_url');
      // And its button isn't offered on the sign-in page.
      const status = await (await page.request.get('/api/v1/auth/status')).json();
      expect((status.oidc as { id: string }[]).some((p) => p.id === 'lab-sso')).toBe(false);
    } finally {
      await page.close();
    }
  });

  test('api_016 a node with a public_url shows an active provider and a file provider read-only', async ({ browser }) => {
    const page = await adminPage(browser);
    try {
      await page.route('**/api/v1/oidc-providers', (route) =>
        route.request().method() === 'GET'
          ? route.fulfill({
              json: {
                publicUrl: 'https://dns.example.com',
                items: [
                  {
                    id: 'kc', name: 'Keycloak', issuer: 'https://kc.example/realms/home', clientId: 'wrendns', source: 'file',
                    scopes: ['openid'], usernameClaim: 'preferred_username', groupsClaim: 'groups',
                    roles: [{ group: 'admins', role: 'admin' }], requireVerifiedEmail: false,
                    secretSource: 'inline', active: true, redirectUri: 'https://dns.example.com/api/v1/auth/oidc/kc/callback',
                  },
                  {
                    id: 'lab', name: 'Lab', issuer: 'https://lab.example', clientId: 'wrendns', source: 'api',
                    scopes: ['openid'], usernameClaim: 'preferred_username', groupsClaim: 'groups', roles: [],
                    defaultRole: 'viewer', requireVerifiedEmail: false, secretSource: 'stored', secret: 'oidc.lab.client_secret',
                    secretReadable: false, active: true,
                    reason: "the new settings aren't applied yet, because the provider couldn't be read: timed out",
                    redirectUri: 'https://dns.example.com/api/v1/auth/oidc/lab/callback',
                  },
                ],
              },
            })
          : route.continue(),
      );
      await page.goto('/#/settings?tab=signin');
      await page.reload();
      await expect(page.getByTestId('oidc-no-public-url')).toHaveCount(0);
      const kc = page.getByTestId('oidc-card').filter({ hasText: 'Keycloak' });
      await expect(kc.getByTestId('oidc-state')).toHaveText('Active');
      await expect(kc.getByTestId('oidc-file')).toHaveText('Set by file');
      await expect(kc.getByTestId('oidc-redirect')).toHaveText('https://dns.example.com/api/v1/auth/oidc/kc/callback');
      // A file provider can't be changed or removed here.
      await expect(kc.getByTestId('oidc-edit')).toHaveCount(0);
      await expect(kc.getByTestId('oidc-delete')).toHaveCount(0);
      // A provider whose new settings could not be read yet says so; its secret issue shows.
      const lab = page.getByTestId('oidc-card').filter({ hasText: 'Lab' }).filter({ hasText: 'oidc.lab.client_secret' });
      await expect(lab.getByTestId('oidc-reason')).toContainText("couldn't be read");
      await expect(lab.getByTestId('oidc-secret-issue')).toBeVisible();
      await expect(lab.getByTestId('oidc-edit')).toBeVisible();
    } finally {
      await page.close();
    }
  });

  test('api_016 change and remove a provider from the UI', async ({ browser }) => {
    const page = await adminPage(browser);
    try {
      const card = page.getByTestId('oidc-card').filter({ hasText: 'lab-sso' });
      await card.getByTestId('oidc-edit').click();
      await expect(page.getByTestId('oidc-editor')).toBeVisible();
      // The ID can't change; the stored secret stays referenced.
      await expect(page.getByRole('textbox', { name: 'ID', exact: true })).toBeDisabled();
      await expect(page.getByTestId('oidc-secret')).toHaveAttribute('data-mode', 'set');
      await page.getByRole('textbox', { name: 'Button label' }).fill('Lab Single Sign-On');
      await page.getByTestId('oidc-save').click();
      await expect(page.getByTestId('oidc-card').filter({ hasText: 'Lab Single Sign-On' })).toBeVisible({ timeout: 10_000 });
      // A second add with a taken ID is refused before anything is stored.
      await page.getByTestId('oidc-add').click();
      await page.getByRole('textbox', { name: 'ID', exact: true }).fill('lab-sso');
      await expect(page.getByTestId('oidc-id-taken')).toBeVisible();
      await expect(page.getByTestId('oidc-save')).toBeDisabled();
      await page.getByRole('button', { name: 'Cancel', exact: true }).click();
      // Remove it.
      const changed = page.getByTestId('oidc-card').filter({ hasText: 'Lab Single Sign-On' });
      await changed.getByTestId('oidc-delete').click();
      await changed.getByTestId('oidc-delete-confirm').click();
      await expect(page.getByTestId('oidc-card').filter({ hasText: 'lab-sso' })).toHaveCount(0, { timeout: 10_000 });
      await expect(page.getByTestId('oidc-notice')).toContainText('sessions it opened have ended');
    } finally {
      await page.close();
    }
  });

  test('api_016 operator cannot see the sign-in tab', async ({ browser }) => {
    const admin = await adminPage(browser);
    try {
      const made = await admin.request.post('/api/v1/users', {
        headers: { 'x-csrf-token': await csrfOf(admin) },
        data: { username: 'oidc-operator', password: 'operator oidc password', role: 'operator' },
      });
      expect([200, 201, 409]).toContain(made.status());
    } finally {
      await admin.close();
    }
    const op = await browser.newPage();
    try {
      await op.goto('/#/settings');
      await op.getByLabel('Username', { exact: true }).fill('oidc-operator');
      await op.getByLabel('Password', { exact: true }).fill('operator oidc password');
      await op.getByRole('button', { name: 'Sign in' }).click();
      await expect(op.getByRole('tablist', { name: 'Settings' })).toBeVisible({ timeout: 30_000 });
      await expect(op.getByRole('tab', { name: 'Sign-in' })).toHaveCount(0);
      await op.goto('/#/settings?tab=signin');
      await expect(op.getByTestId('signin-tab')).toHaveCount(0);
      // And the server says no whatever the page does.
      const csrf = await csrfOf(op);
      expect((await op.request.get('/api/v1/oidc-providers')).status()).toBe(403);
      const put = await op.request.put('/api/v1/oidc-providers/sneaky', {
        headers: { 'x-csrf-token': csrf },
        data: { issuer: 'https://idp.example', client_id: 'x', default_role: 'viewer' },
      });
      expect(put.status()).toBe(403);
    } finally {
      await op.close();
    }
  });
});
