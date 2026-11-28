// REQ: API-016, OBS-010, OBS-006 (T23.11, ADR-903 §7, ADR-984) — Settings → Telemetry: event sinks and
// the OTLP export made in the UI and applied without a restart. Runs against the suite's own server
// (after 1-ui.spec.ts, which creates the admin): nothing listens at the addresses used, which is
// the point — a sink to a dead collector is stored, shown running and counted, and DNS is untouched.
import { expect, test, type Browser, type Page } from '@playwright/test';

const ADMIN = { user: 'admin', pass: 'correct horse battery' };

async function signIn(browser: Browser, user: { user: string; pass: string }): Promise<Page> {
  const page = await browser.newPage();
  await page.goto('/#/settings?tab=telemetry');
  await page.getByLabel('Username', { exact: true }).fill(user.user);
  await page.getByLabel('Password', { exact: true }).fill(user.pass);
  await page.getByRole('button', { name: 'Sign in' }).click();
  await expect(page.getByTestId('telemetry-tab')).toBeVisible({ timeout: 30_000 });
  return page;
}

const csrfOf = async (page: Page) => (await (await page.request.get('/api/v1/auth/status')).json()).csrfToken as string;

test.describe('api_016 telemetry in the UI', () => {
  test.describe.configure({ mode: 'serial' });

  test('api_016 add a sink from the UI', async ({ browser }) => {
    const page = await signIn(browser, ADMIN);
    try {
      await page.getByRole('button', { name: 'Add sink' }).click();
      await page.getByRole('textbox', { name: 'Name', exact: true }).fill('e2e-loki');
      await page.getByRole('textbox', { name: 'URL', exact: true }).fill('http://127.0.0.1:9/ingest');
      // The token goes through SecretField: typed once, stored by name, never shown again.
      const token = page.getByTestId('secret-token_ref');
      await token.getByLabel('Token', { exact: true }).fill('sink-e2e-token-5521');
      await token.getByRole('button', { name: 'Save secret' }).click();
      await expect(token).toHaveAttribute('data-mode', 'set', { timeout: 10_000 });
      await expect(page.locator('body')).not.toContainText('sink-e2e-token-5521');
      await page.getByRole('button', { name: 'Check', exact: true }).click();
      await expect(page.getByTestId('entry-preview')).toContainText('without a restart');
      await page.getByRole('button', { name: 'Apply', exact: true }).click();
      const row = page.getByTestId('entry-row').filter({ hasText: 'e2e-loki' });
      await expect(row).toBeVisible({ timeout: 10_000 });
      await expect(row).toContainText('webhook: http://127.0.0.1:9/ingest');
      await expect(row).toContainText('token stored');
      // The node runs it without a restart, and the answer names the secret and carries no value.
      await expect
        .poll(async () => (await (await page.request.get('/api/v1/sinks')).json()).items.find((s: { name: string }) => s.name === 'e2e-loki')?.running, { timeout: 15_000 })
        .toBe(true);
      const list = await page.request.get('/api/v1/sinks');
      const text = await list.text();
      expect(text).toContain('sink.e2e-loki.token');
      expect(text).not.toContain('sink-e2e-token-5521');
      await expect(page.getByTestId('sink-state').filter({ hasText: 'e2e-loki' })).toContainText('running on this node', { timeout: 15_000 });
      // A file sink: a file name only, written under the node's data directory.
      await page.getByRole('button', { name: 'Add sink' }).click();
      await page.getByRole('textbox', { name: 'Name', exact: true }).fill('e2e-file');
      await page.getByRole('combobox', { name: 'Type', exact: true }).selectOption('file');
      await expect(page.getByRole('textbox', { name: 'URL', exact: true })).toHaveCount(0);
      await page.getByRole('textbox', { name: 'File name', exact: true }).fill('e2e-events.jsonl');
      await page.getByRole('button', { name: 'Check', exact: true }).click();
      await page.getByRole('button', { name: 'Apply', exact: true }).click();
      await expect(page.getByTestId('entry-row').filter({ hasText: 'e2e-file' })).toContainText('e2e-events.jsonl', { timeout: 10_000 });
      // A path outside the data directory is refused by the server.
      const csrf = await csrfOf(page);
      const bad = await page.request.put('/api/v1/sinks/e2e-evil', { headers: { 'x-csrf-token': csrf }, data: { type: 'file', path: '../../etc/cron.d/x' } });
      expect(bad.status()).toBe(422);
      // Remove both.
      for (const name of ['e2e-loki', 'e2e-file']) {
        await page.getByTestId('entry-row').filter({ hasText: name }).getByRole('button', { name: 'Remove' }).click();
        await expect(page.getByTestId('entry-row').filter({ hasText: name })).toHaveCount(0, { timeout: 10_000 });
      }
    } finally {
      await page.close();
    }
  });

  test('api_016 a sink set by file is read-only', async ({ browser }) => {
    const page = await signIn(browser, ADMIN);
    try {
      await page.route('**/api/v1/config/entries?kind=sink', (route) =>
        route.fulfill({
          json: {
            items: [
              { kind: 'sink', name: 'from-file', source: 'file', definition: { type: 'syslog', address: 'udp://192.168.1.20:514' }, redacted: [], setByFile: [] },
              { kind: 'sink', name: 'from-ui', source: 'added', definition: { type: 'file', path: 'x.jsonl' }, redacted: [], setByFile: [] },
            ],
          },
        }),
      );
      await page.reload();
      await expect(page.getByTestId('telemetry-tab')).toBeVisible({ timeout: 30_000 });
      const file = page.getByTestId('entry-row').filter({ hasText: 'from-file' });
      await expect(file.getByTestId('set-by-file-row')).toContainText('Set by file');
      await expect(file.getByRole('button', { name: 'Edit' })).toHaveCount(0);
      await expect(file.getByRole('button', { name: 'Remove' })).toHaveCount(0);
      const mine = page.getByTestId('entry-row').filter({ hasText: 'from-ui' });
      await expect(mine.getByRole('button', { name: 'Edit' })).toBeVisible();
    } finally {
      await page.close();
    }
  });

  test('obs_006 otlp header from a stored secret', async ({ browser }) => {
    const page = await signIn(browser, ADMIN);
    try {
      await expect(page.getByTestId('otlp-off')).toBeVisible();
      await page.getByTestId('otlp-edit').click();
      await page.getByRole('textbox', { name: 'Collector address' }).fill('http://127.0.0.1:9');
      await page.getByTestId('otlp-add-header').click();
      await page.getByRole('textbox', { name: 'Header name 1' }).fill('x-api-key');
      // The value goes through SecretField: typed once, stored by name, never shown again.
      const secret = page.getByTestId('otlp-secret-0');
      await secret.getByLabel('Value of x-api-key', { exact: true }).fill('otlp-e2e-key-7788');
      await secret.getByRole('button', { name: 'Save secret' }).click();
      await expect(secret).toHaveAttribute('data-mode', 'set', { timeout: 10_000 });
      await expect(page.locator('body')).not.toContainText('otlp-e2e-key-7788');
      // REQ: OBS-006 (issue #155) — requests can go out gzip compressed.
      await page.getByTestId('otlp-compression-select').selectOption('gzip');
      // REQ: OBS-006 (T41.2) — the protobuf encoding and an extra resource attribute.
      await page.getByTestId('otlp-encoding-select').selectOption('protobuf');
      await page.getByTestId('otlp-add-attr').click();
      await page.getByRole('textbox', { name: 'Attribute name 1' }).fill('deployment.environment');
      await page.getByRole('textbox', { name: 'Attribute value 1' }).fill('home');
      await page.getByTestId('otlp-save').click();
      await expect(page.getByTestId('otlp-notice')).toContainText('no restart', { timeout: 10_000 });
      const header = page.getByTestId('otlp-header').filter({ hasText: 'x-api-key' });
      await expect(header).toContainText('otlp.default.header-x-api-key');
      await expect(page.getByTestId('otlp-source')).toHaveText('From the UI');
      await expect(page.getByTestId('otlp-endpoint')).toHaveText('http://127.0.0.1:9');
      const answer = await (await page.request.get('/api/v1/otlp')).text();
      expect(answer).toContain('otlp.default.header-x-api-key');
      expect(JSON.parse(answer).compression).toBe('gzip');
      expect(JSON.parse(answer).encoding).toBe('protobuf');
      expect(JSON.parse(answer).resourceAttributes).toEqual({ 'deployment.environment': 'home' });
      await expect(page.getByTestId('otlp-compression')).toHaveText('gzip compressed');
      await expect(page.getByTestId('otlp-encoding')).toHaveText('protobuf');
      await expect(page.getByTestId('otlp-attributes')).toContainText('deployment.environment=home');
      expect(answer).not.toContain('otlp-e2e-key-7788');
      // An inline value never comes back: here the list is mocked as a node whose file sets it.
      await page.route('**/api/v1/otlp', (route) =>
        route.request().method() === 'GET'
          ? route.fulfill({
              json: {
                source: 'file', endpoint: 'https://otel.example', intervalSecs: 60, tracesSampleEvery: 0, tracesSlowMs: 0, active: true,
                headers: [{ name: 'api-key', source: 'inline', value: '<redacted>' }],
              },
            })
          : route.continue(),
      );
      await page.reload();
      await expect(page.getByTestId('otlp-header-redacted')).toHaveText('<redacted>', { timeout: 30_000 });
      await expect(page.getByTestId('otlp-file-note')).toContainText('read-only');
      await expect(page.getByTestId('otlp-edit')).toHaveCount(0);
      await page.unroute('**/api/v1/otlp');
      await page.reload();
      // Turn it off again.
      await expect(page.getByTestId('otlp-off-button')).toBeVisible({ timeout: 30_000 });
      await page.getByTestId('otlp-off-button').click();
      await page.getByTestId('otlp-off-confirm').click();
      await expect(page.getByTestId('otlp-off')).toBeVisible({ timeout: 10_000 });
    } finally {
      await page.close();
    }
  });

  // REQ: OBS-006 (T41.2) — a collector behind a private CA: the CA is a stored secret of the pem
  // kind picked on the card; it needs an https address; the answer shows where it comes from and
  // never the certificate; reserved attribute names are refused before anything is sent.
  test('obs_006 otlp private ca from a stored pem secret', async ({ browser }) => {
    const page = await signIn(browser, ADMIN);
    const pem = '-----BEGIN CERTIFICATE-----\nMIIBszCCAVmgAwIBAgIUZGVtby1jYS1mb3ItZTJlLW9ubHkwCgYIKoZIzj0EAwIw\n-----END CERTIFICATE-----';
    try {
      const csrf = await csrfOf(page);
      const put = await page.request.put('/api/v1/secrets/otlp-e2e-ca', { headers: { 'x-csrf-token': csrf }, data: { value: pem, kind: 'pem' } });
      expect(put.status()).toBe(200);
      await page.reload();
      await expect(page.getByTestId('otlp-off')).toBeVisible({ timeout: 30_000 });
      await page.getByTestId('otlp-edit').click();
      await page.getByRole('textbox', { name: 'Collector address' }).fill('http://127.0.0.1:9');
      await page.getByTestId('otlp-ca-select').selectOption('otlp-e2e-ca');
      // A CA is for TLS: an http address is refused on the page.
      await page.getByTestId('otlp-save').click();
      await expect(page.getByTestId('otlp-error')).toContainText('https://');
      // A reserved attribute name is refused too.
      await page.getByRole('textbox', { name: 'Collector address' }).fill('https://127.0.0.1:9');
      await page.getByTestId('otlp-add-attr').click();
      await page.getByRole('textbox', { name: 'Attribute name 1' }).fill('service.name');
      await page.getByRole('textbox', { name: 'Attribute value 1' }).fill('x');
      await page.getByTestId('otlp-save').click();
      await expect(page.getByTestId('otlp-error')).toContainText('sets service.name');
      await page.getByRole('textbox', { name: 'Attribute name 1' }).fill('deployment.environment');
      await page.getByTestId('otlp-save').click();
      await expect(page.getByTestId('otlp-notice')).toContainText('no restart', { timeout: 10_000 });
      await expect(page.getByTestId('otlp-ca')).toContainText('otlp-e2e-ca');
      const answer = await (await page.request.get('/api/v1/otlp')).text();
      expect(JSON.parse(answer).tlsCa.source).toBe('stored');
      expect(JSON.parse(answer).tlsCa.secret).toBe('otlp-e2e-ca');
      expect(answer).not.toContain('BEGIN CERTIFICATE');
      // The server refuses a CA file path in a body (the files set it) and a text secret as a CA.
      const csrf2 = await csrfOf(page);
      const file = await page.request.put('/api/v1/otlp/default', { headers: { 'x-csrf-token': csrf2 }, data: { endpoint: 'https://127.0.0.1:9', tls_ca: '/etc/ssl/ca.pem' } });
      expect(file.status()).toBe(422);
      // Turn it off, then the secret can go.
      await page.getByTestId('otlp-off-button').click();
      await page.getByTestId('otlp-off-confirm').click();
      await expect(page.getByTestId('otlp-off')).toBeVisible({ timeout: 10_000 });
      const del = await page.request.delete('/api/v1/secrets/otlp-e2e-ca', { headers: { 'x-csrf-token': await csrfOf(page) } });
      expect(del.status()).toBe(200);
    } finally {
      await page.close();
    }
  });

  test('api_016 operator sees telemetry read-only', async ({ browser }) => {
    const admin = await signIn(browser, ADMIN);
    try {
      const made = await admin.request.post('/api/v1/users', {
        headers: { 'x-csrf-token': await csrfOf(admin) },
        data: { username: 'telemetry-operator', password: 'operator telemetry password', role: 'operator' },
      });
      expect([200, 201, 409]).toContain(made.status());
    } finally {
      await admin.close();
    }
    const op = await signIn(browser, { user: 'telemetry-operator', pass: 'operator telemetry password' });
    try {
      await expect(op.getByTestId('telemetry-readonly')).toBeVisible();
      await expect(op.getByRole('button', { name: 'Add sink' })).toHaveCount(0);
      await expect(op.getByTestId('otlp-edit')).toHaveCount(0);
      await expect(op.getByTestId('otlp-readonly')).toBeVisible();
      // The server says no whatever the page does.
      const csrf = await csrfOf(op);
      expect((await op.request.get('/api/v1/sinks')).status()).toBe(200);
      const put = await op.request.put('/api/v1/sinks/sneaky', { headers: { 'x-csrf-token': csrf }, data: { type: 'webhook', url: 'http://127.0.0.1:9/x' } });
      expect(put.status()).toBe(403);
      const otlp = await op.request.put('/api/v1/otlp/default', { headers: { 'x-csrf-token': csrf }, data: { endpoint: 'http://127.0.0.1:9' } });
      expect(otlp.status()).toBe(403);
    } finally {
      await op.close();
    }
  });
});
