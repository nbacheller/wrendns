// REQ: API-003, UI-AUTH — two-factor sign-in (upstream #64). The enrolment and sign-in fields
// reached the browser with a swallowed quantifier, so no code matched. These tests enrol with a
// real RFC 6238 code computed from the shown secret, then sign in with a code, end to end.
import { createHmac } from 'node:crypto';
import { expect, test, type APIRequestContext, type Page } from '@playwright/test';

test.describe.configure({ mode: 'serial' });

const ADMIN = { user: 'admin', pass: 'correct horse battery' };
const TOTP_USER = { user: 'totp-user', pass: 'totp user passphrase' };

const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

// REQ: API-003 — RFC 4648 base32, as the server shows the enrolment key.
export function base32Decode(s: string): Buffer {
  const clean = s.replace(/[\s=]/g, '').toUpperCase();
  let bits = 0;
  let value = 0;
  const out: number[] = [];
  for (const ch of clean) {
    const v = B32.indexOf(ch);
    if (v < 0) throw new Error(`not base32: ${ch}`);
    value = (value << 5) | v;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

// REQ: API-003 — RFC 6238 TOTP: HMAC-SHA1, 30-second steps, six digits (RFC 4226 truncation).
export function totpAt(secretBase32: string, ms: number): string {
  const counter = Math.floor(ms / 1000 / 30);
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(BigInt(counter));
  const h = createHmac('sha1', base32Decode(secretBase32)).update(msg).digest();
  const off = h[h.length - 1] & 0x0f;
  const bin = ((h[off] & 0x7f) << 24) | (h[off + 1] << 16) | (h[off + 2] << 8) | h[off + 3];
  return String(bin % 1_000_000).padStart(6, '0');
}

// Spot-check the implementation against the RFC 6238 SHA-1 vector (T = 59 s, 8 digits = 94287082).
test('totp helper matches the RFC 6238 vector', () => {
  const rfcSecret = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';
  expect(totpAt(rfcSecret, 59_000)).toBe('287082');
  expect(totpAt(rfcSecret, 1_111_111_109_000)).toBe('081804');
});

// Replay protection (spec/08 API-003): a code can't be used twice, so sign-in waits for the next step.
async function nextStepCode(secret: string, afterCode: string): Promise<string> {
  for (;;) {
    const now = Date.now();
    const code = totpAt(secret, now);
    if (code !== afterCode) return code;
    await new Promise((r) => setTimeout(r, 1000));
  }
}

let page: Page;
let api: APIRequestContext;
// The enrolled secret and the code used to enrol, shared by the two tests (serial).
let enrolledSecret = '';
let enrolCode = '';

test.beforeAll(async ({ browser, request }) => {
  page = await browser.newPage();
  api = request;
  // Create the second-factor user through the API as the admin, in its own cookie jar,
  // so the admin's browser session is not touched.
  const login = await api.post('/api/v1/auth/login', { data: { username: ADMIN.user, password: ADMIN.pass } });
  expect(login.ok()).toBeTruthy();
  const { csrfToken } = (await login.json()) as { csrfToken: string };
  const created = await api.post('/api/v1/users', {
    data: { username: TOTP_USER.user, password: TOTP_USER.pass, role: 'admin' },
    headers: { 'x-csrf-token': csrfToken },
  });
  // A retry finds the user from an earlier run, with two-factor already on (the enrolment
  // button would be missing): delete it and create it again, so the run starts clean (L2).
  if (created.status() === 409) {
    const listed = (await (await api.get('/api/v1/users')).json()) as { items: { id: number; username: string }[] };
    const old = listed.items.find((u) => u.username === TOTP_USER.user);
    if (old) {
      const removed = await api.delete(`/api/v1/users/${old.id}`, { headers: { 'x-csrf-token': csrfToken } });
      expect(removed.status()).toBe(204);
    }
    const again = await api.post('/api/v1/users', {
      data: { username: TOTP_USER.user, password: TOTP_USER.pass, role: 'admin' },
      headers: { 'x-csrf-token': csrfToken },
    });
    expect([200, 201]).toContain(again.status());
  } else {
    expect([200, 201]).toContain(created.status());
  }
});

test.afterAll(async () => {
  await page.close();
});

async function signIn(user: string, pass: string) {
  await page.getByLabel('Username', { exact: true }).fill(user);
  await page.getByLabel('Password', { exact: true }).fill(pass);
  await page.getByRole('button', { name: 'Sign in' }).click();
}

test('UI-AUTH: TOTP enrolment accepts a real six-digit code and turns two-factor on', async () => {
  test.setTimeout(120_000);
  await page.goto('/');
  await signIn(TOTP_USER.user, TOTP_USER.pass);
  await expect(page.getByRole('heading', { name: 'Dashboard' })).toBeVisible({ timeout: 30_000 });

  await page.goto('/#/settings');
  await page.getByRole('button', { name: 'Set up two-factor sign-in' }).click();
  const input = page.getByPlaceholder('123456');
  // The pattern reaches the DOM intact (upstream #64): six digits, not "[0-9]6".
  await expect(input).toHaveAttribute('pattern', '[0-9]{6}');
  const secret = (await page.locator('.key').first().innerText()).replace(/\s/g, '');
  const code = totpAt(secret, Date.now());
  enrolledSecret = secret;
  enrolCode = code;
  await input.fill(code);
  await page.getByRole('button', { name: 'Turn on' }).click();
  await expect(page.getByText('Save these recovery codes now.')).toBeVisible({ timeout: 15_000 });
  await expect(page.locator('.badge.ok', { hasText: 'on' }).first()).toBeVisible();
});

test('UI-AUTH: sign-in asks for a code and accepts the current one', async () => {
  test.setTimeout(120_000);
  await page.getByRole('button', { name: 'Sign out' }).click();
  await page.goto('/');
  await signIn(TOTP_USER.user, TOTP_USER.pass);
  const code = page.getByLabel('Code', { exact: true });
  await expect(code).toBeVisible({ timeout: 15_000 });
  await expect(code).toHaveAttribute('pattern', '[0-9]{6}');
  // A wrong code is refused, and the sign-in page stays.
  await code.fill('000000');
  await page.getByRole('button', { name: 'Sign in' }).click();
  await expect(page.getByRole('heading', { name: 'Sign in' })).toBeVisible();
  // The code for the next 30-second step is accepted (the enrolment code is spent, spec/08 API-003).
  await code.fill(await nextStepCode(enrolledSecret, enrolCode));
  await page.getByRole('button', { name: 'Sign in' }).click();
  await expect(page.getByRole('heading', { name: 'Dashboard' })).toBeVisible({ timeout: 30_000 });
});

// REQ: API-004 (ADR-944) — the Users tab says where break-glass sign-in is allowed, and its
// help topic explains the loopback default.
test('UI-AUTH: Users tab names the break-glass default and its help topic', async () => {
  test.setTimeout(60_000);
  await page.goto('/#/settings');
  await page.getByRole('tab', { name: 'Users' }).click();
  await expect(
    page.getByText('Without allowed_admin_networks, break-glass sign-in is from this computer only.'),
  ).toBeVisible({ timeout: 15_000 });
  await page.getByRole('button', { name: 'Help: Signing in when the provider is down' }).click();
  const panel = page.getByTestId('help-panel');
  await expect(panel).toBeVisible();
  await expect(panel).toContainText('Break-glass sign-in');
});
