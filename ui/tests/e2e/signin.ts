// SPDX-License-Identifier: AGPL-3.0-or-later
// REQ: API-003 — one way to submit the sign-in form that says which part was lost when a sign-in does
// nothing under load, instead of leaving the test to time out waiting for what the sign-in would show.
import { expect, type Page } from '@playwright/test';

const isLogin = (r: { method(): string; url(): string }) => r.method() === 'POST' && r.url().endsWith('/api/v1/auth/login');

/**
 * Fills the sign-in form and submits it, then waits for the login request to be sent and answered.
 * Fails with the reason when the field does not hold what was typed (the form was replaced after the
 * fill), no request was sent (a click that landed while the form mounted), or the server answered 503
 * (password checks busy) or 429 (locked out). A 401 is an answer: the caller checks what the page shows.
 */
export async function signInSent(page: Page, user: string, pass: string): Promise<void> {
  const name = page.getByLabel('Username', { exact: true });
  const word = page.getByLabel('Password', { exact: true });
  await name.fill(user);
  await word.fill(pass);
  await expect(name, 'the username field holds what was typed').toHaveValue(user);
  await expect(word, 'the password field holds what was typed').toHaveValue(pass);
  const sent = page.waitForRequest((r) => isLogin(r), { timeout: 15_000 });
  const answered = page.waitForResponse((r) => isLogin(r.request()), { timeout: 15_000 });
  await page.getByRole('button', { name: 'Sign in' }).click();
  await sent;
  const res = await answered.catch(() => null);
  const verdict = res === null ? 'no response within 15 s' : res.status() >= 500 || res.status() === 429 ? `status ${res.status()}` : 'answered';
  expect(verdict, 'the sign-in request was answered').toBe('answered');
}
