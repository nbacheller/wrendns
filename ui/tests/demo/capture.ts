// SPDX-License-Identifier: AGPL-3.0-or-later
// REQ: DOC-002 — what the screenshot specs of the demo share: a signed-in browser on the made-up
// network (run.sh), in one theme and at one size. Not part of the e2e suite.
import type { Browser } from '@playwright/test';

export async function capture(browser: Browser, theme: 'light' | 'dark', width: number, height: number, scale: number) {
  const context = await browser.newContext({
    baseURL: 'http://127.0.0.1:28053',
    colorScheme: theme,
    // Still pictures: the map and the charts settle at once instead of animating.
    reducedMotion: 'reduce',
    viewport: { width, height },
    deviceScaleFactor: scale,
  });
  const page = await context.newPage();
  // The demo's devices are on loopback, which reads as masked client IPs (OPS-003): keep that
  // banner out of the pictures.
  await page.route('**/api/v1/system/info', async (route) => {
    const res = await route.fetch();
    const info = await res.json();
    delete info.clientIpsMasked;
    await route.fulfill({ response: res, json: info });
  });
  // The demo network is minutes old, so the period before it has a few stray queries and the
  // dashboard's change arrows read as nonsense ("up 14,099%"). The pictures leave them out: the
  // request for the previous period fails, and the page shows no change.
  await page.route('**/api/v1/stats/summary*', async (route) => {
    if (new URL(route.request().url()).searchParams.has('to')) await route.abort();
    else await route.continue();
  });
  await page.goto('/');
  await page.getByLabel('Username', { exact: true }).fill('admin');
  await page.getByLabel('Password', { exact: true }).fill('correct horse battery');
  await page.getByRole('button', { name: 'Sign in' }).click();
  await page.getByRole('heading', { name: 'Dashboard' }).waitFor();
  await page.getByRole('button', { name: '15 min' }).click();
  await page.waitForTimeout(3000);
  return { page, context };
}
