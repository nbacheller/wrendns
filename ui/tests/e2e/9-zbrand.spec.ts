// REQ: API-005, DOC-006 (T33.2, ADR-1030) — the brand in the UI: the tokens from brand/tokens.json as
// CSS variables for Day and Night (the system's choice, and the header's toggle kept per viewer),
// Figtree and IBM Plex Mono, the logo files (byte for byte from brand/logos) and the app icon as the
// favicon, and status colours that always come with a word. These tests sign in as the admin
// `1-ui.spec.ts` created; the file is named `9-z` so it runs after it and after `9-categories.spec.ts`, whose timing it must not shift.
import { expect, test, type BrowserContext, type Page } from '@playwright/test';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { E2E_ROOT } from './ports';

test.describe.configure({ mode: 'serial' });

const ADMIN = { user: 'admin', pass: 'correct horse battery' };
const BRAND = resolve(fileURLToPath(new URL('.', import.meta.url)), '../../../brand');
const tokens = JSON.parse(readFileSync(resolve(BRAND, 'tokens.json'), 'utf8')) as {
  color: { tokens: { name: string; value: { light: string; dark: string } }[] };
};
const color = (name: string, theme: 'light' | 'dark'): string => {
  const v = tokens.color.tokens.find((t) => t.name === name)!.value[theme];
  const m = /^\{(.+)\}$/.exec(v);
  return m ? color(m[1], theme) : v;
};
/** `#rrggbb` as the browser reports a computed colour. */
const rgb = (hex: string): string => {
  const n = parseInt(hex.slice(1), 16);
  return `rgb(${(n >> 16) & 255}, ${(n >> 8) & 255}, ${n & 255})`;
};
/** WCAG relative luminance and contrast of two `rgb(r, g, b)` strings. */
const lum = (c: string): number => {
  const [r, g, b] = (c.match(/\d+/g) ?? []).slice(0, 3).map((x) => {
    const v = Number(x) / 255;
    return v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4;
  });
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
};
const contrast = (a: string, b: string): number => {
  const [x, y] = [lum(a), lum(b)].sort((p, q) => q - p);
  return (x + 0.05) / (y + 0.05);
};

let ctx: BrowserContext;
let page: Page;
const problems: string[] = [];

async function open(browser: import('@playwright/test').Browser, colorScheme: 'light' | 'dark') {
  ctx = await browser.newContext({ colorScheme });
  page = await ctx.newPage();
  page.on('pageerror', (e) => problems.push(`page error: ${e.message}`));
  await page.goto('/');
  const welcome = page.getByRole('heading', { name: 'Welcome to WrenDNS' });
  const signInHeading = page.getByRole('heading', { name: 'Sign in' });
  await expect(welcome.or(signInHeading)).toBeVisible();
  if (await welcome.isVisible()) {
    const token = readFileSync(resolve(E2E_ROOT, 'data/setup-token'), 'utf8').trim();
    await page.getByLabel('Setup token').fill(token);
    await page.getByLabel('Admin username').fill(ADMIN.user);
    await page.getByLabel('Password (at least 10 characters)').fill(ADMIN.pass);
    await page.getByLabel('Repeat password').fill(ADMIN.pass);
    await page.getByRole('button', { name: 'Create admin and sign in' }).click();
  } else {
    await page.getByLabel('Username', { exact: true }).fill(ADMIN.user);
    await page.getByLabel('Password', { exact: true }).fill(ADMIN.pass);
    await page.getByRole('button', { name: 'Sign in' }).click();
  }
  await expect(page.getByRole('heading', { name: 'Dashboard' })).toBeVisible({ timeout: 30_000 });
}

const bodyBg = () => page.evaluate(() => getComputedStyle(document.body).backgroundColor);
const toggle = () => page.getByTestId('theme-toggle');

test.afterEach(() => {
  expect(problems, 'no page errors').toEqual([]);
});

test.describe('light system', () => {
  test.beforeAll(async ({ browser }) => {
    await open(browser, 'light');
  });
  test.afterAll(async () => {
    await ctx.close();
  });

  test('api_005 Day is the default: the page, cards and the interactive colour come from the tokens', async () => {
    expect(await bodyBg()).toBe(rgb(color('surface', 'light')));
    // A custom property reports as written (`#fff`); read it as the colour it is.
    const as = (name: string) =>
      page.evaluate((n) => {
        const d = document.createElement('div');
        d.style.color = `var(${n})`;
        document.body.append(d);
        const c = getComputedStyle(d).color;
        d.remove();
        return c;
      }, name);
    expect(await as('--surface')).toBe(rgb(color('surface-raised', 'light')));
    expect(await as('--accent')).toBe(rgb(color('sky-strong', 'light')));
    expect(await as('--text')).toBe(rgb(color('ink', 'light')));
    expect(await page.evaluate(() => document.documentElement.dataset.theme ?? '')).toBe('');
    expect(await toggle().getAttribute('aria-label')).toBe('Theme: System');
  });

  test('api_005 the toggle goes System, Night, Day and the choice is kept for this viewer', async () => {
    await toggle().click();
    await expect(toggle()).toHaveAttribute('aria-label', 'Theme: Night');
    expect(await page.evaluate(() => document.documentElement.dataset.theme)).toBe('dark');
    expect(await bodyBg()).toBe(rgb(color('surface', 'dark')));
    expect(await page.evaluate(() => localStorage.getItem('wrendns.theme'))).toBe('dark');

    await page.reload();
    await expect(page.getByRole('heading', { name: 'Dashboard' })).toBeVisible();
    expect(await page.evaluate(() => document.documentElement.dataset.theme)).toBe('dark');
    expect(await bodyBg()).toBe(rgb(color('surface', 'dark')));

    await toggle().click();
    await expect(toggle()).toHaveAttribute('aria-label', 'Theme: Day');
    expect(await bodyBg()).toBe(rgb(color('surface', 'light')));
    expect(await page.evaluate(() => localStorage.getItem('wrendns.theme'))).toBe('light');

    await toggle().click();
    await expect(toggle()).toHaveAttribute('aria-label', 'Theme: System');
    expect(await page.evaluate(() => localStorage.getItem('wrendns.theme'))).toBeNull();
    expect(await page.evaluate(() => document.documentElement.dataset.theme ?? '')).toBe('');
  });

  test('api_005 a theme an earlier build stored is read and moved to the new key', async () => {
    await page.evaluate(() => {
      localStorage.removeItem('wrendns.theme');
      localStorage.setItem('theme', 'dark');
    });
    await page.reload();
    await expect(page.getByRole('heading', { name: 'Dashboard' })).toBeVisible();
    expect(await page.evaluate(() => document.documentElement.dataset.theme)).toBe('dark');
    expect(await page.evaluate(() => [localStorage.getItem('theme'), localStorage.getItem('wrendns.theme')])).toEqual([null, 'dark']);
    await page.evaluate(() => localStorage.removeItem('wrendns.theme'));
    await page.reload();
    await expect(page.getByRole('heading', { name: 'Dashboard' })).toBeVisible();
  });

  test('api_005 the fonts are Figtree and IBM Plex Mono, both loaded', async () => {
    await page.goto('/#/local-dns');
    await page.evaluate(() => document.fonts.ready);
    const faces = await page.evaluate(async () => {
      await document.fonts.load('16px Figtree');
      await document.fonts.load('400 14px "IBM Plex Mono"');
      return [...document.fonts].filter((f) => f.status === 'loaded').map((f) => f.family.replace(/"/g, ''));
    });
    expect(faces).toContain('Figtree');
    expect(faces).toContain('IBM Plex Mono');
    expect(await page.evaluate(() => getComputedStyle(document.body).fontFamily)).toMatch(/^Figtree/);
    expect(await page.evaluate(() => getComputedStyle(document.createElement('code')).fontFamily)).toBeDefined();
    const mono = await page.evaluate(() => {
      const c = document.createElement('code');
      document.body.append(c);
      const f = getComputedStyle(c).fontFamily;
      c.remove();
      return f;
    });
    expect(mono).toMatch(/IBM Plex Mono/);
  });

  test('api_005 the logo is the brand file, the favicon the app icon', async () => {
    const lockup = page.locator('nav.side [data-testid="logo"] img.day').first();
    await expect(lockup).toHaveAttribute('src', '/brand/wrendns-lockup-day.svg');
    for (const [url, file] of [
      ['/brand/wrendns-lockup-day.svg', 'logos/wrendns-lockup-day.svg'],
      ['/brand/wrendns-lockup-night.svg', 'logos/wrendns-lockup-night.svg'],
      ['/brand/wrendns-mark-day.svg', 'logos/wrendns-mark-day.svg'],
      ['/brand/wrendns-mark-night.svg', 'logos/wrendns-mark-night.svg'],
      ['/favicon.svg', 'logos/wrendns-app-icon.svg'],
    ]) {
      const res = await page.request.get(url);
      expect(res.status(), url).toBe(200);
      expect((await res.body()).toString('utf8'), `${url} is brand/${file}, byte for byte`).toBe(readFileSync(resolve(BRAND, file), 'utf8'));
    }
    await expect(page.locator('link[rel="icon"]')).toHaveAttribute('href', '/favicon.svg');
    // Day shows the Day lockup; Night shows the Night one.
    await expect(lockup).toBeVisible();
    await expect(page.locator('nav.side img.night').first()).toBeHidden();
    await toggle().click();
    await expect(toggle()).toHaveAttribute('aria-label', 'Theme: Night');
    await expect(page.locator('nav.side [data-testid="logo"] img.night').first()).toBeVisible();
    await expect(lockup).toBeHidden();
    await toggle().click();
    await toggle().click();
    await expect(toggle()).toHaveAttribute('aria-label', 'Theme: System');
  });

  test('api_005 the wren is the logo only: no mark in the page content, and the sidebar has the one logo', async () => {
    await expect(page.locator('main img[src*="wrendns-mark"], main img[src*="wrendns-app-icon"], main img[src*="favicon"]')).toHaveCount(0);
    await expect(page.locator('nav.side [data-testid="logo"]:visible')).toHaveCount(1);
  });

  test('api_005 text and the interactive colour pass AA in Day', async () => {
    const c = await page.evaluate(() => {
      const s = getComputedStyle(document.body);
      const link = document.createElement('a');
      link.href = '#/';
      link.textContent = 'x';
      const card = document.createElement('div');
      card.className = 'card';
      card.append(link);
      document.querySelector('main')!.append(card);
      const out = { text: s.color, bg: s.backgroundColor, link: getComputedStyle(link).color, card: getComputedStyle(card).backgroundColor };
      card.remove();
      return out;
    });
    expect(contrast(c.text, c.bg)).toBeGreaterThanOrEqual(4.5);
    expect(contrast(c.link, c.card)).toBeGreaterThanOrEqual(4.5);
  });

  test('api_005 every status badge says a word, not only a colour', async () => {
    for (const path of ['/#/', '/#/lists', '/#/upstreams', '/#/cluster', '/#/groups']) {
      await page.goto(path);
      await expect(page.locator('main')).toBeVisible();
      await page.waitForTimeout(400);
      const empty = await page.locator('.badge.ok, .badge.bad, .badge.warn').evaluateAll((els) =>
        els.filter((e) => !(e.textContent ?? '').trim() && !(e.getAttribute('aria-label') ?? '').trim()).length,
      );
      expect(empty, `badges without a word on ${path}`).toBe(0);
    }
  });
});

test.describe('dark system', () => {
  test.beforeAll(async ({ browser }) => {
    await open(browser, 'dark');
  });
  test.afterAll(async () => {
    await ctx.close();
  });

  test('api_005 Night follows the system, and a viewer who chose Day keeps Day', async () => {
    expect(await bodyBg()).toBe(rgb(color('surface', 'dark')));
    expect(await page.evaluate(() => document.documentElement.dataset.theme ?? '')).toBe('');
    await expect(page.locator('nav.side [data-testid="logo"] img.night').first()).toBeVisible();
    // System -> Night -> Day: an explicit Day beats the system's Night.
    await toggle().click();
    await toggle().click();
    await expect(toggle()).toHaveAttribute('aria-label', 'Theme: Day');
    expect(await bodyBg()).toBe(rgb(color('surface', 'light')));
    await expect(page.locator('nav.side [data-testid="logo"] img.day').first()).toBeVisible();
    await page.reload();
    await expect(page.getByRole('heading', { name: 'Dashboard' })).toBeVisible();
    expect(await bodyBg()).toBe(rgb(color('surface', 'light')));
    await toggle().click();
    await expect(toggle()).toHaveAttribute('aria-label', 'Theme: System');
  });

  test('api_005 text and the interactive colour pass AA in Night', async () => {
    const c = await page.evaluate(() => {
      const s = getComputedStyle(document.body);
      const link = document.createElement('a');
      link.href = '#/';
      link.textContent = 'x';
      const card = document.createElement('div');
      card.className = 'card';
      card.append(link);
      document.querySelector('main')!.append(card);
      const out = { text: s.color, bg: s.backgroundColor, link: getComputedStyle(link).color, card: getComputedStyle(card).backgroundColor };
      card.remove();
      return out;
    });
    expect(contrast(c.text, c.bg)).toBeGreaterThanOrEqual(4.5);
    expect(contrast(c.link, c.card)).toBeGreaterThanOrEqual(4.5);
  });
});
