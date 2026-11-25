// REQ: API-005, DOC-006 (T33.2, ADR-1030) — the brand in the UI: the tokens from brand/tokens.json as
// CSS variables for Day and Night (the system's choice, and the header's toggle kept per viewer),
// Figtree and IBM Plex Mono, the logo files (byte for byte from brand/logos) and the app icon as the
// favicon, and status colours that always come with a word. T33.6 (the brand pass): the focus ring on
// every kind of control in both themes, status badges with a word on their tint, disabled controls
// that aren't faded, and reduced motion. These tests sign in as the admin
// `1-ui.spec.ts` created; the file is named `9-z` so it runs after it and after `9-categories.spec.ts`, whose timing it must not shift.
import { expect, test, type BrowserContext, type Page } from '@playwright/test';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { E2E_ROOT } from './ports';
import { flockCss } from '../../src/lib/flock';

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

async function open(browser: import('@playwright/test').Browser, colorScheme: 'light' | 'dark', reducedMotion: 'reduce' | 'no-preference' = 'no-preference') {
  ctx = await browser.newContext({ colorScheme, reducedMotion });
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

// REQ: API-005, DOC-006 (T33.6) — the brand pass, in Day and Night.
/** The ring the focused element (or the box it sits in, for the header's search) shows. */
async function ringOf(target: import('@playwright/test').Locator, ringOn?: string) {
  // Keyboard modality first, so a programmatic focus counts as keyboard focus (:focus-visible).
  await page.keyboard.press('Shift');
  await target.focus();
  return target.evaluate((el, sel) => {
    const ringEl = sel ? (el.closest(sel) as Element) : el;
    const s = getComputedStyle(ringEl);
    const bg = (e: Element | null): string => {
      for (let x = e; x; x = x.parentElement) {
        const c = getComputedStyle(x).backgroundColor;
        if (c !== 'rgba(0, 0, 0, 0)' && c !== 'transparent') return c;
      }
      return getComputedStyle(document.body).backgroundColor;
    };
    return {
      visible: el.matches(':focus-visible') || !!sel,
      style: s.outlineStyle,
      width: s.outlineWidth,
      offset: s.outlineOffset,
      color: s.outlineColor,
      around: bg(ringEl.parentElement),
    };
  }, ringOn);
}

for (const theme of ['light', 'dark'] as const) {
  test.describe(`brand pass (${theme})`, () => {
    test.beforeAll(async ({ browser }) => {
      await open(browser, theme);
    });
    test.afterAll(async () => {
      await ctx.close();
    });

    test(`api_005 doc_006 the focus ring is 2px of focus-ring, 2px outside, on every kind of control (${theme})`, async () => {
      await page.goto('/#/');
      await expect(page.getByRole('heading', { name: 'Dashboard' })).toBeVisible();
      const want = rgb(color('focus-ring', theme));
      const controls: [string, import('@playwright/test').Locator, string?][] = [
        ['a nav link', page.locator('nav.side a.nav').nth(1)],
        ['a segmented button', page.getByRole('group', { name: 'Detail level', exact: true }).getByRole('button', { name: 'Simple' })],
        ['an icon button', page.getByTestId('theme-toggle')],
        ['a switch', page.locator('input[role="switch"]').first()],
        ['a picker', page.getByRole('group', { name: 'Group', exact: true }).getByRole('combobox'), '.box'],
        ['the search box', page.getByLabel('Search names or clients'), '.search'],
      ];
      for (const [what, loc, ringOn] of controls) {
        await expect(loc, what).toBeVisible();
        const r = await ringOf(loc, ringOn);
        expect(r.visible, `${what} matches :focus-visible`).toBe(true);
        expect([r.style, r.width, r.offset, r.color], `${what}'s ring`).toEqual(['solid', '2px', '2px', want]);
        expect(contrast(r.color, r.around), `${what}'s ring against what is around it`).toBeGreaterThanOrEqual(3);
      }
      // A native select (the Queries page's Match; the dashboard's own are pickers now).
      await page.goto('/#/queries');
      const select = page.locator('main select[name="match"]');
      await expect(select, 'a select').toBeVisible();
      const sr = await ringOf(select);
      expect(sr.visible, 'a select matches :focus-visible').toBe(true);
      expect([sr.style, sr.width, sr.offset, sr.color], "a select's ring").toEqual(['solid', '2px', '2px', want]);
      expect(contrast(sr.color, sr.around), "a select's ring against what is around it").toBeGreaterThanOrEqual(3);
      // A tab (the Clients page) and a primary button (Names on your network).
      await page.goto('/#/clients');
      const tab = page.getByRole('tab').first();
      await expect(tab).toBeVisible();
      const t = await ringOf(tab);
      expect([t.style, t.width, t.offset, t.color], 'a tab').toEqual(['solid', '2px', '2px', want]);
      await page.goto('/#/local-dns');
      const primary = page.getByRole('button', { name: 'Set up your home domain', exact: true });
      await expect(primary).toBeVisible();
      const p = await ringOf(primary);
      expect([p.style, p.width, p.offset, p.color], 'a primary button').toEqual(['solid', '2px', '2px', want]);
    });

    test(`api_005 doc_006 status badges carry a word, on their own tint (${theme})`, async () => {
      for (const path of ['/#/', '/#/queries', '/#/lists', '/#/upstreams', '/#/cluster', '/#/groups', '/#/clients', '/#/settings?tab=system']) {
        await page.goto(path);
        await expect(page.locator('main')).toBeVisible();
        await page.waitForTimeout(400);
        const bad = await page.locator('.badge.ok, .badge.bad, .badge.warn').evaluateAll((els) =>
          els
            .filter((e) => !(e.textContent ?? '').trim() && !(e.getAttribute('aria-label') ?? '').trim())
            .map((e) => e.outerHTML.slice(0, 80)),
        );
        expect(bad, `badges without a word on ${path}`).toEqual([]);
      }
      // Each tone: the status colour on its -soft tint.
      const tones = await page.evaluate(() =>
        ['ok', 'warn', 'bad'].map((tone) => {
          const b = document.createElement('span');
          b.className = `badge ${tone}`;
          b.textContent = tone;
          document.querySelector('main')!.append(b);
          const s = getComputedStyle(b);
          const out = [s.color, s.backgroundColor];
          b.remove();
          return out;
        }),
      );
      const names = [
        ['ok', 'ok-soft'],
        ['warn', 'warn-soft'],
        ['alert', 'alert-soft'],
      ];
      tones.forEach(([fg, bg], i) => {
        expect([fg, bg]).toEqual([rgb(color(names[i][0], theme)), rgb(color(names[i][1], theme))]);
        expect(contrast(fg, bg), `${names[i][0]} on its tint`).toBeGreaterThanOrEqual(4.5);
      });
    });

    // REQ: UI-*, DOC-006 (T33.6, ADR-1040) — groups in the flock's order, in this theme's values: a
    // group the server gave a Day flock colour shows the theme's own token.
    test(`api_005 doc_006 group colours are the flock, in order, in this theme (${theme}) [T33.6]`, async () => {
      const names = ['flock-1', 'flock-2', 'flock-3', 'flock-4', 'flock-5', 'flock-other'];
      const groups = [...names.slice(0, 5).map((_, i) => ({ name: `g${i + 1}`, color: color(names[i], 'light') })), { name: 'g6' }, { name: 'default' }];
      const vars = ['g1', 'g2', 'g3', 'g4', 'g5', 'g6', 'default'].map((g) => flockCss(groups, g));
      expect(vars).toEqual([...names.slice(0, 5).map((n) => `var(--brand-${n})`), 'var(--brand-flock-other)', 'var(--brand-flock-other)']);
      const shown = await page.evaluate((vs) => {
        const d = document.createElement('div');
        document.body.append(d);
        const out = vs.map((v) => ((d.style.color = v), getComputedStyle(d).color));
        d.remove();
        return out;
      }, vars.slice(0, 6));
      expect(shown).toEqual(names.map((n) => rgb(color(n, theme))));
    });

    test(`api_005 doc_006 disabled controls are muted with a hairline edge, never faded (${theme})`, async () => {
      await page.goto('/#/lists');
      await expect(page.locator('main')).toBeVisible();
      const looks = await page.evaluate(() => {
        const main = document.querySelector('main')!;
        const made = ['<button disabled>Off</button>', '<button class="primary" disabled>Off</button>', '<input disabled value="off">', '<select disabled><option>off</option></select>'].map(
          (h) => {
            const t = document.createElement('template');
            t.innerHTML = h;
            const el = t.content.firstElementChild as HTMLElement;
            main.append(el);
            const s = getComputedStyle(el);
            const out = { opacity: s.opacity, color: s.color, border: s.borderTopColor };
            el.remove();
            return out;
          },
        );
        // And every disabled control the page shows.
        const real = [...document.querySelectorAll('button:disabled, input:disabled, select:disabled, textarea:disabled')].map((e) => {
          let o = 1;
          for (let x: Element | null = e; x; x = x.parentElement) o *= Number(getComputedStyle(x).opacity);
          return o;
        });
        return { made, real };
      });
      for (const m of looks.made) {
        expect(m).toEqual({ opacity: '1', color: rgb(color('ink-muted', theme)), border: rgb(color('line', theme)) });
      }
      expect(looks.real.filter((o) => o < 1), 'disabled controls drawn with opacity').toEqual([]);
    });
  });
}

test.describe('reduced motion', () => {
  test.beforeAll(async ({ browser }) => {
    await open(browser, 'light', 'reduce');
  });
  test.afterAll(async () => {
    await ctx.close();
  });

  test('api_005 doc_006 reduced motion turns every transition and animation off', async () => {
    for (const path of ['/#/', '/#/traffic', '/#/cluster', '/#/settings?tab=system']) {
      await page.goto(path);
      await expect(page.locator('main')).toBeVisible();
      await page.waitForTimeout(300);
      const moving = await page.evaluate(() =>
        [...document.querySelectorAll('*')]
          .filter((e) => {
            const s = getComputedStyle(e);
            const secs = (v: string) => Math.max(...v.split(',').map((x) => parseFloat(x) || 0));
            return secs(s.transitionDuration) > 0 || (s.animationName !== 'none' && secs(s.animationDuration) > 0);
          })
          .map((e) => `${e.tagName.toLowerCase()}.${[...e.classList].join('.')}`),
      );
      expect(moving, `moving things on ${path}`).toEqual([]);
    }
  });

  test('api_005 doc_006 without it, things move in the one motion: 160 ms ease-out', async ({ browser }) => {
    const c = await browser.newContext({ storageState: await ctx.storageState() });
    const p = await c.newPage();
    await p.goto('/#/');
    const sw = p.locator('input[role="switch"]').first();
    await expect(sw).toBeVisible();
    expect(await sw.evaluate((e) => [getComputedStyle(e).transitionDuration, getComputedStyle(e).transitionTimingFunction])).toEqual(['0.16s', 'ease-out']);
    await c.close();
  });
});
