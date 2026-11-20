// SPDX-License-Identifier: AGPL-3.0-or-later
// REQ: UI-*, DOC-006 (T33.6, ADR-1042) — the focus ring on an SVG control (a map node, a topology
// chip), which can't take a CSS outline: its own `rect.ring`, 2px of `focus-ring` centred 3px outside
// the control's edge (so it covers 2px to 4px out), drawn on keyboard focus and never on hover.
import type { Locator, Page } from '@playwright/test';

export interface RectRing {
  focusVisible: boolean;
  stroke: string;
  /** `--focus` as the browser computes it. */
  want: string;
  width: string;
  /** How far the ring's centre line sits outside the control: left, top, and the growth in width and height. */
  gap: number[];
}

/** Focuses `target` (a `<g>` with a `rect` and a `rect.ring`) as the keyboard would and reads its ring. */
export async function rectRing(page: Page, target: Locator): Promise<RectRing> {
  await page.keyboard.press('Shift');
  await target.focus();
  return target.evaluate((g) => {
    const probe = document.createElement('div');
    probe.style.color = 'var(--focus)';
    document.body.append(probe);
    const want = getComputedStyle(probe).color;
    probe.remove();
    const base = g.querySelector('rect:not(.ring)') as SVGRectElement;
    const ring = g.querySelector('rect.ring') as SVGRectElement;
    const s = getComputedStyle(ring);
    const b = base.getBBox();
    const r = ring.getBBox();
    return { focusVisible: g.matches(':focus-visible'), stroke: s.stroke, want, width: s.strokeWidth, gap: [b.x - r.x, b.y - r.y, r.width - b.width, r.height - b.height] };
  });
}

/** The ring's stroke while the pointer is over `target` and it doesn't have focus. */
export async function hoverRing(page: Page, target: Locator): Promise<string> {
  await target.evaluate((el) => (el as SVGElement).blur());
  await target.hover();
  return target.evaluate((g) => getComputedStyle(g.querySelector('rect.ring') as SVGRectElement).stroke);
}
