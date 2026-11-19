// REQ: FLT-901, FLT-902 (T24.29, ADR-994, ADR-995) — what the Categories view and the profile editor
// share: the cost the API reports, the sizes in words, and the choices a profile makes.
import type { S } from './api';

/** What `GET /categories` and `GET /categories/budget` report for a selection (the server's `Budget`). */
export type Budget = {
  sources: string[];
  entries: number;
  snapshotBytes: number;
  compilePeakBytes: number;
  baselineRssBytes: number;
  neededBytes: number;
  allowedBytes?: number | null;
  memoryLimitBytes?: number | null;
  mergeBudgetBytes: number;
  heavy: string[];
  overBudgetAlone: string[];
  dailyDownloadBytes: number;
  entryBudget: number;
  overBudget: boolean;
  refused: boolean;
  reasons: string[];
};

export const asBudget = (b: unknown): Budget => b as Budget;

export type Level = 'off' | 'basic' | 'enhanced';

/** What a profile selects: the level, the categories (kept when off), the tiers, and ad block. */
export type Choice = { level: Level; categories: string[]; tiers: Record<string, string>; ads: boolean };

export const emptyChoice = (): Choice => ({ level: 'off', categories: [], tiers: {}, ads: false });

/** The names of the engines safe search can cover, the first three as UniFi shows them. */
export const ENGINES: { id: string; name: string; more?: boolean }[] = [
  { id: 'google', name: 'Google' },
  { id: 'bing', name: 'Bing' },
  { id: 'youtube', name: 'YouTube' },
  { id: 'duckduckgo', name: 'DuckDuckGo', more: true },
  { id: 'yandex', name: 'Yandex', more: true },
  { id: 'pixabay', name: 'Pixabay', more: true },
];

/** Bytes in the largest unit that keeps the number short ("27.9 MiB"). */
export function size(n: number): string {
  if (n >= 1 << 30) return `${(n / (1 << 30)).toFixed(1)} GiB`;
  if (n >= 1 << 20) return `${(n / (1 << 20)).toFixed(n >= 100 << 20 ? 0 : 1)} MiB`;
  if (n >= 1 << 10) return `${Math.round(n / (1 << 10))} KiB`;
  return `${n} B`;
}

/** Entries with thousands separators ("2,438,879"). */
export const entriesText = (n: number) => n.toLocaleString('en-US');

/** "About 28 MiB" for a count of entries, at the catalog's 12 bytes per distinct domain. */
export const snapshotText = (entries: number) => `about ${size(entries * 12)}`;

type Cat = S['CategoryView'];

/** The sources a category uses at `tier` (its own, plus the chosen tier's; the ads tier is a setting). */
export function sourcesOf(c: Cat, tier: string | undefined, adsTier = 'pro'): string[] {
  const out = [...c.sources];
  const want = c.tierFrom === 'adsTier' ? adsTier.replace('_', '-') : (tier ?? c.defaultTier ?? undefined);
  const t = c.tiers.find((x) => x.id === want);
  if (t) out.push(...t.sources);
  return out;
}

/** True when the category at that tier needs a heavy source (NRD 7 days, the full threat feed). */
export function isHeavyNow(c: Cat, tier: string | undefined, sources: Map<string, S['SourceView']>, adsTier = 'pro'): boolean {
  return sourcesOf(c, tier, adsTier).some((id) => sources.get(id)?.weight === 'heavy');
}

/** What `level` selects: the preset's categories for basic, the picked ones for enhanced, none for off. */
export function effective(view: S['CategoriesView'], c: Choice): string[] {
  if (c.level === 'off') return [];
  if (c.level === 'basic') return view.presets.find((p) => p.id === 'basic')?.categories ?? [];
  return c.categories;
}

/** The profile list's Filter Scope: "Off", "Basic", "Enhanced (3 of 20)", with "Ad block" when on. */
export function scopeText(view: S['CategoriesView'] | null, g: S['GroupInfo']): string {
  const base = g.filterScope || 'Off';
  void view;
  return base;
}
