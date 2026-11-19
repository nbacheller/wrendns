// REQ: OBS-039 (ADR-167) — what a person chose for domain icons, and how a stored choice is read
// back. Pure, so it can be tested without a browser; `prefs.svelte.ts` keeps the live value.

/** Brand tiles with a monogram for the rest, a monogram for every name, or no icons. */
export type IconStyle = 'brand' | 'mono' | 'off';
export type IconSize = 'default' | 'small';
export interface IconPrefs {
  style: IconStyle;
  size: IconSize;
}

export const DEFAULT_PREFS: IconPrefs = { style: 'brand', size: 'default' };

/** The mark's side, in pixels. */
export const ICON_PX: Record<IconSize, number> = { default: 20, small: 16 };

/** A stored choice (JSON text) as preferences; anything unreadable or unknown falls back to the default. */
export function parsePrefs(raw: string | null): IconPrefs {
  try {
    const v = JSON.parse(raw ?? '') as Partial<IconPrefs> | null;
    return {
      style: v?.style === 'mono' || v?.style === 'off' || v?.style === 'brand' ? v.style : DEFAULT_PREFS.style,
      size: v?.size === 'small' ? 'small' : 'default',
    };
  } catch {
    return { ...DEFAULT_PREFS };
  }
}
