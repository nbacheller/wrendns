// REQ: OBS-039 (ADR-167) — the domain icon choice, remembered per user in this browser (like the
// detail level, `mode.svelte.ts`): nothing is stored on the server, so it never reaches the
// cluster or the configuration.
import { session } from '../session.svelte';
import { DEFAULT_PREFS, parsePrefs, type IconPrefs } from './prefs';

function key(): string {
  return `telltale.icons.${session.user?.username ?? ''}`;
}

export const iconPrefs = $state<IconPrefs>({ ...DEFAULT_PREFS });

/** Loads the signed-in user's choice (App calls this whenever the user changes). */
export function loadIconPrefs(): void {
  let raw: string | null = null;
  try {
    raw = localStorage.getItem(key());
  } catch {
    // No storage (blocked, private window): the default applies.
  }
  Object.assign(iconPrefs, parsePrefs(raw));
}

export function setIconPrefs(p: Partial<IconPrefs>): void {
  Object.assign(iconPrefs, p);
  try {
    localStorage.setItem(key(), JSON.stringify({ style: iconPrefs.style, size: iconPrefs.size }));
  } catch {
    // Private mode: the choice lasts for this page only.
  }
}
