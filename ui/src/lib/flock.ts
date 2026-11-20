// SPDX-License-Identifier: AGPL-3.0-or-later
// REQ: API-005, DOC-006 (T33.6, ADR-1040) — a group's colour: the brand's flock-1 to flock-5 in the
// groups' configured order, then flock-other (also for `default`, the ungrouped devices). A group
// keeps its colour when filters change. The server fills in that colour (in its Day value) for a
// group without one; here it becomes the token, so Night shows Night's. A `color` set explicitly
// to anything else wins as it is.
type G = { name: string; color?: string | null };

/** What the server gives a group with no colour of its own: the flock's Day values (brand/tokens.json). */
const DAY = ['#226fb3', '#d55c13', '#894d97', '#33903c', '#a63f66', '#5b6b7c'];

/** The group's colour as a CSS custom property name (`--brand-flock-2`), or its configured colour. */
export function flock(groups: G[], name: string | null | undefined): string {
  const g = groups.find((x) => x.name === name);
  const j = DAY.indexOf((g?.color ?? '').toLowerCase());
  if (j >= 0) return j < 5 ? `--brand-flock-${j + 1}` : '--brand-flock-other';
  if (g?.color) return g.color;
  const i = groups.filter((x) => x.name !== 'default').findIndex((x) => x.name === name);
  return i >= 0 && i < 5 ? `--brand-flock-${i + 1}` : '--brand-flock-other';
}

/** The same, ready for a style value. */
export const flockCss = (groups: G[], name: string | null | undefined): string => {
  const c = flock(groups, name);
  return c.startsWith('--') ? `var(${c})` : c;
};
