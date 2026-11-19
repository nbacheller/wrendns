// REQ: API-005, DOC-006 (T33.6, ADR-1040) — a group's colour: the brand's flock-1 to flock-5 in the
// groups' configured order, then flock-other (also for `default`, the ungrouped devices). A group
// keeps its colour when filters change. A `color` set explicitly in the configuration wins.
type G = { name: string; color?: string | null };

/** The group's colour as a CSS custom property name (`--brand-flock-2`), or its configured colour. */
export function flock(groups: G[], name: string | null | undefined): string {
  const g = groups.find((x) => x.name === name);
  if (g?.color) return g.color;
  const i = groups.filter((x) => x.name !== 'default').findIndex((x) => x.name === name);
  return i >= 0 && i < 5 ? `--brand-flock-${i + 1}` : '--brand-flock-other';
}

/** The same, ready for a style value. */
export const flockCss = (groups: G[], name: string | null | undefined): string => {
  const c = flock(groups, name);
  return c.startsWith('--') ? `var(${c})` : c;
};
