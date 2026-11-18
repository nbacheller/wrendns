// REQ: FLT-006 (T24.9, ADR-973) — a router's name for a device, in the label form the server
// matches (`hostname:<label>`): "Kitchen Tablet" is `kitchen-tablet`, as device names in DNS are.

/** The label a router name gives: lowercase letters, digits and single dashes, at most 63. */
export function routerLabel(name: string): string {
  return name
    .replace(/['’]/g, '')
    .replace(/[^A-Za-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .toLowerCase()
    .slice(0, 63)
    .replace(/-+$/g, '');
}

/** The match key or rule device for a router name, e.g. `hostname:kitchen-tablet`. */
export const routerKey = (name: string): string => `hostname:${routerLabel(name)}`;

/** Whether a match key or rule device names a router name. */
export const isRouterKey = (s: string): boolean => s.toLowerCase().startsWith('hostname:');

/** The label inside a `hostname:` key. */
export const routerLabelOf = (key: string): string => key.slice('hostname:'.length).toLowerCase();
