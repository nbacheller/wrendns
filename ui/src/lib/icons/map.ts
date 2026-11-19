// REQ: OBS-039 (ADR-167) — which brand a name belongs to, the colour and letter of a name that has
// none. Pure functions: no network, no storage, nothing here touches the DNS path.
import { BRAND_OF, BRAND_TITLE } from './map.data';

/** Two-label public suffixes the name split keeps together (`bbc.co.uk`, not `co.uk`). */
const TWO_LABEL = new Set([
  'co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'com.au', 'net.au', 'org.au', 'co.nz', 'co.jp', 'ne.jp',
  'or.jp', 'com.br', 'com.cn', 'co.in', 'co.kr', 'com.mx', 'com.tr', 'co.za',
]);

const clean = (name: string) => name.trim().toLowerCase().replace(/\.$/, '');

/** The part of a name that says who owns it: `api.example.com` → `example.com`. */
export function registrable(name: string): string {
  const parts = clean(name).split('.');
  if (parts.length <= 2) return parts.join('.');
  const last2 = parts.slice(-2).join('.');
  return TWO_LABEL.has(last2) ? parts.slice(-3).join('.') : last2;
}

/** The brand a name belongs to, if the map has one: the longest matching suffix wins. */
export function brandFor(name: string): string | null {
  const parts = clean(name).split('.');
  for (let k = 0; k < parts.length - 1; k++) {
    const slug = BRAND_OF[parts.slice(k).join('.')];
    if (slug) return slug;
  }
  return null;
}

export const brandTitle = (slug: string): string => BRAND_TITLE[slug] ?? slug;

const INTERNAL = ['.arpa', '.local', '.lan', '.home', '.internal', '.localdomain', '.corp', '.intranet', '.private', '.svc'];
/** A name of the network itself (a local host, a reverse zone, a Kubernetes service). */
export function isInternal(name: string): boolean {
  const n = clean(name);
  return !n.includes('.') || INTERNAL.some((s) => n.endsWith(s));
}

/**
 * A name the privacy level hid (level 1 and up): one label, `h` and 16 hex digits. It names
 * nothing, so it wears no icon (and must not pass for a name of the network itself).
 */
export const isHashed = (name: string): boolean => /^h[0-9a-f]{16}$/.test(clean(name));

/** A hue (0–359) from the name's registrable part: the same owner always gets the same colour. */
export function hueOf(reg: string): number {
  let h = 0x811c9dc5;
  for (let i = 0; i < reg.length; i++) {
    h ^= reg.charCodeAt(i);
    h = Math.imul(h, 0x01000193) >>> 0;
  }
  return h % 360;
}

/** The letter a name wears: the first of its owner's label (`www.bbc.co.uk` → B, `cdn.nx.example` → N). */
export function letterOf(reg: string): string {
  const parts = reg.split('.');
  const label = parts[0] === 'www' && parts.length > 1 ? parts[1] : (parts[0] ?? '');
  return (label.charAt(0) || '·').toUpperCase();
}

/** Relative luminance of a `RRGGBB` colour (0 black … 1 white). */
export function luminance(hex: string): number {
  const c = [0, 2, 4].map((i) => parseInt(hex.slice(i, i + 2), 16) / 255);
  const lin = c.map((v) => (v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4));
  return 0.2126 * lin[0] + 0.7152 * lin[1] + 0.0722 * lin[2];
}

/** The glyph colour that reads on a brand tile. */
export const inkFor = (hex: string): string => (luminance(hex) > 0.4 ? '#111418' : '#ffffff');
