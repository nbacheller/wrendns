// REQ: OBS-902 (T26.5, ADR-958 section 8) - the world view's pure parts: the dot grid from the
// land mask, a point per country, the arcs from the network to where answers point, and the words
// for why a view isn't available. No map library, no tiles: the data is baked in `world-data.ts`.
import type { S } from './api';
import { COUNTRY_DATA, GRID, LAND_MASK } from './world-data';
import { pulse, type Health, type Pulse } from './map';

export type World = S['MapWorld'];
export type Region = S['WorldRegion'];
export type Marker = S['WorldMarker'];

/** Pixels a grid cell takes in the drawing. */
export const CELL = 4;
export const MAP_W = GRID.w * CELL;
export const MAP_H = GRID.h * CELL;
/** Room under the map for the "Your network" marker, and above it for the arcs' tops. */
export const PAD_TOP = 36;
export const PAD_BOTTOM = 44;
export const VIEW_W = MAP_W;
export const VIEW_H = PAD_TOP + MAP_H + PAD_BOTTOM;

/** The one place arcs start from when no home country is set. */
export const HOME_POINT = { x: MAP_W / 2, y: PAD_TOP + MAP_H + 24 };

interface Country {
  cc: string;
  name: string;
  lon: number;
  lat: number;
}

let table: Map<string, Country> | null = null;
function countries(): Map<string, Country> {
  if (!table) {
    table = new Map();
    for (const row of COUNTRY_DATA.split(';')) {
      const [cc, name, lon, lat] = row.split('|');
      if (cc) table.set(cc, { cc, name, lon: Number(lon), lat: Number(lat) });
    }
  }
  return table;
}

/** A country's name, or its code when the table doesn't know it. */
export function countryName(cc: string): string {
  return countries().get(cc.toUpperCase())?.name ?? cc.toUpperCase();
}

/** Where a country is drawn (its centre), or null when the table has no point for it. */
export function countryPoint(cc: string): { x: number; y: number } | null {
  const c = countries().get(cc.toUpperCase());
  return c ? project(c.lon, c.lat) : null;
}

export function project(lon: number, lat: number): { x: number; y: number } {
  const x = ((lon - GRID.lonMin) / GRID.step) * CELL;
  const y = PAD_TOP + ((GRID.latMax - lat) / GRID.step) * CELL;
  return { x: Math.round(x * 10) / 10, y: Math.round(y * 10) / 10 };
}

/** The land as one path of small squares (one DOM node, whatever the grid's size). */
export function landPath(): string {
  const bytes = Uint8Array.from(atob(LAND_MASK), (c) => c.charCodeAt(0));
  const out: string[] = [];
  const d = CELL - 1.2;
  for (let r = 0; r < GRID.h; r++) {
    for (let c = 0; c < GRID.w; c++) {
      const i = r * GRID.w + c;
      if ((bytes[i >> 3] >> (i & 7)) & 1) out.push(`M${c * CELL + 0.6} ${PAD_TOP + r * CELL + 0.6}h${d}v${d}h-${d}z`);
    }
  }
  return out.join('');
}

export interface Arc {
  id: string;
  cc: string;
  region: Region;
  d: string;
  /** Where the arc ends: the shape and the label sit here. */
  x: number;
  y: number;
  /** Mid-point, for the rate label when nothing moves. */
  mx: number;
  my: number;
  width: number;
  pulse: Pulse;
  animated: boolean;
}

export interface Placed {
  arcs: Arc[];
  /** Regions the table has no point for (drawn in the table only). */
  unplaced: Region[];
  home: { x: number; y: number; label: string };
}

/** A curve that rises between two points: the longer the way, the higher it goes. */
export function arcPath(x0: number, y0: number, x1: number, y1: number): { d: string; mx: number; my: number } {
  const dist = Math.hypot(x1 - x0, y1 - y0);
  const cx = (x0 + x1) / 2;
  const cy = Math.max(-PAD_TOP + 8, (y0 + y1) / 2 - dist * 0.3);
  // The curve's mid-point (t = 0.5 of a quadratic) is a quarter of the way to the control point.
  const mx = 0.25 * x0 + 0.5 * cx + 0.25 * x1;
  const my = 0.25 * y0 + 0.5 * cy + 0.25 * y1;
  const r = (n: number) => Math.round(n * 10) / 10;
  return { d: `M${r(x0)} ${r(y0)}Q${r(cx)} ${r(cy)} ${r(x1)} ${r(y1)}`, mx: r(mx), my: r(my) };
}

/** The arcs from the network (or the home country) to each country answers point at. */
export function place(w: World, opts: { maxAnimated: number }): Placed {
  const home = w.homeCountry ? countryPoint(w.homeCountry) : null;
  const start = home ?? HOME_POINT;
  const label = home ? `${countryName(w.homeCountry ?? '')} (home)` : 'Your network';
  const arcs: Arc[] = [];
  const unplaced: Region[] = [];
  let n = 0;
  for (const region of w.regions) {
    const p = countryPoint(region.cc);
    if (!p) {
      unplaced.push(region);
      continue;
    }
    // Answers that stay in the home country: a short loop above it, so they are seen.
    const same = home !== null && Math.hypot(p.x - start.x, p.y - start.y) < 6;
    const geo = same ? arcPath(start.x - 10, start.y, start.x + 10, start.y) : arcPath(start.x, start.y, p.x, p.y);
    const id = `arc:${region.cc}`;
    arcs.push({
      id,
      cc: region.cc,
      region,
      d: geo.d,
      x: p.x,
      y: p.y,
      mx: geo.mx,
      my: geo.my,
      width: Math.min(6, Math.round((1 + Math.log10(1 + region.qps) * 2.2) * 100) / 100),
      pulse: pulse(region.qps, id),
      animated: n++ < opts.maxAnimated,
    });
  }
  return { arcs, unplaced, home: { x: start.x, y: start.y, label } };
}

export interface MarkerPlaced {
  id: string;
  name: string;
  cc: string;
  x: number;
  y: number;
  health: Health;
  qps: number;
}

/** Upstream markers at their country, fanned out a little when several share one. */
export function placeMarkers(markers: Marker[]): MarkerPlaced[] {
  const seen = new Map<string, number>();
  const out: MarkerPlaced[] = [];
  for (const m of markers) {
    const cc = (m.cc ?? '').toUpperCase();
    const p = cc ? countryPoint(cc) : null;
    if (!p) continue;
    const k = seen.get(cc) ?? 0;
    seen.set(cc, k + 1);
    const a = (k * 2 * Math.PI) / 5;
    const r = k === 0 ? 0 : 9;
    out.push({
      id: `mk:${m.name}`,
      name: m.name,
      cc,
      x: Math.round((p.x + Math.cos(a) * r) * 10) / 10,
      y: Math.round((p.y + Math.sin(a) * r) * 10) / 10,
      health: m.health,
      qps: m.qps,
    });
  }
  return out;
}

/** What each reason means for the person looking, and what (if anything) they can do. */
export type Why = { code: string; title: string; body: string; admin: boolean };

export function whyUnavailable(reason: string | null | undefined): Why | null {
  switch (reason) {
    case 'geoip_off':
      return {
        code: reason,
        title: 'GeoIP is off',
        body: 'The world view places answers with a country database, which is never bundled and is downloaded only after an admin turns it on.',
        admin: true,
      };
    case 'geoip_missing':
      return {
        code: reason,
        title: 'The GeoIP database is not on this node yet',
        body: 'GeoIP is on, but this node has no database: it is still downloading, the download was not accepted, or it was deleted. The status says which.',
        admin: true,
      };
    case 'address_not_recorded':
      return {
        code: reason,
        title: "Answer addresses aren't recorded",
        body: "TelltaleDNS doesn't keep the address each answer points at (it would make every query-log record bigger on the DNS path), so arcs can't be drawn yet. The upstreams' own locations are shown instead.",
        admin: false,
      };
    case 'privacy':
      return {
        code: reason,
        title: 'Privacy level 3 keeps nothing per lookup',
        body: 'At query-log privacy level 3 only counters are kept, so no answer can be placed.',
        admin: false,
      };
    default:
      return null;
  }
}

/** True when the view shows only where the upstreams are, not where answers point. */
export const upstreamsOnly = (w: World): boolean => w.regions.length === 0 && w.markers.length > 0;

export function summary(w: World, placed: Placed): string {
  if (w.regions.length === 0) return w.markers.length ? `${w.markers.length} upstream locations, no answers placed.` : 'Nothing is placed.';
  const top = w.regions.slice(0, 3).map((r) => `${countryName(r.cc)} ${r.count}`);
  return `${w.regions.length} countries, ${placed.arcs.length} drawn. Busiest: ${top.join(', ')}.`;
}
