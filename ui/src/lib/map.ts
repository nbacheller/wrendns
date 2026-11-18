// REQ: OBS-901 (T26.3, ADR-958 sections 8 to 10) — the network map's pure parts: filtering a
// snapshot, a deterministic layered layout (no graph library, no force simulation), the pulse
// parameters of an edge, the words and shapes of each health, and the table rows. The page
// (`pages/Map.svelte`) draws what this returns; nothing here touches the DOM.
import type { S } from './api';

export type Snapshot = S['MapSnapshot'];
export type MapNode = S['MapNode'];
export type MapEdge = S['MapEdge'];
export type Health = S['MapHealth'];

/** What the filters (the URL's parameters) narrow the map to. Empty means no filter. */
export interface Filters {
  network: string;
  group: string;
  device: string;
  node: string;
  health: '' | Health;
}
export const NO_FILTERS: Filters = { network: '', group: '', device: '', node: '', health: '' };

/** The filters the server narrows (`GET /api/v1/map` takes these four); `health` is the page's own. */
export const serverFilters = (f: Filters): Record<string, string | undefined> => ({
  network: f.network || undefined,
  group: f.group || undefined,
  device: f.device || undefined,
  node: f.node || undefined,
});
export const hasServerFilter = (f: Filters): boolean => !!(f.network || f.group || f.device || f.node);

/** Colour is never alone (NFR-008, ADR-104): each health has its own shape and its own words. */
export const HEALTH_WORDS: Record<Health, string> = {
  green: 'healthy',
  yellow: 'degraded',
  red: 'failing',
  idle: 'idle (too few answers to say)',
};
/** The short word drawn on the node. */
export const HEALTH_SHORT: Record<Health, string> = { green: 'OK', yellow: 'Warning', red: 'Failing', idle: 'Idle' };
/** Circle with a check, triangle, octagon with a cross; idle is a dashed circle. */
export const HEALTH_SHAPE: Record<Health, string> = {
  green: 'M0 -6.5a6.5 6.5 0 1 0 0.01 0zM-3.2 0.2l2.4 2.4 4-4.6',
  yellow: 'M0 -7.2L7 5.6H-7zM0 -2.4v4.4M0 3.9h.01',
  red: 'M-2.7 -6.5h5.4l3.8 3.8v5.4l-3.8 3.8h-5.4l-3.8 -3.8v-5.4zM-2.6 -2.6l5.2 5.2M2.6 -2.6l-5.2 5.2',
  idle: 'M0 -6.5a6.5 6.5 0 1 0 0.01 0zM-3 0h6',
};
export const HEALTH_ORDER: Health[] = ['red', 'yellow', 'green', 'idle'];

export const KIND_WORDS: Record<MapNode['kind'], string> = {
  gateway: 'gateway',
  network: 'network',
  device: 'device',
  more: 'folded devices',
  resolver: 'resolver',
  answer: 'answer kind',
  upstream: 'upstream',
};

/** The five columns, left to right (ADR-958 section 8). */
export const COLUMN: Record<MapNode['kind'], number> = {
  gateway: 0,
  network: 1,
  device: 2,
  more: 2,
  resolver: 3,
  answer: 4,
  upstream: 4,
};
export const COLUMN_TITLES = ['Gateway', 'Networks', 'Devices', 'Resolvers', 'Answers and upstreams'];

// ---------------------------------------------------------------------------------------------
// Filtering

const has = (hay: string | null | undefined, needle: string) => (hay ?? '').toLowerCase().includes(needle.toLowerCase());

/**
 * Narrows a snapshot to the filters, on this side (the stream carries the unfiltered snapshot, and
 * the health filter is the page's own). A filter keeps what it names and what is connected to it
 * (the networks of the devices it keeps, the resolvers they use, their answers and upstreams), so
 * what is left still reads as a map.
 */
export function filterSnapshot(snap: Snapshot, f: Filters): Snapshot {
  const nodes = snap.nodes;
  const edges = snap.edges;
  const none = !f.network && !f.group && !f.device && !f.node && !f.health;
  if (none) return snap;
  const byId = new Map(nodes.map((n) => [n.id, n]));
  const keep = new Set<string>();

  const deviceFilter = !!(f.network || f.group || f.device);
  // Devices (and folds) that pass the device-level filters.
  for (const n of nodes) {
    if (n.kind !== 'device' && n.kind !== 'more') continue;
    if (f.network && n.network !== f.network) continue;
    if (n.kind === 'more') {
      // A fold holds devices that can't be matched by group or text.
      if (f.group || f.device) continue;
    } else {
      if (f.group && n.group !== f.group) continue;
      if (f.device && !has(n.label, f.device) && !has(n.address, f.device)) continue;
    }
    keep.add(n.id);
  }
  // Resolvers: the named node, or any when no node is named.
  const resolvers = nodes.filter((n) => n.kind === 'resolver' && (!f.node || n.node === f.node));
  const resolverIds = new Set(resolvers.map((n) => n.id));
  // With a node filter, a device stays only when it uses that node.
  if (f.node) {
    const using = new Set(edges.filter((e) => resolverIds.has(e.to) && !e.structural).map((e) => e.from));
    for (const id of [...keep]) if (!using.has(id)) keep.delete(id);
    // No device-level filter and a node filter: every device of the node.
    if (!deviceFilter) for (const n of nodes) if ((n.kind === 'device' || n.kind === 'more') && using.has(n.id)) keep.add(n.id);
  }
  // Resolvers connected from a kept device (when devices are filtered); else the named ones.
  const usedResolvers = new Set<string>();
  if (deviceFilter || f.node) {
    for (const e of edges) if (!e.structural && keep.has(e.from) && resolverIds.has(e.to)) usedResolvers.add(e.to);
    // Devices hidden at privacy 2 and an unfiltered device list still show the named resolver.
    if (f.node && !deviceFilter) for (const id of resolverIds) usedResolvers.add(id);
    if (f.node && deviceFilter) for (const id of resolverIds) if (usedResolvers.size === 0) usedResolvers.add(id);
  } else for (const id of resolverIds) usedResolvers.add(id);
  for (const id of usedResolvers) keep.add(id);
  // Terminals of a kept resolver.
  for (const e of edges) if (usedResolvers.has(e.from) && byId.get(e.to) && ['answer', 'upstream'].includes(byId.get(e.to)!.kind)) keep.add(e.to);
  // Networks: those holding a kept device, the one named, or all when no device is filtered.
  for (const n of nodes) {
    if (n.kind !== 'network') continue;
    const name = n.id.replace(/^net:/, '');
    const holds = edges.some((e) => e.structural && e.from === n.id && keep.has(e.to));
    if (holds || (f.network && (name === f.network || n.label === f.network)) || (!deviceFilter && !f.node)) keep.add(n.id);
  }
  // Networks of a node filter: only those with a kept device.
  if (f.node && !deviceFilter) {
    for (const n of nodes) if (n.kind === 'network' && !edges.some((e) => e.structural && e.from === n.id && keep.has(e.to))) keep.delete(n.id);
  }
  if (f.network) for (const n of nodes) if (n.kind === 'network' && n.id !== `net:${f.network}` && n.label !== f.network) keep.delete(n.id);
  // The gateway stays while any network does.
  for (const n of nodes) if (n.kind === 'gateway' && [...keep].some((id) => byId.get(id)?.kind === 'network')) keep.add(n.id);

  // The health filter: the nodes of that health, with their neighbours for context.
  if (f.health) {
    const core = new Set(nodes.filter((n) => keep.has(n.id) && n.health === f.health).map((n) => n.id));
    const withContext = new Set(core);
    for (const e of edges) {
      if (!keep.has(e.from) || !keep.has(e.to)) continue;
      if (core.has(e.from)) withContext.add(e.to);
      if (core.has(e.to)) withContext.add(e.from);
    }
    for (const id of [...keep]) if (!withContext.has(id)) keep.delete(id);
  }

  const outNodes = nodes.filter((n) => keep.has(n.id));
  const outEdges = edges.filter((e) => keep.has(e.from) && keep.has(e.to));
  return { ...snap, nodes: outNodes, edges: outEdges };
}

// ---------------------------------------------------------------------------------------------
// Layout

export const NODE_W = 156;
export const NODE_H = 30;
export const COL_GAP = 206;
export const ROW_GAP = 40;
export const PAD_X = 10;
export const PAD_TOP = 34;

export interface PlacedNode {
  node: MapNode;
  x: number;
  y: number;
  col: number;
  /** The words a screen reader gets: name, kind, state, rate. */
  label: string;
}
export interface PlacedEdge {
  edge: MapEdge;
  id: string;
  d: string;
  /** Midpoint, for the rate label under reduced motion. */
  mx: number;
  my: number;
  structural: boolean;
  /** Pulse parameters; null for a structural edge or one with no rate. */
  pulse: Pulse | null;
  /** Whether this edge is among the busiest that animate (the others are drawn static). */
  animated: boolean;
}
export interface Layout {
  nodes: PlacedNode[];
  edges: PlacedEdge[];
  width: number;
  height: number;
}

export const rate = (qps: number): string => (qps >= 10 ? qps.toFixed(0) : qps >= 1 ? qps.toFixed(1) : qps.toFixed(2)) + '/s';

export function nodeLabel(n: MapNode): string {
  const rates = n.kind === 'gateway' || n.kind === 'network' ? '' : `, ${rate(n.qps)}`;
  return `${n.label}, ${KIND_WORDS[n.kind]}, ${HEALTH_WORDS[n.health]}${rates}`;
}

const stableSort = <T,>(a: T[], cmp: (x: T, y: T) => number): T[] => a.map((v, i) => [v, i] as const).sort((p, q) => cmp(p[0], q[0]) || p[1] - q[1]).map((p) => p[0]);

/**
 * The layered layout: gateway, networks, devices, resolvers, then answer kinds and upstreams.
 * Devices are ordered by network then rate (the busiest first), every other column follows from
 * them, and nothing moves between two snapshots unless the data does.
 */
export function layout(snap: Snapshot, opts: { maxAnimated: number }): Layout {
  const nodes = snap.nodes;
  const byId = new Map(nodes.map((n) => [n.id, n]));
  const netOrder = nodes.filter((n) => n.kind === 'network').map((n) => n.id);
  // Which network a device or fold sits under: its structural edge, else its `network` field.
  const netOf = new Map<string, string>();
  for (const e of snap.edges) if (e.structural && byId.get(e.from)?.kind === 'network') netOf.set(e.to, e.from);
  for (const n of nodes) if (!netOf.has(n.id) && n.network) netOf.set(n.id, `net:${n.network}`);
  const netIndex = (id: string) => {
    const i = netOrder.indexOf(netOf.get(id) ?? '');
    return i < 0 ? netOrder.length : i;
  };

  const devices = stableSort(
    nodes.filter((n) => n.kind === 'device' || n.kind === 'more'),
    // A network's devices busiest first, its fold last.
    (a, b) => netIndex(a.id) - netIndex(b.id) || Number(a.kind === 'more') - Number(b.kind === 'more') || b.qps - a.qps,
  );
  const resolvers = nodes.filter((n) => n.kind === 'resolver');
  const answers = stableSort(
    nodes.filter((n) => n.kind === 'answer'),
    (a, b) => resolvers.findIndex((r) => r.node === a.node) - resolvers.findIndex((r) => r.node === b.node),
  );
  const upstreams = stableSort(nodes.filter((n) => n.kind === 'upstream'), (a, b) => b.qps - a.qps);

  const pos = new Map<string, { x: number; y: number; col: number }>();
  const colX = (c: number) => PAD_X + c * COL_GAP;
  const put = (n: MapNode, y: number) => pos.set(n.id, { x: colX(COLUMN[n.kind]), y, col: COLUMN[n.kind] });

  // Devices: one row each. The terminals column is answers, a gap, then upstreams.
  devices.forEach((n, i) => put(n, PAD_TOP + i * ROW_GAP));
  const terminals = [...answers, ...upstreams];
  const rows = Math.max(devices.length, terminals.length + (answers.length && upstreams.length ? 1 : 0), resolvers.length, netOrder.length, 1);
  const bodyH = (rows - 1) * ROW_GAP;
  // Spreads a column over the full height when it has fewer rows than the tallest.
  const spread = (list: MapNode[], gap = 0) => {
    const count = list.length + gap;
    const step = count > 1 ? Math.min(bodyH / (count - 1), ROW_GAP * 2.5) : 0;
    const used = step * (count - 1);
    const top = PAD_TOP + (bodyH - used) / 2;
    let i = 0;
    for (const n of list) {
      if (gap && n.kind === 'upstream' && i === answers.length) i += gap;
      put(n, top + i * step);
      i++;
    }
  };
  spread(terminals, answers.length && upstreams.length ? 1 : 0);
  spread(resolvers);

  // Networks: the middle of their devices, pushed apart where they would touch.
  const netsPlaced: { n: MapNode; y: number }[] = [];
  for (const id of netOrder) {
    const n = byId.get(id)!;
    const ys = devices.filter((d) => netOf.get(d.id) === id).map((d) => pos.get(d.id)!.y);
    const y = ys.length ? (Math.min(...ys) + Math.max(...ys)) / 2 : NaN;
    netsPlaced.push({ n, y });
  }
  let last = PAD_TOP - ROW_GAP;
  netsPlaced.forEach((p, i) => {
    let y = Number.isNaN(p.y) ? (i === 0 ? PAD_TOP : last + ROW_GAP) : p.y;
    if (y < last + ROW_GAP) y = last + ROW_GAP;
    last = y;
    put(p.n, y);
  });
  // The gateway: the middle of the networks.
  const gw = nodes.find((n) => n.kind === 'gateway');
  if (gw) {
    const ys = netOrder.map((id) => pos.get(id)!.y);
    put(gw, ys.length ? (Math.min(...ys) + Math.max(...ys)) / 2 : PAD_TOP);
  }
  // Anything of an unknown kind (a newer server) goes in the last column, under the rest.
  let extra = 0;
  for (const n of nodes) if (!pos.has(n.id)) pos.set(n.id, { x: colX(4), y: PAD_TOP + (rows + 1 + extra++) * ROW_GAP, col: 4 });

  const placed: PlacedNode[] = nodes.map((n) => ({ node: n, ...pos.get(n.id)!, label: nodeLabel(n) }));
  const height = Math.max(...placed.map((p) => p.y + NODE_H), PAD_TOP + NODE_H) + 12;
  const width = colX(4) + NODE_W + PAD_X;

  // Edges: a cubic curve from a node's right side to the next one's left; the busiest animate.
  const rated = snap.edges.filter((e) => !e.structural && e.qps > 0).sort((a, b) => b.qps - a.qps);
  const animate = new Set(rated.slice(0, Math.max(0, opts.maxAnimated)).map(edgeId));
  const placedEdges: PlacedEdge[] = [];
  for (const e of snap.edges) {
    const a = pos.get(e.from);
    const b = pos.get(e.to);
    if (!a || !b) continue;
    const forward = b.x >= a.x;
    const x0 = forward ? a.x + NODE_W : a.x;
    const x1 = forward ? b.x : b.x + NODE_W;
    const y0 = a.y + NODE_H / 2;
    const y1 = b.y + NODE_H / 2;
    const k = Math.max(24, Math.abs(x1 - x0) / 2);
    const dir = forward ? 1 : -1;
    const d = `M${x0} ${y0}C${x0 + k * dir} ${y0} ${x1 - k * dir} ${y1} ${x1} ${y1}`;
    const id = edgeId(e);
    placedEdges.push({
      edge: e,
      id,
      d,
      mx: (x0 + x1) / 2,
      my: (y0 + y1) / 2,
      structural: e.structural,
      pulse: e.structural || e.qps <= 0 ? null : pulse(e.qps, id),
      animated: animate.has(id),
    });
  }
  return { nodes: placed, edges: placedEdges, width, height };
}

export const edgeId = (e: Pick<MapEdge, 'from' | 'to'>): string => `${e.from}>${e.to}`;

// ---------------------------------------------------------------------------------------------
// Pulses (ADR-958 section 9)

export interface Pulse {
  /** Dashes along the edge: one per half query a second, 1 to 6. */
  dashes: number;
  /** Stroke width, from the log of the rate. */
  width: number;
  /** Length of one dash and of the gap, in `pathLength = 100` units. */
  dash: number;
  gap: number;
  /** One period of the animation, in seconds, and the negative delay a seed gives. */
  seconds: number;
  delay: number;
}

/** A small stable hash in [0, 1): the same edge always starts at the same phase, so a refresh doesn't restart it. */
export function seed(id: string): number {
  let h = 2166136261;
  for (let i = 0; i < id.length; i++) {
    h ^= id.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return (h >>> 0) / 4294967296;
}

export function pulse(qps: number, id: string): Pulse {
  const dashes = Math.min(6, Math.max(1, Math.ceil(qps * 2)));
  const period = 100 / dashes;
  const dash = period * 0.32;
  const width = Math.min(6, 1.4 + Math.log10(1 + qps) * 2.2);
  const seconds = 2.4 + seed(`s${id}`) * 1.2;
  return { dashes, width: Math.round(width * 100) / 100, dash: Math.round(dash * 100) / 100, gap: Math.round((period - dash) * 100) / 100, seconds: Math.round(seconds * 100) / 100, delay: -Math.round(seed(id) * seconds * 100) / 100 };
}

/** At most 150 edges animate; on a small host (4 cores or fewer) at most 60 (ADR-958 section 8). */
export function animatedBudget(cores: number | undefined): number {
  return cores !== undefined && cores > 0 && cores <= 4 ? 60 : 150;
}

// ---------------------------------------------------------------------------------------------
// The table view and the summary

export interface FlowRow {
  id: string;
  from: string;
  to: string;
  qps: number;
  slowPct: number;
  errPct: number;
  health: Health;
}

/** The accessible equivalent of the drawing: one row per edge with a rate. */
export function flowRows(snap: Snapshot): FlowRow[] {
  const label = new Map(snap.nodes.map((n) => [n.id, n.label]));
  return snap.edges
    .filter((e) => !e.structural && label.has(e.from) && label.has(e.to))
    .map((e) => ({ id: edgeId(e), from: label.get(e.from)!, to: label.get(e.to)!, qps: e.qps, slowPct: e.slowPct, errPct: e.errPct, health: e.health }))
    .sort((a, b) => b.qps - a.qps);
}

/** A sentence for the figure's `aria-label` and the visible summary. */
export function summary(snap: Snapshot): string {
  const c = snap.nodes.reduce((m, n) => ({ ...m, [n.health]: (m[n.health] ?? 0) + 1 }), {} as Partial<Record<Health, number>>);
  const kinds = (k: MapNode['kind']) => snap.nodes.filter((n) => n.kind === k).length;
  const devs = kinds('device');
  const folded = snap.nodes.filter((n) => n.kind === 'more').reduce((s, n) => s + (n.folded ?? 0), 0);
  const parts = [
    `${snap.nodes.length} nodes`,
    `${kinds('network')} network${kinds('network') === 1 ? '' : 's'}`,
    `${devs} device${devs === 1 ? '' : 's'}${folded ? ` and ${folded} more folded` : ''}`,
    `${kinds('resolver')} resolver${kinds('resolver') === 1 ? '' : 's'}`,
    `${kinds('upstream')} upstream${kinds('upstream') === 1 ? '' : 's'}`,
  ];
  return `${parts.join(', ')}. ${c.red ?? 0} failing, ${c.yellow ?? 0} degraded, ${c.green ?? 0} healthy, ${c.idle ?? 0} idle.`;
}

/** The path of the link a node click-through offers, per kind (ADR-958 section 10). */
export interface Link {
  label: string;
  path: string;
  params?: Record<string, string | undefined>;
  testid: string;
}
export function links(n: MapNode, privacy: number): Link[] {
  switch (n.kind) {
    case 'device': {
      const a = n.address;
      // At privacy 2 and above a device has no address and no click-through.
      if (!a || privacy >= 2) return [];
      return [
        { label: 'Show its queries', path: '/queries', params: { client: a }, testid: 'to-queries' },
        { label: 'Explain a name for it', path: '/explain', params: { client: a }, testid: 'to-explain' },
        { label: 'Anomalies for it', path: '/anomalies', params: { client: a }, testid: 'to-anomalies' },
        { label: 'Device page', path: '/clients', params: { device: a }, testid: 'to-device' },
      ];
    }
    case 'more':
      if (privacy >= 2) return [];
      return [{ label: 'All devices', path: '/clients', testid: 'to-clients' }];
    case 'upstream':
      return [{ label: 'Upstreams', path: '/upstreams', testid: 'to-upstreams' }];
    case 'resolver':
      return [{ label: 'Cluster', path: '/cluster', testid: 'to-cluster' }];
    case 'network':
      return [{ label: 'Networks', path: '/networks', testid: 'to-networks' }];
    case 'gateway':
      return [{ label: 'Routers', path: '/routers', testid: 'to-routers' }];
    case 'answer': {
      const kind = n.id.split(':').pop() ?? '';
      const status = ({ cache: 'cached', local: 'local', blocked: 'blocked' } as Record<string, string>)[kind];
      return status ? [{ label: `Queries answered ${kind === 'cache' ? 'from the cache' : kind === 'local' ? 'locally' : 'with a block'}`, path: '/queries', params: { status }, testid: 'to-queries' }] : [];
    }
    default:
      return [];
  }
}

/** A device's switch and port, only when the snapshot carries them (the inventory's data, T25). */
export function via(n: MapNode): string | null {
  const x = n as MapNode & { via?: string | null; port?: string | null };
  if (!x.via) return null;
  return x.port ? `${x.via}, port ${x.port}` : x.via;
}
