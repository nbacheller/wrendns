// REQ: OBS-901 (T26.6, ADR-958 section 4) — the map's thresholds as the settings card previews them:
// the current snapshot reclassified with the values being typed. It mirrors the server's rules for
// the rates a snapshot carries (a flow's error, slow and blocked percents), so the preview is of the
// same decision; what a snapshot can't say (the rate limiter, anomalies, a breaker) keeps the
// colour it has, and the slow share is the one the server counted with the current latency
// threshold (a different `warn_latency_ms` shows only after it is applied).
import type { Health, MapEdge, MapNode, Snapshot } from './map';

export interface Thresholds {
  minSample: number;
  warnSlowPct: number;
  warnErrorPct: number;
  errorPct: number;
  warnBlockedPct: number;
}

/** The server's defaults (`[map]`). */
export const DEFAULT_THRESHOLDS: Thresholds = { minSample: 20, warnSlowPct: 10, warnErrorPct: 5, errorPct: 25, warnBlockedPct: 60 };

const num = (v: unknown, d: number): number => {
  const n = typeof v === 'string' ? Number(v.trim() === '' ? NaN : v) : (v as number);
  return typeof n === 'number' && Number.isFinite(n) ? n : d;
};

/** The thresholds a form's values (snake_case, as `[map]`) say; a blank or bad value is the default. */
export function fromSettings(v: Record<string, unknown>): Thresholds {
  const d = DEFAULT_THRESHOLDS;
  return {
    minSample: num(v.min_sample, d.minSample),
    warnSlowPct: num(v.warn_slow_pct, d.warnSlowPct),
    warnErrorPct: num(v.warn_error_pct, d.warnErrorPct),
    errorPct: num(v.error_pct, d.errorPct),
    warnBlockedPct: num(v.warn_blocked_pct, d.warnBlockedPct),
  };
}

const RANK: Record<Health, number> = { idle: 0, green: 1, yellow: 2, red: 3 };
const worst = (a: Health, b: Health): Health => (RANK[a] >= RANK[b] ? a : b);

// Reasons a rate can't explain: they hold a colour whatever the thresholds are.
const HOLDS_RED = new Set(['breaker_open', 'unreachable', 'severe']);
const HOLDS_YELLOW = new Set(['rate_limited', 'anomaly', 'breaker_half_open', 'degraded', 'router_error']);

function floor(n: MapNode): Health {
  const codes = n.reasons.map((r) => r.code);
  if (codes.some((c) => HOLDS_RED.has(c))) return 'red';
  if (codes.some((c) => HOLDS_YELLOW.has(c))) return 'yellow';
  return 'green';
}

/** The node a flow's colour belongs to: the device that asked, else the upstream or answer it reaches. */
function owner(e: MapEdge, byId: Map<string, MapNode>): MapNode | undefined {
  const from = byId.get(e.from);
  if (from && (from.kind === 'device' || from.kind === 'more')) return from;
  return byId.get(e.to);
}

/** One entity's health under the thresholds, over its flows. */
function classify(n: MapNode, flows: MapEdge[], t: Thresholds): Health {
  // The server's order: facts first (an open breaker or an unreachable node is red whatever was
  // sampled; a half-open breaker is yellow), then idle for too few samples, then the rates.
  const codes = n.reasons.map((r) => r.code);
  if (codes.some((c) => c === 'breaker_open' || c === 'unreachable')) return 'red';
  if (n.sampled < t.minSample) return codes.includes('breaker_half_open') ? 'yellow' : 'idle';
  let h: Health = floor(n);
  for (const e of flows) {
    // The answer kinds (cache, local, blocked) have no error rate: SERVFAIL is not theirs.
    if (n.kind !== 'answer') {
      if (e.errPct >= t.errorPct) h = worst(h, 'red');
      else if (e.errPct >= t.warnErrorPct) h = worst(h, 'yellow');
    }
    if (e.slowPct >= t.warnSlowPct) h = worst(h, 'yellow');
    if (n.kind === 'device' && e.blockedPct >= t.warnBlockedPct) h = worst(h, 'yellow');
  }
  return h;
}

export interface Change {
  id: string;
  label: string;
  from: Health;
  to: Health;
}

export interface Preview {
  /** Devices, upstreams and answer kinds looked at. */
  total: number;
  now: Record<Health, number>;
  draft: Record<Health, number>;
  changes: Change[];
}

const zero = (): Record<Health, number> => ({ green: 0, yellow: 0, red: 0, idle: 0 });

/**
 * Reclassify the devices, upstreams and answer kinds of `snap` under `t`. `now` is what the snapshot
 * says as drawn; `draft` is what the thresholds would make of the same flows.
 */
export function reclassify(snap: Snapshot, t: Thresholds): Preview {
  const byId = new Map(snap.nodes.map((n) => [n.id, n]));
  const flows = new Map<string, MapEdge[]>();
  for (const e of snap.edges) {
    if (e.structural) continue;
    const n = owner(e, byId);
    if (!n || !['device', 'upstream', 'answer'].includes(n.kind)) continue;
    flows.set(n.id, [...(flows.get(n.id) ?? []), e]);
  }
  const out: Preview = { total: 0, now: zero(), draft: zero(), changes: [] };
  for (const n of snap.nodes) {
    const f = flows.get(n.id);
    if (!f) continue;
    out.total++;
    const to = classify(n, f, t);
    out.now[n.health]++;
    out.draft[to]++;
    if (to !== n.health) out.changes.push({ id: n.id, label: n.label, from: n.health, to });
  }
  return out;
}

const WORD: Record<Health, string> = { green: 'OK', yellow: 'Warning', red: 'Failing', idle: 'Idle' };

/** The card's sentence about a draft. */
export function previewSentence(p: Preview | null): string {
  if (!p) return 'No map data to preview yet: the thresholds apply when lookups arrive.';
  if (p.total === 0) return 'The map has no flows right now, so there is nothing to preview.';
  const counts = (c: Record<Health, number>) => `${c.red} failing, ${c.yellow} warning, ${c.green} OK, ${c.idle} idle`;
  if (p.changes.length === 0) return `With these values the current map is, by estimate, unchanged (${counts(p.now)}).`;
  const named = p.changes
    .slice(0, 3)
    .map((c) => `${c.label} ${WORD[c.from]} to ${WORD[c.to]}`)
    .join('; ');
  const more = p.changes.length > 3 ? `; and ${p.changes.length - 3} more` : '';
  return `With these values ${p.changes.length} of ${p.total} would change (an estimate from the flows drawn): ${named}${more}. Now ${counts(p.now)}; then ${counts(p.draft)}.`;
}
