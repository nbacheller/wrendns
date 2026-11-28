// REQ: API-902 (T27.13, ADR-956) — what is guarded on this node and what is pending, polled while a
// guarded control is on screen. The listing never holds a value, a preview ID or a confirmation
// token (ADR-956 §7): only that a change is pending, which setting, and the seconds left, so the
// countdown is driven by the server's `deadlineSecs`, never by this browser's clock alone.
import { api, ApiError, type S } from './api';
import { poll } from './poll';

export type GuardedNode = S['GuardedNodeStatus'];

export const guarded = $state<{
  /** The node the controls act on (this node, unless another was picked), once read. */
  node: GuardedNode | null;
  /** Every node the listing covers: this node first, then the cluster members the primary can see. */
  nodes: GuardedNode[];
  /** The node picked in the picker; empty is this node (the first in the listing). */
  selected: string;
  loaded: boolean;
  /** The last read failed (a restarting node, an agent-less session...). */
  error: string;
}>({ node: null, nodes: [], selected: '', loaded: false, error: '' });

/** Picks the node the controls act on (empty: this node). */
export function selectGuardedNode(name: string) {
  guarded.selected = name;
  guarded.node = pick(guarded.nodes, name);
}

/** The listing's node named `name`, else this node (the first). */
function pick(nodes: GuardedNode[], name: string): GuardedNode | null {
  return nodes.find((n) => n.node === name) ?? nodes[0] ?? null;
}

/** The `node` field for a request about the picked node: absent for this node (the first listed). */
export function targetNode(): string | undefined {
  const first = guarded.nodes[0];
  return guarded.node && first && guarded.node.node !== first.node ? guarded.node.node : undefined;
}

// REQ: API-902, API-901 (T27.14g0; owner decision, 2026-11-27) - the picked node's own web UI and API settings
// and DNS listeners, read through the primary (admin only), so the Web UI and API card and the Listeners card
// show and stage that node's values instead of this node's. Empty for this node (its values are in the system
// information the page already has).
export type NodeApi = S['GuardedNodeApi'];
export const nodeApi = $state<{ node: string; data: NodeApi | null; loading: boolean; error: string; code: string }>({
  node: '',
  data: null,
  loading: false,
  error: '',
  code: '',
});
let nodeApiSeq = 0;

/** Reads the values of `node` (another node; `undefined` clears). A repeat for the same node is not asked again unless forced. */
export async function loadNodeApi(node: string | undefined, force = false): Promise<void> {
  if (!node) {
    nodeApiSeq += 1;
    Object.assign(nodeApi, { node: '', data: null, loading: false, error: '', code: '' });
    return;
  }
  if (!force && nodeApi.node === node && (nodeApi.loading || nodeApi.data || nodeApi.error)) return;
  const mine = ++nodeApiSeq;
  // A forced read of the node already shown keeps what is on screen until the new values arrive: the card that
  // asked for it (a change was just kept) must not lose the outcome it is still showing.
  const keep = force && nodeApi.node === node ? nodeApi.data : null;
  Object.assign(nodeApi, { node, data: keep, loading: true, error: '', code: '' });
  try {
    const d = await api.guardedNodeApi(node);
    if (mine === nodeApiSeq) Object.assign(nodeApi, { data: d, loading: false });
  } catch (e) {
    if (mine !== nodeApiSeq) return;
    const code = e instanceof ApiError ? e.code : '';
    Object.assign(nodeApi, { loading: false, code, error: nodeApiMessage(node, code, e instanceof ApiError ? e.message : String(e)) });
  }
}

/** What to tell the admin when another node's values cannot be read, in plain words. */
function nodeApiMessage(node: string, code: string, text: string): string {
  if (code === 'upgrade_required') return `${node} runs an older build that cannot report its web UI and API settings, so they are not shown or changed from here. Upgrade it first, or change them on that node itself. (${text})`;
  if (code === 'not_primary') return `Only the primary reads another node's settings: ${text}`;
  return `${node}'s settings could not be read: ${text}`;
}

/** The web UI address a node announces, as a plain http(s) URL, or an empty string when it announces none. */
export function nodeUrl(name: string | undefined): string {
  const url = guarded.nodes.find((n) => n.node === name)?.apiUrl ?? '';
  return /^https?:\/\//.test(url) ? url : '';
}

/** Whether a node has anything the admin should see (a pending window, a restart waiting, a restart under way). */
export const hasItems = (n: GuardedNode): boolean => !!n.pending || n.pendingRestart.length > 0 || n.restarting;

/** Reads the status now. */
export async function refreshGuarded(): Promise<GuardedNode | null> {
  try {
    const s = await api.guarded();
    guarded.nodes = s.nodes;
    guarded.node = pick(s.nodes, guarded.selected);
    guarded.error = '';
    return guarded.node;
  } catch (e) {
    guarded.error = e instanceof ApiError ? e.message : String(e);
    return null;
  } finally {
    guarded.loaded = true;
  }
}

/** Polls every `ms` (2 s while a window is open, slower otherwise); returns the stop function. */
export function watchGuarded(ms = 2_000): () => void {
  return poll(refreshGuarded, ms);
}

/** The words for a rollback or failed-start reason. */
export function reasonText(reason: string | null | undefined): string {
  switch (reason) {
    case 'expired':
      return 'it was not confirmed in time';
    case 'cancelled':
      return 'it was cancelled';
    case 'commit_failed':
      return 'the node could not keep it (it could not be applied or recorded)';
    case 'bind_failed':
      return 'the new address could not be opened';
    case 'failed_start':
      return 'the node did not become healthy after it, twice, so it was dropped';
    default:
      return reason ?? 'unknown';
  }
}

/** Whether this node can be restarted from here: only where a supervisor is declared. */
export const hasSupervisor = (n: GuardedNode | null): boolean => !!n && n.supervisor.kind !== 'none';
