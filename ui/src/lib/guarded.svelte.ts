// REQ: API-902 (T27.13, ADR-956) — what is guarded on this node and what is pending, polled while a
// guarded control is on screen. The listing never holds a value, a preview ID or a confirmation
// token (ADR-956 §7): only that a change is pending, which setting, and the seconds left, so the
// countdown is driven by the server's `deadlineSecs`, never by this browser's clock alone.
import { api, ApiError, type S } from './api';
import { poll } from './poll';

export type GuardedNode = S['GuardedNodeStatus'];

export const guarded = $state<{
  /** This node's status, once read. */
  node: GuardedNode | null;
  loaded: boolean;
  /** The last read failed (a restarting node, an agent-less session...). */
  error: string;
}>({ node: null, loaded: false, error: '' });

/** Reads the status now. */
export async function refreshGuarded(): Promise<GuardedNode | null> {
  try {
    const s = await api.guarded();
    guarded.node = s.nodes[0] ?? null;
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
