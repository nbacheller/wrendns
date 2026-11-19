// The e2e ports, from one base (T24.19, DOC-006). Every port the harness uses is a fixed offset
// from E2E_HTTP_PORT: server.mjs, every spec and the fakes read them from here, so nothing
// hard-codes a port. Parallel worktrees each run their own suite by moving the base.
// The temp root (data directory, generated config, setup token) is keyed by the base too.
import { resolve } from 'node:path';

export const HTTP_PORT = Number(process.env.E2E_HTTP_PORT ?? 18054);

// Offsets from the base. Each one is a distinct port in 0..999 (asserted below).
export const OFFSETS = {
  http: 0, // the API and the web UI (the base itself)
  dns: 1, // the WrenDNS listener
  mdns: 2, // mDNS naming (the test sends an announcement there)
  upstream: 3, // the stub upstream that answers every name with 192.0.2.7
  metrics: 4, // the Prometheus / OpenMetrics listener
  webhook: 6, // a test webhook receiver (api_015)
  ntfy: 7, // a test ntfy server (api_015 and the file destination)
  ntfyAlt: 8, // a second ntfy address that is only typed or offered, never listened on
  haAdd: 9, // a Home Assistant address the add test types (not listened on)
  haDelete: 10, // a Home Assistant address for the delete test (not listened on)
  haMoved: 11, // a Home Assistant address for the moved-credential check (route-mocked)
  probeTarget: 12, // the probe target the System tab test shows (route-mocked)
  guardedNew: 13, // the guarded window test's new address (a temporary listener the node opens for the window)
  guardedRoll: 14, // the guarded rollback test's new address
  geoipSource: 15, // the fake HTTPS source the GeoIP tests (obs_902) download the country database from
  catalog: 16, // the fake host the category lists come from (the categories test serves it; REQ: FLT-901)
} as const;

export type PortName = keyof typeof OFFSETS;

for (const [name, offset] of Object.entries(OFFSETS)) {
  if (!Number.isInteger(offset) || offset < 0 || offset > 999) {
    throw new Error(`e2e port offset ${name}=${offset} must be an integer in 0..999`);
  }
}
if (!Number.isInteger(HTTP_PORT) || HTTP_PORT < 1024 || HTTP_PORT + 999 > 65535) {
  throw new Error(`E2E_HTTP_PORT=${HTTP_PORT} must leave room for offsets 0..999 (1024..64536)`);
}

/** The port an e2e name is at: the base plus its offset. */
export function portOf(name: PortName): number {
  return HTTP_PORT + OFFSETS[name];
}

export const PORTS = Object.fromEntries(
  (Object.keys(OFFSETS) as PortName[]).map((name) => [name, portOf(name)]),
) as Record<PortName, number>;

export const BASE_URL = `http://127.0.0.1:${PORTS.http}`;
export const DNS_PORT = PORTS.dns;
export const MDNS_PORT = PORTS.mdns;

// The temp root for this base (ui/.e2e-<base>): a parallel run on another base gets its own.
export const E2E_ROOT = resolve(import.meta.dirname, '../../.e2e-' + HTTP_PORT);
