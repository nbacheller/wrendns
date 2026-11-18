// REQ: OBS-003, API-010 (T24.34, ADR-1013) — the devices the query log's client filter offers:
// by the name you gave, the router's name, mDNS and the inventory, each with its address and MAC.
import { api } from './api';
import { isRouterKey, routerKey } from './router-name';
import type { PickItem } from './components/Picker.svelte';

const IPV4 = /^\d{1,3}(\.\d{1,3}){3}$/;
const MAC = /^([0-9a-f]{2}:){5}[0-9a-f]{2}$/i;
const isIp = (s: string) => !MAC.test(s) && (IPV4.test(s) || (s.includes(':') && /^[0-9a-f:.]+$/i.test(s)));

/** What was typed in full as a client that no list names: an address or a router name key. */
export function typedClient(typed: string): PickItem | null {
  const t = typed.trim();
  if (isRouterKey(t) && t.length > 'hostname:'.length) {
    const v = routerKey(t.slice('hostname:'.length));
    return { value: v, label: v.slice('hostname:'.length), secondary: 'router name', kind: 'clients' };
  }
  return isIp(t) ? { value: t, label: t, secondary: 'address', kind: 'clients' } : null;
}

interface Acc {
  label: string;
  rank: number;
  ips: Set<string>;
  macs: Set<string>;
}

/**
 * One item per device address: named devices first (the name you gave, ranked highest), then what routers
 * and mDNS call them, then the last hour's busiest clients. A device's value is its first address.
 */
export async function deviceItems(): Promise<PickItem[]> {
  const [clients, leases, seen] = await Promise.all([
    api.clients().catch(() => null),
    api.dhcpLeases().catch(() => null),
    api.top('clients', 100, undefined, undefined, undefined, 'rolling').catch(() => null),
  ]);
  const byIp = new Map<string, Acc>();
  const put = (ip: string, label: string, rank: number, mac?: string) => {
    const a = byIp.get(ip) ?? { label, rank: -1, ips: new Set([ip]), macs: new Set<string>() };
    if (rank > a.rank) {
      a.label = label;
      a.rank = rank;
    }
    if (mac) a.macs.add(mac.toLowerCase());
    byIp.set(ip, a);
  };
  const ipOfMac = new Map<string, string>();
  for (const l of leases?.items ?? []) {
    if (l.mac && !l.offline) ipOfMac.set(l.mac.toLowerCase(), l.ip);
    put(l.ip, l.clientName ?? l.hostname ?? l.ip, l.clientName ? 3 : l.hostname ? 2 : 0, l.mac || undefined);
  }
  const offline = new Set((leases?.items ?? []).filter((l) => l.offline).map((l) => l.ip));
  for (const c of clients?.items ?? []) {
    const ips = c.match.filter(isIp);
    const macs = c.match.filter((m) => MAC.test(m));
    const viaMac = macs.map((m) => ipOfMac.get(m.toLowerCase())).filter((x): x is string => !!x);
    const router = c.match.find(isRouterKey);
    const all = [...new Set([...ips, ...viaMac])];
    if (!all.length && router) put(router, c.name, 4);
    for (const ip of all) put(ip, c.name, 4, macs[0]);
  }
  for (const t of seen?.items ?? []) put(t.key, t.name ?? t.key, t.name ? 3 : 0);
  return [...byIp.entries()]
    .map(([ip, a]) => ({
      value: ip,
      label: a.label,
      secondary: [ip === a.label ? '' : isRouterKey(ip) ? 'router name' : ip, ...a.macs, offline.has(ip) ? 'offline' : ''].filter(Boolean).join(' · '),
      kind: 'clients',
      rank: a.rank,
    }))
    .sort((x, y) => y.rank - x.rank || x.label.localeCompare(y.label))
    .map(({ rank: _r, ...i }) => i);
}
