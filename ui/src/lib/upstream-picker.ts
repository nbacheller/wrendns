// REQ: UPS-004, API-002 (T24.36) — the Upstreams page's simple view: which upstream entries a set of
// ticked providers means, and which ticked providers the saved entries mean. Pure, so it is tested
// without a browser. The entries it makes are named `pub-<preset>-<protocol>-<n>` (and
// `pub-custom-<n>`): that prefix is how the simple view knows what it made and what it must leave
// alone.
import type { S } from './api';

export type Preset = S['UpstreamPreset'];
export type Transport = 'encrypted' | 'plain';

export const PREFIX = 'pub-';

export interface Entry {
  name: string;
  url: string;
  tls_server_name?: string;
}

export interface Plan {
  entries: Entry[];
  /** Providers that have no plain address, so the encrypted ones were used. */
  fellBack: string[];
}

const keep = (e: S['UpstreamPresetEndpoint'], v4: boolean, v6: boolean) =>
  e.family === 'name' ? v4 || v6 : e.family === 'v4' ? v4 : v6;

/** The addresses to write for one provider variant under the chosen transport and families. */
export function endpointsFor(p: Preset, transport: Transport, v4: boolean, v6: boolean): { eps: S['UpstreamPresetEndpoint'][]; fellBack: boolean } {
  const usable = p.endpoints.filter((e) => keep(e, v4, v6));
  const of = (...protos: string[]) => usable.filter((e) => protos.includes(e.protocol));
  const encrypted = () => {
    const dot = of('tls');
    return dot.length ? dot : of('https');
  };
  if (transport === 'plain') {
    const plain = of('udp');
    if (plain.length) return { eps: plain, fellBack: false };
    return { eps: encrypted(), fellBack: true };
  }
  return { eps: encrypted(), fellBack: false };
}

/** Every entry the ticked providers need. */
export function planFor(presets: Preset[], ticked: Set<string>, transport: Transport, v4: boolean, v6: boolean): Plan {
  const entries: Entry[] = [];
  const fellBack: string[] = [];
  for (const p of presets) {
    if (!ticked.has(p.id)) continue;
    const { eps, fellBack: fb } = endpointsFor(p, transport, v4, v6);
    if (fb) fellBack.push(p.id);
    const n: Record<string, number> = {};
    for (const e of eps) {
      n[e.protocol] = (n[e.protocol] ?? 0) + 1;
      const entry: Entry = { name: `${PREFIX}${p.id}-${e.protocol}-${n[e.protocol]}`, url: e.url };
      if (e.tlsServerName) entry.tls_server_name = e.tlsServerName;
      entries.push(entry);
    }
  }
  return { entries, fellBack };
}

const ENTRY_NAME = /^pub-(.+)-(udp|tcp|tls|https|quic)-(\d+)$/;
const CUSTOM_NAME = /^pub-custom-(\d+)$/;

export const isPickerEntry = (name: string) => name.startsWith(PREFIX);
export const isCustomName = (name: string) => CUSTOM_NAME.test(name);
/** The provider an entry the picker made belongs to (`null` for a custom one or another entry). */
export const presetOf = (name: string): string | null => ENTRY_NAME.exec(name)?.[1] ?? null;

export interface Saved {
  ticked: Set<string>;
  transport: Transport | null;
  v4: boolean | null;
  v6: boolean | null;
  customs: { name: string; url: string; tls_server_name?: string }[];
}

const literal = (url: string): 'v4' | 'v6' | null => {
  const host = /^[a-z]+:\/\/(\[[^\]]+\]|[^/:]+)/i.exec(url)?.[1] ?? '';
  if (host.startsWith('[')) return 'v6';
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(host) ? 'v4' : null;
};

/** What the saved `pub-` entries say the picker was set to. */
export function readSaved(entries: S['ConfigEntry'][], presets: Preset[]): Saved {
  const known = new Set(presets.map((p) => p.id));
  const out: Saved = { ticked: new Set(), transport: null, v4: null, v6: null, customs: [] };
  let encrypted = false;
  let plain = false;
  let sawV4 = false;
  let sawV6 = false;
  let literals = 0;
  for (const e of entries) {
    if (!isPickerEntry(e.name) || !e.definition) continue;
    const d = e.definition as { url?: string; tls_server_name?: string };
    const url = String(d.url ?? '');
    if (isCustomName(e.name)) {
      out.customs.push({ name: e.name, url, ...(d.tls_server_name ? { tls_server_name: d.tls_server_name } : {}) });
      continue;
    }
    const id = presetOf(e.name);
    if (!id || !known.has(id)) continue;
    out.ticked.add(id);
    if (/^udp:/i.test(url)) plain = true;
    else encrypted = true;
    const lit = literal(url);
    if (lit) literals++;
    if (lit === 'v4') sawV4 = true;
    if (lit === 'v6') sawV6 = true;
  }
  if (out.ticked.size) {
    // Plain wins: a provider with no plain address falls back to encrypted entries even in plain mode.
    out.transport = plain ? 'plain' : encrypted ? 'encrypted' : null;
    // Host-name addresses carry no family: only addresses say which were chosen.
    if (literals) {
      out.v4 = sawV4;
      out.v6 = sawV6;
    }
  }
  return out;
}

const IPV4 = /^\d{1,3}(\.\d{1,3}){3}(:\d+)?$/;
const IPV6 = /^[0-9a-f:]*:[0-9a-f:.]*$/i;

/** What someone typed in the custom row, as an address: a bare IP is plain DNS; null if it isn't one. */
export function customUrl(text: string): string | null {
  const t = text.trim();
  if (!t) return null;
  if (/^(udp|tcp|tls|https|quic):\/\/\S+$/i.test(t)) return t;
  if (IPV4.test(t)) return `udp://${t}`;
  if (IPV6.test(t)) return `udp://[${t}]`;
  return null;
}

/** An IP-literal DoT address needs the name on the server's certificate. */
export const needsTlsName = (url: string) => /^tls:\/\//i.test(url) && literal(url) !== null;

/** The next `pub-custom-<n>` not taken. */
export function nextCustomName(taken: string[]): string {
  let n = 1;
  while (taken.includes(`${PREFIX}custom-${n}`)) n++;
  return `${PREFIX}custom-${n}`;
}
