// REQ: DSC-004, DSC-007 (T25.6, ADR-908, ADR-1001) — the drafts the network inventory page edits:
// `[[discovery.snmp_agent]]` and `[[discovery.snmp_credential]]`, as the API entry carries them
// (snake_case, like the rest of `[discovery]`). A credential holds only the names of files under the
// node's secret directories: the secret itself is never typed or shown here (T25.8 adds the stored
// secrets).

/** The tables an agent may be polled for. */
export const SNMP_TABLES = ['arp', 'ifmib', 'bridge', 'lldp'] as const;
export type SnmpTable = (typeof SNMP_TABLES)[number];

/** What each table gives the inventory, for the form. */
export const TABLE_HELP: Record<SnmpTable, string> = {
  arp: 'ARP: which MAC sits behind each address (a gateway or router)',
  ifmib: 'Interfaces: port names and the agent’s own addresses',
  bridge: 'Forwarding table: which switch port and VLAN a MAC is on (a switch)',
  lldp: 'LLDP: the neighbours each port sees (a switch)',
};

export interface AgentDraft {
  name: string;
  address: string;
  port: number;
  credential: string;
  interval_secs: number;
  max_repetitions: number;
  tables: string[];
}

export interface CredDraft {
  name: string;
  role: 'infrastructure' | 'host';
  version: 'v2c' | 'v3';
  community_file: string;
  user: string;
  auth_protocol: string;
  auth_password_file: string;
  priv_protocol: string;
  priv_password_file: string;
}

export const blankAgent = (): AgentDraft => ({
  name: '',
  address: '',
  port: 161,
  credential: '',
  interval_secs: 300,
  max_repetitions: 10,
  tables: [...SNMP_TABLES],
});

export const blankCred = (): CredDraft => ({
  name: '',
  role: 'infrastructure',
  version: 'v3',
  community_file: '',
  user: '',
  auth_protocol: 'sha-256',
  auth_password_file: '',
  priv_protocol: 'aes-128',
  priv_password_file: '',
});

const str = (v: unknown): string => (typeof v === 'string' ? v : '');
const num = (v: unknown, d: number): number => (typeof v === 'number' && Number.isFinite(v) ? v : d);

/** Reads the stored `snmp_agent` list. */
export function agentsOf(def: Record<string, unknown>): AgentDraft[] {
  const list = Array.isArray(def.snmp_agent) ? (def.snmp_agent as Record<string, unknown>[]) : [];
  return list.map((a) => ({
    name: str(a.name),
    address: str(a.address),
    port: num(a.port, 161),
    credential: str(a.credential),
    interval_secs: num(a.interval_secs, 300),
    max_repetitions: num(a.max_repetitions, 10),
    tables: Array.isArray(a.tables) ? (a.tables as unknown[]).map(String) : [...SNMP_TABLES],
  }));
}

/** Reads the stored `snmp_credential` list. */
export function credsOf(def: Record<string, unknown>): CredDraft[] {
  const list = Array.isArray(def.snmp_credential) ? (def.snmp_credential as Record<string, unknown>[]) : [];
  return list.map((c) => ({
    name: str(c.name),
    role: c.role === 'host' ? 'host' : 'infrastructure',
    version: c.version === 'v3' ? 'v3' : 'v2c',
    community_file: str(c.community_file),
    user: str(c.user),
    auth_protocol: str(c.auth_protocol),
    auth_password_file: str(c.auth_password_file),
    priv_protocol: str(c.priv_protocol),
    priv_password_file: str(c.priv_password_file),
  }));
}

/** The agent as the API takes it. */
export function agentBody(a: AgentDraft): Record<string, unknown> {
  return {
    name: a.name.trim(),
    address: a.address.trim(),
    port: Number(a.port),
    credential: a.credential,
    interval_secs: Number(a.interval_secs),
    max_repetitions: Number(a.max_repetitions),
    tables: a.tables,
  };
}

/** The credential as the API takes it: only the fields of its version, empty ones left out. */
export function credBody(c: CredDraft): Record<string, unknown> {
  const out: Record<string, unknown> = { name: c.name.trim(), role: c.role, version: c.version };
  const set = (k: string, v: string) => {
    if (v.trim()) out[k] = v.trim();
  };
  if (c.version === 'v2c') {
    set('community_file', c.community_file);
  } else {
    set('user', c.user);
    set('auth_protocol', c.auth_protocol);
    set('auth_password_file', c.auth_password_file);
    set('priv_protocol', c.priv_protocol);
    if (c.priv_protocol.trim()) set('priv_password_file', c.priv_password_file);
  }
  return out;
}

/** An agent state in words. */
export function stateText(s: string): string {
  switch (s) {
    case 'ok':
      return 'Polling';
    case 'error':
      return 'Last poll failed';
    case 'failing':
      return 'Failing';
    case 'skipped':
      return 'Skipped';
    default:
      return 'Waiting for its first poll';
  }
}

/** What a table's state means. */
export function tableText(s: string): string {
  switch (s) {
    case 'answered':
      return 'answers';
    case 'unanswered':
      return 'no answer (skipped)';
    default:
      return 'not probed yet';
  }
}
