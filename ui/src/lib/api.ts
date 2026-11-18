// Typed client for /api/v1 (types generated from docs/api/openapi.json: `npm run types`).
// REQ: API-005 — the UI uses only the public API, the same one scripts and agents use.

import type { components } from './api-types';

export type S = components['schemas'];
export type Problem = S['Problem'];

/** The first `code` names a field the server's detail quotes in backticks (`token_file`). */
// `<redacted>` is the marker for a kept value, never a field, so it is skipped (ADR-927 §4).
const fieldIn = (detail: string): string => {
  const f = [...detail.matchAll(/`([^`]+)`/g)].map((m) => m[1]).find((t) => t !== '<redacted>');
  return f ? ` \`${f}\`` : '';
};

/**
 * REQ: API-014, API-015 (T24.16, ADR-926 §3, ADR-927) — a kept credential that must be entered again.
 * The server's detail says which of three cases it is, and the sentence follows the case: a check
 * never uses a stored value; there is no stored value to keep; or the destination changed.
 */
function reentry(d: string): string {
  if (/never uses stored values/.test(d)) {
    return "A check can't use a stored credential. Enter it in the draft to check it, or save the upstream unchanged and check it from the Upstreams page.";
  }
  const field = fieldIn(d);
  // Headers and arguments have no field in the forms: only telltale ctl or the file can enter them.
  const how = /`(headers|args)/.test(d)
    ? "This form can't enter it: change it with telltale ctl, or in the configuration file."
    : 'Enter it again on this form (an admin does this).';
  if (/no stored value to keep/.test(d)) return `The stored credential${field} has no value to keep. ${how}`;
  return `The stored credential${field} isn't kept, because this entry now points somewhere else. ${how}`;
}

/**
 * REQ: API-015, API-014 (T24.16, ADR-926) — the sentence a person reads for a problem code. The
 * server's own detail stays on `ApiError.detail` (a check of what it said). A code not listed here
 * reads as the server's detail.
 */
const READABLE: Record<string, (detail: string) => string> = {
  path_not_allowed: (d) =>
    `That file path can't be used${fieldIn(d)}: TelltaleDNS won't read from there. Pick another path, or set it in the configuration file on this node.`,
  set_by_file: (d) =>
    `The configuration file sets${fieldIn(d) || ' this credential'}, and it wins over the UI and the API. Change it in the file.`,
  credential_reentry_required: (d) => reentry(d),
  upgrade_required: () =>
    'This change touches a credential, and this node is too old to send it to the primary. Upgrade this node, or make the change on the primary.',
  secret_missing: (d) =>
    `A reference names a secret this node doesn't store${fieldIn(d)}. Store the secret first under Settings → Integrations & secrets, or pick one that exists.`,
  // The server's detail names the entries and nodes that use it, so it stays in the sentence.
  secret_in_use: (d) => `The secret is still in use, so it isn't deleted: ${d}`,
  secrets_locked: () =>
    "The secrets on this node can't be read, so they can't be changed. Check the secrets key under Settings → Integrations & secrets.",
  insecure_transport: () =>
    'A secret is only sent over HTTPS, or from this node itself. Open this page over HTTPS to change it.',
  lists_not_here: () => "This node doesn't download lists. Ask a node that does.",
};

/** An API error (RFC 9457 problem+json). `message` reads as a sentence; `detail` is the server's text. */
export class ApiError extends Error {
  readonly status: number;
  readonly code: string;
  readonly hint?: string;
  readonly detail: string;
  constructor(p: Partial<Problem> & { status: number }) {
    const detail = p.detail ?? p.title ?? `HTTP ${p.status}`;
    const readable = p.code ? READABLE[p.code] : undefined;
    super(readable ? readable(detail) : detail);
    this.detail = detail;
    this.status = p.status;
    this.code = p.code ?? 'internal';
    // A header or an argument has no field in the form, and the sentence already says how to enter it:
    // the server's hint ("send the value itself") would contradict it, so it isn't kept.
    this.hint = p.code === 'credential_reentry_required' && /`(headers|args)/.test(detail) ? undefined : (p.hint ?? undefined);
  }
}

let csrf: string | undefined;
let onSignedOut: (() => void) | undefined;

/** The session's CSRF token, sent as `X-CSRF-Token` on every change. */
export function setCsrf(token: string | undefined) {
  csrf = token;
}

/** Called when a request finds the session gone (expired, signed out elsewhere). */
export function whenSignedOut(f: () => void) {
  onSignedOut = f;
}

type Query = Record<string, string | number | boolean | undefined | null>;

function qs(q?: Query): string {
  if (!q) return '';
  const p = new URLSearchParams();
  for (const [k, v] of Object.entries(q)) {
    if (v !== undefined && v !== null && v !== '') p.set(k, String(v));
  }
  const s = p.toString();
  return s ? `?${s}` : '';
}

async function call<T>(
  method: string,
  path: string,
  opts: { query?: Query; body?: unknown; raw?: Blob; headers?: Record<string, string> } = {},
): Promise<T> {
  const headers: Record<string, string> = { accept: 'application/json', ...opts.headers };
  if (opts.raw) headers['content-type'] = 'application/octet-stream';
  else if (opts.body !== undefined) headers['content-type'] = 'application/json';
  if (method !== 'GET' && csrf) headers['x-csrf-token'] = csrf;
  let res: Response;
  try {
    res = await fetch(`/api/v1${path}${qs(opts.query)}`, {
      method,
      headers,
      credentials: 'same-origin',
      body: opts.raw ?? (opts.body === undefined ? undefined : JSON.stringify(opts.body)),
    });
  } catch {
    throw new ApiError({ status: 0, code: 'unavailable', detail: 'cannot reach the server' });
  }
  if (res.status === 204) return undefined as T;
  const text = await res.text();
  let json: unknown;
  try {
    json = text ? JSON.parse(text) : undefined;
  } catch {
    json = undefined;
  }
  if (!res.ok) {
    const p = (json ?? {}) as Partial<Problem>;
    const err = new ApiError({ ...p, status: res.status, detail: p.detail ?? (text || res.statusText) });
    if (res.status === 401 && err.code === 'unauthorized' && !path.startsWith('/auth/')) onSignedOut?.();
    throw err;
  }
  return json as T;
}

/** A random Idempotency-Key (getRandomValues also works on plain-HTTP LAN addresses). */
function newKey(): string {
  return Array.from(crypto.getRandomValues(new Uint8Array(16)), (b) => b.toString(16).padStart(2, '0')).join('');
}

export type EntryPath = 'upstreams' | 'upstream-groups' | 'lists' | 'groups' | 'alerts/destinations' | 'alerts/rules' | 'schedules' | 'anomaly-mutes' | 'ratelimit' | 'exclusions' | 'simulate-settings' | 'cluster/rollout-settings' | 'special-names' | 'local-settings' | 'clients-settings' | 'discovery-settings';

/** REQ: OPS-011 — a support package's manifest (`MANIFEST.json`). */
export type SupportManifest = {
  created: string;
  level: string;
  files: { path: string; collector: string; bytes: number; status: 'ok' | 'truncated' | 'missing'; note?: string; redactions?: Record<string, number> }[];
  redactions: Record<string, number>;
  config_fields_removed: string[];
  config_fields_unclassified: string[];
  notes: string[];
};

/** The package's `MANIFEST.json`, read from the archive itself: the first entry of the tar. */
async function manifestOf(archive: Blob): Promise<SupportManifest> {
  const tar = await new Response(archive.stream().pipeThrough(new DecompressionStream('gzip'))).arrayBuffer();
  const head = new Uint8Array(tar, 0, 512);
  const field = (from: number, to: number) => new TextDecoder().decode(head.subarray(from, to)).replace(/\x00.*$/s, '').trim();
  if (field(0, 100) !== 'MANIFEST.json') throw new ApiError({ status: 0, code: 'internal', detail: 'the package has no manifest' });
  const size = parseInt(field(124, 136), 8);
  return JSON.parse(new TextDecoder().decode(new Uint8Array(tar, 512, size))) as SupportManifest;
}

/** A request whose answer is a file: the response, once it is known to be a success. */
async function callFile(method: string, path: string, body: unknown): Promise<Response> {
  const headers: Record<string, string> = { 'content-type': 'application/json' };
  if (method !== 'GET' && csrf) headers['x-csrf-token'] = csrf;
  let res: Response;
  try {
    res = await fetch(`/api/v1${path}`, {
      method,
      headers,
      credentials: 'same-origin',
      body: body === undefined ? undefined : JSON.stringify(body),
    });
  } catch {
    throw new ApiError({ status: 0, code: 'unavailable', detail: 'cannot reach the server' });
  }
  if (!res.ok) {
    const text = await res.text();
    let p: Partial<Problem> = {};
    try {
      p = JSON.parse(text) as Partial<Problem>;
    } catch {
      // Not problem+json: the status text will do.
    }
    throw new ApiError({ ...p, status: res.status, detail: p.detail ?? (text || res.statusText) });
  }
  return res;
}

const get = <T>(path: string, query?: Query) => call<T>('GET', path, { query });
const post = <T>(path: string, body?: unknown) => call<T>('POST', path, { body: body ?? {} });

/** REQ: API-007 (T24.18, ADR-940) — one Pi-hole import item: what it would do, and why not. */
export type PiholeItem = { kind: string; name: string; action: 'add' | 'change' | 'skip'; reason: string; detail: string };

/** REQ: API-007, ADR-941 — the comparison of a sample through a Pi-hole and TelltaleDNS. */
export type PiholeCompare = {
  names: number;
  agree: number;
  differences: { name: string; qtype: string; pihole: { rcode: string; values: string[] }; telltale: { rcode: string; values: string[] } }[];
  errors: string[];
};

/** REQ: API-007 (T24.18) — a preview: a plan the same admin applies, with its counts. */
export type PiholePreview = {
  planId: string;
  expiresUnixSeconds: number;
  configVersion: number;
  source: string;
  counts: string;
  summary: { add: number; change: number; skip: number; samples: number };
  items: PiholeItem[];
  itemsTotal: number;
  notes: string[];
  compare: PiholeCompare | null;
};

/** REQ: API-007 (T24.18) — what applying a plan changed. */
export type PiholeApplied = {
  applied: boolean;
  configVersion: number;
  added: number;
  changed: number;
  skipped: number;
  entries: number;
  counts: string;
  source: string;
};

export const api = {
  // REQ: API-005 (T24.10, ADR-961) — the Pi-hole compatible API: admins turn it on and make its token
  // (shown once). Agents may read the status; nothing here is an agent's to change.
  piholeApi: () => get<S['PiholeApiStatus']>('/pihole-api'),
  setPiholeApi: (b: S['PiholeApiSettings']) => call<S['PiholeApiStatus']>('PUT', '/pihole-api', { body: b }),
  newPiholeToken: () => post<S['PiholeApiToken']>('/pihole-api/token'),
  revokePiholeToken: () => call<S['PiholeApiStatus']>('DELETE', '/pihole-api/token'),
  // REQ: API-007 (T24.18, ADR-940) — importing a Pi-hole export: admins only. The file is the body;
  // nothing changes until its plan is applied.
  piholePreview: (file: Blob, q: { compare?: string; telltale?: string; samples?: string } = {}) =>
    call<PiholePreview>('POST', '/import/pihole', { raw: file, query: q }),
  piholeApply: (planId: string) => post<PiholeApplied>(`/import/pihole/plans/${encodeURIComponent(planId)}/apply`),
  piholeDiscard: (planId: string) => call<{ discarded: boolean }>('DELETE', `/import/pihole/plans/${encodeURIComponent(planId)}`),
  // Sign-in (API-003)
  status: () => get<S['AuthStatus']>('/auth/status'),
  setup: (b: S['SetupRequest']) => post<S['LoginResponse']>('/auth/setup', b),
  login: (b: S['LoginRequest']) => post<S['LoginResponse']>('/auth/login', b),
  logout: () => post<S['LogoutResult'] | undefined>('/auth/logout'),
  me: () => get<S['Me']>('/auth/me'),
  changePassword: (b: S['PasswordChange']) => post<void>('/auth/password', b),
  totpSetup: () => post<S['TotpSetup']>('/auth/totp/setup'),
  totpEnable: (code: string) => post<S['RecoveryCodes']>('/auth/totp/enable', { code }),
  totpDisable: (password: string) => post<void>('/auth/totp/disable', { password }),
  tokens: () => get<S['Listed_TokenInfo']>('/tokens'),
  // REQ: API-016 (T23.8) — router integrations: the list with each router's status, an admin's
  // writes, and the admin's checks of a draft (one read, nothing saved).
  routers: () => get<S['RouterList']>('/routers'),
  putRouter: (name: string, b: Record<string, unknown>) => call<unknown>('PUT', `/routers/${encodeURIComponent(name)}`, { body: b }),
  deleteRouter: (name: string) => call<unknown>('DELETE', `/routers/${encodeURIComponent(name)}`),
  checkRouter: (b: Record<string, unknown>) => post<S['RouterCheck']>('/checks/router', b),
  routerCertificate: (url: string) => post<S['RouterCertificate']>('/checks/router-certificate', { url }),
  // REQ: API-016 (T23.10) — OIDC sign-in providers (admins): the list with each one's status on this
  // node, and the writes (the client secret is a stored name, never a value).
  oidcProviders: () => get<S['OidcProviderList']>('/oidc-providers'),
  putOidcProvider: (id: string, b: Record<string, unknown>) => call<unknown>('PUT', `/oidc-providers/${encodeURIComponent(id)}`, { body: b }),
  deleteOidcProvider: (id: string) => call<unknown>('DELETE', `/oidc-providers/${encodeURIComponent(id)}`),
  // REQ: OBS-035 (T14.13) — wall displays.
  displays: () => get<S['Listed_DisplayInfo']>('/displays'),
  createDisplay: (b: S['CreateDisplay']) => post<S['NewDisplay']>('/displays', b),
  revokeDisplay: (id: string) => call<void>('DELETE', `/displays/${encodeURIComponent(id)}`),
  openDisplay: (b: S['OpenDisplay']) => post<S['DisplayOpened']>('/auth/display', b),
  createToken: (b: S['CreateToken']) => post<S['NewToken']>('/tokens', b),
  deleteToken: (id: string) => call<void>('DELETE', `/tokens/${encodeURIComponent(id)}`),
  users: () => get<S['Listed_UserInfo']>('/users'),
  createUser: (b: S['CreateUser']) => post<S['UserInfo']>('/users', b),
  updateUser: (id: number, b: S['UpdateUser']) => call<S['UserInfo']>('PATCH', `/users/${id}`, { body: b }),
  deleteUser: (id: number) => call<void>('DELETE', `/users/${id}`),
  userTokens: (id: number) => get<S['Listed_TokenInfo']>(`/users/${id}/tokens`),
  revokeUserToken: (id: number, token: string) =>
    call<void>('DELETE', `/users/${id}/tokens/${encodeURIComponent(token)}`),
  audit: (q: { action?: string; cursor?: string; limit?: number }) => get<S['AuditPage']>('/audit', q),
  auditVerify: () => get<S['AuditVerify']>('/audit/verify'),

  // Data (API-001)
  info: () => get<S['SystemInfo']>('/system/info'),
  // REQ: AGT-007 (T7.1) — agents' plans; operators approve or reject them.
  plans: () => get<S['Items_Plan']>('/plans'),
  approvePlan: (id: string) => post<S['Plan']>(`/plans/${encodeURIComponent(id)}/approve`),
  rejectPlan: (id: string) => post<S['Plan']>(`/plans/${encodeURIComponent(id)}/reject`),
  // REQ: OPS-011 (ADR-156) — a support package (admin): what it would hold, the archive, its map.
  supportPreview: (b: S['SupportPackageRequest']) =>
    call<SupportManifest>('POST', '/system/support-package', { body: b, query: { dryRun: true } }),
  supportPackage: async (b: S['SupportPackageRequest']) => {
    const res = await callFile('POST', '/system/support-package', b);
    const name = /filename="([^"]+)"/.exec(res.headers.get('content-disposition') ?? '')?.[1] ?? 'telltale-support.tar.gz';
    const blob = await res.blob();
    return { blob, name, id: res.headers.get('x-support-package-id') ?? undefined, manifest: await manifestOf(blob) };
  },
  supportMap: async (id: string) => (await callFile('GET', `/system/support-package/${encodeURIComponent(id)}/map`, undefined)).blob(),
  // REQ: OPS-004 — "Check now" (admin).
  checkUpdates: () => post<S['UpdateStatus']>('/system/update-check'),
  // `scope`: `cluster` (default, every node), `node:<id>`, or `site:<name>` (CLU-002).
  summary: (from = '-24h', to?: string, scope?: string) =>
    get<S['Summary']>('/stats/summary', { from, to, scope }),
  timeseries: (q: { from?: string; step?: S['Step']; scope?: string }) =>
    get<S['Items_TimeBucket']>('/stats/timeseries', q),
  // REQ: OBS-004 — `from` reads a window of hours instead of one (not with client or group).
  top: (kind: S['TopKind'], limit = 10, client?: string, group?: string, scope?: string, hour?: S['TopHour'], from?: string) =>
    get<S['Items_TopItem']>('/stats/top', { kind, limit, client, group, scope, hour, from }),
  latency: (by: S['LatencyBy'], scope?: string) => get<S['Items_LatencyRow']>('/stats/latency', { by, scope }),
  // REQ: OBS-016 — the service-level objectives and their error budgets.
  slo: (scope?: string) => get<S['SloStatus']>('/stats/slo', { scope }),
  // REQ: OBS-030 — answers per latency bucket over time, and recent exemplars.
  latencyHeatmap: (q: { from?: string; step?: string; by?: string; scope?: string }) =>
    get<S['LatencyHeatmap']>('/stats/latency/heatmap', q),
  latencyExemplars: (q: { from?: string; path?: string; scope?: string }) =>
    get<S['LatencyExemplars']>('/stats/latency/exemplars', q),
  // REQ: OBS-029 — queries per slot (network, a device, or a name).
  heatmap: (q: { from?: string; grain?: string; kind?: string; key?: string; measure?: string; scope?: string }) =>
    get<S['Heatmap']>('/stats/heatmap', q),
  // REQ: OBS-032 — where queries went (the network, or one device from the query log).
  flow: (q: { from?: string; client?: string; scope?: string }) => get<S['QueryFlow']>('/stats/flow', q),
  compare: (q: { from?: string; to?: string; step?: string }) => get<S['NodeCompare']>('/cluster/compare', q),
  // REQ: OBS-027 — who and what spent an objective's error budget.
  sloAttribution: (q: { objective?: string; from?: string; scope?: string; limit?: number; step?: string }) =>
    get<S['SloAttribution']>('/stats/slo/attribution', q),
  queries: (q: Query) => get<S['QueryPage']>('/queries', q),
  explain: (q: { name: string; client?: string; qtype?: string }) => get<S['Explanation']>('/explain', q),
  lists: () => get<S['Items_ListInfo']>('/lists'),
  // REQ: FLT-004 — "update lists now" (202: what was queued; `refreshing` in `lists()` follows it).
  refreshLists: (names?: string[]) =>
    call<S['ListsRefreshResult']>('POST', '/lists/refresh', {
      body: names?.length ? { names } : {},
      headers: { 'idempotency-key': newKey() },
    }),
  groups: () => get<S['Items_GroupInfo']>('/groups'),
  // REQ: FLT-012 (T7.9) — the blockable services.
  services: () => get<S['Items_ServiceInfo']>('/services'),
  clients: () => get<S['Items_ClientInfo']>('/clients'),
  // REQ: OBS-038 — `muted` true also lists findings an anomaly mute matched (each has `mutedBy`).
  anomalies: (since = '-7d', acknowledged?: boolean, muted?: boolean) =>
    get<S['Items_AnomalyFinding']>('/analytics/anomalies', {
      since,
      acknowledged: acknowledged === undefined ? undefined : String(acknowledged),
      muted: muted === undefined ? undefined : String(muted),
    }),
  // REQ: OBS-014 — acknowledge findings (or take it back), on every node.
  acknowledgeAnomalies: (ids: string[], note?: string) =>
    post<S['AnomalyAckResult']>('/analytics/anomalies/acknowledge', { ids, ...(note ? { note } : {}) }),
  unacknowledgeAnomalies: (ids: string[]) => post<S['AnomalyAckResult']>('/analytics/anomalies/unacknowledge', { ids }),
  // REQ: OBS-015 — healthy, degraded, or severe, and why.
  health: () => get<S['Health']>('/system/health'),
  // REQ: OBS-033 — change markers (every node's, newest first), and notes.
  annotations: (q: { from?: string; to?: string; kinds?: string; scope?: string; limit?: number; before?: string }) =>
    get<S['AnnotationPage']>('/annotations', q),
  annotate: (b: S['NoteRequest']) => post<S['Annotation']>('/annotations', b),
  // REQ: OBS-020 — the synthetic probes of every node's listeners.
  probes: () => get<S['Items_ProbeResult']>('/system/probes'),
  // REQ: OBS-009 (T7.14)
  newDomains: (since = '-24h', limit = 200) =>
    get<S['Items_NewDomain']>('/analytics/new-domains', { since, limit: String(limit) }),
  // REQ: AGT-012 (T8.6) — vqlog, from the Analyze page.
  vqlog: (q: string, dryRun = false) => get<S['VqlogResult']>('/analytics/vqlog', { q, dryRun: dryRun ? 'true' : undefined }),
  // REQ: T8.2, T8.3 — device names from the routers' DHCP and mDNS.
  dhcpLeases: () => get<S['Items_DhcpLease']>('/dhcp/leases'),
  // REQ: API-013 (T22.2, T24.15) - the networks the routers report, and the groups' networks.
  networks: () => get<S['Items_NetworkInfo']>('/networks'),
  // REQ: DNS-018 (T8.6)
  zones: () => get<S['Items_ZoneInfo']>('/zones'),
  // REQ: OBS-010 (T9.6)
  alertsStatus: () => get<S['AlertsStatus']>('/alerts'),
  alertTest: (name: string) => post<S['AlertTest']>(`/alerts/destinations/${encodeURIComponent(name)}/test`),
  // REQ: API-002 (T9.12) — pre-save checks of a draft.
  checkUpstream: (body: Record<string, unknown>) => post<S['CheckResult']>('/checks/upstream', body),
  checkList: (body: Record<string, unknown>) => post<S['CheckResult']>('/checks/list', body),
  // REQ: OBS-025 (T13.3) — what each device looks like.
  identities: () => get<S['Items_DeviceIdentity']>('/clients/identities'),
  identity: (id: string) => get<S['DeviceIdentity']>(`/clients/${encodeURIComponent(id)}/identity`),
  rhythm: (id: string) => get<S['ClientRhythm']>(`/clients/${encodeURIComponent(id)}/rhythm`),
  timeline: (id: string, q: { from?: string; to?: string; bins?: number; lanes?: number } = {}) =>
    get<S['DeviceTimeline']>(`/clients/${encodeURIComponent(id)}/timeline`, q),
  // REQ: FLT-017 (T15.1) — Kubernetes workloads as devices.
  kubernetesStatus: () => get<S['KubernetesStatus']>('/kubernetes/status'),
  workloads: (q: { namespace?: string; group?: string; cursor?: string } = {}) =>
    get<S['WorkloadPage']>('/kubernetes/workloads', q),
  // The key keeps its slashes: `namespace/kind/name`.
  putWorkloadGroup: (key: string, group: string, dryRun = false) =>
    call<S['ConfigChange']>('PUT', `/kubernetes/map/${key.split('/').map(encodeURIComponent).join('/')}`, {
      body: { group },
      query: { dryRun: dryRun || undefined },
      headers: dryRun ? {} : { 'idempotency-key': newKey() },
    }),
  // REQ: OBS-024 (T13.1) — what a whole shared configuration would have done.
  simulate: (body: S['SimulateRequest']) => post<S['Simulation']>('/simulate', body),
  cluster: () => get<S['ClusterView']>('/cluster'),
  promoteCluster: (emergency = false, password = '', totp = '') =>
    post<S['ClusterView']>('/cluster/promote', { emergency, password, ...(totp ? { totp } : {}) }),
  // REQ: CLU-001 (ADR-155) — remove a node from the cluster (admin); a node that is up needs `force`.
  removeNode: (id: string, o: { dryRun?: boolean; force?: boolean } = {}) =>
    call<S['NodeRemoval']>('DELETE', `/cluster/nodes/${encodeURIComponent(id)}`, {
      query: { dryRun: o.dryRun || undefined, force: o.force || undefined },
    }),
  // REQ: OPS-010 — maintenance on a node (`local` or a node ID): not ready, still answering.
  startMaintenance: (node: string, body: S['MaintenanceRequest']) =>
    post<S['MaintenanceResult']>(`/nodes/${encodeURIComponent(node)}/maintenance`, body),
  endMaintenance: (node: string) => call<S['MaintenanceResult']>('DELETE', `/nodes/${encodeURIComponent(node)}/maintenance`),
  // REQ: CLU-014 (T15.2) — failover drills (operators start and end them).
  startDrill: (node: string, body: S['DrillRequest'], dryRun = false) =>
    call<S['DrillStart']>('POST', `/nodes/${encodeURIComponent(node)}/drill`, { body, query: { dryRun: dryRun || undefined } }),
  endDrill: (node: string) => call<S['DrillStart']>('DELETE', `/nodes/${encodeURIComponent(node)}/drill`),
  activeDrill: (node: string) => get<S['ActiveDrill']>(`/nodes/${encodeURIComponent(node)}/drill`),
  drills: (limit = 20) => get<S['DrillPage']>('/drills', { limit }),
  drillReport: (id: string) => get<S['DrillReport']>(`/drills/${encodeURIComponent(id)}`),
  affinity: (window = '7d') => get<S['AffinityPage']>('/clients/affinity', { window }),
  // REQ: CLU-013 (T13.2) — staged rollouts and pins (commands need an admin).
  rolloutStatus: () => get<S['RolloutStatus']>('/cluster/rollout'),
  clusterVersions: () => get<S['ClusterVersions']>('/cluster/versions'),
  promoteRollout: () => post<S['RolloutAction']>('/cluster/rollout/promote'),
  abortRollout: () => post<S['RolloutAction']>('/cluster/rollout/abort'),
  pinVersion: (version: string, reason: string, dryRun = false) =>
    call<S['RolloutAction']>('POST', `/cluster/versions/${encodeURIComponent(version)}/pin`, {
      body: { reason },
      query: { dryRun: dryRun || undefined },
    }),
  unpin: (dryRun = false) => call<S['RolloutAction']>('DELETE', '/cluster/pin', { query: { dryRun: dryRun || undefined } }),
  localNames: () => get<S['Items_LocalName']>('/records'),
  forwards: () => get<S['Items_ForwardInfo']>('/forwards'),
  rules: () => get<S['Items_RuleInfo']>('/rules'),
  cacheStats: () => get<S['Items_CacheNodeStats']>('/cache/stats'),
  cacheLookup: (name: string) => get<S['CacheLookup']>('/cache/lookup', { name }),
  cacheEntries: (q: { sort?: string; limit?: number; node?: string }) =>
    get<S['Items_CacheNodeEntries']>('/cache/entries', q),
  cacheFlush: (body: S['CacheFlushRequest']) => post<S['CacheFlushResult']>('/cache/flush', body),
  blocking: () => get<S['Items_BlockingNode']>('/blocking'),
  blockingPause: (body: S['BlockingRequest']) => post<S['Items_BlockingNode']>('/blocking/pause', body),
  blockingResume: (body: S['BlockingRequest']) => post<S['Items_BlockingNode']>('/blocking/resume', body),
  upstreams: () => get<S['Items_UpstreamInfo']>('/upstreams'),
  // REQ: OBS-018 — what shadow lists would have blocked, and likely over-blocking.
  shadowLists: () => get<S['Items_ShadowListStats']>('/analytics/shadow-lists'),
  overblocking: (limit = 50) => get<S['Items_OverblockSuspect']>('/analytics/overblocking', { limit }),
  // REQ: OBS-019 — upstream answer quality and second opinions, per node.
  upstreamChecks: () => get<S['Items_UpstreamChecks']>('/analytics/upstream-checks'),

  // Configuration changes (API-002, API-010). Each change carries a fresh Idempotency-Key, so a
  // retried request (flaky Wi-Fi) is applied once.
  putClient: (name: string, body: S['ClientInput'], dryRun = false, simulate?: string) =>
    call<S['ClientChange']>('PUT', `/clients/${encodeURIComponent(name)}`, {
      body,
      query: { dryRun: dryRun || undefined, simulate: dryRun ? simulate : undefined },
      headers: dryRun ? {} : { 'idempotency-key': newKey() },
    }),
  putRecords: (name: string, body: S['RecordsInput'], dryRun = false, simulate?: string) =>
    call<S['ConfigChange']>('PUT', `/records/${encodeURIComponent(name)}`, {
      body,
      query: { dryRun: dryRun || undefined, simulate: dryRun ? simulate : undefined },
      headers: dryRun ? {} : { 'idempotency-key': newKey() },
    }),
  deleteRecords: (name: string) =>
    call<S['ConfigChange']>('DELETE', `/records/${encodeURIComponent(name)}`, { headers: { 'idempotency-key': newKey() } }),
  putForward: (domain: string, body: S['ForwardInput'], dryRun = false, simulate?: string) =>
    call<S['ConfigChange']>('PUT', `/forwards/${encodeURIComponent(domain)}`, {
      body,
      query: { dryRun: dryRun || undefined, simulate: dryRun ? simulate : undefined },
      headers: dryRun ? {} : { 'idempotency-key': newKey() },
    }),
  deleteForward: (domain: string) =>
    call<S['ConfigChange']>('DELETE', `/forwards/${encodeURIComponent(domain)}`, { headers: { 'idempotency-key': newKey() } }),
  // REQ: FLT-005 (T6.12) — quick rules.
  putRule: (id: string, body: S['RuleInput'], dryRun = false, simulate?: string) =>
    call<S['ConfigChange']>('PUT', `/rules/${encodeURIComponent(id)}`, {
      body,
      query: { dryRun: dryRun || undefined, simulate: dryRun ? simulate : undefined },
      headers: dryRun ? {} : { 'idempotency-key': newKey() },
    }),
  // REQ: API-015 (T23.6, ADR-903 §4) — stored secrets: metadata and the node's store only. A value
  // goes in once (PUT) and is never read back; the answers carry none.
  secrets: () => get<S['SecretsStatus']>('/secrets'),
  // REQ: API-015 (ADR-903 §2) — `ifMatch` is the secrets head's etag as the page last read it:
  // a write after another admin's change is refused (412) rather than overwriting it.
  putSecret: (name: string, value: string, kind = 'text', dryRun = false, ifMatch?: string) =>
    call<S['SecretChange']>('PUT', `/secrets/${encodeURIComponent(name)}`, {
      body: { value, kind },
      query: { dryRun: dryRun || undefined },
      headers: { ...(dryRun ? {} : { 'idempotency-key': newKey() }), ...(ifMatch ? { 'if-match': `"${ifMatch}"` } : {}) },
    }),
  deleteSecret: (name: string, force = false, ifMatch?: string) =>
    call<S['SecretChange']>('DELETE', `/secrets/${encodeURIComponent(name)}`, {
      query: { force: force || undefined },
      headers: { 'idempotency-key': newKey(), ...(ifMatch ? { 'if-match': `"${ifMatch}"` } : {}) },
    }),
  // REQ: API-002 (T7.5, ADR-069) — upstreams, upstream groups, lists, and groups.
  configEntries: (kind?: string) => get<S['Items_ConfigEntry']>('/config/entries', { kind }),
  // REQ: DSC-014 (T25.3) — the network inventory's status and its discovery workers.
  discoveryStatus: () => get<S['DiscoveryStatus']>('/discovery/status'),
  putEntry: (path: EntryPath, name: string, body: Record<string, unknown>, dryRun = false, simulate?: string) =>
    call<S['ConfigChange']>('PUT', `/${path}/${encodeURIComponent(name)}`, {
      body,
      query: { dryRun: dryRun || undefined, simulate: dryRun ? simulate : undefined },
      headers: dryRun ? {} : { 'idempotency-key': newKey() },
    }),
  deleteEntry: (path: EntryPath, name: string) =>
    call<S['ConfigChange']>('DELETE', `/${path}/${encodeURIComponent(name)}`, { headers: { 'idempotency-key': newKey() } }),
  deleteRule: (id: string) =>
    call<S['ConfigChange']>('DELETE', `/rules/${encodeURIComponent(id)}`, { headers: { 'idempotency-key': newKey() } }),
  deleteClient: (name: string) =>
    call<S['ClientChange']>('DELETE', `/clients/${encodeURIComponent(name)}`, {
      headers: { 'idempotency-key': newKey() },
    }),
};
