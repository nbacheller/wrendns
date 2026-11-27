// REQ: OBS-016, OBS-020, OBS-019, OBS-013, OBS-003, OBS-005 (T27.5, ADR-1007) — the form fields of
// the tuning sections: the objectives (`[slo]`), the listener checks (`[probe]`), second opinions
// (`[upstream_check]`), device anomaly settings, the query log's store and the per-client metric
// series. The server checks every bound and refuses an unknown field; these bounds are the form's,
// and `validate` repeats the server's checks that a single bound can't say (REQ: API-901).
import type { Field } from './components/ConfigEditor.svelte';

export type TuningKey = 'slo' | 'probe' | 'upstream_check' | 'anomaly' | 'qlog' | 'metrics' | 'dnstap';

export type TuningSpec = {
  /** The kind the server lists the entry under (`GET /config/entries?kind=`). */
  kind: 'slo' | 'probe' | 'upstream_check' | 'anomaly_settings' | 'qlog_settings' | 'metrics_settings' | 'dnstap_settings';
  /** The entry path (`PUT /{path}/default`). */
  path: 'slo-settings' | 'probe-settings' | 'upstream-check-settings' | 'anomaly-settings' | 'qlog-settings' | 'metrics-settings' | 'dnstap-settings';
  title: string;
  noun: string;
  /** Who may change it: the telemetry sections are an admin's (ADR-1007). */
  role: 'operator' | 'admin';
  /** The one-line summary of the disclosure, before it is opened. */
  summary: string;
  fields: Field[];
  /** A sentence under the fields (dnstap: the settings are read when a node starts). */
  note?: string;
  /** The guarded row that takes a change the server refuses as `guarded_only` (dnstap: a widening). */
  guardedId?: string;
  describe: (def: Record<string, unknown>) => string;
  /** The reason a draft is refused, or null (the server checks the same; this is the sooner check). */
  validate?: (values: Record<string, unknown>) => string | null;
};

const num = (v: unknown) => (typeof v === 'number' ? v : Number(v ?? 0));
/** A value the user gave (an empty field is left out, so the server's default applies). */
const given = (v: unknown) => v !== undefined && v !== null && v !== '';
/** The histogram bounds of /metrics (`SLO_LATENCY_MS` in wrendns-config). */
const SLO_LATENCY_MS = [1, 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000];
/** A byte size as the server reads it (`ByteSize::parse`): a number, then an optional unit. */
const SIZE = /^\s*\d+\s*(B|KiB|K|k|MiB|M|GiB|G|TiB|T|KB|kB|MB|GB|TB)?\s*$/;

export const TUNING: Record<TuningKey, TuningSpec> = {
  slo: {
    kind: 'slo',
    path: 'slo-settings',
    title: 'Objectives',
    noun: 'objectives',
    role: 'operator',
    summary: 'Change the objectives',
    fields: [
      { key: 'enabled', label: 'Track the objectives', type: 'bool', initial: true },
      { key: 'availability_target', label: 'Answers that must not fail (%)', type: 'number', min: 50, max: 99.999, initial: 99.9,
        help: 'SERVFAIL answers count against it; queries dropped by a rate limit do not. Below 100: 100 leaves no budget to burn.' },
      { key: 'latency_target', label: 'Answers that must be fast enough (%)', type: 'number', min: 50, max: 99.999, initial: 99,
        help: 'Below 100, as above.' },
      { key: 'latency_ms', label: 'Fast enough means within (ms)', type: 'number', min: 1, max: 5000, initial: 250,
        help: 'One of 1, 5, 10, 25, 50, 100, 250, 500, 1000, 2500 or 5000 ms (the histogram bounds of /metrics).' },
      { key: 'window_days', label: 'Error budget window (days)', type: 'number', min: 1, max: 90, initial: 30,
        help: 'The burn-rate alerts are tuned for 30.' },
    ],
    describe: (d) =>
      `Availability ${num(d.availability_target)}%, latency ${num(d.latency_target)}% within ${num(d.latency_ms)} ms, over ${num(d.window_days)} days${d.enabled === false ? ' (off)' : ''}.`,
    validate: (v) => {
      for (const [k, label] of [['availability_target', 'Answers that must not fail'], ['latency_target', 'Answers that must be fast enough']] as const) {
        if (given(v[k]) && !(Number(v[k]) >= 50 && Number(v[k]) < 100)) return `${label}: a percentage from 50 up to (not including) 100.`;
      }
      if (given(v.latency_ms) && !SLO_LATENCY_MS.includes(Number(v.latency_ms)))
        return `Fast enough means within one of ${SLO_LATENCY_MS.join(', ')} ms (the histogram bounds of /metrics).`;
      return null;
    },
  },
  probe: {
    kind: 'probe',
    path: 'probe-settings',
    title: 'Listener checks',
    noun: 'listener checks',
    role: 'operator',
    summary: 'Change the listener checks',
    fields: [
      { key: 'enabled', label: 'Check the listeners', type: 'bool', initial: true },
      { key: 'interval_secs', label: 'Seconds between rounds', type: 'number', min: 5, max: 86400, initial: 30 },
      { key: 'timeout_ms', label: 'Timeout per check (ms)', type: 'number', min: 100, max: 10000, initial: 2000 },
      { key: 'cert_warn_days', label: 'Warn when a certificate expires within (days)', type: 'number', min: 1, max: 365, initial: 14 },
      { key: 'targets', label: 'Extra addresses to check', type: 'lines', placeholder: 'udp://10.50.5.112:53\ntls://10.50.5.112:853',
        help: 'A load balancer or another address, one per line. Certificates aren’t verified for these.' },
    ],
    describe: (d) =>
      `Every ${num(d.interval_secs)} s, timeout ${num(d.timeout_ms)} ms${d.enabled === false ? ' (off)' : ''}.`,
    validate: (v) =>
      given(v.timeout_ms) && given(v.interval_secs) && Math.floor(Number(v.timeout_ms) / 1000) >= Number(v.interval_secs)
        ? 'The timeout must be shorter than the interval: the timeout in whole seconds must be below the interval in seconds.'
        : null,
  },
  upstream_check: {
    kind: 'upstream_check',
    path: 'upstream-check-settings',
    title: 'Second opinions',
    noun: 'second opinions',
    role: 'operator',
    summary: 'Change the second opinions',
    fields: [
      { key: 'sample_every', label: 'One answer in this many gets a second opinion (0 is off)', type: 'number', min: 0, max: 1000000, initial: 0,
        help: 'The second upstream sees the sampled names.' },
      { key: 'reference', label: 'Reference group (optional)', type: 'text', placeholder: 'quad9',
        help: 'The upstream group asked for second opinions. Empty: another upstream of the same group.' },
      { key: 'keep', label: 'Disagreements kept', type: 'number', min: 1, max: 1000, initial: 100 },
    ],
    describe: (d) =>
      num(d.sample_every) === 0 ? 'Off.' : `One answer in ${num(d.sample_every)} is checked against a second upstream.`,
  },
  anomaly: {
    kind: 'anomaly_settings',
    path: 'anomaly-settings',
    title: 'Device anomaly settings',
    noun: 'anomaly settings',
    role: 'admin',
    summary: 'Change the anomaly settings',
    fields: [
      { key: 'enabled', label: 'Detect anomalies', type: 'bool', initial: true },
      { key: 'learning_days', label: 'Learning period (days)', type: 'number', min: 1, max: 90, initial: 7,
        help: 'A device can raise a finding only after this long.' },
      { key: 'sensitivity', label: 'Sensitivity', type: 'select', options: ['low', 'normal', 'high'], initial: 'normal' },
      { key: 'max_clients', label: 'Devices with state', type: 'number', min: 1, max: 100000, initial: 1024 },
      { key: 'ignore_domains', label: 'Domains never reported', type: 'lines', placeholder: 'connectivitycheck.gstatic.com' },
      { key: 'nxdomain_per_minute', label: 'NXDOMAIN storm: answers a minute', type: 'number', min: 1, max: 100000, initial: 30 },
      { key: 'nxdomain_percent', label: 'NXDOMAIN storm: percent of queries', type: 'number', min: 1, max: 100, initial: 50 },
    ],
    describe: (d) =>
      `${d.enabled === false ? 'Off' : `${String(d.sensitivity ?? 'normal')} sensitivity, learning ${num(d.learning_days)} days`}.`,
  },
  qlog: {
    kind: 'qlog_settings',
    path: 'qlog-settings',
    title: 'Query log store',
    noun: 'query log settings',
    role: 'admin',
    summary: 'Change the store, retention and privacy',
    fields: [
      { key: 'enabled', label: 'Keep the query log', type: 'bool', initial: true },
      { key: 'retention_days', label: 'Keep for (days)', type: 'number', min: 1, max: 3650, initial: 30 },
      { key: 'retention_bytes', label: 'Keep at most (size)', type: 'text', placeholder: '2GiB',
        help: 'A size such as 500MiB or 2GiB. The oldest segments go first.' },
      { key: 'privacy_level', label: 'Privacy level (0 to 3)', type: 'number', min: 0, max: 3, initial: 0,
        help: '0 full; 1 hides domains; 2 hides domains and devices; 3 keeps aggregates only.' },
      { key: 'fsync', label: 'Flush each block to disk (fsync)', type: 'bool', initial: false },
      { key: 'flush_interval_secs', label: 'Flush the open block after (s)', type: 'number', min: 1, max: 3600, initial: 10 },
    ],
    describe: (d) =>
      `Privacy level ${num(d.privacy_level)}, kept ${num(d.retention_days)} days${d.enabled === false ? ' (off)' : ''}.`,
    validate: (v) =>
      given(v.retention_bytes) && !SIZE.test(String(v.retention_bytes))
        ? 'Keep at most: a size such as 500MiB or 2GiB (B, KiB, MiB, GiB, TiB, KB, MB, GB or TB).'
        : null,
  },
  metrics: {
    kind: 'metrics_settings',
    path: 'metrics-settings',
    title: 'Per-client metric series',
    noun: 'metric series settings',
    role: 'admin',
    summary: 'Change the per-client metric series',
    fields: [
      { key: 'per_client', label: 'Export a series per device', type: 'bool', initial: false,
        help: 'High cardinality: one series per device. Off by default.' },
      { key: 'per_client_cap', label: 'Devices with their own series', type: 'number', min: 1, max: 10000, initial: 100,
        help: 'The rest are counted as “other”.' },
    ],
    describe: (d) => (d.per_client ? `Per device, up to ${num(d.per_client_cap)} devices.` : 'Off.'),
  },
  // REQ: OBS-007, API-905 (T40.13) — the whole [telemetry.dnstap] section. It is read when a node starts,
  // so the row says "Restart needed" while the running tap differs (`restart_needed`, this node's answer).
  dnstap: {
    kind: 'dnstap_settings',
    path: 'dnstap-settings',
    title: 'dnstap output',
    noun: 'dnstap settings',
    role: 'admin',
    summary: 'Change the dnstap output',
    guardedId: 'dnstap-output',
    note: 'dnstap is read when a node starts: a saved change takes effect after a restart of each node (restart needed). Turning it on, pointing it at another socket or address, copying more kinds of exchange or sampling more often copies more of the clients’ queries out of the process, so Check sends it to the review: a preview, a phrase you type and a sign-in from the last 10 minutes. The settings are each node’s own: a change here is for the node you are on, and judged against what that node will run. Going back to the file’s values when they copy more is the review’s too.',
    fields: [
      { key: 'socket', label: 'Unix socket of the reader', type: 'text', placeholder: '/run/dnstap.sock',
        help: 'Leave the socket and the address empty for no tap.' },
      { key: 'address', label: 'Or a TCP reader', type: 'text', placeholder: 'tcp://host:port' },
      { key: 'sample_every', label: 'Copy one query in', type: 'number', min: 1, initial: 1, help: '1 copies every query.' },
      { key: 'buffer', label: 'Copies held while the reader is slow', type: 'number', min: 100, max: 1000000, initial: 10000 },
      { key: 'forwarder', label: 'Also copy queries to upstreams and their answers', type: 'bool', initial: false },
      { key: 'resolver', label: 'Also copy the recursive resolver’s queries and answers', type: 'bool', initial: false },
    ],
    describe: (d) =>
      `${d.socket || d.address ? `Copying to ${String(d.socket || d.address)}, one query in ${num(d.sample_every)}` : 'Off'}; upstream ${d.forwarder ? 'on' : 'off'}, resolver ${d.resolver ? 'on' : 'off'}.${d.restart_needed ? ' Restart needed.' : ''}`,
    validate: (v) => {
      if (given(v.socket) && given(v.address)) return 'Set a socket or an address, not both.';
      // eslint-disable-next-line no-control-regex
      if (given(v.socket) && (!String(v.socket).startsWith('/') || /[ -]/.test(String(v.socket)))) return 'The socket is an absolute path, for example /run/dnstap.sock.';
      if (given(v.address) && !/:\d{1,5}$/.test(String(v.address))) return 'The address is tcp://host:port.';
      if (given(v.sample_every) && !(Number.isInteger(Number(v.sample_every)) && Number(v.sample_every) >= 1)) return 'Copy one query in: a whole number, at least 1.';
      if (given(v.buffer) && !(Number(v.buffer) >= 100 && Number(v.buffer) <= 1000000)) return 'Copies held: from 100 to 1,000,000.';
      return null;
    },
  },
};
