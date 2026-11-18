// REQ: OBS-016, OBS-020, OBS-019, OBS-013, OBS-003, OBS-005 (T27.5, ADR-1007) — the form fields of
// the tuning sections: the objectives (`[slo]`), the listener checks (`[probe]`), second opinions
// (`[upstream_check]`), device anomaly settings, the query log's store and the per-client metric
// series. The server checks every bound and refuses an unknown field; these bounds are the form's.
import type { Field } from './components/ConfigEditor.svelte';

export type TuningKey = 'slo' | 'probe' | 'upstream_check' | 'anomaly' | 'qlog' | 'metrics';

export type TuningSpec = {
  /** The kind the server lists the entry under (`GET /config/entries?kind=`). */
  kind: 'slo' | 'probe' | 'upstream_check' | 'anomaly_settings' | 'qlog_settings' | 'metrics_settings';
  /** The entry path (`PUT /{path}/default`). */
  path: 'slo-settings' | 'probe-settings' | 'upstream-check-settings' | 'anomaly-settings' | 'qlog-settings' | 'metrics-settings';
  title: string;
  noun: string;
  /** Who may change it: the telemetry sections are an admin's (ADR-1007). */
  role: 'operator' | 'admin';
  /** The one-line summary of the disclosure, before it is opened. */
  summary: string;
  fields: Field[];
  describe: (def: Record<string, unknown>) => string;
};

const num = (v: unknown) => (typeof v === 'number' ? v : Number(v ?? 0));

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
      { key: 'availability_target', label: 'Answers that must not fail (%)', type: 'number', min: 50, max: 100, initial: 99.9,
        help: 'SERVFAIL answers count against it; queries dropped by a rate limit do not.' },
      { key: 'latency_target', label: 'Answers that must be fast enough (%)', type: 'number', min: 50, max: 100, initial: 99 },
      { key: 'latency_ms', label: 'Fast enough means within (ms)', type: 'number', min: 1, max: 5000, initial: 250,
        help: 'One of 1, 5, 10, 25, 50, 100, 250, 500, 1000, 2500 or 5000 ms (the histogram bounds of /metrics).' },
      { key: 'window_days', label: 'Error budget window (days)', type: 'number', min: 1, max: 90, initial: 30,
        help: 'The burn-rate alerts are tuned for 30.' },
    ],
    describe: (d) =>
      `Availability ${num(d.availability_target)}%, latency ${num(d.latency_target)}% within ${num(d.latency_ms)} ms, over ${num(d.window_days)} days${d.enabled === false ? ' (off)' : ''}.`,
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
};
