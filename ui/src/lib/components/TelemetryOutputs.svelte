<script lang="ts">
  // REQ: API-016, OBS-010, OBS-006 (T23.11, ADR-903 §7, ADR-984) — Settings → Telemetry: where this
  // cluster sends query events (event sinks) and metrics (the OTLP export). Operators see them
  // read-only; only an admin adds, changes or removes one (the server enforces it). A sink or the
  // export changed here applies on every node within seconds, with no restart; one the
  // configuration files define is read-only ("set by file"); a token or header value is entered
  // through SecretField (write-only, stored by name).
  import { api, type S } from '../api';
  import { can } from '../session.svelte';
  import { poll } from '../poll';
  import ConfigEditor, { type Field } from './ConfigEditor.svelte';
  import ErrorNote from './ErrorNote.svelte';
  import HelpButton from './HelpButton.svelte';
  import OtlpExport from './OtlpExport.svelte';
  import { secretNameFor } from './SecretField.svelte';

  const isAdmin = $derived(can('admin'));
  let list = $state<S['SinkList'] | null>(null);
  let error = $state<unknown>(null);

  async function load() {
    try {
      list = await api.sinks();
      error = null;
    } catch (e) {
      error = e;
    }
  }
  $effect(() => poll(load, 10_000));
  // A change reaches this node's sinks within a second or so: read the status again then.
  const reloadSoon = () => {
    setTimeout(() => void load(), 1_500);
  };

  const type = (v: Record<string, unknown>) => v.type as string | undefined;
  const STATUSES = ['cached', 'forwarded', 'stale', 'refreshed', 'local', 'special', 'blocked', 'refused', 'rate_limited', 'malformed', 'servfail', 'dropped'];

  const sinkFields: Field[] = [
    { key: 'type', label: 'Type', type: 'select', options: ['webhook', 'syslog', 'file'], initial: 'webhook',
      help: 'webhook: batched HTTP POSTs (Loki, Vector, Splunk, a SIEM). syslog: RFC 5424 over UDP, TCP or TLS. file: JSON lines, rotated, on this node.' },
    { key: 'url', label: 'URL', type: 'text', placeholder: 'https://logs.example.net/ingest', showIf: (v) => type(v) === 'webhook',
      help: 'Where batches are posted. A password in the address is set in the configuration file, not here: store a token below instead.' },
    { key: 'format', label: 'Format', type: 'select', options: ['json_lines', 'json_array', 'otlp_logs'], showIf: (v) => type(v) === 'webhook',
      help: 'json_lines suits Loki, Vector and Fluent Bit; otlp_logs sends OpenTelemetry logs to <collector>/v1/logs.' },
    { key: 'token_ref', label: 'Token', type: 'secret', fileKey: 'token_file', secretName: (n) => secretNameFor('sink', n, 'token'),
      showIf: (v) => type(v) === 'webhook',
      help: 'Sent as Authorization: <scheme> <token>. Stored encrypted and read for every batch, so a rotated token is used from the next one.' },
    { key: 'token_scheme', label: 'Token scheme', type: 'text', placeholder: 'Bearer', advanced: true, showIf: (v) => type(v) === 'webhook',
      help: 'Bearer by default; Splunk HEC uses Splunk.' },
    { key: 'batch', label: 'Events per batch', type: 'number', placeholder: '500', showIf: (v) => type(v) === 'webhook' },
    { key: 'flush_secs', label: 'Longest wait for a batch (seconds)', type: 'number', placeholder: '5', showIf: (v) => type(v) === 'webhook' },
    { key: 'spill_max_bytes', label: 'Keep refused batches on disk (size)', type: 'text', placeholder: '64MiB', advanced: true, showIf: (v) => type(v) === 'webhook',
      help: 'Empty: a refused batch is dropped (and counted). Otherwise kept on this node up to this size and sent once the collector is back.' },
    { key: 'address', label: 'Address', type: 'text', placeholder: 'udp://192.168.1.20:514', showIf: (v) => type(v) === 'syslog',
      help: 'udp://host:514, tcp://host:514 or tls://host:6514. A private collector\'s CA is set in the configuration file.' },
    { key: 'facility', label: 'Syslog facility', type: 'number', placeholder: '16', advanced: true, showIf: (v) => type(v) === 'syslog', help: '16 is local0.' },
    { key: 'path', label: 'File name', type: 'text', placeholder: 'queries.jsonl', showIf: (v) => type(v) === 'file',
      help: 'Written under this node\'s data directory, in sinks/. Letters, digits, dot, dash and underscore only.' },
    { key: 'max_bytes', label: 'Rotate at (size)', type: 'text', placeholder: '100MiB', advanced: true, showIf: (v) => type(v) === 'file' },
    { key: 'keep', label: 'Rotated files kept', type: 'number', placeholder: '3', advanced: true, showIf: (v) => type(v) === 'file' },
    { key: 'statuses', label: 'Only these answers', type: 'multi', options: STATUSES,
      help: 'None chosen means every event. Names and clients follow the query log\'s privacy level.' },
    { key: 'max_buffer', label: 'Events held while it is slow', type: 'number', placeholder: '10000', advanced: true,
      help: 'Past this, new events are dropped and counted: a slow collector never slows DNS.' },
  ];

  function summary(def: Record<string, unknown>): string {
    const t = String(def.type ?? '');
    const where = t === 'file' ? String(def.path ?? '') : t === 'syslog' ? String(def.address ?? '') : String(def.url ?? '');
    return `${t}: ${where}${def.token_ref ? ' · token stored' : ''}`;
  }

</script>

<section class="card" data-testid="telemetry-tab">
  <h2>Where events and metrics go<HelpButton id="sinks" /></h2>
  <p class="muted">
    Copy every query event to your own log pipeline (an event sink), and push the metrics to an OpenTelemetry collector. A change applies on every node within
    seconds, with no restart, and a slow or missing destination never slows DNS.
  </p>
  {#if !isAdmin}
    <p class="notice" role="status" data-testid="telemetry-readonly">Only an admin changes these. You can see what each node sends.</p>
  {/if}
  <ErrorNote {error} />
  {#if list && list.items.length}
    <ul class="status small" data-testid="sink-status">
      {#each list.items as s (s.name)}
        <li data-testid="sink-state" data-sink={s.name}>
          <strong>{s.name}</strong>
          {#if s.running}<span class="badge ok">running on this node</span>{:else}<span class="badge bad">not running on this node</span>{/if}
          {#if s.reason}<span class="bad-text">{s.reason}</span>{/if}
          {#if s.tokenSource === 'stored'}
            <span class="muted">token <span class="mono">{s.token}</span></span>
            {#if s.tokenReadable === false}<span class="badge bad" data-testid="sink-token-issue">can't be read on this node</span>{/if}
          {:else if s.tokenSource === 'file'}
            <span class="muted">token from a file</span>
          {/if}
          {#if s.dropped > 0}<span class="badge warn" data-testid="sink-dropped">{s.dropped} dropped since start</span>{/if}
        </li>
      {/each}
    </ul>
  {/if}
</section>

<ConfigEditor
  kind="sink"
  path="sinks"
  role="admin"
  title="Event sinks"
  noun="sink"
  help="sinks"
  fields={sinkFields}
  {summary}
  fileReadOnly
  onchanged={() => {
    void load();
    reloadSoon();
  }}
/>

<OtlpExport />

<style>
  .status {
    list-style: none;
    padding: 0;
    margin: 0.5rem 0 0;
    display: grid;
    gap: 0.35rem;
  }
  .status li {
    display: flex;
    gap: 0.5rem;
    flex-wrap: wrap;
    align-items: center;
  }
  .bad-text {
    color: var(--bad, #b00020);
  }
  .notice {
    padding: 0.5rem 0.75rem;
    border-radius: 0.5rem;
    background: var(--panel-2, rgba(127, 127, 127, 0.12));
  }
</style>
