<script lang="ts">
  // REQ: API-016, OBS-006 (T23.11, ADR-903 §7, ADR-984) — the OTLP metrics export, as a card in
  // Settings → Telemetry. The collector's address and the interval are plain settings; each header's
  // value is a stored secret entered through SecretField (write-only, named in `header_refs`). A
  // destination the configuration files set is read-only ("set by file"), and its inline header
  // values show as <redacted>: a value is never shown again. Operators see it read-only.
  import { api, ApiError, type S } from '../api';
  import { can } from '../session.svelte';
  import { poll } from '../poll';
  import ErrorNote from './ErrorNote.svelte';
  import HelpButton from './HelpButton.svelte';
  import SecretField, { secretNameFor } from './SecretField.svelte';

  type Entry = S['OtlpEntry'];
  type Row = { header: string; ref: string | undefined };

  let entry = $state<Entry | null>(null);
  let error = $state<unknown>(null);
  let notice = $state('');
  const isAdmin = $derived(can('admin'));

  async function load() {
    try {
      entry = await api.otlp();
      error = null;
    } catch (e) {
      error = e;
    }
  }
  $effect(() => poll(load, 10_000));
  const reloadSoon = () => {
    setTimeout(() => void load(), 1_500);
  };

  // ---- the form
  let editing = $state(false);
  let endpoint = $state('');
  let interval = $state<number | string>(60);
  let compression = $state<'none' | 'gzip'>('none');
  let rows = $state<Row[]>([]);
  let formError = $state('');
  let busy = $state(false);
  let dirty = $state<Record<number, boolean>>({});
  const anyDirty = $derived(Object.values(dirty).some(Boolean));
  let confirmOff = $state(false);

  function openForm() {
    if (!entry) return;
    editing = true;
    formError = '';
    notice = '';
    dirty = {};
    endpoint = entry.endpoint ?? 'http://';
    interval = entry.intervalSecs;
    compression = entry.compression === 'gzip' ? 'gzip' : 'none';
    rows = entry.headers.filter((h) => h.source === 'stored').map((h) => ({ header: h.name, ref: h.secret ?? undefined }));
  }
  function closeForm() {
    editing = false;
    formError = '';
    dirty = {};
  }
  function addHeader() {
    rows.push({ header: '', ref: undefined });
  }
  function dropHeader(i: number) {
    rows.splice(i, 1);
    dirty = {};
  }

  const headerOk = (h: string) => /^[A-Za-z0-9_-]{1,64}$/.test(h);

  function bodyOf(): Record<string, unknown> {
    const refs: Record<string, string> = {};
    for (const r of rows) if (r.header.trim() && r.ref) refs[r.header.trim()] = r.ref;
    const body: Record<string, unknown> = { endpoint: endpoint.trim(), interval_secs: Number(interval) || 60, header_refs: refs };
    // Plain stays out of the body: an unchanged export never needs a member that reads the field.
    if (compression === 'gzip') body.compression = 'gzip';
    return body;
  }

  async function save() {
    formError = '';
    if (!/^https?:\/\//.test(endpoint.trim())) {
      formError = 'The collector address starts with http:// or https://, for example http://otel-collector:4318.';
      return;
    }
    if (Number(interval) < 5) {
      formError = 'The interval is at least 5 seconds.';
      return;
    }
    const names = rows.map((r) => r.header.trim()).filter(Boolean);
    if (names.some((n) => !headerOk(n))) {
      formError = 'A header name is letters, digits, dash or underscore.';
      return;
    }
    if (new Set(names.map((n) => n.toLowerCase())).size !== names.length) {
      formError = 'Each header is listed once.';
      return;
    }
    if (rows.some((r) => r.header.trim() && !r.ref)) {
      formError = 'Save a value for each header, or remove it.';
      return;
    }
    busy = true;
    try {
      await api.putOtlp(bodyOf());
      notice = 'Saved. It applies on every node within seconds, with no restart.';
      closeForm();
      await load();
      reloadSoon();
    } catch (e) {
      formError = e instanceof ApiError ? e.message : 'The export could not be saved.';
    } finally {
      busy = false;
    }
  }

  async function turnOff() {
    busy = true;
    try {
      await api.deleteOtlp();
      notice = 'The export is off. Metrics stop going out on every node.';
      confirmOff = false;
      await load();
      reloadSoon();
    } catch (e) {
      notice = e instanceof ApiError ? e.message : 'The export could not be turned off.';
    } finally {
      busy = false;
    }
  }

  const sourceLabel: Record<string, string> = { none: 'Off', file: 'Set by file', api: 'From the UI' };
</script>

<section class="card" data-testid="otlp-card">
  <div class="head">
    <h2>OpenTelemetry metrics export<HelpButton id="otlp" /></h2>
    {#if entry}<span class="badge {entry.source === 'file' ? 'warn' : ''}" data-testid="otlp-source">{sourceLabel[entry.source] ?? entry.source}</span>{/if}
  </div>
  <p class="muted">
    Push the metrics to an OpenTelemetry collector (the OpenTelemetry Collector, Grafana Alloy, a hosted backend) instead of, or as well as, having Prometheus scrape them.
    The same collector can take sampled traces; those settings stay in the configuration file.
  </p>
  <ErrorNote {error} />
  {#if notice}<p class="notice" role="status" data-testid="otlp-notice">{notice}</p>{/if}

  {#if entry}
    {#if entry.endpoint}
      <ul class="facts small">
        <li>Collector: <span class="mono" data-testid="otlp-endpoint">{entry.endpoint}</span> (metrics go to <span class="mono">/v1/metrics</span>)</li>
        <li>Every {entry.intervalSecs} seconds{#if entry.compression === 'gzip'}, <span data-testid="otlp-compression">gzip compressed</span>{/if}</li>
        <li>
          {#if entry.active}<span class="badge ok" data-testid="otlp-state">Exporting from this node</span>{:else}<span class="badge bad" data-testid="otlp-state">Not exporting from this node</span>{/if}
          {#if entry.reason}<span class="bad-text" data-testid="otlp-reason">{entry.reason}</span>{/if}
        </li>
        {#each entry.headers as h (h.name)}
          <li data-testid="otlp-header" data-header={h.name}>
            Header <span class="mono">{h.name}</span>:
            {#if h.source === 'stored'}
              a stored secret (<span class="mono">{h.secret}</span>)
              {#if h.readable === false}<span class="badge bad" data-testid="otlp-header-issue">can't be read on this node</span>{:else}<span class="badge ok">readable</span>{/if}
            {:else}
              <span class="mono" data-testid="otlp-header-redacted">{h.value ?? '<redacted>'}</span>
              <span class="muted">set in the configuration file; the value is never shown. To change it, edit the file, or move it to a stored secret.</span>
              <HelpButton id="credentials-in-forms" />
            {/if}
          </li>
        {/each}
      </ul>
    {:else}
      <p class="empty" data-testid="otlp-off">No export is set. Add a collector to send metrics.</p>
    {/if}

    {#if entry.source === 'file'}
      <p class="small muted" data-testid="otlp-file-note">The configuration file sets the collector, so it is read-only here.</p>
    {:else if isAdmin && !editing}
      <div class="row-actions">
        <button type="button" class="btn primary" data-testid="otlp-edit" onclick={openForm}>{entry.source === 'api' ? 'Change the export' : 'Set up the export'}</button>
        {#if entry.source === 'api'}
          {#if confirmOff}
            <button type="button" class="btn danger" data-testid="otlp-off-confirm" onclick={turnOff} disabled={busy}>Yes, turn it off</button>
            <button type="button" class="btn" onclick={() => (confirmOff = false)}>Keep it</button>
          {:else}
            <button type="button" class="btn danger" data-testid="otlp-off-button" onclick={() => (confirmOff = true)}>Turn it off</button>
          {/if}
        {/if}
      </div>
    {:else if !isAdmin && entry.source !== 'file'}
      <p class="small muted" data-testid="otlp-readonly">Only an admin changes this.</p>
    {/if}
  {/if}

  {#if editing}
    <div class="card inner" data-testid="otlp-editor" role="group" aria-label="OTLP export">
      <div class="grid">
        <label>
          <span>Collector address</span>
          <input bind:value={endpoint} placeholder="http://otel-collector:4318" autocomplete="off" aria-label="Collector address" />
        </label>
        <label>
          <span>Seconds between exports</span>
          <input type="number" min="5" bind:value={interval} aria-label="Seconds between exports" />
        </label>
        <label>
          <span>Compression</span>
          <select bind:value={compression} data-testid="otlp-compression-select" aria-label="Compression">
            <option value="none">None (plain JSON)</option>
            <option value="gzip">gzip</option>
          </select>
        </label>
      </div>
      <h4>Headers</h4>
      <p class="small muted">
        For a hosted collector that wants an API key. Each value is stored encrypted on the node, replicated to the other nodes, read for every export, and never shown again.
      </p>
      {#each rows as r, i (i)}
        <div class="header-row" data-testid="otlp-row">
          <input bind:value={r.header} placeholder="x-api-key" autocomplete="off" aria-label={`Header name ${i + 1}`} />
          {#if r.header.trim() && headerOk(r.header.trim())}
            <SecretField
              label={`Value of ${r.header.trim()}`}
              testid={`otlp-secret-${i}`}
              reference={r.ref}
              defaultName={secretNameFor('otlp', 'default', `header-${r.header.trim()}`)}
              canSet={true}
              ondirty={(d) => (dirty[i] = d)}
              onreference={(n) => (r.ref = n)}
            />
          {:else}
            <span class="small muted">Name the header first.</span>
          {/if}
          <button type="button" class="btn" aria-label={`Remove header ${i + 1}`} onclick={() => dropHeader(i)}>Remove</button>
        </div>
      {/each}
      <div class="row-actions">
        <button type="button" class="btn" data-testid="otlp-add-header" onclick={addHeader}>Add a header</button>
      </div>
      {#if anyDirty}<p class="notice warn small" role="status" data-testid="otlp-secret-unsaved">Save or discard the value you typed first; Save the export waits for it.</p>{/if}
      {#if formError}<p class="bad-text" role="alert" data-testid="otlp-error">{formError}</p>{/if}
      <div class="row-actions">
        <button type="button" class="btn primary" data-testid="otlp-save" onclick={save} disabled={busy || anyDirty}>Save the export</button>
        <button type="button" class="btn" onclick={closeForm}>Cancel</button>
      </div>
    </div>
  {/if}
</section>

<style>
  .head {
    display: flex;
    align-items: center;
    gap: 0.75rem;
    flex-wrap: wrap;
  }
  .head h2 {
    margin: 0;
  }
  .row-actions {
    display: flex;
    gap: 0.5rem;
    flex-wrap: wrap;
    margin: 0.5rem 0;
  }
  .grid {
    display: grid;
    gap: 0.75rem;
    grid-template-columns: repeat(auto-fit, minmax(14rem, 1fr));
  }
  label {
    display: grid;
    gap: 0.25rem;
  }
  .header-row {
    display: grid;
    gap: 0.5rem;
    margin: 0.5rem 0;
    padding: 0.5rem;
    border: 1px dashed var(--border);
    border-radius: var(--radius-md);
  }
  .facts {
    list-style: none;
    padding: 0;
    margin: 0.25rem 0;
    display: grid;
    gap: 0.25rem;
  }
  .inner {
    margin-top: 0.75rem;
  }
  .bad-text {
    color: var(--bad);
  }
</style>
