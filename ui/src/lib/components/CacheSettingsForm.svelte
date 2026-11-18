<script lang="ts">
  // REQ: DNS-006 (T27.2, ADR-1006) — the `[cache]` settings of one node, on the Cache page: a form
  // for operators (a viewer reads them), with the fields the configuration files set locked, a
  // preview before the change is saved, and "pending restart" until the node restarts (the cache is
  // sized and tuned when a node starts, so every field applies then).
  import { api, type S } from '../api';
  import { can } from '../session.svelte';
  import { duration } from '../format';
  import ErrorNote from './ErrorNote.svelte';
  import HelpButton from './HelpButton.svelte';

  let { node = null }: { node?: string | null } = $props();

  type Section = S['NodeSection'];
  let owner = $state('');
  let section = $state<Section | null>(null);
  let error = $state<unknown>(null);
  let notice = $state('');

  // The form (operators); the preview of the last Check is what Apply sends.
  type Form = {
    mib: number;
    max_entries: number;
    min_ttl: number;
    max_ttl: number;
    negative_ttl_max: number;
    servfail_ttl: number;
    serve_stale: boolean;
    stale_max_age: number;
    stale_answer_client_timeout_ms: number;
    stale_answer_ttl: number;
    prefetch: boolean;
    prefetch_threshold_pct: number;
    prefetch_min_hits: number;
    persist: boolean;
    warm_names: number;
  };
  let form = $state<Form | null>(null);
  let preview = $state<S['ConfigChange'] | null>(null);
  let formError = $state<unknown>(null);
  let busy = $state(false);

  const writable = $derived(can('operator'));
  const fields = $derived((section?.fields ?? {}) as Record<string, unknown>);
  const fileSet = $derived(section?.setByFile ?? []);
  const setByFile = (k: string) => fileSet.includes(k);
  const pending = $derived(section?.pendingRestart === true);

  // Sizes come back as text ("32MiB"); the form works in MiB.
  const UNITS: Record<string, number> = { B: 1, KB: 1e3, KIB: 1024, MB: 1e6, MIB: 1024 ** 2, GB: 1e9, GIB: 1024 ** 3 };
  function parseBytes(v: unknown): number {
    if (typeof v === 'number') return v;
    const m = /^\s*(\d+(?:\.\d+)?)\s*([a-z]*)\s*$/i.exec(String(v ?? ''));
    if (!m) return 0;
    return Math.round(Number(m[1]) * (UNITS[(m[2] || 'B').toUpperCase()] ?? 1));
  }
  const num = (k: string) => Number(fields[k] ?? 0);
  const flag = (k: string) => fields[k] === true;

  async function load() {
    try {
      const ns = await api.nodeSettings(node);
      owner = ns.node;
      section = ns.sections.find((s) => s.section === 'cache') ?? null;
      error = null;
    } catch (e) {
      error = e;
    }
  }
  $effect(() => {
    void node;
    void load();
  });

  function open() {
    preview = null;
    formError = null;
    notice = '';
    form = {
      mib: parseBytes(fields.max_bytes) / 1048576,
      max_entries: num('max_entries'),
      min_ttl: num('min_ttl'),
      max_ttl: num('max_ttl'),
      negative_ttl_max: num('negative_ttl_max'),
      servfail_ttl: num('servfail_ttl'),
      serve_stale: flag('serve_stale'),
      stale_max_age: num('stale_max_age'),
      stale_answer_client_timeout_ms: num('stale_answer_client_timeout_ms'),
      stale_answer_ttl: num('stale_answer_ttl'),
      prefetch: flag('prefetch'),
      prefetch_threshold_pct: num('prefetch_threshold_pct'),
      prefetch_min_hits: num('prefetch_min_hits'),
      persist: flag('persist'),
      warm_names: num('warm_names'),
    };
  }

  // The body: the fields the files don't set (the files' values apply to those, as the server keeps them).
  function body(): Record<string, unknown> {
    const f = form!;
    const all: Record<string, unknown> = {
      max_bytes: Math.round(Number(f.mib) * 1048576),
      max_entries: Number(f.max_entries),
      min_ttl: Number(f.min_ttl),
      max_ttl: Number(f.max_ttl),
      negative_ttl_max: Number(f.negative_ttl_max),
      servfail_ttl: Number(f.servfail_ttl),
      serve_stale: f.serve_stale,
      stale_max_age: Number(f.stale_max_age),
      stale_answer_client_timeout_ms: Number(f.stale_answer_client_timeout_ms),
      stale_answer_ttl: Number(f.stale_answer_ttl),
      prefetch: f.prefetch,
      prefetch_threshold_pct: Number(f.prefetch_threshold_pct),
      prefetch_min_hits: Number(f.prefetch_min_hits),
      persist: f.persist,
      warm_names: Number(f.warm_names),
    };
    for (const k of fileSet) delete all[k];
    return all;
  }

  async function check(e: SubmitEvent) {
    e.preventDefault();
    if (!form) return;
    busy = true;
    formError = null;
    try {
      preview = await api.putEntry('cache-settings', owner, body(), true);
    } catch (err) {
      formError = err;
      preview = null;
    } finally {
      busy = false;
    }
  }

  async function apply() {
    if (!form) return;
    busy = true;
    try {
      await api.putEntry('cache-settings', owner, body(), false);
      form = null;
      preview = null;
      notice = 'Saved. The new cache settings take effect when this node restarts.';
      await load();
    } catch (err) {
      formError = err;
    } finally {
      busy = false;
    }
  }

  async function revert() {
    busy = true;
    try {
      await api.deleteEntry('cache-settings', owner);
      form = null;
      notice = 'Back to the configuration file. It takes effect when this node restarts.';
      await load();
    } catch (err) {
      error = err;
    } finally {
      busy = false;
    }
  }

  const stale = (ms: number) => (ms === 0 ? 'answered at once and refreshed in the background' : `when upstreams don't answer within ${(ms / 1000).toFixed(1)} s`);
</script>

<details class="settings" open={writable && form !== null} data-testid="cache-node-settings">
  <summary class="small">Settings {#if pending}<span class="badge warn" data-testid="cache-pending-restart">pending restart</span>{/if}</summary>
  <ErrorNote {error} />
  {#if notice}<p class="notice ok small" role="status">{notice}</p>{/if}
  {#if section}
    {#if !form}
      <dl class="facts small" data-testid="cache-settings">
        <dt>Memory</dt>
        <dd>
          {String(fields.max_bytes ?? '')}{#if num('max_entries')}{`, at most ${num('max_entries')} answers`}{/if}
          {#if setByFile('max_bytes')}<span class="muted"> (set by file)</span>{/if}
        </dd>
        <dt>TTL</dt>
        <dd>{duration(num('min_ttl'))} to {duration(num('max_ttl'))}; negative answers up to {duration(num('negative_ttl_max'))}; SERVFAIL {duration(num('servfail_ttl'))}</dd>
        <dt>Serve stale</dt>
        <dd>
          {#if !flag('serve_stale')}off{:else}{stale(num('stale_answer_client_timeout_ms'))}, for up to {duration(num('stale_max_age'))} after expiry{/if}
        </dd>
        <dt>Prefetch</dt>
        <dd>{flag('prefetch') ? `on, with under ${num('prefetch_threshold_pct')}% of the TTL left, after ${num('prefetch_min_hits')} hits` : 'off'}</dd>
        <dt>Across restarts</dt>
        <dd>{flag('persist') ? 'kept' : 'not kept'}; warm start from {num('warm_names')} hot names</dd>
      </dl>
      {#if writable}
        <div class="row">
          <button onclick={open} data-testid="cache-settings-edit">Change cache settings</button>
          {#if section.stored}
            <button class="link" disabled={busy} onclick={revert}>Revert to the file</button>
          {/if}
        </div>
      {:else}
        <p class="muted small">Operators change these. Every field applies when the node restarts.</p>
      {/if}
    {:else}
      <form class="form" data-testid="cache-settings-form" onsubmit={check}>
        <p class="muted small">Every field here applies when this node restarts, not at once.</p>
        <label>
          Memory budget (MiB)
          <input type="number" min="1" aria-label="Memory budget (MiB)" bind:value={form.mib} readonly={setByFile('max_bytes')} />
          {#if setByFile('max_bytes')}<span class="muted small" data-testid="set-by-file">Set by the configuration file: change it there.</span>{/if}
          <span class="muted small">How much memory cached answers may use. <HelpButton id="cache-size" /></span>
        </label>
        <label>
          Most answers (0: no limit)
          <input type="number" min="0" aria-label="Most answers" bind:value={form.max_entries} readonly={setByFile('max_entries')} />
        </label>
        <label>
          Shortest TTL served (seconds)
          <input type="number" min="0" aria-label="Shortest TTL served (seconds)" bind:value={form.min_ttl} readonly={setByFile('min_ttl')} />
          <span class="muted small">How long answers are kept at least. <HelpButton id="cache-ttl" /></span>
        </label>
        <label>
          Longest TTL served (seconds)
          <input type="number" min="0" aria-label="Longest TTL served (seconds)" bind:value={form.max_ttl} readonly={setByFile('max_ttl')} />
        </label>
        <label>
          Longest TTL for "no such name" answers (seconds)
          <input type="number" min="0" aria-label="Longest TTL for negative answers (seconds)" bind:value={form.negative_ttl_max} readonly={setByFile('negative_ttl_max')} />
        </label>
        <label>
          How long SERVFAIL is kept (seconds)
          <input type="number" min="0" aria-label="How long SERVFAIL is kept (seconds)" bind:value={form.servfail_ttl} readonly={setByFile('servfail_ttl')} />
        </label>
        <label class="check">
          <input type="checkbox" role="switch" aria-label="Serve stale answers when upstreams fail" bind:checked={form.serve_stale} disabled={setByFile('serve_stale')} />
          Serve stale answers when upstreams fail
        </label>
        <label>
          Keep stale answers for (seconds)
          <input type="number" min="0" aria-label="Keep stale answers for (seconds)" bind:value={form.stale_max_age} readonly={setByFile('stale_max_age')} />
        </label>
        <label>
          Wait for upstreams before answering stale (ms, 0: at once)
          <input type="number" min="0" aria-label="Wait for upstreams before answering stale (ms)" bind:value={form.stale_answer_client_timeout_ms} readonly={setByFile('stale_answer_client_timeout_ms')} />
          <span class="muted small">{stale(form.stale_answer_client_timeout_ms)}.</span>
        </label>
        <label>
          TTL of a stale answer (seconds)
          <input type="number" min="0" aria-label="TTL of a stale answer (seconds)" bind:value={form.stale_answer_ttl} readonly={setByFile('stale_answer_ttl')} />
        </label>
        <label class="check">
          <input type="checkbox" role="switch" aria-label="Refresh hot answers before they expire" bind:checked={form.prefetch} disabled={setByFile('prefetch')} />
          Refresh hot answers before they expire
        </label>
        <label>
          Refresh when this share of the TTL is left (%)
          <input type="number" min="0" max="100" aria-label="Refresh when this share of the TTL is left (%)" bind:value={form.prefetch_threshold_pct} readonly={setByFile('prefetch_threshold_pct')} />
        </label>
        <label>
          Hits before an answer is refreshed
          <input type="number" min="0" aria-label="Hits before an answer is refreshed" bind:value={form.prefetch_min_hits} readonly={setByFile('prefetch_min_hits')} />
        </label>
        <label class="check">
          <input type="checkbox" role="switch" aria-label="Keep the cache across restarts" bind:checked={form.persist} disabled={setByFile('persist')} />
          Keep the cache across restarts <HelpButton id="cache-persistence" />
        </label>
        <label>
          Names to warm up after a start (in a cluster)
          <input type="number" min="0" aria-label="Names to warm up after a start" bind:value={form.warm_names} readonly={setByFile('warm_names')} />
          <span class="muted small">0 turns the warm-up off.</span>
        </label>
        <ErrorNote error={formError} />
        {#if preview}
          <div class="preview" data-testid="cache-settings-preview">
            <p><b>What this will do:</b> {preview.impact || 'Changes the cache settings as shown, after a restart.'}</p>
            {#each preview.warnings as w (w)}<p class="small warn-text">{w}</p>{/each}
          </div>
          <div class="row">
            <button type="button" class="primary" disabled={busy} onclick={apply}>Apply</button>
            <button type="button" onclick={() => (preview = null)}>Change it</button>
          </div>
        {:else}
          <div class="row">
            <button type="submit" class="primary" disabled={busy}>Check</button>
            <button type="button" disabled={busy} onclick={() => (form = null)}>Cancel</button>
          </div>
        {/if}
      </form>
    {/if}
  {:else if !error}
    <p class="muted small">Loading the cache settings…</p>
  {/if}
</details>
