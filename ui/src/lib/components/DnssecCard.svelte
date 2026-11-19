<script lang="ts">
  // REQ: DNS-011 (T27.11, ADR-1006) — DNSSEC on Settings → Query handling: how answers are validated
  // (off, validate, or validate and count) and the domains that are not validated (negative trust
  // anchors, one per line). Operators change it; the change is checked first and applies on every
  // node within seconds.
  import { api, type S } from '../api';
  import { can } from '../session.svelte';
  import ErrorNote from './ErrorNote.svelte';
  import HelpButton from './HelpButton.svelte';

  let entry = $state<S['ConfigEntry'] | null>(null);
  let error = $state<unknown>(null);
  let notice = $state('');
  let editing = $state(false);
  let mode = $state('off');
  let anchors = $state('');
  let preview = $state<S['ConfigChange'] | null>(null);
  let formError = $state<unknown>(null);
  let busy = $state(false);

  const writable = $derived(can('operator'));
  const defs = $derived((entry?.definition ?? {}) as Record<string, unknown>);
  const fileSet = $derived(entry?.setByFile ?? []);
  const lines = (text: string) =>
    text
      .split('\n')
      .map((l) => l.trim())
      .filter(Boolean);

  async function load() {
    try {
      entry = (await api.configEntries('dnssec')).items[0] ?? null;
      error = null;
    } catch (e) {
      error = e;
    }
  }
  $effect(() => {
    void load();
  });

  function open() {
    preview = null;
    formError = null;
    notice = '';
    mode = typeof defs.mode === 'string' ? defs.mode : 'off';
    anchors = Array.isArray(defs.negative_trust_anchors) ? (defs.negative_trust_anchors as string[]).join('\n') : '';
    editing = true;
  }

  function body(): Record<string, unknown> {
    const all: Record<string, unknown> = { mode, negative_trust_anchors: lines(anchors) };
    for (const k of fileSet) delete all[k];
    return all;
  }

  async function check(e: SubmitEvent) {
    e.preventDefault();
    busy = true;
    formError = null;
    try {
      preview = await api.putEntry('dnssec-settings', 'default', body(), true);
    } catch (err) {
      formError = err;
      preview = null;
    } finally {
      busy = false;
    }
  }

  async function apply() {
    busy = true;
    try {
      await api.putEntry('dnssec-settings', 'default', body(), false);
      editing = false;
      preview = null;
      notice = 'Saved. It applies on every node within a few seconds.';
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
      await api.deleteEntry('dnssec-settings', 'default');
      editing = false;
      notice = 'Back to the configuration file.';
      await load();
    } catch (err) {
      error = err;
    } finally {
      busy = false;
    }
  }
</script>

<section class="card" data-testid="dnssec-card">
  <h2>DNSSEC<HelpButton id="dnssec-mode" /></h2>
  <ErrorNote {error} />
  {#if notice}<p class="notice ok small" role="status">{notice}</p>{/if}
  {#if entry}
    <dl class="facts small" data-testid="dnssec-values">
      <dt>Validation</dt>
      <dd>{defs.mode ?? 'off'}{#if fileSet.includes('mode')} <span class="muted">(set by file)</span>{/if}</dd>
      <dt>Not validated</dt>
      <dd class="mono">{Array.isArray(defs.negative_trust_anchors) && defs.negative_trust_anchors.length ? (defs.negative_trust_anchors as string[]).join(', ') : 'none'}</dd>
    </dl>
    {#if writable && !editing}
      <div class="row">
        <button onclick={open} data-testid="dnssec-edit">Change DNSSEC settings</button>
        {#if entry.source === 'override'}<button class="link" disabled={busy} onclick={revert}>Revert to the file</button>{/if}
      </div>
    {/if}
  {/if}
  {#if editing}
    <form class="form" data-testid="dnssec-form" onsubmit={check}>
      <label>
        Validation
        <select aria-label="Validation" bind:value={mode} disabled={fileSet.includes('mode')}>
          <option value="off">off (answers pass through as sent)</option>
          <option value="validate">validate (bogus answers become SERVFAIL)</option>
          <option value="permissive">validate and count (serve bogus answers anyway)</option>
        </select>
      </label>
      <label>
        Domains not validated (negative trust anchors), one per line
        <textarea aria-label="Negative trust anchors" rows="3" bind:value={anchors} readonly={fileSet.includes('negative_trust_anchors')}></textarea>
        <span class="muted small">For a domain whose server isn't signed, such as an internal one.</span>
      </label>
      <ErrorNote error={formError} />
      {#if preview}
        <div class="preview" data-testid="dnssec-preview">
          <p><b>What this will do:</b> {preview.impact || 'Changes the DNSSEC settings as shown.'}</p>
          {#each preview.warnings as w (w)}<p class="small warn-text">{w}</p>{/each}
        </div>
        <div class="row">
          <button type="button" class="primary" disabled={busy} onclick={apply}>Apply</button>
          <button type="button" onclick={() => (preview = null)}>Change it</button>
        </div>
      {:else}
        <div class="row">
          <button type="submit" class="primary" disabled={busy}>Check</button>
          <button type="button" disabled={busy} onclick={() => (editing = false)}>Cancel</button>
        </div>
      {/if}
    </form>
  {/if}
</section>
