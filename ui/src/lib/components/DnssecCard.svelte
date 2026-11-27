<script lang="ts">
  // REQ: DNS-011 (T27.11, ADR-1006) — DNSSEC on Settings → Query handling: how answers are validated
  // (off, validate, or validate and count) and the domains that are not validated (negative trust
  // anchors, one per line). Operators change it; the change is checked first and applies on every
  // node within seconds. REQ: DNS-906 (T40.5) — below it, the root trust anchors each node holds and
  // where each stands in RFC 5011's hold-down (everyone may read them).
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
  let aggressive = $state(true);
  let preview = $state<S['ConfigChange'] | null>(null);
  let formError = $state<unknown>(null);
  let busy = $state(false);
  let nodes = $state<S['TrustAnchorStatus'][]>([]);
  let anchorError = $state<unknown>(null);

  const when = (s?: number | null) => (s ? new Date(s * 1000).toLocaleDateString() : '');
  const STATES: Record<string, string> = {
    valid: 'trusted',
    add_pend: 'new, in hold-down',
    missing: 'trusted, not listed by the root',
    revoked: 'revoked',
  };
  const NOT_FOLLOWED: Record<string, string> = {
    file: 'The keys come from trust_anchors_file; they are not followed.',
    off: 'DNSSEC validation is off on this node.',
    unsupported: 'This node runs an older build that cannot report its anchors.',
  };

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
  async function loadAnchors() {
    try {
      nodes = (await api.trustAnchors()).items;
      anchorError = null;
    } catch (e) {
      anchorError = e;
    }
  }
  $effect(() => {
    void load();
    void loadAnchors();
  });

  function open() {
    preview = null;
    formError = null;
    notice = '';
    mode = typeof defs.mode === 'string' ? defs.mode : 'off';
    anchors = Array.isArray(defs.negative_trust_anchors) ? (defs.negative_trust_anchors as string[]).join('\n') : '';
    aggressive = defs.aggressive_nsec !== false;
    editing = true;
  }

  function body(): Record<string, unknown> {
    const all: Record<string, unknown> = { mode, negative_trust_anchors: lines(anchors), aggressive_nsec: aggressive };
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
      <dt>Answer from proven ranges<HelpButton id="aggressive-nsec" /></dt>
      <dd>{defs.aggressive_nsec === false ? 'off' : 'on'}{#if fileSet.includes('aggressive_nsec')} <span class="muted">(set by file)</span>{/if}</dd>
    </dl>
    {#if writable && !editing}
      <div class="row">
        <button onclick={open} data-testid="dnssec-edit">Change DNSSEC settings</button>
        {#if entry.source === 'override'}<button class="link" disabled={busy} onclick={revert}>Revert to the file</button>{/if}
      </div>
    {/if}
  {/if}
  <h3 class="small">Root trust anchors<HelpButton id="trust-anchors" /></h3>
  <ErrorNote error={anchorError} />
  <div data-testid="anchors-list">
    {#each nodes as n (n.node ?? '')}
      <div class="small" data-testid="anchors-node">
        {#if n.node}<b>{n.node}</b>{/if}
        {#if NOT_FOLLOWED[n.mode]}
          <span class="muted">{NOT_FOLLOWED[n.mode]}</span>
        {:else}
          <ul>
            {#each n.keys as k}
              <li data-testid="anchor-key" data-state={k.state}>
                <span class="mono">{k.keyTag}</span> {STATES[k.state] ?? k.state}
                {#if k.state === 'add_pend' && k.trustedAtS}<span class="muted">(trusted from {when(k.trustedAtS)})</span>
                {:else if k.sinceS}<span class="muted">(since {when(k.sinceS)})</span>{/if}
              </li>
            {/each}
          </ul>
          <span class="muted">
            {#if n.lastReadingS}Root last read {when(n.lastReadingS)}.{:else}Root not read yet.{/if}
            {#if n.lastError}{n.lastError}{/if}
          </span>
        {/if}
      </div>
    {/each}
  </div>
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
      <label class="check">
        <input type="checkbox" aria-label="Answer from proven ranges" bind:checked={aggressive} disabled={fileSet.includes('aggressive_nsec')} />
        Answer names a signed zone proved absent without asking upstream (RFC 8198)
        <span class="muted small">Covers NSEC and NSEC3. Needs validation on; on by default.</span>
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
