<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<script lang="ts">
  // REQ: DNS-014, API-901 (T27.14h; ADR-014, ADR-029, ADR-040, ADR-1090, ADR-1098 point 4) — the one
  // cluster-wide list of allowed networks (`[access] allowed_networks`) on Settings -> System. Admins
  // edit it: each entry is checked by the node, a public range warns before the change is saved, and a
  // list that leaves out the admin's own address is refused. Operators and viewers read it. A
  // configuration file that sets the list wins ("Set by file"). With `summary` it is only a read-only
  // line that links to the card (the Listener access card).
  import { api, ApiError, type S } from '../api';
  import { can } from '../session.svelte';
  import ErrorNote from './ErrorNote.svelte';
  import HelpButton from './HelpButton.svelte';

  let { summary = false }: { summary?: boolean } = $props();

  let entry = $state<S['ConfigEntry'] | null>(null);
  let error = $state<unknown>(null);
  let notice = $state('');
  let editing = $state(false);
  let draft = $state<string[]>([]);
  let adding = $state('');
  let preview = $state<S['ConfigChange'] | null>(null);
  let formError = $state<unknown>(null);
  let busy = $state(false);

  const admin = $derived(can('admin'));
  const current = $derived(((entry?.definition ?? {}) as { allowed_networks?: string[] }).allowed_networks ?? []);
  const byFile = $derived((entry?.setByFile ?? []).includes('allowed_networks'));
  const origin = $derived(byFile ? 'Set by file' : entry?.source === 'override' ? 'From the UI' : 'Built-in defaults');

  async function load() {
    try {
      entry = (await api.configEntries('access')).items[0] ?? null;
      error = null;
    } catch (e) {
      error = e;
    }
  }
  $effect(() => {
    void load();
  });

  /**
   * The shared "would cut you off" and "too old to send it to the primary" sentences are about
   * listeners and credentials; these refusals keep the server's own words here (the list, the member).
   */
  const readable = (err: unknown): unknown =>
    err instanceof ApiError && (err.code === 'would_disconnect_you' || err.code === 'upgrade_required')
      ? new ApiError({ status: err.status, code: 'invalid_config', detail: err.detail, hint: err.hint })
      : err;

  function open() {
    preview = null;
    formError = null;
    notice = '';
    draft = [...current];
    adding = '';
    editing = true;
  }
  function add() {
    const v = adding.trim();
    if (v && !draft.includes(v)) draft = [...draft, v];
    adding = '';
    preview = null;
  }
  function remove(at: number) {
    draft = draft.filter((_, i) => i !== at);
    preview = null;
  }
  function jump() {
    document.getElementById('allowed-networks')?.scrollIntoView({ block: 'start' });
  }

  async function check(e: SubmitEvent) {
    e.preventDefault();
    add();
    busy = true;
    formError = null;
    try {
      preview = await api.putEntry('access-settings', 'default', { allowed_networks: draft }, true);
    } catch (err) {
      formError = readable(err);
      preview = null;
    } finally {
      busy = false;
    }
  }
  async function apply() {
    busy = true;
    try {
      await api.putEntry('access-settings', 'default', { allowed_networks: draft }, false);
      editing = false;
      preview = null;
      notice = 'Saved. Every node applies it within a few seconds.';
      await load();
    } catch (err) {
      formError = readable(err);
    } finally {
      busy = false;
    }
  }
  async function revert() {
    busy = true;
    try {
      await api.deleteEntry('access-settings', 'default');
      editing = false;
      notice = 'Back to the configuration file, or the built-in defaults.';
      await load();
    } catch (err) {
      error = readable(err);
    } finally {
      busy = false;
    }
  }
</script>

{#if summary}
  {#if entry}
    <p class="small" data-testid="allowed-networks-summary">
      <strong>Allowed networks</strong> (one list for the whole cluster, {origin.toLowerCase()}):
      <span class="mono">{current.join(', ') || 'none'}</span>
      <button class="link" onclick={jump} data-testid="allowed-networks-link">{admin ? 'Change it' : 'See it'}</button>
    </p>
  {/if}
{:else}
  <section class="card" id="allowed-networks" data-testid="allowed-networks-card">
    <h2>Allowed networks<HelpButton id="allowed-networks" /></h2>
    <p class="muted small">
      Who may use this resolver, for the whole cluster: a client outside the list gets REFUSED for DNS and cannot reach the web UI or the API. The same list applies on every node.
    </p>
    <ErrorNote {error} />
    {#if notice}<p class="notice ok small" role="status">{notice}</p>{/if}
    {#if entry}
      {#if byFile}
        <div class="notice small" role="status" data-testid="allowed-networks-file">
          <strong>Set by file.</strong> A configuration file sets <code>[access] allowed_networks</code>, and the file wins: change it there. Removing the line hands the control back to this page.
        </div>
      {/if}
      <p class="small muted" data-testid="allowed-networks-origin">{origin}</p>
      <ul class="plain mono" data-testid="allowed-networks-list">
        {#each current as n, i (i)}<li data-testid="allowed-networks-row">{n}</li>{/each}
        {#if !current.length}<li class="muted">none: every client is refused</li>{/if}
      </ul>
      {#if admin && !editing && !byFile}
        <div class="row">
          <button onclick={open} data-testid="allowed-networks-edit">Change the list</button>
          {#if entry.source === 'override'}<button class="link" disabled={busy} onclick={revert} data-testid="allowed-networks-revert">Revert to the file</button>{/if}
        </div>
      {/if}
    {/if}
    {#if editing}
      <form class="form" data-testid="allowed-networks-form" onsubmit={check}>
        <ul class="plain mono">
          {#each draft as n, i (i)}
            <li data-testid="allowed-networks-draft-row">
              {n} <button type="button" class="link" aria-label="Remove {n}" onclick={() => remove(i)}>remove</button>
            </li>
          {/each}
        </ul>
        <label>
          Add a network (<code>10.20.0.0/24</code>, <code>fd00::/8</code> or one address)
          <input aria-label="Network to add" data-testid="allowed-networks-input" bind:value={adding} autocomplete="off" />
        </label>
        <div class="row"><button type="button" onclick={add} data-testid="allowed-networks-add">Add</button></div>
        <ErrorNote error={formError} />
        {#if preview}
          <div class="preview" data-testid="allowed-networks-preview">
            <p><b>What this will do:</b> {preview.impact || 'Changes the list as shown.'}</p>
            {#each preview.warnings as w, i (i)}<p class="small warn-text" data-testid="allowed-networks-warning">{w}</p>{/each}
          </div>
          <div class="row">
            <button type="button" class="primary" disabled={busy} onclick={apply} data-testid="allowed-networks-apply">Apply</button>
            <button type="button" onclick={() => (preview = null)}>Change it</button>
          </div>
        {:else}
          <div class="row">
            <button type="submit" class="primary" disabled={busy} data-testid="allowed-networks-check">Check</button>
            <button type="button" disabled={busy} onclick={() => (editing = false)}>Cancel</button>
          </div>
        {/if}
      </form>
    {/if}
  </section>
{/if}

<style>
  ul.plain {
    list-style: none;
    padding: 0;
    margin: var(--space-2) 0;
  }
</style>
