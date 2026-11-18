<script lang="ts">
  // REQ: FLT-004 (T27.11, ADR-1006) — the list settings on the Lists page: how often URL and file lists
  // are refreshed, and after how many days without a confirmation a list is flagged as stale. Operators
  // change them; the change is checked first and applies after a restart (the list fetcher reads them
  // at start).
  import { api, type S } from '../api';
  import { can } from '../session.svelte';
  import ErrorNote from './ErrorNote.svelte';
  import HelpButton from './HelpButton.svelte';

  let entry = $state<S['ConfigEntry'] | null>(null);
  let error = $state<unknown>(null);
  let notice = $state('');
  let editing = $state(false);
  let refreshHours = $state(24);
  let staleDays = $state(30);
  let preview = $state<S['ConfigChange'] | null>(null);
  let formError = $state<unknown>(null);
  let busy = $state(false);

  const writable = $derived(can('operator'));
  const defs = $derived((entry?.definition ?? {}) as Record<string, unknown>);
  const fileSet = $derived(entry?.setByFile ?? []);

  async function load() {
    try {
      entry = (await api.configEntries('filter')).items[0] ?? null;
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
    refreshHours = Math.round(Number(defs.refresh_secs ?? 86_400) / 3600);
    staleDays = Number(defs.stale_after_days ?? 30);
    editing = true;
  }

  // The refresh interval is in hours on the form (at least 15 minutes, as the server requires).
  function body(): Record<string, unknown> {
    const all: Record<string, unknown> = {
      refresh_secs: Math.round(Number(refreshHours) * 3600),
      stale_after_days: Number(staleDays),
    };
    for (const k of fileSet) delete all[k];
    return all;
  }

  async function check(e: SubmitEvent) {
    e.preventDefault();
    busy = true;
    formError = null;
    try {
      preview = await api.putEntry('filter-settings', 'default', body(), true);
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
      await api.putEntry('filter-settings', 'default', body(), false);
      editing = false;
      preview = null;
      notice = 'Saved. It takes effect after a restart.';
      await load();
    } catch (err) {
      formError = err;
    } finally {
      busy = false;
    }
  }
</script>

<section class="card" data-testid="filter-settings-card">
  <h2>List settings<HelpButton id="list-limits" /></h2>
  <ErrorNote {error} />
  {#if notice}<p class="notice ok small" role="status">{notice}</p>{/if}
  {#if entry}
    <dl class="facts small" data-testid="filter-settings-values">
      <dt>Refresh URL and file lists</dt>
      <dd>every {Math.round(Number(defs.refresh_secs ?? 0) / 3600)} h{#if fileSet.includes('refresh_secs')} <span class="muted">(set by file)</span>{/if}</dd>
      <dt>Stale after</dt>
      <dd>{Number(defs.stale_after_days ?? 0) ? `${defs.stale_after_days} days without a confirmation` : 'never'}{#if fileSet.includes('stale_after_days')} <span class="muted">(set by file)</span>{/if}</dd>
    </dl>
    {#if writable && !editing}
      <div class="row"><button onclick={open} data-testid="filter-settings-edit">Change list settings</button></div>
    {/if}
  {/if}
  {#if editing}
    <form class="form" data-testid="filter-settings-form" onsubmit={check}>
      <label>
        Refresh URL and file lists every (hours, at least 1)
        <input type="number" min="1" aria-label="Refresh lists every (hours)" bind:value={refreshHours} readonly={fileSet.includes('refresh_secs')} />
      </label>
      <label>
        Flag a list as stale after (days; 0: never)
        <input type="number" min="0" aria-label="Flag a list as stale after (days)" bind:value={staleDays} readonly={fileSet.includes('stale_after_days')} />
      </label>
      <ErrorNote error={formError} />
      {#if preview}
        <div class="preview" data-testid="filter-settings-preview">
          <p><b>What this will do:</b> {preview.impact || 'Changes the list settings as shown, after a restart.'}</p>
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
