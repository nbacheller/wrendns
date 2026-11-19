<script lang="ts">
  // REQ: FLT-004 (T27.11, ADR-1006), FLT-901 (T24.29) — the list settings on the Lists page: how often URL
  // and file lists are refreshed, after how many days without a confirmation a list is flagged as stale,
  // how many entries the selected categories may add before the Categories view warns, and the size of the
  // Ad Block list. Operators change them; the change is checked first. The refresh and stale settings
  // apply after a restart (the list fetcher reads them at start); the entry budget and ad block size
  // apply within seconds. One form writes all four: a write replaces the whole section.
  import { api, type S } from '../api';
  import { can } from '../session.svelte';
  import ErrorNote from './ErrorNote.svelte';
  import HelpButton from './HelpButton.svelte';

  let entry = $state<S['ConfigEntry'] | null>(null);
  let error = $state<unknown>(null);
  let notice = $state('');
  let editing = $state(false);
  // The stored refresh interval in seconds, as read (a file's 900 or 5400 stays as it is unless the
  // operator changes the hours field).
  let storedSecs = $state(86_400);
  let refreshHours = $state(24);
  let staleDays = $state(30);
  let entryBudget = $state(1_000_000);
  let adsTier = $state('pro');
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

  // Shown as minutes below an hour, else hours (up to two decimals).
  function everyText(secs: number): string {
    if (secs < 3600) return `${Math.round(secs / 60)} min`;
    return `${Number((secs / 3600).toFixed(2))} h`;
  }

  function open() {
    preview = null;
    formError = null;
    notice = '';
    storedSecs = Number(defs.refresh_secs ?? 86_400);
    refreshHours = storedSecs / 3600;
    staleDays = Number(defs.stale_after_days ?? 30);
    entryBudget = Number(defs.entry_budget ?? 1_000_000);
    adsTier = String(defs.ads_tier ?? 'pro');
    editing = true;
  }

  // The refresh interval is in hours on the form (at least 15 minutes, as the server requires). It is
  // sent only when the operator changed it, so an unchanged stored value keeps its exact seconds.
  function body(): Record<string, unknown> {
    const all: Record<string, unknown> = {
      stale_after_days: Number(staleDays),
      entry_budget: Number(entryBudget),
      ads_tier: adsTier,
    };
    const secs = Math.round(Number(refreshHours) * 3600);
    if (secs !== storedSecs) all.refresh_secs = secs;
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
      notice = 'Saved. The entry budget and the ad block size apply within seconds; the refresh and stale settings after a restart.';
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
      <dd>every {everyText(Number(defs.refresh_secs ?? 0))}{#if fileSet.includes('refresh_secs')} <span class="muted">(set by file)</span>{/if}</dd>
      <dt>Stale after</dt>
      <dd>{Number(defs.stale_after_days ?? 0) ? `${defs.stale_after_days} days without a confirmation` : 'never'}{#if fileSet.includes('stale_after_days')} <span class="muted">(set by file)</span>{/if}</dd>
      <dt>Category entry budget<HelpButton id="category-budget" /></dt>
      <dd data-testid="filter-entry-budget">{Number(defs.entry_budget ?? 1_000_000).toLocaleString('en-US')} entries{#if fileSet.includes('entry_budget')} <span class="muted">(set by file)</span>{/if}</dd>
      <dt>Ad block size</dt>
      <dd data-testid="filter-ads-tier">{String(defs.ads_tier ?? 'pro').replace('_', '+')}{#if fileSet.includes('ads_tier')} <span class="muted">(set by file)</span>{/if}</dd>
    </dl>
    {#if writable && !editing}
      <div class="row"><button onclick={open} data-testid="filter-settings-edit">Change list settings</button></div>
    {/if}
  {/if}
  {#if editing}
    <form class="form" data-testid="filter-settings-form" onsubmit={check}>
      <label>
        Refresh URL and file lists every (hours, at least 0.25: 15 minutes)
        <input type="number" min="0.25" step="any" required aria-label="Refresh lists every (hours)" bind:value={refreshHours} readonly={fileSet.includes('refresh_secs')} />
      </label>
      <label>
        Flag a list as stale after (days; 0: never)
        <input type="number" min="0" required aria-label="Flag a list as stale after (days)" bind:value={staleDays} readonly={fileSet.includes('stale_after_days')} />
      </label>
      <label>
        Entry budget (the most distinct entries the selected categories may add before the Categories view warns; a node too small refuses a selection whatever this says)
        <input type="number" min="1" required aria-label="Entry budget" bind:value={entryBudget} readonly={fileSet.includes('entry_budget')} />
      </label>
      <label>
        Ad block size (which of HaGeZi's lists every profile's Ad Block checkbox uses)
        <select aria-label="Ad block size" bind:value={adsTier} disabled={fileSet.includes('ads_tier')}>
          {#each ['light', 'pro', 'pro_plus', 'ultimate'] as t (t)}<option value={t}>{t.replace('_', '+')}</option>{/each}
        </select>
      </label>
      <ErrorNote error={formError} />
      {#if preview}
        <div class="preview" data-testid="filter-settings-preview">
          <p><b>What this will do:</b> {preview.impact || 'Changes the list settings as shown.'}</p>
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
