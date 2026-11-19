<script lang="ts">
  // REQ: CLU-014 (T27.11, ADR-1006) — the scheduled failover drills on the Cluster page: whether they
  // run each month, and on which nodes. Admins change it (a drill starts on the cluster's nodes); the
  // change is checked first, and the scheduler reads it again at its next check (no restart).
  import { api, type S } from '../api';
  import { can } from '../session.svelte';
  import ErrorNote from './ErrorNote.svelte';
  import HelpButton from './HelpButton.svelte';

  let entry = $state<S['ConfigEntry'] | null>(null);
  let error = $state<unknown>(null);
  let notice = $state('');
  let editing = $state(false);
  let schedule = $state<'off' | 'monthly'>('off');
  let nodes = $state('');
  let preview = $state<S['ConfigChange'] | null>(null);
  let formError = $state<unknown>(null);
  let busy = $state(false);

  const admin = $derived(can('admin'));
  const defs = $derived((entry?.definition ?? {}) as Record<string, unknown>);
  const fileSet = $derived(entry?.setByFile ?? []);
  const nodeList = (text: string) =>
    text
      .split(/[\s,]+/)
      .map((n) => n.trim())
      .filter(Boolean);

  async function load() {
    try {
      entry = (await api.configEntries('drill')).items[0] ?? null;
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
    schedule = defs.schedule === 'monthly' ? 'monthly' : 'off';
    nodes = Array.isArray(defs.nodes) ? (defs.nodes as string[]).join(', ') : '';
    editing = true;
  }

  function body(): Record<string, unknown> {
    const all: Record<string, unknown> = { schedule, nodes: nodeList(nodes) };
    for (const k of fileSet) delete all[k];
    return all;
  }

  async function check(e: SubmitEvent) {
    e.preventDefault();
    busy = true;
    formError = null;
    try {
      preview = await api.putEntry('drill-settings', 'default', body(), true);
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
      await api.putEntry('drill-settings', 'default', body(), false);
      editing = false;
      preview = null;
      notice = 'Saved. The scheduler reads it at its next check.';
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
      await api.deleteEntry('drill-settings', 'default');
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

<section class="card" data-testid="drill-schedule-card">
  <h2>Scheduled drills<HelpButton id="drill-schedule" /></h2>
  <ErrorNote {error} />
  {#if notice}<p class="notice ok small" role="status">{notice}</p>{/if}
  {#if entry}
    <dl class="facts small" data-testid="drill-schedule-values">
      <dt>Schedule</dt>
      <dd>{defs.schedule === 'monthly' ? 'once a month' : 'off'}{#if fileSet.includes('schedule')} <span class="muted">(set by file)</span>{/if}</dd>
      <dt>Nodes that drill</dt>
      <dd class="mono">{Array.isArray(defs.nodes) && defs.nodes.length ? (defs.nodes as string[]).join(', ') : 'none'}</dd>
    </dl>
    {#if admin && !editing}
      <div class="row">
        <button onclick={open} data-testid="drill-schedule-edit">Change the schedule</button>
        {#if entry.source === 'override'}<button class="link" disabled={busy} onclick={revert}>Revert to the file</button>{/if}
      </div>
    {/if}
  {/if}
  {#if editing}
    <form class="form" data-testid="drill-schedule-form" onsubmit={check}>
      <label>
        Scheduled drills
        <select aria-label="Scheduled drills" bind:value={schedule} disabled={fileSet.includes('schedule')}>
          <option value="off">off</option>
          <option value="monthly">once a month</option>
        </select>
      </label>
      <label>
        Nodes that drill themselves (sites, pod names, or node IDs; separated by commas)
        <input aria-label="Nodes that drill" bind:value={nodes} readonly={fileSet.includes('nodes')} />
      </label>
      <ErrorNote error={formError} />
      {#if preview}
        <div class="preview" data-testid="drill-schedule-preview">
          <p><b>What this will do:</b> {preview.impact || 'Changes the schedule as shown.'}</p>
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
