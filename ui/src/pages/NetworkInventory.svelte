<script lang="ts">
  // REQ: DSC-001 (T25.2, ADR-907, ADR-928) — Settings → Network inventory: whether the inventory runs,
  // the node that runs it, the private subnets it may read, and the worker memory limit. Admins
  // change it (Check is a dry run, Apply saves); operators and viewers read it. The status card shows
  // whether this node runs the inventory and each discovery worker (REQ: DSC-002, DSC-014, ADR-929).
  import { api, type S } from '../lib/api';
  import { poll } from '../lib/poll';
  import { can } from '../lib/session.svelte';
  import ErrorNote from '../lib/components/ErrorNote.svelte';
  import HelpButton from '../lib/components/HelpButton.svelte';

  type Entry = S['ConfigEntry'];

  let entry = $state<Entry | null>(null);
  let status = $state<S['DiscoveryStatus'] | null>(null);
  let error = $state<unknown>(null);
  let notice = $state('');

  // The form: what the admin edits.
  let enabled = $state(false);
  let node = $state('');
  let memory = $state(64);
  let subnets = $state('');
  let preview = $state<S['ConfigChange'] | null>(null);
  let formError = $state<unknown>(null);
  let busy = $state(false);

  const writable = $derived(can('admin'));
  const fileSet = $derived(entry?.setByFile ?? []);
  const setByFile = (k: string) => fileSet.includes(k);

  function fromEntry(e: Entry | null) {
    const d = (e?.definition ?? {}) as Record<string, unknown>;
    enabled = d.enabled === true;
    node = typeof d.node === 'string' ? d.node : '';
    memory = Number(d.worker_memory_mib ?? 64);
    const list = Array.isArray(d.subnet) ? (d.subnet as { cidr: string }[]) : [];
    subnets = list.map((s) => s.cidr).join('\n');
  }

  async function load() {
    try {
      const [cfg, st] = await Promise.all([api.configEntries('discovery'), api.discoveryStatus()]);
      entry = cfg.items[0] ?? null;
      status = st;
      if (!busy) fromEntry(entry);
      error = null;
    } catch (e) {
      error = e;
    }
  }
  $effect(() => {
    void load();
    return poll(load, 15_000);
  });

  // The body: the fields the files don't set (the entry keeps those as the files set them).
  function body(): Record<string, unknown> {
    const all: Record<string, unknown> = {
      enabled,
      node: node.trim() || null,
      worker_memory_mib: Number(memory),
      subnet: subnets
        .split(/\r?\n|,/)
        .map((s) => s.trim())
        .filter(Boolean)
        .map((cidr) => ({ cidr })),
    };
    for (const k of fileSet) delete all[k];
    return all;
  }

  async function check() {
    busy = true;
    formError = null;
    notice = '';
    try {
      preview = await api.putEntry('discovery-settings', 'default', body(), true);
    } catch (e) {
      preview = null;
      formError = e;
    } finally {
      busy = false;
    }
  }

  async function apply() {
    busy = true;
    formError = null;
    try {
      await api.putEntry('discovery-settings', 'default', body(), false);
      preview = null;
      notice = 'Saved. The inventory starts or stops on the designated node within a few seconds.';
      await load();
    } catch (e) {
      formError = e;
    } finally {
      busy = false;
    }
  }

  const stateText = $derived(
    !status
      ? 'Loading'
      : !status.enabled
        ? 'Off'
        : status.designated
          ? 'Runs on this node'
          : `Runs on ${status.node ?? 'another node'}`,
  );
</script>

<div class="page">
  <div class="page-head">
    <h1>Network inventory<HelpButton id="network-inventory" /></h1>
    <span class="muted small">Settings</span>
  </div>
  <ErrorNote {error} />

  <section class="card" data-testid="inventory-status">
    <h2>Status</h2>
    <p>
      <strong data-testid="inventory-state">{stateText}</strong>
      {#if status?.enabled && !status.designated}
        <span class="muted small">This node doesn't run it; the designated node does.</span>
      {/if}
    </p>
    {#if status && status.workers.length > 0}
      <h3>Workers<HelpButton id="discovery-workers" /></h3>
      <table>
        <thead>
          <tr><th>Worker</th><th>State</th><th>Restarts</th><th>Notes</th></tr>
        </thead>
        <tbody>
          {#each status.workers as w (w.worker)}
            <tr data-testid="worker-{w.worker}">
              <td>{w.worker}</td>
              <td>
                {#if w.versionMismatch}refused: build differs{:else if w.up}running{:else}stopped{/if}
                {#if w.failing}<span data-testid="worker-failing">failing</span>{/if}
              </td>
              <td>{w.restarts}</td>
              <td class="small">
                {#if w.lastError}{w.lastError}{/if}
                {#if w.dataLimitMib}<span class="muted">memory limit {w.dataLimitMib} MiB</span>{/if}
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    {:else}
      <p class="muted small">No worker runs on this node. DNS is unaffected either way.</p>
    {/if}
  </section>

  <section class="card" data-testid="inventory-settings">
    <h2>Settings</h2>
    {#if !writable}
      <p class="muted small">Only an administrator can change the network inventory. You can read it here.</p>
    {/if}
    <label class="row">
      <input
        type="checkbox"
        role="switch"
        bind:checked={enabled}
        disabled={!writable || setByFile('enabled')}
        aria-label="Turn the network inventory on"
      />
      Turn the network inventory on
      {#if setByFile('enabled')}<span class="muted small" data-testid="set-by-file">(set by file)</span>{/if}
    </label>
    <label>
      Designated node (blank: the primary, or this node alone)
      <input
        type="text"
        bind:value={node}
        disabled={!writable || setByFile('node')}
        aria-label="Designated node"
        placeholder="pi-a"
      />
      {#if setByFile('node')}<span class="muted small" data-testid="set-by-file">(set by file)</span>{/if}
    </label>
    <label>
      Subnets it may read (one per line, private IPv4 only)
      <textarea
        rows="3"
        bind:value={subnets}
        disabled={!writable || setByFile('subnet')}
        aria-label="Subnets it may read"
        placeholder="192.168.1.0/24"
      ></textarea>
      {#if setByFile('subnet')}<span class="muted small" data-testid="set-by-file">(set by file)</span>{/if}
    </label>
    <label>
      Memory limit of each worker (MiB, 32 to 128)
      <input
        type="number"
        min="32"
        max="128"
        bind:value={memory}
        disabled={!writable || setByFile('worker_memory_mib')}
        aria-label="Worker memory limit"
      />
      {#if setByFile('worker_memory_mib')}<span class="muted small" data-testid="set-by-file">(set by file)</span>{/if}
    </label>

    {#if writable}
      <div class="row actions">
        <button onclick={check} disabled={busy}>Check</button>
        {#if preview}
          <button class="primary" onclick={apply} disabled={busy}>Apply</button>
        {/if}
      </div>
    {/if}
    {#if preview}
      <div data-testid="inventory-preview" class="card">
        <p>{preview.impact}</p>
        {#each preview.warnings as w (w)}<p class="small">{w}</p>{/each}
      </div>
    {/if}
    <ErrorNote error={formError} />
    {#if notice}<p class="small" role="status">{notice}</p>{/if}
  </section>
</div>
