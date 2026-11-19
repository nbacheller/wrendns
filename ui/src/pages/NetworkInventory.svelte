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
  import SnmpAgents from '../lib/components/SnmpAgents.svelte';
  import SnmpCredentials from '../lib/components/SnmpCredentials.svelte';
  import { type AgentDraft, type CredDraft, agentBody, agentsOf, credBody, credsOf } from '../lib/snmp';

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
  // REQ: DSC-004 (T25.6) — the SNMP agents and the credentials they name, edited with the rest.
  let agents = $state<AgentDraft[]>([]);
  let credentials = $state<CredDraft[]>([]);
  // REQ: DSC-009 (T25.10, ADR-912) — the extra reads. UniFi's are off until turned on; Home
  // Assistant's is on. Each is read-only and adds to the inventory only.
  let unifiClientFields = $state(false);
  let unifiAllUsers = $state(false);
  let unifiDevices = $state(false);
  let withinHours = $state(720);
  let haAll = $state(true);
  let preview = $state<S['ConfigChange'] | null>(null);
  // The form as Check previewed it. Apply is offered only while the form still holds exactly that.
  let previewedWith = $state<string | null>(null);
  let formError = $state<unknown>(null);
  let busy = $state(false);
  // The form as the stored settings last filled it. A poll refills the form only while it still
  // holds that, so an admin's unsaved edits are kept (REQ: DSC-001).
  let filledWith = $state<string | null>(null);

  const writable = $derived(can('admin'));
  const fileSet = $derived(entry?.setByFile ?? []);
  const setByFile = (k: string) => fileSet.includes(k);
  const snapshot = () =>
    JSON.stringify([enabled, node, memory, subnets, agents, credentials, unifiClientFields, unifiAllUsers, unifiDevices, withinHours, haAll]);
  // The agents as stored, so the Test button knows which agent is already saved.
  const storedAgents = $derived(agentsOf((entry?.definition ?? {}) as Record<string, unknown>));
  const previewCurrent = $derived(preview !== null && previewedWith === snapshot());
  // The stored settings are in use and an override of the files' settings (DSC-001).
  const overridden = $derived(entry?.source === 'override');

  function fromEntry(e: Entry | null) {
    const d = (e?.definition ?? {}) as Record<string, unknown>;
    enabled = d.enabled === true;
    node = typeof d.node === 'string' ? d.node : '';
    memory = Number(d.worker_memory_mib ?? 64);
    const list = Array.isArray(d.subnet) ? (d.subnet as { cidr: string }[]) : [];
    subnets = list.map((s) => s.cidr).join('\n');
    agents = agentsOf(d);
    credentials = credsOf(d);
    const reads = (d.unifi_reads ?? {}) as Record<string, unknown>;
    unifiClientFields = reads.client_fields === true;
    unifiAllUsers = reads.all_users === true;
    unifiDevices = reads.devices === true;
    withinHours = Number(d.unifi_all_users_within_hours ?? 720);
    haAll = d.home_assistant_all_devices !== false;
  }

  // Reads the stored settings. The form is refilled when `force` is set (after a save or a revert),
  // or when the poll finds the form unchanged since the stored settings last filled it.
  async function load(force = false) {
    try {
      const [cfg, st] = await Promise.all([api.configEntries('discovery'), api.discoveryStatus()]);
      entry = cfg.items[0] ?? null;
      status = st;
      if (force || (!busy && (filledWith === null || filledWith === snapshot()))) {
        fromEntry(entry);
        filledWith = snapshot();
      }
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
      snmp_agent: agents.map(agentBody),
      snmp_credential: credentials.map(credBody),
      unifi_reads: { client_fields: unifiClientFields, all_users: unifiAllUsers, devices: unifiDevices },
      unifi_all_users_within_hours: Number(withinHours),
      home_assistant_all_devices: haAll,
    };
    for (const k of fileSet) delete all[k];
    return all;
  }

  async function check() {
    busy = true;
    formError = null;
    notice = '';
    const asChecked = snapshot();
    try {
      preview = await api.putEntry('discovery-settings', 'default', body(), true);
      previewedWith = asChecked;
    } catch (e) {
      preview = null;
      previewedWith = null;
      formError = e;
    } finally {
      busy = false;
    }
  }

  async function apply() {
    if (!previewCurrent) return;
    busy = true;
    formError = null;
    try {
      await api.putEntry('discovery-settings', 'default', body(), false);
      preview = null;
      previewedWith = null;
      notice = 'Saved. The inventory starts or stops on the designated node within a few seconds.';
      await load(true);
    } catch (e) {
      formError = e;
    } finally {
      busy = false;
    }
  }

  // Drops the stored settings: the files' settings apply again (REQ: DSC-001).
  async function useFile() {
    busy = true;
    formError = null;
    notice = '';
    try {
      await api.deleteEntry('discovery-settings', 'default');
      preview = null;
      previewedWith = null;
      notice = "Back to the configuration file's settings.";
      await load(true);
    } catch (e) {
      formError = e;
    } finally {
      busy = false;
    }
  }

  const READ_LABELS: Record<string, string> = {
    client_fields: 'UniFi client fields',
    all_users: 'UniFi client history',
    devices: 'UniFi devices and ports',
    home_assistant_all_devices: 'Home Assistant devices without entities',
  };
  const readLabel = (r: string) => READ_LABELS[r] ?? r;

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
    {#if status && (status.reads ?? []).length > 0}
      <h3>Router reads<HelpButton id="inventory-unifi-reads" /></h3>
      <table data-testid="inventory-reads">
        <thead>
          <tr><th>Router</th><th>Read</th><th>State</th><th>Rows</th><th>Notes</th></tr>
        </thead>
        <tbody>
          {#each status.reads ?? [] as r (r.router + '/' + r.read)}
            <tr data-testid="read-{r.router}-{r.read}">
              <td>{r.router}</td>
              <td>{readLabel(r.read)}</td>
              <td data-testid="read-state">{r.state}</td>
              <td>{r.rows}{#if r.truncated} <span class="muted small">(cut at 8,192)</span>{/if}</td>
              <td class="small">{#if r.error}{r.error}{/if}</td>
            </tr>
          {/each}
        </tbody>
      </table>
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

    <SnmpCredentials bind:credentials {agents} {writable} fileSet={setByFile('snmp_credential')} />
    <SnmpAgents bind:agents {credentials} {writable} fileSet={setByFile('snmp_agent')} status={status?.agents ?? []} saved={storedAgents} />
    <h3>More from the routers<HelpButton id="inventory-unifi-reads" /></h3>
    <p class="muted small">
      Read-only. These add to the inventory only: they never name a device in DNS, and a console that
      refuses one still answers the others. They run on the designated node.
    </p>
    <label class="row">
      <input
        type="checkbox"
        role="switch"
        bind:checked={unifiClientFields}
        disabled={!writable || setByFile('unifi_reads')}
        aria-label="UniFi client fields"
      />
      UniFi: more fields of each client (port or access point, VLAN, network, first seen)
    </label>
    <label class="row">
      <input
        type="checkbox"
        role="switch"
        bind:checked={unifiAllUsers}
        disabled={!writable || setByFile('unifi_reads')}
        aria-label="UniFi client history"
      />
      UniFi: clients seen before, as history (<code>stat/alluser</code>)
    </label>
    <label class="row">
      <input
        type="checkbox"
        role="switch"
        bind:checked={unifiDevices}
        disabled={!writable || setByFile('unifi_reads')}
        aria-label="UniFi devices and ports"
      />
      UniFi: its own devices, the switch ports' MAC tables and LLDP (<code>stat/device</code>)
    </label>
    {#if setByFile('unifi_reads')}<span class="muted small" data-testid="set-by-file">(set by file)</span>{/if}
    <label>
      How far back client history reaches (hours, 1 to 8,760)
      <input
        type="number"
        min="1"
        max="8760"
        bind:value={withinHours}
        disabled={!writable || setByFile('unifi_all_users_within_hours')}
        aria-label="History window in hours"
      />
      {#if setByFile('unifi_all_users_within_hours')}<span class="muted small" data-testid="set-by-file">(set by file)</span>{/if}
    </label>
    <label class="row">
      <input
        type="checkbox"
        role="switch"
        bind:checked={haAll}
        disabled={!writable || setByFile('home_assistant_all_devices')}
        aria-label="Home Assistant devices without entities"
      />
      Home Assistant: devices that have a MAC address and no entity
      {#if setByFile('home_assistant_all_devices')}<span class="muted small" data-testid="set-by-file">(set by file)</span>{/if}
    </label>

    {#if writable}
      <div class="row actions">
        <button onclick={check} disabled={busy}>Check</button>
        {#if previewCurrent}
          <button class="primary" onclick={apply} disabled={busy}>Apply</button>
        {/if}
        {#if overridden}
          <button class="link" onclick={useFile} disabled={busy} data-testid="inventory-use-file">
            Use the file's settings
          </button>
        {/if}
      </div>
      {#if preview && !previewCurrent}
        <p class="small muted" data-testid="inventory-stale">The form changed after the Check. Check again before you apply.</p>
      {/if}
    {/if}
    {#if previewCurrent && preview}
      <div data-testid="inventory-preview" class="card">
        <p>{preview.impact}</p>
        {#each preview.warnings as w (w)}<p class="small">{w}</p>{/each}
      </div>
    {/if}
    <ErrorNote error={formError} />
    {#if notice}<p class="small" role="status">{notice}</p>{/if}
  </section>
</div>
