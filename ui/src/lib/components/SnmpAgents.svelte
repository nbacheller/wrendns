<script lang="ts">
  // REQ: DSC-004, DSC-014 (T25.6, ADR-908, ADR-1002) — the SNMP agents of the network inventory: the
  // devices the poller reads (a gateway's ARP table, a switch's forwarding table, LLDP neighbours).
  // Admins add, edit and delete them (the page's Check and Apply save the whole list); everyone reads
  // them with their last poll and capability record. **Test** probes one saved agent now, or with
  // its dry run lists the OIDs without sending a packet. Device text (sysObjectID, names) is shown as
  // text only.
  import { api, type S } from '../api';
  import { ago } from '../format';
  import {
    type AgentDraft,
    type CredDraft,
    SNMP_TABLES,
    TABLE_HELP,
    agentBody,
    blankAgent,
    stateText,
    tableText,
  } from '../snmp';
  import ErrorNote from './ErrorNote.svelte';
  import HelpButton from './HelpButton.svelte';

  let {
    agents = $bindable(),
    credentials,
    writable,
    fileSet,
    status,
    saved,
  }: {
    agents: AgentDraft[];
    credentials: CredDraft[];
    writable: boolean;
    /** The configuration files set the list: it is read-only here. */
    fileSet: boolean;
    /** What the poller says about each agent (`GET /api/v1/discovery/status`). */
    status: S['DiscoveryAgent'][];
    /** The agents as stored, to tell which draft is already saved (Test works on saved agents). */
    saved: AgentDraft[];
  } = $props();

  const canEdit = $derived(writable && !fileSet);
  let draft = $state<AgentDraft | null>(null);
  let index = $state(-1);
  let formError = $state('');
  const statusOf = (name: string) => status.find((s) => s.name === name);
  const isSaved = (a: AgentDraft) => saved.some((s) => JSON.stringify(agentBody(s)) === JSON.stringify(agentBody(a)));

  function add() {
    draft = blankAgent();
    index = -1;
    formError = '';
    const first = credentials.find((c) => c.role === 'infrastructure');
    if (first) draft.credential = first.name;
  }
  function edit(i: number) {
    draft = { ...agents[i], tables: [...agents[i].tables] };
    index = i;
    formError = '';
  }
  function cancel() {
    draft = null;
    formError = '';
  }
  function remove(i: number) {
    const gone = agents[i]?.name;
    agents = agents.filter((_, j) => j !== i);
    if (test === gone) closeTest();
  }
  function keep() {
    if (!draft) return;
    const d = { ...draft, name: draft.name.trim(), address: draft.address.trim() };
    if (!d.name) return void (formError = 'Give the agent a name.');
    if (!/^[A-Za-z0-9._-]{1,64}$/.test(d.name) || /^\d+\.\d+\.\d+\.\d+$/.test(d.name)) {
      return void (formError = 'A name is letters, digits, "." "_" or "-", up to 64, and is not an address.');
    }
    if (agents.some((a, j) => j !== index && a.name === d.name)) return void (formError = `There is already an agent named ${d.name}.`);
    if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(d.address)) return void (formError = 'The address is an IPv4 address, such as 192.168.1.1.');
    if (!d.credential) return void (formError = 'Pick a credential (add one under Credentials first).');
    if (d.tables.length === 0) return void (formError = 'Pick at least one table to poll.');
    agents = index < 0 ? [...agents, d] : agents.map((a, j) => (j === index ? d : a));
    draft = null;
    formError = '';
  }
  function toggle(t: string, on: boolean) {
    if (!draft) return;
    draft.tables = on ? [...draft.tables.filter((x) => x !== t), t] : draft.tables.filter((x) => x !== t);
  }

  // ---- Test
  let test = $state<string | null>(null);
  let result = $state<S['SnmpTestResult'] | null>(null);
  let testError = $state<unknown>(null);
  let testing = $state(false);
  function openTest(name: string) {
    test = name;
    result = null;
    testError = null;
  }
  function closeTest() {
    test = null;
    result = null;
    testError = null;
  }
  async function run(dry: boolean) {
    if (!test) return;
    testing = true;
    testError = null;
    try {
      result = await api.snmpTest(test, dry);
    } catch (e) {
      result = null;
      testError = e;
    } finally {
      testing = false;
    }
  }
</script>

<div data-testid="inventory-agents">
  <h3>SNMP agents<HelpButton id="snmp-agents" /></h3>
  <p class="muted small">
    Devices WrenDNS may read over SNMP: a gateway's ARP table, a switch's forwarding table and its LLDP neighbours. Read-only.
    <HelpButton id="snmp-setup" />
  </p>
  {#if fileSet}<p class="muted small" data-testid="set-by-file">(the agents are set by file)</p>{/if}
  {#if agents.length === 0}
    <p class="muted small" data-testid="agents-empty">No SNMP agent is configured.</p>
  {:else}
    <table>
      <thead>
        <tr><th>Agent</th><th>Address</th><th>Credential</th><th>State</th><th>Last poll</th><th>Tables</th>{#if canEdit}<th></th>{/if}</tr>
      </thead>
      <tbody>
        {#each agents as a, i (a.name)}
          {@const st = statusOf(a.name)}
          <tr data-testid="agent-{a.name}">
            <td>{a.name}</td>
            <td>{a.address}{a.port === 161 ? '' : `:${a.port}`}</td>
            <td>{a.credential}</td>
            <td>
              {#if st}
                <span class="badge {st.state === 'ok' ? 'ok' : st.state === 'failing' ? 'bad' : st.state === 'error' ? 'warn' : ''}" data-testid="agent-state">{stateText(st.state)}</span>
                {#if st.lastError}<div class="small muted" data-testid="agent-error">{st.lastError}</div>{/if}
              {:else}
                <span class="muted small">Not applied yet</span>
              {/if}
            </td>
            <td class="small">
              {#if st?.lastSuccessUnix}{ago(st.lastSuccessUnix)}{:else}<span class="muted">never</span>{/if}
            </td>
            <td class="small">
              {#each st?.tables ?? a.tables.map((t) => ({ table: t, state: 'unprobed', rows: null, stop: null, error: null })) as t (t.table)}
                <div data-testid="agent-table-{t.table}">
                  {t.table}: {tableText(t.state)}{#if t.rows != null}, {t.rows} rows{/if}
                  {#if t.error}<span class="muted"> ({t.error})</span>{/if}
                </div>
              {/each}
            </td>
            {#if canEdit}
              <td class="actions">
                <button class="link" onclick={() => edit(i)} aria-label={`Edit agent ${a.name}`}>Edit</button>
                <button class="link" onclick={() => remove(i)} aria-label={`Delete agent ${a.name}`}>Delete</button>
                <button
                  onclick={() => openTest(a.name)}
                  disabled={!isSaved(a)}
                  title={isSaved(a) ? 'Probe this agent now' : 'Apply your changes first: a test reads the saved agent'}
                  aria-label={`Test agent ${a.name}`}>Test</button
                >
              </td>
            {/if}
          </tr>
        {/each}
      </tbody>
    </table>
  {/if}

  {#if canEdit && !draft}
    <div class="row actions"><button onclick={add} data-testid="agent-add">Add an agent</button></div>
  {/if}

  {#if draft}
    <div class="card" data-testid="agent-form">
      <h4>{index < 0 ? 'Add an agent' : `Edit ${agents[index]?.name}`}</h4>
      <label>
        Name
        <input type="text" bind:value={draft.name} aria-label="Agent name" placeholder="gateway" />
      </label>
      <label>
        Address (a private IPv4 address)
        <input type="text" bind:value={draft.address} aria-label="Agent address" placeholder="192.168.1.1" />
      </label>
      <label>
        Credential
        <select bind:value={draft.credential} aria-label="Agent credential">
          <option value="">Pick one</option>
          {#each credentials.filter((c) => c.role === 'infrastructure') as c (c.name)}
            <option value={c.name}>{c.name} ({c.version})</option>
          {/each}
        </select>
      </label>
      <label>
        Seconds between polls (60 or more)
        <input type="number" min="60" max="86400" bind:value={draft.interval_secs} aria-label="Seconds between polls" />
      </label>
      <details>
        <summary class="small">More</summary>
        <label>
          UDP port
          <input type="number" min="1" max="65535" bind:value={draft.port} aria-label="Agent port" />
        </label>
        <label>
          GETBULK repetitions (5 to 25)
          <input type="number" min="5" max="25" bind:value={draft.max_repetitions} aria-label="GETBULK repetitions" />
        </label>
      </details>
      <fieldset>
        <legend class="small">Tables to poll (a table the device doesn't answer is skipped)</legend>
        {#each SNMP_TABLES as t (t)}
          <label class="row">
            <input type="checkbox" checked={draft.tables.includes(t)} onchange={(e) => toggle(t, e.currentTarget.checked)} aria-label={`Poll the ${t} table`} />
            {TABLE_HELP[t]}
          </label>
        {/each}
      </fieldset>
      {#if formError}<p class="notice bad" role="alert">{formError}</p>{/if}
      <div class="row actions">
        <button class="primary" onclick={keep} data-testid="agent-keep">{index < 0 ? 'Add to the list' : 'Keep the change'}</button>
        <button class="link" onclick={cancel}>Cancel</button>
      </div>
      <p class="muted small">Nothing is saved until you press Check and Apply below.</p>
    </div>
  {/if}

  {#if test}
    <div class="card" data-testid="snmp-test">
      <h4>Test {test}</h4>
      <p class="muted small">
        A test sends one GETNEXT on the first column of each table, and one GET of sysObjectID. It reads and never writes, and waits a minute before the next test of the same agent.
      </p>
      <div class="row actions">
        <button onclick={() => run(true)} disabled={testing} data-testid="test-dry">Show the OIDs (dry run)</button>
        <button class="primary" onclick={() => run(false)} disabled={testing} data-testid="test-now">Test now</button>
        <button class="link" onclick={closeTest}>Close</button>
      </div>
      <ErrorNote error={testError} />
      {#if result}
        <div data-testid="test-result">
          {#if result.dryRun}
            <p class="small" role="status">{result.note}</p>
            <table>
              <thead><tr><th>Table</th><th>Part</th><th>MIB table</th><th>Probe OID</th></tr></thead>
              <tbody>
                {#each result.oids as o (o.alternative + o.probeOid)}
                  <tr><td>{o.table}</td><td>{o.part}</td><td>{o.alternative}</td><td><code>{o.probeOid}</code></td></tr>
                {/each}
              </tbody>
            </table>
          {:else if !result.ok}
            <p class="notice bad" role="alert" data-testid="test-failed">The agent did not answer: {result.error}</p>
          {:else if result.capability}
            <p class="small" role="status">{result.note} ({result.durationMs} ms)</p>
            <dl class="small">
              <dt>Security level</dt>
              <dd data-testid="cap-level">{result.capability.level}</dd>
              {#if result.capability.engineId}<dt>Engine ID</dt><dd><code>{result.capability.engineId}</code></dd>{/if}
              {#if result.capability.sysObjectId}<dt>sysObjectID (from the device)</dt><dd><code>{result.capability.sysObjectId}</code></dd>{/if}
            </dl>
            <table data-testid="cap-parts">
              <thead><tr><th>Table</th><th>Part</th><th>Answered by</th></tr></thead>
              <tbody>
                {#each result.capability.parts as p (p.table + p.part)}
                  <tr><td>{p.table}</td><td>{p.part}</td><td>{p.source ?? 'no alternative answered (skipped)'}</td></tr>
                {/each}
              </tbody>
            </table>
          {/if}
        </div>
      {/if}
    </div>
  {/if}
</div>
