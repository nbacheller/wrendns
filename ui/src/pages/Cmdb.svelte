<script lang="ts">
  // REQ: DSC-901, DSC-902, DSC-903, DSC-906 (T31.2, ADR-1004, ADR-1005) — the CMDB: one configuration item
  // (CI) for each real thing on the network, built from every source that reports on it. This page has
  // its status (does it run here, what it holds, what it dropped), its settings (admins; Check is a dry
  // run, Apply saves), the CIs with a search, and one CI with every source's record side by side. A
  // wrong link is fixed here: Move a record to another device, Unlink it, Merge two devices, Split
  // records out, each with a preview of the records that would move. It only reads the network and never
  // names a device in DNS (DSC-901).
  import { untrack } from 'svelte';
  import { api, type S } from '../lib/api';
  import { poll } from '../lib/poll';
  import { can } from '../lib/session.svelte';
  import CmdbChange from '../lib/components/CmdbChange.svelte';
  import CmdbPicker from '../lib/components/CmdbPicker.svelte';
  import ErrorNote from '../lib/components/ErrorNote.svelte';
  import HelpButton from '../lib/components/HelpButton.svelte';

  type Entry = S['ConfigEntry'];
  type Ci = S['CmdbCi'];
  type Detail = S['CmdbCiDetail'];
  type Rec = S['CmdbRecord'];

  // -- status and settings (the same pattern as the network inventory's) -------------------------
  let entry = $state<Entry | null>(null);
  let status = $state<S['CmdbStatus'] | null>(null);
  let error = $state<unknown>(null);
  let notice = $state('');

  let enabled = $state(false);
  let disappear = $state(14);
  let settle = $state(600);
  let alertHours = $state(24);
  let planDays = $state(30);
  let historyDays = $state(90);
  let macdDays = $state(365);
  let secondApprover = $state(false);
  let preview = $state<S['ConfigChange'] | null>(null);
  let previewedWith = $state<string | null>(null);
  let formError = $state<unknown>(null);
  let busy = $state(false);
  let filledWith = $state<string | null>(null);

  const writable = $derived(can('admin'));
  const operator = $derived(can('operator'));
  const fileSet = $derived(entry?.setByFile ?? []);
  const setByFile = (k: string) => fileSet.includes(k);
  const snapshot = () => JSON.stringify([enabled, disappear, settle, alertHours, planDays, historyDays, macdDays, secondApprover]);
  const previewCurrent = $derived(preview !== null && previewedWith === snapshot());
  const overridden = $derived(entry?.source === 'override');

  function fromEntry(e: Entry | null) {
    const d = (e?.definition ?? {}) as Record<string, unknown>;
    enabled = d.enabled === true;
    disappear = Number(d.disappear_after_days ?? 14);
    settle = Number(d.detect_settle_secs ?? 600);
    alertHours = Number(d.unconfirmed_alert_hours ?? 24);
    planDays = Number(d.plan_expiry_days ?? 30);
    historyDays = Number(d.history_days ?? 90);
    macdDays = Number(d.macd_retention_days ?? 365);
    secondApprover = d.require_second_approver === true;
  }

  async function load(force = false) {
    try {
      const [cfg, st] = await Promise.all([api.configEntries('cmdb'), api.cmdbStatus()]);
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

  function body(): Record<string, unknown> {
    const all: Record<string, unknown> = {
      enabled,
      disappear_after_days: Number(disappear),
      detect_settle_secs: Number(settle),
      unconfirmed_alert_hours: Number(alertHours),
      plan_expiry_days: Number(planDays),
      history_days: Number(historyDays),
      macd_retention_days: Number(macdDays),
      require_second_approver: secondApprover,
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
      preview = await api.putEntry('cmdb-settings', 'default', body(), true);
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
      await api.putEntry('cmdb-settings', 'default', body(), false);
      preview = null;
      previewedWith = null;
      notice = 'Saved. The CMDB starts or stops on the designated node within a few seconds.';
      await load(true);
      await loadList();
    } catch (e) {
      formError = e;
    } finally {
      busy = false;
    }
  }

  async function useFile() {
    busy = true;
    formError = null;
    notice = '';
    try {
      await api.deleteEntry('cmdb-settings', 'default');
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

  const stateText = $derived(
    !status
      ? 'Loading'
      : !status.enabled
        ? 'Off'
        : status.running
          ? 'Runs on this node'
          : status.designated
            ? 'Starting on this node'
            : `Runs on ${status.node ?? 'the designated node'}`,
  );
  const count = (ty: string) => status?.cis.find((c) => c.ty === ty)?.count ?? 0;
  const learning = $derived(status?.learningUntil ? new Date(status.learningUntil * 1000).toLocaleString() : '');
  const mib = (b: number) => (b / (1024 * 1024)).toFixed(1);
  const when = (t: number | null | undefined) => (t ? new Date(t * 1000).toLocaleString() : '');
  const short = (c: string | null | undefined) => (c ? `${c.slice(0, 7)}…${c.slice(-4)}` : '');

  // -- the CIs ------------------------------------------------------------------------------------
  let type = $state('');
  let q = $state('');
  let items = $state<Ci[]>([]);
  let next = $state<string | null>(null);
  let listError = $state<unknown>(null);
  let loadingList = $state(false);

  async function loadList(more = false) {
    if (loadingList || !status?.running) return;
    loadingList = true;
    try {
      const page = await api.cmdbCis({ type: type || undefined, q: q.trim() || undefined, after: more ? (next ?? undefined) : undefined, limit: 50 });
      items = more ? [...items, ...page.items] : page.items;
      next = page.next ?? null;
      listError = null;
    } catch (e) {
      listError = e;
    } finally {
      loadingList = false;
    }
  }
  let queryTimer: ReturnType<typeof setTimeout> | undefined;
  function filterChanged() {
    clearTimeout(queryTimer);
    queryTimer = setTimeout(() => void loadList(), 200);
  }
  // The list loads once the CMDB runs here, and again when the status first says it does.
  // `untrack`: the load reads and writes its own state (`loadingList`, `items`); tracked here it would
  // run again after every load, in a loop that keeps replacing the rows under the reader's pointer.
  $effect(() => {
    const running = status?.running === true;
    if (running) untrack(() => void loadList());
  });

  // -- one CI -------------------------------------------------------------------------------------
  let selected = $state<string | null>(null);
  let detail = $state<Detail | null>(null);
  let detailError = $state<unknown>(null);
  let ticked = $state<Record<string, boolean>>({});

  async function open(id: string) {
    selected = id;
    try {
      detail = await api.cmdbCi(id);
      // A merged-away id leads to the CI it became.
      selected = detail.ci.id;
      ticked = {};
      detailError = null;
    } catch (e) {
      detail = null;
      detailError = e;
    }
  }

  const recKey = (r: Rec) => `${r.source}\u0000${r.key}`;
  const tickedRecords = $derived((detail?.records ?? []).filter((r) => ticked[recKey(r)]));
  // The attribute rows of the side-by-side table: every name any record has.
  const attrNames = $derived.by(() => {
    const names = new Set<string>();
    for (const r of detail?.records ?? []) for (const k of Object.keys((r.attrs ?? {}) as Record<string, unknown>)) names.add(k);
    return [...names].sort();
  });
  const show = (r: Rec, k: string): string => {
    const v = ((r.attrs ?? {}) as Record<string, unknown>)[k];
    if (v === undefined || v === null) return '';
    return Array.isArray(v) ? v.join(', ') : String(v);
  };
  // A row differs when two records that have the attribute give different values.
  const differs = (k: string): boolean => {
    const vals = new Set((detail?.records ?? []).map((r) => show(r, k)).filter((v) => v !== ''));
    return vals.size > 1;
  };

  // -- a manual change: pick what it needs, then the preview --------------------------------------
  type Change = { op: 'link' | 'unlink' | 'merge' | 'split'; id: string; body: Record<string, unknown>; title: string };
  let change = $state<Change | null>(null);
  let picking = $state<null | { label: string; then: (c: Ci) => void }>(null);
  let linkSource = $state('');
  let linkKey = $state('');
  let changeNotice = $state('');

  function startUnlink(r: Rec) {
    if (!detail) return;
    change = { op: 'unlink', id: detail.ci.id, body: { record: { source: r.source, key: r.key } }, title: `Unlink ${r.source} ${r.key}` };
  }
  function startMove(r: Rec) {
    picking = {
      label: `Move ${r.source} ${r.key} to which device?`,
      then: (c) => {
        change = { op: 'link', id: c.id, body: { record: { source: r.source, key: r.key } }, title: `Move ${r.source} ${r.key} to ${c.name ?? c.id}` };
        picking = null;
      },
    };
  }
  function startMerge() {
    if (!detail) return;
    const from = detail.ci;
    picking = {
      label: `Merge ${from.name ?? from.id} into which device?`,
      then: (c) => {
        change = { op: 'merge', id: from.id, body: { into: c.id }, title: `Merge ${from.name ?? from.id} into ${c.name ?? c.id}` };
        picking = null;
      },
    };
  }
  function startSplit() {
    if (!detail || tickedRecords.length === 0) return;
    change = {
      op: 'split',
      id: detail.ci.id,
      body: { records: tickedRecords.map((r) => ({ source: r.source, key: r.key })) },
      title: `Split ${tickedRecords.length} record${tickedRecords.length === 1 ? '' : 's'} out of ${detail.ci.name ?? detail.ci.id}`,
    };
  }
  function startLinkHere() {
    if (!detail || !linkSource.trim() || !linkKey.trim()) return;
    change = {
      op: 'link',
      id: detail.ci.id,
      body: { record: { source: linkSource.trim(), key: linkKey.trim() } },
      title: `Link ${linkSource.trim()} ${linkKey.trim()} to ${detail.ci.name ?? detail.ci.id}`,
    };
  }
  async function changed(r: S['CmdbChange']) {
    const was = change;
    change = null;
    changeNotice = `${r.op === 'merge' ? 'Merged' : r.op === 'split' ? 'Split' : r.op === 'unlink' ? 'Unlinked' : 'Linked'}: ${r.moves.length} record${r.moves.length === 1 ? '' : 's'} moved.`;
    await loadList();
    await loadProposals();
    // Show where it ended: the new device of a split or an unlink, the survivor of a merge, else
    // the CI that was open (or the one the record went to).
    const go = r.op === 'split' || r.op === 'unlink' || r.op === 'merge' ? (r.result ?? selected) : (was?.id ?? selected);
    if (go) await open(go);
  }

  // -- the merge proposals -------------------------------------------------------------------------
  let proposals = $state<S['CmdbProposal'][]>([]);
  async function loadProposals() {
    if (!status?.running) return;
    try {
      proposals = await api.cmdbProposals();
    } catch {
      proposals = [];
    }
  }
  $effect(() => {
    const running = status?.running === true;
    if (running) untrack(() => void loadProposals());
  });
  function proposeMerge(p: S['CmdbProposal']) {
    change = { op: 'merge', id: p.a, body: { into: p.b }, title: `Merge ${short(p.a)} into ${short(p.b)}` };
  }
  const proposalKind: Record<string, string> = {
    level_disagreement: 'A record points at two devices',
    host_network: 'Same host name on the same network',
    ambiguous_record: 'A record holds an address that two devices hold',
  };
</script>

<div class="page">
  <div class="page-head">
    <h1>CMDB<HelpButton id="cmdb" /></h1>
    <span class="muted small">Devices</span>
  </div>
  <ErrorNote {error} />

  <section class="card" data-testid="cmdb-status">
    <h2>Status</h2>
    <p>
      <strong data-testid="cmdb-state">{stateText}</strong>
      {#if status?.enabled && !status.running && !status.designated}
        <span class="muted small">This node doesn't run it. The designated node does, and DNS is unaffected.</span>
      {/if}
      {#if learning}<span class="muted small" data-testid="cmdb-learning">Learning until {learning}: no new or missing device is reported yet.</span>{/if}
    </p>
    {#if status?.running}
      <p class="small" data-testid="cmdb-counts">
        {count('device')} devices, {count('interface')} interfaces, {count('network')} networks, {count('node')} nodes,
        {count('service')} services, {count('upstream')} upstreams. {status.records} source records ({status.recordsPresent} present).
        {status.proposalsOpen} merge proposals. {mib(status.diskBytes)} MiB on disk.
      </p>
      {#if status.sources.length > 0}
        <h3>Sources<HelpButton id="cmdb-sources" /></h3>
        <div class="table-wrap">
          <table class="compact" data-testid="cmdb-sources">
            <thead><tr><th>Source</th><th>Held</th><th>Last batch</th><th>Records</th></tr></thead>
            <tbody>
              {#each status.sources as s (s.source)}
                <tr><td>{s.source}</td><td>{s.held}</td><td class="small">{when(s.lastBatchUnix)}{#if !s.complete} <span class="muted">(partial)</span>{/if}</td><td>{s.records}</td></tr>
              {/each}
            </tbody>
          </table>
        </div>
      {/if}
      {#if status.dropped.ci > 0 || status.dropped.record > 0 || status.dropped.batch > 0}
        <p class="small" data-testid="cmdb-dropped">
          Dropped at a cap: {status.dropped.ci} CIs refused, {status.dropped.record} records, {status.dropped.batch} batches. DNS is unaffected.
        </p>
      {/if}
      {#if status.lastError}<p class="small" role="alert">Last error: {status.lastError}</p>{/if}
    {/if}
  </section>

  <section class="card" data-testid="cmdb-settings">
    <h2>Settings</h2>
    {#if !writable}
      <p class="muted small">Only an administrator can change the CMDB's settings. You can read them here.</p>
    {/if}
    <label class="row">
      <input type="checkbox" role="switch" bind:checked={enabled} disabled={!writable || setByFile('enabled')} aria-label="Turn the CMDB on" />
      Turn the CMDB on
      {#if setByFile('enabled')}<span class="muted small" data-testid="set-by-file">(set by file)</span>{/if}
    </label>
    <p class="muted small">
      It runs on the node the network inventory is designated to (the primary, or the node `[discovery] node` names), even when the
      inventory itself is off. It cannot be on while the privacy level is 2 or 3.
    </p>
    <p class="muted small" data-testid="cmdb-settings-inert">
      The settings below are saved and checked now. Nothing reads them yet: they take effect when change detection and the
      value history arrive in a later part of the CMDB.
    </p>
    <label>
      A device is reported gone after (days, 1 to 365)
      <input type="number" min="1" max="365" bind:value={disappear} disabled={!writable || setByFile('disappear_after_days')} aria-label="Days before a device is reported gone" />
      {#if setByFile('disappear_after_days')}<span class="muted small" data-testid="set-by-file">(set by file)</span>{/if}
    </label>
    <label>
      A change must hold for (seconds, 60 to 86,400)
      <input type="number" min="60" max="86400" bind:value={settle} disabled={!writable || setByFile('detect_settle_secs')} aria-label="Seconds a change must hold" />
      {#if setByFile('detect_settle_secs')}<span class="muted small" data-testid="set-by-file">(set by file)</span>{/if}
    </label>
    <label>
      An unconfirmed change raises an alert after (hours, 1 to 720)
      <input type="number" min="1" max="720" bind:value={alertHours} disabled={!writable || setByFile('unconfirmed_alert_hours')} aria-label="Hours before an unconfirmed change alerts" />
      {#if setByFile('unconfirmed_alert_hours')}<span class="muted small" data-testid="set-by-file">(set by file)</span>{/if}
    </label>
    <label>
      An approved plan expires after (days, 1 to 365)
      <input type="number" min="1" max="365" bind:value={planDays} disabled={!writable || setByFile('plan_expiry_days')} aria-label="Days before an approved plan expires" />
      {#if setByFile('plan_expiry_days')}<span class="muted small" data-testid="set-by-file">(set by file)</span>{/if}
    </label>
    <label>
      Value history is kept (days, 1 to 730)
      <input type="number" min="1" max="730" bind:value={historyDays} disabled={!writable || setByFile('history_days')} aria-label="Days of value history" />
      {#if setByFile('history_days')}<span class="muted small" data-testid="set-by-file">(set by file)</span>{/if}
    </label>
    <label>
      Change records are kept (days, 1 to 1,825)
      <input type="number" min="1" max="1825" bind:value={macdDays} disabled={!writable || setByFile('macd_retention_days')} aria-label="Days of change records" />
      {#if setByFile('macd_retention_days')}<span class="muted small" data-testid="set-by-file">(set by file)</span>{/if}
    </label>
    <label class="row">
      <input type="checkbox" role="switch" bind:checked={secondApprover} disabled={!writable || setByFile('require_second_approver')} aria-label="Require a second approver" />
      Nobody approves their own request
      {#if setByFile('require_second_approver')}<span class="muted small" data-testid="set-by-file">(set by file)</span>{/if}
    </label>

    {#if writable}
      <div class="row actions">
        <button onclick={check} disabled={busy}>Check</button>
        {#if previewCurrent}
          <button class="primary" onclick={apply} disabled={busy}>Apply</button>
        {/if}
        {#if overridden}
          <button class="link" onclick={useFile} disabled={busy} data-testid="cmdb-use-file">Use the file's settings</button>
        {/if}
      </div>
      {#if preview && !previewCurrent}
        <p class="small muted" data-testid="cmdb-stale">The form changed after the Check. Check again before you apply.</p>
      {/if}
    {/if}
    {#if previewCurrent && preview}
      <div data-testid="cmdb-settings-preview" class="card">
        <p>{preview.impact}</p>
        {#each preview.warnings as w (w)}<p class="small">{w}</p>{/each}
      </div>
    {/if}
    <ErrorNote error={formError} />
    {#if notice}<p class="small" role="status">{notice}</p>{/if}
  </section>

  {#if status?.running}
    {#if proposals.length > 0}
      <section class="card" data-testid="cmdb-proposals">
        <h2>Merge proposals<HelpButton id="cmdb-proposals" /></h2>
        <p class="muted small">Reconciliation never merges two devices on a doubtful match: it asks. Nothing here has been applied.</p>
        <ul class="plain">
          {#each proposals as p (p.id)}
            <li data-testid="cmdb-proposal" data-kind={p.kind}>
              <strong>{proposalKind[p.kind] ?? p.kind}</strong>
              <span class="muted small">(rule {p.rule})</span>
              <div class="small">{p.detail}</div>
              <div class="row actions">
                <button class="link" onclick={() => open(p.a)}>Open <code>{short(p.a)}</code></button>
                <button class="link" onclick={() => open(p.b)}>Open <code>{short(p.b)}</code></button>
                {#if operator && p.kind !== 'ambiguous_record'}
                  <button onclick={() => proposeMerge(p)} data-testid="cmdb-propose-merge">Merge them…</button>
                {/if}
              </div>
            </li>
          {/each}
        </ul>
      </section>
    {/if}

    <section class="card" data-testid="cmdb-list">
      <h2>Configuration items</h2>
      <div class="row">
        <label>
          Type
          <select bind:value={type} onchange={filterChanged} aria-label="Type">
            <option value="">Everything but interfaces</option>
            <option value="device">Devices</option>
            <option value="interface">Interfaces and ports</option>
            <option value="network">Networks</option>
            <option value="node">Nodes</option>
            <option value="service">Services</option>
            <option value="upstream">Upstreams</option>
          </select>
        </label>
        <label>
          Find
          <input type="search" bind:value={q} oninput={filterChanged} aria-label="Find a CI" placeholder="name, MAC, serial or id" />
        </label>
      </div>
      <ErrorNote error={listError} />
      <div class="table-wrap">
        <table data-testid="cmdb-cis">
          <thead><tr><th>Name</th><th>Type</th><th>Sources</th><th>Records</th><th>Flags</th></tr></thead>
          <tbody>
            {#each items as c (c.id)}
              <tr data-testid="cmdb-row" data-ci={c.id} data-name={c.name ?? ''}>
                <td><button class="link" onclick={() => open(c.id)}>{c.name ?? c.id}</button></td>
                <td>{c.ty}{#if c.kind} <span class="muted small">({c.kind})</span>{/if}</td>
                <td class="small">{c.sources.join(', ')}</td>
                <td>{c.records}</td>
                <td class="small">
                  {#if c.unconfirmed}<span class="chip" title="No source confirms it yet">unconfirmed</span>{/if}
                  {#if c.unmappedPort}<span class="chip" title="A port no alias joins to another source's port">unmapped port</span>{/if}
                  {#if c.proposals > 0}<span class="chip" title="A merge proposal names it">{c.proposals} proposal{c.proposals === 1 ? '' : 's'}</span>{/if}
                </td>
              </tr>
            {:else}
              <tr><td colspan="5" class="muted small">{loadingList ? 'Loading' : 'Nothing yet. The sources report once a minute.'}</td></tr>
            {/each}
          </tbody>
        </table>
      </div>
      {#if next}<button onclick={() => loadList(true)} disabled={loadingList}>More</button>{/if}
    </section>

    {#if picking}
      <CmdbPicker label={picking.label} exclude={detail?.ci.id ?? ''} onpick={(c) => picking?.then(c)} oncancel={() => (picking = null)} />
    {/if}
    {#if change}
      <CmdbChange op={change.op} id={change.id} body={change.body} title={change.title} ondone={changed} oncancel={() => (change = null)} />
    {/if}
    {#if changeNotice}<p class="small" role="status" data-testid="cmdb-change-notice">{changeNotice}</p>{/if}

    {#if detail}
      <section class="card" data-testid="cmdb-ci" data-ci={detail.ci.id}>
        <h2>{detail.ci.name ?? detail.ci.id}</h2>
        <p class="small">
          <code>{detail.ci.id}</code> · {detail.ci.ty}{#if detail.ci.kind} ({detail.ci.kind}){/if} · first seen {when(detail.ci.firstSeen)}{#if detail.ci.lastSeen}, last seen {when(detail.ci.lastSeen)}{/if}{#if detail.ci.daysSeen} on {detail.ci.daysSeen} day{detail.ci.daysSeen === 1 ? '' : 's'}{/if}
        </p>
        {#if detail.ci.unconfirmed}<p class="small">No source confirms this yet: it was made from a record with no key that matched no device.</p>{/if}
        {#each detail.aliases as a (a.id)}
          <p class="small muted" data-testid="cmdb-alias">The id <code>{short(a.id)}</code> was merged into this one and redirects until {when(a.until)}.</p>
        {/each}
        {#if detail.interfaces.length > 0}
          <h3>Interfaces</h3>
          <ul class="plain small" data-testid="cmdb-interfaces">
            {#each detail.interfaces as i (i.id)}
              <li>{i.name ?? i.id} <span class="muted">({i.kind ?? 'interface'}{#if i.unmappedPort}, unmapped port{/if})</span></li>
            {/each}
          </ul>
        {/if}

        <h3>Sources, side by side<HelpButton id="cmdb-sources" /></h3>
        <p class="muted small">Each column is what one source said, as it said it. A row where they differ is marked.</p>
        <div class="table-wrap">
          <table class="compact" data-testid="cmdb-records">
            <thead>
              <tr>
                <th></th>
                {#each detail.records as r (recKey(r))}
                  <th data-testid="cmdb-record" data-source={r.source} data-key={r.key}>
                    {#if operator && detail.ci.ty === 'device'}
                      <input type="checkbox" aria-label={`Select ${r.source} ${r.key}`} bind:checked={ticked[recKey(r)]} data-testid="cmdb-tick" />
                    {/if}
                    {r.source}<br /><code class="small">{r.key}</code><br />
                    <span class="muted small">{r.state}, {r.link}</span>
                    {#if operator && detail.ci.ty === 'device'}
                      <br />
                      <button class="link" onclick={() => startMove(r)} data-testid="cmdb-move">Move to…</button>
                      <button class="link" onclick={() => startUnlink(r)} data-testid="cmdb-unlink">Unlink</button>
                    {/if}
                  </th>
                {/each}
              </tr>
            </thead>
            <tbody>
              {#each attrNames as k (k)}
                <tr class:differs={differs(k)}>
                  <th class="small">{k}{#if differs(k)} <span class="chip">differs</span>{/if}</th>
                  {#each detail.records as r (recKey(r))}<td class="small">{show(r, k)}</td>{/each}
                </tr>
              {/each}
            </tbody>
          </table>
        </div>

        {#if operator && detail.ci.ty === 'device'}
          <div class="row actions">
            <button onclick={startMerge} data-testid="cmdb-merge">Merge into another device…</button>
            <button onclick={startSplit} disabled={tickedRecords.length === 0} data-testid="cmdb-split">Split the selected records out…</button>
          </div>
          <details>
            <summary>Link a record to this device<HelpButton id="cmdb-changes" /></summary>
            <p class="muted small">Name a record shown on another CI (its source and key). A record with a MAC moves its whole interface.</p>
            <div class="row">
              <label>Source<input type="text" bind:value={linkSource} aria-label="Source of the record" placeholder="mdns" /></label>
              <label>Key<input type="text" bind:value={linkKey} aria-label="Key of the record" placeholder="printer" /></label>
              <button onclick={startLinkHere} disabled={!linkSource.trim() || !linkKey.trim()} data-testid="cmdb-link-here">Preview</button>
            </div>
          </details>
        {/if}

        {#if detail.proposals.length > 0}
          <h3>Proposals about this CI</h3>
          <ul class="plain small">
            {#each detail.proposals as p (p.id)}<li>{proposalKind[p.kind] ?? p.kind}: {p.detail}</li>{/each}
          </ul>
        {/if}
        {#if detail.pins.length > 0}
          <h3>Decisions made here</h3>
          <ul class="plain small" data-testid="cmdb-pins">
            {#each detail.pins as p (p.kind + p.subject + p.target)}
              <li>{p.kind === 'nic_device' ? 'Interface pinned here' : p.kind === 'rec_device' ? 'Record linked here' : 'Record unlinked from here'}: <code>{p.subject}</code> · {p.by} · {when(p.at)}{#if p.reason} · {p.reason}{/if}</li>
            {/each}
          </ul>
        {/if}
      </section>
    {/if}
    <ErrorNote error={detailError} />
  {/if}
</div>

<style>
  tr.differs th,
  tr.differs td {
    background: color-mix(in srgb, var(--warn, #d97706) 12%, transparent);
  }
  ul.plain {
    list-style: none;
    padding: 0;
    margin: 0;
  }
  ul.plain li {
    margin: 0.35rem 0;
  }
  .chip {
    display: inline-block;
    padding: 0 0.4rem;
    margin-right: 0.25rem;
    border: 1px solid var(--border, #8884);
    border-radius: 999px;
    font-size: 0.75rem;
  }
</style>
