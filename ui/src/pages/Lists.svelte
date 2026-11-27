<script lang="ts">
  // REQ: API-005, FLT-004 — filter lists with their download state.
  import { api, type S } from '../lib/api';
  import { ago, bytes, num } from '../lib/format';
  import { poll } from '../lib/poll';
  import ErrorNote from '../lib/components/ErrorNote.svelte';
  import StatusBadge from '../lib/components/StatusBadge.svelte';
  import HelpButton from '../lib/components/HelpButton.svelte';
  import ShareBar from '../lib/components/ShareBar.svelte';
  import { currentMode } from '../lib/mode.svelte';
  import { can } from '../lib/session.svelte';
  import ConfigEditor, { type Field } from '../lib/components/ConfigEditor.svelte';
  // REQ: FLT-004 (T27.11) — the list refresh and stale settings, above the lists.
  import FilterSettings from '../lib/components/FilterSettings.svelte';
  import { classifyListError } from '../lib/list-failure';
  // REQ: FLT-901 (T24.29) - the Categories tab, and the lists the categories own.
  import Tabs, { activeTab, type TabItem } from '../lib/components/Tabs.svelte';
  import TabPanel from '../lib/components/TabPanel.svelte';
  import Categories from '../lib/components/Categories.svelte';
  import { navigate } from '../lib/router.svelte';

  const tabs: TabItem[] = [
    { id: 'lists', label: 'Lists' },
    { id: 'categories', label: 'Categories' },
  ];
  const tab = $derived(activeTab(tabs));
  let catView = $state<S['CategoriesView'] | null>(null);
  let catError = $state<unknown>(null);
  $effect(() => {
    if (tab !== 'categories') return;
    api.categories().then((v) => (catView = v)).catch((e) => (catError = e));
  });
  // The categories some group selects, shown ticked in the (read-only) catalog browser.
  const inUse = $derived(
    catView ? catView.groups.flatMap((g) => g.categories).filter((c) => c.groups.length > 0).map((c) => c.id) : [],
  );
  // The lists page shows every list, or only the ones the categories own (REQ: FLT-901).
  let only = $state<'all' | 'categories'>('all');

  // REQ: API-002 (T7.5) — add and change lists here.
  const listFields: Field[] = [
    { key: 'url', label: 'Download from', type: 'text', placeholder: 'https://example.org/hosts.txt',
      help: 'Hosts files, plain domain lists, and Adblock-style lists all work. Or leave this empty and write the rules below.' },
    { key: 'rules', label: 'Rules', type: 'lines', placeholder: 'ads.example.com, ||tracker.example^ (one per line)' },
    { key: 'kind', label: 'Kind', type: 'select', options: ['block', 'allow'], initial: 'block' },
    { key: 'match', label: 'Plain names match', type: 'select', options: ['subtree', 'exact'], advanced: true,
      help: 'subtree: the name and everything below it. exact: only the name itself.' },
    { key: 'enabled', label: 'On', type: 'bool', initial: true },
    // REQ: FLT-004 (T27.11) — the list's own size limit and stale age (empty: the lists' defaults).
    { key: 'max_bytes', label: 'Largest download', type: 'text', placeholder: '64MiB (empty: the default)', helpTopic: 'list-limits' },
    { key: 'stale_after_days', label: 'Stale after (days; 0: never)', type: 'number', min: 0, helpTopic: 'list-limits' },
    // REQ: OBS-018 — try a list before it blocks anything.
    { key: 'mode', label: 'Mode', type: 'select', options: ['enforce', 'shadow'], initial: 'enforce',
      help: 'enforce: it blocks. shadow: it never blocks; the page shows what it would have blocked, so you can judge it first.' },
    { key: 'refresh_secs', label: 'Check for updates every (seconds)', type: 'number', placeholder: '86400', advanced: true },
  ];

  let lists = $state<S['ListInfo'][]>([]);
  // REQ: FLT-004 — on a replica, the nodes whose hits are left out (the primary's among them when
  // it didn't answer its reads).
  let unread = $state<string[]>([]);
  // The names `missingNodes` may use for the primary: its pod, site and node ID (from GET /cluster,
  // as `ctl lists refresh --wait` reads them).
  let primaryNames = $state<string[]>([]);
  // The primary is unread, so the download state shown isn't confirmed from it (REQ: FLT-004).
  const primaryUnread = $derived(unread.some((u) => primaryNames.includes(u)));
  function primaryNamesOf(c: S['ClusterView']): string[] {
    const p = c.nodes.find((n) => n.role === 'primary');
    return p ? [p.pod, p.site, p.nodeId].filter((s): s is string => !!s) : [];
  }
  let info = $state<S['SystemInfo'] | null>(null);
  // REQ: OBS-018 — what shadow lists would have blocked, and likely over-blocking.
  let shadow = $state<S['ShadowListStats'][]>([]);
  let suspects = $state<S['OverblockSuspect'][]>([]);
  let error = $state<unknown>(null);
  // Until the first answer, the table isn't "empty": it's loading.
  let loaded = $state(false);

  $effect(() =>
    poll(async () => {
      try {
        const [l, i, sh, ob, cl] = await Promise.all([
          api.lists(),
          api.info(),
          api.shadowLists().catch(() => ({ items: [] as S['ShadowListStats'][] })),
          api.overblocking(20).catch(() => ({ items: [] as S['OverblockSuspect'][] })),
          api.cluster().catch(() => null),
        ]);
        lists = l.items;
        unread = l.missingNodes ?? [];
        if (cl) primaryNames = primaryNamesOf(cl);
        info = i;
        shadow = sh.items;
        suspects = ob.items;
        loaded = true;
        error = null;
      } catch (e) {
        error = e;
      }
    }, 15000),
  );
  const advanced = $derived(currentMode() === 'advanced');

  // REQ: FLT-004 — "Update now" (like Pi-hole's Update Gravity): queue every enabled list,
  // then follow `refreshing` until the downloads end (the snapshot follows within seconds).
  let refresh = $state<S['ListsRefreshResult'] | null>(null);
  let refreshError = $state<unknown>(null);
  let starting = $state(false);
  // REQ: FLT-004 (T24.17) — the list whose row's "Update now" is waiting for its answer.
  let startingRow = $state<string | null>(null);
  const updating = $derived(
    starting || (refresh !== null && lists.some((l) => l.refreshing && refresh!.queued.includes(l.name))),
  );
  const busy = $derived(updating || startingRow !== null);
  // A refresh of every enabled list (the page-wide button), or of one list (a row's "Update now").
  let refreshScope = $state<'all' | 'one'>('all');
  const wholeSet = $derived(refresh !== null && refreshScope === 'all');
  // The oldest enabled list's last confirmation, so one fresh list can't hide a stale one. A
  // list never downloaded makes it null.
  const lastUpdated = $derived.by(() => {
    const on = lists.filter((l) => l.enabled && l.source !== 'inline');
    if (on.length === 0 || on.some((l) => !l.lastSuccessUnixSeconds)) return null;
    return Math.min(...on.map((l) => l.lastSuccessUnixSeconds ?? 0));
  });
  // The lists this refresh queued whose download failed.
  const failed = $derived(
    refresh === null
      ? []
      : lists.filter((l) => refresh!.queued.includes(l.name) && (l.state === 'failed' || !!l.error)),
  );
  async function updateNow() {
    starting = true;
    refreshScope = 'all';
    refreshError = null;
    try {
      refresh = await api.refreshLists();
      ({ items: lists, missingNodes: unread = [] } = await api.lists());
    } catch (e) {
      refreshError = e;
      refresh = null;
    } finally {
      starting = false;
    }
  }
  // REQ: FLT-004 (T24.17) — one list's "Update now": the same request with that list's name.
  async function updateOne(name: string) {
    startingRow = name;
    refreshScope = 'one';
    refreshError = null;
    try {
      refresh = await api.refreshLists([name]);
      ({ items: lists, missingNodes: unread = [] } = await api.lists());
    } catch (e) {
      refreshError = e;
      refresh = null;
    } finally {
      startingRow = null;
    }
  }
  // REQ: FLT-004 (T24.28, ADR-992) — prune: preview the lists that add little at a threshold, turn them
  // off after a confirmation, and turn them back on from the notice that follows.
  let pruning = $state(false);
  let threshold = $state(1);
  let plan = $state<S['ListPrunePlan'] | null>(null);
  let planError = $state<unknown>(null);
  let planning = $state(false);
  let confirming = $state(false);
  let applying = $state(false);
  let pruned = $state<string[]>([]);
  let restoring = $state(false);
  const prunable = $derived(lists.filter((l) => l.enabled && l.kind === 'block').length >= 2);
  const thresholdOk = $derived(Number.isFinite(threshold) && threshold >= 0 && threshold <= 50);
  async function preview() {
    if (!thresholdOk) return;
    planning = true;
    confirming = false;
    planError = null;
    try {
      plan = await api.listPrunePlan(threshold);
    } catch (e) {
      planError = e;
      plan = null;
    } finally {
      planning = false;
    }
  }
  function openPrune() {
    pruning = true;
    void preview();
  }
  function closePrune() {
    pruning = false;
    confirming = false;
    plan = null;
    planError = null;
  }
  async function applyPrune() {
    if (!plan || plan.candidates.length === 0) return;
    applying = true;
    planError = null;
    try {
      // The lists previewed, with the versions the preview was read at: a plan that changed since (a
      // list edited, another compile) is refused (409) and changes nothing.
      const r = await api.pruneLists({
        thresholdPercent: plan.thresholdPercent,
        names: plan.candidates.map((c) => c.name),
        snapshotVersion: plan.snapshotVersion,
        configVersion: plan.configVersion,
      });
      pruned = r.disabled;
      closePrune();
      ({ items: lists, missingNodes: unread = [] } = await api.lists());
    } catch (e) {
      planError = e;
      confirming = false;
    } finally {
      applying = false;
    }
  }
  // Undo: each list is written back with `enabled: true` (the same edit as turning it on in Manage lists).
  async function restorePruned() {
    restoring = true;
    planError = null;
    try {
      const entries = (await api.configEntries('list')).items;
      for (const name of pruned) {
        const def = entries.find((e) => e.name === name)?.definition;
        if (def) await api.putEntry('lists', name, { ...(def as Record<string, unknown>), enabled: true });
      }
      pruned = [];
      ({ items: lists, missingNodes: unread = [] } = await api.lists());
    } catch (e) {
      planError = e;
    } finally {
      restoring = false;
    }
  }
  const shownLists = $derived(only === 'categories' ? lists.filter((l) => (l.owners ?? []).length) : lists);
  // REQ: FLT-901 - a category list can be put in shadow mode and back (the one thing a person sets on it).
  async function setShadow(l: S['ListInfo']) {
    await fix(l.name, `${l.name} is now ${l.mode === 'shadow' ? 'enforcing' : 'in shadow mode: it counts what it would block and blocks nothing'}.`, async () => {
      await api.putEntry('lists', l.name, { mode: l.mode === 'shadow' ? 'enforce' : 'shadow' });
    });
  }
  const addsPercent = (l: S['ListInfo']) => (l.entries > 0 ? Math.round(((l.unique + (l.rules ?? 0)) / l.entries) * 1000) / 10 : 0);
  const pct = (n: number) => `${n}%`;
  // While lists download, check every 2 s instead of every 15 s.
  $effect(() => {
    if (!busy) return;
    const t = setInterval(async () => {
      try {
        ({ items: lists, missingNodes: unread = [] } = await api.lists());
      } catch {
        // the 15 s poll reports errors
      }
    }, 2000);
    return () => clearInterval(t);
  });
  // REQ: T24.27 — fixes offered on a list row: raise a list's size limit, turn off or remove a list
  // that failed for good (404) or adds nothing (every name is in another list).
  let fixing = $state<string | null>(null);
  let fixError = $state<unknown>(null);
  let fixNote = $state<string | null>(null);
  let confirmRemove = $state<string | null>(null);
  async function definitionOf(name: string): Promise<Record<string, unknown>> {
    const e = (await api.configEntries('list')).items.find((x) => x.name === name);
    if (!e?.definition) throw new Error(`The list ${name} isn't in this node's configuration.`);
    const { name: _n, ...def } = e.definition as Record<string, unknown>;
    return def;
  }
  async function fix(name: string, note: string, change: () => Promise<unknown>) {
    fixing = name;
    fixError = null;
    fixNote = null;
    confirmRemove = null;
    try {
      await change();
      fixNote = note;
      ({ items: lists, missingNodes: unread = [] } = await api.lists());
    } catch (e) {
      fixError = e;
    } finally {
      fixing = null;
    }
  }
  // Sets this list's own `max_bytes`, then downloads it again.
  const raiseLimit = (name: string, mib: number) =>
    fix(name, `${name}: the limit is now ${mib} MiB and the list is downloading again.`, async () => {
      const def = await definitionOf(name);
      await api.putEntry('lists', name, { ...def, max_bytes: `${mib}MiB` });
      await api.refreshLists([name]);
    });
  const turnOff = (name: string) =>
    fix(name, `${name} is off. It stays in the configuration; turn it on from Manage lists.`, async () => {
      const def = await definitionOf(name);
      await api.putEntry('lists', name, { ...def, enabled: false });
    });
  const removeList = (name: string) =>
    fix(name, `${name} was removed.`, () => api.deleteEntry('lists', name));
  // Every name in it is also in another list: it adds nothing, so it can go.
  // Only when ONE enabled, enforcing list of the same kind holds every name (a shadow or allow list
  // covering a block list is not redundant). Identical lists: only the later-sorting one is offered.
  const redundantWith = (l: S['ListInfo']): string | null => {
    if (!(l.enabled && l.state === 'ok' && l.entries > 0 && l.unique === 0 && l.overlap.length)) return null;
    const top = l.overlap[0];
    if (top.names !== l.entries) return null;
    const cover = lists.find((x) => x.name === top.list);
    if (!cover || !cover.enabled || cover.state !== 'ok' || cover.mode !== 'enforce' || cover.kind !== l.kind) return null;
    if (cover.unique === 0 && cover.entries === l.entries && cover.name > l.name) return null;
    return cover.name;
  };

  // REQ: API-002 (T9.12) — download and parse the draft list before saving it.
  const tryList = {
    label: 'Test it',
    run: async (b: Record<string, unknown>) => {
      const r = await api.checkList(b);
      const notes = r.warnings.length ? ` Lines it can't use: ${r.warnings.slice(0, 3).join('; ')}` : '';
      return r.ok
        ? { ok: true, text: `Works: ${r.detail}, in ${r.elapsedMs} ms.${notes}` }
        : { ok: false, text: `Doesn't work: ${r.error ?? r.detail}.${notes}` };
    },
  };
</script>

{#snippet removeButtons(name: string)}
  {#if confirmRemove === name}
    <button class="link small danger" disabled={fixing !== null} data-testid="list-remove-confirm" onclick={() => removeList(name)}>Yes, remove {name}</button>
    <button class="link small" onclick={() => (confirmRemove = null)}>Keep it</button>
  {:else}
    <button class="link small danger" disabled={fixing !== null} data-testid="list-remove" onclick={() => (confirmRemove = name)}>Remove it</button>
  {/if}
{/snippet}

<div class="page">
  <div class="page-head">
    <h1>Lists<HelpButton id="lists" /></h1>
    <div class="head-side">
      {#if info}
        <span class="muted">
          {num(info.filterNames)} blocked names in snapshot {info.filterSnapshot ?? '–'}
        </span>
      {/if}
      {#if can('operator') && lists.some((l) => l.enabled)}
        <!-- REQ: FLT-004 — download every enabled list again now. -->
        <button class="update" onclick={updateNow} disabled={busy} data-testid="lists-update-now"
          title="Download every enabled list again now instead of waiting for its schedule">
          {busy ? 'Updating…' : 'Update now'}
        </button><HelpButton id="list-update-now" />
      {/if}
      {#if can('operator') && prunable}
        <!-- REQ: FLT-004 (T24.28) — find the lists that add little, and turn them off. -->
        <button class="prune" onclick={openPrune} disabled={pruning} data-testid="lists-prune"
          title="Find lists that add little because other lists already have their names">Prune…</button><HelpButton id="list-prune" />
      {/if}
    </div>
  </div>
  <Tabs {tabs} active={tab} label="Lists" />
  <TabPanel active={tab}>
  {#if tab === 'categories'}
    <ErrorNote error={catError} />
    {#if catView}
      <section class="card">
        <h2>Categories<HelpButton id="categories" /></h2>
        <p class="muted small">
          Categories group the lists you can turn on for a profile: adult content, gambling, threats and more. Each is backed by an
          open list its maintainer publishes, downloaded once and shared by every profile that uses it. This is the catalog; choose
          categories in a profile.
        </p>
        <Categories view={catView} selected={inUse} readonly showAds />
        {#if can('operator')}
          <p><button type="button" data-testid="cat-use-in-profile" onclick={() => navigate('/groups', { new: '1' })}>Use in a profile</button></p>
        {/if}
      </section>
    {:else if !catError}
      <p class="empty muted">Loading…</p>
    {/if}
  {:else}
  <ErrorNote {error} />
  <ErrorNote error={refreshError} />
  <ErrorNote error={fixError} />
  {#if fixNote}<div class="notice" role="status" data-testid="list-fix-note">{fixNote}</div>{/if}
  {#if unread.length}
    {#if primaryUnread}
      <div class="notice warn" role="status" data-testid="lists-unread">Not read: {unread.join(', ')}. The download state shown isn't confirmed from the primary until it answers.</div>
    {:else}
      <div class="notice warn" role="status" data-testid="lists-unread">Hits leave out: {unread.join(', ')}.</div>
    {/if}
  {/if}
  {#if refresh || starting || startingRow || lastUpdated || lists.some((l) => l.enabled && l.source !== 'inline')}
    <p class="small muted refresh-status" data-testid="lists-refresh-status" aria-live="polite">
      {#if startingRow}
        Downloading {startingRow}…
      {:else if starting}
        Downloading every enabled list…
      {:else if updating && refresh}
        Downloading {refresh.queued.length} {refresh.queued.length === 1 ? 'list' : 'lists'}{refresh.node ? ` on ${refresh.node}` : ''}…
      {:else if refresh && refresh.queued.length === 0}
        {refresh.note}
      {:else if refresh && failed.length}
        <span class="err" data-testid="lists-refresh-failed">{failed.length} of {refresh.queued.length} {refresh.queued.length === 1 ? 'list' : 'lists'} failed to download{refresh.node ? ` on ${refresh.node}` : ''}: {failed.map((l) => `${l.name} (${l.error ?? 'failed'})`).join('; ')}.</span>
        They keep their last good copy.
      {:else if refresh && !wholeSet}
        {refresh.queued.join(', ')} updated{refresh.node ? ` on ${refresh.node}` : ''}. Unchanged lists keep their copy; the snapshot follows within seconds if anything changed.
      {:else if refresh}
        Lists updated{refresh.node ? ` on ${refresh.node}` : ''}: {lastUpdated ? `every enabled list confirmed current ${ago(lastUpdated)} or later` : 'some lists have never downloaded'}. Unchanged lists keep their copy; the snapshot follows within seconds if anything changed.
      {:else if lastUpdated}
        Every enabled list confirmed current {ago(lastUpdated)} or later.
      {:else}
        Some enabled lists have never downloaded.
      {/if}
      {#if refresh?.skipped.length}<span> Left out (off): {refresh.skipped.map((k) => k.name).join(', ')}.</span>{/if}
    </p>
  {/if}
  <ErrorNote error={planError} />
  {#if pruned.length}
    <div class="notice ok" role="status" data-testid="prune-done">
      {pruned.length} {pruned.length === 1 ? 'list' : 'lists'} turned off: {pruned.join(', ')}. They stay in the configuration.
      {#if can('operator')}
        <button onclick={restorePruned} disabled={restoring} data-testid="prune-undo">{restoring ? 'Turning on…' : 'Undo: turn them on again'}</button>
      {/if}
      <button onclick={() => (pruned = [])} data-testid="prune-dismiss">Dismiss</button>
    </div>
  {/if}
  {#if pruning}
    <section class="card prune-panel" aria-labelledby="prune-title" data-testid="prune-panel">
      <h2 id="prune-title">Prune lists<HelpButton id="list-prune" /></h2>
      <p class="muted small">
        Turns off block lists that add little: nearly every name they hold is also in another list.
        They stay in the configuration, so turning one on again is one click. Allow lists, shadow lists and lists a group names are never proposed.
      </p>
      <div class="prune-controls">
        <label>
          Adds at most
          <input type="number" min="0" max="50" step="0.5" bind:value={threshold} data-testid="prune-threshold" onchange={preview} />
          % of its own entries
        </label>
        <button onclick={preview} disabled={planning || !thresholdOk} data-testid="prune-preview">{planning ? 'Checking…' : 'Preview'}</button>
      </div>
      {#if !thresholdOk}<p class="err small">Enter a number from 0 to 50.</p>{/if}
      {#if plan}
        {#if plan.candidates.length === 0}
          <p data-testid="prune-none">{plan.note}</p>
        {:else}
          <div class="table-wrap">
            <table class="compact" data-testid="prune-candidates">
              <thead><tr><th>List</th><th class="num">Names</th><th class="num">Unique</th><th class="num">Adds</th><th class="num">Could lose</th><th>Also in</th></tr></thead>
              <tbody>
                {#each plan.candidates as c (c.name)}
                  <tr data-testid="prune-candidate">
                    <td><strong>{c.name}</strong></td>
                    <td class="num">{num(c.entries)}</td>
                    <td class="num">{num(c.unique)}</td>
                    <td class="num">{pct(c.addsPercent)}</td>
                    <td class="num">{num(c.losesAtMost)}</td>
                    <td class="small">{c.coveredBy.map((x) => `${x.list} (${pct(x.percent)})`).join(', ')}</td>
                  </tr>
                {/each}
              </tbody>
            </table>
          </div>
          <p class="small" data-testid="prune-note">{plan.note}</p>
        {/if}
        {#if plan.kept.length}
          <details class="small">
            <summary>{plan.kept.length} {plan.kept.length === 1 ? 'list stays' : 'lists stay'}, and why</summary>
            <ul data-testid="prune-kept">
              {#each plan.kept as k (k.name)}<li><strong>{k.name}</strong>: {k.reason}</li>{/each}
            </ul>
          </details>
        {/if}
      {/if}
      <div class="prune-actions">
        {#if confirming && plan}
          <span data-testid="prune-confirm-text">Turn off {plan.candidates.length} {plan.candidates.length === 1 ? 'list' : 'lists'}?</span>
          <button onclick={applyPrune} disabled={applying} data-testid="prune-confirm">{applying ? 'Turning off…' : 'Yes, turn them off'}</button>
          <button onclick={() => (confirming = false)} disabled={applying}>Back</button>
        {:else}
          <button onclick={() => (confirming = true)} disabled={!plan || plan.candidates.length === 0 || planning} data-testid="prune-apply">
            Turn off {plan ? plan.candidates.length : 0} {plan?.candidates.length === 1 ? 'list' : 'lists'}…
          </button>
          <button onclick={closePrune} data-testid="prune-close">Close</button>
        {/if}
      </div>
    </section>
  {/if}
  {#if lists.some((l) => (l.owners ?? []).length)}
    <p class="chips" role="group" aria-label="Show lists">
      <button type="button" class="chip" class:on={only === 'all'} data-testid="lists-filter-all" aria-pressed={only === 'all'} onclick={() => (only = 'all')}>All lists</button>
      <button type="button" class="chip" class:on={only === 'categories'} data-testid="lists-filter-categories" aria-pressed={only === 'categories'} onclick={() => (only = 'categories')}>Categories</button>
    </p>
  {/if}
  <section class="card">
    {#if !loaded}
      <p class="empty muted">Loading…</p>
    {:else if lists.length === 0}
      <p class="empty">No lists are configured. Add <code>[[list]]</code> entries (URLs, files, or inline rules).</p>
    {:else}
      <div class="table-wrap">
        <table>
          <thead>
            <tr><th>List</th><th>Kind<HelpButton id="list-kind" /></th><th>State<HelpButton id="list-refresh" /></th><th class="num">Names used</th><th class="num">Unique<HelpButton id="list-overlap" /></th><th class="num">Hits</th>{#if advanced}<th class="num">Lines</th><th class="num">Size</th>{/if}<th>Checked</th><th>Changed</th><th>Confirmed current</th>{#if can('operator')}<th class="actions-head"><span class="sr-only">Actions</span></th>{/if}</tr>
          </thead>
          <tbody>
            {#each shownLists as l (l.name)}
              {@const failure = classifyListError(l.error)}
              {@const redundant = redundantWith(l)}
              <tr class:off={!l.enabled}>
                <td>
                  <strong>{l.name}</strong>{#if !l.enabled} <span class="badge">off</span>{/if}{#if l.mode === 'shadow'} <span class="badge info" title="Never blocks: what it would have blocked is counted below">shadow</span>{/if}
                  <!-- REQ: FLT-901 (T24.29) - a category list: taken from the catalog, never edited or deleted here. -->
                  {#each l.owners ?? [] as o (o.id)}<span class="badge info" data-testid="list-owner" title="This list comes from the catalog: it goes when no profile uses the category">Owned by category: {o.name}</span>{/each}
                  {#if (l.owners ?? []).length && can('operator')}
                    <button type="button" class="link small" data-testid="list-shadow-toggle" disabled={fixing !== null} onclick={() => setShadow(l)}>{l.mode === 'shadow' ? 'Enforce' : 'Shadow'}</button>
                  {/if}
                  {#if advanced}<div class="muted small src">{l.source}</div>{/if}
                  {#if l.error}<div class="small err" data-testid="list-error">{l.error}</div>{/if}
                  <!-- REQ: T24.27 — a failure says what to do about it. -->
                  {#if failure?.kind === 'too_large'}
                    <div class="small fix" data-testid="list-too-large">
                      This list is bigger than its {bytes(failure.limit)} limit{failure.seen ? ` (the server says ${bytes(failure.seen)})` : ''}; the last good copy, if any, is still used.<HelpButton id="list-too-large" />
                      {#if can('operator') && failure.suggestedMiB}
                        <button class="link small" disabled={fixing !== null} data-testid="list-raise-limit"
                          onclick={() => raiseLimit(l.name, failure.suggestedMiB!)}
                          title="Sets this list's max_bytes to {failure.suggestedMiB} MiB and downloads it again">
                          {fixing === l.name ? 'Working…' : `Raise the limit to ${failure.suggestedMiB} MiB`}
                        </button>
                      {:else if failure.suggestedMiB === null}
                        <span class="muted">It is over what a small device's memory allows for one list (128 MiB); remove it or use a smaller list.</span>
                      {/if}
                    </div>
                  {:else if failure?.kind === 'not_found'}
                    <div class="small fix" data-testid="list-not-found">
                      The address returns "not found" (HTTP {failure.status}): the list was moved or deleted by its maintainer. Remove it, or replace it with the list's new address.<HelpButton id="list-not-found" />
                      {#if can('operator')}
                        {@render removeButtons(l.name)}
                      {/if}
                    </div>
                  {/if}
                  <!-- Pruning: a list that adds nothing. -->
                  {#if redundant}
                    <div class="small fix" data-testid="list-redundant">
                      Every name in it is also in <strong>{redundant}</strong>: it adds nothing.<HelpButton id="list-redundant" />
                      {#if can('operator')}
                        <button class="link small" disabled={fixing !== null} data-testid="list-turn-off" onclick={() => turnOff(l.name)}>Turn it off</button>
                        {@render removeButtons(l.name)}
                      {/if}
                    </div>
                  {/if}
                  <!-- REQ: FLT-003 (review 02-08) — regex rules the snapshot leaves out. -->
                  {#if l.regexSkipped > 0}<div class="small warn-text" data-testid="list-regex-skipped">{num(l.regexSkipped)} regex {l.regexSkipped === 1 ? 'rule' : 'rules'} left out (over the limit of <code>max_regexes</code>, or too large to compile)</div>{/if}
                </td>
                <td><span class="badge {l.kind === 'allow' ? 'ok' : 'bad'}">{l.kind}</span></td>
                <td>
                  <StatusBadge value={l.state} />
                  {#if l.refreshing}<div class="small muted" data-testid="list-refreshing">updating…</div>{/if}
                  <!-- REQ: OBS-023 — downloads fine, but its content stopped changing. -->
                  {#if l.staleDays}<div class="small warn-text" data-testid="list-stale" title="Its source may be abandoned while still answering">unchanged for {l.staleDays} days</div>{/if}
                </td>
                <td class="num">{num(l.entries)}{#if info?.filterNames && l.kind !== 'allow'}<ShareBar value={(l.entries / info.filterNames) * 100} color="--s-blocked" label="share of the blocked names in the snapshot" />{/if}</td>
                <!-- REQ: OBS-009 (T7.14) — unique contribution, overlap, hits. -->
                <td class="num" data-testid="list-unique">
                  {num(l.unique)}
                  {#if l.enabled && l.entries > 0}
                    <!-- REQ: FLT-004 (T24.28) — what it adds, and which lists have the rest. -->
                    <div class="small muted" data-testid="list-adds" title="Unique names and regex or modifier rules, as a share of its entries">adds {pct(addsPercent(l))}</div>
                    {#if l.overlap.length}
                      <div class="small" class:warn-text={l.overlap[0].names / l.entries >= 0.95} data-testid="list-covered-by">
                        {l.overlap.slice(0, 2).map((o) => `${Math.round((o.names / l.entries) * 100)}% also in ${o.list}`).join(', ')}
                      </div>
                    {/if}
                  {/if}
                </td>
                <td class="num">{num(l.hits)}{#if l.state === 'ok' && l.entries > 0 && l.hits === 0}<div class="small muted">none yet</div>{/if}</td>
                {#if advanced}
                  <td class="num">{num(l.lines)}</td>
                  <td class="num">{bytes(l.bytes)}</td>
                {/if}
                <td class="small">{ago(l.lastCheckedUnixSeconds)}</td>
                <td class="small">{ago(l.lastChangedUnixSeconds)}</td>
                <!-- REQ: FLT-004 (T24.17) — when the list was last confirmed current (its download succeeded). -->
                <td class="small" data-testid="list-confirmed">
                  {#if l.source === 'inline'}<span class="muted" title="Inline rules have no download to confirm">inline</span>{:else if !l.enabled && !l.lastSuccessUnixSeconds}<span class="muted" title="An off list is not downloaded, so there is nothing to confirm">off</span>{:else}{ago(l.lastSuccessUnixSeconds)}{/if}
                </td>
                {#if can('operator')}
                  <!-- REQ: FLT-004 (T24.17) — download this one list now; off lists are left out by the server. -->
                  <td>
                    <button class="row-update" onclick={() => updateOne(l.name)} data-testid="list-update-now"
                      aria-label={`Update ${l.name} now`}
                      disabled={starting || startingRow !== null || l.refreshing || !l.enabled}
                      title={l.enabled ? `Download ${l.name} again now` : 'Turn the list on to update it'}>
                      {l.refreshing || startingRow === l.name ? 'Updating…' : 'Update now'}
                    </button>
                  </td>
                {/if}
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    {/if}
  </section>
  {#if shadow.length}
    <!-- REQ: OBS-018 (ADR-109) — what a list would do before it does it. -->
    <section class="card" data-testid="shadow-lists">
      <h2>Would have blocked<HelpButton id="shadow-lists" /></h2>
      {#each shadow as s (s.list)}
        <div class="shadow-list">
          <div class="row">
            <strong>{s.list}</strong>
            <span class="muted small">
              {num(s.hits)} {s.hits === 1 ? 'query' : 'queries'} from {num(s.devices)} {s.devices === 1 ? 'device' : 'devices'}{#if s.since}{' '}since {ago(Date.parse(s.since) / 1000)}{/if}{#if s.lastHitAt}{' '}· last {ago(Date.parse(s.lastHitAt) / 1000)}{/if}
            </span>
          </div>
          {#if s.topNames.length}
            <div class="small names">{#each s.topNames.slice(0, 10) as n (n.name)}<span class="name mono">{n.name} <span class="muted">{num(n.count)}</span></span>{/each}</div>
          {:else}
            <p class="muted small">Nothing yet: it hasn't matched anything your devices asked for.</p>
          {/if}
        </div>
      {/each}
      <p class="muted small">Shadow lists never block. When the names above are ones you'd want blocked, switch the list to <strong>enforce</strong>.</p>
    </section>
  {/if}
  {#if suspects.length}
    <!-- REQ: OBS-018 — blocked names someone seems to want. -->
    <section class="card" data-testid="overblocking">
      <h2>Likely over-blocking<HelpButton id="overblocking" /></h2>
      <div class="table-wrap">
        <table class="compact">
          <thead><tr><th>Name</th><th>Blocked by</th><th class="num">Allowed soon after</th><th class="num">Retry bursts</th><th class="num">Devices</th><th>Last</th></tr></thead>
          <tbody>
            {#each suspects as s (s.name)}
              <tr>
                <td class="mono">{s.name}</td>
                <td class="small">{s.lists.join(', ')}</td>
                <td class="num">{num(s.allowedAfterBlock)}</td>
                <td class="num">{num(s.retryBursts)}</td>
                <td class="num">{num(s.devices)}</td>
                <td class="small">{ago(Date.parse(s.lastSeen) / 1000)}</td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
      <p class="muted small">"Allowed soon after" counts devices that got the name within 10 minutes of a block (a pause or an allow): someone wanted it. Retry bursts are apps asking 10+ times a minute; ad libraries do that too.</p>
    </section>
  {/if}
  <FilterSettings />
  <ConfigEditor kind="list" path="lists" title="Manage lists" noun="list" fields={listFields}
    summary={(d) => `${String(d.kind ?? 'block')} · ${d.url ? String(d.url) : `${((d.rules as string[]) ?? []).length} rules`}${d.enabled === false ? ' · off' : ''}`}
    onchanged={async () => (lists = (await api.lists()).items)} formAction={tryList} />
  <p class="muted small">"Names used" counts the names this list puts in the active snapshot; "Unique" the ones no other list of its kind has (what removing it would lose), "adds" that plus its regex and modifier rules as a share of its entries, and "also in" the lists that have the rest. <strong>Prune…</strong> turns off the lists that add little, after a preview. "Hits" counts the queries it decided since each node started, across the cluster.</p>
  {/if}
  </TabPanel>
</div>

<style>
  .chips {
    display: flex;
    gap: 6px;
    margin: 0 0 8px;
  }
  .chip {
    border: 1px solid var(--border-strong);
    background: var(--surface);
    color: var(--text);
    border-radius: var(--radius-full);
    padding: 0 var(--space-3);
    cursor: pointer;
  }
  .chip.on {
    background: var(--accent);
    color: var(--accent-text);
  }
  .head-side {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 10px;
  }
  .prune-panel {
    display: grid;
    gap: 10px;
  }
  .prune-controls,
  .prune-actions {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 10px;
  }
  .prune-controls input {
    width: 5em;
  }
  .refresh-status {
    margin: 0 0 8px;
  }
  /* The hidden label is positioned inside the table's scroll box, not the page (it would widen the page). */
  .actions-head {
    position: relative;
  }
  .row-update {
    white-space: nowrap;
  }
  .src {
    word-break: break-all;
    max-width: 420px;
  }
  .err {
    color: var(--bad);
  }
  .fix {
    margin-top: 2px;
  }
  .warn-text {
    color: var(--warn);
  }
  /* A list that is off: muted text, not faded (T33.6). */
  tr.off td {
    color: var(--muted);
  }
  .shadow-list {
    display: grid;
    gap: 4px;
    margin-bottom: 12px;
  }
  .names {
    display: flex;
    flex-wrap: wrap;
    gap: 4px 12px;
  }
  .name {
    word-break: break-all;
  }
</style>
