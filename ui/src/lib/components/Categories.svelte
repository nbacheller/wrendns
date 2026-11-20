<script lang="ts">
  // REQ: FLT-901, FLT-902 (T24.29, ADR-994, ADR-995) — the Categories view: the catalog's groups with a
  // checkbox, an indeterminate state and "n of m", a row per category with an info popover and its source
  // line, heavy badges with a confirmation that states the daily download, tiers, a search with Select all
  // and Deselect all (the shared picker), a running total, the sources and their licences, and what is not
  // offered. Read-only it is a catalog browser; with `readonly` off it edits one profile's selection.
  import Picker, { type PickItem } from './Picker.svelte';
  import Drawer from './Drawer.svelte';
  import HelpButton from './HelpButton.svelte';
  import type { S } from '../api';
  import { entriesText, isHeavyNow, size, snapshotText, asBudget, type Budget } from '../categories';

  let {
    view,
    selected = $bindable([]),
    tiers = $bindable({}),
    services = $bindable([]),
    readonly = true,
    total = null,
    showAds = false,
    onchange,
  }: {
    view: S['CategoriesView'];
    /** The category IDs selected (list categories). */
    selected?: string[];
    /** The tier chosen per category. */
    tiers?: Record<string, string>;
    /** The blocked services selected (a service category turns its services on here, FLT-012). */
    services?: string[];
    readonly?: boolean;
    /** What the selection costs, from the server (null: not known yet). */
    total?: S['BudgetView'] | null;
    /** Show the Ad Block category too (the catalog browser; a profile has its own checkbox). */
    showAds?: boolean;
    onchange?: () => void;
  } = $props();

  const sources = $derived(new Map(view.sources.map((s) => [s.id, s])));
  const adsTier = $derived(view.node.adsTier);
  const visibleGroups = $derived(
    view.groups
      .map((g) => ({ ...g, categories: g.categories.filter((c) => showAds || c.tierFrom !== 'adsTier') }))
      .filter((g) => g.categories.length > 0),
  );
  const allCategories = $derived(visibleGroups.flatMap((g) => g.categories));
  const byId = $derived(new Map(allCategories.map((c) => [c.id, c])));
  const isService = (c: S['CategoryView']) => c.kind === 'service';
  const serviceOn = (c: S['CategoryView']) => c.services.length > 0 && c.services.every((s) => services.includes(s));
  const isOn = (c: S['CategoryView']) => (isService(c) ? serviceOn(c) : selected.includes(c.id));
  const tierOf = (c: S['CategoryView']) => tiers[c.id] ?? c.defaultTier ?? undefined;
  const heavyNow = (c: S['CategoryView']) => isHeavyNow(c, tierOf(c), sources, adsTier);

  // The picker (search) offers the list categories; a row or a group checkbox changes the same selection.
  const items = $derived<PickItem[]>(
    allCategories
      .filter((c) => !isService(c) && c.tierFrom !== 'adsTier')
      .map((c) => ({ value: c.id, label: c.name, secondary: view.groups.find((g) => g.categories.some((x) => x.id === c.id))?.name })),
  );
  let pickerSel = $state<string[]>([]);
  $effect(() => {
    pickerSel = [...selected];
  });

  // A heavy category asks first, with what it costs a day.
  let pending = $state<{ text: string; run: () => void } | null>(null);
  function dailyOf(ids: string[]): number {
    const seen = new Set<string>();
    let bytes = 0;
    for (const id of ids) {
      const c = byId.get(id);
      if (!c) continue;
      for (const sid of sourcesOf(c)) {
        const s = sources.get(sid);
        if (!s || seen.has(sid) || s.weight !== 'heavy') continue;
        seen.add(sid);
        bytes += s.bytes * Math.max(1, Math.floor(86_400 / s.refreshSeconds));
      }
    }
    return bytes;
  }
  function sourcesOf(c: S['CategoryView']): string[] {
    return [...c.sources, ...(c.tiers.find((t) => t.id === tierOf(c))?.sources ?? [])];
  }
  function apply(next: string[]) {
    selected = next;
    pickerSel = [...next];
    onchange?.();
  }
  function request(add: string[], keep: string[]) {
    const heavy = add.filter((id) => {
      const c = byId.get(id);
      return c && heavyNow(c);
    });
    if (heavy.length === 0) {
      apply([...keep, ...add]);
      return;
    }
    const names = heavy.map((id) => byId.get(id)?.name ?? id).join(', ');
    const entries = heavy.reduce((n, id) => n + (byId.get(id)?.entries ?? 0), 0);
    pending = {
      text: `${names}: about ${entriesText(entries)} entries (${snapshotText(entries)} in memory) and about ${size(dailyOf(heavy))} to download every day. Keep it on a node with the memory for it.`,
      run: () => apply([...keep, ...add]),
    };
  }
  function toggle(c: S['CategoryView']) {
    if (readonly) return;
    if (isService(c)) {
      const mine = new Set(c.services);
      services = serviceOn(c) ? services.filter((s) => !mine.has(s)) : [...new Set([...services, ...c.services])];
      onchange?.();
      return;
    }
    if (selected.includes(c.id)) apply(selected.filter((x) => x !== c.id));
    else request([c.id], selected);
  }
  function fromPicker(next: string[]) {
    if (readonly) return;
    const added = next.filter((x) => !selected.includes(x));
    const kept = next.filter((x) => selected.includes(x));
    if (added.length === 0) apply(kept);
    else request(added, kept);
    // The picker shows the real selection again (a confirmation may keep it as it was).
    pickerSel = [...selected];
  }
  function groupState(g: { categories: S['CategoryView'][] }): { on: number; of: number } {
    return { on: g.categories.filter(isOn).length, of: g.categories.length };
  }
  function toggleGroup(g: { categories: S['CategoryView'][] }) {
    if (readonly) return;
    const st = groupState(g);
    if (st.on === st.of) {
      // Everything on: clear the group.
      const list = g.categories.filter((c) => !isService(c)).map((c) => c.id);
      const mine = new Set(g.categories.filter(isService).flatMap((c) => c.services));
      services = services.filter((s) => !mine.has(s));
      apply(selected.filter((x) => !list.includes(x)));
      return;
    }
    const svc = g.categories.filter((c) => isService(c) && !serviceOn(c));
    if (svc.length) services = [...new Set([...services, ...svc.flatMap((c) => c.services)])];
    const add = g.categories.filter((c) => !isService(c) && !selected.includes(c.id)).map((c) => c.id);
    if (add.length) request(add, selected);
    else onchange?.();
  }
  function setTier(c: S['CategoryView'], id: string) {
    if (readonly) return;
    const set = () => {
      const next = { ...tiers };
      if (c.tierKind === 'additive' && id === '') delete next[c.id];
      else next[c.id] = id;
      tiers = next;
      onchange?.();
    };
    const picked = c.tiers.find((t) => t.id === id)?.sources ?? [];
    const heavy = picked.filter((sid) => sources.get(sid)?.weight === 'heavy');
    if (heavy.length && selected.includes(c.id) && !heavyNow(c)) {
      const entries = heavy.reduce((n, sid) => n + (sources.get(sid)?.entries ?? 0), 0);
      const daily = heavy.reduce((n, sid) => {
        const s = sources.get(sid);
        return n + (s ? s.bytes * Math.max(1, Math.floor(86_400 / s.refreshSeconds)) : 0);
      }, 0);
      pending = {
        text: `${c.name} at this size: about ${entriesText(entries)} entries (${snapshotText(entries)} in memory) and about ${size(daily)} to download every day.`,
        run: set,
      };
    } else set();
  }

  // REQ: FLT-004 (T24.28, ADR-992) — how much of a downloaded source the lists already in use cover.
  const overlapText = (s: S['SourceView']): string => {
    if (!s.state.downloaded || s.state.snapshotEntries === 0) return `${entriesText(s.entries)} entries; not downloaded yet, so its overlap with your lists is not known`;
    const shared = s.state.snapshotEntries - s.state.uniqueEntries;
    const where = s.state.alsoIn.map((o) => o.list).join(', ');
    return `${entriesText(s.state.snapshotEntries)} entries, ${entriesText(shared)} also in the lists you already use${where ? ` (${where})` : ''}`;
  };
  let open = $state<string | null>(null);
  let licences = $state(false);
  const totals = $derived(total ? asBudget(total.total) : (asBudget(view.total) as Budget));
</script>

{#snippet sourceLine(c: S['CategoryView'])}
  {@const used = sourcesOf(c)
    .map((id) => sources.get(id))
    .filter((s): s is S['SourceView'] => !!s)}
  {#if used.length}
    <button type="button" class="link small cat-source" data-testid="cat-source" onclick={() => (licences = true)}>
      {used.slice(0, 2).map((s) => `${s.name}, ${s.licence}`).join(' · ')}{used.length > 2 ? ` · +${used.length - 2}` : ''}
    </button>
  {/if}
{/snippet}

<div class="cats" data-testid="categories-view">
  <div class="top">
    <div class="search">
      <Picker
        label="Search categories"
        placeholder="Search categories…"
        {items}
        bind:selected={pickerSel}
        onchange={fromPicker}
        disabled={readonly}
        maxChips={2}
        testid="cat-search"
      />
    </div>
    <button type="button" class="link small" data-testid="cat-licences-open" onclick={() => (licences = true)}>Sources and licences</button>
    <HelpButton id="category-sources" />
    <HelpButton id="categories" />
  </div>

  {#if pending}
    <div class="notice warn" role="alertdialog" aria-label="Heavy selection" data-testid="cat-heavy-confirm">
      <strong>Heavy:</strong> {pending.text}
      <div class="row">
        <button type="button" data-testid="cat-heavy-yes" onclick={() => { pending?.run(); pending = null; }}>Yes, use it</button>
        <button type="button" data-testid="cat-heavy-no" onclick={() => (pending = null)}>No</button>
      </div>
    </div>
  {/if}

  {#each visibleGroups as g (g.id)}
    {@const st = groupState(g)}
    <section class="cgroup" data-testid="cat-group" data-group={g.id}>
      <header>
        <label class="gcheck">
          <input
            type="checkbox"
            data-testid="cat-group-check"
            aria-label={`Select every category in ${g.name}`}
            checked={st.on === st.of}
            indeterminate={st.on > 0 && st.on < st.of}
            disabled={readonly}
            onchange={(e) => { toggleGroup(g); e.currentTarget.checked = groupState(g).on === groupState(g).of; }}
          />
          <strong>{g.name}</strong>
        </label>
        <span class="muted small" data-testid="cat-group-count">{st.on} of {st.of}</span>
      </header>
      <ul>
        {#each g.categories as c (c.id)}
          <li data-testid="cat-row" data-category={c.id}>
            <div class="line">
              <label class="rcheck">
                <input type="checkbox" data-testid="cat-check" checked={isOn(c)} disabled={readonly} onchange={(e) => { toggle(c); e.currentTarget.checked = isOn(c); }} />
                <span>{c.name}</span>
              </label>
              {#if isService(c)}<span class="badge info" title="A hand-written bundle of a service's domains: it turns on Blocked services">Services</span>{/if}
              {#if heavyNow(c)}<span class="badge warn" data-testid="cat-heavy" title="Over the default budget on its own">Heavy: {snapshotText(c.entries)}</span>{/if}
              <button
                type="button"
                class="info"
                data-testid="cat-info"
                aria-label={`About ${c.name}`}
                aria-expanded={open === c.id}
                onclick={() => (open = open === c.id ? null : c.id)}>i</button>
            </div>
            {#if c.tiers.length && c.tierFrom !== 'adsTier'}
              <div class="tiers" role="radiogroup" aria-label={`Size of ${c.name}`} data-testid="cat-tier">
                {#if c.tierKind === 'additive'}
                  <button type="button" role="radio" aria-checked={!tiers[c.id]} class:on={!tiers[c.id]} disabled={readonly} onclick={() => setTier(c, '')}>Standard</button>
                {/if}
                {#each c.tiers as t (t.id)}
                  <button type="button" role="radio" aria-checked={tierOf(c) === t.id && (c.tierKind !== 'additive' || !!tiers[c.id])} class:on={tierOf(c) === t.id && (c.tierKind !== 'additive' || !!tiers[c.id])} disabled={readonly} onclick={() => setTier(c, t.id)}>{t.name}</button>
                {/each}
              </div>
            {/if}
            {@render sourceLine(c)}
            {#if open === c.id}
              <div class="pop" role="note" data-testid="cat-popover">
                <p>{c.description}</p>
                {#if !isService(c)}
                  <p class="muted small">{entriesText(c.entries)} entries by default ({snapshotText(c.entries)} in memory){c.heavy ? '; a larger size is heavy' : ''}.</p>
                {:else}
                  <p class="muted small">Turns on these services: {c.services.join(', ')}.</p>
                {/if}
                {#each sourcesOf(c).map((id) => sources.get(id)).filter((s) => !!s) as s (s.id)}
                  <p class="small" data-testid="cat-overlap" data-source={s.id}>{s.name}: {overlapText(s)}.</p>
                {/each}
                {#if c.warn}<p class="notice warn small">{c.warn}</p>{/if}
              </div>
            {/if}
          </li>
        {/each}
      </ul>
    </section>
  {/each}

  <div class="total" data-testid="cat-total" aria-live="polite">
    Selected: {entriesText(totals.entries)} entries, {snapshotText(totals.entries)}, budget {entriesText(totals.entryBudget)}
    {#if totals.overBudget}<span class="badge warn" data-testid="cat-over-budget">over the entry budget</span>{/if}
    {#if totals.refused}<span class="badge bad" data-testid="cat-refused">too big for this node</span>{/if}
    <span class="bar" aria-hidden="true"><span style:width={`${Math.min(100, (totals.entries / Math.max(1, totals.entryBudget)) * 100)}%`}></span></span>
    <HelpButton id="category-budget" />
    {#if totals.reasons.length}<div class="small muted">{totals.reasons[0]}</div>{/if}
  </div>

  <details class="na" data-testid="cat-not-available">
    <summary>Not available ({view.notOffered.length})</summary>
    <p class="muted small">No category is offered without an open, maintained, licensed list behind it. These are not offered, and why.</p>
    <ul>
      {#each view.notOffered as n (n.name)}
        <li><strong>{n.name}</strong> <span class="muted small">({n.group})</span>: {n.reason}{#if n.alternative} <span class="muted small">{n.alternative}</span>{/if}</li>
      {/each}
    </ul>
  </details>
</div>

{#if licences}
  <Drawer title="Sources and licences" onclose={() => (licences = false)}>
    <div data-testid="cat-licences">
      <p class="small muted">Lists are downloaded by this node from their maintainers while a profile uses them. Nothing is bundled or redistributed.</p>
      {#each view.attributions as a (a)}<p class="notice" data-testid="cat-attribution">{a}</p>{/each}
      <div class="table-wrap">
        <table class="compact">
          <thead><tr><th>Source</th><th>Maintainer</th><th>Licence</th><th class="num">Entries</th><th>Overlap with your lists</th><th>State</th></tr></thead>
          <tbody>
            {#each view.sources as s (s.id)}
              <tr data-testid="cat-licence-row" data-source={s.id}>
                <td><a href={s.homepage} target="_blank" rel="noreferrer">{s.name}</a></td>
                <td class="small">{s.maintainer}</td>
                <td class="small"><a href={s.licenceUrl} target="_blank" rel="noreferrer">{s.licence}</a></td>
                <td class="num">{entriesText(s.entries)}{#if s.weight === 'heavy'} <span class="badge warn">heavy</span>{/if}</td>
                <td class="small" data-testid="cat-licence-overlap">{overlapText(s)}</td>
                <td class="small">{s.state.providedBy ? `provided by list ${s.state.providedBy} (set by file)` : s.state.state}</td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    </div>
  </Drawer>
{/if}

<style>
  .cats {
    display: grid;
    gap: 12px;
  }
  .top {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 8px 12px;
  }
  .search {
    flex: 1 1 280px;
    max-width: 460px;
  }
  .cgroup {
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
    padding: 8px 12px;
  }
  .cgroup header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 10px;
  }
  .gcheck,
  .rcheck {
    display: inline-flex;
    align-items: center;
    gap: 8px;
  }
  ul {
    list-style: none;
    margin: 6px 0 0;
    padding: 0;
    display: grid;
    gap: 8px;
  }
  li {
    padding: 4px 0 4px 26px;
    border-top: 1px solid var(--border);
  }
  .line {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 8px;
  }
  .info {
    border: 1px solid var(--border);
    background: var(--surface-2);
    color: var(--muted);
    border-radius: 50%;
    width: 20px;
    height: 20px;
    padding: 0;
    font-size: 12px;
    font-style: italic;
    cursor: pointer;
  }
  .tiers {
    display: inline-flex;
    gap: 0;
    margin: 4px 0;
  }
  .tiers button {
    border: 1px solid var(--border-strong);
    background: var(--surface);
    color: var(--text);
    padding: 0 var(--space-3);
    font-size: var(--type-label-size);
    cursor: pointer;
  }
  .tiers button:first-child {
    border-radius: var(--radius-sm) 0 0 var(--radius-sm);
  }
  .tiers button:last-child {
    border-radius: 0 var(--radius-sm) var(--radius-sm) 0;
  }
  .tiers button.on {
    background: var(--accent);
    color: var(--accent-text);
  }
  .cat-source {
    display: block;
    text-align: left;
    padding: 0;
  }
  .pop {
    margin-top: 6px;
    padding: 6px 10px;
    border-radius: var(--radius-sm);
    background: var(--surface-2);
  }
  .pop p {
    margin: 4px 0;
  }
  .total {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 8px;
  }
  .bar {
    display: inline-block;
    width: 120px;
    height: 6px;
    border-radius: 3px;
    background: var(--surface-2);
    overflow: hidden;
  }
  .bar > span {
    display: block;
    height: 100%;
    background: var(--accent);
  }
  .row {
    display: flex;
    gap: 8px;
    margin-top: 6px;
  }
  .na ul {
    margin-top: 6px;
  }
  .na li {
    padding-left: 0;
    border-top: 0;
  }
</style>
