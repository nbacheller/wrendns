<script lang="ts">
  // REQ: OBS-901, API-005 (T26.3, ADR-958, ADR-970) — the network map: the gateway, networks,
  // devices, TelltaleDNS nodes, answer kinds and upstreams, coloured by health, with pulses along
  // each flow (density from the rate, width from its log). Inline SVG, laid out by `lib/map.ts`
  // (no graph library). It runs from the 2 s stream, or polls `GET /api/v1/map` when a filter that
  // the server narrows is set (the stream is unfiltered) or the stream can't be had. The tab being
  // hidden closes the stream and pauses the pulses; `prefers-reduced-motion` stops them for good and
  // the rate is written on each flow. The table view is the same data in words.
  import { untrack } from 'svelte';
  import { api, ApiError } from '../lib/api';
  import { route, navigate, href } from '../lib/router.svelte';
  import PolicyPanel from '../lib/components/PolicyPanel.svelte';
  import { poll } from '../lib/poll';
  import { num, pct } from '../lib/format';
  import ErrorNote from '../lib/components/ErrorNote.svelte';
  import HelpButton from '../lib/components/HelpButton.svelte';
  import {
    COLUMN_TITLES,
    HEALTH_ORDER,
    HEALTH_SHAPE,
    HEALTH_SHORT,
    HEALTH_WORDS,
    KIND_WORDS,
    NODE_H,
    NODE_W,
    animatedBudget,
    filterSnapshot,
    flowRows,
    hasServerFilter,
    layout,
    links,
    rate,
    serverFilters,
    summary,
    via,
    COL_GAP,
    PAD_X,
    type Filters,
    type Snapshot,
  } from '../lib/map';

  // ---- The filters live in the URL (and so can be linked).
  const filters = $derived<Filters>({
    network: route.params.get('network') ?? '',
    group: route.params.get('group') ?? '',
    device: route.params.get('device') ?? '',
    node: route.params.get('node') ?? '',
    health: (['green', 'yellow', 'red', 'idle'] as const).find((h) => h === route.params.get('health')) ?? '',
  });
  const tableView = $derived(route.params.get('view') === 'table');
  function setParams(change: Record<string, string | undefined>, replace = true) {
    const p: Record<string, string | undefined> = {};
    for (const k of ['network', 'group', 'device', 'node', 'health', 'view']) p[k] = route.params.get(k) ?? undefined;
    navigate('/map', { ...p, ...change }, replace);
  }

  // ---- The data.
  let raw = $state<Snapshot | null>(null);
  // Whether `raw` already came narrowed by the server (a polled read with filters).
  let rawNarrowed = $state(false);
  let error = $state<unknown>(null);
  let off = $state(false);
  type Mode = 'connecting' | 'live' | 'retrying' | 'polling' | 'paused' | 'off';
  let mode = $state<Mode>('connecting');
  let streamFailed = $state(false);
  let hidden = $state(typeof document !== 'undefined' && document.visibilityState === 'hidden');
  let userPaused = $state(false);
  let reduced = $state(typeof matchMedia !== 'undefined' && matchMedia('(prefers-reduced-motion: reduce)').matches);

  // Names the filter lists offer, remembered across snapshots (a narrowed read lists fewer).
  let networks = $state<{ value: string; label: string }[]>([]);
  let nodes = $state<{ value: string; label: string }[]>([]);
  let groups = $state<string[]>([]);
  let seenGroups = $state<string[]>([]);
  const groupNames = $derived([...new Set([...groups, ...seenGroups])].sort());

  function remember(s: Snapshot) {
    const nets = new Map<string, string>();
    const res = new Map<string, string>();
    const gs = new Set<string>();
    for (const n of s.nodes) {
      if (n.group) gs.add(n.group);
      if (n.kind === 'network') nets.set(n.id.replace(/^net:/, ''), n.label);
      if (n.kind === 'resolver' && n.node) res.set(n.node, n.label);
    }
    // The unfiltered snapshot is the whole picture: replace the lists (so gone entries drop and a
    // renamed label updates), assigning only when the contents differ.
    const nl = [...nets].map(([value, label]) => ({ value, label }));
    const rl = [...res].map(([value, label]) => ({ value, label }));
    const gl = [...gs];
    if (JSON.stringify(nl) !== JSON.stringify(networks)) networks = nl;
    if (JSON.stringify(rl) !== JSON.stringify(nodes)) nodes = rl;
    if (JSON.stringify(gl) !== JSON.stringify(seenGroups)) seenGroups = gl;
  }

  function accept(s: Snapshot, narrowed: boolean) {
    raw = s;
    rawNarrowed = narrowed;
    error = null;
    if (off) {
      off = false;
      mode = 'polling';
    }
    if (!narrowed) remember(s);
  }
  function failed(e: unknown) {
    if (e instanceof ApiError && e.code === 'map_disabled') {
      off = true;
      raw = null;
      error = null;
      mode = 'off';
    } else error = e;
  }
  // Only the latest request may set the data: a slow reply for an old filter is dropped.
  let seq = 0;
  async function fetchMap(f: Filters) {
    const mine = ++seq;
    try {
      const s = await api.map(serverFilters(f));
      if (mine === seq) accept(s, hasServerFilter(f));
    } catch (e) {
      if (mine === seq) failed(e);
    }
  }

  $effect(() => {
    api
      .groups()
      .then((g) => (groups = g.items.map((x) => x.name)))
      .catch(() => {});
  });

  // The motion and visibility inputs.
  $effect(() => {
    const onVis = () => {
      hidden = document.visibilityState === 'hidden';
      // A stream that failed is tried again when the tab comes back.
      if (!hidden) streamFailed = false;
    };
    document.addEventListener('visibilitychange', onVis);
    const mq = matchMedia('(prefers-reduced-motion: reduce)');
    const onMq = () => (reduced = mq.matches);
    mq.addEventListener('change', onMq);
    return () => {
      document.removeEventListener('visibilitychange', onVis);
      mq.removeEventListener('change', onMq);
    };
  });

  // The stream (unfiltered), or polling (a server filter is set, or the stream can't be had).
  $effect(() => {
    const f = filters;
    const server = hasServerFilter(f);
    if (hidden) {
      mode = 'paused';
      return;
    }
    if (server || streamFailed) {
      mode = 'polling';
      const stop = poll(() => fetchMap(f), 2000);
      // After a stream failure, try the stream again in a while.
      const retry = streamFailed && !server ? setTimeout(() => (streamFailed = false), 30000) : undefined;
      return () => {
        seq++;
        clearTimeout(retry);
        stop();
      };
    }
    mode = 'connecting';
    void fetchMap(f);
    const es = new EventSource('/api/v1/map/stream');
    let errors = 0;
    es.addEventListener('snapshot', (m) => {
      try {
        const frame = JSON.parse((m as MessageEvent).data) as Snapshot;
        seq++; // a slower initial fetch must not overwrite this newer frame
        accept(frame, false);
        mode = 'live';
        errors = 0;
      } catch {
        // A frame that doesn't parse is skipped; the next one replaces it.
      }
    });
    es.addEventListener('map_disabled', () => {
      off = true;
      raw = null;
      mode = 'off';
      es.close();
      // Poll until the map is turned on again, then the stream is tried once more.
      streamFailed = true;
    });
    es.onerror = () => {
      errors++;
      // A refusal (a busy node, a missing scope) closes the stream for good: poll instead.
      if (es.readyState === EventSource.CLOSED || errors >= 3) {
        es.close();
        streamFailed = true;
      } else mode = 'retrying';
    };
    return () => {
      seq++;
      es.close();
    };
  });

  // ---- What is drawn.
  const snap = $derived<Snapshot | null>(raw ? (rawNarrowed ? filterSnapshot(raw, { ...filters, network: '', group: '', device: '', node: '' }) : filterSnapshot(raw, filters)) : null);
  const cores = typeof navigator !== 'undefined' ? navigator.hardwareConcurrency : undefined;
  const lay = $derived(snap ? layout(snap, { maxAnimated: animatedBudget(cores) }) : null);
  const rows = $derived(snap ? flowRows(snap) : []);
  const motion = $derived(!reduced && !userPaused && !hidden);
  let selected = $state<string | null>(null);
  const sel = $derived(selected ? (snap?.nodes.find((n) => n.id === selected) ?? null) : null);
  const selEdges = $derived(sel && snap ? snap.edges.filter((e) => (e.from === sel.id || e.to === sel.id) && !e.structural) : []);
  const labelOf = (id: string) => snap?.nodes.find((n) => n.id === id)?.label ?? id;
  const recent = $derived(sel?.kind === 'device' ? selEdges.flatMap((e) => e.recent ?? []).sort((a, b) => b.tsUnixMicros - a.tsUnixMicros).slice(0, 5) : []);

  const trunc = (s: string, n: number) => (s.length > n ? `${s.slice(0, n - 1)}…` : s);
  function pick(id: string) {
    selected = id;
  }
  function keyPick(e: KeyboardEvent, id: string) {
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      pick(id);
    }
  }
  const stateWords: Record<Mode, string> = {
    connecting: 'Connecting',
    live: 'Live, every 2 seconds',
    retrying: 'Reconnecting',
    polling: 'Updating every 2 seconds',
    paused: 'Paused: this tab is hidden',
    off: 'Turned off on this node',
  };

  let deviceText = $state(route.params.get('device') ?? '');
  let typing: ReturnType<typeof setTimeout> | undefined;
  // The box follows the URL (back/forward, "Clear filters" from elsewhere).
  $effect(() => {
    const d = filters.device;
    if (untrack(() => deviceText.trim()) !== d) deviceText = d;
  });
  $effect(() => () => clearTimeout(typing));
  function typed() {
    clearTimeout(typing);
    typing = setTimeout(() => setParams({ device: deviceText.trim() || undefined }), 300);
  }
  const anyFilter = $derived(!!(filters.network || filters.group || filters.device || filters.node || filters.health));
  function clear() {
    deviceText = '';
    setParams({ network: undefined, group: undefined, device: undefined, node: undefined, health: undefined });
  }
</script>

<div class="page mappage">
  <div class="page-head">
    <h1>Network map<HelpButton id="network-map" /></h1>
    <div class="row">
      <a class="small" href="#/settings?tab=queries" data-testid="map-settings-link">Map settings</a>
      <span class="small muted" data-testid="map-state" data-stream={mode} role="status">{stateWords[mode]}</span>
      <div class="seg" role="group" aria-label="View">
        <button type="button" aria-pressed={!tableView} onclick={() => setParams({ view: undefined })} data-testid="view-map">Map</button>
        <button type="button" aria-pressed={tableView} onclick={() => setParams({ view: 'table' })} data-testid="view-table">Table</button>
      </div>
      {#if !reduced}
        <button type="button" class="small" aria-pressed={userPaused} onclick={() => (userPaused = !userPaused)} data-testid="pause-motion">{userPaused ? 'Resume motion' : 'Pause motion'}</button>
      {/if}
    </div>
  </div>

  <form class="row filters" onsubmit={(e) => e.preventDefault()} aria-label="Map filters">
    <label class="pill-field">
      Network
      <select value={filters.network} onchange={(e) => setParams({ network: e.currentTarget.value || undefined })} data-testid="filter-network">
        <option value="">all</option>
        {#each networks as n (n.value)}<option value={n.value}>{n.label}</option>{/each}
        {#if filters.network && !networks.some((n) => n.value === filters.network)}<option value={filters.network}>{filters.network}</option>{/if}
      </select>
    </label>
    <label class="pill-field">
      Group
      <select value={filters.group} onchange={(e) => setParams({ group: e.currentTarget.value || undefined })} data-testid="filter-group">
        <option value="">all</option>
        {#each groupNames as g (g)}<option value={g}>{g}</option>{/each}
        {#if filters.group && !groupNames.includes(filters.group)}<option value={filters.group}>{filters.group}</option>{/if}
      </select>
    </label>
    <label class="pill-field">
      Node
      <select value={filters.node} onchange={(e) => setParams({ node: e.currentTarget.value || undefined })} data-testid="filter-node">
        <option value="">all</option>
        {#each nodes as n (n.value)}<option value={n.value}>{n.label}</option>{/each}
        {#if filters.node && !nodes.some((n) => n.value === filters.node)}<option value={filters.node}>{filters.node}</option>{/if}
      </select>
    </label>
    <label class="pill-field">
      State
      <select value={filters.health} onchange={(e) => setParams({ health: e.currentTarget.value || undefined })} data-testid="filter-health">
        <option value="">all</option>
        {#each HEALTH_ORDER as h (h)}<option value={h}>{HEALTH_SHORT[h]}</option>{/each}
      </select>
    </label>
    <label class="pill-field">
      Device
      <input type="search" bind:value={deviceText} oninput={typed} placeholder="name or address" aria-label="Device name or address" data-testid="filter-device" />
    </label>
    {#if anyFilter}<button type="button" class="small" onclick={clear} data-testid="filter-clear">Clear filters</button>{/if}
  </form>

  <ErrorNote {error} />

  {#if off}
    <p class="notice warn" data-testid="map-off">The network map is turned off on this node (<code>[map] enabled = false</code>), so there is nothing to draw.</p>
  {:else if snap}
    {#if snap.sampleRate > 1 || snap.dropped > 0}
      <p class="notice small" data-testid="banner-sampled">
        Sampled, 1 in {num(Math.max(1, snap.sampleRate))} lookups: the rates are estimates{snap.dropped > 0 ? ` (${num(snap.dropped)} lookups were dropped under load and are counted in)` : ''}.
      </p>
    {/if}
    {#if snap.partial}
      <p class="notice warn small" data-testid="banner-partial">
        Partial: {snap.missingNodes.length ? snap.missingNodes.join(', ') : 'a node'} didn't answer in time, so its part of the map is missing or out of date.
      </p>
    {/if}
    {#if snap.truncated}
      <p class="notice small" data-testid="banner-truncated">Only the busiest devices are drawn; the rest are folded into "+N more" under their network.</p>
    {/if}
    {#if snap.privacy >= 2}
      <p class="notice small" data-testid="banner-privacy">
        {snap.privacy >= 3 ? 'Privacy level 3: only network and resolver totals are kept, so no device is drawn.' : `Privacy level ${snap.privacy}: devices are hidden, so the map shows one "devices hidden by privacy" node and the flows of each resolver.`}
      </p>
    {/if}

    <div class="mapgrid">
      <section class="card mapcard" aria-label="Network map">
        {#if snap.nodes.length === 0}
          <p class="empty" data-testid="map-empty">{anyFilter ? 'Nothing matches these filters.' : 'Nothing to show yet: no lookups have been sampled.'}</p>
        {:else if !tableView && lay}
          <figure class="mapfig" role="group" aria-label="Network map" aria-describedby="map-summary" data-testid="map-figure" data-motion={motion ? 'on' : 'off'}>
            <figcaption id="map-summary" class="small muted" data-testid="map-summary">{summary(snap)} Use Tab to move between nodes and Enter to open one, or switch to the table.</figcaption>
            <div class="mapscroll">
              <svg viewBox="0 0 {lay.width} {lay.height}" width={lay.width} height={lay.height} class:paused={!motion} class:still={reduced} focusable="false">
                {#each COLUMN_TITLES as t, i (t)}
                  <text class="coltitle" x={PAD_X + i * COL_GAP} y="14">{t}</text>
                {/each}
                <g class="edges">
                  {#each lay.edges as e (e.id)}
                    <path class="track {e.edge.health}" class:structural={e.structural} d={e.d} data-edge={e.id} data-flow={e.structural ? undefined : ''} />
                    {#if e.pulse}
                      <path
                        class="pulse {e.edge.health}"
                        class:run={e.animated && !reduced}
                        d={e.d}
                        pathLength="100"
                        stroke-width={e.pulse.width}
                        stroke-dasharray="{e.pulse.dash} {e.pulse.gap}"
                        style:--period={e.pulse.dash + e.pulse.gap}
                        style:--secs="{e.pulse.seconds}s"
                        style:--delay="{e.pulse.delay}s"
                        data-pulse={e.id}
                      />
                      {#if reduced}<text class="ratelabel" x={e.mx} y={e.my - 3} text-anchor="middle" data-testid="rate-label">{rate(e.edge.qps)}</text>{/if}
                    {/if}
                  {/each}
                </g>
                <g class="nodes">
                  {#each lay.nodes as p (p.node.id)}
                    <g
                      class="node {p.node.health} k-{p.node.kind}"
                      class:selected={selected === p.node.id}
                      transform="translate({p.x} {p.y})"
                      role="button"
                      tabindex="0"
                      aria-label={p.label}
                      aria-pressed={selected === p.node.id}
                      data-node={p.node.id}
                      data-kind={p.node.kind}
                      data-health={p.node.health}
                      onclick={() => pick(p.node.id)}
                      onkeydown={(e) => keyPick(e, p.node.id)}
                    >
                      {#if p.node.reasons.length}<title>{p.node.label}: {p.node.reasons.map((r) => r.summary).join('; ')}</title>{/if}
                      <rect width={NODE_W} height={NODE_H} rx="8" />
                      <path class="shape" d={HEALTH_SHAPE[p.node.health]} transform="translate(15 {NODE_H / 2})" />
                      <text class="nlabel" x="30" y="13">{trunc(p.node.label, 19)}</text>
                      <text class="nstate" x="30" y="25">{HEALTH_SHORT[p.node.health]}{p.node.kind === 'gateway' || p.node.kind === 'network' ? '' : ` · ${rate(p.node.qps)}`}</text>
                    </g>
                  {/each}
                </g>
              </svg>
            </div>
          </figure>
        {:else}
          <div data-testid="map-table">
            <h2 class="tabletitle">Flows</h2>
            <div class="tablewrap">
              <table aria-label="Flows">
                <thead><tr><th scope="col">From</th><th scope="col">To</th><th scope="col" class="num">Per second</th><th scope="col" class="num">Slow</th><th scope="col" class="num">Failing</th><th scope="col">State</th></tr></thead>
                <tbody>
                  {#each rows as r (r.id)}
                    <tr data-flow-row={r.id}>
                      <td>{r.from}</td><td>{r.to}</td><td class="num">{rate(r.qps)}</td><td class="num">{pct(r.slowPct, 0)}</td><td class="num">{pct(r.errPct, 0)}</td>
                      <td>{HEALTH_WORDS[r.health]}</td>
                    </tr>
                  {:else}
                    <tr><td colspan="6" class="muted">No flows with a rate in the window.</td></tr>
                  {/each}
                </tbody>
              </table>
            </div>
            <h2 class="tabletitle">Nodes</h2>
            <div class="tablewrap">
              <table aria-label="Nodes">
                <thead><tr><th scope="col">Node</th><th scope="col">Kind</th><th scope="col">State</th><th scope="col">Why</th><th scope="col" class="num">Per second</th></tr></thead>
                <tbody>
                  {#each snap.nodes as n (n.id)}
                    <tr data-node-row={n.id}>
                      <td><button type="button" class="link" onclick={() => pick(n.id)}>{n.label}</button></td>
                      <td>{KIND_WORDS[n.kind]}</td><td>{HEALTH_WORDS[n.health]}</td>
                      <td class="small">{n.reasons.map((r) => r.summary).join('; ')}</td>
                      <td class="num">{n.kind === 'gateway' || n.kind === 'network' ? '' : rate(n.qps)}</td>
                    </tr>
                  {/each}
                </tbody>
              </table>
            </div>
          </div>
        {/if}
        <p class="legend small muted" aria-label="Legend">
          {#each HEALTH_ORDER as h (h)}
            <span class="lg {h}" data-testid="legend-item"><svg class="hicon" width="16" height="16" viewBox="-9 -9 18 18" aria-hidden="true"><path d={HEALTH_SHAPE[h]} /></svg>{HEALTH_SHORT[h]}</span>
          {/each}
          <span>Wider and denser pulses mean more lookups a second. {Math.round(snap.windowSecs)}-second window.</span>
        </p>
      </section>

      {#if selected}
        <aside class="card nodepanel" aria-label="Node details" data-testid="node-panel">
          {#if sel}
            <div class="card-head">
              <h2>{sel.label}</h2>
              <button type="button" class="small" onclick={() => (selected = null)} aria-label="Close the details">Close</button>
            </div>
            <p>
              <span class="hbadge {sel.health}"><svg class="hicon" width="16" height="16" viewBox="-9 -9 18 18" aria-hidden="true"><path d={HEALTH_SHAPE[sel.health]} /></svg>{HEALTH_SHORT[sel.health]}</span>
              <span class="muted small">{KIND_WORDS[sel.kind]}{sel.network ? ` in ${sel.network}` : ''}{sel.group ? `, group ${sel.group}` : ''}</span>
            </p>
            {#if sel.address && snap.privacy < 2}<p class="mono small" data-testid="panel-address">{sel.address}</p>{/if}
            {#if via(sel)}<p class="small" data-testid="panel-via">Connected through {via(sel)}</p>{/if}
            {#if sel.kind === 'device' || sel.kind === 'more' || sel.kind === 'resolver' || sel.kind === 'upstream' || sel.kind === 'answer'}
              <p class="small">{rate(sel.qps)} over the window ({num(sel.count)} answers, {num(sel.sampled)} sampled){sel.folded ? `; ${num(sel.folded)} devices folded` : ''}.</p>
            {/if}
            {#if sel.reasons.length}
              <ul class="reasons small">{#each sel.reasons as r, i (`${r.code}#${i}`)}<li><b>{r.code.replace(/_/g, ' ')}</b>: {r.summary}</li>{/each}</ul>
            {/if}
            <!-- REQ: FLT-006, API-010 (T24.30, ADR-996) — what applies to this device, and why. -->
            {#if sel.kind === 'device' && sel.address && snap.privacy < 2}
              <h3>Policy</h3>
              <PolicyPanel client={sel.address} compact />
            {/if}
            {#if selEdges.length}
              <h3>Flows</h3>
              <ul class="small flows">
                {#each selEdges as e, i (`${e.from}>${e.to}#${i}`)}
                  <li>{labelOf(e.from)} → {labelOf(e.to)}: {rate(e.qps)}, {pct(e.slowPct, 0)} slow, {pct(e.errPct, 0)} failing, {HEALTH_WORDS[e.health]}</li>
                {/each}
              </ul>
            {/if}
            {#if recent.length}
              <h3>Recent lookups</h3>
              <ul class="small flows">{#each recent as r (r.tsUnixMicros)}<li>{new Date(r.tsUnixMicros / 1000).toLocaleTimeString()}: {r.status}, {r.totalMs} ms</li>{/each}</ul>
            {/if}
            {#if snap.privacy >= 2 && sel.kind === 'device'}
              <p class="muted small">Devices are hidden at this privacy level, so there is nowhere to click through to.</p>
            {/if}
            <p class="row links">
              {#each links(sel, snap.privacy) as l (l.testid)}
                <a class="pill-link" href={href(l.path, l.params)} data-testid={l.testid}>{l.label}</a>
              {/each}
            </p>
          {:else}
            <p class="muted">This node is no longer in the map.</p>
            <button type="button" class="small" onclick={() => (selected = null)}>Close</button>
          {/if}
        </aside>
      {/if}
    </div>
  {:else if !error}
    <p class="empty" data-testid="map-loading">Loading the map…</p>
  {/if}
</div>

<style>
  .mapgrid {
    display: grid;
    gap: var(--gap);
    grid-template-columns: minmax(0, 1fr);
    align-items: start;
  }
  @media (min-width: 1100px) {
    .mapgrid:has(.nodepanel) {
      grid-template-columns: minmax(0, 1fr) 320px;
    }
  }
  .filters {
    gap: 10px;
  }
  .pill-field input {
    border: 0;
    border-radius: 999px;
    min-height: 28px;
    padding: 3px 12px;
    background: var(--surface);
    color: var(--text);
    min-width: 9rem;
  }
  .mapscroll {
    overflow-x: auto;
    padding-bottom: 4px;
  }
  .mapfig {
    margin: 0;
  }
  .mapfig figcaption {
    margin-bottom: 6px;
  }
  /* Only the map itself: the legend's and the panel's icons keep their own 16 px (fork #25). */
  .mapscroll > svg {
    display: block;
    min-width: 760px;
    max-width: 100%;
    height: auto;
  }
  .coltitle {
    font-size: 11px;
    font-weight: 600;
    letter-spacing: 0.04em;
    text-transform: uppercase;
    fill: var(--muted);
  }
  .track {
    fill: none;
    stroke: var(--border);
    stroke-width: 1.5;
  }
  .track.structural {
    stroke-dasharray: 2 4;
  }
  .pulse {
    fill: none;
    stroke-linecap: round;
    opacity: 0.95;
  }
  .pulse.green {
    stroke: var(--ok);
  }
  .pulse.yellow {
    stroke: var(--warn);
  }
  .pulse.red {
    stroke: var(--bad);
  }
  .pulse.idle {
    stroke: var(--muted);
  }
  .pulse.run {
    animation: mapflow var(--secs) linear infinite;
    animation-delay: var(--delay);
  }
  .paused .pulse.run {
    animation-play-state: paused;
  }
  @keyframes mapflow {
    from {
      stroke-dashoffset: 0;
    }
    to {
      stroke-dashoffset: calc(var(--period) * -1);
    }
  }
  /* Reduced motion: nothing moves, whatever the script thinks. */
  @media (prefers-reduced-motion: reduce) {
    .pulse.run {
      animation: none;
    }
  }
  .ratelabel {
    font-size: 10px;
    fill: var(--text);
    paint-order: stroke;
    stroke: var(--surface);
    stroke-width: 3px;
  }
  .node {
    cursor: pointer;
  }
  .node rect {
    fill: var(--surface);
    stroke: var(--border);
    stroke-width: 1.5;
  }
  .node.green rect {
    stroke: var(--ok);
  }
  .node.yellow rect {
    stroke: var(--warn);
    stroke-width: 2;
  }
  .node.red rect {
    stroke: var(--bad);
    stroke-width: 2.5;
  }
  .node.idle rect {
    stroke: var(--muted);
    stroke-dasharray: 4 3;
  }
  .node:hover rect,
  .node.selected rect {
    fill: var(--surface-2);
  }
  .node:focus {
    outline: none;
  }
  .node:focus-visible rect {
    stroke: var(--focus);
    stroke-width: 3;
    stroke-dasharray: none;
  }
  .shape {
    fill: none;
    stroke-width: 1.8;
    stroke-linecap: round;
    stroke-linejoin: round;
  }
  .node.green .shape {
    stroke: var(--ok-strong);
  }
  .node.yellow .shape {
    stroke: var(--warn-strong);
  }
  .node.red .shape {
    stroke: var(--bad-strong);
  }
  .node.idle .shape {
    stroke: var(--muted);
  }
  .nlabel {
    font-size: 12px;
    font-weight: 600;
    fill: var(--text);
  }
  .nstate {
    font-size: 10px;
    fill: var(--muted);
  }
  .legend {
    display: flex;
    flex-wrap: wrap;
    gap: 6px 14px;
    align-items: center;
    margin: 10px 0 0;
  }
  .lg {
    display: inline-flex;
    align-items: center;
    gap: 4px;
  }
  .hicon {
    width: 16px;
    height: 16px;
    flex: none;
  }
  .lg path,
  .hbadge path {
    fill: none;
    stroke-width: 1.8;
    stroke-linecap: round;
    stroke-linejoin: round;
    stroke: currentColor;
  }
  .lg.green,
  .hbadge.green {
    color: var(--ok-strong);
  }
  .lg.yellow,
  .hbadge.yellow {
    color: var(--warn-strong);
  }
  .lg.red,
  .hbadge.red {
    color: var(--bad-strong);
  }
  .lg.idle,
  .hbadge.idle {
    color: var(--muted);
  }
  .hbadge {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    font-weight: 600;
    margin-right: 8px;
  }
  .tabletitle {
    font-size: 14px;
    margin: 4px 0 8px;
  }
  .tablewrap {
    overflow-x: auto;
    margin-bottom: 14px;
  }
  table {
    width: 100%;
    border-collapse: collapse;
    font-size: 13px;
  }
  th,
  td {
    text-align: left;
    padding: 5px 8px;
    border-bottom: 1px solid var(--surface-2);
  }
  .num {
    text-align: right;
    font-variant-numeric: tabular-nums;
  }
  .nodepanel h3 {
    font-size: 13px;
    margin: 12px 0 4px;
  }
  .reasons,
  .flows {
    margin: 4px 0;
    padding-left: 18px;
  }
  .links {
    margin-top: 12px;
  }
</style>
