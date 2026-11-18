<script lang="ts">
  // REQ: OBS-902 (T26.5, ADR-958, ADR-959, ADR-970) - the world view: arcs from the network to
  // the countries answers point at, wider and denser for more lookups, coloured and shaped by how
  // slow they were. A dot grid from a baked-in land mask (no tiles, fonts or scripts from outside).
  // Without a GeoIP database it says so, with the admin's link to the setting; while the answer
  // address isn't recorded (ADR-970) it shows only where the upstreams are, labelled as that.
  // Reduced motion and a hidden tab stop the pulses; the table of countries is the same data in words.
  import { api, ApiError } from '../lib/api';
  import { route, navigate, href } from '../lib/router.svelte';
  import { poll } from '../lib/poll';
  import { can } from '../lib/session.svelte';
  import { num, pct } from '../lib/format';
  import ErrorNote from '../lib/components/ErrorNote.svelte';
  import HelpButton from '../lib/components/HelpButton.svelte';
  import { HEALTH_ORDER, HEALTH_SHAPE, HEALTH_SHORT, HEALTH_WORDS, animatedBudget, rate } from '../lib/map';
  import {
    VIEW_H,
    VIEW_W,
    countryName,
    landPath,
    place,
    placeMarkers,
    summary,
    upstreamsOnly,
    whyUnavailable,
    type World,
  } from '../lib/world';

  const nodeFilter = $derived(route.params.get('node') ?? '');
  const healthFilter = $derived((HEALTH_ORDER as string[]).find((h) => h === route.params.get('health')) ?? '');
  const tableView = $derived(route.params.get('view') === 'table');
  const showUpstreams = $derived(route.params.get('upstreams') !== '0');
  function setParams(change: Record<string, string | undefined>) {
    const p: Record<string, string | undefined> = {};
    for (const k of ['node', 'health', 'view', 'upstreams']) p[k] = route.params.get(k) ?? undefined;
    navigate('/world', { ...p, ...change }, true);
  }

  let raw = $state<World | null>(null);
  let error = $state<unknown>(null);
  let off = $state(false);
  let hidden = $state(typeof document !== 'undefined' && document.visibilityState === 'hidden');
  let userPaused = $state(false);
  let reduced = $state(typeof matchMedia !== 'undefined' && matchMedia('(prefers-reduced-motion: reduce)').matches);
  let nodes = $state<string[]>([]);

  let seq = 0;
  async function fetchWorld(node: string) {
    const mine = ++seq;
    try {
      const w = await api.mapWorld(node ? { node } : {});
      if (mine !== seq) return;
      raw = w;
      error = null;
      off = false;
    } catch (e) {
      if (mine !== seq) return;
      if (e instanceof ApiError && e.code === 'map_disabled') {
        off = true;
        raw = null;
        error = null;
      } else error = e;
    }
  }
  $effect(() => {
    const node = nodeFilter;
    const stop = poll(() => fetchWorld(node), 5000);
    return () => {
      seq++;
      stop();
    };
  });
  // The nodes the filter offers: the resolvers of the network map.
  $effect(() => {
    api
      .map()
      .then((s) => (nodes = s.nodes.filter((n) => n.kind === 'resolver' && n.node).map((n) => n.node as string)))
      .catch(() => {});
  });
  $effect(() => {
    const onVis = () => (hidden = document.visibilityState === 'hidden');
    document.addEventListener('visibilitychange', onVis);
    const mq = matchMedia('(prefers-reduced-motion: reduce)');
    const onMq = () => (reduced = mq.matches);
    mq.addEventListener('change', onMq);
    return () => {
      document.removeEventListener('visibilitychange', onVis);
      mq.removeEventListener('change', onMq);
    };
  });

  const land = landPath();
  const cores = typeof navigator !== 'undefined' ? navigator.hardwareConcurrency : undefined;
  const w = $derived<World | null>(
    raw ? { ...raw, regions: raw.regions.filter((r) => !healthFilter || r.health === healthFilter) } : null,
  );
  const placed = $derived(w ? place(w, { maxAnimated: animatedBudget(cores) }) : null);
  const markers = $derived(w && showUpstreams ? placeMarkers(w.markers.filter((m) => !healthFilter || m.health === healthFilter)) : []);
  const why = $derived(raw ? whyUnavailable(raw.reason) : null);
  const onlyUpstreams = $derived(raw ? upstreamsOnly(raw) : false);
  const motion = $derived(!reduced && !userPaused && !hidden);
  const total = $derived(raw ? raw.regions.reduce((a, r) => a + r.count, 0) + raw.unlocated.count : 0);
  const stateText = $derived(off ? 'Turned off on this node' : hidden ? 'Paused: this tab is hidden' : raw ? 'Updating every 5 seconds' : 'Loading');
  const sorted = $derived(w ? [...w.regions].sort((a, b) => b.count - a.count) : []);
  const drawable = $derived(!!raw && (raw.available || raw.markers.length > 0));
</script>

<div class="page worldpage">
  <div class="page-head">
    <h1>World view<HelpButton id="world-view" /></h1>
    <div class="row">
      <span class="small muted" data-testid="world-state" role="status">{stateText}</span>
      <a class="pill-link" href={href('/map')} data-testid="to-network-map">Network map</a>
      <div class="seg" role="group" aria-label="View">
        <button type="button" aria-pressed={!tableView} onclick={() => setParams({ view: undefined })} data-testid="view-map">Map</button>
        <button type="button" aria-pressed={tableView} onclick={() => setParams({ view: 'table' })} data-testid="view-table">Table</button>
      </div>
      {#if !reduced}
        <button type="button" class="small" aria-pressed={userPaused} onclick={() => (userPaused = !userPaused)} data-testid="pause-motion">{userPaused ? 'Resume motion' : 'Pause motion'}</button>
      {/if}
    </div>
  </div>

  <form class="row filters" onsubmit={(e) => e.preventDefault()} aria-label="World view filters">
    <label class="pill-field">
      Node
      <select value={nodeFilter} onchange={(e) => setParams({ node: e.currentTarget.value || undefined })} data-testid="filter-node">
        <option value="">all</option>
        {#each nodes as n (n)}<option value={n}>{n}</option>{/each}
        {#if nodeFilter && !nodes.includes(nodeFilter)}<option value={nodeFilter}>{nodeFilter}</option>{/if}
      </select>
    </label>
    <label class="pill-field">
      State
      <select value={healthFilter} onchange={(e) => setParams({ health: e.currentTarget.value || undefined })} data-testid="filter-health">
        <option value="">all</option>
        {#each HEALTH_ORDER as h (h)}<option value={h}>{HEALTH_SHORT[h]}</option>{/each}
      </select>
    </label>
    <label class="pill-field">
      <input type="checkbox" checked={showUpstreams} onchange={(e) => setParams({ upstreams: e.currentTarget.checked ? undefined : '0' })} data-testid="layer-upstreams" />
      Upstream locations
    </label>
    {#if nodeFilter || healthFilter}<button type="button" class="small" onclick={() => setParams({ node: undefined, health: undefined })} data-testid="filter-clear">Clear filters</button>{/if}
  </form>
  <p class="muted small" data-testid="filter-note">
    Answers are counted per node, not per device, so the network, group and device filters of the network map don't apply here.
  </p>

  <ErrorNote {error} />

  {#if off}
    <p class="notice warn" data-testid="map-off">The network map is turned off on this node (<code>[map] enabled = false</code>), so there is nothing to draw.</p>
  {:else if raw && w && placed}
    {#if why}
      <div class="notice {why.code === 'address_not_recorded' ? '' : 'warn'}" data-testid="world-unavailable" data-reason={why.code} role="status">
        <b>{why.title}.</b>
        {why.body}
        {#if why.admin}
          {#if can('admin')}
            <a class="pill-link" href={href('/settings', { tab: 'queries' })} data-testid="world-setting-link">Open the GeoIP setting</a>
          {:else}
            <span data-testid="world-ask-admin">Ask an admin to turn it on in Settings, Query handling, GeoIP.</span>
          {/if}
        {/if}
      </div>
    {/if}

    {#if drawable}
      <section class="card worldcard" aria-label="World view">
        {#if onlyUpstreams}
          <p class="notice small" data-testid="world-upstream-only">Upstream locations, not where answers point.</p>
        {/if}
        {#if !tableView}
          <figure class="worldfig" role="group" aria-label="World view" aria-describedby="world-summary" data-testid="world-figure" data-motion={motion ? 'on' : 'off'}>
            <figcaption id="world-summary" class="small muted" data-testid="world-summary">{summary(w, placed)} Switch to the table for the same data as text.</figcaption>
            <div class="worldscroll">
              <svg viewBox="0 0 {VIEW_W} {VIEW_H}" class:paused={!motion} class:still={reduced} focusable="false">
                <path class="land" d={land} />
                <g class="arcs">
                  {#each placed.arcs as a (a.id)}
                    <path class="track {a.region.health}" d={a.d} data-arc={a.cc} />
                    <path
                      class="pulse {a.region.health}"
                      class:run={a.animated && !reduced}
                      d={a.d}
                      pathLength="100"
                      stroke-width={a.width}
                      stroke-dasharray="{a.pulse.dash} {a.pulse.gap}"
                      style:--period={a.pulse.dash + a.pulse.gap}
                      style:--secs="{a.pulse.seconds}s"
                      style:--delay="{a.pulse.delay}s"
                      data-pulse={a.cc}
                    />
                    {#if reduced}<text class="ratelabel" x={a.mx} y={a.my - 3} text-anchor="middle" data-testid="rate-label">{rate(a.region.qps)}</text>{/if}
                  {/each}
                </g>
                <g class="home" transform="translate({placed.home.x} {placed.home.y})" data-testid="world-home">
                  <circle r="5" />
                  <text x="-9" y="4" text-anchor="end">{placed.home.label}</text>
                </g>
                <g class="countries">
                  {#each placed.arcs as a (a.id)}
                    <g class="end {a.region.health}" transform="translate({a.x} {a.y})" data-country={a.cc} data-health={a.region.health} role="img" aria-label="{countryName(a.cc)}: {HEALTH_SHORT[a.region.health]}, {rate(a.region.qps)}">
                      <path class="shape" d={HEALTH_SHAPE[a.region.health]} />
                      <text x="9" y="4" class="cc">{a.cc}</text>
                    </g>
                  {/each}
                  {#each markers as m (m.id)}
                    <g class="marker {m.health}" transform="translate({m.x} {m.y})" data-marker={m.name} role="img" aria-label="Upstream {m.name} in {countryName(m.cc)}: {HEALTH_SHORT[m.health]}">
                      <path class="diamond" d="M0 -6L6 0L0 6L-6 0z" />
                      <text x="9" y="4" class="mk">{m.name}</text>
                    </g>
                  {/each}
                </g>
              </svg>
            </div>
          </figure>
        {:else}
          <div data-testid="world-table">
            <h2 class="tabletitle">Where answers point</h2>
            <div class="tablewrap">
              <table aria-label="Countries">
                <thead><tr><th scope="col">Country</th><th scope="col" class="num">Per second</th><th scope="col" class="num">Lookups</th><th scope="col" class="num">Slow</th><th scope="col">State</th></tr></thead>
                <tbody>
                  {#each sorted as r (r.cc)}
                    <tr data-region-row={r.cc}>
                      <td>{countryName(r.cc)} <span class="muted">({r.cc})</span></td><td class="num">{rate(r.qps)}</td><td class="num">{num(r.count)}</td><td class="num">{pct(r.slowPct, 0)}</td>
                      <td>{HEALTH_WORDS[r.health]}</td>
                    </tr>
                  {:else}
                    <tr><td colspan="5" class="muted">No answers are placed.</td></tr>
                  {/each}
                </tbody>
              </table>
            </div>
            {#if w.markers.length}
              <h2 class="tabletitle">Upstream locations</h2>
              <div class="tablewrap">
                <table aria-label="Upstream locations">
                  <thead><tr><th scope="col">Upstream</th><th scope="col">Country</th><th scope="col" class="num">Per second</th><th scope="col">State</th></tr></thead>
                  <tbody>
                    {#each w.markers as m (m.name)}
                      <tr data-marker-row={m.name}><td>{m.name}</td><td>{m.cc ? countryName(m.cc) : ''}</td><td class="num">{rate(m.qps)}</td><td>{HEALTH_WORDS[m.health]}</td></tr>
                    {/each}
                  </tbody>
                </table>
              </div>
            {/if}
          </div>
        {/if}
        <p class="legend small muted" aria-label="Legend">
          {#each HEALTH_ORDER as h (h)}
            <span class="lg {h}"><svg width="16" height="16" viewBox="-9 -9 18 18" aria-hidden="true"><path d={HEALTH_SHAPE[h]} /></svg>{HEALTH_SHORT[h]}</span>
          {/each}
          <span class="lg marker-lg"><svg width="16" height="16" viewBox="-9 -9 18 18" aria-hidden="true"><path d="M0 -6L6 0L0 6L-6 0z" /></svg>Upstream</span>
          <span>Wider, denser pulses mean more lookups a second; a region's colour comes from the share of slow answers. {Math.round(raw.windowSecs)}-second window.</span>
        </p>
        <p class="small" data-testid="world-unlocated">
          <b>{num(raw.unlocated.count)}</b>{total > 0 ? ` of ${num(total)}` : ''} lookups have no location: failed, blocked and local answers, answers at privacy level 3, and addresses with no country.
          {#if raw.unplacedUpstreams > 0}{num(raw.unplacedUpstreams)} {raw.unplacedUpstreams === 1 ? 'upstream has' : 'upstreams have'} no place on the map (a host name, or an address with no country).{/if}
        </p>
        {#if placed.unplaced.length}
          <p class="small muted" data-testid="world-unplaced">Not drawn (no point for the code): {placed.unplaced.map((r) => r.cc).join(', ')}. They are in the table.</p>
        {/if}
      </section>
    {/if}
    <p class="small muted attribution" data-testid="world-attribution">
      IP geolocation by <a href="https://db-ip.com" target="_blank" rel="noopener noreferrer">DB-IP.com</a>, under
      <a href="https://creativecommons.org/licenses/by/4.0/" target="_blank" rel="noopener noreferrer">CC BY 4.0</a>.
      Country accuracy is a database's: good for a picture, not for compliance.
    </p>
  {:else if !error}
    <p class="empty" data-testid="world-loading">Loading the world view…</p>
  {/if}
</div>

<style>
  .filters {
    gap: 10px;
  }
  .worldscroll {
    overflow-x: auto;
    padding-bottom: 4px;
  }
  .worldfig {
    margin: 0;
  }
  .worldfig figcaption {
    margin-bottom: 6px;
  }
  svg {
    display: block;
    width: 100%;
    min-width: 640px;
    height: auto;
  }
  .land {
    fill: var(--surface-2);
    stroke: none;
  }
  .track {
    fill: none;
    stroke: var(--border);
    stroke-width: 1.2;
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
    animation: worldflow var(--secs) linear infinite;
    animation-delay: var(--delay);
  }
  .paused .pulse.run {
    animation-play-state: paused;
  }
  @keyframes worldflow {
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
  .home circle {
    fill: var(--surface);
    stroke: var(--text);
    stroke-width: 2;
  }
  .home text,
  .cc,
  .mk {
    font-size: 11px;
    font-weight: 600;
    fill: var(--text);
    paint-order: stroke;
    stroke: var(--surface);
    stroke-width: 3px;
  }
  .mk {
    font-weight: 500;
  }
  .shape,
  .diamond {
    fill: var(--surface);
    stroke-width: 1.8;
    stroke-linecap: round;
    stroke-linejoin: round;
  }
  .end.green .shape,
  .marker.green .diamond {
    stroke: var(--ok-strong);
  }
  .end.yellow .shape,
  .marker.yellow .diamond {
    stroke: var(--warn-strong);
  }
  .end.red .shape,
  .marker.red .diamond {
    stroke: var(--bad-strong);
  }
  .end.idle .shape,
  .marker.idle .diamond {
    stroke: var(--muted);
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
  .lg path {
    fill: none;
    stroke-width: 1.8;
    stroke-linecap: round;
    stroke-linejoin: round;
    stroke: currentColor;
  }
  .lg svg {
    min-width: 0;
  }
  .lg.green {
    color: var(--ok-strong);
  }
  .lg.yellow {
    color: var(--warn-strong);
  }
  .lg.red {
    color: var(--bad-strong);
  }
  .lg.idle,
  .lg.marker-lg {
    color: var(--muted);
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
    min-width: 0;
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
  .attribution {
    margin: 12px 0 0;
  }
</style>
