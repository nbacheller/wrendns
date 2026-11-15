<script lang="ts">
  // REQ: API-005 (ADR-157) — the dashboard: the numbers that matter as plain text, one chart whose
  // hover gives the exact figures, and the top lists. One card (the chart) on an otherwise open page.
  //
  // Advanced adds, without adding cards: the service level (OBS-016) as a strip under the numbers;
  // the chart's other views (groups, upstream exchanges) beside Status; where time goes (OBS-030)
  // and the upstreams as plain sections; devices by type (OBS-025) as a line under the clients.
  import { api, type S } from '../lib/api';
  import { changes } from '../lib/annotations.svelte';
  import { change, DashData, remember } from '../lib/dash/data.svelte';
  import DashHead from '../lib/dash/DashHead.svelte';
  import SmoothChart from '../lib/dash/SmoothChart.svelte';
  import Stat from '../lib/dash/Stat.svelte';
  import TopList from '../lib/dash/TopList.svelte';
  import BreakerBadge from '../lib/components/BreakerBadge.svelte';
  import HelpButton from '../lib/components/HelpButton.svelte';
  import LatencyHeatmap from '../lib/components/LatencyHeatmap.svelte';
  import Tip from '../lib/components/Tip.svelte';
  import { href } from '../lib/router.svelte';
  import { ms, num, pct, short } from '../lib/format';

  const d = new DashData();
  $effect(() => d.attach());
  $effect(() => remember(d.scope));
  const s = $derived(d.summary);
  const scopeLabel = $derived(
    d.scope.startsWith('node:')
      ? (d.nodes.find((n) => `node:${n.nodeId}` === d.scope)?.site ?? 'one node')
      : d.scope.startsWith('site:')
        ? `site ${d.scope.slice(5)}`
        : 'every node',
  );

  const lists = $derived([
    {
      title: 'Top domains',
      items: d.topDomains,
      kind: 'domains' as const,
      link: (k: string, merged: boolean) => href('/queries', { name: k, match: merged ? 'substring' : 'exact' }),
    },
    {
      title: 'Top blocked',
      items: d.topBlocked,
      kind: 'blocked' as const,
      link: (k: string, merged: boolean) => href('/queries', { name: k, match: merged ? 'substring' : 'exact', status: 'blocked' }),
    },
    { title: 'Top clients', items: d.topClients, kind: 'clients' as const, link: (k: string) => href('/queries', { client: k }) },
  ]);

  // The chart's view: Totals (queries and the blocked part) and Status (stacked) for everyone;
  // Groups and Upstream in the Advanced view.
  type View = 'totals' | 'status' | 'group' | 'upstream';
  let view = $state<View>('totals');
  const hasGroups = $derived(d.groupSeries.length > 1 || (d.groupSeries.length === 1 && d.groupSeries[0].label !== 'default'));
  const views = $derived([
    { id: 'totals' as View, name: 'Totals' },
    { id: 'status' as View, name: 'Status' },
    ...(d.advanced ? [...(hasGroups ? [{ id: 'group' as View, name: 'Groups' }] : []), { id: 'upstream' as View, name: 'Upstream' }] : []),
  ]);
  const shown = $derived(views.some((v) => v.id === view) ? view : 'totals');
  const chart = $derived(
    shown === 'status'
      ? { title: 'Queries by status', series: d.statusSeries, mode: 'stack' as const }
      : shown === 'group'
        ? { title: 'Traffic by group', series: d.groupSeries, mode: 'stack' as const }
        : shown === 'upstream'
          ? { title: 'Upstream exchanges', series: d.upstreamSeries, mode: 'area' as const }
          : { title: 'Queries', series: [d.totalSeries, d.blockedSeries], mode: 'area' as const },
  );

  // The cache number, split the way the Advanced view splits it (DNS-007).
  const cacheSub = $derived(
    d.advanced && d.refreshedPercent != null && (s?.refreshed ?? 0) > 0
      ? `${pct((s?.cacheHitPercent ?? 0) - d.refreshedPercent)} fresh · ${pct(d.refreshedPercent)} refreshed`
      : `${short(s?.cached)} answers`,
  );

  // Service level (OBS-016).
  const sloTitles: Record<string, string> = { availability: 'Answers that work', latency: 'Answers that are quick' };
  const sloAlerts: Record<string, { text: string; tone: string; tip: string }> = {
    fast: {
      text: 'burning fast',
      tone: 'bad',
      tip: 'Over the last hour (and the last 5 minutes) the budget is going more than 14 times faster than it can last: at this rate a month’s budget is gone in about two days.',
    },
    slow: {
      text: 'burning',
      tone: 'bad',
      tip: 'Over the last 6 hours (and the last 30 minutes) the budget is going more than 6 times faster than it can last.',
    },
    ticket: {
      text: 'on course to run out',
      tone: 'warn',
      tip: 'Over the last 3 days the budget has been going faster than it can last: worth a look this week.',
    },
  };
  const sloPct = (v: number | null | undefined, digits = 2) => (v == null ? '–' : `${v.toFixed(v >= 99.995 || v === 0 ? 0 : digits)}%`);
  const budgetTone = (v: number | null | undefined) => (v == null ? '' : v >= 50 ? 'ok' : v >= 25 ? 'warn' : 'bad');
  const burnText = (b: S['SloBurn']) => (b.rate == null ? '–' : `${b.rate >= 10 ? b.rate.toFixed(0) : b.rate.toFixed(1)}×`);
  const burnTip = (b: S['SloBurn']) =>
    b.rate == null
      ? `No answers to judge in the last ${b.window}.`
      : `Last ${b.window}: ${short(b.bad)} bad of ${short(b.total)} answers. 1× spends exactly the budget over the window.`;

  // Where time goes (OBS-030): what each row means (path/transport, or a wait stage).
  let timeView = $state<'table' | 'heatmap'>('table');
  const paths: Record<string, string> = {
    cache:
      'Answered from the cache: a repeat question, no upstream asked. Includes answers whose cached copy had just expired and was given at once while it was refreshed in the background. Usually well under a millisecond.',
    upstream:
      'Not in the cache: asked an upstream resolver and waited for it. Also counts stale answers served because the upstream was slow or failing, and SERVFAIL. Usually the slowest path.',
    local: 'Answered from names on your network (local records), without asking anyone.',
    synthesized:
      "Answered without looking anything up: blocked names, refused or rate-limited queries, malformed ones, and special names (like Firefox's DNS-over-HTTPS canary).",
  };
  const protos: Record<string, string> = {
    udp: 'plain DNS over UDP, what most devices use',
    tcp: 'plain DNS over TCP, for large answers and some tools',
    dot: 'DNS over TLS (port 853), e.g. Android Private DNS',
    doh: 'DNS over HTTPS, e.g. browsers or Apple devices with a profile',
  };
  const pathTip = (key: string) => {
    if (key.startsWith('wait: ')) {
      const what = key.slice(6);
      return what === 'upstream'
        ? "Of the upstream path above: the time spent waiting for upstream resolvers (the rest is this node's own work)."
        : `Time spent waiting for ${what} when it answered.`;
    }
    const [path, proto] = key.split('/');
    const p = paths[path] ?? 'Answers that took this path.';
    return proto && protos[proto] ? `${p} Over ${protos[proto]}.` : p;
  };
  const timeRows = $derived([...d.byPath, ...d.stages.map((x) => ({ ...x, key: `wait: ${x.key}` }))]);

  // Upstreams: health is each node's own, so say whose when another node is shown.
  const totalUp = $derived(d.upstreams.reduce((a, u) => a + u.requests, 0));
  const otherNode = $derived(d.scope !== '' && !(d.scope.startsWith('node:') && d.nodes.find((n) => `node:${n.nodeId}` === d.scope)?.thisNode));

  // Devices by type (OBS-025).
  let identities = $state<S['DeviceIdentity'][]>([]);
  $effect(() => {
    if (!d.advanced) return;
    api
      .identities()
      .then((r) => (identities = r.items))
      .catch(() => (identities = []));
  });
  const types = $derived.by(() => {
    const m = new Map<string, number>();
    for (const i of identities) m.set(i.class, (m.get(i.class) ?? 0) + 1);
    return [...m.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
  });
</script>

<div class="page calm">
  <DashHead {d} />

  <div class="stats">
    <div class="cell" data-testid="stat-queries"><Stat label="Queries" value={short(s?.queries)} delta={change(s?.queries, d.previous?.queries)} sub={`last ${d.range.label}${d.scope ? ` · ${scopeLabel}` : ''}`} /></div>
    <div class="cell" data-testid="stat-blocked"><Stat label="Blocked" value={pct(s?.blockedPercent)} delta={change(s?.blockedPercent, d.previous?.blockedPercent)} sub={`${short(s?.blocked)} queries`} /></div>
    <div class="cell" data-testid="stat-cache"><Stat label="Cache hits" value={pct(s?.cacheHitPercent)} delta={change(s?.cacheHitPercent, d.previous?.cacheHitPercent)} good="up" sub={cacheSub} /></div>
    <div class="cell" data-testid="stat-upstream"><Stat label="Upstream p90" value={ms(d.upstreamP90?.p90Ms)} sub={d.cacheP50 ? `cache p50 ${ms(d.cacheP50.p50Ms)}` : 'this hour'} delta={change(d.upstreamP90?.p90Ms, d.prevP90?.p90Ms)} good="down" /></div>
    <div class="cell" data-testid="stat-clients"><Stat label="Active clients" value={num(s?.activeClients)} sub={d.rangeLabel} /></div>
  </div>
  <p class="fine muted small">{short(s?.nxdomain)} NXDOMAIN · {short(s?.servfail)} SERVFAIL in the last {d.range.label}</p>

  {#if d.advanced}
    <section class="slo sec" data-testid="slo-card" aria-label="Service level">
      <div class="sh">
        <h2>Service level {#if d.slo?.enabled}<span class="muted small">last {d.slo.windowDays} days</span>{/if}<HelpButton id="slo" /></h2>
      </div>
      {#if !d.slo}
        <p class="muted small">Loading…</p>
      {:else if !d.slo.enabled}
        <p class="muted small">Objectives are off (<code>[slo] enabled = false</code>).</p>
      {:else}
        {#if d.slo.missingNodes?.length}
          <p class="small muted">Without {d.slo.missingNodes.join(', ')}: they didn’t answer.</p>
        {/if}
        <div class="objs">
          {#each d.slo.objectives as o (o.name)}
            {@const left = o.budgetRemainingPercent}
            <div class="obj" data-testid={`slo-${o.name}`}>
              <div class="oh">
                <strong>{sloTitles[o.name] ?? o.name}</strong>
                {#if o.alert && sloAlerts[o.alert]}
                  <Tip text={sloAlerts[o.alert].tip}><span class="badge {sloAlerts[o.alert].tone}">{sloAlerts[o.alert].text}</span></Tip>
                {:else if o.total > 0}
                  <span class="badge ok">on track</span>
                {/if}
              </div>
              <div class="muted small">{o.goodMeans} · target {o.targetPercent}%</div>
              <div class="fig"><b>{sloPct(o.sliPercent, 3)}</b> <span class="muted small">of {short(o.total)} answers</span></div>
              <div class="track {budgetTone(left)}" title="Error budget left: the bad answers the target still allows over the window"><span style:width={`${Math.max(0, Math.min(100, left ?? 0))}%`}></span></div>
              <div class="small">
                {#if left == null}no answers yet{:else if left < 0}budget overspent{:else}{left.toFixed(0)}% of the error budget left{/if}
                · <a href={href('/analyze', { tab: 'budget', objective: o.name })} data-testid={`slo-who-${o.name}`}>Who spent it?</a>
              </div>
              <div class="small muted">
                Burn rate
                {#each o.burnRates as b, i (b.window)}{i ? ' · ' : ' '}<Tip text={burnTip(b)}><span class="burn" class:hot={(b.rate ?? 0) >= 6}>{b.window} {burnText(b)}</span></Tip>{/each}
              </div>
            </div>
          {/each}
        </div>
      {/if}
    </section>
  {/if}

  <section class="card plot" data-testid="dashboard-chart">
    <div class="views seg" role="group" aria-label="Chart view">
      {#each views as v (v.id)}
        <button aria-pressed={shown === v.id} onclick={() => (view = v.id)}>{v.name}</button>
      {/each}
    </div>
    <SmoothChart title={chart.title} times={d.times} series={chart.series} mode={chart.mode} height={260} axes="minimal" markers={changes.markers} />
  </section>

  {#if d.advanced}
    <div class="pair">
      <section class="sec" class:wide={timeView === 'heatmap'}>
        <div class="sh">
          <h2>Where time goes {#if timeView === 'table'}<span class="muted small">this hour</span>{/if}{#if timeView === 'heatmap'}<HelpButton id="latency-heatmap" />{:else}<HelpButton id="cache" />{/if}</h2>
          <div class="seg" role="group" aria-label="Where time goes as">
            <button type="button" aria-pressed={timeView === 'table'} onclick={() => (timeView = 'table')}>Percentiles</button>
            <button type="button" aria-pressed={timeView === 'heatmap'} onclick={() => (timeView = 'heatmap')} data-testid="time-heatmap-tab">Heatmap</button>
          </div>
        </div>
        {#if timeView === 'heatmap'}
          <LatencyHeatmap />
        {:else if timeRows.length === 0}
          <p class="empty">No answers yet this hour.</p>
        {:else}
          <div class="table-wrap">
            <table class="compact times">
              <thead><tr><th>Path</th><th class="num hide-sm">Answers</th><th class="num">p50</th><th class="num">p90</th><th class="num">p99</th><th class="num hide-sm">max</th></tr></thead>
              <tbody>
                {#each timeRows as r (r.key)}
                  <tr>
                    <td><Tip text={pathTip(r.key)}>{r.key}</Tip></td>
                    <td class="num hide-sm">{num(r.count)}</td>
                    <td class="num">{ms(r.p50Ms)}</td>
                    <td class="num">{ms(r.p90Ms)}</td>
                    <td class="num">{ms(r.p99Ms)}</td>
                    <td class="num hide-sm">{ms(r.maxMs)}</td>
                  </tr>
                {/each}
              </tbody>
            </table>
          </div>
        {/if}
      </section>

      <section class="sec">
        <div class="sh">
          <h2>Upstreams{#if otherNode} <span class="muted small">as this node sees them</span>{/if}</h2>
          <a href={href('/upstreams')} class="small">Details</a>
        </div>
        {#if d.upstreams.length === 0}
          <p class="empty">No upstreams configured.</p>
        {:else}
          <ul class="ups">
            {#each d.upstreams as u (u.id)}
              {@const share = totalUp ? (u.requests / totalUp) * 100 : 0}
              <li style:--w={`${share}%`}>
                <div class="uh">
                  <strong>{u.name}</strong>
                  <BreakerBadge value={u.breaker} />
                  <span class="spacer"></span>
                  <span class="muted small">{pct(share, 0)} · {ms(u.latencyEwmaMs)}</span>
                </div>
              </li>
            {/each}
          </ul>
        {/if}
      </section>
    </div>
  {/if}

  <div class="lists">
    {#each lists as l (l.title)}
      <section>
        {#if l.title === 'Top domains'}
          <div class="sh">
            <h2>{l.title} <span class="muted small">{d.topLabel}</span><HelpButton id="internal-names" /></h2>
            <div class="seg" role="group" aria-label="Top domains on the internet or internal">
              <button type="button" aria-pressed={d.domainsView === 'internet'} onclick={() => (d.domainsView = 'internet')}>Internet</button>
              <button type="button" aria-pressed={d.domainsView === 'internal'} onclick={() => (d.domainsView = 'internal')} data-testid="domains-internal-tab">Internal</button>
            </div>
          </div>
        {:else}
          <div class="sh"><h2>{l.title} <span class="muted small">{d.topLabel}</span></h2></div>
        {/if}
        <TopList items={l.items} kind={l.kind} link={l.link} groupColor={d.groupColor} onchanged={() => void d.load()} />
        {#if d.advanced && l.kind === 'clients' && types.length}
          <p class="types small muted" data-testid="devices-by-type">
            By type
            {#each types as [cls, n] (cls)}<span class="ty">{cls} <b>{n}</b></span>{/each}
            <a href={href('/clients')}>Clients</a>
          </p>
        {/if}
      </section>
    {/each}
  </div>
</div>

<style>
  .calm {
    gap: 22px;
  }
  .stats {
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: 16px 12px;
  }
  .cell {
    min-width: 0;
  }
  .fine {
    margin: -8px 0 0;
  }
  .plot {
    padding: 14px 18px 8px;
  }
  /* The chart's views: one switch above the chart, left-aligned, so the Table link keeps the corner. */
  .views {
    margin-bottom: 8px;
    max-width: 100%;
    overflow-x: auto;
    scrollbar-width: none;
  }
  .views button {
    flex: none;
  }

  /* Plain sections: a heading over a hairline, no card. */
  .sec {
    min-width: 0;
  }
  .sh {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    justify-content: space-between;
    gap: 6px 10px;
    margin: 0 0 4px;
    padding: 0 0 8px;
    border-bottom: 1px solid var(--border);
  }
  .sec .sh {
    margin-bottom: 8px;
  }
  .sh h2 {
    margin: 0;
    padding: 0;
    font-size: 14px;
  }
  .sh h2::before {
    display: none;
  }

  /* Service level: two objectives side by side, a thin budget track under each figure. */
  .objs {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(min(100%, 300px), 1fr));
    gap: 16px 36px;
  }
  .obj {
    display: grid;
    gap: 5px;
    min-width: 0;
  }
  .oh {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 8px;
  }
  .fig b {
    font-size: 22px;
    font-weight: 650;
    letter-spacing: -0.02em;
    font-variant-numeric: tabular-nums;
    margin-right: 6px;
  }
  .track {
    height: 4px;
    border-radius: 999px;
    background: var(--surface-2);
    overflow: hidden;
  }
  .track span {
    display: block;
    height: 100%;
    border-radius: 999px;
    background: var(--ok);
  }
  .track.warn span {
    background: var(--warn);
  }
  .track.bad span {
    background: var(--bad);
  }
  .burn.hot {
    color: var(--bad-strong);
    font-weight: 600;
  }

  .pair {
    display: grid;
    grid-template-columns: minmax(0, 1fr);
    gap: 22px 36px;
  }
  .wide {
    grid-column: 1 / -1;
  }
  .times th,
  .times td {
    padding: 6px 8px 6px 0;
    vertical-align: middle;
  }
  .times td {
    line-height: 1.3;
  }
  .times th.num,
  .times td.num {
    padding-right: 0;
    padding-left: 12px;
  }
  @media (max-width: 640px) {
    .hide-sm {
      display: none;
    }
  }
  .ups {
    list-style: none;
    margin: 0;
    padding: 0;
    display: grid;
  }
  .ups li {
    position: relative;
    padding: 9px 0 11px;
    border-bottom: 1px solid var(--surface-2);
  }
  .ups li:last-child {
    border-bottom: 0;
  }
  /* The share of requests as a thin line under the name. */
  .ups li::after {
    content: '';
    position: absolute;
    left: 0;
    bottom: 4px;
    height: 2px;
    width: var(--w);
    min-width: 2px;
    border-radius: 2px;
    background: var(--s-forwarded);
    opacity: 0.55;
  }
  .uh {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 8px;
  }

  .types {
    display: flex;
    flex-wrap: wrap;
    gap: 2px 12px;
    margin: 10px 0 0;
  }
  .ty b {
    color: var(--text);
    font-variant-numeric: tabular-nums;
  }
  .lists {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(min(100%, 270px), 1fr));
    gap: 8px 36px;
    margin-top: 6px;
  }
  @media (min-width: 560px) {
    .stats {
      grid-template-columns: repeat(3, minmax(0, 1fr));
    }
  }
  @media (min-width: 980px) {
    .stats {
      grid-template-columns: repeat(5, minmax(0, 1fr));
      gap: 0;
    }
    .cell {
      padding: 2px 22px;
      border-left: 1px solid var(--border);
    }
    .cell:first-child {
      padding-left: 0;
      border-left: 0;
    }
    .pair {
      grid-template-columns: minmax(0, 1.6fr) minmax(0, 1fr);
    }
  }
</style>
