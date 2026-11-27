<script lang="ts">
  import Icon from './Icon.svelte';
  // FLT-013: why a name is or isn't blocked for a client, every matching rule, and the route.
  import type { S } from '../api';
  import { dateTime } from '../format';
  import StatusBadge from './StatusBadge.svelte';
  import FlowDiagram from './FlowDiagram.svelte';
  import type { FlowPath } from '../help';
  import { href } from '../router.svelte';
  import PolicyLine from './PolicyLine.svelte';
  import RecursorTrace from './RecursorTrace.svelte';

  let { x }: { x: S['Explanation'] } = $props();

  const tierLabel: Record<string, string> = {
    important_allow: 'allow (important)',
    important_block: 'block (important)',
    allow: 'allow',
    block: 'block',
  };

  // REQ: API-011 — the decision as a diagram: which way this query goes.
  const path = $derived<FlowPath>(
    x.outcome === 'refused'
      ? 'refused'
      : x.outcome === 'blocked'
        ? 'blocked'
        : x.outcome === 'local' || x.outcome === 'special'
          ? 'local'
          : x.route?.routed
            ? 'route'
            : 'upstream',
  );
  // REQ: DNS-019 (T24.12, ADR-904) — the special-name rule that answered, and its switch.
  const specialSwitch: Record<string, string> = {
    private_relay: 'Block iCloud Private Relay names',
    single_label: 'Keep one-label names off the internet',
    firefox_canary: "Answer Firefox's DoH canary NXDOMAIN",
    private_ptr: 'Private reverse lookups get NXDOMAIN',
    chaos: 'Refuse CHAOS queries',
    localhost: 'Answer localhost',
    ddr: 'Encrypted DNS name (DDR)',
  };
  const detail = $derived(
    x.outcome === 'blocked' && x.block
      ? `list ${x.block.list}`
      : x.outcome === 'special'
        ? 'a special-use name WrenDNS answers itself'
        : x.route
          ? `upstream group ${x.route.group}`
          : '',
  );
</script>

<div class="explain">
  <div class="notice {x.outcome === 'blocked' || x.outcome === 'refused' ? 'bad' : 'ok'}">
    <div class="row">
      <StatusBadge value={x.outcome} />
      <strong>{x.summary}</strong>
    </div>
    {#if x.pausedUntilUnixSeconds}
      <div class="muted small">Blocking is paused for this client until {dateTime(x.pausedUntilUnixSeconds)}.</div>
    {/if}
  </div>

  {#if x.outcome === 'special'}
    <section class="card" data-testid="explain-special">
      <h3>Special name</h3>
      {#if x.special && specialSwitch[x.special]}
        <p>
          This is answered by the special-name rule <strong>{specialSwitch[x.special]}</strong>.
          <a href={href('/settings', { tab: 'queries' })} data-testid="explain-special-switch">Its switch is in Settings</a>.
        </p>
      {:else if x.special === 'resolver_arpa'}
        <p>resolver.arpa is answered here and never forwarded (RFC 9462). Its switch is the encrypted DNS name in Settings.</p>
        <p><a href={href('/settings', { tab: 'queries' })}>Special names in Settings</a></p>
      {:else}
        <p>A special-use name, answered without forwarding.</p>
      {/if}
      <p><a href={href('/queries', { status: 'special' })} data-testid="explain-special-log">Special answers in the query log</a></p>
    </section>
  {/if}

  <section class="card" data-testid="explain-flow">
    <FlowDiagram highlight={path} device={['neighbor_mac', 'edns_mac', 'client_id'].includes(x.client.identifiedBy) ? (x.client.device ?? x.client.ip) : x.client.ip} name={x.name} {detail} />
  </section>

  <section class="card">
    <h3>Client</h3>
    <dl>
      <dt>Address</dt>
      <dd class="mono">{x.client.ip}</dd>
      {#if x.client.mac}<dt>MAC</dt><dd class="mono">{x.client.mac}</dd>{/if}
      <dt>Device</dt>
      <dd>{x.client.device ?? 'not a configured device'} <span class="muted small">(by {x.client.identifiedBy})</span></dd>
      <dt>Groups</dt>
      <dd>{x.client.groups.join(', ') || '–'}</dd>
    </dl>
    <!-- REQ: FLT-006, API-010 (T24.30, ADR-996) — the policy step: the group, where it came from and the key that matched. -->
    {#if x.client.group}
      <PolicyLine
        device={x.client.device ?? x.client.ip}
        group={x.client.group}
        groupFrom={x.client.groupFrom}
        groupKey={x.client.groupKey}
        matchedKey={x.client.matchedKey}
        identifiedBy={x.client.identifiedBy}
      />
    {/if}
    <dl>
      <dt>Query</dt>
      <dd><span class="mono">{x.name}</span> {x.qtype}</dd>
    </dl>
  </section>

  {#if x.block}
    <section class="card">
      <h3>Block response</h3>
      <dl>
        <dt>List</dt>
        <dd>{x.block.list}</dd>
        <dt>Answer</dt>
        <dd>{x.block.mode} · TTL {x.block.ttlSeconds} s · EDE {x.block.edeCode}</dd>
      </dl>
    </section>
  {/if}

  <section class="card">
    <h3>Matching rules</h3>
    {#if !x.filter && ['local', 'special', 'refused'].includes(x.outcome)}
      <p class="muted">Not checked: this query is answered before filtering.</p>
    {:else if !x.filter}
      <p class="muted">No filter snapshot is loaded yet.</p>
    {:else if x.filter.rules.length === 0}
      <p class="muted">No list has a rule for this name (snapshot {x.filter.snapshot ?? '–'}).</p>
    {:else}
      <p class="muted small">Snapshot {x.filter.snapshot ?? '–'}, in precedence order. The starred rule decides; muted lists aren't used by this client.</p>
      <ul class="rules">
        {#each x.filter.rules as r, i (i)}
          <li class:winner={r.winner} class:off={!r.enabled}>
            <div class="row">
              <span class="mark">{#if r.winner}<span role="img" aria-label="Decides" data-testid="rule-winner"><Icon name="star" size={16} /></span>{/if}</span>
              <span class="badge {r.tier.includes('allow') ? 'ok' : 'bad'}">{tierLabel[r.tier] ?? r.tier}</span>
              <strong>{r.list}</strong>
              <!-- REQ: OBS-018 — a shadow list's rule is counted, never enforced. -->
              {#if r.shadow}<span class="badge info" title="This list is in shadow mode: it never blocks">shadow</span>{/if}
              {#if r.name}<span class="mono">{r.name}</span>{/if}
              <span class="muted small">{r.kind}{r.scope ? ` · ${r.scope}` : ''}</span>
            </div>
            {#each r.lines as l (l.line)}
              <div class="line mono"><span class="muted">{r.list}:{l.line}</span> {l.text}</div>
            {/each}
          </li>
        {/each}
      </ul>
    {/if}
    {#each x.filter?.notes ?? [] as n, i (i)}<p class="muted small">{n}</p>{/each}
  </section>

  {#if x.route}
    <section class="card">
      <h3>Route</h3>
      <p>Upstream group <strong>{x.route.group}</strong> {x.route.routed ? '(matched a route)' : '(default)'}</p>
      <!-- REQ: DNS-904 (T40.3) — the built-in resolver's walk, only when asked for. -->
      {#key `${x.name}/${x.qtype}`}<RecursorTrace name={x.name} qtype={x.qtype} />{/key}
    </section>
  {/if}

  {#each x.notes as n, i (i)}<p class="muted small">{n}</p>{/each}
</div>

<style>
  .explain {
    display: grid;
    gap: 12px;
  }
  dl {
    display: grid;
    grid-template-columns: max-content 1fr;
    gap: 4px 14px;
    margin: 0;
  }
  dt {
    color: var(--muted);
    font-size: 12.5px;
  }
  dd {
    margin: 0;
    word-break: break-all;
  }
  .rules {
    list-style: none;
    margin: 0;
    padding: 0;
    display: grid;
    gap: 8px;
  }
  .rules li {
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    padding: 8px 10px;
  }
  .rules li.winner {
    border-color: var(--accent);
  }
  .rules li.off {
    color: var(--muted);
  }
  .mark {
    display: inline-flex;
    width: 16px;
    color: var(--text);
  }
  .line {
    margin-top: 4px;
    word-break: break-all;
  }
</style>
