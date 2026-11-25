<script lang="ts">
  // REQ: API-005, CLU-002, OBS-033 (ADR-157) — the dashboard's view controls: node (or site), device
  // group, time range, and the Changes switch with Note….
  import { RANGES, type DashData } from './data.svelte';
  import type { S } from '../api';
  import ChangesControls from '../components/ChangesControls.svelte';
  import Picker from '../components/Picker.svelte';

  let { d, part = 'all' }: { d: DashData; part?: 'all' | 'range' | 'filters' } = $props();

  const nodeLabel = (n: S['ClusterView']['nodes'][number]) =>
    (n.ephemeral ? `${n.site} pod ${n.pod ?? n.nodeId.slice(0, 8)}` : n.site) +
    (n.role.includes('primary') ? ' (primary)' : '') +
    (n.thisNode ? ' · this node' : '');
  const podSites = $derived([...new Set(d.nodes.filter((n) => n.ephemeral).map((n) => n.site))]);
</script>

<div class="ctl">
  {#if part !== 'range'}
    {#if d.nodes.length > 1}
      <label class="pill-field">
        Showing
        <select bind:value={d.scope} aria-label="Nodes">
          <option value="">every node</option>
          {#each d.nodes as n (n.nodeId)}<option value={`node:${n.nodeId}`}>{nodeLabel(n)}</option>{/each}
          {#each podSites as s (s)}<option value={`site:${s}`}>site {s} (all its nodes)</option>{/each}
        </select>
      </label>
    {/if}
    {#if d.groups.length > 1}
      <div class="pill-field">
        Top lists for
        <Picker label="Group" multiple={false} clearable placeholder="Every device" hint="Type to search; empty means every device."
          items={d.groups.map((g) => ({ value: g.name, label: g.name, kind: 'groups' }))} selected={d.group ? [d.group] : []} onchange={(n) => (d.group = n[0] ?? '')} />
      </div>
    {/if}
  {/if}
  {#if part !== 'filters'}
    <div class="seg" role="group" aria-label="Time range">
      {#each RANGES as r (r.id)}
        <button aria-pressed={d.range.id === r.id} onclick={() => (d.range = r)}>{r.label}</button>
      {/each}
    </div>
    <ChangesControls />
  {/if}
</div>

<style>
  .ctl {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 8px;
  }
  /* On a phone the range scrolls inside its own track instead of wrapping into two rows. */
  .seg {
    max-width: 100%;
    overflow-x: auto;
    scrollbar-width: none;
  }
  .seg button {
    flex: none;
  }
</style>
