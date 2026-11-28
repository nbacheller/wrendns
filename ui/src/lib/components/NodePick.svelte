<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<script lang="ts">
  // REQ: API-902, API-901 (T27.14g0; owner decision, 2026-11-27) — the node the Web UI and API card and the
  // Listeners card show and change: this node, or another member of the cluster (the same pick as in Guarded
  // settings). Shown only in a cluster. Another node's values are read through the primary; the confirm of a
  // change on another node is done on that node itself, through the address it announces.
  import { guarded, loadNodeApi, nodeApi, nodeUrl, selectGuardedNode, targetNode } from '../guarded.svelte';

  let { testid = 'node-pick' }: { testid?: string } = $props();
  const target = $derived(targetNode());
  const url = $derived(nodeUrl(target));
  $effect(() => {
    void loadNodeApi(target);
  });
</script>

{#if guarded.nodes.length > 1}
  <div class="small" data-testid={testid}>
    <label>Show and change the settings of
      <select aria-label="Node" data-testid="{testid}-select" value={guarded.node?.node ?? ''} onchange={(e) => selectGuardedNode(e.currentTarget.value)}>
        {#each guarded.nodes as x, i (x.node)}
          <option value={x.node}>{x.node}{i === 0 ? ' (this node)' : ''}</option>
        {/each}
      </select>
    </label>
    {#if target}
      <span class="muted" data-testid="{testid}-note">
        {#if nodeApi.loading}Reading {target}…
        {:else if nodeApi.error}<span role="alert" data-testid="{testid}-error">{nodeApi.error}</span>
        {:else}The values below are {target}'s, read through the primary. A change is confirmed on {target} itself:
          {#if url}the card links to <a href={url} target="_blank" rel="noopener noreferrer" data-testid="{testid}-link">{url.replace(/^https?:\/\//, '')}</a> for that.
          {:else}it has not announced its web UI address (an older build, or it cannot name one), so open its web UI yourself to confirm.{/if}
        {/if}
      </span>
    {/if}
  </div>
{/if}
