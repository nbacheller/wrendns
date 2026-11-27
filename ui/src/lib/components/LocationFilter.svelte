<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<script lang="ts">
  // REQ: DSC-914 (T36.10c) — the location filter on a list: shown only when the node has locations.
  import { labelOf, locs } from '../locations.svelte';
  let { value = $bindable('') }: { value?: string } = $props();
</script>

{#if locs.items.length}
  <label class="small">
    Location
    <select bind:value aria-label="Location" data-testid="location-filter">
      <option value="">All</option>
      {#each locs.items as l (l.slug)}<option value={l.slug}>{labelOf(l)}</option>{/each}
    </select>
  </label>
{/if}
