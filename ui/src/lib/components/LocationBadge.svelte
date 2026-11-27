<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<script lang="ts">
  // REQ: DSC-914, DSC-910 (T36.10c) — a device's location as a badge; a pinned device says so.
  import type { Loc } from '../locations.svelte';
  let { loc }: { loc: Loc | null | undefined } = $props();
</script>

{#if loc}<a class="badge info" href="#/locations" data-testid="location-badge" title={loc.pinned ? 'Pinned to this location on the device' : 'The location whose network holds its address'}>{loc.label}{loc.pinned ? ' (pinned)' : ''}</a>{/if}
