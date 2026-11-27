<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<script lang="ts">
  // REQ: DSC-914 (T36.10c) — the Locations page is a lazy-loaded chunk: its code loads when the route is
  // first opened, so the rest of the console doesn't carry it.
  const page = import('./Locations.svelte');
</script>

{#await page then m}
  {@const Page = m.default}
  <Page />
{:catch error}
  <div class="page"><p role="alert">The Locations page didn't load: {String(error)}</p></div>
{/await}
