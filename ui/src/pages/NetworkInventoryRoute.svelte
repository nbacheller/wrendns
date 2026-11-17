<script lang="ts">
  // REQ: DSC-001 (T25.2) — the Network inventory page is a lazy-loaded chunk: its code loads when
  // the route is first opened, so the rest of the console doesn't carry it.
  const page = import('./NetworkInventory.svelte');
</script>

{#await page then m}
  {@const Page = m.default}
  <Page />
{:catch error}
  <div class="page"><p role="alert">The Network inventory page didn't load: {String(error)}</p></div>
{/await}
