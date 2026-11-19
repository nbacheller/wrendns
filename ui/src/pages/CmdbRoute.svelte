<script lang="ts">
  // REQ: DSC-901 (T31.2) — the CMDB page is a lazy-loaded chunk: its code loads when the route is
  // first opened, so the rest of the console doesn't carry it.
  const page = import('./Cmdb.svelte');
</script>

{#await page then m}
  {@const Page = m.default}
  <Page />
{:catch error}
  <div class="page"><p role="alert">The CMDB page didn't load: {String(error)}</p></div>
{/await}
