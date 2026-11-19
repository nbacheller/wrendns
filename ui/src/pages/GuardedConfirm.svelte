<script lang="ts">
  // REQ: API-902 (T27.13; ADR-956 §3, §9) — the confirm step, opened from the link a window change
  // gives. It is the page on the NEW address: the admin has no session on a new origin, so the
  // single-use token in the URL's #fragment stands in for it. The fragment is never sent to a server
  // or a log. A request that arrives here proves the admin can reach the node through the new address;
  // that is the whole point of the window.
  import { api, ApiError } from '../lib/api';
  import { route } from '../lib/router.svelte';
  import ErrorNote from '../lib/components/ErrorNote.svelte';
  import HelpButton from '../lib/components/HelpButton.svelte';

  const id = $derived(route.params.get('id') ?? '');
  const token = $derived(route.params.get('t') ?? '');
  let busy = $state(false);
  let error = $state<unknown>(null);
  let done = $state<{ setting: string; node: string; seen?: string | null } | null>(null);
  let gone = $state(false);

  async function confirm() {
    busy = true;
    error = null;
    try {
      const r = await api.guardedConfirm(id, token);
      done = { setting: r.setting, node: r.node, seen: r.seenClient };
    } catch (e) {
      if (e instanceof ApiError && e.status === 404) gone = true;
      else error = e;
    } finally {
      busy = false;
    }
  }
</script>

<main class="center" data-testid="guarded-confirm-page">
  <section class="card">
    <h1>Confirm the change<HelpButton id="guarded-settings" /></h1>
    {#if !id || !token}
      <div class="notice bad">This link is missing its change or its token. Use the link from the page where you made the change.</div>
    {:else if done}
      <div class="notice ok" role="status" data-testid="guarded-confirmed">
        Confirmed. The change to <strong>{done.setting}</strong> on {done.node} is kept: this address is where WrenDNS answers now.
        {#if done.seen}<div class="small">The node sees this request as coming from {done.seen}.</div>{/if}
      </div>
      <p><a class="button primary" href="#/settings?tab=system">Open Settings</a></p>
    {:else if gone}
      <div class="notice bad" role="alert" data-testid="guarded-confirm-gone">
        Nothing is waiting for confirmation here: it was already confirmed, cancelled, or the time ran out and it rolled back.
        Open the settings page on the address you started from to see why.
      </div>
    {:else}
      <p>
        You reached this node through the new address, which is what the change needed to prove. Confirm to keep it; if you
        don't, it rolls back by itself when the time runs out.
      </p>
      <p>
        <button class="primary" disabled={busy} onclick={confirm} data-testid="guarded-confirm-button">{busy ? 'Working…' : 'Confirm the change'}</button>
      </p>
      <ErrorNote {error} />
    {/if}
  </section>
</main>
