<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<script lang="ts">
  // REQ: API-902, API-901, API-003 (T27.14f; ADR-914, ADR-956, ADR-977, ADR-1098) — Settings, System, Web UI and
  // API (admins): how this node serves the UI and API, the HTTP to HTTPS redirect (moved here from the guarded
  // card) and the trusted proxies, a list of CIDRs changed through the review step (`GuardedChange`, id
  // `trusted-proxies`) as the whole list. Nothing reaches the server before Review. An address typed wrong is
  // caught here; the server checks every entry again. A file that sets `[api] trusted_proxies` locks the list. A
  // node that does not report the `api` block (an older build) shows the redirect form only. With another node
  // picked (T27.14g0, owner decision 2026-11-27) the card shows that node's values, read through the primary
  // (admin only), and stages changes for it; the confirm of such a change is done on that node itself, through
  // the address it announces. An older member cannot report them: the card says so and changes nothing.
  import { onMount } from 'svelte';
  import type { S } from '../api';
  import { guarded, loadNodeApi, nodeApi, nodeUrl, refreshGuarded, targetNode } from '../guarded.svelte';
  import GuardedChange from './GuardedChange.svelte';
  import HelpButton from './HelpButton.svelte';
  import NodePick from './NodePick.svelte';

  let { web, probes = [], onChanged = undefined }: { web?: S['ApiInfo'] | null; probes?: S['ProbeResult'][]; onChanged?: () => void } = $props();

  onMount(() => void refreshGuarded());
  const target = $derived(targetNode());
  const setting = (n: typeof guarded.node, id: string) => n?.settings.find((s) => s.id === id);
  // Both forms act on the picked node, so their lock and label come from that node. The values shown are the picked
  // node's: this node's from the system information, another's from the per-node read (an older member has none).
  const redirectRow = $derived(setting(guarded.node, 'api-http-redirect'));
  const proxiesRow = $derived(setting(guarded.node, 'trusted-proxies'));
  const view = $derived<S['ApiInfo'] | null | undefined>(target ? nodeApi.data?.api : web);
  const nodeUnread = $derived(!!target && !nodeApi.data);
  const url = $derived(nodeUrl(target));
  const changed = () => {
    if (target) void loadNodeApi(target, true);
    onChanged?.();
  };

  let redirect = $state('');
  const inForce = $derived(JSON.stringify(view?.trustedProxies ?? []));
  let draft = $state<string[]>([]);
  let typed = $state('');
  $effect(() => {
    void inForce;
    draft = JSON.parse(inForce) as string[];
    typed = '';
  });
  // An IPv4 or IPv6 address with an optional prefix length.
  function ok(v: string): boolean {
    const [a, p, more] = v.split('/');
    if (more !== undefined || !a) return false;
    const v4 = /^\d{1,3}(\.\d{1,3}){3}$/.test(a) && a.split('.').every((o) => Number(o) < 256);
    const v6 = !v4 && a.includes(':') && /^[0-9a-f:.]+$/i.test(a) && a.split(':').length < 9;
    if (!v4 && !v6) return false;
    return p === undefined || (/^\d{1,3}$/.test(p) && Number(p) <= (v4 ? 32 : 128));
  }
  const bad = $derived(typed.trim() !== '' && !ok(typed.trim()));
  const dirty = $derived(JSON.stringify(draft) !== inForce);
  const apiProbe = $derived(probes.find((p) => p.proto === 'api'));
  function add() {
    const v = typed.trim();
    if (!ok(v) || draft.includes(v)) return;
    draft = [...draft, v];
    typed = '';
  }
</script>

<section class="card" data-testid="web-api-card">
  <h2>Web UI and API</h2>
  <NodePick testid="web-api-node" />
  {#if view}
    <dl class="sys" data-testid="web-api-facts">
      <dt>Address</dt><dd class="mono">{view.scheme}://{view.listen}{#if target && url} (<a href={url} target="_blank" rel="noopener noreferrer" data-testid="web-api-node-url">open</a>){/if}</dd>
      {#if view.certificate}<dt>Certificate</dt><dd>{view.certificate}{#if !target && apiProbe?.certDaysLeft != null}, {apiProbe.certDaysLeft} days left{/if}</dd>{/if}
    </dl>
  {/if}
  <div data-testid="guarded-http-redirect" data-setting="api.http_redirect">
    <h3>{redirectRow?.label ?? 'HTTP to HTTPS redirect'}<HelpButton id="api-http-redirect" />{#if redirectRow?.setByFile} <span class="muted small" data-testid="guarded-set-by-file">(set by file)</span>{/if}</h3>
    {#if target && nodeUnread}<p class="small muted" data-testid="redirect-other">This form acts on {target}; the value it runs now is not shown (see above).</p>
    {:else if view?.httpRedirect}<p class="small">Now{#if target} on {target}{/if}: <span class="mono">{view.httpRedirect}</span></p>{/if}
    <label class="small">Address (empty: off)
      <input bind:value={redirect} placeholder="0.0.0.0:80" aria-label="HTTP redirect address" disabled={redirectRow?.setByFile} />
    </label>
    <GuardedChange id="api-http-redirect" label="HTTP to HTTPS redirect" value={{ address: redirect.trim() }} node={target} disabled={(redirectRow?.setByFile ?? true) || nodeUnread} onDone={changed} />
  </div>
  {#if view}
    <div data-testid="trusted-proxies" data-setting="api.trusted_proxies">
      <h3>Trusted proxies<HelpButton id="trusted-proxies" />{#if proxiesRow?.setByFile} <span class="muted small" data-testid="trusted-proxies-file">(set by file)</span>{/if}</h3>
      <p class="small muted">Hosts whose <code>X-Forwarded-For</code> the node believes: it takes the client's address from there (sign-in lockouts, the break-glass networks and the audit log). List only your own proxy or ingress.</p>
      <ul class="plain mono">
        {#each draft as n, i (i)}
          <li data-testid="trusted-proxies-row">{n}{#if !proxiesRow?.setByFile} <button class="link" aria-label="Remove {n}" data-testid="trusted-proxies-remove" onclick={() => (draft = draft.filter((_, j) => j !== i))}>Remove</button>{/if}</li>
        {/each}
        {#if !draft.length}<li class="muted">none: the connection's address is the client</li>{/if}
      </ul>
      {#if !proxiesRow?.setByFile}
        <form onsubmit={(e) => { e.preventDefault(); add(); }}>
          <input bind:value={typed} placeholder="10.0.0.0/8 or 192.0.2.7" aria-label="Proxy address or network" aria-invalid={bad} data-testid="trusted-proxies-input" />
          <button disabled={!typed.trim() || bad} data-testid="trusted-proxies-add">Add</button>
          {#if bad}<span class="small" role="alert" data-testid="trusted-proxies-bad">Not an address or network (for example 10.0.0.0/8).</span>{/if}
        </form>
      {/if}
      {#if target && !nodeUnread}<p class="small muted" data-testid="trusted-proxies-other">The list above is {target}'s, as it runs it now. The change is applied on {target}, and confirmed there: the node must see your request through the new list, so the confirm cannot be relayed.</p>{/if}
      <GuardedChange id="trusted-proxies" label="Trusted proxies" value={{ proxies: draft }} node={target} disabled={!dirty || !!proxiesRow?.setByFile || nodeUnread} onDone={changed} />
    </div>
  {/if}
</section>
