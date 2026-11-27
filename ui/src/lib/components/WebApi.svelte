<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<script lang="ts">
  // REQ: API-902, API-901, API-003 (T27.14f; ADR-914, ADR-956, ADR-977, ADR-1098) — Settings, System, Web UI and
  // API (admins): how this node serves the UI and API, the HTTP to HTTPS redirect (moved here from the guarded
  // card) and the trusted proxies, a list of CIDRs changed through the review step (`GuardedChange`, id
  // `trusted-proxies`) as the whole list. Nothing reaches the server before Review. An address typed wrong is
  // caught here; the server checks every entry again. A file that sets `[api] trusted_proxies` locks the list. A
  // node that does not report the `api` block (an older build) shows the redirect form only.
  import { onMount } from 'svelte';
  import type { S } from '../api';
  import { guarded, refreshGuarded, targetNode } from '../guarded.svelte';
  import GuardedChange from './GuardedChange.svelte';
  import HelpButton from './HelpButton.svelte';

  let { web, probes = [], onChanged = undefined }: { web?: S['ApiInfo'] | null; probes?: S['ProbeResult'][]; onChanged?: () => void } = $props();

  onMount(() => void refreshGuarded());
  const target = $derived(targetNode());
  const setting = (n: typeof guarded.node, id: string) => n?.settings.find((s) => s.id === id);
  // The redirect form acts on the picked node (as the guarded card did), so its lock and label come from that
  // node; the trusted-proxies list acts on this node only (the first listed), so its lock comes from this node.
  const redirectRow = $derived(setting(guarded.node, 'api-http-redirect'));
  const proxiesRow = $derived(setting(guarded.nodes[0] ?? guarded.node, 'trusted-proxies'));

  let redirect = $state('');
  const inForce = $derived(JSON.stringify(web?.trustedProxies ?? []));
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
  {#if web}
    <dl class="sys" data-testid="web-api-facts">
      <dt>Address</dt><dd class="mono">{web.scheme}://{web.listen}</dd>
      {#if web.certificate}<dt>Certificate</dt><dd>{web.certificate}{#if apiProbe?.certDaysLeft != null}, {apiProbe.certDaysLeft} days left{/if}</dd>{/if}
    </dl>
  {/if}
  <div data-testid="guarded-http-redirect" data-setting="api.http_redirect">
    <h3>{redirectRow?.label ?? 'HTTP to HTTPS redirect'}<HelpButton id="api-http-redirect" />{#if redirectRow?.setByFile} <span class="muted small" data-testid="guarded-set-by-file">(set by file)</span>{/if}</h3>
    {#if target}<p class="small muted" data-testid="redirect-other">This form acts on {target}; the value it runs now is not shown here.</p>
    {:else if web?.httpRedirect}<p class="small">Now: <span class="mono">{web.httpRedirect}</span></p>{/if}
    <label class="small">Address (empty: off)
      <input bind:value={redirect} placeholder="0.0.0.0:80" aria-label="HTTP redirect address" disabled={redirectRow?.setByFile} />
    </label>
    <GuardedChange id="api-http-redirect" label="HTTP to HTTPS redirect" value={{ address: redirect.trim() }} node={target} disabled={redirectRow?.setByFile ?? true} />
  </div>
  {#if web}
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
      {#if target}<p class="small muted" data-testid="trusted-proxies-other">The list above is this node's. Pick this node in Guarded settings to change it: a list is changed on the node you are signed in to.</p>{/if}
      <GuardedChange id="trusted-proxies" label="Trusted proxies" value={{ proxies: draft }} disabled={!dirty || !!proxiesRow?.setByFile || !!target} onDone={() => onChanged?.()} />
    </div>
  {/if}
</section>
