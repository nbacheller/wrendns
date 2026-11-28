<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<script lang="ts">
  // REQ: API-902, DNS-001, DNS-901 (T27.14c; ADR-914, ADR-956, ADR-1098) — Settings, System, Listeners: the
  // node's DNS listeners as a table with the probe status, and a draft the admin edits (add, edit, remove)
  // that goes to the review step (`GuardedChange`, id `listen`) as the whole list. Nothing reaches the server
  // before Review. A change that adds and removes offers "Add only" first. Operators and viewers read the
  // table. With another node picked (T27.14g0) the card shows that node's listeners, read through the primary, and
  // stages the change for it; the confirm is done on that node itself. A file that sets `[[listen]]` locks the card. Certificate and key paths, limits and options are an admin's: the others see the address, the protocol, the certificate's name and its expiry. The device key (gate) and PROXY are read-only here.
  import { onMount } from 'svelte';
  import type { S } from '../api';
  import { guarded, loadNodeApi, nodeApi, refreshGuarded, targetNode } from '../guarded.svelte';
  import AllowedNetworks from './AllowedNetworks.svelte';
  import GuardedChange from './GuardedChange.svelte';
  import HelpButton from './HelpButton.svelte';
  import NodePick from './NodePick.svelte';

  let {
    rows: ownRows,
    probes: ownProbes = [],
    editable = false,
    onChanged = undefined,
  }: { rows: S['ListenerAccess'][]; probes?: S['ProbeResult'][]; editable?: boolean; onChanged?: () => void } = $props();

  // The picked node: this node's own rows and probes, or another's, read through the primary (its probes are its own).
  const target = $derived(targetNode());
  const nodeUnread = $derived(!!target && !nodeApi.data);
  const rows = $derived(target ? (nodeApi.data?.listeners ?? []) : ownRows);
  const probes = $derived(target ? [] : ownProbes);
  const changed = () => {
    if (target) void loadNodeApi(target, true);
    onChanged?.();
  };

  type D = { id: number; proto: string; addr: string; cert: string; tkey: string; path: string; max: string; per: string; gone: boolean; fresh: boolean; edit: boolean; from?: S['ListenerAccess'] };
  let seq = 0;
  const PORT: Record<string, string> = { udp: '53', tcp: '53', dot: '853', doq: '853', doh: '443', doh3: '443' };
  const tls = (p: string) => p === 'dot' || p === 'doh' || p === 'doh3' || p === 'doq';
  const http = (p: string) => p === 'doh' || p === 'doh3';
  const split = (l: string) => [l.slice(0, l.indexOf('://')), l.slice(l.indexOf('://') + 3)];
  const mk = (l: S['ListenerAccess']): D => {
    const [proto, addr] = split(l.listener);
    return { id: seq++, proto, addr, cert: l.tlsCert ?? '', tkey: l.tlsKey ?? '', path: l.path ?? '', max: String(l.maxConnections ?? ''), per: String(l.maxConnectionsPerAddress ?? ''), gone: false, fresh: false, edit: false, from: l };
  };
  let draft = $state<D[]>([]);
  let keepOld = $state(true);
  const inForce = $derived(JSON.stringify(rows));
  $effect(() => {
    void inForce;
    draft = rows.map(mk);
    keepOld = true;
  });
  onMount(() => void refreshGuarded());

  const setByFile = $derived(!!guarded.node?.settings.find((s) => s.id === 'listen')?.setByFile);
  const num = (s: string) => (s.trim() ? Number(s) : null);
  const entry = (d: D) => ({
    proto: d.proto,
    addr: d.addr.trim(),
    tls: tls(d.proto) ? { cert: d.cert.trim(), key: d.tkey.trim() } : null,
    path: http(d.proto) && d.path.trim() ? d.path.trim() : null,
    maxConnections: d.proto === 'udp' ? null : num(d.max),
    maxConnectionsPerAddress: d.proto === 'udp' ? null : num(d.per),
  });
  const baseline = $derived(JSON.stringify(rows.map((l) => entry(mk(l)))));
  const addsAndRemoves = $derived(draft.some((d) => d.gone) && draft.some((d) => !d.gone && (d.fresh || d.edit)));
  const value = $derived({ listeners: draft.filter((d) => !d.gone || (addsAndRemoves && keepOld)).map(entry) });
  const dirty = $derived(JSON.stringify(value.listeners) !== baseline);

  const stateOf = (d: D) => (d.gone ? 'to remove' : d.fresh ? 'new' : d.edit ? 'changed' : '');
  // The probe of one listener: its protocol and the whole address it was asked on (a wildcard is asked on loopback).
  const probeOf = (d: D) => {
    const at = d.addr.replace(/^0\.0\.0\.0:/, '127.0.0.1:').replace(/^\[::\]:/, '[::1]:');
    return probes.find((x) => {
      const rest = x.target.replace(/^[a-z0-9]+:\/\//, '');
      return x.listener && x.proto === d.proto && (rest === at || rest.startsWith(`${at}/`));
    });
  };
  const status = (d: D): string => {
    if (d.fresh) return 'not open yet';
    const p = probeOf(d);
    return !p ? '-' : p.skipped ? `not probed: ${p.skipped}` : p.ok ? `answering${p.latencyMs != null ? `, ${p.latencyMs} ms` : ''}` : 'no answer';
  };
  const certText = (d: D) => {
    const p = probeOf(d);
    // The name comes from the file name every role sees; the path itself is an admin's (owner decision, 2026-11-27).
    const name = d.from?.tlsCertName ?? d.cert.slice(d.cert.lastIndexOf('/') + 1);
    return name ? `${name}${p?.certDaysLeft != null ? `, ${p.certDaysLeft} days left` : ''}` : '';
  };
  const setProto = (d: D, p: string) => {
    d.proto = p;
    d.addr = d.addr.replace(/:\d+$/, `:${PORT[p]}`);
  };
  const add = () => (draft = [...draft, { id: seq++, proto: 'dot', addr: `0.0.0.0:${PORT.dot}`, cert: '', tkey: '', path: '', max: '', per: '', gone: false, fresh: true, edit: true }]);
  const drop = (d: D) => (draft = d.fresh ? draft.filter((x) => x !== d) : draft.map((x) => (x === d ? { ...x, gone: !x.gone } : x)));
</script>

<section class="card" data-testid="listeners-card">
  <h2>Listeners<HelpButton id="listeners" /></h2>
  <p class="small muted">
    The addresses and ports this node answers DNS on. A change is tried next to the current listeners and kept only when you confirm it; if you don't, the old ones stay and the new ones close.
  </p>
  {#if setByFile}
    <div class="notice" role="status" data-testid="listeners-file">
      <strong>Set by file.</strong> A configuration file sets <code>[[listen]]</code> and wins. Edit the file and reload to change the listeners.
    </div>
  {/if}
  <NodePick testid="listeners-node" />
  <div class="table-wrap">
    <table class="compact">
      <thead><tr><th>Protocol</th><th>Address</th><th>Certificate</th><th>Device key</th><th>PROXY</th><th>Status</th>{#if editable && !setByFile}<th></th>{/if}</tr></thead>
      <tbody>
        {#each draft as d (d.id)}
          <tr data-testid="listeners-row" data-listener="{d.proto}://{d.addr}" class:muted={d.gone}>
            {#if d.edit}
              <td>
                <select aria-label="Protocol" data-testid="listeners-proto" value={d.proto} disabled={!d.fresh} onchange={(e) => setProto(d, e.currentTarget.value)}>
                  {#each Object.keys(PORT) as p (p)}<option value={p}>{p}</option>{/each}
                </select>
              </td>
              <td><input aria-label="Address" data-testid="listeners-addr" bind:value={d.addr} placeholder="0.0.0.0:853 or [::]:853" /></td>
              <td>
                {#if tls(d.proto)}
                  <input aria-label="Certificate path" data-testid="listeners-cert" bind:value={d.cert} placeholder="/path/to/cert.pem" />
                  <input aria-label="Key path" data-testid="listeners-key" bind:value={d.tkey} placeholder="/path/to/key.pem" />
                  {#if http(d.proto)}<input aria-label="Path" bind:value={d.path} placeholder="/dns-query" />{/if}
                {/if}
                {#if d.proto !== 'udp'}
                  <details><summary class="small">Advanced</summary>
                    <input aria-label="Connections open at once" bind:value={d.max} inputmode="numeric" placeholder="1024" />
                    <input aria-label="Connections per address" bind:value={d.per} inputmode="numeric" placeholder="32" />
                  </details>
                {/if}
              </td>
            {:else}
              <td class="mono">{d.proto}</td>
              <td class="mono">{d.addr}</td>
              <td class="small">{certText(d)}</td>
            {/if}
            <td class="small">{d.from ? (d.from.requireClientId ? 'required' : d.from.canCarryKey ? 'not required' : '') : ''}{#if d.from?.canCarryKey} <a href="#/settings?tab=system">Listener access</a>{/if}</td>
            <td class="small">{d.from?.proxyProtocol ? 'on (file only)' : ''}</td>
            <td class="small" data-testid="listeners-status">{stateOf(d) || status(d)}</td>
            {#if editable && !setByFile}
              <td>
                {#if !d.edit}<button data-testid="listeners-edit" aria-label="Edit {d.proto}://{d.addr}" onclick={() => (d.edit = true)} disabled={d.gone}>Edit</button>{/if}
                <button data-testid="listeners-remove" aria-label="{d.gone ? 'Keep' : 'Remove'} {d.proto}://{d.addr}" onclick={() => drop(d)}>{d.gone ? 'Keep' : 'Remove'}</button>
              </td>
            {/if}
          </tr>
        {/each}
      </tbody>
    </table>
  </div>
  {#if editable && !setByFile && !nodeUnread}
    <button data-testid="listeners-add" onclick={add}>Add listener</button>
    {#if addsAndRemoves}
      <label class="small"><input type="checkbox" bind:checked={keepOld} data-testid="listeners-keep-old" /> Add only, keep the old listeners (recommended): remove them in a later change, once your clients use the new address.</label>
    {/if}
    {#if dirty}
      <p class="small muted">Review sends the whole list. The node asks each new listener a test question itself before you can confirm.</p>
    {/if}
    <GuardedChange id="listen" label="Listeners" {value} node={target} disabled={!dirty} onDone={changed} />
  {/if}
  <p class="small muted">PROXY protocol stays in the configuration file: a PROXY listener trusts the address in each connection's header, so turning it on here would let any client choose its own address.</p>
  <AllowedNetworks summary />
</section>
