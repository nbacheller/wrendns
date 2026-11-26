<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<script lang="ts">
  // REQ: DNS-901, API-902 (T27.14; ADR-1090 point 1, ADR-914, ADR-956) — the known-ID gate of each
  // listener, changed through the guarded framework: three states per DoT, DoH, DoH3 or DoQ listener
  // (default, on, off), what "default" resolves to for that listener and why, the red "open resolver"
  // warning when a public listener's gate is turned off, and one review (the phrase, the sign-in prompt
  // when it weakens, the audit record) for the whole set. Plain UDP and TCP can't carry a key and show
  // no control. A configuration file that sets `require_client_id` locks it ("set by file"). It acts on
  // this node: the listeners shown are this node's.
  import { onMount } from 'svelte';
  import type { S } from '../api';
  import { guarded, refreshGuarded } from '../guarded.svelte';
  import GuardedChange from './GuardedChange.svelte';
  import HelpButton from './HelpButton.svelte';

  let { rows, onChanged = undefined }: { rows: S['ListenerAccess'][]; onChanged?: () => void } = $props();

  type Choice = 'default' | 'on' | 'off';
  const fromSetting = (s: string): Choice => (s === 'true' ? 'on' : s === 'false' ? 'off' : 'default');
  const parts = (l: S['ListenerAccess']) => {
    const i = l.listener.indexOf('://');
    return { proto: l.listener.slice(0, i), addr: l.listener.slice(i + 3) };
  };

  let choice = $state<Record<string, Choice>>({});
  // Start from what is in force; follow it again whenever the node's own state changes under us.
  const inForce = $derived(rows.map((l) => `${l.listener}=${l.setting}`).join('|'));
  $effect(() => {
    void inForce;
    choice = Object.fromEntries(rows.map((l) => [l.listener, fromSetting(l.setting)]));
  });

  onMount(() => {
    void refreshGuarded();
  });

  const here = $derived(guarded.nodes[0] ?? guarded.node);
  const setting = $derived(here?.settings.find((s) => s.id === 'listen-access'));
  const setByFile = $derived(!!setting?.setByFile);

  const value = $derived({
    listeners: rows.map((l) => ({
      ...parts(l),
      require_client_id: !l.canCarryKey ? null : choice[l.listener] === 'on' ? true : choice[l.listener] === 'off' ? false : null,
    })),
  });
  const changed = $derived(rows.some((l) => l.canCarryKey && (choice[l.listener] ?? 'default') !== fromSetting(l.setting)));

  /** What the default is for this listener, and why (the node's sentence: it names the wildcard rule). */
  const defaultText = (l: S['ListenerAccess']): string => l.defaultReason;
  const defaultOn = (l: S['ListenerAccess']) => l.defaultOn;
  /** What the choice makes of this listener once applied. */
  const resulting = (l: S['ListenerAccess']): boolean => {
    const c = choice[l.listener] ?? 'default';
    return c === 'on' || (c === 'default' && defaultOn(l));
  };
</script>

<div data-testid="listener-gate" class="gate">
  <h3>Change who may query a listener<HelpButton id="listener-keys" /></h3>
  {#if setByFile}
    <div class="notice" role="status" data-testid="listener-gate-file">
      <strong>Set by file.</strong> A configuration file sets <code>require_client_id</code> on a listener, and the file wins:
      change it there. Removing the line there hands the control back to this page.
    </div>
  {/if}
  <p class="small muted">
    <strong>Default</strong> follows the address: on for a public one, off otherwise. A listener that binds every address is on when this host has a public IPv4 address, and off when it has only private IPv4 addresses (a global IPv6 address alone does not turn it on). <strong>On</strong> answers a query only when it carries a
    known device key, from any address. <strong>Off</strong> leaves the listener to the allowed networks alone.
  </p>
  <div class="table-wrap">
    <table class="compact">
      <thead><tr><th>Listener</th><th>Device key</th><th>The default would be</th></tr></thead>
      <tbody>
        {#each rows as l (l.listener)}
          <tr data-testid="listener-gate-row" data-listener={l.listener}>
            <td class="mono">{l.listener}</td>
            <td>
              {#if l.canCarryKey}
                <select
                  aria-label="Device key for {l.listener}"
                  data-testid="listener-gate-select"
                  bind:value={choice[l.listener]}
                  disabled={setByFile}
                >
                  <option value="default">Default</option>
                  <option value="on">On: a known key only</option>
                  <option value="off">Off: allowed networks only</option>
                </select>
                {#if changed && resulting(l) !== l.requireClientId}
                  <span class="small muted" data-testid="listener-gate-result">
                    becomes {resulting(l) ? 'on' : 'off'}
                  </span>
                {/if}
                {#if choice[l.listener] === 'off' && l.publicExposure}
                  <div class="notice warn small" data-testid="listener-gate-open-warning">
                    This listener is on a public address, or binds every address on a host with a public IPv4 address. With the device key off, only the allowed networks keep it from being an open resolver for the whole internet.
                  </div>
                {/if}
              {:else}
                <span class="muted small" data-testid="listener-gate-plain">not available: a plain UDP or TCP query carries no device key</span>
              {/if}
            </td>
            <td class="small" data-testid="listener-gate-default">
              {#if l.canCarryKey}{defaultText(l)}{/if}
            </td>
          </tr>
        {/each}
      </tbody>
    </table>
  </div>
  {#if !changed && !setByFile}<p class="muted small">Pick a state for a listener to review the change.</p>{/if}
  <GuardedChange id="listen-access" label="Listener device keys" {value} disabled={setByFile || !changed} onDone={() => onChanged?.()} />
</div>

<style>
  .gate {
    border-top: 1px solid var(--border);
    margin-top: var(--space-3);
    padding-top: var(--space-2);
  }
  select {
    max-width: 260px;
  }
</style>
