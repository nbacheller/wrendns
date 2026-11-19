<script lang="ts">
  // REQ: API-902, API-006, AGT-009 (T27.13; ADR-914, ADR-956) — Settings → System → Guarded settings
  // (admins only: an operator or viewer sees nothing here, and the server refuses them anyway). It
  // shows what the framework knows about this node: whether a file sets a guarded setting (the control
  // is locked and says so), a window change waiting for its confirmation, changes waiting for a
  // restart (with "Restart now" only where the node declares a supervisor), the latest outcomes with
  // their reasons, and the recovery steps. A setting's own form (T27.14 to T27.17) uses GuardedChange
  // on its own page; the end-to-end build lists its test settings here.
  import { onMount } from 'svelte';
  import {
    guarded,
    hasItems,
    hasSupervisor,
    reasonText,
    refreshGuarded,
    selectGuardedNode,
    targetNode,
    watchGuarded,
  } from '../guarded.svelte';
  import GuardedChange from './GuardedChange.svelte';
  import HelpButton from './HelpButton.svelte';

  onMount(() => watchGuarded(2_000));

  const n = $derived(guarded.node);
  // Which node the controls act on: another node's change goes through the primary, which forwards it
  // (the API's `node` field); empty is this node.
  const target = $derived(targetNode());
  const others = $derived(guarded.nodes.filter((x) => x.node !== n?.node && hasItems(x)));
  // The settings this build has a form for: the end-to-end build's test rows. The real ones come with
  // their own pages (T27.14 to T27.17); until then they are listed, read-only.
  const test = $derived((n?.settings ?? []).filter((s) => s.id.startsWith('e2e-')));
  const listed = $derived((n?.settings ?? []).filter((s) => !s.id.startsWith('e2e-') && s.id !== 'restart-now'));

  let label = $state('hello');
  let weaken = $state(false);
  let port = $state(0);
  let fail = $state(false);
  let redirect = $state('');

  const outcomeText = (o: { outcome: string; reason?: string | null }) =>
    o.outcome === 'rolled_back' ? `rolled back: ${reasonText(o.reason)}` : o.outcome;
  const ago = (t: number) => {
    const s = Math.max(0, Math.round(Date.now() / 1000 - t));
    return s < 90 ? `${s} s ago` : s < 5400 ? `${Math.round(s / 60)} min ago` : `${Math.round(s / 3600)} h ago`;
  };
</script>

<section class="card" data-testid="guarded-card">
  <h2>Guarded settings<HelpButton id="guarded-settings" /></h2>
  {#if !n}
    <p class="muted small">{guarded.error || 'Reading…'}</p>
  {:else}
    <p>
      Some settings can lock every admin out, put passwords on the wire, or replace this node's configuration
      (the listeners, the API address and its certificate, trusted proxies, the secrets key, the cluster). They are
      changed with a review, a phrase you type, and (for addresses) a confirmation window that rolls back by itself.
      A configuration file always wins, and is the way back:
      the recovery steps are in the help<HelpButton id="guarded-recovery" />.
    </p>
    {#if guarded.nodes.length > 1}
      <p class="small" data-testid="guarded-node-pick">
        <label>Change settings on
          <select
            aria-label="Node"
            data-testid="guarded-node-picker"
            value={n?.node ?? ''}
            onchange={(e) => selectGuardedNode(e.currentTarget.value)}
          >
            {#each guarded.nodes as x, i (x.node)}
              <option value={x.node}>{x.node}{i === 0 ? ' (this node)' : ''}</option>
            {/each}
          </select>
        </label>
        {#if target}<span class="muted">The change is sent to {target} through the primary, with your sign-in vouched for by it.</span>{/if}
      </p>
      {#if others.length}
        <ul class="small" data-testid="guarded-other-nodes">
          {#each others as x (x.node)}
            <li>
              <button class="link" onclick={() => selectGuardedNode(x.node)}>{x.node}</button>:
              {#if x.pending}a change to {x.pending.setting} waits for confirmation ({x.pending.deadlineSecs} s left){/if}
              {#if x.pendingRestart.length}{x.pending ? '; ' : ''}pending restart: {x.pendingRestart.join(', ')}{/if}
              {#if x.restarting}{x.pending || x.pendingRestart.length ? '; ' : ''}restarting{/if}
            </li>
          {/each}
        </ul>
      {/if}
    {/if}
    <p class="small muted" data-testid="guarded-supervisor">
      Node <strong>{n.node}</strong>. Supervisor:
      {#if hasSupervisor(n)}<strong>{n.supervisor.kind}</strong> ({n.supervisor.how}).
      {:else}none declared ({n.supervisor.how}): a staged change waits until you restart the node yourself.{/if}
    </p>
    {#if n.ignored}
      <div class="notice warn" role="status" data-testid="guarded-ignored">
        <code>WRENDNS_IGNORE_GUARDED=1</code> is set: this node ignores every stored guarded setting and runs on its
        configuration files (nothing is deleted). Remove the variable and restart to use them again.
      </div>
    {/if}
    {#if n.pending}
      <div class="notice warn" role="status" data-testid="guarded-pending-item">
        A change to <strong>{n.pending.setting}</strong> by {n.pending.by} waits for confirmation:
        <strong>{n.pending.deadlineSecs}</strong> seconds left. If it isn't confirmed through the new address it rolls back.
      </div>
    {/if}
    {#if n.restarting}
      <div class="notice warn" role="status" data-testid="guarded-restarting-item">This node is restarting.</div>
    {/if}
    {#if n.pendingRestart.length}
      <div class="notice" data-testid="guarded-restart-item">
        <strong>Pending restart:</strong> {n.pendingRestart.join(', ')}. {n.pendingRestart.length === 1 ? 'It takes' : 'They take'}
        effect when the node starts again.
        {#if !hasSupervisor(n)}
          <div class="muted small" data-testid="guarded-restart-manual">
            Nothing is declared to start this node again, so it can't restart itself from here: restart it yourself
            (systemd: <code>systemctl restart wrendns</code>; Compose: <code>docker compose restart</code>; Kubernetes:
            delete the pod). If it doesn't come back, see recovery.
          </div>
        {/if}
      </div>
    {/if}
    {#if hasSupervisor(n)}
      <!-- Kept mounted while a restart is under way, so its outcome shows after the node is back. -->
      {#key n.node}
        <GuardedChange id="restart-now" label="Restart now" startLabel="Restart now…" node={target} hideIdle={n.pendingRestart.length === 0} />
      {/key}
    {/if}
    {#if listed.length}
      <table class="small" data-testid="guarded-list">
        <thead><tr><th>Setting</th><th>How it applies</th><th>State</th></tr></thead>
        <tbody>
          {#each listed as s (s.id)}
            <tr>
              <td>{s.label}</td>
              <td>{s.mode}{s.proof ? ` (${s.proof})` : ''}</td>
              <td>
                {#if s.setByFile}<span title={s.paths.join(', ')}>set by file</span>
                {:else if s.pendingRestart}pending restart
                {:else if s.onProbation}on probation
                {:else if s.suppressed}hidden by a local clear
                {:else if s.hasEntry}set here{:else}default{/if}
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    {/if}
    <!-- REQ: API-003, API-902 (T24.44, ADR-1053) — [api] http_redirect: port 80 to HTTPS. -->
    {#each listed.filter((x) => x.id === 'api-http-redirect') as s (s.id)}
      <div class="test" data-testid="guarded-http-redirect" data-setting="api.http_redirect">
        <h4>{s.label}<HelpButton id="api-http-redirect" />{#if s.setByFile} <span class="muted small" data-testid="guarded-set-by-file">(set by file)</span>{/if}</h4>
        <label class="small">Address (empty: off)
          <input bind:value={redirect} placeholder="0.0.0.0:80" aria-label="HTTP redirect address" disabled={s.setByFile} />
        </label>
        <GuardedChange id={s.id} label={s.label} value={{ address: redirect.trim() }} node={target} disabled={s.setByFile} />
      </div>
    {/each}
    {#if n.outcomes.length}
      <h3>Latest outcomes</h3>
      <ul class="small" data-testid="guarded-outcomes">
        {#each n.outcomes.slice(0, 5) as o, i (i)}
          <li>{o.setting}: {outcomeText(o)} <span class="muted">({ago(o.at)})</span></li>
        {/each}
      </ul>
    {/if}
    {#if test.length}
      <!-- The end-to-end build's test settings: they exist only in a build with the `e2e` feature. -->
      <h3 data-testid="guarded-test-settings">Test settings (end-to-end builds only)</h3>
      {#each test as s (s.id)}
        <div class="test" data-testid="guarded-test-{s.id}">
          <h4>{s.label}{#if s.setByFile} <span class="muted small" data-testid="guarded-set-by-file">(set by file)</span>{/if}</h4>
          {#if s.id === 'e2e-window'}
            <label class="small">Port <input type="number" bind:value={port} aria-label="Test port" disabled={s.setByFile} /></label>
            <GuardedChange id={s.id} label={s.label} value={{ port }} node={target} disabled={s.setByFile} />
          {:else if s.id === 'e2e-staged'}
            <label class="small">Label <input bind:value={label} aria-label="Test label" disabled={s.setByFile} /></label>
            <label class="check small"><input type="checkbox" bind:checked={fail} disabled={s.setByFile} /> The next start fails</label>
            <GuardedChange id={s.id} label={s.label} value={{ label, fail }} node={target} disabled={s.setByFile} />
          {:else}
            <label class="small">Label <input bind:value={label} aria-label="Test label" disabled={s.setByFile} /></label>
            <label class="check small"><input type="checkbox" bind:checked={weaken} disabled={s.setByFile} /> Weakens security</label>
            <GuardedChange id={s.id} label={s.label} value={{ label, weaken }} node={target} disabled={s.setByFile} />
          {/if}
        </div>
      {/each}
    {/if}
  {/if}
  <button class="link small" onclick={refreshGuarded}>Refresh</button>
</section>

<style>
  .test {
    border-top: 1px solid var(--line, #ddd);
    padding: 8px 0;
  }
  label {
    display: inline-grid;
    gap: 4px;
    margin: 4px 12px 4px 0;
  }
  .check {
    display: inline-flex;
    gap: 6px;
    align-items: center;
  }
  table {
    border-collapse: collapse;
    margin: 8px 0;
  }
  th,
  td {
    text-align: left;
    padding: 2px 12px 2px 0;
  }
</style>
