<script lang="ts">
  // REQ: API-902, API-006 (T27.13; ADR-914, ADR-956 §9) — the one shell every guarded change goes
  // through: the dry run (what it does, which node, a red "weakens security" mark, the warnings), the
  // phrase to type (paste is allowed; the server checks it), a sign-in prompt when the change needs a
  // recent sign-in, and then, by mode, the result: applied, "pending restart" (with Restart now where
  // the node declares a supervisor), or the confirmation window's countdown (driven by the seconds the
  // server says are left, not by this browser's clock alone) with the link to the new address that
  // carries the single-use token in its #fragment, Confirm and Cancel, and the rollback's reason.
  // A setting's own form gives it `id`, `value` and (optionally) `options`; nothing else is needed.
  import { onDestroy } from 'svelte';
  import { api, ApiError, type S } from '../api';
  import { session, signedIn } from '../session.svelte';
  import { guarded, hasSupervisor, reasonText, refreshGuarded, watchGuarded } from '../guarded.svelte';
  import ErrorNote from './ErrorNote.svelte';
  import HelpButton from './HelpButton.svelte';

  let {
    id,
    label,
    value = null,
    options = null,
    node = undefined,
    startLabel = 'Review change',
    disabled = false,
    hideIdle = false,
    onDone = undefined,
  }: {
    id: string;
    label: string;
    value?: unknown;
    options?: unknown;
    node?: string;
    startLabel?: string;
    disabled?: boolean;
    /** Show nothing until a change is under way (the card keeps Restart now mounted to show its outcome). */
    hideIdle?: boolean;
    onDone?: () => void;
  } = $props();

  // The node the change is for: the one named, else this node (the first in the listing); never just the
  // node picked in the Guarded settings picker, which a card on another node does not follow.
  const target = $derived(node ? (guarded.nodes.find((x) => x.node === node) ?? null) : (guarded.nodes[0] ?? null));

  type Step = 'idle' | 'review' | 'working' | 'pending' | 'done' | 'restarting';
  let step = $state<Step>('idle');
  let pv = $state<S['GuardedPreview'] | null>(null);
  let typed = $state('');
  let reason = $state('');
  let acks = $state<string[]>([]);
  let busy = $state(false);
  let error = $state<unknown>(null);
  let result = $state<S['GuardedApplied'] | null>(null);
  /** The text of the final outcome (applied, confirmed, rolled back and why). */
  let finalText = $state('');
  let finalKind = $state<'ok' | 'bad' | ''>('');
  // The recent-sign-in prompt.
  let reauth = $state(false);
  let password = $state('');
  let totp = $state('');
  let needTotp = $state(false);
  // The countdown: the seconds the server last said were left, and when this browser heard it.
  let left = $state(0);
  let heardAt = performance.now();
  let tick = $state(0);
  let timer: ReturnType<typeof setInterval> | undefined;
  let stopWatch: (() => void) | undefined;
  let restartStarted = 0;
  let restartTimedOut = $state(false);
  // The listing may have been read before the change started: only a read that has shown it pending (or a
  // deadline that has passed, with a margin) can say it ended.
  let sawPending = $state(false);
  // Restart now: the staged settings the restart applies, and when it was asked for (server seconds).
  let restartIds: string[] = [];
  let restartAsked = 0;

  const isRestart = $derived(id === 'restart-now');
  const secsLeft = $derived.by(() => {
    void tick;
    return Math.max(0, Math.ceil(left - (performance.now() - heardAt) / 1000));
  });
  const total = $derived(result?.deadlineSecs ?? 0);
  const pct = $derived(total > 0 ? Math.max(0, Math.min(100, (secsLeft / total) * 100)) : 0);
  const typedOk = $derived(!!pv && typed.trim() === pv.phrase);
  const acksOk = $derived(!pv || (pv.acknowledgements ?? []).every((a) => acks.includes(a)));

  function hear(secs: number) {
    left = secs;
    heardAt = performance.now();
  }

  function reset() {
    step = 'idle';
    pv = null;
    typed = '';
    reason = '';
    acks = [];
    error = null;
    result = null;
    reauth = false;
    password = '';
    totp = '';
    needTotp = false;
    stop();
  }

  function stop() {
    if (timer) clearInterval(timer);
    timer = undefined;
    stopWatch?.();
    stopWatch = undefined;
  }
  onDestroy(stop);

  async function review() {
    busy = true;
    error = null;
    finalText = '';
    finalKind = '';
    try {
      pv = await api.guardedPreview(id, { node, value, options });
      typed = '';
      acks = [];
      step = 'review';
    } catch (e) {
      error = e;
    } finally {
      busy = false;
    }
  }

  async function apply() {
    if (!pv) return;
    busy = true;
    error = null;
    try {
      const r = await api.guardedApply(id, {
        previewId: pv.previewId,
        confirm: typed.trim(),
        reason: reason.trim() || undefined,
        value,
        options,
        node,
        acknowledge: acks,
      });
      result = r;
      reauth = false;
      afterApply(r);
    } catch (e) {
      if (e instanceof ApiError && e.code === 'reauth_required' && pv.needsRecentSignIn && session.user) {
        // The preview stays valid (it is bound to the admin, not the session): sign in again, then retry.
        reauth = true;
        error = null;
      } else {
        error = e;
      }
    } finally {
      busy = false;
    }
  }

  async function signInAgain() {
    const user = session.user?.username;
    if (!user) return;
    busy = true;
    error = null;
    try {
      const r = await api.login({ username: user, password, totp: totp || undefined });
      signedIn(r);
      password = '';
      totp = '';
      needTotp = false;
      busy = false;
      await apply();
    } catch (e) {
      if (e instanceof ApiError && e.code === 'totp_required') needTotp = true;
      else error = e;
      busy = false;
    }
  }

  function afterApply(r: S['GuardedApplied']) {
    if (r.status === 'pending') {
      step = 'pending';
      sawPending = false;
      hear(r.deadlineSecs ?? 0);
      timer = setInterval(() => (tick += 1), 500);
      stopWatch = watchGuarded(1_500);
    } else if (r.status === 'restarting') {
      step = 'restarting';
      restartIds = [...(target?.pendingRestart ?? [])];
      restartAsked = Math.floor(Date.now() / 1000) - 5;
      restartStarted = Date.now();
      restartTimedOut = false;
      stopWatch = watchGuarded(1_000);
    } else {
      step = 'done';
      finalKind = 'ok';
      finalText = r.message;
      void refreshGuarded();
      onDone?.();
    }
  }

  // The window: follow the server's own count, and notice how it ended.
  $effect(() => {
    if (step !== 'pending' || !result) return;
    const p = target?.pending;
    void tick;
    if (p && p.id === result.pendingId) {
      sawPending = true;
      hear(p.deadlineSecs);
    } else if (guarded.loaded && target && (sawPending || secsLeft === 0)) {
      const o = target.outcomes.find((x) => x.setting === id);
      step = 'done';
      stop();
      if (o?.outcome === 'confirmed') {
        finalKind = 'ok';
        finalText = `The change was confirmed and is kept on ${target.node}.`;
        onDone?.();
      } else {
        finalKind = 'bad';
        finalText = `The change was rolled back: ${reasonText(o?.reason ?? 'expired')}. Nothing was kept.`;
      }
    }
  });

  // The node's own test query to each DNS socket the change opened (T27.14b), read every 2 s while the
  // window is open. A change with no probes (or one pending on another node) answers an empty list or a
  // 404, and shows nothing.
  let probes = $state<S['GuardedProbeLine'][]>([]);
  const probeFailing = $derived(probes.some((p) => p.state === 'no_answer'));
  $effect(() => {
    const pid = step === 'pending' ? result?.pendingId : undefined;
    if (!pid) {
      probes = [];
      return;
    }
    let alive = true;
    const read = async () => {
      try {
        const v = await api.guardedPending(pid);
        if (alive) probes = v.probes;
      } catch {
        if (alive) probes = [];
      }
    };
    void read();
    const t = setInterval(read, 2_000);
    return () => {
      alive = false;
      clearInterval(t);
    };
  });
  function probeText(p: S['GuardedProbeLine']): string {
    if (p.state === 'answered') return "the node's own test query was answered";
    if (p.state === 'refused_by_gate') return "the node's own test query was refused by the device-key gate, as it should be";
    if (p.state === 'no_answer') return `no answer to the node's own test query${p.error ? `: ${p.error}` : ''}`;
    return 'waiting for the first test query';
  }

  // Restart now: the node goes away and comes back; its outcome is read from the listing.
  $effect(() => {
    if (step !== 'restarting') return;
    const n = target;
    if (n && !n.restarting && guarded.error === '' && Date.now() - restartStarted > 800) {
      // The newest outcome of each staged setting since the restart was asked for.
      const mine = restartIds.flatMap((sid) => {
        const o = n.outcomes.find((x) => x.setting === sid && x.at >= restartAsked);
        return o ? [o] : [];
      });
      step = 'done';
      stop();
      const bad = mine.find((o) => o.outcome === 'rolled_back');
      if (bad) {
        finalKind = 'bad';
        finalText = `${n.node} is back, but the staged change to ${bad.setting} was rolled back: ${reasonText(bad.reason)}.`;
      } else {
        finalKind = 'ok';
        finalText = `${n.node} is back.${mine.length ? ` Applied: ${mine.map((o) => o.setting).join(', ')}.` : ''}`;
      }
      onDone?.();
    } else if (Date.now() - restartStarted > Math.max(n?.confirmWindowSecs ?? 120, 180) * 2000) {
      restartTimedOut = true;
    }
  });
  $effect(() => {
    if (step !== 'restarting') return;
    const t = setInterval(() => (tick += 1), 1000);
    return () => clearInterval(t);
  });
  $effect(() => {
    void tick;
    if (step === 'restarting' && Date.now() - restartStarted > Math.max(target?.confirmWindowSecs ?? 120, 180) * 2000) {
      restartTimedOut = true;
    }
  });

  async function cancelPending() {
    if (!result?.pendingId) return;
    busy = true;
    try {
      await api.guardedCancel(result.pendingId);
      await refreshGuarded();
    } catch (e) {
      error = e;
    } finally {
      busy = false;
    }
  }

  // The same-origin proofs (a proxy list) confirm from here, with the admin's session.
  async function confirmHere() {
    if (!result?.pendingId) return;
    busy = true;
    error = null;
    try {
      const r = await api.guardedConfirm(result.pendingId);
      finalKind = 'ok';
      finalText = r.seenClient
        ? `Confirmed. The node now sees this request as coming from ${r.seenClient}.`
        : 'The change was confirmed and is kept.';
      step = 'done';
      stop();
      void refreshGuarded();
      onDone?.();
    } catch (e) {
      error = e;
    } finally {
      busy = false;
    }
  }

  /** The new address with the confirm step in its fragment (never sent to a server or a log). */
  const confirmLink = $derived(
    result?.newAddress && result.pendingId && result.confirmToken
      ? `${result.newAddress.replace(/\/$/, '')}/#/guarded-confirm?id=${encodeURIComponent(result.pendingId)}&t=${encodeURIComponent(result.confirmToken)}`
      : '',
  );
</script>

<div class="guarded" data-testid="guarded-{id}">
  {#if step === 'idle' && hideIdle}
    <!-- nothing to offer now -->
  {:else if step === 'idle'}
    <button class="primary" disabled={disabled || busy} onclick={review} data-testid="guarded-start-{id}">
      {busy ? 'Checking…' : startLabel}
    </button>
    <HelpButton id="guarded-settings" />
    <ErrorNote {error} />
  {:else if step === 'review' && pv}
    <section class="preview" data-testid="guarded-preview">
      <h4>
        {label}: review
        {#if pv.weakening}<span class="weak" data-testid="guarded-weakens" title="This change weakens security">weakens security</span>{/if}
        <HelpButton id="guarded-settings" />
      </h4>
      <p data-testid="guarded-effect">{pv.effect}</p>
      <p class="small muted">
        Node: <strong data-testid="guarded-node">{pv.nodes.join(', ')}</strong>.
        {#if pv.mode === 'window'}It takes effect now and is kept only if you confirm it through the new address within {pv.windowSecs} seconds; otherwise it rolls back.{/if}
        {#if pv.restartRequired}It takes effect at the node's next start.{/if}
      </p>
      {#each pv.warnings as w (w)}
        <div class="notice warn small" data-testid="guarded-warning">{w}</div>
      {/each}
      {#each pv.checks.filter((c) => !c.ok) as c (c.name)}
        <div class="notice bad small">{c.name}: {c.detail}</div>
      {/each}
      {#each pv.acknowledgements ?? [] as a (a)}
        <label class="check small">
          <input type="checkbox" checked={acks.includes(a)} onchange={(e) => (acks = e.currentTarget.checked ? [...acks, a] : acks.filter((x) => x !== a))} />
          {a}
        </label>
      {/each}
      <label class="small">Why (kept in the audit log)
        <input bind:value={reason} placeholder="optional" aria-label="Reason" />
      </label>
      <label class="small">Type <code data-testid="guarded-phrase">{pv.phrase}</code> to confirm
        <input bind:value={typed} autocomplete="off" aria-label="Confirmation phrase" data-testid="guarded-phrase-input" />
      </label>
      {#if reauth}
        <div class="notice warn" role="alert" data-testid="guarded-reauth">
          <strong>Confirm it's you.</strong> This needs a sign-in from the last 10 minutes.
          <div class="fields">
            <label class="small">Password for {session.user?.username}
              <input type="password" autocomplete="current-password" bind:value={password} aria-label="Your password" data-testid="guarded-reauth-password" />
            </label>
            {#if needTotp}
              <label class="small">Authenticator code
                <input bind:value={totp} inputmode="numeric" autocomplete="one-time-code" aria-label="Authenticator code" />
              </label>
            {/if}
          </div>
          <button class="primary" disabled={busy || !password} onclick={signInAgain} data-testid="guarded-reauth-go">
            {busy ? 'Working…' : 'Sign in again and apply'}
          </button>
          <div class="muted small">Signed in with single sign-on? Sign out, sign in again, and retry. API tokens can't change guarded settings: use the configuration file or `wrendns guarded`.</div>
        </div>
      {:else}
        <div class="row">
          <button class="primary" disabled={busy || !typedOk || !acksOk} onclick={apply} data-testid="guarded-apply">
            {busy ? 'Working…' : isRestart ? 'Restart now' : 'Apply'}
          </button>
          <button disabled={busy} onclick={reset} data-testid="guarded-back">Cancel</button>
        </div>
      {/if}
      <ErrorNote {error} />
      <p class="muted small">
        A configuration file always wins over what is set here, and is the way back if you get locked out
        (the recovery steps are in the help)<HelpButton id="guarded-recovery" />
      </p>
    </section>
  {:else if step === 'pending' && result}
    <section class="pending" data-testid="guarded-pending" aria-live="polite">
      <h4>{label}: waiting for confirmation</h4>
      <div class="bar" role="progressbar" aria-valuemin="0" aria-valuemax={total} aria-valuenow={secsLeft}>
        <div class="fill" style="width: {pct}%"></div>
      </div>
      <p>
        <strong data-testid="guarded-countdown">{secsLeft}</strong> seconds left. {result.message}
      </p>
      {#if probes.length}
        <ul class="probes small" data-testid="guarded-probes">
          {#each probes as p, i (i)}
            <li data-testid="guarded-probe" data-state={p.state}>
              <code>{p.listener}</code>: {probeText(p)}.
              <span class="muted" data-testid="guarded-evidence">{p.otherHosts > 0 ? `${p.otherHosts} other ${p.otherHosts === 1 ? 'host has' : 'hosts have'} used it.` : 'No other host has used it yet.'}</span>
            </li>
          {/each}
        </ul>
      {/if}
      {#if confirmLink}
        <p>
          <a class="button primary" href={confirmLink} data-testid="guarded-confirm-link">Open the new address and confirm</a>
        </p>
        <p class="small muted">The link carries a one-time token in its #fragment, which is never sent to a server or a log. If you can't reach the new address, do nothing: the change rolls back.</p>
      {:else}
        <button class="primary" disabled={busy || probeFailing} onclick={confirmHere} data-testid="guarded-confirm-here">{busy ? 'Working…' : 'Confirm'}</button>
      {/if}
      <button disabled={busy} onclick={cancelPending} data-testid="guarded-cancel">Cancel the change</button>
      <ErrorNote {error} />
    </section>
  {:else if step === 'restarting'}
    <section class="pending" data-testid="guarded-restarting" aria-live="polite">
      <h4>{target?.node ?? 'The node'} is restarting…</h4>
      <p>
        Waiting for it to answer. {hasSupervisor(target) ? `Your ${target?.supervisor.kind} starts it again.` : ''}
        This page keeps trying.
      </p>
      {#if restartTimedOut}
        <div class="notice bad" role="alert" data-testid="guarded-restart-timeout">
          It hasn't come back. If nothing starts it again, start it by hand; if it starts and stops, see the
          recovery steps (the configuration file, <code>wrendns guarded clear</code>,
          <code>WRENDNS_IGNORE_GUARDED=1</code>).<HelpButton id="guarded-recovery" />
        </div>
      {/if}
    </section>
  {:else if step === 'done'}
    <section class="done" data-testid="guarded-done">
      <div class="notice {finalKind === 'bad' ? 'bad' : 'ok'}" role="status" data-testid={finalKind === 'bad' ? 'guarded-rolled-back' : 'guarded-result'}>{finalText}</div>
      {#if result?.status === 'staged'}
        <p class="small" data-testid="guarded-pending-restart">Pending restart: it takes effect when the node starts again.</p>
      {/if}
      <button onclick={reset} data-testid="guarded-again">Done</button>
    </section>
  {/if}
</div>

<style>
  .guarded {
    display: block;
  }
  /* The alert colour on its tint, in sentence case (T33.6). */
  .weak {
    background: var(--bad-soft);
    color: var(--bad);
    border-radius: var(--radius-sm);
    padding: 0 var(--space-2);
    font-size: var(--type-label-size);
    font-weight: 600;
    margin-left: var(--space-2);
  }
  .row {
    display: flex;
    gap: var(--space-2);
    margin: var(--space-2) 0;
    flex-wrap: wrap;
  }
  .fields {
    display: grid;
    gap: var(--space-2);
    max-width: 420px;
    margin: var(--space-2) 0;
  }
  .check {
    display: flex;
    gap: var(--space-2);
    align-items: flex-start;
    margin: var(--space-2) 0;
  }
  .bar {
    height: 8px;
    background: var(--surface-2);
    border-radius: var(--radius-full);
    overflow: hidden;
    margin: var(--space-2) 0;
  }
  .fill {
    height: 100%;
    background: var(--accent);
    transition: width var(--motion);
  }
  label {
    display: grid;
    gap: var(--space-1);
    margin: var(--space-2) 0;
    max-width: 460px;
  }
  .probes {
    margin: var(--space-2) 0;
    padding-left: var(--space-4);
  }
  .button {
    display: inline-block;
    text-decoration: none;
  }
</style>
