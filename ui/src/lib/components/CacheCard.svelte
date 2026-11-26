<script lang="ts">
  // REQ: DNS-006, API-005 (T6.13) — the cache: counters per node, what it holds for a name,
  // and flushing a name, a subtree, or everything, on every node (or one).
  // REQ: DNS-905 (T40.4) — and flushing one query type, the negative answers or the failed
  // lookups, or what the recursive resolver remembers (zone cuts, round-trip times). The broad
  // ones ask first.
  import { api, type S } from '../api';
  import { can } from '../session.svelte';
  import { bytes, num, pct } from '../format';
  import ErrorNote from './ErrorNote.svelte';
  import HelpButton from './HelpButton.svelte';

  let {
    name: initial = '',
    compact = false,
    more = undefined,
    title = 'Cache',
  }: { name?: string; compact?: boolean; more?: boolean; title?: string } = $props();

  let stats = $state<S['CacheNodeStats'][]>([]);
  let name = $state('');
  let found = $state<S['CacheLookup'] | null>(null);
  let subtree = $state(false);
  let node = $state('');
  let flushed = $state<S['CacheFlushResult'] | null>(null);
  let busy = $state(false);
  let error = $state<unknown>(null);
  let confirmAll = $state(false);
  let qtype = $state('');
  // A broad flush waiting for its confirmation.
  let pending = $state<{ label: string; body: S['CacheFlushRequest'] } | null>(null);
  const writable = $derived(can('operator'));
  // The type, kind and recursor flushes: on by default except in the compact quick cards, and a
  // page that hides only the counters (the Cache page has its own) asks for them with `more`.
  const showMore = $derived(more ?? !compact);
  const typeName = $derived(qtype.trim().toUpperCase());
  const recursorDropped = $derived(
    flushed ? flushed.nodes.reduce((a, n) => a + (n.recursorRemoved ?? 0), 0) : 0,
  );

  async function loadStats() {
    try {
      stats = (await api.cacheStats()).items;
    } catch (e) {
      error = e;
    }
  }
  async function lookup(e?: SubmitEvent) {
    e?.preventDefault();
    if (!name.trim()) return;
    error = null;
    try {
      found = await api.cacheLookup(name.trim());
    } catch (err) {
      error = err;
    }
  }
  async function flush(all: boolean) {
    busy = true;
    error = null;
    try {
      flushed = await api.cacheFlush({
        name: all ? undefined : name.trim(),
        subtree: all ? undefined : subtree,
        node: node || undefined,
      });
      confirmAll = false;
      await loadStats();
      if (!all) await lookup();
    } catch (err) {
      error = err;
    } finally {
      busy = false;
    }
  }
  async function run(body: S['CacheFlushRequest']) {
    busy = true;
    error = null;
    try {
      flushed = await api.cacheFlush({ ...body, node: node || undefined });
      pending = null;
      await loadStats();
      if (name.trim()) await lookup();
    } catch (err) {
      error = err;
    } finally {
      busy = false;
    }
  }
  /** A flush with a name and a type is narrow and runs at once; the rest ask first. */
  function ask(label: string, body: S['CacheFlushRequest']) {
    confirmAll = false;
    pending = { label, body };
  }
  $effect(() => {
    name = initial;
    void loadStats();
    if (initial) void lookup();
  });
  const ttl = (s: number) => (s >= 0 ? `${num(s)} s left` : `stale for ${num(-s)} s`);
</script>

<section class="card" data-testid="cache-card">
  <h2>{title}<HelpButton id="cache-tools" /></h2>
  {#if stats.length && !compact}
    <div class="table-wrap">
      <table class="compact">
        <thead>
          <tr><th>Node</th><th class="num">Entries</th><th class="num">Memory</th><th class="num" title="Answered from the cache: fresh, or refreshed in the background">From cache</th><th class="num">Stale served</th><th class="num">Prefetches</th><th class="num">Evictions</th></tr>
        </thead>
        <tbody>
          {#each stats as s, i (s.node ?? i)}
            <tr>
              <td>{s.node ?? 'this node'}</td>
              <td class="num">{num(s.entries)}</td>
              <td class="num">{bytes(s.bytes)}</td>
              <td class="num">{pct(s.answeredPercent ?? s.hitPercent)}</td>
              <td class="num">{num(s.staleServed)}</td>
              <td class="num">{num(s.prefetches)}</td>
              <td class="num">{num(s.evictions)}</td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  {/if}

  <form class="row" onsubmit={lookup}>
    <input class="grow mono" aria-label="Name to look up" placeholder="www.example.com" bind:value={name} />
    <button>Look up</button>
  </form>
  {#if found}
    {#if found.entries.length === 0}
      <p class="muted small">Nothing cached for <span class="mono">{found.name}</span>.</p>
    {:else}
      <div class="table-wrap">
        <table class="compact" data-testid="cache-entries">
          <thead><tr><th>Node</th><th>Type</th><th>Answer</th><th>Fresh</th><th class="num">Hits</th></tr></thead>
          <tbody>
            {#each found.entries as e, i (i)}
              <tr>
                <td>{e.node ?? 'this node'}</td>
                <td>{e.qtype}{#if e.dnssecOk}<span class="muted small"> (DO)</span>{/if}</td>
                <td>{e.rcode} · {e.answers} answer{e.answers === 1 ? '' : 's'}{#if e.authentic}<span class="badge ok">validated</span>{/if}</td>
                <td class="small">{ttl(e.ttlLeftSeconds)}</td>
                <td class="num">{num(e.hits)}</td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    {/if}
  {/if}

  {#if writable}
    <div class="row">
      <label class="small"><input type="checkbox" bind:checked={subtree} /> and everything under it</label>
      {#if stats.length > 1}
        <select aria-label="Node" bind:value={node}>
          <option value="">every node</option>
          {#each stats as s, i (s.node ?? i)}<option value={s.node ?? ''}>{s.node}</option>{/each}
        </select>
      {/if}
      <button disabled={busy || !name.trim()} onclick={() => flush(false)}>Flush this name</button>
      {#if confirmAll}
        <button class="danger" disabled={busy} onclick={() => flush(true)}>Yes, empty the cache</button>
        <button class="link" onclick={() => (confirmAll = false)}>Cancel</button>
      {:else}
        <button class="link" onclick={() => { pending = null; confirmAll = true; }}>Flush everything…</button>
      {/if}
    </div>
    {#if showMore}
      <div class="row" data-testid="cache-flush-more">
        <input
          class="mono type"
          list="cache-flush-types"
          aria-label="Query type"
          data-testid="cache-flush-type"
          placeholder="Type, e.g. AAAA"
          bind:value={qtype}
        />
        <datalist id="cache-flush-types">
          {#each ['A', 'AAAA', 'CNAME', 'HTTPS', 'MX', 'NS', 'PTR', 'SRV', 'TXT'] as t (t)}<option value={t}></option>{/each}
        </datalist>
        {#if name.trim()}
          <button
            disabled={busy || !typeName}
            onclick={() => run({ name: name.trim(), subtree: subtree || undefined, type: typeName })}
          >Flush {typeName || 'one type'} for this name</button>
        {:else}
          <button
            disabled={busy || !typeName}
            onclick={() => ask(`Flush every ${typeName} answer`, { type: typeName })}
          >Flush this type everywhere…</button>
        {/if}
        <button disabled={busy} onclick={() => ask('Flush negative answers', { kind: 'negative' })}>Flush negative answers…</button>
        <button disabled={busy} onclick={() => ask('Flush failed lookups', { kind: 'bogus' })}>Flush failed lookups…</button>
      </div>
      <div class="row" data-testid="cache-flush-recursor">
        <span class="small muted">Recursive resolver:</span>
        <button disabled={busy} onclick={() => ask("Flush the recursor's zone cuts", { recursor: 'cuts' })}>Flush zone cuts…</button>
        <button disabled={busy} onclick={() => ask("Flush the recursor's round-trip times", { recursor: 'rtts' })}>Flush round-trip times…</button>
      </div>
      {#if pending}
        <div class="row" data-testid="cache-flush-confirm">
          <span class="small">{pending.label}{node ? ` on ${node}` : ' on every node'}?</span>
          <button class="danger" disabled={busy} onclick={() => run(pending!.body)}>Yes, flush</button>
          <button class="link" onclick={() => (pending = null)}>Cancel</button>
        </div>
      {/if}
    {/if}
  {/if}
  {#if flushed}
    <p class="notice ok small" data-testid="cache-flushed">
      {#if recursorDropped > 0 || flushed.nodes.some((n) => n.recursorRemoved != null)}
        Dropped {num(recursorDropped)} resolver {recursorDropped === 1 ? 'entry' : 'entries'}{:else}
        Removed {num(flushed.totalRemoved)} {flushed.totalRemoved === 1 ? 'entry' : 'entries'}{/if}{#each flushed.nodes.filter((n) => n.error) as n (n.node)}{` · ${n.node}: ${n.error}`}{/each}.
    </p>
  {/if}
  <ErrorNote {error} />
  <p class="muted small">
    Flushing doesn't clear devices' own caches. Blocked answers are never cached, so unblocking needs no flush. To change
    what a name resolves to, use Names on your network.
  </p>
</section>

<style>
  .row {
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
    align-items: center;
    margin: 12px 0;
  }
  .grow {
    flex: 1 1 220px;
  }
  .type {
    width: 150px;
  }
  .badge {
    margin-left: 6px;
  }
</style>
