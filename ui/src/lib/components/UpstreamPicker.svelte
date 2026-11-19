<script lang="ts">
  // REQ: UPS-004, API-002 (T24.36) — the Upstreams page's simple view: tick the public resolvers to
  // use, choose encrypted or plain DNS and IPv4 and/or IPv6, add your own. Saving writes upstream
  // entries (named pub-<provider>-<protocol>-<n>) and the `default` group (fastest) through the same
  // API the Advanced view uses; entries the picker didn't make are shown and left alone.
  import { api, type S } from '../api';
  import { can } from '../session.svelte';
  import ErrorNote from './ErrorNote.svelte';
  import HelpButton from './HelpButton.svelte';
  import {
    customUrl,
    isPickerEntry,
    needsTlsName,
    nextCustomName,
    planFor,
    readSaved,
    type Entry,
    type Transport,
  } from '../upstream-picker';

  let { onchanged, onadvanced }: { onchanged?: () => void; onadvanced?: () => void } = $props();

  let presets = $state<S['UpstreamPreset'][]>([]);
  let ipv6Route = $state(true);
  let entries = $state<S['ConfigEntry'][]>([]);
  let groups = $state<S['ConfigEntry'][]>([]);
  let loaded = $state(false);
  let error = $state<unknown>(null);
  let note = $state<string | null>(null);
  let busy = $state(false);

  // What the form says. `dirty` stops a refresh from replacing choices that aren't saved yet.
  let ticked = $state<Set<string>>(new Set());
  let transport = $state<Transport>('encrypted');
  let v4 = $state(true);
  let v6 = $state(true);
  let customs = $state<{ name: string; url: string; tls_server_name?: string }[]>([]);
  let dirty = $state(false);
  let customText = $state('');
  let customTls = $state('');
  let customProblem = $state<string | null>(null);

  const writable = $derived(can('operator'));
  const simple = $derived(presets.filter((p) => p.simple));
  const providers = $derived.by(() => {
    const by = new Map<string, S['UpstreamPreset'][]>();
    for (const p of simple) by.set(p.provider, [...(by.get(p.provider) ?? []), p]);
    return [...by.entries()];
  });
  // The picker's own entries and everyone else's.
  const others = $derived(entries.filter((e) => !isPickerEntry(e.name) && e.definition));
  const defaultGroup = $derived(groups.find((g) => g.name === 'default'));
  const groupMembers = $derived(((defaultGroup?.definition as { members?: string[] } | undefined)?.members ?? []));
  const keptMembers = $derived(groupMembers.filter((m) => !isPickerEntry(m)));

  /** Re-read what is saved (the Advanced editor changed something): a stale picker would rewrite the group. */
  export async function refresh() {
    await load();
  }
  async function load() {
    try {
      const [p, e, g] = await Promise.all([api.upstreamPresets(), api.configEntries('upstream'), api.configEntries('upstream_group')]);
      presets = p.items;
      ipv6Route = p.ipv6Route;
      entries = e.items;
      groups = g.items;
      if (!dirty) adopt();
      error = null;
    } catch (err) {
      error = err;
    } finally {
      loaded = true;
    }
  }
  /** The form shows what is saved. */
  function adopt() {
    const s = readSaved(entries, presets);
    ticked = new Set(s.ticked);
    customs = s.customs;
    transport = s.transport ?? 'encrypted';
    v4 = s.v4 ?? true;
    // Without an IPv6 route the default is off; saved choices stand (an explicit IPv6 entry stays).
    v6 = s.v6 ?? ipv6Route;
  }
  $effect(() => {
    void load();
  });

  function toggle(id: string) {
    const next = new Set(ticked);
    if (next.has(id)) next.delete(id);
    else next.add(id);
    ticked = next;
    dirty = true;
  }
  const mark = () => {
    dirty = true;
    note = null;
  };

  function addCustom() {
    customProblem = null;
    const url = customUrl(customText);
    if (!url) {
      customProblem = 'Type an address such as 9.9.9.9, tls://dns.example.net or https://dns.example.net/dns-query.';
      return;
    }
    const tls = customTls.trim();
    if (needsTlsName(url) && !tls) {
      customProblem = 'A DNS over TLS address given by IP needs the name on the server’s certificate.';
      return;
    }
    customs = [
      ...customs,
      { name: nextCustomName(customs.map((c) => c.name)), url, ...(tls ? { tls_server_name: tls } : {}) },
    ];
    customText = '';
    customTls = '';
    mark();
  }
  function dropCustom(name: string) {
    customs = customs.filter((c) => c.name !== name);
    mark();
  }

  const plan = $derived(planFor(presets, ticked, transport, v4, v6));
  const wanted = $derived<Entry[]>([...plan.entries, ...customs.map((c) => ({ ...c }))]);
  const nothing = $derived(wanted.length === 0 && keptMembers.length === 0);
  const noFamily = $derived(!v4 && !v6);
  const fellBack = $derived(plan.fellBack.map((id) => presets.find((p) => p.id === id)?.name ?? id));

  const same = (e: S['ConfigEntry'] | undefined, w: Entry) => {
    const d = e?.definition as { url?: string; tls_server_name?: string } | null | undefined;
    return !!d && d.url === w.url && (d.tls_server_name ?? '') === (w.tls_server_name ?? '');
  };

  async function save() {
    if (nothing || noFamily) return;
    busy = true;
    error = null;
    note = null;
    try {
      let keepInGit = false;
      // The new upstreams first, so the group never names one that isn't there.
      for (const w of wanted) {
        const have = entries.find((e) => e.name === w.name);
        if (same(have, w)) continue;
        const body: Record<string, unknown> = { url: w.url };
        if (w.tls_server_name) body.tls_server_name = w.tls_server_name;
        const r = await api.putEntry('upstreams', w.name, body);
        keepInGit ||= !!r.keepInGit;
      }
      // The default group: everything already in it that the picker didn't make, and these.
      const members = [...keptMembers, ...wanted.map((w) => w.name)];
      if (members.length) {
        const base = { ...((defaultGroup?.definition as Record<string, unknown> | null) ?? {}) };
        const r = await api.putEntry('upstream-groups', 'default', { ...base, members, strategy: 'fastest' });
        keepInGit ||= !!r.keepInGit;
      }
      // Then the ones that were unticked.
      const names = new Set(wanted.map((w) => w.name));
      for (const e of entries) {
        if (isPickerEntry(e.name) && e.definition && !names.has(e.name)) {
          const r = await api.deleteEntry('upstreams', e.name);
          keepInGit ||= !!r.keepInGit;
        }
      }
      dirty = false;
      await load();
      adopt();
      onchanged?.();
      note = keepInGit
        ? 'Saved, but this node keeps its configuration in Git: open the Advanced view for the TOML to commit.'
        : 'Saved. The group of upstreams now asks the fastest of these.';
    } catch (err) {
      error = err;
      await load();
    } finally {
      busy = false;
    }
  }
  function discard() {
    dirty = false;
    note = null;
    customProblem = null;
    adopt();
  }

  const filterLabel: Record<string, string> = { none: 'no filtering', malware: 'blocks malware', family: 'family filter', ads: 'blocks ads' };
</script>

<section class="card" data-testid="upstream-picker">
  <div class="card-head">
    <h2>Choose your upstream DNS servers<HelpButton id="upstream-picker" /></h2>
  </div>
  <p class="muted small">
    These are the public servers WrenDNS asks for names it doesn’t know yet. Tick the ones you want: it asks the fastest
    of them. Each one sees the names you look up, so the notes say what each does with them.
  </p>
  <ErrorNote {error} />
  {#if !loaded}
    <p class="empty">Loading…</p>
  {:else}
    <fieldset class="opts" disabled={!writable}>
      <legend class="small muted">How to ask</legend>
      <label class="opt" title="DNS over TLS or HTTPS: your ISP can't read the questions.">
        <input type="radio" name="transport" value="encrypted" bind:group={transport} onchange={mark} data-testid="transport-encrypted" />
        Encrypted <span class="muted small">(recommended)</span>
      </label>
      <label class="opt" title="Ordinary DNS on port 53: faster to set up, but anyone on the path can read it.">
        <input type="radio" name="transport" value="plain" bind:group={transport} onchange={mark} data-testid="transport-plain" />
        Plain <span class="muted small">(not private)</span>
      </label>
      <span class="sep"></span>
      <label class="opt"><input type="checkbox" bind:checked={v4} onchange={mark} data-testid="family-v4" /> IPv4</label>
      <label class="opt" class:off={!ipv6Route} title={ipv6Route ? '' : 'This node has no IPv6 route'}>
        <input type="checkbox" bind:checked={v6} onchange={mark} disabled={!ipv6Route && !v6} data-testid="family-v6" /> IPv6
      </label>
    </fieldset>
    {#if !ipv6Route}
      <p class="muted small" data-testid="ipv6-reason">
        IPv6 is off here: this node has no IPv6 route, so an IPv6 server would only time out. {v6 ? 'It is ticked because an IPv6 server is saved; untick it to remove them.' : ''}
      </p>
    {/if}
    {#if noFamily}<p class="notice warn small">Tick IPv4, IPv6 or both.</p>{/if}
    {#if transport === 'plain'}
      <p class="notice warn small" data-testid="plain-warning">
        Plain DNS isn’t private: your ISP and anyone on the way can read every name you look up.
        {#if fellBack.length}{fellBack.join(', ')} has no plain address, so its encrypted one is used.{/if}
      </p>
    {/if}

    <div class="providers">
      {#each providers as [provider, variants] (provider)}
        <div class="provider" data-testid="provider-{provider}">
          <h3>{provider}</h3>
          {#each variants as p (p.id)}
            <label class="variant">
              <input type="checkbox" checked={ticked.has(p.id)} onchange={() => toggle(p.id)} disabled={!writable} data-testid="pick-{p.id}" />
              <span>
                <strong>{p.variant}</strong>
                <span class="chip">{filterLabel[p.filtering] ?? p.filtering}</span>
                {#if p.dnssec}<span class="chip">DNSSEC</span>{/if}
                <span class="muted small note">{p.note} <a href={p.homepage} target="_blank" rel="noopener noreferrer">Provider page</a></span>
              </span>
            </label>
          {/each}
        </div>
      {/each}
    </div>

    <div class="provider" data-testid="picker-custom">
      <h3>Custom</h3>
      {#each customs as c (c.name)}
        <div class="custom-row" data-testid="custom-entry">
          <code>{c.url}</code>{#if c.tls_server_name}<span class="muted small"> ({c.tls_server_name})</span>{/if}
          {#if writable}<button class="link small" onclick={() => dropCustom(c.name)}>Remove</button>{/if}
        </div>
      {/each}
      {#if writable}
        <div class="custom-add">
          <input type="text" bind:value={customText} placeholder="9.9.9.9, tls://dns.example.net or https://dns.example.net/dns-query"
            aria-label="Custom upstream address" data-testid="custom-address" onkeydown={(e) => e.key === 'Enter' && addCustom()} />
          {#if needsTlsName(customUrl(customText) ?? '')}
            <input type="text" bind:value={customTls} placeholder="name on its certificate" aria-label="TLS server name" data-testid="custom-tls" />
          {/if}
          <button onclick={addCustom} data-testid="custom-add">Add</button>
        </div>
        {#if customProblem}<p class="small bad-text" role="alert">{customProblem}</p>{/if}
      {/if}
    </div>

    {#if others.length}
      <div class="provider" data-testid="picker-others">
        <h3>Also set up (kept as they are)</h3>
        <p class="muted small">
          These weren’t made here: they come from the config files, an import or the Advanced view. Saving doesn’t change them.
          {#if keptMembers.length}They stay in the default group.{/if}
          {#if onadvanced}<button class="link small" onclick={onadvanced}>Open the Advanced view</button>{/if}
        </p>
        <ul class="small">
          {#each others as e (e.name)}
            <li><strong>{e.name}</strong> <span class="muted mono">{(e.definition as { url?: string }).url}</span>
              <span class="badge {e.source === 'added' ? 'ok' : e.source === 'override' ? 'warn' : ''}">{e.source === 'file' ? 'config file' : e.source === 'added' ? 'added here' : e.source === 'override' ? 'overrides the file' : e.source}</span></li>
          {/each}
        </ul>
      </div>
    {/if}

    <div class="actions">
      {#if writable}
        <button class="primary" onclick={save} disabled={busy || !dirty || nothing || noFamily} data-testid="picker-save">
          {busy ? 'Saving…' : 'Save'}
        </button>
        <button onclick={discard} disabled={busy || !dirty}>Discard changes</button>
      {:else}
        <span class="muted small">Operators and admins can change these.</span>
      {/if}
      {#if nothing && dirty}<span class="small bad-text">Pick at least one server.</span>{/if}
      {#if note}<span class="small" data-testid="picker-note" role="status">{note}</span>{/if}
    </div>
  {/if}
</section>

<style>
  .opts {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 6px 16px;
    border: 0;
    padding: 0;
    margin: 8px 0;
  }
  .opt {
    display: inline-flex;
    gap: 6px;
    align-items: center;
  }
  .opt.off {
    color: var(--muted);
  }
  .sep {
    flex: 0 0 1px;
    align-self: stretch;
    background: var(--border);
  }
  .providers {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(min(100%, 340px), 1fr));
    gap: 12px;
    margin: 8px 0;
  }
  .provider h3 {
    margin: 8px 0 4px;
    font-size: 1rem;
  }
  .variant {
    display: flex;
    gap: 8px;
    align-items: flex-start;
    padding: 4px 0;
  }
  .variant input {
    margin-top: 3px;
  }
  .note {
    display: block;
  }
  .chip {
    display: inline-block;
    padding: 0 6px;
    margin: 0 2px;
    border-radius: var(--radius-full);
    background: var(--surface-2);
    font-size: 0.8em;
    white-space: nowrap;
  }
  .custom-row {
    padding: 2px 0;
  }
  .custom-add {
    display: flex;
    flex-wrap: wrap;
    gap: 6px;
    margin-top: 4px;
  }
  .custom-add input[type='text'] {
    flex: 1 1 260px;
    min-width: 0;
  }
  .actions {
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
    align-items: center;
    margin-top: 10px;
  }
  .bad-text {
    color: var(--bad);
    font-weight: 600;
  }
</style>
