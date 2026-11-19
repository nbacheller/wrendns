<script lang="ts">
  // REQ: DNS-023 (T24.13, ADR-901, ADR-914) — "Device names in DNS" on the Local DNS page: the
  // domain devices get names under, their TTL, reverse names, the mDNS switch (disabled while
  // `[clients] mdns` is off), and the count of names answered. The `[clients] mdns` switch is
  // admin-only, on the same card: turning it on opens multicast listening on every node.
  import { api, type S } from '../api';
  import { can } from '../session.svelte';
  import ErrorNote from './ErrorNote.svelte';
  import HelpButton from './HelpButton.svelte';

  let local = $state<S['ConfigEntry'] | null>(null);
  let clients = $state<S['ConfigEntry'] | null>(null);
  let error = $state<unknown>(null);
  let notice = $state('');

  // The form (operators and admins).
  type Form = { domain: string; device_ttl: number; auto_ptr: boolean; default_ttl: number; device_mdns: boolean };
  let form = $state<Form | null>(null);
  let preview = $state<S['ConfigChange'] | null>(null);
  let formError = $state<unknown>(null);
  let busy = $state(false);
  // The admin's switch.
  let mdnsOn = $state(false);
  // The value the last Check sent: Apply sends this, so it applies what was previewed.
  let mdnsChecked = $state(false);
  // The server's value at the last load. A reload only moves the switch when the admin has not changed it.
  let mdnsSeen = false;
  let mdnsPreview = $state<S['ConfigChange'] | null>(null);
  let mdnsError = $state<unknown>(null);

  const writable = $derived(can('operator'));
  const adminMdns = $derived(can('admin'));
  const defs = $derived((local?.definition ?? {}) as Record<string, unknown>);
  const cdefs = $derived((clients?.definition ?? {}) as Record<string, unknown>);
  const clientsMdns = $derived(cdefs.mdns === true);
  // REQ: DNS-019, DNS-023 (M4, ADR-914) — every field the files set is locked and labelled, and
  // is left out of the request (the files' value applies).
  const fileSet = $derived(local?.setByFile ?? []);
  const cFileSet = $derived(clients?.setByFile ?? []);
  const setByFile = (k: string) => fileSet.includes(k);
  const domainText = $derived(typeof defs.device_domain === 'string' && defs.device_domain ? String(defs.device_domain) : 'off');
  const hostsFiles = $derived(Array.isArray(defs.hosts_files) ? (defs.hosts_files as string[]) : []);

  async function load() {
    try {
      const [l, c] = await Promise.all([api.configEntries('local'), api.configEntries('clients')]);
      local = l.items[0] ?? null;
      clients = c.items[0] ?? null;
      if (mdnsOn === mdnsSeen) mdnsOn = clientsMdns;
      mdnsSeen = clientsMdns;
      error = null;
    } catch (e) {
      error = e;
    }
  }
  $effect(() => {
    void load();
  });

  function open() {
    preview = null;
    formError = null;
    notice = '';
    form = {
      domain: typeof defs.device_domain === 'string' ? String(defs.device_domain) : '',
      device_ttl: Number(defs.device_ttl ?? 60),
      auto_ptr: defs.auto_ptr !== false,
      default_ttl: Number(defs.default_ttl ?? 300),
      device_mdns: defs.device_mdns === true,
    };
  }

  // The body: the fields the files don't set (the entry keeps those as the files set them).
  // `device_mdns` is sent as the switch shows it: the switch is disabled while mDNS listening is
  // off, so it can't be turned on then, and a file's `true` is left out, not coerced.
  function body(): Record<string, unknown> {
    const f = form!;
    const all: Record<string, unknown> = {
      device_domain: f.domain.trim().toLowerCase() || null,
      device_ttl: Number(f.device_ttl),
      device_mdns: f.device_mdns,
      auto_ptr: f.auto_ptr,
      default_ttl: Number(f.default_ttl),
    };
    for (const k of fileSet) delete all[k];
    return all;
  }

  async function check(e: SubmitEvent) {
    e.preventDefault();
    if (!form) return;
    busy = true;
    formError = null;
    try {
      preview = await api.putEntry('local-settings', 'default', body(), true);
    } catch (err) {
      formError = err;
      preview = null;
    } finally {
      busy = false;
    }
  }

  async function apply() {
    if (!form) return;
    busy = true;
    try {
      await api.putEntry('local-settings', 'default', body(), false);
      form = null;
      preview = null;
      notice = 'Saved. Names change within about 10 seconds.';
      await load();
    } catch (err) {
      formError = err;
    } finally {
      busy = false;
    }
  }

  async function revert() {
    busy = true;
    try {
      await api.deleteEntry('local-settings', 'default');
      form = null;
      notice = 'Back to the configuration file.';
      await load();
    } catch (err) {
      error = err;
    } finally {
      busy = false;
    }
  }

  // The admin's `[clients] mdns` switch.
  async function mdnsCheck() {
    busy = true;
    mdnsError = null;
    try {
      mdnsChecked = mdnsOn;
      mdnsPreview = await api.putEntry('clients-settings', 'default', { mdns: mdnsChecked }, true);
    } catch (err) {
      mdnsError = err;
      mdnsPreview = null;
    } finally {
      busy = false;
    }
  }
  async function mdnsApply() {
    busy = true;
    try {
      await api.putEntry('clients-settings', 'default', { mdns: mdnsChecked }, false);
      mdnsPreview = null;
      notice = mdnsChecked ? 'mDNS listening is on.' : 'mDNS listening is off.';
      await load();
    } catch (err) {
      mdnsError = err;
    } finally {
      busy = false;
    }
  }

  function jump(e: MouseEvent) {
    e.preventDefault();
    document.getElementById('clients-mdns')?.scrollIntoView({ block: 'center' });
  }
</script>

<section class="card" data-testid="device-names-card">
  <h2>Device names in DNS<HelpButton id="device-names-dns" /></h2>
  <p class="small muted">
    Devices WrenDNS knows by name (a named device, a router's DHCP client, Home Assistant, and mDNS names when on) answer as
    <span class="mono">name.domain</span>. A name is answered within about 10 seconds of the router's next read.
  </p>
  <ErrorNote {error} />
  {#if notice}<p class="notice ok small" role="status">{notice}</p>{/if}
  {#if local}
    <dl data-testid="device-names-values">
      <dt>Domain</dt>
      <dd class="mono" data-testid="device-domain">{domainText}{#if fileSet.includes('device_domain')} <span class="muted small">(set by file)</span>{/if}</dd>
      <dt>Names answered now</dt>
      <dd data-testid="device-names-count">{local.answering ?? 0}</dd>
      <dt>TTL of device names</dt>
      <dd>{String(defs.device_ttl ?? 60)} s</dd>
      <dt>Reverse names for local addresses</dt>
      <dd>{defs.auto_ptr === false ? 'off' : 'on'}</dd>
      <dt>TTL of other local names</dt>
      <dd>{String(defs.default_ttl ?? 300)} s</dd>
      <dt>mDNS names</dt>
      <dd>
        {#if defs.device_mdns === true}on{:else}off{/if}
        {#if !clientsMdns}<span class="muted small"> · needs mDNS listening (<a href="#/local-dns" onclick={jump}>see below</a>)</span>{/if}
      </dd>
      <dt>Hosts files</dt>
      <dd class="mono small">{hostsFiles.length ? hostsFiles.join(', ') : 'none'} <span class="muted small">(read-only: set in the configuration file)</span></dd>
    </dl>
    {#if writable && !form}
      <div class="row">
        <button onclick={open} data-testid="device-names-edit">Change device names</button>
        {#if local.source === 'override'}
          <button class="link" disabled={busy} onclick={revert}>Revert to the file</button>
        {/if}
      </div>
    {/if}
  {/if}

  {#if form}
    <form class="form" data-testid="device-names-form" onsubmit={check}>
      <label>
        Domain
        <input class="mono" placeholder="home.arpa" aria-label="Domain" bind:value={form.domain} readonly={setByFile('device_domain')} />
        {#if setByFile('device_domain')}<span class="muted small" data-testid="set-by-file">Set by the configuration file: change it there.</span>{/if}
        <span class="muted small">
          Devices get names under it, such as kitchen-tablet.home.arpa. home.arpa is the domain for homes (RFC 8375). Leave it empty to turn names off.
        </span>
        {#if form.domain.trim().toLowerCase() === 'local'}
          <span class="warn-text small">local is refused: it belongs to mDNS (RFC 6762). Use home.arpa.</span>
        {/if}
      </label>
      <label>
        TTL of device names (seconds)
        <input type="number" min="0" aria-label="TTL of device names (seconds)" bind:value={form.device_ttl} readonly={setByFile('device_ttl')} />
        {#if setByFile('device_ttl')}<span class="muted small" data-testid="set-by-file">Set by the configuration file: change it there.</span>{/if}
        <span class="muted small">Names follow DHCP, so keep it short (60 by default).</span>
      </label>
      <label class="check">
        <input type="checkbox" role="switch" aria-label="Reverse names for local addresses" bind:checked={form.auto_ptr} disabled={setByFile('auto_ptr')} />
        {#if setByFile('auto_ptr')}<span class="muted small" data-testid="set-by-file">Set by the configuration file: change it there.</span>{/if}
        Reverse names for local addresses (a PTR for each)
      </label>
      <label>
        TTL of other local names (seconds)
        <input type="number" min="0" aria-label="TTL of other local names (seconds)" bind:value={form.default_ttl} readonly={setByFile('default_ttl')} />
        {#if setByFile('default_ttl')}<span class="muted small" data-testid="set-by-file">Set by the configuration file: change it there.</span>{/if}
      </label>
      <label class="check">
        <input
          type="checkbox"
          role="switch"
          aria-label="Name devices by their mDNS names"
          bind:checked={form.device_mdns}
          disabled={!clientsMdns || setByFile('device_mdns')}
        />
        {#if setByFile('device_mdns')}<span class="muted small" data-testid="set-by-file">Set by the configuration file: change it there.</span>{/if}
        Name devices by the names they announce over mDNS
      </label>
      {#if !clientsMdns}
        <p class="muted small" data-testid="mdns-needed">
          Off until mDNS listening is on. <a href="#/local-dns" onclick={jump}>Turn it on below</a> (an admin does).
        </p>
      {/if}
      <ErrorNote error={formError} />
      {#if preview}
        <div class="preview" data-testid="device-names-preview">
          <p><b>What this will do:</b> {preview.impact || 'Changes the device names as shown.'}</p>
          {#each preview.warnings as w (w)}<p class="small warn-text">{w}</p>{/each}
        </div>
        <div class="row">
          <button type="button" class="primary" disabled={busy} onclick={apply}>Apply</button>
          <button type="button" onclick={() => (preview = null)}>Change it</button>
        </div>
      {:else}
        <div class="row">
          <button class="primary" disabled={busy}>Check</button>
          <button type="button" onclick={() => (form = null)}>Cancel</button>
        </div>
      {/if}
    </form>
  {/if}

  <!-- REQ: DNS-023 (T24.13, ADR-914) — `[clients] mdns`: an admin's switch (no agent scope writes it). -->
  <div class="mdns" id="clients-mdns" data-testid="clients-mdns">
    <h3>Listen for mDNS announcements</h3>
    <p class="small muted">
      Turns on listening for the names devices announce on the LAN (<code>.local</code>), on every node. It needs host networking
      or a native install. The port
      <span class="mono">{String(cdefs.mdns_port ?? 5353)}</span>{#if cFileSet.includes('mdns_port')} <span class="muted small">(set by file)</span>{/if}
      is set in the configuration file.
    </p>
    {#if cFileSet.includes('mdns')}
      <p class="small muted" data-testid="mdns-set-by-file">Set by the configuration file: change it there.</p>
    {:else if adminMdns}
      <label class="check">
        <input type="checkbox" role="switch" aria-label="Listen for mDNS announcements" bind:checked={mdnsOn} onchange={() => (mdnsPreview = null)} />
        Listen for mDNS announcements
      </label>
      <ErrorNote error={mdnsError} />
      {#if mdnsPreview}
        <p class="small" data-testid="mdns-preview"><b>What this will do:</b> {mdnsPreview.impact}</p>
        <div class="row">
          <button class="primary" disabled={busy} onclick={mdnsApply}>Apply</button>
          <button onclick={() => (mdnsPreview = null)}>Change it</button>
        </div>
      {:else if mdnsOn !== clientsMdns}
        <div class="row"><button disabled={busy} onclick={mdnsCheck}>Check</button></div>
      {/if}
    {:else}
      <label class="check">
        <input type="checkbox" role="switch" aria-label="Listen for mDNS announcements" checked={clientsMdns} disabled />
        Listen for mDNS announcements
      </label>
      <p class="small muted" data-testid="mdns-admin-only">Only an admin can change this.</p>
    {/if}
  </div>
</section>

<style>
  dl {
    display: grid;
    grid-template-columns: max-content 1fr;
    gap: 6px 14px;
    margin: 0 0 12px;
  }
  dt {
    color: var(--muted);
  }
  dd {
    margin: 0;
  }
  .form {
    display: grid;
    gap: 12px;
    margin-top: 12px;
  }
  .form label {
    display: grid;
    gap: 4px;
  }
  .check {
    display: inline-flex !important;
    align-items: center;
    gap: 6px;
  }
  .row {
    display: flex;
    gap: 8px;
    flex-wrap: wrap;
    margin-top: 8px;
  }
  .preview {
    border: 1px dashed var(--border);
    border-radius: 8px;
    padding: 10px 12px;
  }
  .preview p {
    margin: 0 0 4px;
  }
  .warn-text {
    color: var(--warn-strong, var(--warn));
  }
  .mdns {
    margin-top: 18px;
    padding-top: 12px;
    border-top: 1px solid var(--border);
  }
  .mdns h3 {
    margin: 0 0 6px;
  }
</style>
