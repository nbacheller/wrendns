<script lang="ts">
  // REQ: API-016 (T23.8, ADR-903 §9, ADR-120, ADR-921, ADR-922) — the Routers page: UniFi, OPNsense
  // and Home Assistant as sources of device names. Each router shows its status (its last read on
  // this node, what it reported, the error if any) and where each credential comes from. Admins
  // add, change, check and remove routers; operators and viewers read. Credentials are entered
  // through SecretField (write-only, stored by name); the certificate is fetched from the
  // console and trusted only when the admin chooses it.
  import { api, ApiError, type S } from '../lib/api';
  import { poll } from '../lib/poll';
  import { session } from '../lib/session.svelte';
  import { dateTime } from '../lib/format';
  import ErrorNote from '../lib/components/ErrorNote.svelte';
  import HelpButton from '../lib/components/HelpButton.svelte';
  import SecretField from '../lib/components/SecretField.svelte';
  import { href } from '../lib/router.svelte';

  type Kind = 'unifi' | 'opnsense' | 'home_assistant';
  type Entry = S['RouterEntry'];

  let items = $state<Entry[]>([]);
  let error = $state<unknown>(null);
  let notice = $state('');
  const isAdmin = $derived(session.user?.role === 'admin');

  const kindLabel: Record<string, string> = { unifi: 'UniFi', opnsense: 'OPNsense', home_assistant: 'Home Assistant' };
  const stateLabel: Record<string, string> = {
    ok: 'Reading',
    failing: 'Failing (keeping its last answer)',
    waiting: 'Not read yet',
    skipped: 'Not read on this node',
  };
  const credLabel: Record<string, string> = {
    api_key: 'API key',
    api_secret: 'API secret',
    password: 'Password',
  };

  async function load() {
    try {
      const r = await api.routers();
      items = r.items;
      error = null;
    } catch (e) {
      error = e;
    }
  }
  $effect(() => poll(load, 15_000));

  function when(s: number | undefined | null): string {
    return s ? dateTime(s) : 'never';
  }

  // ---- the editor: one router, a new one or the one being changed
  type Form = {
    original: string | null;
    name: string;
    kind: Kind;
    url: string;
    site: string;
    username: string;
    api_key_ref: string | undefined;
    api_secret_ref: string | undefined;
    password_ref: string | undefined;
    tls_ca_pem: string;
    tls_server_name: string;
    interval_secs: number;
  };
  let form = $state<Form | null>(null);
  let formError = $state('');
  let checkOut = $state<{ ok: boolean; text: string } | null>(null);
  let cert = $state<S['RouterCertificate'] | null>(null);
  let certError = $state('');
  let busy = $state(false);
  let confirmDelete = $state<string | null>(null);

  function blank(): Form {
    return { original: null, name: '', kind: 'unifi', url: 'https://', site: 'default', username: '', api_key_ref: undefined, api_secret_ref: undefined, password_ref: undefined, tls_ca_pem: '', tls_server_name: '', interval_secs: 300 };
  }

  function openAdd() {
    form = blank();
    formError = '';
    checkOut = null;
    cert = null;
    certError = '';
    notice = '';
  }

  function openEdit(e: Entry) {
    const d = e.definition as Record<string, unknown>;
    const s = (k: string) => (typeof d[k] === 'string' ? (d[k] as string) : undefined);
    form = {
      original: e.name,
      name: e.name,
      kind: e.kind as Kind,
      url: e.url,
      site: s('site') ?? 'default',
      username: s('username') ?? '',
      api_key_ref: s('api_key_ref'),
      api_secret_ref: s('api_secret_ref'),
      password_ref: s('password_ref'),
      tls_ca_pem: s('tls_ca_pem') ?? '',
      tls_server_name: s('tls_server_name') ?? '',
      interval_secs: typeof d.interval_secs === 'number' ? d.interval_secs : 300,
    };
    formError = '';
    checkOut = null;
    cert = null;
    certError = '';
    notice = '';
  }

  function closeForm() {
    form = null;
    formError = '';
    checkOut = null;
  }

  /** The request body the form sends: only the fields the router's kind takes. */
  function bodyOf(f: Form): Record<string, unknown> {
    const b: Record<string, unknown> = { type: f.kind, url: f.url.trim(), interval_secs: f.interval_secs };
    if (f.kind === 'unifi') {
      if (f.site.trim()) b.site = f.site.trim();
      if (f.username.trim()) b.username = f.username.trim();
      if (f.password_ref) b.password_ref = f.password_ref;
    }
    if (f.kind === 'opnsense' && f.api_secret_ref) b.api_secret_ref = f.api_secret_ref;
    if (f.api_key_ref) b.api_key_ref = f.api_key_ref;
    if (f.kind !== 'home_assistant' && f.tls_ca_pem.trim()) b.tls_ca_pem = f.tls_ca_pem.trim() + '\n';
    if (f.kind !== 'home_assistant' && f.tls_server_name.trim()) b.tls_server_name = f.tls_server_name.trim();
    return b;
  }

  /** The name a new value is stored under: `<kind>.<router>.<field>` (ADR-903 §9). */
  function secretName(f: Form, field: string): string {
    return `${f.kind}.${(f.name.trim() || 'new').toLowerCase()}.${field}`;
  }

  const nameOk = (n: string) => /^[a-z0-9][a-z0-9._-]{0,62}$/.test(n);
  // REQ: API-016 (review of T23.8) — Add never replaces a router: a name another router holds is
  // refused before anything is stored under it (the form's secrets are named after the router).
  const nameTaken = $derived.by(() => {
    if (form === null || form.original !== null) return false;
    const name = form.name.trim().toLowerCase();
    return items.some((i) => i.name === name);
  });

  async function check() {
    if (!form) return;
    if (!form.name.trim()) {
      checkOut = { ok: false, text: 'Name the router first: a check of a stored credential needs the name it is stored under.' };
      return;
    }
    checkOut = { ok: true, text: 'Checking…' };
    try {
      const r = await api.checkRouter({ ...bodyOf(form), name: form.name.trim().toLowerCase() });
      if (r.ok) {
        checkOut = { ok: true, text: `It works: ${r.devices} device${r.devices === 1 ? '' : 's'}${r.networks ? ` and ${r.networks} network${r.networks === 1 ? '' : 's'}` : ''} read. Nothing was saved.` };
      } else {
        checkOut = { ok: false, text: `${r.error ?? 'The read failed.'} Nothing was saved.` };
      }
      if (!r.credentialSent) {
        checkOut = { ok: checkOut.ok, text: `${checkOut.text} A stored credential wasn't sent: the address or TLS settings differ from the saved router, so it's only sent to the address it was saved for.` };
      }
    } catch (e) {
      checkOut = { ok: false, text: e instanceof ApiError ? e.message : 'The check could not run.' };
    }
  }

  async function fetchCert() {
    if (!form) return;
    certError = '';
    cert = null;
    try {
      cert = await api.routerCertificate(form.url.trim());
    } catch (e) {
      certError = e instanceof ApiError ? e.message : 'The certificate could not be read.';
    }
  }

  function trustCert() {
    if (!form || !cert) return;
    form.tls_ca_pem = cert.pem;
    form.tls_server_name = cert.suggestedTlsServerName ?? '';
    notice = 'The certificate is in the form. Save the router to trust it. Check it before you save.';
  }

  async function save() {
    if (!form) return;
    formError = '';
    const name = form.name.trim().toLowerCase();
    if (nameTaken) {
      formError = `A router named ${name} exists. Change it, or choose another name.`;
      return;
    }
    if (!nameOk(name)) {
      formError = 'The name uses lower-case letters, digits, dots, dashes, and underscores, and starts with a letter or digit.';
      return;
    }
    if (!/^https?:\/\//.test(form.url.trim())) {
      formError = 'The address starts with https:// (the console) or http:// (Home Assistant on the LAN).';
      return;
    }
    if (form.interval_secs < 30) {
      formError = 'Read at least every 30 seconds.';
      return;
    }
    busy = true;
    try {
      await api.putRouter(name, bodyOf(form));
      notice = `Saved ${name}. It's read on the next round, with no restart.`;
      closeForm();
      await load();
    } catch (e) {
      formError = e instanceof ApiError ? e.message : 'The router could not be saved.';
    } finally {
      busy = false;
    }
  }

  async function remove(name: string) {
    busy = true;
    try {
      await api.deleteRouter(name);
      notice = `Removed ${name}. Its names are gone from the next read.`;
      confirmDelete = null;
      await load();
    } catch (e) {
      notice = e instanceof ApiError ? e.message : 'The router could not be removed.';
    } finally {
      busy = false;
    }
  }

  /** The credential fields a kind takes, in the order the form shows them. */
  function fieldsOf(k: Kind): ('api_key' | 'api_secret' | 'password')[] {
    if (k === 'unifi') return ['api_key', 'password'];
    if (k === 'opnsense') return ['api_key', 'api_secret'];
    return ['api_key'];
  }
  const refOf = (f: Form, field: string): string | undefined =>
    field === 'api_key' ? f.api_key_ref : field === 'api_secret' ? f.api_secret_ref : f.password_ref;
  function setRef(f: Form, field: string, name: string | undefined) {
    if (field === 'api_key') f.api_key_ref = name;
    else if (field === 'api_secret') f.api_secret_ref = name;
    else f.password_ref = name;
  }
  const keyLabel = (k: Kind, field: string) =>
    field === 'api_key' && k === 'home_assistant' ? 'Long-lived access token' : credLabel[field] ?? field;
</script>

<div class="page">
  <h1>Routers<HelpButton id="routers" /></h1>
  <p class="muted">
    Routers and Home Assistant tell TelltaleDNS the names of the devices on your network, so a device shows up by name. They're read, never changed.
    {#if !isAdmin}Only an admin adds, changes, checks, or removes a router.{/if}
  </p>
  <ErrorNote {error} />
  {#if notice}<p class="notice" role="status" data-testid="routers-notice">{notice}</p>{/if}

  {#if isAdmin}
    <div class="row-actions">
      <button type="button" class="btn primary" data-testid="routers-add" onclick={openAdd} disabled={form !== null}>Add a router</button>
    </div>
  {/if}

  {#if form}
    <section class="card" data-testid="routers-editor" aria-label={form.original ? `Edit ${form.original}` : 'Add a router'}>
      <h2>{form.original ? `Change ${form.original}` : 'Add a router'}</h2>
      <div class="grid">
        <label>
          <span>Kind {#if form.kind === 'unifi'}<HelpButton id="router-unifi" />{:else if form.kind === 'home_assistant'}<HelpButton id="router-home-assistant" />{/if}</span>
          <select bind:value={form.kind} disabled={form.original !== null} aria-label="Kind">
            <option value="unifi">UniFi (a console, or the Network application)</option>
            <option value="opnsense">OPNsense</option>
            <option value="home_assistant">Home Assistant</option>
          </select>
        </label>
        <label>
          <span>Name</span>
          <input bind:value={form.name} disabled={form.original !== null} placeholder="home-gateway" autocomplete="off" aria-label="Name" />
          {#if nameTaken}<span class="small bad-text" role="alert" data-testid="routers-name-taken">A router named {form.name.trim().toLowerCase()} exists. Change it, or choose another name.</span>{/if}
        </label>
        <label>
          <span>Address</span>
          <input bind:value={form.url} placeholder={form.kind === 'home_assistant' ? 'http://homeassistant.local:8123' : 'https://192.168.1.1'} autocomplete="off" aria-label="Address" />
        </label>
        {#if form.kind === 'unifi'}
          <label>
            <span>Site</span>
            <input bind:value={form.site} placeholder="default" autocomplete="off" aria-label="Site" />
          </label>
          <label>
            <span>Username (without an API key)</span>
            <input bind:value={form.username} autocomplete="off" aria-label="Username" />
          </label>
        {/if}
        <label>
          <span>Read every (seconds)</span>
          <input type="number" min="30" bind:value={form.interval_secs} aria-label="Read every (seconds)" />
        </label>
      </div>

      <h3>Credentials</h3>
      <!-- REQ: API-015 (T24.16, ADR-903 §9) — a router's credentials are entered through SecretField, like every other. -->
      <p class="small muted">Entered once, stored encrypted on the node, and never shown again. The form keeps the stored name. <a href={href('/settings', { tab: 'secrets' })}>Stored secrets</a> lists them.</p>
      {#if form.name.trim() && !nameTaken}
        {#each fieldsOf(form.kind) as field (field)}
          <SecretField
            label={keyLabel(form.kind, field)}
            testid={`router-secret-${field}`}
            reference={refOf(form, field)}
            defaultName={secretName(form, field)}
            canSet={isAdmin}
            onreference={(n) => form && setRef(form, field, n)}
          />
        {/each}
      {:else if !nameTaken}
        <p class="small muted">Enter a name first: the stored secrets are named after the router.</p>
      {/if}

      <h3>Certificate <HelpButton id="router-certificate" /></h3>
      <p class="small muted">A console's own certificate names <span class="mono">unifi.local</span>, not its address. Fetch it from the console and trust it: nothing else is trusted for this router.</p>
      <label class="wide">
        <span>Certificate (PEM)</span>
        <textarea rows="4" bind:value={form.tls_ca_pem} placeholder="-----BEGIN CERTIFICATE-----" aria-label="Certificate (PEM)" spellcheck="false"></textarea>
      </label>
      <label>
        <span>Name the certificate checks (optional)</span>
        <input bind:value={form.tls_server_name} placeholder="unifi.local" autocomplete="off" aria-label="Name the certificate checks" />
      </label>
      <div class="row-actions">
        <button type="button" class="btn" data-testid="routers-fetch-cert" onclick={fetchCert} disabled={!/^https:\/\//.test(form.url.trim())}>Fetch the console's certificate</button>
        {#if cert}<button type="button" class="btn" onclick={trustCert}>Trust this certificate</button>{/if}
      </div>
      {#if certError}<p class="small bad-text" role="alert">{certError}</p>{/if}
      {#if cert}
        <div class="small" data-testid="routers-cert">
          <p>Names: <span class="mono">{cert.names.join(', ')}</span></p>
          <p>SHA-256: <span class="mono">{cert.fingerprintSha256}</span></p>
          {#if cert.suggestedTlsServerName}<p>Use the name <span class="mono">{cert.suggestedTlsServerName}</span> to check it.</p>{/if}
        </div>
      {/if}

      {#if formError}<p class="bad-text" role="alert">{formError}</p>{/if}
      {#if checkOut}<p class={checkOut.ok ? 'ok-text' : 'bad-text'} role="status" data-testid="routers-check">{checkOut.text}</p>{/if}
      <div class="row-actions">
        <button type="button" class="btn" data-testid="routers-check-button" onclick={check} disabled={busy || !form.url.trim()}>Check it</button>
        <HelpButton id="router-check" />
        <button type="button" class="btn primary" data-testid="routers-save" onclick={save} disabled={busy || nameTaken}>Save the router</button>
        <button type="button" class="btn" onclick={closeForm}>Cancel</button>
      </div>
    </section>
  {/if}

  {#if items.length === 0 && !error}
    <p class="empty" data-testid="routers-empty">No routers yet. Add UniFi, OPNsense, or Home Assistant to name your devices.</p>
  {/if}

  {#each items as e (e.name)}
    <section class="card router" data-testid="router-card" aria-label={e.name}>
      <div class="card-head">
        <h2>{e.name}</h2>
        <span class="badge info">{kindLabel[e.kind] ?? e.kind}</span>
        {#if e.source === 'file'}<span class="badge warn" data-testid="router-file">Set by file</span>{:else}<span class="badge">From the UI</span>{/if}
      </div>
      <p class="mono small">{e.url}</p>
      <p data-testid="router-state">
        <span class={e.status.state === 'ok' ? 'badge ok' : e.status.state === 'failing' ? 'badge bad' : 'badge'}>{stateLabel[e.status.state] ?? e.status.state}</span>
        {#if e.status.state === 'skipped'}<span class="small muted">({e.status.polledBy})</span>{/if}
        {#if e.status.lastPoll}<span class="small muted">Last read {when(e.status.lastPoll)}: {e.status.devices} devices{e.status.networks ? `, ${e.status.networks} networks` : ''}.</span>{/if}
      </p>
      {#if e.status.error}<p class="small bad-text" data-testid="router-error">{e.status.error}</p>{/if}
      <ul class="creds">
        {#each e.credentials as c (c.field)}
          <li>
            <span>{credLabel[c.field] ?? c.field}:</span>
            {#if c.source === 'file'}
              <span class="small">set by file</span>
            {:else if c.source === 'stored'}
              <span class="small">stored as <span class="mono">{c.secret}</span></span>
              {#if c.readable === false}<span class="badge bad" data-testid="router-credential-issue">{c.issue ?? "can't be read here"}</span>{:else}<span class="badge ok">readable</span>{/if}
            {:else}
              <span class="small muted">none</span>
            {/if}
          </li>
        {/each}
      </ul>
      {#if (e.definition as Record<string, unknown>).tls_insecure_skip_verify}
        <p class="small bad-text">This router's certificate isn't checked. Trust its certificate instead.</p>
      {/if}
      {#if e.source === 'file'}
        <p class="small muted">The configuration file defines this router, so it's read-only here.</p>
      {:else if isAdmin}
        <div class="row-actions">
          <button type="button" class="btn" data-testid="router-edit" onclick={() => openEdit(e)} disabled={form !== null}>Change</button>
          {#if confirmDelete === e.name}
            <button type="button" class="btn danger" data-testid="router-delete-confirm" onclick={() => remove(e.name)} disabled={busy}>Yes, remove {e.name}</button>
            <button type="button" class="btn" onclick={() => (confirmDelete = null)}>Keep it</button>
          {:else}
            <button type="button" class="btn danger" data-testid="router-delete" onclick={() => (confirmDelete = e.name)}>Remove</button>
          {/if}
        </div>
      {/if}
    </section>
  {/each}
</div>

<style>
  .row-actions {
    display: flex;
    gap: 0.5rem;
    flex-wrap: wrap;
    margin: 0.5rem 0;
  }
  .grid {
    display: grid;
    gap: 0.75rem;
    grid-template-columns: repeat(auto-fit, minmax(14rem, 1fr));
  }
  label {
    display: grid;
    gap: 0.25rem;
  }
  label.wide {
    margin-top: 0.5rem;
  }
  textarea {
    width: 100%;
    font-family: ui-monospace, monospace;
    font-size: 0.85rem;
  }
  .creds {
    list-style: none;
    padding: 0;
    margin: 0.25rem 0;
    display: grid;
    gap: 0.25rem;
  }
  .router .card-head {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    flex-wrap: wrap;
  }
  .ok-text {
    color: var(--ok, #1b7f3a);
  }
  .bad-text {
    color: var(--bad, #b00020);
  }
  .notice {
    padding: 0.5rem 0.75rem;
    border-radius: 0.5rem;
    background: var(--panel-2, rgba(127, 127, 127, 0.12));
  }
</style>
