<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<script lang="ts">
  // REQ: CLD-904 (T36.10b, ADR-1084, ADR-1104) — Settings → DNS providers (admins): the accounts at a
  // DNS host (or a self-run server) the node may write record sets in. T36.10b step b3 (CLD-919) adds the
  // **Test** button (the scope the credential has, never the secret; the first success ends the entry's
  // dry run), the dry-run state, and the **Records** table with **Adopt** (the node changes or deletes only
  // record sets it made or an admin adopted). A kind with no provider code yet says so. A provider added, changed or removed applies on every node
  // within seconds; one the configuration file defines is read-only ("set by file"); the credential goes
  // through SecretField (write-only, stored by name) and the entry holds only its name; the first
  // provider waits until every cluster member's build knows the table, and the refusal is shown in the
  // form with the member named.
  import { api, ApiError, type S } from '../api';
  import { poll } from '../poll';
  import ErrorNote from './ErrorNote.svelte';
  import HelpButton from './HelpButton.svelte';
  import SecretField, { secretNameFor } from './SecretField.svelte';
  import { href } from '../router.svelte';

  type Entry = S['DnsProviderEntry'];
  type Kind = 'azure_dns' | 'cloudflare' | 'route53' | 'rfc2136';

  const KINDS: { id: Kind; label: string; secret: string }[] = [
    { id: 'azure_dns', label: 'Azure DNS', secret: 'the application\'s client secret' },
    { id: 'cloudflare', label: 'Cloudflare', secret: 'the API token' },
    { id: 'route53', label: 'Amazon Route 53', secret: 'the access key ID and secret joined with a colon (AKIA…:secret)' },
    { id: 'rfc2136', label: 'RFC 2136 (BIND, Knot, PowerDNS)', secret: 'the TSIG key\'s secret (HMAC-SHA256, base64)' },
  ];
  const kindLabel = (id: string) => KINDS.find((k) => k.id === id)?.label ?? id;

  let items = $state<Entry[]>([]);
  let held = $state(false);
  let heldReason = $state('');
  let loaded = $state(false);
  let error = $state<unknown>(null);
  let notice = $state('');

  // REQ: CLD-904, CLD-919 — the latest Test of each provider, and its record sets with their owners.
  let testing = $state<string | null>(null);
  let tests = $state<Record<string, S['DnsProviderTestResult'] | { failed: string }>>({});
  let recordsOf = $state<Record<string, S['DnsProviderRecords'] | { failed: string }>>({});
  let recordsBusy = $state<string | null>(null);

  async function runTest(name: string) {
    testing = name;
    try {
      tests[name] = await api.testDnsProvider(name);
    } catch (e) {
      tests[name] = { failed: e instanceof ApiError ? e.message : 'The test could not be run.' };
    } finally {
      testing = null;
    }
    // The first success ended dry run: show the entry as it is now.
    await load();
  }

  async function loadRecords(name: string) {
    recordsBusy = name;
    try {
      recordsOf[name] = await api.dnsProviderRecords(name);
    } catch (e) {
      recordsOf[name] = { failed: e instanceof ApiError ? e.message : 'The records could not be read.' };
    } finally {
      recordsBusy = null;
    }
  }

  async function adopt(name: string, r: S['DnsProviderRecord']) {
    recordsBusy = name;
    try {
      await api.adoptDnsRecord(name, { name: r.name, recordType: r.recordType });
      notice = `Adopted ${r.name} (${r.recordType}). The node may now change and delete it.`;
    } catch (e) {
      notice = e instanceof ApiError ? e.message : 'The record set could not be adopted.';
    }
    await loadRecords(name);
  }

  const failedOf = (v: unknown): string | null =>
    v && typeof v === 'object' && 'failed' in v ? String((v as { failed: string }).failed) : null;

  async function load() {
    try {
      const r = await api.dnsProviders();
      items = r.items;
      held = r.held ?? false;
      heldReason = r.heldReason ?? '';
      loaded = true;
      error = null;
    } catch (e) {
      error = e;
    }
  }
  $effect(() => poll(load, 10_000));

  type Form = {
    original: string | null;
    name: string;
    kind: Kind;
    zone: string;
    credential_ref: string | undefined;
    subscription: string;
    resource_group: string;
    tenant: string;
    client_id: string;
    hosted_zone_id: string;
    server: string;
    key_name: string;
    delegated_to: string;
    dry_run: boolean;
    max_writes_per_hour: number;
    max_writes_per_minute: number;
  };
  let form = $state<Form | null>(null);
  let formError = $state('');
  let busy = $state(false);
  let confirmDelete = $state<string | null>(null);
  // A secret typed and not yet saved: Save the provider waits for it.
  let secretDirty = $state(false);

  function blank(): Form {
    return {
      original: null,
      name: '',
      kind: 'cloudflare',
      zone: '',
      credential_ref: undefined,
      subscription: '',
      resource_group: '',
      tenant: '',
      client_id: '',
      hosted_zone_id: '',
      server: '',
      key_name: '',
      delegated_to: '',
      // A new entry starts in dry run until its first successful test (design 4.5).
      dry_run: true,
      max_writes_per_hour: 30,
      max_writes_per_minute: 5,
    };
  }

  function openAdd() {
    form = blank();
    formError = '';
    notice = '';
  }

  function openEdit(e: Entry) {
    const d = e.definition as Record<string, unknown>;
    const s = (k: string) => (typeof d[k] === 'string' ? (d[k] as string) : '');
    const n = (k: string, dflt: number) => (typeof d[k] === 'number' ? (d[k] as number) : dflt);
    form = {
      original: e.name,
      name: e.name,
      kind: e.kind as Kind,
      zone: e.zone,
      credential_ref: e.credentialSecret ?? undefined,
      subscription: s('subscription'),
      resource_group: s('resource_group'),
      tenant: s('tenant'),
      client_id: s('client_id'),
      hosted_zone_id: s('hosted_zone_id'),
      server: s('server'),
      key_name: s('key_name'),
      delegated_to: s('delegated_to'),
      dry_run: e.dryRun,
      max_writes_per_hour: n('max_writes_per_hour', 30),
      max_writes_per_minute: n('max_writes_per_minute', 5),
    };
    formError = '';
    notice = '';
  }

  function closeForm() {
    form = null;
    formError = '';
    secretDirty = false;
  }

  /** The request body: the fields of `[[dns_provider]]` for the kind; the credential by name only. */
  function bodyOf(f: Form): Record<string, unknown> {
    const b: Record<string, unknown> = {
      kind: f.kind,
      zone: f.zone.trim().toLowerCase().replace(/\.$/, ''),
      dry_run: f.dry_run,
      max_writes_per_hour: f.max_writes_per_hour,
      max_writes_per_minute: f.max_writes_per_minute,
    };
    if (f.credential_ref) b.credential_ref = f.credential_ref;
    const set = (k: string, v: string) => {
      if (v.trim()) b[k] = v.trim();
    };
    if (f.kind === 'azure_dns') {
      set('subscription', f.subscription);
      set('resource_group', f.resource_group);
      set('tenant', f.tenant);
      set('client_id', f.client_id);
    } else if (f.kind === 'route53') {
      set('hosted_zone_id', f.hosted_zone_id);
    } else if (f.kind === 'rfc2136') {
      set('server', f.server);
      set('key_name', f.key_name);
    }
    set('delegated_to', f.delegated_to.replace(/\.$/, ''));
    return b;
  }

  const nameOk = (n: string) => /^[a-z0-9][a-z0-9._-]{0,62}$/.test(n);
  const nameTaken = $derived.by(() => {
    if (form === null || form.original !== null) return false;
    return items.some((i) => i.name === form!.name.trim());
  });

  // What to grant, shown before the secret field. The record set names the challenge only: the
  // ACME DNS-01 name for a location, `_acme-challenge.<label>` in the zone.
  const challenge = (f: Form) => `_acme-challenge.<location>.${f.zone.trim() || '<zone>'}`;
  const azureScope = (f: Form) =>
    `az role assignment create --assignee ${f.client_id.trim() || '<application id>'} --role "DNS Zone Contributor" --scope /subscriptions/${f.subscription.trim() || '<subscription>'}/resourceGroups/${f.resource_group.trim() || '<resource group>'}/providers/Microsoft.Network/dnszones/${f.zone.trim() || '<zone>'}/TXT/_acme-challenge.<location>`;
  const route53Policy = (f: Form) =>
    JSON.stringify(
      {
        Version: '2012-10-17',
        Statement: [
          {
            Effect: 'Allow',
            Action: 'route53:ChangeResourceRecordSets',
            Resource: `arn:aws:route53:::hostedzone/${f.hosted_zone_id.trim() || '<hosted zone ID>'}`,
            Condition: {
              'ForAllValues:StringEquals': {
                'route53:ChangeResourceRecordSetsNormalizedRecordNames': [challenge(f)],
                'route53:ChangeResourceRecordSetsRecordTypes': ['TXT'],
                'route53:ChangeResourceRecordSetsActions': ['UPSERT', 'DELETE'],
              },
            },
          },
          {
            Effect: 'Allow',
            Action: ['route53:ListResourceRecordSets', 'route53:GetHostedZone', 'route53:GetChange', 'route53:ListHostedZonesByName'],
            Resource: '*',
          },
        ],
      },
      null,
      2,
    );
  const bindPolicy = (f: Form) => `update-policy { grant ${f.key_name.trim() || '<key name>'} name ${challenge(f)}. TXT; };
allow-transfer { key ${f.key_name.trim() || '<key name>'}; };`;

  async function save() {
    if (!form) return;
    formError = '';
    const name = form.name.trim();
    if (!nameOk(name)) {
      formError = 'The name is 1 to 63 lower-case letters, digits, dots, dashes or underscores.';
      return;
    }
    if (nameTaken) {
      formError = `A provider named ${name} exists. Change the name, or choose it from the list to change it.`;
      return;
    }
    if (!form.zone.trim().includes('.')) {
      formError = 'Enter the zone the provider serves, such as example.net.';
      return;
    }
    if (!form.credential_ref) {
      formError = 'Store the credential first: a provider names a stored secret and holds no credential itself.';
      return;
    }
    busy = true;
    try {
      await api.putDnsProvider(name, bodyOf(form));
      notice = `Saved ${name}. It is stored and shared with the cluster, and it starts in dry run until its first successful test.`;
      closeForm();
      await load();
    } catch (e) {
      // The gate's refusal (409 upgrade_required) names the member to upgrade; it is shown as it is.
      formError = e instanceof ApiError ? e.message : 'The provider could not be saved.';
    } finally {
      busy = false;
    }
  }

  async function remove(name: string) {
    busy = true;
    try {
      await api.deleteDnsProvider(name);
      notice = `Removed ${name}.`;
      confirmDelete = null;
      await load();
    } catch (e) {
      notice = e instanceof ApiError ? e.message : 'The provider could not be removed.';
    } finally {
      busy = false;
    }
  }
</script>

<section class="card" data-testid="dnsproviders-tab">
  <h2>DNS providers<HelpButton id="dns-providers" /></h2>
  <p class="muted">
    The accounts at a DNS host (Azure DNS, Cloudflare, Route 53) or a self-run server (RFC 2136) where WrenDNS may write a few record sets,
    such as the challenge for a certificate. Each holds only the name of a stored secret, never the credential itself, and it can be limited to one
    name. <strong data-testid="dnsproviders-intro">Every entry starts in dry run:</strong> changes are recorded in the audit log and none is
    sent until the entry's first successful test. The node changes or deletes only record sets it made itself or that you adopt.
  </p>
  <ErrorNote {error} />
  {#if notice}<p class="notice" role="status" data-testid="dnsproviders-notice">{notice}</p>{/if}
  {#if held}
    <p class="notice warn" role="status" data-testid="dnsproviders-held">
      These providers are held back on this node: {heldReason || 'waiting to hear from the cluster members'}. DNS answers as without them, and they are
      applied when every member knows them.
    </p>
  {/if}
  <div class="row-actions">
    <button type="button" class="btn primary" data-testid="dnsproviders-add" onclick={openAdd} disabled={form !== null}>Add a provider</button>
  </div>

  {#if form}
    <div class="card inner" data-testid="dnsproviders-editor" role="group" aria-label={form.original ? `Edit ${form.original}` : 'Add a provider'}>
      <h3>{form.original ? `Change ${form.original}` : 'Add a provider'}</h3>
      <div class="grid">
        <label>
          <span>Name</span>
          <input bind:value={form.name} disabled={form.original !== null} placeholder="azure-home" autocomplete="off" aria-label="Name" />
          {#if nameTaken}<span class="small bad-text" role="alert" data-testid="dnsproviders-name-taken">A provider named {form.name.trim()} exists.</span>{/if}
        </label>
        <label>
          <span>Kind</span>
          <select bind:value={form.kind} aria-label="Kind">
            {#each KINDS as k (k.id)}<option value={k.id}>{k.label}</option>{/each}
          </select>
        </label>
        <label>
          <span>Zone</span>
          <input bind:value={form.zone} placeholder="example.net" autocomplete="off" aria-label="Zone" />
        </label>
        {#if form.kind === 'azure_dns'}
          <label><span>Subscription ID</span><input bind:value={form.subscription} autocomplete="off" aria-label="Subscription ID" /></label>
          <label><span>Resource group</span><input bind:value={form.resource_group} autocomplete="off" aria-label="Resource group" /></label>
          <label><span>Tenant ID</span><input bind:value={form.tenant} autocomplete="off" aria-label="Tenant ID" /></label>
          <label><span>Application (client) ID</span><input bind:value={form.client_id} autocomplete="off" aria-label="Application ID" /></label>
        {:else if form.kind === 'route53'}
          <label><span>Hosted zone ID (optional)</span><input bind:value={form.hosted_zone_id} placeholder="Z0123456789ABC" autocomplete="off" aria-label="Hosted zone ID" /></label>
        {:else if form.kind === 'rfc2136'}
          <label><span>Server</span><input bind:value={form.server} placeholder="ns1.example.net or 192.168.1.53:53" autocomplete="off" aria-label="Server" /></label>
          <label><span>TSIG key name</span><input bind:value={form.key_name} placeholder="acme-key" autocomplete="off" aria-label="TSIG key name" /></label>
        {/if}
      </div>

      <h4>What to grant first</h4>
      <div class="small" data-testid="dnsproviders-scope">
        {#if form.kind === 'azure_dns'}
          <p>
            Give the application a role on one record set, not the zone. The record set must exist first (create an empty <code>TXT</code> record set
            named <code>_acme-challenge.&lt;location&gt;</code>), then run:
          </p>
          <pre class="mono">{azureScope(form)}</pre>
        {:else if form.kind === 'cloudflare'}
          <p>
            Create an API token with <em>Zone, DNS, Edit</em> for this one zone only. Cloudflare cannot limit a token to one record, so if the zone holds
            anything else that matters, delegate the challenge name to a separate zone instead (below).
          </p>
        {:else if form.kind === 'route53'}
          <p>Attach this policy to the IAM user whose access key you store. It allows changing only the challenge name, only <code>TXT</code> records, only <code>UPSERT</code> and <code>DELETE</code>:</p>
          <pre class="mono">{route53Policy(form)}</pre>
          <p>
            Leave the hosted zone ID empty to look the zone up by name (the <code>ListHostedZonesByName</code> permission above). Test reads the zone with the key and shows that it is accepted; Route 53 does not
            report what a key may change, so a change the policy does not allow is refused when it is made. A record set that is an alias or has a routing policy is never changed.
          </p>
        {:else}
          <p>Limit the TSIG key to the challenge name on the server, and let it read the zone (WrenDNS lists the zone with a transfer before every change), for example in BIND:</p>
          <pre class="mono">{bindPolicy(form)}</pre>
          <p>
            Test sends a signed update that changes nothing and a signed zone transfer, and shows whether the server accepts the key for both. The server does not report what a key may change, so the grant for a
            name and a type is checked when a record is written, and a refusal then says so.
          </p>
        {/if}
      </div>

      <h4>Credential</h4>
      <p class="small muted">
        {KINDS.find((k) => k.id === form!.kind)?.secret}. Entered once, stored encrypted on the node and replicated to the other nodes, and never shown
        again. <a href={href('/settings', { tab: 'secrets' })}>Stored secrets</a> lists them.
      </p>
      {#if form.name.trim() && !nameTaken}
        <SecretField
          label="Credential"
          testid="dnsproviders-secret"
          reference={form.credential_ref}
          defaultName={secretNameFor('dns', form.name, 'credential')}
          canSet={true}
          ondirty={(d) => (secretDirty = d)}
          onreference={(n) => form && (form.credential_ref = n)}
        />
      {:else if !nameTaken}
        <p class="small muted">Enter a name first: the stored secret is named after the provider.</p>
      {/if}
      {#if secretDirty}<p class="notice warn small" role="status">Save or discard the secret you typed first; Save the provider waits for it.</p>{/if}

      <h4>Delegation and limits<HelpButton id="dns-provider-delegation" /></h4>
      <div class="grid">
        <label>
          <span>Delegate the challenge to (optional)</span>
          <input bind:value={form.delegated_to} placeholder="home.acme-validation.example.org" autocomplete="off" aria-label="Delegate the challenge to" />
        </label>
        <label class="check">
          <input type="checkbox" bind:checked={form.dry_run} />
          <span>Dry run: compute and record changes, never write</span>
        </label>
        <label>
          <span>Most writes an hour</span>
          <input type="number" min="1" max="1000" bind:value={form.max_writes_per_hour} aria-label="Most writes an hour" />
        </label>
        <label>
          <span>Most writes a minute</span>
          <input type="number" min="1" max="60" bind:value={form.max_writes_per_minute} aria-label="Most writes a minute" />
        </label>
      </div>

      {#if formError}<p class="bad-text" role="alert" data-testid="dnsproviders-form-error">{formError}</p>{/if}
      <div class="row-actions">
        <button type="button" class="btn primary" data-testid="dnsproviders-save" onclick={save} disabled={busy || nameTaken || secretDirty}>Save the provider</button>
        <button type="button" class="btn" onclick={closeForm}>Cancel</button>
      </div>
    </div>
  {/if}

  {#if loaded && items.length === 0 && !error}
    <p class="empty" data-testid="dnsproviders-empty">No providers yet. Add one to let this cluster manage a few records at your DNS host.</p>
  {/if}

  {#each items as e (e.name)}
    <div class="card inner provider" data-testid="dnsproviders-card" role="group" aria-label={e.name}>
      <div class="card-head">
        <h3>{e.name}</h3>
        <span class="small">{kindLabel(e.kind)}</span>
        <span class="mono small">{e.zone}</span>
        {#if e.source === 'file'}<span class="badge warn" data-testid="dnsproviders-file">Set by file</span>{:else}<span class="badge">From the UI</span>{/if}
        {#if e.state === 'not_used'}
          <span class="badge" data-testid="dnsproviders-state">Not used yet</span>
        {:else if e.state === 'ready'}
          <span class="badge ok" data-testid="dnsproviders-state">Ready</span>
        {/if}
        {#if e.dryRun}<span class="badge" data-testid="dnsproviders-dry">Dry run</span>{/if}
        {#if e.held}<span class="badge warn" data-testid="dnsproviders-card-held">Held back</span>{/if}
      </div>
      <ul class="facts small">
        <li>
          Credential: stored secret <span class="mono">{e.credentialSecret ?? 'none'}</span>
          {#if e.credentialSecret}
            {#if e.credentialPresent}<span class="badge ok">stored on this node</span>{:else}<span class="badge bad" data-testid="dnsproviders-secret-missing">not stored on this node</span>{/if}
          {/if}
        </li>
      </ul>
      <p class="small muted" data-testid="dnsproviders-detail">{e.detail}</p>
      <div class="row-actions">
        <button type="button" class="btn" data-testid="dnsproviders-test" onclick={() => runTest(e.name)} disabled={testing !== null || e.held}>
          {testing === e.name ? 'Testing…' : 'Test and show scope'}
        </button>
        <HelpButton id="dns-provider-test" />
        {#if e.state !== 'not_used'}
          <button type="button" class="btn" data-testid="dnsproviders-records" onclick={() => loadRecords(e.name)} disabled={recordsBusy !== null || e.held}>Records</button>
          <HelpButton id="dns-provider-ownership" />
        {/if}
      </div>
      {#if tests[e.name]}
        {@const t = tests[e.name]}
        <div class="test-result small" data-testid="dnsproviders-test-result" role="status">
          {#if failedOf(t)}
            <p class="bad-text">{failedOf(t)}</p>
          {:else}
            {@const r = t as S['DnsProviderTestResult']}
            {#if r.ok}
              <p><strong>The credential was accepted.</strong> {r.scope?.summary}</p>
              <ul>
                <li>Zone: <span class="mono">{r.scope?.zone}</span></li>
                <li>Record types it may write: <span class="mono">{r.scope?.recordTypes.join(', ')}</span></li>
                <li>
                  {#if r.scope?.recordSets}Limited to: <span class="mono">{r.scope.recordSets.join(', ')}</span>{:else}Any record set in the zone{/if}
                </li>
                {#each r.scope?.notes ?? [] as n (n)}<li>{n}</li>{/each}
              </ul>
              {#if r.scope?.broaderThanNeeded}
                <p class="notice warn" data-testid="dnsproviders-broad">
                  This credential can change more than WrenDNS needs. Narrow it at the provider to the challenge names (see What to grant first when you change this provider).
                </p>
              {/if}
              {#if r.dryRunCleared}
                <p data-testid="dnsproviders-dry-ended">The first test passed, so dry run is now off: changes to record sets this node owns are sent.</p>
              {/if}
            {:else}
              <p class="bad-text" data-testid="dnsproviders-test-error">{r.error}</p>
            {/if}
            {#if r.note}<p class="muted">{r.note}</p>{/if}
          {/if}
        </div>
      {/if}
      {#if recordsOf[e.name]}
        {@const rs = recordsOf[e.name]}
        <div class="small" data-testid="dnsproviders-records-table">
          {#if failedOf(rs)}
            <p class="bad-text">{failedOf(rs)}</p>
          {:else}
            {@const rec = rs as S['DnsProviderRecords']}
            {#if rec.items.length === 0}
              <p class="muted">No TXT, A or AAAA record sets in the zone.</p>
            {:else}
              <table>
                <thead><tr><th>Name</th><th>Type</th><th>TTL</th><th>Values</th><th>Owner</th><th></th></tr></thead>
                <tbody>
                  {#each rec.items as r (r.name + '/' + r.recordType)}
                    <tr data-testid="dnsproviders-record">
                      <td class="mono">{r.name}</td>
                      <td>{r.recordType}</td>
                      <td>{r.ttl}</td>
                      <td class="mono">{r.values.join(', ')}</td>
                      <td>
                        {#if r.owner}{r.owner === 'adopted' ? 'Adopted' : 'Created'} by {r.by}{:else}<span class="muted">Not owned: never changed or deleted</span>{/if}
                      </td>
                      <td>
                        {#if !r.owner}
                          <button type="button" class="btn" data-testid="dnsproviders-adopt" onclick={() => adopt(e.name, r)} disabled={recordsBusy !== null}>Adopt</button>
                        {/if}
                      </td>
                    </tr>
                  {/each}
                </tbody>
              </table>
            {/if}
          {/if}
        </div>
      {/if}
      {#if e.source === 'file'}
        <p class="small muted">The configuration file defines this provider, so it's read-only here.</p>
      {:else}
        <div class="row-actions">
          <button type="button" class="btn" data-testid="dnsproviders-edit" onclick={() => openEdit(e)} disabled={form !== null}>Change</button>
          {#if confirmDelete === e.name}
            <button type="button" class="btn danger" data-testid="dnsproviders-delete-confirm" onclick={() => remove(e.name)} disabled={busy}>Yes, remove {e.name}</button>
            <button type="button" class="btn" onclick={() => (confirmDelete = null)}>Keep it</button>
          {:else}
            <button type="button" class="btn danger" data-testid="dnsproviders-delete" onclick={() => (confirmDelete = e.name)}>Remove</button>
          {/if}
        </div>
      {/if}
    </div>
  {/each}
</section>

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
  label.check {
    display: flex;
    align-items: center;
    gap: 0.5rem;
  }
  pre {
    overflow-x: auto;
    padding: 0.5rem;
    white-space: pre-wrap;
    word-break: break-all;
  }
  .inner {
    margin-top: 0.75rem;
  }
  .provider .card-head {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    flex-wrap: wrap;
  }
  .facts {
    list-style: none;
    padding: 0;
    margin: 0.25rem 0;
    display: grid;
    gap: 0.25rem;
  }
  .bad-text {
    color: var(--bad);
  }
  .test-result,
  table {
    margin: 0.5rem 0;
  }
  table {
    width: 100%;
    border-collapse: collapse;
  }
  th,
  td {
    text-align: left;
    padding: 0.25rem 0.5rem;
    border-bottom: 1px solid var(--border);
  }
</style>
