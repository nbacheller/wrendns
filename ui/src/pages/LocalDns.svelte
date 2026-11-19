<script lang="ts">
  // REQ: API-011, DNS-010, UPS-007 (T3.12) — "Names on my network": the names WrenDNS answers
  // itself, grouped by domain (a zone-lite view: SOA/NS are generated, never asked for), plus the
  // domains sent to other servers. A wizard sets up a home domain; another sends a domain
  // elsewhere. Every change is previewed (sentence + diagram) and can be tested with Explain.
  import { api, ApiError, type S } from '../lib/api';
  import { href } from '../lib/router.svelte';
  import { session } from '../lib/session.svelte';
  import { currentMode } from '../lib/mode.svelte';
  import ErrorNote from '../lib/components/ErrorNote.svelte';
  import HelpButton from '../lib/components/HelpButton.svelte';
  import ChangePreview from '../lib/components/ChangePreview.svelte';
  import Drawer from '../lib/components/Drawer.svelte';
  import DeviceNamesCard from '../lib/components/DeviceNamesCard.svelte';

  let names = $state<S['LocalName'][]>([]);
  let forwards = $state<S['ForwardInfo'][]>([]);
  // REQ: DNS-018 (T7.22) — zones from the config files (shown since T8.6).
  let zones = $state<S['ZoneInfo'][]>([]);
  let error = $state<unknown>(null);
  const canEdit = $derived(session.user?.role === 'admin' || session.user?.role === 'operator');
  const advanced = $derived(currentMode() === 'advanced');
  const types = $derived(advanced ? ['A', 'AAAA', 'CNAME', 'PTR', 'TXT', 'MX', 'SRV'] : ['A', 'AAAA', 'CNAME']);

  function load() {
    Promise.all([api.localNames(), api.forwards()])
      .then(([n, f]) => {
        names = n.items;
        forwards = f.items;
        error = null;
      })
      .catch((e) => (error = e));
    api
      .zones()
      .then((z) => (zones = z.items))
      .catch(() => (zones = []));
  }
  $effect(load);

  /** Names grouped by their domain (everything after the first label). */
  const groups = $derived.by(() => {
    const m = new Map<string, S['LocalName'][]>();
    for (const n of names) {
      const i = n.name.indexOf('.');
      const d = i < 0 ? n.name : n.name.slice(i + 1);
      m.set(d, [...(m.get(d) ?? []), n]);
    }
    return [...m.entries()].sort(([a], [b]) => a.localeCompare(b));
  });

  // ---- one form for "add a name", "edit", and the home-domain wizard
  // REQ: DNS-010 (T27.7) — a record's TTL (blank: the default) and whether only this node keeps it.
  type Editor = { title: string; name: string; rtype: string; value: string; ttl: string; nodeOnly: boolean; existing: S['RecordInput'][]; wizard: boolean; step: number; domain: string; label: string };
  let ed = $state<Editor | null>(null);
  let busy = $state(false);
  let formError = $state('');
  let done = $state('');

  function openAdd() {
    ed = { title: 'Add a name', name: '', rtype: 'A', value: '', ttl: '', nodeOnly: false, existing: [], wizard: false, step: 1, domain: '', label: '' };
    formError = done = '';
  }
  function openEdit(n: S['LocalName']) {
    const r = n.records[0];
    ed = { title: `Edit ${n.name}`, name: n.name, rtype: r?.type ?? 'A', value: r?.value ?? '', ttl: r?.ttl != null ? String(r.ttl) : '', nodeOnly: r?.nodeOnly ?? false, existing: n.records.slice(1), wizard: false, step: 1, domain: '', label: '' };
    formError = done = '';
  }
  function openWizard() {
    ed = { title: 'Set up my home domain', name: '', rtype: 'A', value: '', ttl: '', nodeOnly: false, existing: [], wizard: true, step: 1, domain: 'home.arpa', label: '' };
    formError = done = '';
  }

  const fullName = $derived(ed ? (ed.wizard ? `${ed.label.trim().toLowerCase()}.${ed.domain.trim().toLowerCase()}` : ed.name.trim().toLowerCase()) : '');
  const sentence = $derived.by(() => {
    if (!ed) return '';
    const v = ed.value.trim() || '…';
    const what: Record<string, string> = {
      A: `the address ${v}`,
      AAAA: `the IPv6 address ${v}`,
      CNAME: `the same answer as ${v}`,
      PTR: `the name ${v} (a reverse lookup)`,
      TXT: `the text “${v}”`,
      MX: `mail server ${v}`,
      SRV: `service ${v}`,
    };
    return `Every device that asks for ${fullName || '…'} gets ${what[ed.rtype] ?? v}, answered by WrenDNS itself${ed.rtype === 'A' || ed.rtype === 'AAAA' ? ', and a reverse lookup of the address finds the name' : ''}.`;
  });

  async function saveName(ev: SubmitEvent) {
    ev.preventDefault();
    if (!ed) return;
    if (!fullName || fullName.startsWith('.') || fullName.endsWith('.')) {
      formError = 'Give the name, like nas.home.arpa.';
      return;
    }
    const ttlText = ed.ttl.trim();
    if (ttlText && !/^\d+$/.test(ttlText)) {
      formError = 'The TTL is a number of seconds, or blank for the default.';
      return;
    }
    busy = true;
    formError = '';
    try {
      const records = [{ type: ed.rtype, value: ed.value.trim(), ttl: ttlText ? Number(ttlText) : undefined, nodeOnly: ed.nodeOnly }, ...ed.existing];
      await api.putRecords(fullName, { records });
      done = `Saved. ${fullName} now answers on every device.`;
      load();
    } catch (e) {
      formError = e instanceof ApiError && e.hint ? `${e.message} ${e.hint}` : e instanceof Error ? e.message : String(e);
    } finally {
      busy = false;
    }
  }

  async function removeName(n: string) {
    try {
      await api.deleteRecords(n);
      load();
    } catch (e) {
      error = e;
    }
  }

  // ---- "Send a domain to another server"
  // REQ: DNS-022 — `stub`: the servers are the domain's own (authoritative only); their
  // hand-offs to other servers for sub-domains are followed.
  // REQ: DNS-010 (T27.7) — groups and query types the route is limited to (comma-separated),
  // the trust anchor (on by default), and node-only.
  let fw = $state<{ domain: string; servers: string; stub: boolean; groups: string; qtypes: string; dnssec: boolean; nodeOnly: boolean } | null>(null);
  const splitList = (s: string) => s.split(/[\s,]+/).filter(Boolean);
  const fwScope = $derived.by(() => {
    if (!fw) return '';
    const g = splitList(fw.groups);
    const q = splitList(fw.qtypes);
    return `${g.length ? ` for the devices in ${g.join(', ')}` : ''}${q.length ? ` for ${q.map((t) => t.toUpperCase()).join(', ')} questions` : ''}`;
  });
  const fwSentence = $derived(
    fw
      ? fw.stub
        ? `Every name under ${fw.domain.trim() || '…'} is looked up starting at ${fw.servers.trim() || '…'}, following any sub-domains they hand to other servers, instead of the public DNS servers${fwScope}; your local names still answer first.`
        : `Every name under ${fw.domain.trim() || '…'} is asked of ${fw.servers.trim() || '…'} instead of the public DNS servers${fwScope}; your local names still answer first.`
      : '',
  );
  // REQ: API-014 (T24.16, ADR-926) — a server that runs a program (exec://, unix://) is an admin's.
  const runsProgram = (servers: string) => servers.split(/[\s,]+/).some((s) => /^(exec|unix):\/\//i.test(s));
  const forwardBlocked = $derived(Boolean(fw && session.user?.role !== 'admin' && runsProgram(fw.servers)));
  async function saveForward(ev: SubmitEvent) {
    ev.preventDefault();
    if (!fw) return;
    busy = true;
    formError = '';
    try {
      const servers = fw.servers.split(/[\s,]+/).filter(Boolean);
      await api.putForward(fw.domain.trim().toLowerCase(), {
        servers,
        stub: fw.stub,
        matchGroup: splitList(fw.groups),
        matchQtype: splitList(fw.qtypes).map((t) => t.toUpperCase()),
        dnssecNta: fw.dnssec,
        nodeOnly: fw.nodeOnly,
      });
      done = `Saved. Names under ${fw.domain.trim()}${fwScope} now go to ${servers.join(', ')}.`;
      load();
    } catch (e) {
      formError = e instanceof ApiError && e.hint ? `${e.message} ${e.hint}` : e instanceof Error ? e.message : String(e);
    } finally {
      busy = false;
    }
  }
  async function removeForward(d: string) {
    try {
      await api.deleteForward(d);
      load();
    } catch (e) {
      error = e;
    }
  }

  // ---- REQ: DNS-010 (T27.7) — zones made in the UI: an apex, the groups that see it, the
  // negative TTL, and its records (name, type, value, optional TTL). A file zone stays read-only.
  type ZoneRow = { name: string; rtype: string; value: string; ttl: string };
  type ZoneEditor = { apex: string; isNew: boolean; groups: string; negativeTtl: string; rows: ZoneRow[] };
  let zed = $state<ZoneEditor | null>(null);
  const zoneTypes = ['A', 'AAAA', 'CNAME', 'PTR', 'TXT', 'MX', 'SRV'];

  function openZone() {
    zed = { apex: '', isNew: true, groups: '', negativeTtl: '300', rows: [{ name: '', rtype: 'A', value: '', ttl: '' }] };
    formError = done = '';
  }
  function openZoneEdit(z: S['ZoneInfo']) {
    zed = {
      apex: z.name,
      isNew: false,
      groups: z.groups.join(', '),
      negativeTtl: String(z.negativeTtlSeconds),
      rows: z.values.map((v) => ({ name: v.name, rtype: v.type, value: v.value, ttl: v.ttl != null ? String(v.ttl) : '' })),
    };
    formError = done = '';
  }

  async function saveZone(ev: SubmitEvent) {
    ev.preventDefault();
    if (!zed) return;
    const apex = zed.apex.trim().toLowerCase();
    if (!apex || apex.startsWith('.') || apex.endsWith('.')) {
      formError = 'Give the zone’s domain, like home.example.com.';
      return;
    }
    if (!/^\d+$/.test(zed.negativeTtl.trim())) {
      formError = 'The negative TTL is a number of seconds.';
      return;
    }
    const rows = zed.rows.filter((r) => r.name.trim() || r.value.trim());
    if (rows.some((r) => r.ttl.trim() && !/^\d+$/.test(r.ttl.trim()))) {
      formError = 'A record’s TTL is a number of seconds, or blank for the default.';
      return;
    }
    busy = true;
    formError = '';
    try {
      await api.putZone(apex, {
        groups: splitList(zed.groups),
        negativeTtlSeconds: Number(zed.negativeTtl.trim()),
        records: rows.map((r) => ({
          name: r.name.trim().toLowerCase(),
          type: r.rtype,
          value: r.value.trim(),
          ttl: r.ttl.trim() ? Number(r.ttl.trim()) : undefined,
        })),
      });
      done = `Saved. WrenDNS answers everything under ${apex} from its records now.`;
      if (zed) {
        zed.isNew = false;
        zed.apex = apex;
      }
      load();
    } catch (e) {
      formError = e instanceof ApiError && e.hint ? `${e.message} ${e.hint}` : e instanceof Error ? e.message : String(e);
    } finally {
      busy = false;
    }
  }

  async function removeZone(name: string) {
    try {
      await api.deleteZone(name);
      load();
    } catch (e) {
      error = e;
    }
  }
</script>

<div class="page">
  <div class="page-head">
    <h1>Names on my network<HelpButton id="local-dns" /></h1>
    <span class="muted small">Local DNS</span>
  </div>
  <ErrorNote {error} />

  {#if canEdit}
    <div class="row actions">
      <button class="primary" onclick={openWizard}>Set up my home domain</button>
      <button onclick={openAdd}>Add a name</button>
      <button onclick={() => ((fw = { domain: '', servers: '', stub: false, groups: '', qtypes: '', dnssec: true, nodeOnly: false }), (formError = done = ''))}>Send a domain to another server</button>
      <button onclick={openZone} data-testid="zone-add">Add a zone</button>
    </div>
  {/if}

  <!-- REQ: DNS-023 (T24.13, ADR-901, ADR-914) — device names in DNS, and the admin's mDNS switch. -->
  <DeviceNamesCard />

  {#if groups.length === 0}
    <section class="card">
      <p class="empty">
        No local names yet. “Set up my home domain” gives your NAS, printer, or server a name like
        <code>nas.home.arpa</code> that every device can use.
      </p>
    </section>
  {/if}
  {#each groups as [domain, list] (domain)}
    <section class="card">
      <h2>{domain}</h2>
      <div class="table-wrap">
        <table>
          <thead><tr><th>Name</th><th>Answers with</th><th>TTL</th><th>Defined in</th><th></th></tr></thead>
          <tbody>
            {#each list as n (n.name)}
              <tr>
                <td class="mono">{n.name}</td>
                <td>
                  {#each n.records as r, i (i)}
                    <div><span class="badge">{r.type}</span> <span class="mono">{r.value}</span>{#if r.nodeOnly}<span class="muted small"> (this node only)</span>{/if}</div>
                  {/each}
                </td>
                <td class="small">{n.records.map((r) => r.ttl ?? 'default').join(', ')}</td>
                <td class="small">{n.source === 'api' ? 'the UI / API' : 'config file'}</td>
                <td class="num nowrap">
                  <a class="small" href={href('/explain', { name: n.name, client: '127.0.0.1' })}>Test</a>
                  {#if n.source === 'api' && canEdit}
                    <button class="link small" onclick={() => openEdit(n)}>Edit</button>
                    <button class="link small" onclick={() => removeName(n.name)} aria-label={`Remove ${n.name}`}>Remove</button>
                  {/if}
                </td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    </section>
  {/each}

  {#if zones.length || canEdit}
    <section class="card" data-testid="zones">
      <h2>Zones<HelpButton id="zones" /></h2>
      <p class="muted small">
        WrenDNS answers everything under these domains itself, from the configuration files (<code>[[zone]]</code>) or
        from the zones made here: names it doesn't have get “no such name”. A zone limited to groups is seen only by their devices.
      </p>
      {#if zones.length === 0}
        <p class="empty">No zones yet. “Add a zone” answers a whole domain from its own records.</p>
      {:else}
        <div class="table-wrap">
          <table>
            <thead><tr><th>Zone</th><th class="num">Records</th><th>Seen by</th><th>From</th><th></th></tr></thead>
            <tbody>
              {#each zones as z (z.name)}
                <tr data-testid="zone-row">
                  <td class="mono">{z.name}</td>
                  <td class="num">{z.records}</td>
                  <td class="small">{z.groups.length ? z.groups.join(', ') : 'everyone'}</td>
                  <td class="small mono">{z.source === 'api' ? 'the UI / API' : (z.file ?? 'config file')}</td>
                  <td class="num nowrap">
                    <a class="small" href={href('/explain', { name: z.name, client: '127.0.0.1' })}>Test</a>
                    {#if z.source === 'api' && canEdit}
                      <button class="link small" onclick={() => openZoneEdit(z)} aria-label={`Edit zone ${z.name}`}>Edit</button>
                      <button class="link small" onclick={() => removeZone(z.name)} aria-label={`Remove zone ${z.name}`}>Remove</button>
                    {/if}
                  </td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
      {/if}
    </section>
  {/if}

  <section class="card">
    <h2>Domains sent to other servers<HelpButton id="routes" /></h2>
    {#if forwards.length === 0}
      <p class="empty">None: every name not on this page is asked of the public DNS servers.</p>
    {:else}
      <div class="table-wrap">
        <table>
          <thead><tr><th>Domain</th><th>Servers</th><th>Defined in</th><th></th></tr></thead>
          <tbody>
            {#each forwards as f (f.domain)}
              <tr>
                <td class="mono">{f.domain}</td>
                <td class="mono small">{f.servers.join(', ')}{#if f.stub}<span class="muted"> (stub zone)</span>{/if}{#if f.matchGroup.length}<span class="muted"> for {f.matchGroup.join(', ')}</span>{/if}{#if f.matchQtype.length}<span class="muted"> for {f.matchQtype.join(', ')}</span>{/if}{#if f.nodeOnly}<span class="muted"> (this node only)</span>{/if}</td>
                <td class="small">{f.source === 'api' ? 'the UI / API' : 'config file'}</td>
                <td class="num">
                  {#if f.source === 'api' && canEdit}
                    <button class="link small" onclick={() => removeForward(f.domain)} aria-label={`Stop sending ${f.domain}`}>Remove</button>
                  {/if}
                </td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    {/if}
  </section>
</div>

{#if ed}
  <Drawer title={ed.title} onclose={() => (ed = null)}>
    <form class="stack" onsubmit={saveName}>
      {#if ed.wizard && ed.step === 1}
        <p>
          Pick the domain your devices' names end with. <b>home.arpa</b> is reserved for exactly this
          (RFC 8375), so it never clashes with the internet; use a domain you own if you have one.
        </p>
        <label>Home domain <input name="home-domain" bind:value={ed.domain} required /></label>
        <div class="row">
          <button type="button" class="primary" onclick={() => ed && (ed.step = 2)} disabled={!ed.domain.trim()}>Next</button>
        </div>
      {:else}
        {#if ed.wizard}
          <p>Now your first device. You can add more with “Add a name”.</p>
          <label>Device name <input name="label" bind:value={ed.label} placeholder="nas" required /></label>
          <p class="muted small">Its full name will be <code>{fullName}</code>.</p>
        {:else}
          <label>Name <input name="name" bind:value={ed.name} placeholder="nas.home.arpa" required readonly={ed.title.startsWith('Edit')} /></label>
        {/if}
        <label>
          Type
          <select name="type" bind:value={ed.rtype}>
            {#each types as t (t)}<option value={t}>{t === 'A' ? 'A (IPv4 address)' : t === 'AAAA' ? 'AAAA (IPv6 address)' : t === 'CNAME' ? 'CNAME (alias of another name)' : t}</option>{/each}
          </select>
        </label>
        <label>
          {ed.rtype === 'A' || ed.rtype === 'AAAA' ? 'Address' : 'Value'}
          <input name="value" bind:value={ed.value} placeholder={ed.rtype === 'A' ? '192.168.1.10' : ed.rtype === 'CNAME' ? 'nas.home.arpa' : ''} required />
        </label>
        <label>
          TTL in seconds (optional)
          <input name="ttl" bind:value={ed.ttl} inputmode="numeric" placeholder="default" />
        </label>
        <label>
          <input type="checkbox" name="node-only" bind:checked={ed.nodeOnly} /> Only on this node (the cluster doesn't share it)<HelpButton id="records" />
        </label>
        {#if ed.existing.length}<p class="muted small">Also keeps: {ed.existing.map((r) => `${r.type} ${r.value}`).join(', ')}.</p>{/if}
        {#if fullName && ed.value.trim()}
          <ChangePreview highlight="local" device="Any device" name={fullName} {sentence} />
        {/if}
        {#if formError}<p class="notice bad" role="alert">{formError}</p>{/if}
        {#if done}<p class="notice ok" role="status">{done} <a href={href('/explain', { name: fullName, client: '127.0.0.1' })}>Test it</a></p>{/if}
        <div class="row">
          {#if ed.wizard}<button type="button" onclick={() => ed && (ed.step = 1)}>Back</button>{/if}
          <button type="submit" class="primary" disabled={busy}>{busy ? 'Saving…' : 'Save'}</button>
        </div>
      {/if}
    </form>
  </Drawer>
{/if}

{#if fw}
  <Drawer title="Send a domain to another server" onclose={() => (fw = null)}>
    <form class="stack" onsubmit={saveForward}>
      <p>For names that only another DNS server knows: a work network over VPN, your router's own names, another lab.</p>
      <label>Domain <input name="domain" bind:value={fw.domain} placeholder="corp.example" required /></label>
      <label>Server address <input name="servers" bind:value={fw.servers} placeholder="10.0.0.53" required /></label>
      <p class="muted small">Several servers: separate them with spaces (tried in order). Encrypted: <code>tls://10.0.0.53</code>.</p>
      <label
        ><input type="checkbox" name="stub" bind:checked={fw.stub} /> These servers only know this domain, and hand some sub-domains to other servers</label
      >
      <p class="muted small">
        A <em>stub zone</em>: the servers are asked directly (by IP address) and their hand-offs are followed, as BIND's stub zones do.
        Use it when the servers refuse other questions.
      </p>
      <!-- REQ: DNS-010 (T27.7) — the route's limits: client groups, query types, trust anchor, node-only. -->
      <label>Only for the devices in these groups (optional) <input name="match-group" bind:value={fw.groups} placeholder="Kids, Guests" /></label>
      <label>Only for these query types (optional) <input name="match-qtype" bind:value={fw.qtypes} placeholder="PTR" /></label>
      <label
        ><input type="checkbox" name="dnssec-nta" bind:checked={fw.dnssec} /> Don't check this domain's DNSSEC signatures (local zones are usually unsigned)<HelpButton id="routes" /></label
      >
      <label><input type="checkbox" name="node-only" bind:checked={fw.nodeOnly} /> Only on this node (the cluster doesn't share it)</label>
      {#if fw.domain.trim() && fw.servers.trim()}
        <ChangePreview highlight="route" device="Any device" name={`anything.${fw.domain.trim()}`} sentence={fwSentence} />
      {/if}
      {#if forwardBlocked}<p class="notice warn small" role="status" data-testid="admin-only-forward">Only an admin can send names to a program (an exec:// or unix:// server). <HelpButton id="credentials-in-forms" /></p>{/if}
      {#if formError}<p class="notice bad" role="alert">{formError}</p>{/if}
      {#if done}<p class="notice ok" role="status">{done}</p>{/if}
      <div class="row"><button type="submit" class="primary" disabled={busy || forwardBlocked}>{busy ? 'Saving…' : 'Save'}</button></div>
    </form>
  </Drawer>
{/if}

{#if zed}
  <Drawer title={zed.isNew ? 'Add a zone' : `Edit ${zed.apex}`} onclose={() => (zed = null)}>
    <form class="stack" onsubmit={saveZone} data-testid="zone-form">
      <p>
        WrenDNS answers every name under the zone from the records below: a name it doesn't list gets “no such name”, so
        the zone's devices never reach the internet for it.
      </p>
      <label>Zone (its domain) <input name="zone" bind:value={zed.apex} placeholder="home.example.com" required readonly={!zed.isNew} /></label>
      <label>Seen by (groups, comma-separated; empty for everyone) <input name="zone-groups" bind:value={zed.groups} placeholder="Kids" /></label>
      <label>Negative TTL in seconds (for “no such name”) <input name="negative-ttl" bind:value={zed.negativeTtl} inputmode="numeric" /></label>
      <p class="small"><b>Records</b> <HelpButton id="zones" /></p>
      {#each zed.rows as row, i (i)}
        <div class="row zone-row">
          <input aria-label={`Record ${i + 1} name`} placeholder="printer.home.example.com" bind:value={row.name} />
          <select aria-label={`Record ${i + 1} type`} bind:value={row.rtype}>
            {#each zoneTypes as t (t)}<option value={t}>{t}</option>{/each}
          </select>
          <input aria-label={`Record ${i + 1} value`} placeholder="192.168.1.20" bind:value={row.value} />
          <input aria-label={`Record ${i + 1} TTL`} placeholder="default" inputmode="numeric" size="6" bind:value={row.ttl} />
          <button type="button" class="link small" onclick={() => zed && zed.rows.splice(i, 1)} aria-label={`Remove record ${i + 1}`}>Remove</button>
        </div>
      {/each}
      <div class="row">
        <button type="button" onclick={() => zed && zed.rows.push({ name: '', rtype: 'A', value: '', ttl: '' })}>Add a record</button>
      </div>
      {#if formError}<p class="notice bad" role="alert">{formError}</p>{/if}
      {#if done}<p class="notice ok" role="status">{done}</p>{/if}
      <div class="row"><button type="submit" class="primary" disabled={busy}>{busy ? 'Saving…' : 'Save'}</button></div>
    </form>
  </Drawer>
{/if}

<style>
  .zone-row {
    flex-wrap: wrap;
    gap: 6px;
  }
  .actions {
    margin-bottom: 12px;
    flex-wrap: wrap;
    gap: 8px;
  }
  .stack {
    display: grid;
    gap: 12px;
  }
</style>
