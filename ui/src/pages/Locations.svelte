<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<script lang="ts">
  // REQ: DSC-914, DSC-909, DSC-910, DSC-916 (T36.10c; ADR-1081, ADR-1096, ADR-1104) — the Locations page: each
  // location with its networks (as resolved now), serving nodes, the names it composes, every collision with the
  // ADR-901 winner, and the flat-names switch with its 7-day use count. Operators create, change and delete
  // locations made through the API (a dry run first); a location the files define is read-only here, and while the
  // start-up hold keeps locations out of the answers the page says so and why.
  import { api, type S } from '../lib/api';
  import { can } from '../lib/session.svelte';
  import { poll } from '../lib/poll';
  import { num } from '../lib/format';
  import { labelOf, loadLocations } from '../lib/locations.svelte';
  import Drawer from '../lib/components/Drawer.svelte';
  import ErrorNote from '../lib/components/ErrorNote.svelte';
  import HelpButton from '../lib/components/HelpButton.svelte';
  import Picker from '../lib/components/Picker.svelte';

  type Loc = S['LocationInfo'];
  type Collision = S['LocationCollision'];
  let list = $state<S['LocationList'] | null>(null);
  let error = $state<unknown>(null);
  let open = $state<string | null>(null);
  const shown = $derived(list?.items.find((l) => l.slug === open) ?? null);
  const operator = $derived(can('operator'));

  function load() {
    return api
      .locations()
      .then((r) => {
        list = r;
        error = null;
      })
      .catch((e) => (error = e));
  }
  $effect(() => poll(load, 15_000));

  // -- the form: a new location, or a change to one made through the API ------------------------------
  type Form = { isNew: boolean; slug: string; label: string; domain: string; visibility: string; networks: string; nodes: string[]; flat: boolean; wasFlat: boolean };
  let form = $state<Form | null>(null);
  let reason = $state('');
  let preview = $state<S['ConfigChange'] | null>(null);
  let previewedWith = $state<string | null>(null);
  let formError = $state<unknown>(null);
  let busy = $state(false);
  let nodeNames = $state<string[]>([]);
  let defaultDomain = $state('');
  let returnTo: string | null = null;
  const closeForm = () => {
    form = null;
    open = returnTo;
  };
  const snapshot = () => JSON.stringify([form, reason]);
  const previewCurrent = $derived(preview !== null && previewedWith === snapshot());
  // Turning the old names off is an audited write that says why (DSC-916).
  const needsReason = $derived(!!form && !form.flat && (form.isNew || form.wasFlat));

  async function edit(l: Loc | null) {
    reason = '';
    // One dialog at a time: the details drawer closes while the form is open and comes back with the form's end.
    returnTo = l?.slug ?? null;
    open = deleting = null;
    preview = previewedWith = formError = null;
    const [c, d] = await Promise.all([api.cluster().catch(() => null), api.configEntries('local').catch(() => null)]);
    nodeNames = (c?.nodes ?? []).map((n) => n.nodeId);
    const dd = (d?.items[0]?.definition as Record<string, unknown> | undefined)?.device_domain;
    defaultDomain = typeof dd === 'string' ? dd : '';
    form = l
      ? { isNew: false, slug: l.slug, label: l.label ?? '', domain: l.domain, visibility: l.visibility, networks: l.networks.map((n) => n.entry).join('\n'), nodes: [...l.nodes], flat: l.flatNames, wasFlat: l.flatNames }
      : { isNew: true, slug: '', label: '', domain: '', visibility: 'shared', networks: '', nodes: [], flat: true, wasFlat: true };
  }

  function body(f: Form): S['LocationInput'] {
    return {
      label: f.label.trim() || null,
      domain: f.domain.trim().toLowerCase() || null,
      visibility: f.visibility,
      networks: f.networks.split(/[\s,]+/).filter(Boolean),
      nodes: f.nodes,
      flatNames: f.flat,
    };
  }

  async function submit(dryRun: boolean) {
    if (!form) return;
    busy = true;
    formError = null;
    const asChecked = snapshot();
    try {
      const r = await api.putLocation(form.slug.trim().toLowerCase(), body(form), dryRun, reason.trim() || undefined);
      if (dryRun) {
        preview = r;
        previewedWith = asChecked;
      } else {
        preview = null;
        closeForm();
        await Promise.all([load(), loadLocations()]);
      }
    } catch (e) {
      if (dryRun) preview = previewedWith = null;
      formError = e;
    } finally {
      busy = false;
    }
  }

  let deleting = $state<string | null>(null);
  // A refused delete is shown beside the question, in the drawer, and stays until the next try.
  let deleteError = $state<unknown>(null);
  async function remove(slug: string) {
    busy = true;
    deleteError = null;
    try {
      await api.deleteLocation(slug);
      deleting = open = null;
      await Promise.all([load(), loadLocations()]);
    } catch (e) {
      deleteError = e;
    } finally {
      busy = false;
    }
  }

  const keptBy = (c: Collision) => (c.keptAddress ? c.keptAddress : 'the location itself');
  const netText = (l: Loc) => l.networks.map((n) => n.entry).join(', ');
</script>

{#snippet collisions(items: Collision[], testid: string)}
  <div class="table-wrap">
    <table data-testid={testid}>
      <thead><tr><th>Name</th><th>Kept by</th><th>Lost by</th><th>Kind</th></tr></thead>
      <tbody>
        {#each items as c, i (i)}
          <tr data-testid="collision-row">
            <td class="mono small">{c.name}</td>
            <td class="mono small">{keptBy(c)}</td>
            <td class="mono small">{c.lostAddress}{#if c.lostLocation} <span class="muted">({c.lostLocation})</span>{/if}</td>
            <td class="small">{c.flat ? 'flat name' : 'location name'}</td>
          </tr>
        {/each}
      </tbody>
    </table>
  </div>
{/snippet}

<div class="page">
  <h1>Locations<HelpButton id="locations" /></h1>
  <ErrorNote {error} />
  <p class="muted small">
    A location is a part of the network (a site, a lab, a VLAN) with a device-name subtree of its own: a device on its networks
    answers as <code>&lt;device&gt;.&lt;location&gt;.&lt;domain&gt;</code>, and the old flat name keeps answering while the
    location's flat names are on.
  </p>

  {#if list?.held}
    <p class="notice warn small" role="status" data-testid="locations-held">
      Held: the locations are configured but this node does not serve or publish them yet. {list.heldReason ?? ''} The devices
      and collisions below are not resolved until the hold ends.
    </p>
  {:else if list?.heldReason}
    <p class="notice warn small" role="status" data-testid="locations-held">{list.heldReason}</p>
  {/if}
  {#each list?.conflicts ?? [] as c, i (i)}<p class="notice bad small" role="alert" data-testid="location-conflict">{c}</p>{/each}

  <section class="card">
    <div class="card-head">
      <h2>Locations</h2>
      {#if operator}<button type="button" class="primary" onclick={() => edit(null)} data-testid="location-new">New location</button>{/if}
    </div>
    {#if list && list.items.length === 0}
      <p class="empty" data-testid="locations-empty">No locations yet. Without one, every device answers as <code>&lt;device&gt;.&lt;device_domain&gt;</code>, as before.</p>
    {:else if list}
      <div class="table-wrap">
        <table data-testid="locations-table">
          <thead>
            <tr><th>Location</th><th>Domain</th><th class="wide">Networks</th><th class="wide">Served by</th><th class="num">Devices</th><th>Flat names<HelpButton id="location-flat-names" /></th><th class="num">Collisions</th></tr>
          </thead>
          <tbody>
            {#each list.items as l (l.slug)}
              <tr data-testid="location-row">
                <td>
                  <button type="button" class="link" onclick={() => (open = l.slug)} data-testid="location-open">{labelOf(l)}</button>
                  <span class="mono small muted">{l.slug}</span>
                  {#if l.visibility === 'private'}<span class="badge info">private</span>{/if}
                  {#if l.source === 'file'}<span class="badge info" data-testid="location-file">config file</span>{/if}
                  {#if l.held}<span class="badge warn" data-testid="location-held">held</span>{/if}
                </td>
                <td class="mono small">{l.domain}</td>
                <td class="mono small wide">{netText(l)}</td>
                <td class="small wide">{l.nodes.length ? l.nodes.join(', ') : 'every node'}</td>
                <td class="num">{num(l.devices.length)}</td>
                <td class="small" data-testid="flat-use">
                  {#if l.flatNames}on, {num(l.flatNameUses7d)} queries in 7 days{:else}off{/if}
                </td>
                <td class="num" data-testid="collision-count">{num(l.collisions.length)}</td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    {:else if !error}
      <p class="muted small">Loading…</p>
    {/if}
  </section>

  {#if list?.collisions.length}
    <section class="card" data-testid="locations-unplaced">
      <h2>Collisions outside the locations</h2>
      <p class="muted small">Devices on no location's network that wanted the same name. The better-ranked one keeps it.</p>
      {@render collisions(list.collisions, 'unplaced-collisions')}
    </section>
  {/if}

  {#if shown}
    {@const l = shown}
    <Drawer title={`${labelOf(l)} · ${l.slug}`} onclose={() => (open = deleting = deleteError = null)}>
      {#if l.held}<p class="notice warn small">{l.heldReason ?? 'Held: not served yet.'}</p>{/if}
      <h3>Networks</h3>
      <ul class="small" data-testid="location-networks">
        {#each l.networks as n, i (i)}
          <li><span class="mono">{n.entry}</span>{#if n.entry !== n.resolved.join(', ')} <span class="muted">→ {n.resolved.join(', ') || 'nothing'}</span>{/if}{#if n.note} <span class="badge warn">{n.note}</span>{/if}</li>
        {/each}
      </ul>
      <p class="small">
        Served by {l.nodes.length ? l.nodes.join(', ') : 'every node'}. {l.visibility === 'private' ? 'Private: answered only to clients on its networks.' : 'Shared.'}
        Flat names {l.flatNames ? `on: ${num(l.flatNameUses7d)} queries used them in the last 7 days on this node.` : 'off.'}
      </p>
      <h3>Names it composes</h3>
      {#if l.devices.length}
        <div class="table-wrap">
          <table data-testid="location-devices">
            <thead><tr><th>Name</th><th>Flat name</th><th>Address</th></tr></thead>
            <tbody>
              {#each l.devices as d, i (i)}
                <tr>
                  <td class="mono small">{d.name}{#if d.pinned} <span class="badge info" title="Pinned to this location on the device">pinned</span>{/if}</td>
                  <td class="mono small">{d.flatName ?? 'none'}</td>
                  <td class="mono small">{d.address}</td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
      {:else}
        <p class="empty small">No device answers under it yet.</p>
      {/if}
      <h3>Collisions</h3>
      {#if l.collisions.length}
        {@render collisions(l.collisions, 'location-collisions')}
      {:else}
        <p class="empty small">No two devices want the same name here.</p>
      {/if}
      {#if operator}
        {#if l.source === 'file'}
          <p class="muted small">Defined in the configuration file: change it there.</p>
        {:else if deleting === l.slug}
          <p class="notice warn small" data-testid="location-delete-ask">Delete {labelOf(l)}? Its devices go back to <code>&lt;device&gt;.&lt;device_domain&gt;</code>. A device pinned to it must be unpinned first.</p>
          <ErrorNote error={deleteError} />
          <div class="row">
            <button type="button" class="danger" disabled={busy} onclick={() => remove(l.slug)} data-testid="location-delete-yes">Delete</button>
            <button type="button" onclick={() => (deleting = null)}>Keep</button>
          </div>
        {:else}
          <div class="row">
            <button type="button" class="primary" onclick={() => edit(l)} data-testid="location-edit">Edit</button>
            <button type="button" onclick={() => ((deleting = l.slug), (deleteError = null))} data-testid="location-delete">Delete</button>
          </div>
        {/if}
      {/if}
    </Drawer>
  {/if}

  {#if form}
    {@const f = form}
    <Drawer title={f.isNew ? 'New location' : `Edit ${f.slug}`} onclose={closeForm}>
      <form class="stack" onsubmit={(e) => { e.preventDefault(); void submit(false); }} data-testid="location-form">
        <label>
          Slug (the DNS label)
          <input class="mono" bind:value={f.slug} readonly={!f.isNew} required maxlength="63" placeholder="home" aria-label="Slug" />
        </label>
        <label>
          Name
          <input bind:value={f.label} maxlength="64" placeholder="Home" aria-label="Name" />
        </label>
        <label>
          Networks (one per line: a CIDR, or vlan:&lt;id&gt;)
          <textarea class="mono" rows="3" bind:value={f.networks} placeholder={'192.0.2.0/24\nvlan:30'} aria-label="Networks"></textarea>
        </label>
        <label>
          Parent domain
          <input class="mono" bind:value={f.domain} placeholder={defaultDomain || 'example.net'} aria-label="Parent domain" />
          <span class="muted small">Empty: follows the node's device domain{defaultDomain ? ` (${defaultDomain})` : ''}.</span>
        </label>
        <label>
          Who may resolve its names
          <select bind:value={f.visibility} aria-label="Visibility">
            <option value="shared">Everyone the access list allows</option>
            <option value="private">Only clients on its networks</option>
          </select>
        </label>
        <div>
          Serving nodes <span class="muted small">(none: every node)</span>
          <Picker label="Serving nodes" bind:selected={f.nodes} items={nodeNames.map((n) => ({ value: n, label: n }))} custom={(t) => (t.trim() ? { value: t.trim(), label: t.trim() } : null)} />
        </div>
        <label class="check">
          <input type="checkbox" bind:checked={f.flat} data-testid="location-flat" /> Keep answering the old flat names<HelpButton id="location-flat-names" />
        </label>
        {#if needsReason}
          <label>
            Why turn the flat names off
            <input bind:value={reason} required maxlength="200" aria-label="Reason" data-testid="location-reason" placeholder="Nothing uses them any more" />
          </label>
        {/if}
        <ErrorNote error={formError} />
        {#if preview}
          <div class="notice" data-testid="location-preview">
            <p>{preview.impact}</p>
            {#each preview.warnings as w, i (i)}<p class="small">{w}</p>{/each}
          </div>
        {/if}
        <div class="row">
          <button type="button" disabled={busy || !f.slug.trim() || (needsReason && !reason.trim())} onclick={() => submit(true)} data-testid="location-check">Check</button>
          <button type="submit" class="primary" disabled={busy || !previewCurrent} data-testid="location-save">Save</button>
          <button type="button" onclick={closeForm}>Cancel</button>
        </div>
      </form>
    </Drawer>
  {/if}
</div>

<style>
  .stack {
    display: grid;
    gap: 12px;
  }
  .check {
    display: flex;
    gap: 8px;
    align-items: center;
    font-weight: normal;
  }
  @media (max-width: 720px) {
    .wide {
      display: none;
    }
  }
</style>
