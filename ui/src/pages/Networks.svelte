<script lang="ts">
  // REQ: API-013, API-010, API-011, FLT-005 (T24.15) — the networks your routers report (subnet,
  // VLAN, DHCP pool, domain, router), with the group that covers each one, how many devices are
  // in it and how full it is. A row opens its devices with their DNS names. Operators can make a
  // group from a network that no group covers (it opens the Groups editor with `networks` filled).
  import { api, type S } from '../lib/api';
  import { navigate } from '../lib/router.svelte';
  import { num, pct } from '../lib/format';
  import { can } from '../lib/session.svelte';
  import Drawer from '../lib/components/Drawer.svelte';
  import ErrorNote from '../lib/components/ErrorNote.svelte';
  import HelpButton from '../lib/components/HelpButton.svelte';

  type Net = S['NetworkInfo'];
  let networks = $state<Net[]>([]);
  let missingNodes = $state<string[]>([]);
  let error = $state<unknown>(null);
  let loaded = $state(false);
  let leases = $state<S['DhcpLease'][]>([]);
  let leasesLoaded = $state(false);
  let leaseError = $state<unknown>(null);
  let open = $state<Net | null>(null);
  const operator = $derived(can('operator'));

  function load() {
    api
      .networks()
      .then((r) => {
        networks = r.items;
        missingNodes = r.missingNodes ?? [];
        error = null;
      })
      .catch((e) => (error = e))
      .finally(() => (loaded = true));
  }
  $effect(load);

  // IPv4 membership without a library: is `ip` inside `cidr`?
  function ipToInt(ip: string): number | null {
    const parts = ip.split('.');
    if (parts.length !== 4) return null;
    let n = 0;
    for (const p of parts) {
      if (!/^\d{1,3}$/.test(p) || Number(p) > 255) return null;
      n = n * 256 + Number(p);
    }
    return n;
  }
  function inSubnet(ip: string, cidr: string): boolean {
    const [net, bitsText] = cidr.split('/');
    const bits = Number(bitsText ?? 32);
    const a = ipToInt(ip);
    const b = ipToInt(net ?? '');
    if (a === null || b === null || !Number.isInteger(bits) || bits < 0 || bits > 32) return false;
    const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
    return ((a & mask) >>> 0) === ((b & mask) >>> 0);
  }

  // The devices on the open network, from the routers' DHCP leases and mDNS (fetched when opened).
  const devices = $derived(open ? leases.filter((l) => inSubnet(l.ip, open!.subnet)) : []);
  function show(n: Net) {
    open = n;
    leaseError = null;
    leasesLoaded = false;
    api
      .dhcpLeases()
      .then((r) => (leases = r.items))
      .catch((e) => (leaseError = e))
      .finally(() => (leasesLoaded = true));
  }

  // REQ: FLT-005 (T24.15) — "Make a group from this network": the Groups editor opens with the
  // network filled in. Shown only where no group covers the network yet.
  function makeGroup(n: Net) {
    const name = n.name.toLowerCase().replace(/[^a-z0-9-]+/g, '-').replace(/^-+|-+$/g, '') || 'network';
    navigate('/groups', { draft: 'network', name, networks: n.subnet });
  }

  const dhcp = (n: Net) => (n.dhcpStart && n.dhcpEnd ? `${n.dhcpStart} – ${n.dhcpEnd}` : 'none');
  const groupOnly = (n: Net) => n.source === 'group';
</script>

<div class="page">
  <h1>Networks<HelpButton id="networks" /></h1>
  <ErrorNote {error} />
  <p class="muted small">
    The LANs and VLANs your routers report, and any client group's networks no router reported. Each shows the group that covers
    it and how many devices are in it, so you can see which networks are filling up.
    {#if missingNodes.length}<span data-testid="networks-missing">Not answering: {missingNodes.join(', ')}.</span>{/if}
  </p>

  <section class="card">
    {#if loaded && networks.length === 0 && !error}
      <p class="empty" data-testid="networks-empty">
        No networks yet. They come from the routers you connect (a <code>[[router]]</code> in the config file: UniFi, OPNsense or
        Home Assistant) and from the networks of your client groups.
      </p>
    {:else if networks.length}
      <div class="table-wrap">
        <table data-testid="networks-table">
          <thead>
            <tr>
              <th>Name</th>
              <th>Purpose</th>
              <th>Subnet</th>
              <th class="num">VLAN</th>
              <th>Gateway</th>
              <th>DHCP pool</th>
              <th>Domain</th>
              <th>Router</th>
              <th>Group</th>
              <th class="num">Size</th>
              <th class="num">Devices</th>
              <th>Share used</th>
              <th class="num">Outside pool</th>
              {#if operator}<th></th>{/if}
            </tr>
          </thead>
          <tbody>
            {#each networks as n (n.subnet + n.source + (n.router ?? ''))}
              <tr data-testid="network-row">
                <td><button type="button" class="link" onclick={() => show(n)} data-testid="network-open">{n.name}</button></td>
                <td class="small">{n.purpose ?? '–'}</td>
                <td class="mono">{n.subnet}</td>
                <td class="num">{n.vlan ?? '–'}</td>
                <td class="mono small">{n.gateway ?? '–'}</td>
                <td class="mono small">{dhcp(n)}</td>
                <td class="mono small">{n.domain ?? '–'}</td>
                <td class="small">{n.router ?? '–'}</td>
                <td class="small">
                  {#if n.group}{n.group}{:else}<span class="muted">none</span>{/if}
                  {#if groupOnly(n)}<span class="badge info" data-testid="group-only">group only</span>{/if}
                </td>
                <td class="num">{num(n.addresses)}</td>
                <td class="num">{num(n.devices)}</td>
                <td>
                  <span class="meter" role="img" aria-label="{pct(n.usedPercent, 0)} used"><span style:width="{Math.min(100, Math.max(0, n.usedPercent))}%"></span></span>
                  <span class="small">{pct(n.usedPercent, 0)}</span>
                </td>
                <td class="num">{num(n.outsidePool)}</td>
                {#if operator}
                  <td class="actions">
                    {#if !n.group}
                      <button type="button" class="link small" onclick={() => makeGroup(n)} data-testid="make-group">Make a group from this network</button>
                      <HelpButton id="network-group" />
                    {/if}
                  </td>
                {/if}
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    {:else if !loaded}
      <p class="muted small">Loading…</p>
    {/if}
  </section>

  {#if open}
    {@const net = open}
    <Drawer title={`${net.name} · ${net.subnet}`} onclose={() => (open = null)}>
      <p class="muted small">
        The devices on this network, from the routers' DHCP and mDNS, with the DNS name each one answers as.
        {#if net.outsidePool}{num(net.outsidePool)} of {num(net.devices)} are outside the DHCP pool (fixed addresses).{/if}
      </p>
      <ErrorNote error={leaseError} />
      {#if devices.length}
        <div class="table-wrap">
          <table data-testid="network-devices">
            <thead><tr><th>Address</th><th>DNS name</th><th>Name it gave</th><th>From</th></tr></thead>
            <tbody>
              {#each devices as d (d.ip + d.mac)}
                <tr>
                  <td class="mono">{d.ip}</td>
                  <td class="mono small" data-testid="network-dns-name">{d.dnsName ?? 'none'}</td>
                  <td>{d.hostname ?? ''}</td>
                  <td class="small">{d.source === 'router' && d.router ? `router: ${d.router}` : d.source}</td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
      {:else if leasesLoaded && !leaseError}
        <p class="empty" data-testid="network-no-devices">No devices known on this network yet.</p>
      {/if}
      {#if operator && !net.group}
        <button type="button" onclick={() => makeGroup(net)}>Make a group from this network</button>
      {/if}
    </Drawer>
  {/if}
</div>

<style>
  .meter {
    display: inline-block;
    width: 64px;
    height: 8px;
    margin-right: 6px;
    border-radius: 4px;
    background: var(--border);
    overflow: hidden;
    vertical-align: middle;
  }
  .meter > span {
    display: block;
    height: 100%;
    background: var(--accent, #4f8cff);
  }
  .actions {
    white-space: nowrap;
  }
</style>
