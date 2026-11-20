<script lang="ts">
  import Icon from '../lib/components/Icon.svelte';
  // REQ: API-005, FLT-005 (ADR-050) — groups as categories of devices: each group's networks,
  // what its devices did in the last 24 hours, its heaviest names this hour, and its settings.
  import { api, type S } from '../lib/api';
  import { flockCss } from '../lib/flock';
  import { href, navigate, route } from '../lib/router.svelte';
  import { dateTime, num, pct } from '../lib/format';
  import ErrorNote from '../lib/components/ErrorNote.svelte';
  import HelpButton from '../lib/components/HelpButton.svelte';
  import { currentMode } from '../lib/mode.svelte';
  import ConfigEditor, { type Field } from '../lib/components/ConfigEditor.svelte';
  import ClientChip from '../lib/components/ClientChip.svelte';
  import { loadWorkloads, workloads } from '../lib/workloads.svelte';
  // REQ: FLT-902 (T24.29) - the profile list and editor.
  import ProfileEditor from '../lib/components/ProfileEditor.svelte';
  import { can } from '../lib/session.svelte';
  import { ENGINES } from '../lib/categories';

  // undefined: closed; null: a new profile; a name: that profile.
  let editing = $state<string | null | undefined>(undefined);
  // The columns' chips: the first two, then "+N" (the rest in its title).
  type Chip = { label: string; warn?: boolean; title?: string };
  const CHIPS = 2;
  const privateOnly = (s: S['ProfileSource']) => (s.keys ?? []).length > 0 && (s.keys ?? []).every((k) => k.kind === 'mac' && k.randomized);
  const sourceChips = (g: S['GroupInfo']): Chip[] =>
    (g.sources ?? []).map((s) => ({ label: s.label, warn: s.kind === 'device' && privateOnly(s), title: s.kind === 'network' ? `Network ${s.id}` : undefined }));
  const engineChips = (g: S['GroupInfo']): Chip[] => {
    const ids = (g.safeSearchEngines ?? []).length ? (g.safeSearchEngines ?? []) : g.safeSearch ? ENGINES.map((e) => e.id) : [];
    return ids.map((id) => ({ label: ENGINES.find((e) => e.id === id)?.name ?? id }));
  };
  const scheduleChips = (g: S['GroupInfo']): Chip[] => g.schedules.map((s) => ({ label: g.schedulesOn.includes(s) ? `${s} (on now)` : s }));
  $effect(() => {
    // "Use in a profile" on the Lists page's Categories tab opens a new profile.
    if (route.path === '/groups' && route.params.get('new') === '1') {
      editing = null;
      navigate('/groups', undefined, true);
    }
  });

  // REQ: FLT-017 — the workloads a group holds (the default group: those without one).
  const workloadsIn = (group: string) =>
    workloads.items.filter((w) => (w.group ?? 'default') === group);
  $effect(() => {
    void loadWorkloads();
  });

  let groups = $state<S['GroupInfo'][]>([]);
  let tops = $state<Record<string, { domains: S['TopItem'][]; blocked: S['TopItem'][] }>>({});
  let error = $state<unknown>(null);
  let listNames = $state<string[]>([]);
  let services = $state<S['ServiceInfo'][]>([]);
  // REQ: FLT-010 (T9.7) — schedules, edited below the groups.
  let scheduleNames = $state<string[]>([]);
  let upstreamGroupNames = $state<string[]>([]);
  type Window = { days: string[]; start: string; end: string };
  const windowText = (v: unknown) =>
    ((v as Window[] | undefined) ?? []).map((w) => `${w.days.join(',')} ${w.start}-${w.end}`).join('\n');
  function windowsFrom(s: string): Window[] {
    const out: Window[] = [];
    for (const line of s.split('\n').map((x) => x.trim()).filter(Boolean)) {
      const m = /^([a-z,]+)\s+(\d{1,2}:\d{2})\s*-\s*(\d{1,2}:\d{2})$/i.exec(line);
      if (!m) throw new Error(`"${line}": write the days and times like "weekdays 21:00-07:00"`);
      out.push({ days: m[1].toLowerCase().split(',').filter(Boolean), start: m[2], end: m[3] });
    }
    if (!out.length) throw new Error('Add at least one window, like "weekdays 21:00-07:00".');
    return out;
  }
  const scheduleFields = $derived<Field[]>([
    { key: 'action', label: 'During the windows', type: 'select', options: ['block_all', 'enable_lists', 'block_services'], initial: 'block_all',
      help: 'block_all: a bedtime (everything blocked except quick allow rules and local names). enable_lists: extra lists apply. block_services: extra services are blocked.' },
    { key: 'window', label: 'Windows (one per line)', type: 'lines', placeholder: 'weekdays 21:00-07:00\nsat,sun 23:00-08:00',
      help: 'Days: mon … sun, weekdays, weekends, daily. An end before the start runs past midnight.',
      toText: windowText, fromText: windowsFrom },
    { key: 'lists', label: 'Lists (enable_lists)', type: 'multi', options: listNames },
    { key: 'services', label: 'Services (block_services)', type: 'multi', options: services.map((s) => s.id) },
    { key: 'tz', label: 'Time zone', type: 'text', placeholder: 'America/New_York', advanced: true,
      help: 'IANA time zone. Default: the node\u2019s.' },
  ]);
  const serviceName = (id: string) => services.find((s) => s.id === id)?.name ?? id;

  // REQ: FLT-014 (T27.4) — the same rules the server checks (validate.rs `rewrites`, the block and
  // rebinding fields): a name is letters, digits, `-` and `_` labels of 1 to 63 characters, at most
  // 253 in all; an address is IPv4 or IPv6. The server still checks on Check, and its message wins.
  const isName = (s: string) => {
    const d = s.replace(/\.+$/, '');
    return d.length > 0 && d.length <= 253 && d.split('.').every((l) => l.length > 0 && l.length <= 63 && /^[A-Za-z0-9_-]+$/.test(l));
  };
  const isIpv4 = (s: string) => /^(\d{1,3}\.){3}\d{1,3}$/.test(s) && s.split('.').every((o) => Number(o) <= 255);
  // An IPv6 address: at most one `::`, 8 groups of 1 to 4 hex digits (7 with `::`), and an IPv4 tail allowed.
  const isIpv6 = (s: string) => {
    if (!s.includes(':') || !/^[0-9a-fA-F:.]+$/.test(s)) return false;
    let t = s;
    if (t.includes('.')) {
      const cut = t.lastIndexOf(':');
      if (!isIpv4(t.slice(cut + 1))) return false;
      t = `${t.slice(0, cut + 1)}0:0`;
    }
    const halves = t.split('::');
    if (halves.length > 2) return false;
    const groups = (h: string) => (h === '' ? [] : h.split(':'));
    const all = halves.flatMap(groups);
    if (!all.every((g) => /^[0-9a-fA-F]{1,4}$/.test(g))) return false;
    return halves.length === 2 ? all.length <= 7 : all.length === 8;
  };
  const isIp = (s: string) => isIpv4(s) || isIpv6(s);
  const linesOf = (v: unknown) => ((v as string[] | undefined) ?? []).join('\n');
  // Each line of a `lines` field, checked; a bad line stops Check with its message.
  function addressesFrom(s: string): string[] {
    return s.split('\n').map((x) => x.trim()).filter(Boolean).map((x) => {
      if (!isIp(x)) throw new Error(`"${x}": write an IP address, like 192.168.1.2 or fd00::2`);
      return x;
    });
  }
  function namesFrom(s: string): string[] {
    return s.split('\n').map((x) => x.trim()).filter(Boolean).map((x) => {
      if (!isName(x)) throw new Error(`"${x}": write a domain, like plex.direct`);
      return x;
    });
  }
  type Rewrite = { domain: string; answer: string };
  const rewriteText = (v: unknown) => ((v as Rewrite[] | undefined) ?? []).map((r) => `${r.domain} ${r.answer}`).join('\n');
  // REQ: FLT-014 (T27.4) — one rewrite per line: `name answer` (an address, or a name for a CNAME).
  function rewritesFrom(s: string): Rewrite[] {
    const out: Rewrite[] = [];
    const seen = new Set<string>();
    for (const raw of s.split('\n').map((x) => x.trim()).filter(Boolean)) {
      const parts = raw.split(/\s+/);
      if (parts.length !== 2) throw new Error(`"${raw}": write the name and the answer, like nas.example.com 192.168.1.10`);
      const [domain, answer] = parts;
      if (!isName(domain.replace(/^\*\./, ''))) throw new Error(`"${domain}": a domain, or *.domain for every name under it`);
      const key = domain.toLowerCase();
      if (seen.has(key)) throw new Error(`"${domain}" is rewritten twice in this group`);
      seen.add(key);
      if (!isIp(answer) && !isName(answer)) throw new Error(`"${answer}": an IP address or a domain`);
      out.push({ domain, answer });
    }
    return out;
  }

  // REQ: API-002 (T7.5) — add and change groups here.
  const groupFields = $derived<Field[]>([
    { key: 'networks', label: 'Networks', type: 'lines', placeholder: '10.20.2.0/24',
      help: 'One per line. Every device on these networks belongs to the group.' },
    // REQ: API-010 (T24.9, ADR-973) — the names a router gave devices.
    { key: 'router_names', label: 'Router names', type: 'lines', placeholder: 'kitchen-tablet',
      help: 'One per line, in the label form (Kitchen Tablet is kitchen-tablet): a device the router named this, and that no device entry names, belongs to the group, whatever its address.' },
    { key: 'lists', label: 'Lists', type: 'multi', options: listNames,
      help: 'Leave all unticked on a new group to use every enabled list.' },
    // REQ: UPS-007 (T9.25)
    { key: 'upstreams', label: 'Upstream servers', type: 'select', options: upstreamGroupNames,
      help: 'The upstream group this group’s questions go to. (default) uses the default group; routes for a domain still win.' },
    // REQ: FLT-011 (T7.11)
    { key: 'safe_search', label: 'Safe search', type: 'bool',
      help: 'Google, Bing, DuckDuckGo, Yandex, and Pixabay show only safe results; YouTube uses Restricted Mode.' },
    // REQ: FLT-902 (T24.29) - which engines (the profile editor sets this too).
    { key: 'safe_search_engines', label: 'Safe search engines', type: 'multi', options: ENGINES.map((e) => e.id), advanced: true,
      help: 'Only these engines are restricted (and safe search is on). Empty with Safe search on means every engine.' },
    { key: 'youtube_restrict', label: 'YouTube restriction', type: 'select', options: ['strict', 'moderate', 'off'], advanced: true },
    // REQ: FLT-012 (T7.9)
    { key: 'blocked_services', label: 'Blocked services', type: 'multi', options: services.map((s) => s.id),
      help: 'Block a whole service (all its domains) for this group, on top of its lists.' },
    // REQ: FLT-014 (T7.20), DNS-016 (T7.21) — answer filtering and DNS64 (T8.6).
    { key: 'rebinding_protection', label: 'Rebinding protection', type: 'bool', advanced: true, helpTopic: 'rebinding',
      help: 'Block answers from the internet that point at private addresses (DNS rebinding).' },
    // REQ: FLT-014, FLT-015 (T27.4) — the exceptions to rebinding protection, one domain per line.
    { key: 'rebinding_allow', label: 'Rebinding exceptions', type: 'lines', placeholder: 'plex.direct', helpTopic: 'rebinding',
      toText: linesOf, fromText: namesFrom,
      help: 'Domains allowed to answer with private addresses, one per line (your own domain, plex.direct).' },
    { key: 'block_answer_ips', label: 'Block answers in', type: 'lines', placeholder: '203.0.113.0/24', advanced: true,
      help: 'Answers with an address in these networks are blocked, whatever the name.' },
    // REQ: FLT-014 (T27.4) — rewrites: the name answered with an address, or a name (a CNAME).
    { key: 'rewrite', label: 'Rewrites', type: 'lines', placeholder: 'nas.example.com 192.168.1.10', helpTopic: 'rewrites',
      toText: rewriteText, fromText: rewritesFrom,
      help: 'One per line: a name, then its answer. *.example.com covers every name under it. Blocks still win.' },
    { key: 'dns64', label: 'DNS64', type: 'bool', advanced: true,
      help: 'Make IPv6 addresses for IPv4-only names, for IPv6-only networks with NAT64.' },
    { key: 'dns64_prefix', label: 'DNS64 prefix', type: 'text', placeholder: '64:ff9b::/96', advanced: true },
    // REQ: DNS-016 (T9.10)
    { key: 'dns64_exclude', label: 'DNS64 exclusions', type: 'lines', placeholder: '2001:db8:bad::/48', advanced: true,
      help: 'IPv6 addresses here count as missing (the name gets made-up ones); IPv4 addresses here are never made into IPv6.' },
    // REQ: FLT-016 (T12.5)
    { key: 'filter_aaaa', label: 'No IPv6 addresses', type: 'bool', advanced: true,
      help: 'Answer IPv6 (AAAA) questions with nothing, so these devices use IPv4: for a network whose IPv6 is broken. Your own names still answer. Not with DNS64.' },
    // REQ: FLT-010 (T9.7)
    { key: 'schedules', label: 'Schedules', type: 'multi', options: scheduleNames,
      help: 'Schedules this group follows (make them under Schedules, below).' },
    { key: 'block_mode', label: 'Blocked answer', type: 'select', options: ['null_ip', 'nxdomain', 'nodata', 'refused', 'custom_ip'], helpTopic: 'block-response' },
    // REQ: FLT-008 (T27.4) — the addresses for custom_ip (required there, the server checks), the block TTL
    // (0 to 86400 s), the Extended DNS Error code and whether it names the list.
    { key: 'block_ips', label: 'Block addresses (custom_ip)', type: 'lines', placeholder: '192.168.1.2', helpTopic: 'block-response',
      toText: linesOf, fromText: addressesFrom,
      enabledWhen: (v) => v.block_mode === 'custom_ip',
      help: 'Used only with Blocked answer = custom_ip: an IPv4 address answers A, an IPv6 address answers AAAA.' },
    { key: 'block_ttl', label: 'Block TTL (seconds)', type: 'number', placeholder: '60', min: 0, max: 86400, helpTopic: 'block-response',
      help: 'How long clients may keep a block: 0 to 86400 seconds.' },
    { key: 'ede', label: 'Extended DNS Error', type: 'select', options: ['blocked', 'filtered'], helpTopic: 'block-response',
      help: 'blocked (15) for ads and trackers; filtered (17) for parental controls, where the client asked for it.' },
    { key: 'ede_text', label: 'Name the list in the error', type: 'bool', initial: true, helpTopic: 'block-response',
      help: 'Off hides the name of the list that blocked the name from the error text.' },
    { key: 'priority', label: 'Priority', type: 'number', placeholder: '0', advanced: true,
      help: 'When a device matches several groups, the highest priority wins.' },
    { key: 'color', label: 'Color', type: 'text', placeholder: 'the brand colour for its place', advanced: true },
  ]);

  function load() {
    api.lists().then((l) => (listNames = l.items.map((x) => x.name))).catch(() => {});
    api.services().then((s) => (services = s.items)).catch(() => {});
    api
      .configEntries('upstream_group')
      .then((e) => (upstreamGroupNames = e.items.filter((x) => x.source !== 'hidden').map((x) => x.name)))
      .catch(() => {});
    api
      .configEntries('schedule')
      .then((e) => (scheduleNames = e.items.filter((x) => x.source !== 'hidden').map((x) => x.name)))
      .catch(() => {});
    api
      .groups()
      .then(async (g) => {
        groups = g.items;
        const entries = await Promise.all(
          g.items
            .filter((x) => x.queries24h > 0)
            .map(async (x) => {
              const [d, b] = await Promise.all([api.top('domains', 5, undefined, x.name), api.top('blocked', 5, undefined, x.name)]);
              return [x.name, { domains: d.items, blocked: b.items }] as const;
            }),
        );
        tops = Object.fromEntries(entries);
      })
      .catch((e) => (error = e));
  }
  $effect(load);
  const advanced = $derived(currentMode() === 'advanced');
  const total = $derived(groups.reduce((a, g) => a + g.queries24h, 0));
  // REQ: FLT-005 (T24.15) — "Make a group from this network" on the Networks page opens the editor
  // with the network filled in (`/groups?draft=network&name=…&networks=…`). Once taken, the URL is
  // replaced with a clean `/groups`, so a reload or Back/Forward doesn't reopen it.
  const networkDraft = $derived(
    route.path === '/groups' && route.params.get('draft') === 'network'
      ? {
          name: route.params.get('name') ?? '',
          values: { networks: [route.params.get('networks') ?? ''].filter(Boolean) },
          onused: () => navigate('/groups', undefined, true),
        }
      : null,
  );
</script>

{#snippet chips(list: Chip[], empty: string)}
  {#if list.length === 0}
    <span class="muted small">{empty}</span>
  {:else}
    <span class="chiprow">
      {#each list.slice(0, CHIPS) as c (c.label)}
        <span class="pchip" data-testid="chip" title={c.title}>{c.label}{#if c.warn}<span class="warn-icon" data-testid="chip-private" role="img" aria-label="Private Wi-Fi address" title="Private Wi-Fi address: the profile may not follow it"><Icon name="alert" size={16} /></span>{/if}</span>
      {/each}
      {#if list.length > CHIPS}
        <span class="pchip more" data-testid="chip-more" title={list.slice(CHIPS).map((c) => c.label).join(', ')}>+{list.length - CHIPS}</span>
      {/if}
    </span>
  {/if}
{/snippet}

<div class="page">
  <h1>Groups<HelpButton id="groups" /></h1>
  <ErrorNote {error} />
  <p class="muted small">
    A group is a kind of device: every device on a group's networks belongs to it (a named device can also be put in a
    group of its own). Groups decide which lists apply and show what each kind of device does.
  </p>

  <!-- REQ: FLT-902 (T24.29) - the profile list: a profile is a group, with who it applies to and what it filters. -->
  <section class="card" data-testid="profiles">
    <div class="card-head">
      <h2>Profiles<HelpButton id="filter-profiles" /></h2>
      {#if can('operator')}
        <button type="button" data-testid="profile-new" onclick={() => (editing = null)}>New profile</button>
      {/if}
    </div>
    <div class="table-wrap">
      <table data-testid="profile-table">
        <thead><tr><th>Name</th><th>Source</th><th>Filter scope</th><th>Safe search</th><th>Schedule</th>{#if can('operator')}<th><span class="sr-only">Edit</span></th>{/if}</tr></thead>
        <tbody>
          {#each groups as g (g.name)}
            <tr data-testid="profile-row" data-profile={g.name}>
              <td><strong>{g.name}</strong></td>
              <td data-col="source">{@render chips(sourceChips(g), 'no devices or networks')}</td>
              <td data-col="scope">{g.filterScope || 'Off'}</td>
              <td data-col="safe">{@render chips(engineChips(g), 'off')}</td>
              <td data-col="schedule">{@render chips(scheduleChips(g), 'none')}</td>
              {#if can('operator')}<td><button type="button" class="link small" data-testid="profile-edit" onclick={() => (editing = g.name)}>Edit</button></td>{/if}
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  </section>
  {#if editing !== undefined}
    <ProfileEditor name={editing} onclose={() => (editing = undefined)} onsaved={load} />
  {/if}

  <div class="group-grid">
    {#each groups as g (g.name)}
      <section class="card group" data-testid="group-card" style:--gc={flockCss(groups, g.name)}>
        <div class="card-head">
          <h2><span class="swatch" aria-hidden="true"></span>{g.name}</h2>
          {#if g.pausedUntilUnixSeconds}
            <span class="badge warn">paused until {dateTime(g.pausedUntilUnixSeconds)}</span>
          {/if}
        </div>
        <div class="muted small mono">
          {g.networks.length
            ? g.networks.join(', ')
            : g.name === 'default'
              ? 'devices that match nothing else'
              : workloadsIn(g.name).length
                ? 'named devices and Kubernetes workloads'
                : 'named devices only'}
        </div>
        {#if g.safeSearch}
          <div class="small" data-testid="group-safe-search">
            Safe search on{g.youtubeRestrict === 'off' ? ' (not YouTube)' : g.youtubeRestrict === 'moderate' ? ' (YouTube moderate)' : ''}<HelpButton id="safe-search" />
          </div>
        {/if}
        {#if g.schedules.length}
          <div class="small" data-testid="group-schedules">
            Schedules: {#each g.schedules as s, i (s)}{i ? ', ' : ''}{s}{#if g.schedulesOn.includes(s)}
                <span class="badge warn">on now</span>{/if}{/each}<HelpButton id="schedules" />
          </div>
        {/if}
        {#if g.blockedServices.length}
          <div class="small" data-testid="group-services">
            Blocks {g.blockedServices.map(serviceName).join(', ')}<HelpButton id="blocked-services" />
          </div>
        {/if}
        <!-- REQ: FLT-014, FLT-015 (T7.20), DNS-016 (T7.21) — shown since T8.6. -->
        {#if g.rebindingProtection || g.blockAnswerIps.length}
          <div class="small" data-testid="group-answers">
            {[
              g.rebindingProtection ? 'Rebinding protection on' : '',
              g.blockAnswerIps.length ? `blocks answers in ${g.blockAnswerIps.join(', ')}` : '',
            ]
              .filter(Boolean)
              .join('; ')}<HelpButton id="rebinding" />
          </div>
        {/if}
        {#if g.rewrites.length}
          <div class="small" data-testid="group-rewrites">
            Rewrites: {#each g.rewrites as r, i (r.domain)}{i ? ', ' : ''}<span class="mono">{r.domain} → {r.answer}</span>{/each}<HelpButton id="rewrites" />
          </div>
        {/if}
        {#if g.upstreams}
          <div class="small" data-testid="group-upstreams">
            Upstream servers: <span class="mono">{g.upstreams}</span>
          </div>
        {/if}
        {#if g.dns64}
          <div class="small" data-testid="group-dns64">
            DNS64 on (<span class="mono">{g.dns64Prefix ?? '64:ff9b::/96'}</span>)<HelpButton id="dns64" />
          </div>
        {/if}
        {#if g.filterAaaa}
          <div class="small" data-testid="group-filter-aaaa">No IPv6 addresses (AAAA answered with nothing)<HelpButton id="filter-aaaa" /></div>
        {/if}
        <dl class="stats">
          <div><dt>Queries (24 h)</dt><dd>{num(g.queries24h)}{#if total}<span class="muted small"> · {pct((g.queries24h / total) * 100, 0)}</span>{/if}</dd></div>
          <div><dt>Blocked</dt><dd>{g.queries24h ? pct((g.blocked24h / g.queries24h) * 100) : '–'}</dd></div>
          <div><dt>Devices (this hour)</dt><dd>{num(g.devicesThisHour)}</dd></div>
        </dl>
        {#if tops[g.name]}
          <div class="tops small">
            <div>
              <div class="muted">Top names</div>
              <ol>{#each tops[g.name].domains as t (t.key)}<li class="mono">{t.key} <span class="muted">{num(t.count)}</span></li>{/each}</ol>
            </div>
            <div>
              <div class="muted">Top blocked</div>
              {#if tops[g.name].blocked.length}
                <ol>{#each tops[g.name].blocked as t (t.key)}<li class="mono">{t.key} <span class="muted">{num(t.count)}</span></li>{/each}</ol>
              {:else}<span class="muted">nothing blocked</span>{/if}
            </div>
          </div>
        {/if}
        <!-- REQ: FLT-017 — the Kubernetes workloads in the group, with their glyph. -->
        {#if workloadsIn(g.name).length}
          <div class="small workloads" data-testid="group-workloads">
            <span class="muted">Workloads:</span>
            {#each workloadsIn(g.name).slice(0, 8) as w (w.name)}<span class="wl"><ClientChip ip={w.key} name={w.name} /></span>{/each}
            {#if workloadsIn(g.name).length > 8}<a href={href('/clients', { tab: 'workloads' })}>and {workloadsIn(g.name).length - 8} more</a>{/if}
          </div>
        {/if}
        <a class="small" href={href('/queries', { group: g.name })}>Show this group's queries</a>
      </section>
    {/each}
  </div>

  <section class="card">
    <h2>Settings</h2>
    <div class="table-wrap">
      <table>
        <thead><tr><th>Group</th><th class="num">Priority</th><th>Lists<HelpButton id="lists" /></th>{#if advanced}<th>Blocked answer<HelpButton id="block-response" /></th>{/if}<th>Blocking</th></tr></thead>
        <tbody>
          {#each groups as g (g.name)}
            <tr>
              <td><strong>{g.name}</strong></td>
              <td class="num">{g.priority}</td>
              <td>{g.lists ? g.lists.join(', ') || 'none' : 'every enabled list'}</td>
              {#if advanced}<td>{g.blockMode} · TTL {g.blockTtlSeconds} s</td>{/if}
              <td>
                {#if g.pausedUntilUnixSeconds}
                  <span class="badge warn">paused until {dateTime(g.pausedUntilUnixSeconds)}</span>
                {:else}
                  <span class="badge ok">on</span>
                {/if}
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  </section>
  <div id="manage-groups">
  <ConfigEditor kind="group" path="groups" title="Manage groups" noun="group" fields={groupFields} draft={networkDraft}
    summary={(d) => `${((d.networks as string[]) ?? []).join(', ') || 'named devices only'} · ${d.lists ? `${(d.lists as string[]).length} lists` : 'every enabled list'}`}
    onchanged={load} />
  </div>
  <!-- REQ: FLT-010 (T9.7) — schedules made here; groups follow them through `schedules`. -->
  <ConfigEditor kind="schedule" path="schedules" title="Schedules" noun="schedule" help="schedules" fields={scheduleFields}
    summary={(d) => `${String(d.action ?? '')}: ${((d.window as { days: string[]; start: string; end: string }[]) ?? []).map((w) => `${w.days.join(',')} ${w.start}-${w.end}`).join('; ')}`}
    onchanged={load} />
</div>

<style>
  .chiprow {
    display: inline-flex;
    flex-wrap: wrap;
    gap: 4px;
  }
  .pchip {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    padding: 1px 8px;
    border-radius: var(--radius-full);
    background: var(--surface-2);
    border: 1px solid var(--border);
    font-size: 0.85em;
    white-space: nowrap;
  }
  .pchip.more {
    color: var(--muted);
  }
  .warn-icon {
    color: var(--warn);
  }
  .workloads {
    display: flex;
    flex-wrap: wrap;
    gap: 4px 10px;
    align-items: baseline;
  }
  .group-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
    gap: 16px;
    margin-bottom: 16px;
  }
  .group {
    margin: 0;
  }
  /* The group's flock colour, beside its name (T33.6, ADR-1040): never a coloured border. */
  .swatch {
    display: inline-block;
    width: 12px;
    height: 12px;
    margin-right: var(--space-2);
    border-radius: var(--radius-full);
    background: var(--gc);
  }
  .stats {
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: 8px;
    margin: 12px 0;
  }
  .stats dt {
    color: var(--muted);
    font-size: 0.8em;
  }
  .stats dd {
    margin: 0;
    font-size: 1.35em;
    font-weight: 650;
    font-variant-numeric: tabular-nums;
  }
  .tops {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 12px;
    margin-bottom: 8px;
  }
  .tops > div {
    min-width: 0;
  }
  .tops ol {
    margin: 4px 0 0;
    padding-left: 18px;
  }
  .tops li {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
</style>
