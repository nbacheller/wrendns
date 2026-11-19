<script lang="ts">
  // REQ: FLT-902, FLT-901, API-010 (T24.29, ADR-994, ADR-973) — the filter profile editor: Name, Source (the
  // networks and devices the profile applies to, from the shared picker, with a warning on a private Wi-Fi
  // address and an "Add device" form), Ad Block, Safe Search per engine, Filtering (Off, Basic or Enhanced with
  // the category picker) and Schedule. A profile is a group: the fields write the group, its content and its
  // sources, and every field the group has stays in the Advanced settings below the editor.
  import Picker, { type PickItem } from './Picker.svelte';
  import Categories from './Categories.svelte';
  import Drawer from './Drawer.svelte';
  import ErrorNote from './ErrorNote.svelte';
  import HelpButton from './HelpButton.svelte';
  import { api, ApiError, type S } from '../api';
  import { ENGINES, asBudget, emptyChoice, size, type Level } from '../categories';

  let {
    name: editing = null,
    onclose,
    onsaved,
  }: { name?: string | null; onclose: () => void; onsaved: () => void } = $props();

  const isNew = $derived(editing === null);
  let nameInput = $state('');
  let loaded = $state(false);
  let error = $state<unknown>(null);
  let view = $state<S['CategoriesView'] | null>(null);
  let picker = $state<S['ProfileDevices'] | null>(null);
  let group = $state<S['GroupInfo'] | null>(null);
  let definition = $state<Record<string, unknown>>({});
  let scheduleNames = $state<string[]>([]);

  // The form.
  let level = $state<Level>('off');
  let cats = $state<string[]>([]);
  let tiers = $state<Record<string, string>>({});
  let ads = $state(false);
  let engines = $state<string[]>([]);
  let schedules = $state<string[]>([]);
  let services = $state<string[]>([]);
  let sourceSel = $state<string[]>([]);
  let keyFor = $state<Record<string, string>>({});
  let added = $state<{ id: string; label: string; keys: S['ProfileKey'][] }[]>([]);
  let addOpen = $state(false);
  let addName = $state('');
  let addKey = $state('');
  let addError = $state('');

  let impact = $state('');
  let total = $state<S['BudgetView'] | null>(null);
  let needConfirm = $state<string | null>(null);
  let saving = $state(false);
  let more = $state(false);

  async function load() {
    try {
      const [v, p, g, e, sch, svc] = await Promise.all([
        api.categories(),
        api.profileDevices().catch(() => ({ networks: [], devices: [] }) as S['ProfileDevices']),
        api.groups(),
        api.configEntries('group'),
        api.configEntries('schedule'),
        api.services(),
      ]);
      view = v;
      picker = p;
      scheduleNames = sch.items.filter((x) => x.source !== 'hidden').map((x) => x.name);
      void svc;
      if (editing !== null) {
        nameInput = editing;
        group = g.items.find((x) => x.name === editing) ?? null;
        const def = e.items.find((x) => x.name === editing)?.definition as Record<string, unknown> | undefined;
        definition = def ?? {};
        const c = group?.content;
        level = (c?.level as Level) ?? 'off';
        cats = [...(c?.categories ?? [])];
        tiers = { ...(c?.tiers ?? {}) };
        ads = c?.ads ?? false;
        const eng = group?.safeSearchEngines ?? [];
        engines = eng.length ? [...eng] : group?.safeSearch ? ENGINES.map((x) => x.id) : [];
        schedules = [...(group?.schedules ?? [])];
        services = [...(group?.blockedServices ?? [])];
        sourceSel = (group?.sources ?? []).map((s) => (s.kind === 'network' ? `net:${s.id}` : `dev:${s.id}`));
      } else {
        const d = emptyChoice();
        level = d.level;
      }
      loaded = true;
    } catch (e) {
      error = e;
    }
  }
  $effect(() => {
    void load();
  });

  // The picker's items: networks and devices, with what the group already holds.
  const deviceKey = (s: S['ProfileSource']) => s.keys ?? [];
  const items = $derived.by<PickItem[]>(() => {
    const out: PickItem[] = [];
    for (const n of picker?.networks ?? []) {
      out.push({ value: `net:${n.id}`, label: n.label, secondary: n.label === n.id ? 'network' : n.id, kind: 'networks' });
    }
    const seen = new Set<string>();
    const dev = (s: S['ProfileSource']) => {
      if (seen.has(s.id)) return;
      seen.add(s.id);
      const k = deviceKey(s);
      const randomized = k.length > 0 && k.every((x) => x.kind !== 'mac' || x.randomized) && k.some((x) => x.kind === 'mac' && x.randomized);
      out.push({
        value: `dev:${s.id}`,
        label: s.label,
        secondary: [k.find((x) => x.kind === 'ip')?.value, k.find((x) => x.kind === 'mac')?.value, randomized ? 'private address' : '', s.group && s.group !== 'default' ? `in ${s.group}` : '']
          .filter(Boolean)
          .join(' · '),
        kind: 'clients',
      });
    };
    for (const d of picker?.devices ?? []) dev(d);
    for (const s of group?.sources ?? []) if (s.kind === 'device') dev(s);
    for (const a of added) dev({ kind: 'device', id: a.id, label: a.label, icon: 'unknown', keys: a.keys, configured: false });
    for (const s of group?.sources ?? []) {
      if (s.kind === 'network' && !out.some((i) => i.value === `net:${s.id}`)) out.push({ value: `net:${s.id}`, label: s.label, secondary: s.id, kind: 'networks' });
    }
    return out;
  });
  const MAC = /^([0-9a-f]{2}[:-]){5}[0-9a-f]{2}$/i;
  const IPV4 = /^\d{1,3}(\.\d{1,3}){3}$/;
  const typed = (t: string): PickItem | null => {
    const v = t.trim();
    if (MAC.test(v)) return { value: `dev:new:${v.toLowerCase().replace(/-/g, ':')}`, label: v.toLowerCase(), secondary: 'MAC address', kind: 'clients' };
    if (IPV4.test(v)) return { value: `dev:new:${v}`, label: v, secondary: 'address', kind: 'clients' };
    return null;
  };

  // The selected devices, with the keys each can be recognized by and which one is used.
  type Chosen = { value: string; label: string; keys: S['ProfileKey'][]; existing: boolean };
  const chosen = $derived.by<Chosen[]>(() => {
    const out: Chosen[] = [];
    for (const v of sourceSel) {
      if (!v.startsWith('dev:')) continue;
      const id = v.slice(4);
      if (id.startsWith('new:')) {
        const raw = id.slice(4);
        const kind = MAC.test(raw) ? 'mac' : 'ip';
        out.push({ value: v, label: raw, keys: [{ kind, value: raw, randomized: kind === 'mac' && (parseInt(raw.slice(0, 2), 16) & 2) !== 0 }], existing: false });
        continue;
      }
      const item = items.find((i) => i.value === v);
      const src = [...(picker?.devices ?? []), ...(group?.sources ?? [])].find((s) => s.id === id) ?? added.find((a) => a.id === id);
      const keys = (src && 'keys' in src ? (src.keys ?? []) : []) as S['ProfileKey'][];
      const configured = !!(src && 'configured' in src && src.configured);
      out.push({ value: v, label: item?.label ?? id, keys, existing: configured });
    }
    return out;
  });
  const keyOf = (c: Chosen): S['ProfileKey'] | undefined => {
    const want = keyFor[c.value];
    return c.keys.find((k) => k.value === want) ?? c.keys.find((k) => k.kind === 'mac') ?? c.keys[0];
  };
  const keyText = (k: S['ProfileKey']) =>
    `${k.kind === 'mac' ? 'MAC' : k.kind === 'ip' ? 'Address' : k.kind === 'name' ? 'Router name' : 'Client ID'} ${k.value}${k.randomized ? ' (private)' : ''}`;

  function addDevice() {
    addError = '';
    const n = addName.trim();
    const k = addKey.trim();
    const item = typed(k);
    if (!n) return void (addError = 'Give the device a name.');
    if (!item) return void (addError = 'Give its MAC address or its IP address.');
    const raw = item.label;
    const key: S['ProfileKey'] = MAC.test(raw)
      ? { kind: 'mac', value: raw, randomized: (parseInt(raw.slice(0, 2), 16) & 2) !== 0 }
      : { kind: 'ip', value: raw, randomized: false };
    const id = `${n}`;
    added = [...added, { id, label: n, keys: [key] }];
    sourceSel = [...sourceSel, `dev:${id}`];
    addName = '';
    addKey = '';
    addOpen = false;
  }

  // The preview of who moves, from the server's dry run (an existing profile).
  let timer: ReturnType<typeof setTimeout> | undefined;
  function sourcesBody(): Record<string, unknown> {
    return {
      networks: sourceSel.filter((v) => v.startsWith('net:')).map((v) => v.slice(4)),
      devices: chosen.map((c) => ({ name: c.label, match: c.existing && !(c.value.startsWith('dev:new:')) ? [] : [keyOf(c)?.value].filter(Boolean) })),
    };
  }
  $effect(() => {
    const body = sourcesBody();
    void body;
    if (!loaded || isNew || !editing) return;
    clearTimeout(timer);
    timer = setTimeout(async () => {
      try {
        impact = (await api.putGroupSources(editing ?? '', sourcesBody(), true)).impact ?? '';
      } catch (e) {
        impact = e instanceof ApiError ? e.message : '';
      }
    }, 250);
    return () => clearTimeout(timer);
  });
  // What the category selection costs (the running total).
  $effect(() => {
    const q = { group: editing ?? (nameInput.trim() || 'new-profile'), level, categories: cats.join(','), tiers: Object.entries(tiers).map(([k, v]) => `${k}:${v}`).join(','), ads };
    if (!loaded) return;
    const t = setTimeout(() => api.categoryBudget(q).then((b) => (total = b)).catch(() => {}), 200);
    return () => clearTimeout(t);
  });

  const serviceCategoryIds = $derived(
    new Set((view?.groups ?? []).flatMap((g) => g.categories).filter((c) => c.kind === 'service').flatMap((c) => c.services)),
  );
  const adsProvidedBy = $derived(view?.sources.find((s) => s.id === `hagezi-ads-${view?.node.adsTier.replace('_', '-')}`)?.state.providedBy ?? null);

  const nameOk = $derived(/^[a-z0-9][a-z0-9-_ ]*$/i.test(nameInput.trim()));

  async function save(confirm = false) {
    if (!view) return;
    saving = true;
    error = null;
    needConfirm = null;
    const nm = (editing ?? nameInput).trim();
    try {
      // 1. The group itself: safe search, schedules, blocked services (everything else it has is kept).
      const body: Record<string, unknown> = { ...definition };
      delete body.name;
      delete body.content;
      const all = engines.length === ENGINES.length;
      body.safe_search_engines = all ? [] : engines;
      body.safe_search = all ? true : engines.length > 0 ? definition.safe_search === true : false;
      body.schedules = schedules;
      // The services other than the bundles a category turns on are kept as they were.
      const keepSvc = ((definition.blocked_services as string[] | undefined) ?? []).filter((s) => !serviceCategoryIds.has(s));
      body.blocked_services = [...new Set([...keepSvc, ...services.filter((s) => serviceCategoryIds.has(s))])];
      await api.putEntry('groups', nm, body);
      // 2. What it filters by category.
      await api.putGroupContent(nm, { level, categories: cats, tiers, ads }, { confirm });
      // 3. Who it applies to.
      if (sourceSel.length || (group?.sources ?? []).length || !isNew) {
        await api.putGroupSources(nm, sourcesBody());
      }
      onsaved();
      onclose();
    } catch (e) {
      if (e instanceof ApiError && e.code === 'confirm_required') needConfirm = e.detail;
      else error = e;
    } finally {
      saving = false;
    }
  }

  const randomizedChosen = $derived(chosen.filter((c) => keyOf(c)?.randomized));
</script>

<Drawer title={isNew ? 'New profile' : `Profile ${editing}`} onclose={onclose}>
  <div class="editor" data-testid="profile-editor">
    <ErrorNote {error} />
    {#if !loaded}
      <p class="muted">Loading…</p>
    {:else if view}
      <label class="field">
        <span>Name</span>
        <input type="text" bind:value={nameInput} disabled={!isNew} data-testid="profile-name" placeholder="Kids" autocomplete="off" />
      </label>

      <div class="field">
        <span>Source<HelpButton id="filter-profiles" /></span>
        <p class="muted small">The networks and devices this profile applies to.</p>
        <Picker label="Source" placeholder="Search networks and devices…" {items} bind:selected={sourceSel} custom={typed} testid="profile-source" />
        {#each chosen as c (c.value)}
          {@const k = keyOf(c)}
          <div class="dev" data-testid="profile-device">
            <strong>{c.label}</strong>
            {#if c.keys.length > 1}
              <label class="small">Recognized by
                <select data-testid="profile-device-key" value={k?.value} onchange={(e) => (keyFor = { ...keyFor, [c.value]: e.currentTarget.value })}>
                  {#each c.keys as key (key.value)}<option value={key.value}>{keyText(key)}</option>{/each}
                </select>
              </label>
            {:else if k}
              <span class="muted small">{keyText(k)}</span>
            {/if}
            {#if k?.randomized}
              <span class="warn-icon" data-testid="private-mac-warning" role="img" aria-label="Private Wi-Fi address" title="This device uses a private Wi-Fi address">⚠</span>
            {/if}
          </div>
        {/each}
        {#if randomizedChosen.length}
          <p class="notice warn small" role="status" data-testid="private-mac-notice">
            {randomizedChosen.map((c) => c.label).join(', ')}: this device uses a private Wi-Fi address. The profile may not follow it if the address changes.
            Turn off Private Wi-Fi Address for this network on the device, or give it a DHCP reservation and select it by address or name instead.
          </p>
        {/if}
        <p>
          <button type="button" class="link small" data-testid="profile-add-device" onclick={() => (addOpen = !addOpen)}>Add device…</button>
        </p>
        {#if addOpen}
          <div class="add" data-testid="profile-add-form">
            <label class="small">Name <input type="text" bind:value={addName} data-testid="profile-add-name" placeholder="Maya's iPad" autocomplete="off" /></label>
            <label class="small">MAC or address <input type="text" bind:value={addKey} data-testid="profile-add-key" placeholder="aa:bb:cc:dd:ee:ff" autocomplete="off" /></label>
            <button type="button" data-testid="profile-add-confirm" onclick={addDevice}>Add</button>
            {#if addError}<span class="err small" role="alert">{addError}</span>{/if}
          </div>
        {/if}
        {#if impact}<p class="notice small" role="status" data-testid="profile-impact">{impact}</p>{/if}
      </div>

      <div class="field">
        <label class="check">
          <input type="checkbox" bind:checked={ads} disabled={!!adsProvidedBy} data-testid="profile-ads" />
          <span>Ad Block</span>
        </label>
        {#if adsProvidedBy}
          <p class="muted small" data-testid="profile-ads-file">Provided by list <code>{adsProvidedBy}</code> (set by file).</p>
        {:else}
          <p class="muted small">Ads, trackers and telemetry, from HaGeZi's {view.node.adsTier.replace('_', '-')} list (the size is set under Settings, Filtering).</p>
        {/if}
      </div>

      <div class="field">
        <span>Safe Search</span>
        <div class="row" role="group" aria-label="Safe Search engines" data-testid="profile-engines">
          {#each ENGINES.filter((x) => !x.more) as e (e.id)}
            <label class="check"><input type="checkbox" checked={engines.includes(e.id)} onchange={(ev) => (engines = ev.currentTarget.checked ? [...engines, e.id] : engines.filter((x) => x !== e.id))} data-testid={`engine-${e.id}`} /> {e.name}</label>
          {/each}
          <button type="button" class="link small" onclick={() => (more = !more)} aria-expanded={more}>More engines</button>
          {#if more}
            {#each ENGINES.filter((x) => x.more) as e (e.id)}
              <label class="check"><input type="checkbox" checked={engines.includes(e.id)} onchange={(ev) => (engines = ev.currentTarget.checked ? [...engines, e.id] : engines.filter((x) => x !== e.id))} data-testid={`engine-${e.id}`} /> {e.name}</label>
            {/each}
          {/if}
        </div>
        {#if !engines.includes('youtube') && definition.youtube_restrict && definition.youtube_restrict !== 'strict'}
          <p class="muted small" data-testid="profile-youtube-note">YouTube restriction is on although YouTube is not in the Safe Search engines.</p>
        {/if}
      </div>

      <div class="field">
        <span>Filtering<HelpButton id="categories" /></span>
        <div class="row" role="radiogroup" aria-label="Filtering">
          {#each [['off', 'Off'], ['basic', 'Basic'], ['enhanced', 'Enhanced']] as [id, label] (id)}
            <label class="check"><input type="radio" name="level" value={id} checked={level === id} onchange={() => (level = id as Level)} data-testid={`level-${id}`} /> {label}</label>
          {/each}
        </div>
        {#if level === 'basic'}
          <p class="muted small" data-testid="profile-basic-note">Basic blocks adult content, malware, phishing and scams, and nothing else.</p>
        {/if}
        {#if level === 'enhanced'}
          <Categories {view} bind:selected={cats} bind:tiers bind:services readonly={false} {total} />
        {/if}
      </div>

      <div class="field">
        <span>Schedule<HelpButton id="schedules" /></span>
        <Picker label="Schedule" placeholder="Schedules this profile follows…" items={scheduleNames.map((s) => ({ value: s, label: s }))} bind:selected={schedules} testid="profile-schedules" />
        <p class="muted small">Make schedules under Schedules, further down this page.</p>
      </div>

      {#if needConfirm}
        <div class="notice warn" role="alertdialog" data-testid="profile-confirm">
          {needConfirm}
          {#if total}<div class="small">That is {size(asBudget(total.total).snapshotBytes)} of memory for the lists.</div>{/if}
          <p><button type="button" data-testid="profile-confirm-yes" onclick={() => save(true)} disabled={saving}>Confirm and save</button></p>
        </div>
      {/if}

      <div class="actions">
        <button type="button" data-testid="profile-save" onclick={() => save(false)} disabled={saving || (isNew && !nameOk)}>{saving ? 'Saving…' : 'Save'}</button>
        <button type="button" onclick={onclose} disabled={saving}>Cancel</button>
        <a class="small" href="#manage-groups" onclick={onclose} data-testid="profile-advanced">Advanced settings</a>
      </div>
    {/if}
  </div>
</Drawer>

<style>
  .editor {
    display: grid;
    gap: 14px;
  }
  .field {
    display: grid;
    gap: 6px;
  }
  .field > span {
    font-weight: 600;
  }
  .row {
    display: flex;
    flex-wrap: wrap;
    gap: 6px 14px;
    align-items: center;
  }
  .check {
    display: inline-flex;
    align-items: center;
    gap: 6px;
  }
  .dev {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 8px;
    padding: 2px 0;
  }
  .warn-icon {
    color: var(--warn);
  }
  .add {
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
    align-items: end;
  }
  .actions {
    display: flex;
    gap: 10px;
    align-items: center;
  }
  .err {
    color: var(--bad);
  }
</style>
