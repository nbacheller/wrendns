<script lang="ts">
  // REQ: FLT-006, API-010, AGT-001 (T24.30, ADR-996) — a device's effective policy: the group it
  // is in, where the group came from, the key that matched, then every section the server sends
  // (lists, services, schedules, rules, ...), each line linking to where it is set. The panel draws
  // whatever sections arrive, in order; it knows no section ids, so categories and profiles
  // (T24.29) arrive as new sections with no change here. `compact` is the map's version: the
  // group, the key and one line per section, with a link to the full panel.
  import { api, type S } from '../api';
  import { href } from '../router.svelte';
  import { dateTime } from '../format';
  import { groupFromText, matchedByText } from '../policy';
  import ErrorNote from './ErrorNote.svelte';
  import HelpButton from './HelpButton.svelte';

  let { client, compact = false }: { client: string; compact?: boolean } = $props();

  // The compact panel names this many items per section; the rest are "+N more".
  const COMPACT_ITEMS = 3;

  let policy = $state<S['ClientPolicy'] | null>(null);
  let error = $state<unknown>(null);

  $effect(() => {
    const id = client;
    policy = null;
    error = null;
    let live = true;
    api
      .clientPolicy(id)
      .then((p) => live && (policy = p))
      .catch((e) => live && (error = e));
    return () => (live = false);
  });

  // The state is always a word, never only a colour.
  const stateText: Record<string, string> = {
    on: 'on',
    off: 'off',
    in_effect: 'in effect now',
    not_in_effect: 'not in effect',
    not_applied: 'not applied',
    expired: 'expired',
    shadow: 'shadow',
  };
  const stateClass: Record<string, string> = {
    on: 'ok',
    in_effect: 'ok',
    off: '',
    not_in_effect: '',
    not_applied: 'warn',
    expired: 'warn',
    shadow: 'info',
  };
  const fullHref = $derived(href('/clients', { device: client, view: 'policy' }));
  const linkHref = (l: { path: string; params?: Record<string, string> } | null | undefined) =>
    l ? href(l.path, l.params) : undefined;
</script>

<div class="policy" data-testid={compact ? 'policy-compact' : 'policy-panel'}>
  <ErrorNote {error} />
  {#if policy}
    <p class="head" data-testid="policy-group">
      <span class="muted small">Group</span>
      <strong>{policy.group}</strong>
      <span class="muted small" data-testid="policy-group-from">from {groupFromText[policy.groupFrom] ?? policy.groupFrom}{policy.groupKey ? ` (${policy.groupKey})` : ''}</span>
    </p>
    <p class="small" data-testid="policy-key">
      <span class="muted">Recognized by</span>
      <span class="badge info">{matchedByText[policy.identifiedBy] ?? policy.identifiedBy}</span>
      {#if policy.matchedKey}<code data-testid="policy-matched-key">{policy.matchedKey}</code>{/if}
      {#if policy.device}<span class="muted">as</span> <strong>{policy.device}</strong>{/if}
      {#if policy.address}<span class="muted mono">at {policy.address}</span>{/if}
      <HelpButton id="device-policy" />
    </p>
    {#if policy.groups.length > 1}
      <p class="small muted">Also in {policy.groups.slice(1).join(', ')}; the first group's settings apply.</p>
    {/if}

    {#if compact}
      <ul class="small summaries">
        {#each policy.sections.filter((x) => x.items.length > 0) as s (s.id)}
          <li data-testid={`policy-summary-${s.id}`}>
            <strong>{s.title}.</strong> {s.summary}
            <!-- REQ: AGT-001 (T35.2) — up to three items as links, then "+N more" to the full panel. -->
            <span class="peek" data-testid={`policy-peek-${s.id}`}>
              {#each s.items.slice(0, COMPACT_ITEMS) as it, i (`${it.label}#${i}`)}{#if i > 0}, {/if}{#if it.link}<a href={linkHref(it.link)} data-testid="policy-peek-link">{it.label}</a>{:else}<span data-testid="policy-peek-item">{it.label}</span>{/if}{/each}{#if s.items.length > COMPACT_ITEMS}, <a href={fullHref} class="more" data-testid={`policy-more-${s.id}`}>+{s.items.length - COMPACT_ITEMS} more</a>{/if}
            </span>
          </li>
        {/each}
      </ul>
      <p class="small"><a href={fullHref} data-testid="policy-full-link">Full policy</a></p>
    {:else}
      <ol class="ladder small" aria-label="How a device is matched, most specific first" data-testid="policy-ladder">
        {#each policy.precedence as r (r.source)}
          <li class:matched={r.matched}>{r.label}{#if r.matched}<span class="badge ok">decided</span>{/if}</li>
        {/each}
      </ol>
      {#each policy.notes as n, i (i)}<p class="notice small" data-testid="policy-note">{n}</p>{/each}
      {#each policy.sections as s (s.id)}
        <section class="sect" data-testid={`policy-section-${s.id}`}>
          <h3>{#if s.link}<a href={linkHref(s.link)}>{s.title}</a>{:else}{s.title}{/if}</h3>
          <p class="muted small">{s.summary}</p>
          {#if s.items.length}
            <ul class="items">
              {#each s.items as it, i (`${it.label}#${i}`)}
                <li data-testid="policy-item">
                  {#if it.link}<a href={linkHref(it.link)} data-testid="policy-link">{it.label}</a>{:else}<strong>{it.label}</strong>{/if}
                  {#if it.state}<span class="badge {stateClass[it.state] ?? ''}">{stateText[it.state] ?? it.state}</span>{/if}
                  {#if it.untilUnixSeconds}<span class="small muted">until {dateTime(it.untilUnixSeconds)}</span>{/if}
                  {#if it.detail}<span class="small muted">{it.detail}</span>{/if}
                  {#if it.from}<span class="small muted">· {it.from}</span>{/if}
                </li>
              {/each}
            </ul>
          {/if}
        </section>
      {/each}
      <p class="muted small">
        As of {dateTime(policy.atUnixSeconds)}{policy.node ? `, from ${policy.node}'s configuration` : ''}.
        {#if policy.missingNodes?.length}Not answering: {policy.missingNodes.join(', ')}.{/if}
      </p>
    {/if}
  {:else if !error}
    <p class="muted small" data-testid="policy-loading">Loading the policy…</p>
  {/if}
</div>

<style>
  .head {
    display: flex;
    flex-wrap: wrap;
    gap: 6px 10px;
    align-items: baseline;
    margin: 0 0 6px;
  }
  .summaries {
    margin: 6px 0;
    padding-left: 18px;
  }
  .ladder {
    display: flex;
    flex-wrap: wrap;
    gap: 4px 12px;
    padding-left: 18px;
    margin: 8px 0;
  }
  .ladder li.matched {
    font-weight: 600;
  }
  .sect {
    border-top: 1px solid var(--border);
    padding-top: 6px;
    margin-top: 8px;
  }
  .sect h3 {
    margin: 0;
    font-size: 14px;
  }
  .items {
    list-style: none;
    margin: 4px 0 0;
    padding: 0;
    display: grid;
    gap: 4px;
  }
  .items li {
    display: flex;
    flex-wrap: wrap;
    gap: 2px 8px;
    align-items: baseline;
    word-break: break-word;
  }
</style>
