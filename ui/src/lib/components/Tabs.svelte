<script lang="ts" module>
  // REQ: API-005 (ADR-121) — tabs for long pages: the tab lives in the URL (`#/cluster?tab=health`),
  // so links, reloads, and Back keep it. A tab can carry a count, and an alert one stands out:
  // what needs attention mustn't hide behind a tab.
  import { route } from '../router.svelte';

  export type TabItem = {
    id: string;
    label: string;
    /** Shown after the label (rows, nodes, problems, or a word like `pinned`); hidden when
     * null or undefined. */
    count?: number | string | null;
    /** Something on this tab needs attention: the count shows as a warning. */
    alert?: boolean;
  };

  /** The tab named in the URL's `tab`, else the first. */
  export function activeTab(tabs: TabItem[]): string {
    const t = route.params.get('tab');
    return tabs.some((x) => x.id === t) ? (t as string) : (tabs[0]?.id ?? '');
  }
</script>

<script lang="ts">
  import { navigate } from '../router.svelte';

  let { tabs, active, label }: { tabs: TabItem[]; active: string; label: string } = $props();
  let list = $state<HTMLDivElement>();

  function select(id: string) {
    if (id !== active) navigate(route.path, { tab: id });
  }

  // WAI-ARIA tabs: arrow keys move between tabs (and open them), Home and End jump to the ends.
  function onkeydown(e: KeyboardEvent) {
    const i = tabs.findIndex((t) => t.id === active);
    const to: Record<string, number> = {
      ArrowRight: (i + 1) % tabs.length,
      ArrowLeft: (i - 1 + tabs.length) % tabs.length,
      Home: 0,
      End: tabs.length - 1,
    };
    const j = to[e.key];
    if (j === undefined) return;
    e.preventDefault();
    select(tabs[j].id);
    list?.querySelector<HTMLButtonElement>(`#tab-${tabs[j].id}`)?.focus();
  }
</script>

<div class="seg tabs" role="tablist" aria-label={label} bind:this={list}>
  {#each tabs as t (t.id)}
    <button
      role="tab"
      id="tab-{t.id}"
      aria-selected={t.id === active}
      aria-controls="tabpanel"
      tabindex={t.id === active ? 0 : -1}
      data-testid="tab-{t.id}"
      onclick={() => select(t.id)}
      {onkeydown}
    >
      {t.label}{#if t.count != null}<span class="count" class:alert={t.alert}>{typeof t.count === 'number' ? t.count.toLocaleString() : t.count}</span>{/if}
    </button>
  {/each}
</div>

<style>
  .tabs {
    justify-self: start;
    max-width: 100%;
    overflow-x: auto;
    -webkit-overflow-scrolling: touch;
    scrollbar-width: none;
  }
  .tabs button {
    white-space: nowrap;
  }
  /* Selected: `sky-soft` with `sky-strong` text, as the sidebar's current page (T33.6). */
  .tabs button[aria-selected='true'] {
    background: var(--brand-sky-soft);
    border-color: var(--border-strong);
    color: var(--accent);
    font-weight: 600;
  }
  .count {
    display: inline-block;
    margin-left: var(--space-2);
    padding: 0 var(--space-1);
    border-radius: var(--radius-sm);
    font-size: var(--type-mono-sm-size);
    font-weight: 600;
    background: var(--surface);
    color: var(--muted);
  }
  /* Something needs attention: the warning colour on its tint, with an edge (never a saturated fill). */
  .count.alert {
    background: var(--warn-soft);
    color: var(--warn);
    border: 1px solid var(--warn);
  }
</style>
