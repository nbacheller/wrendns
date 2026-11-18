<script lang="ts" module>
  // REQ: UI-901 (T24.34, ADR-1013) — one searchable picker for every "choose from a list" in the UI.
  export interface PickItem {
    value: string;
    label: string;
    /** Smaller text beside the label (addresses, a MAC); searched too. */
    secondary?: string;
    /** An icon name from Icon.svelte (devices, groups, networks…); none when absent or unknown. */
    kind?: string;
    disabled?: boolean;
  }
  /** What a search matches: the label and the secondary text, case-insensitive, every word. */
  export function matches(hay: string, query: string): boolean {
    const words = query.toLowerCase().split(/\s+/).filter(Boolean);
    return words.every((w) => hay.includes(w));
  }
</script>

<script lang="ts">
  import Icon, { paths } from './Icon.svelte';

  let {
    items,
    selected = $bindable([]),
    multiple = true,
    label,
    placeholder = 'Search…',
    maxChips = 3,
    emptyText = 'Nothing matches',
    testid,
    disabled = false,
    custom,
    onchange,
  }: {
    items: PickItem[];
    selected?: string[];
    multiple?: boolean;
    /** The accessible name of the picker (its group and its combobox). */
    label: string;
    placeholder?: string;
    /** Chips shown before "+N". */
    maxChips?: number;
    emptyText?: string;
    testid?: string;
    disabled?: boolean;
    /** Turns what was typed into an item that isn't in the list (an address typed in full); null when it isn't one. */
    custom?: (typed: string) => PickItem | null;
    onchange?: (selected: string[]) => void;
  } = $props();

  const ROW = 32; // px, fixed so the list can be windowed
  const VIEW = 288; // px, the list's height
  const OVERSCAN = 6;
  const uid = Math.random().toString(36).slice(2, 8);

  let open = $state(false);
  let query = $state('');
  let active = $state(0);
  let scrollTop = $state(0);
  let root = $state<HTMLElement | undefined>();
  let input = $state<HTMLInputElement | undefined>();
  let list = $state<HTMLElement | undefined>();

  // Lower-cased once per item list: a keystroke is one pass over a string each.
  const hay = $derived(items.map((i) => `${i.label} ${i.secondary ?? ''}`.toLowerCase()));
  const filtered = $derived.by(() => {
    const q = query.trim();
    if (!q) return items;
    const out: PickItem[] = [];
    const extra = custom?.(q);
    if (extra && !items.some((i) => i.value === extra.value)) out.push(extra);
    for (let i = 0; i < items.length; i++) if (matches(hay[i], q)) out.push(items[i]);
    return out;
  });
  const chosen = $derived(new Set(selected));
  const byValue = $derived(new Map(items.map((i) => [i.value, i])));
  let typedItems = $state<PickItem[]>([]);
  const first = $derived(Math.max(0, Math.floor(scrollTop / ROW) - OVERSCAN));
  const last = $derived(Math.min(filtered.length, Math.ceil((scrollTop + VIEW) / ROW) + OVERSCAN));
  const windowed = $derived(filtered.slice(first, last));
  const shown = $derived(selected.slice(0, maxChips));
  const rest = $derived(Math.max(0, selected.length - maxChips));
  const labelOf = (v: string) => byValue.get(v)?.label ?? typedItems.find((t) => t.value === v)?.label ?? v;
  const optId = (i: number) => `${uid}-opt-${i}`;

  function set(next: string[]) {
    selected = next;
    onchange?.(next);
  }
  function toggle(it: PickItem) {
    if (it.disabled) return;
    if (!byValue.has(it.value) && !typedItems.some((t) => t.value === it.value)) typedItems = [...typedItems, it];
    if (!multiple) {
      set([it.value]);
      close();
      return;
    }
    set(chosen.has(it.value) ? selected.filter((x) => x !== it.value) : [...selected, it.value]);
  }
  /** Select all and Deselect all work on what the search shows, not on the whole list. */
  function selectAll() {
    const add = filtered.filter((i) => !i.disabled && !chosen.has(i.value)).map((i) => i.value);
    set([...selected, ...add]);
  }
  function deselectAll() {
    const drop = new Set(filtered.map((i) => i.value));
    set(selected.filter((v) => !drop.has(v)));
  }
  function remove(v: string) {
    set(selected.filter((x) => x !== v));
    input?.focus();
  }
  function close() {
    open = false;
    query = '';
  }
  function reveal() {
    if (!list) return;
    const top = active * ROW;
    if (top < list.scrollTop) list.scrollTop = top;
    else if (top + ROW > list.scrollTop + VIEW) list.scrollTop = top + ROW - VIEW;
    scrollTop = list.scrollTop;
  }
  function move(to: number) {
    active = Math.max(0, Math.min(filtered.length - 1, to));
    reveal();
  }

  function key(e: KeyboardEvent) {
    if (disabled) return;
    switch (e.key) {
      case 'ArrowDown':
        e.preventDefault();
        if (!open) open = true;
        else move(active + 1);
        break;
      case 'ArrowUp':
        e.preventDefault();
        if (!open) open = true;
        else move(active - 1);
        break;
      case 'PageDown':
        if (open) {
          e.preventDefault();
          move(active + Math.floor(VIEW / ROW));
        }
        break;
      case 'PageUp':
        if (open) {
          e.preventDefault();
          move(active - Math.floor(VIEW / ROW));
        }
        break;
      case 'Home':
        if (open && e.ctrlKey) {
          e.preventDefault();
          move(0);
        }
        break;
      case 'End':
        if (open && e.ctrlKey) {
          e.preventDefault();
          move(filtered.length - 1);
        }
        break;
      case 'Enter':
        // Never submits a surrounding form from the search box.
        e.preventDefault();
        if (!open) open = true;
        else if (filtered[active]) toggle(filtered[active]);
        break;
      case 'Escape':
        if (open) {
          e.preventDefault();
          e.stopPropagation();
          close();
        }
        break;
      case 'Backspace':
        if (!query && selected.length) set(selected.slice(0, -1));
        break;
    }
  }

  // Tab (or any focus move) out of the picker closes the list.
  function leave(e: FocusEvent) {
    const to = e.relatedTarget as Node | null;
    if (open && root && !(to && root.contains(to))) close();
  }

  function outside(e: MouseEvent) {
    if (open && root && !root.contains(e.target as Node)) close();
  }

  // A new search starts at the top; the active row stays inside the results.
  $effect(() => {
    void query;
    active = 0;
    scrollTop = 0;
    if (list) list.scrollTop = 0;
  });
</script>

<svelte:window onclick={outside} />

<div class="picker" bind:this={root} role="group" aria-label={label} data-testid={testid} onfocusout={leave}>
  <!-- svelte-ignore a11y_click_events_have_key_events, a11y_no_static_element_interactions -->
  <div class="box" class:disabled onclick={() => !disabled && (input?.focus(), (open = true))}>
    {#if multiple}
      {#each shown as v (v)}
        <span class="chip" data-testid="picker-chip">
          {labelOf(v)}
          <button type="button" class="x" aria-label={`Remove ${labelOf(v)}`} {disabled} onclick={(e) => { e.stopPropagation(); remove(v); }}>×</button>
        </span>
      {/each}
      {#if rest}<span class="chip more" data-testid="picker-more" title={selected.slice(maxChips).map(labelOf).join(', ')}>+{rest}</span>{/if}
    {:else if selected[0] && !open}
      <span class="single">{labelOf(selected[0])}</span>
    {/if}
    <input
      bind:this={input}
      bind:value={query}
      role="combobox"
      aria-label={label}
      aria-expanded={open}
      aria-controls={open ? `${uid}-list` : undefined}
      aria-autocomplete="list"
      aria-haspopup="listbox"
      aria-activedescendant={open && filtered.length ? optId(active) : undefined}
      autocomplete="off"
      spellcheck="false"
      placeholder={selected.length ? '' : placeholder}
      {disabled}
      onfocus={() => !disabled && (open = true)}
      onkeydown={key}
    />
  </div>
  {#if open}
    <div class="pop">
      {#if multiple}
        <div class="bar">
          <span class="muted small" aria-live="polite" data-testid="picker-count">{filtered.length} of {items.length}{selected.length ? ` · ${selected.length} selected` : ''}</span>
          <span>
            <button type="button" class="link small" data-testid="picker-all" disabled={!filtered.length} onmousedown={(e) => e.preventDefault()} onclick={selectAll}>Select all</button>
            <button type="button" class="link small" data-testid="picker-none" disabled={!filtered.length} onmousedown={(e) => e.preventDefault()} onclick={deselectAll}>Deselect all</button>
          </span>
        </div>
      {/if}
      <!-- svelte-ignore a11y_no_noninteractive_element_interactions -->
      <div
        class="list"
        id={`${uid}-list`}
        role="listbox"
        aria-label={label}
        aria-multiselectable={multiple}
        tabindex="-1"
        style={`max-height:${VIEW}px`}
        bind:this={list}
        onscroll={() => list && (scrollTop = list.scrollTop)}
        onmousedown={(e) => e.preventDefault()}
      >
        {#if !filtered.length}
          <p class="muted small empty">{emptyText}</p>
        {:else}
          <div class="space" style={`height:${filtered.length * ROW}px`}>
            {#each windowed as it, n (it.value)}
              {@const i = first + n}
              <!-- Keys act on the combobox input (aria-activedescendant), not on the options. -->
              <!-- svelte-ignore a11y_click_events_have_key_events -->
              <div
                class="opt"
                class:on={i === active}
                class:picked={chosen.has(it.value)}
                id={optId(i)}
                role="option"
                tabindex="-1"
                aria-selected={chosen.has(it.value)}
                aria-disabled={it.disabled || undefined}
                aria-posinset={i + 1}
                aria-setsize={filtered.length}
                aria-label={it.secondary ? `${it.label} (${it.secondary})` : it.label}
                style={`top:${i * ROW}px;height:${ROW}px`}
                onclick={() => toggle(it)}
                onmousemove={() => (active = i)}
              >
                {#if multiple}<span class="tick" aria-hidden="true">{chosen.has(it.value) ? '✓' : ''}</span>{/if}
                {#if it.kind && paths[it.kind]}<span class="ico" aria-hidden="true"><Icon name={it.kind} size={15} /></span>{/if}
                <span class="lab">{it.label}</span>
                {#if it.secondary}<span class="sec muted small">{it.secondary}</span>{/if}
              </div>
            {/each}
          </div>
        {/if}
      </div>
    </div>
  {/if}
</div>

<style>
  .picker {
    position: relative;
    min-width: 220px;
  }
  .box {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 4px;
    padding: 3px 6px;
    min-height: 34px;
    border: 1px solid var(--border);
    border-radius: 8px;
    background: var(--surface);
    cursor: text;
  }
  .box:focus-within {
    outline: 2px solid var(--accent);
    outline-offset: 1px;
  }
  .box.disabled {
    opacity: 0.6;
    cursor: default;
  }
  .box input {
    flex: 1 1 90px;
    min-width: 90px;
    border: 0;
    outline: 0;
    background: none;
    color: var(--text);
    font: inherit;
    padding: 4px 2px;
  }
  .chip {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    max-width: 180px;
    padding: 1px 4px 1px 8px;
    border-radius: 999px;
    background: var(--surface-2);
    border: 1px solid var(--border);
    font-size: 0.85em;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }
  .chip.more {
    padding-right: 8px;
  }
  .x {
    border: 0;
    background: none;
    color: var(--muted);
    cursor: pointer;
    padding: 0 3px;
    font: inherit;
    line-height: 1;
  }
  .x:hover {
    color: var(--text);
  }
  .single {
    padding: 0 4px;
  }
  .pop {
    position: absolute;
    z-index: 30;
    left: 0;
    right: 0;
    margin-top: 4px;
    min-width: 280px;
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 8px;
    box-shadow: 0 6px 18px rgb(0 0 0 / 18%);
  }
  .bar {
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 8px;
    padding: 6px 10px;
    border-bottom: 1px solid var(--border);
  }
  .bar button {
    margin-left: 8px;
  }
  .list {
    overflow-y: auto;
    position: relative;
  }
  .space {
    position: relative;
  }
  .opt {
    position: absolute;
    left: 0;
    right: 0;
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 0 10px;
    cursor: pointer;
    box-sizing: border-box;
    white-space: nowrap;
  }
  .opt.on {
    background: var(--hover, rgb(127 127 127 / 14%));
  }
  .opt[aria-disabled='true'] {
    opacity: 0.5;
    cursor: default;
  }
  .tick {
    width: 1em;
    color: var(--accent);
    font-weight: 700;
  }
  .ico {
    display: inline-flex;
    color: var(--muted);
  }
  .lab {
    overflow: hidden;
    text-overflow: ellipsis;
    flex: 0 1 auto;
  }
  .sec {
    overflow: hidden;
    text-overflow: ellipsis;
    flex: 1 1 0;
    min-width: 0;
  }
  .empty {
    padding: 10px;
    margin: 0;
  }
</style>
