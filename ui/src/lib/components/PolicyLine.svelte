<script lang="ts">
  // REQ: FLT-006, API-010 (T24.30, ADR-996) — the policy step in one line: the group, where it came
  // from, and the key that matched, with a link to the device's Policy panel. Flow and Explain use it,
  // so each says the same thing the Clients panel does.
  import { href } from '../router.svelte';
  import HelpButton from './HelpButton.svelte';
  import { groupFromText, matchedByText } from '../policy';

  let {
    device,
    group,
    groupFrom,
    groupKey,
    matchedKey,
    identifiedBy,
  }: {
    /** What the panel is opened for: the device's name, or its address. */
    device: string;
    group: string;
    groupFrom: string;
    groupKey?: string | null;
    matchedKey?: string | null;
    identifiedBy: string;
  } = $props();
</script>

<p class="policy-line small" data-testid="policy-line">
  <span class="muted">Policy</span>
  group <strong data-testid="policy-line-group">{group}</strong>
  <span class="muted" data-testid="policy-line-from">from {groupFromText[groupFrom] ?? groupFrom}{groupKey ? ` (${groupKey})` : ''}</span>
  · matched by <span class="badge info">{matchedByText[identifiedBy] ?? identifiedBy}</span>
  {#if matchedKey}<code data-testid="policy-line-key">{matchedKey}</code>{/if}
  · <a href={href('/clients', { device, view: 'policy' })} data-testid="policy-line-link">Device policy</a>
  <HelpButton id="device-policy" />
</p>
