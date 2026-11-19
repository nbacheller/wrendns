<script lang="ts">
  // The WrenDNS logo (brand/logos, copied byte for byte by scripts/brand-assets.mjs): the lockup
  // (the bird on the wordmark's baseline) or, where there is no room for it, the mark. Day and
  // Night each have their own file; the theme decides which one shows (prefers-color-scheme, or
  // the header's toggle through data-theme). The wren is the logo only: never an icon in the UI.
  let { variant = 'lockup' }: { variant?: 'lockup' | 'mark' } = $props();
</script>

<span class="logo {variant}" role="img" aria-label="WrenDNS" data-testid="logo">
  <img class="day" src={`/brand/wrendns-${variant}-day.svg`} alt="" />
  <img class="night" src={`/brand/wrendns-${variant}-night.svg`} alt="" />
</span>

<style>
  .logo {
    display: inline-flex;
    flex: none;
  }
  .logo img {
    display: block;
    height: 28px;
    width: auto;
  }
  .logo.mark img {
    height: 28px;
    width: 28px;
  }
  .night {
    display: none !important;
  }
  :global(:root[data-theme='dark']) .day {
    display: none !important;
  }
  :global(:root[data-theme='dark']) .night {
    display: block !important;
  }
  @media (prefers-color-scheme: dark) {
    :global(:root:not([data-theme='light'])) .day {
      display: none !important;
    }
    :global(:root:not([data-theme='light'])) .night {
      display: block !important;
    }
  }
</style>
