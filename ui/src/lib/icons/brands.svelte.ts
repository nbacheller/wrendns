// Icon lab — the brand glyphs are a separate chunk, fetched once when the first icon needs one, so
// a page that shows none never pays for them.
export const brandData = $state<{ ready: boolean; data: Record<string, [string, string]> }>({
  ready: false,
  data: {},
});

let started = false;
export function ensureBrands(): void {
  if (started) return;
  started = true;
  import('./brands')
    .then((m) => {
      brandData.data = m.BRANDS;
      brandData.ready = true;
    })
    .catch(() => {
      // No glyphs (a failed chunk): names fall back to their monogram, nothing else is affected.
      started = false;
    });
}
