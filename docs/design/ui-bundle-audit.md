# UI bundle audit (T35.8)

The web UI has a budget of 512 KiB gzipped, counted over every file in `ui/dist` (ADR-1020, API-005; `ui/scripts/postbuild.mjs`). This page is the measured composition of the build on 2026-11-25 (main at the merge of `feat/public-listener-not-open-resolver`, after the first trim of 14 KiB), what could be saved, and what each idea would really do to the gate. Tasks: spec/10 T35.8.

## How it was measured

`npm run build` for the file sizes; for the composition a one-off build with source maps (`npx vite build --sourcemap --outDir <scratch>`) read by `source-map-explorer` (installed with `npm i --no-save`, nothing committed, `package.json` and the lock file unchanged). The explorer reports raw bytes per source file; the gzipped figures below are each file's share of its chunk's measured gzip size (a proportional scale, so they are good to about 5%, not exact: gzip does not add up per module). The Svelte compiler's output for the templates carries no source map in this toolchain, so part of the main chunk shows as "no source" and the pages are attributed by their script and style parts only. Treat the page rows as a lower bound.

## Every file against the budget

Total **499.3 KiB** of 512.0 KiB: **12.7 KiB of headroom.**

| File | Raw | Gzipped | Loaded |
|---|---:|---:|---|
| `assets/index-*.js` (the app, every page that is not lazy, uPlot) | 883,536 | 289,049 | first paint |
| `assets/HelpButton-*.js` (Svelte runtime, `api.ts`, `Icon`, the help glossary) | 212,419 | 75,952 | first paint (modulepreload) |
| `assets/brands-*.js` (brand glyph paths, 58 KB) | 57,753 | 23,930 | when the first brand icon is drawn |
| `figtree-latin-wght-normal.woff2` | 20,156 | 20,156 | first paint |
| `index-*.css` (global, brand and every non-lazy page) | 94,896 | 18,702 | first paint |
| `ibm-plex-mono-latin-500-normal.woff2` | 14,888 | 14,888 | when text in it is drawn |
| `ibm-plex-mono-latin-400-normal.woff2` | 14,708 | 14,708 | when text in it is drawn |
| `World-*.js` (lazy page) | 24,990 | 11,379 | on `/world` |
| `NetworkInventory-*.js` (lazy page) | 31,232 | 10,451 | on that page |
| `Cmdb-*.js` (lazy page) | 27,596 | 9,509 | on that page |
| `Map-*.js` (lazy page) | 20,317 | 7,459 | on `/map` |
| two lockup SVGs (day, night) | 8,671 each | 3,422 and 3,419 | first paint (both `<img>` are fetched) |
| `map-*.js` (map layout helper) | 7,991 | 3,170 | with the map |
| `Map-*.css`, `World-*.css`, `HelpButton-*.css`, `Cmdb-*.css` | | 1,212, 887, 872, 246 | with their chunk |
| `favicon.svg`, two mark SVGs, `index.html` | | 511, 502, 502, 379 | first paint (favicon, html) |

**First-load figure.** The first load is `index.html`, the main chunk, the preloaded `HelpButton` chunk, two stylesheets, the Figtree file, the two logo SVGs, the favicon, and the two Plex Mono files when text uses them: about **442 KB, 432 KiB**, 87% of the gate. What a first load never fetches: the brand glyphs (23.4 KiB), World (11.1), Network inventory (10.2), Cmdb (9.3), Map with its helper and styles (11.4), together about 65 KiB. The gate counts them all.

## Main chunk, by module (gzipped share of 289 KiB)

| Part | Gzipped (est.) | Note |
|---|---:|---|
| `src/pages/*.svelte` (script and styles of 40-odd pages) | 68.6 KiB | Settings, Cluster and Lists are a third of it |
| `src/lib` and `src/lib/components` (components, stores, formatters, tuning, treemap, map) | about 99 KiB | each file under 3.4 KiB |
| uPlot (`uPlot.esm.js`, the whole library) | 16.3 KiB | one module, no tree shaking possible |
| Output with no source map | 69.9 KiB | Svelte's template code and bundler glue |
| Unmapped | 28.2 KiB | the same kind, between mapped ranges |

Largest sources in the main chunk (a share of the gzip size):

| Source | Gzipped (est.) |
|---|---:|
| `pages/Settings.svelte` | 9.4 KiB |
| `pages/Cluster.svelte` | 6.0 KiB |
| `pages/Lists.svelte` | 5.4 KiB |
| `pages/Groups.svelte` | 4.6 KiB |
| `pages/DashboardLegacy.svelte` | 4.0 KiB |
| `pages/LocalDns.svelte` | 4.0 KiB |
| `pages/Routers.svelte` | 3.3 KiB |
| `components/ConfigEditor.svelte` | 3.3 KiB |
| `components/ProfileEditor.svelte` | 3.2 KiB |
| `pages/DashboardCalm.svelte` | 3.1 KiB |
| `pages/Queries.svelte` | 3.0 KiB |
| `icons/map.data.ts` (the generated map table) | 2.9 KiB |
| `pages/Upstreams.svelte`, `Flow`, `Heatmap`, `Clients`, `Cache`: | 2.5 to 2.9 KiB each |

Thirty-odd more pages and components follow, each under 2.5 KiB. The generated data in the main chunk is `map.data.ts` (2.9 KiB); the other generated tables are already lazy (`brands.ts` 23.4 KiB in its own chunk, `world-data.ts` inside the World chunk). The scoped class names were already cut to `s` plus four characters in the first trim.

**`HelpButton` chunk (76 KiB).** The help glossary (`docs/help/topics.json`, 162 topics, 141 KB raw) is 48.5 KiB of it, by far the largest single block in the build. The Svelte runtime is about 16.4 KiB, `api.ts` 5.6 KiB, `Icon` 1.4 KiB. The chunk carries the name of one of its importers; the glossary is in it because `help.ts` imports the JSON statically.

## Duplicate and dead code

Checked, none worth removing:

- **Dead modules and components:** every `.svelte` and `.ts` file under `ui/src` is imported by another file (only `main.ts`, the entry, is not). Exported names that nothing else uses are types or constants used in their own file; the bundler already drops what is not reachable.
- **Duplicate function bodies:** a scan of the source for identical functions of 120 characters or more finds two pairs (`save` in `BackupCard`/`SupportPackage`, `color` in `Chart`/`SmoothChart`), 370 bytes raw together, about 100 bytes gzipped. Not worth a shared module.
- **Duplicate help text:** no two topics share a field value of more than 20 characters except the topic ids named in `docs` links; no empty fields to drop (dropping empty keys saves 0.25 KiB gzipped and changes the topic shape).
- **Duplicate CSS:** no repeated rule in the 1,113 rules of the stylesheet. 133 groups of rules have an identical body under different selectors (8.9 KB raw if merged by selector list); gzip already folds most of that, and merging rules can change the cascade order, so the gain (estimated under 1 KiB gzipped) is not worth the risk.
- **Whole icon or locale sets:** the brand glyphs are already a lazy chunk with per-glyph one-decimal paths; there are no locale files; the fonts are the latin subsets.
- **Minifier and compression settings, measured on this build (JS and CSS, gzipped):** the default (oxc) 453.1 KiB; terser 456.0 KiB (+2.8); esbuild 493.5 KiB (+40.4); gzip level 9 with `memLevel` 9 +0.2 KiB. The default is the best of the four; nothing to change.

## Ranked savings and their effect on the gate

No saving is both clearly safe and still on the table: the first trim (`c80b6ea0`) took the dead weight (long class names, glyph precision, glossary comment), and the rest of the build is content (text, glyph paths, pages). So nothing was implemented in this audit. Ranked by gain on the gate, then on the first load:

| # | Idea | Gate effect | First-load effect | Risk |
|---|---|---:|---:|---|
| 1 | The help glossary served by the API on demand (topic by id, cached in the browser), the step ADR-1020 names | **-46.9 KiB** measured (a build with the glossary stubbed: 499.3 to 452.4 KiB), minus the new API route (small, Rust side) | **-46.9 KiB** (the `HelpButton` chunk goes 76 to 28 KiB) | Medium. A "?" shows its text after a request, so help needs a loading state and an offline fallback; `check:help` and the site both read the JSON, so the file stays and the route serves it; needs an API item with its OpenAPI entry, a UI control state, a help entry and tests (the rule that every API item ships with its UI). The route must be exempt from the setup/auth gates the same way the UI files are, or help breaks on the sign-in page |
| 2 | Brotli for the embedded files (`x.br` beside or instead of `x.gz`; the gate measure becomes the brotli size) | about -10% of the JS, CSS and SVG, roughly **-35 to -40 KiB** (estimated, brotli was not run here) | the same share on first load | Medium. The server embeds and serves `.gz` today (ADR-168); every browser that matters takes `br` on HTTPS, but not on plain HTTP on a home LAN, so the `.gz` fallback has to stay, which keeps the budget measure on gzip; the saving would only move the gate if the gate is redefined. A decision for the owner |
| 3 | Zopfli-style recompression of the `.gz` in `postbuild.mjs` | about -3% of the compressible files, **-10 to -13 KiB** (estimated, needs a dependency; Node has no zopfli) | the same share | Low in behaviour (the same format), but it needs a build-time package, so a decision on adding one (the rule on dependencies, and a lock-file change) |
| 4 | Settings (9.4 KiB) and Cluster (6.0 KiB), Lists, Groups, LocalDns, Routers loaded on demand | 0 (slightly more: each chunk adds about 0.3 KiB of wrapper) | up to **-35 KiB** if all six are lazy | Low to medium. Routes already work for Map, World, Cmdb and Network inventory this way; the cost is one short wait on first visit of each page and the e2e tests that expect the page at once |
| 5 | uPlot loaded with the first chart | 0 | -16.3 KiB, but the Dashboard is the landing page and draws charts, so a first load still fetches it | Low, no gain in practice |
| 6 | The legacy Dashboard (4.0 KiB) only when selected | 0 | -4.0 KiB | Low |
| 7 | Brand glyphs split by pack (Simple Icons and Bootstrap Icons in two chunks), the second step ADR-1020 names | 0, or a few hundred bytes more | the glyph chunk is already lazy, so none; a view that needs only one pack saves up to about 5 KiB of loading | Low. Only worth it if a view uses a single pack |
| 8 | Fonts: subset Plex Mono to the characters used, or drop the 500 weight (14.9 KiB) | up to **-14.9 KiB** for the weight, less for a subset | the same | Medium. The 500 weight is the brand's `--type-mono-sm-weight`; dropping or subsetting it is a visible change and needs the owner's say (ADR on the brand) |
| 9 | Lockup SVGs through svgo (8.7 KB raw each, 3.4 KiB gzipped each) | about -1 to -2 KiB (estimated) | the same | Low in code, but the files are the owner's brand files copied byte for byte (`brand-assets.mjs --check` enforces it), so it is the owner's call |
| 10 | Merge the small lazy chunks (`map-*.js` into `Map`), identical-body CSS rules, the two duplicate functions | each under 1 KiB (estimated) | none | Low, not worth the churn |

Reading the table: only 1 to 3, 8 and 9 move the gate. 4 to 7 help the first load only. 1 is the one that would give real room: 47 KiB back, so a total of 452 KiB and 60 KiB of headroom; it also takes the first load to about 385 KiB. It is the next step, and it is a feature change (an API route and a loading state), so it is a proposal here with its numbers, not part of an audit commit.

## Recommendation

1. Take step 1 (the glossary on demand) when the gate next forces a choice; it needs a spec item (an API route, `API-011` is the help glossary's id) and its UI, help and tests.
2. Ask the owner about brotli (2) and the font weight (8): they are decisions, not clean-ups.
3. Keep the rule of this page for new features: measure `npm run build` before and after, and report the first-load figure with the total.
