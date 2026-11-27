# UI bundle audit (T35.8)

The web UI has a budget of 512 KiB gzipped, counted over every file in `ui/dist` (ADR-1020, API-005; `ui/scripts/postbuild.mjs`). This page is the measured composition of the build on 2026-11-25 (main at the merge of `feat/public-listener-not-open-resolver`, after the first trim of 14 KiB), what could be saved, and what each idea would really do to the gate. Tasks: spec/10 T35.8.

## How it was measured

`npm run build` for the file sizes (`npm run measure:compression` after it reports the same total under brotli quality 11 beside gzip level 9, with no dependency); for the composition a one-off build with source maps (`npx vite build --sourcemap --outDir <scratch>`) read by `source-map-explorer` (installed with `npm i --no-save`, nothing committed; `package.json` gained only the `measure:compression` script, the lock file is unchanged). The explorer reports raw bytes per source file; the gzipped figures below are each file's share of its chunk's measured gzip size (a proportional scale, so they are good to about 5%, not exact: gzip does not add up per module). The Svelte compiler's output for the templates carries no source map in this toolchain, so part of the main chunk shows as "no source" and the pages are attributed by their script and style parts only. Treat the page rows as a lower bound.

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

**`HelpButton` chunk (76 KiB).** The help glossary (`docs/help/topics.json`, 162 topics, 161 KB raw) is 48.5 KiB of it, by far the largest single block in the build. The Svelte runtime is about 16.4 KiB, `api.ts` 5.6 KiB, `Icon` 1.4 KiB. The chunk carries the name of one of its importers; the glossary is in it because `help.ts` imports the JSON statically.

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
| 2 | Brotli for the embedded files (`x.br` instead of `x.gz`; the gate measure becomes the brotli size) | **-87.4 KiB** measured (gzip 499.3 to brotli 411.9 KiB with level 9 and quality 11; `npm run measure:compression` reports it from `ui/dist`), the largest saving on the table and no UI change; about 17% less on first load too | the same share, about 17% | Medium. The server already inflates the stored `.gz` for a client that does not accept gzip (ADR-168), so a br-only embed with the server inflating for a client that does not accept `br` is the same design, and the gate could move to the brotli size. What it needs: a brotli decoder in the server for those clients (a new runtime dependency with its image-size cost, to be measured against the 25 MiB gate; the embedded files themselves get smaller, which offsets it), and an ADR amending ADR-168 and the budget's measure in `spec/07` §3 and `postbuild.mjs`. Plain HTTP on a home LAN: browsers do not send `br` there, so those clients would get the inflated file, as a client without gzip does today; the transfer is then uncompressed, a cost to weigh. A decision for the owner |
| 3 | Zopfli recompression of the `.gz` in `postbuild.mjs` | **-17.6 KiB** measured (499.3 to 481.7 KiB with 15 iterations per file, `@gfx/zopfli` installed with `npm i --no-save` in a scratch directory, nothing committed) | the same share | Low in behaviour (the same format), but it needs a build-time package (a lock-file change and a licence check), so a decision on adding one |
| 4 | Settings (53.4 KiB), Cluster (29.8), Groups (12.3), Lists (12.2), LocalDns (10.3) and Routers (6.2) loaded on demand | **+13.2 KiB** measured (a build with the six behind `{#await import()}` route wrappers like `CmdbRoute`: 499.3 to 512.5 KiB, which is over the budget): each chunk loses the shared compression context of the main chunk | **-125 KiB** measured (the main chunk 289.0 to 167.5 KiB, the stylesheet 18.7 to 14.7) until a page is opened | Low to medium. Routes already work for Map, World, Cmdb and Network inventory this way; the cost is one short wait on first visit of each page and the e2e tests that expect the page at once. The source-map figures in the table above undercount these pages (the template code has no source map), which is why the first estimate here, 35 KiB, was a third of the measured effect. It does not help the gate, it breaks it |
| 5 | uPlot loaded with the first chart | 0 | -16.3 KiB, but the Dashboard is the landing page and draws charts, so a first load still fetches it | Low, no gain in practice |
| 6 | The legacy Dashboard (4.0 KiB) only when selected | 0 | -4.0 KiB | Low |
| 7 | Brand glyphs split by pack (Simple Icons and Bootstrap Icons in two chunks), the second step ADR-1020 names | **-0.04 KiB** measured on the glyph data (23,886 B in one chunk, 20,691 B for the 107 Simple Icons glyphs and 3,151 B for the 11 Bootstrap Icons glyphs, 23,842 B together), less the wrapper of a second chunk | none, the chunk is already lazy; a view that needs only the Simple Icons pack loads 20.2 KiB instead of 23.4 (-3.1 KiB) | Low. Only worth it if a view uses a single pack |
| 8 | Fonts: subset Plex Mono to the characters used, or drop the 500 weight (14,888 bytes, 14.5 KiB) | **-14.5 KiB** exactly for the weight (a woff2 file counts at its size; brotli does not shrink it), less for a subset (not measured: it needs the character list of every page and a font tool) | the same | Medium. The 500 weight is the brand's `--type-mono-sm-weight`; dropping or subsetting it is a visible change and needs the owner's say (ADR on the brand) |
| 9 | Lockup and mark SVGs through svgo | **-3.7 KiB** measured (svgo 4.1 with its default preset, installed with `npm i --no-save`: the two lockups 3,419 and 3,422 to 1,575 and 1,577 bytes gzipped, the two marks 502 to 472, the favicon 511 to 483); the default preset was not checked for visual changes | the same | Low in code, but the lockups and marks are the owner's brand files copied byte for byte (`brand-assets.mjs --check` enforces it), so it is the owner's call |
| 10 | Merge the small lazy chunks (`map-*.js` into `Map`), identical-body CSS rules, the two duplicate functions | **-0.3 KiB** measured for the chunk merge (the two files gzipped together, 10,366 B, against 10,629 B apart); the duplicate functions are about 0.1 KiB (measured above); the CSS merge is not measured (under 1 KiB, and it can change the cascade) | none | Low, not worth the churn |

Reading the table: 1 to 4 and 8 and 9 are measured; 5 and 6 are source-map shares (they do not move the gate, so their precision does not matter); 7 and 10 are measured and negligible. Only 1, 2, 3, 8 and 9 lower the gate; 4 to 7 help the first load only, and 4 raises the gate by 13 KiB. By size on the gate: brotli (2) -87.4 KiB, the glossary on demand (1) -46.9 KiB, zopfli (3) -17.6 KiB, the font weight (8) -14.5 KiB, svgo (9) -3.7 KiB. They do not add up exactly (the glossary's share is smaller under brotli), but brotli alone gives 100 KiB of headroom with no feature change, so it comes first; the glossary on demand is a feature change (an API route and a loading state) and the better step for the first load (it takes the first load to about 385 KiB gzipped) once the gate is not the constraint.

## Recommendation

1. Ask the owner about brotli (2) first: it is the largest saving and changes no UI, but it moves the gate's measure (an ADR amending ADR-168) and adds a decoder to the server.
2. Then the glossary on demand (1) when the first load matters or the gate next forces a choice; it needs a spec item (an API route, `API-011` is the help glossary's id) and its UI, help and tests. The font weight (8), zopfli (3) and svgo (9) are smaller decisions for the owner.
3. Keep the rule of this page for new features: measure `npm run build` before and after, and report the first-load figure with the total.

## Brotli: the measured server cost

Owner decision, 2026-11-26: before deciding whether to serve the embedded web UI as brotli (idea 2 above, measured saving 87 KiB of 499 KiB), the cost on the server side is measured; no behaviour change yet. Nothing here is shipped: no code or Cargo change is committed, the variants were built in a scratch copy.

### Method

- **Scratch copy** of this tree (without `.git`, `target` and `node_modules`) in a build container, `npm ci && npm run build` for `ui/dist` (total 499.3 KiB gzipped, as in the table above), then three embedded sets made from that `dist` by a throwaway script: gunzip each `.gz`, recompress with brotli quality 11, window 22 (Node's `zlib`, the same settings `npm run measure:compression` uses); a file is kept as `.br` only when that is smaller than the raw file; fonts and other binaries are untouched.
- **One build per variant**, `cargo build --release -p wrendns --target x86_64-unknown-linux-musl`, the repository's own release profile (opt-level 3, fat LTO, one codegen unit, `panic = "abort"`, the `opt-level = "s"` package list). Only `crates/wrendns-api/src/ui.rs`, the embedded set and, for (b), one dependency differed between builds; (a) is the unchanged code.
- **What was measured is not the exact image build.** The container has no musl C compiler and no `cargo-zigbuild`, so the C parts (SQLite, mimalloc) were compiled by clang against the container's glibc headers, with SQLite's large-file support off (`-DSQLITE_DISABLE_LFS`) so that it links against musl. The binary is therefore not byte for byte what the image ships, and the absolute figures are not the image's. The Rust code, profile and target are the shipped ones, and the differences between the variants (what this section reports) do not depend on the C parts. The binaries are stripped (`objcopy --strip-all`), and gzip -9 of the binary is the stand-in for the compressed layer, as in ADR-170. The image also holds the zoneinfo and a few small files (about 0.2 MiB), which no variant changes.
- **(a) today:** `.gz` only, inflated with `miniz_oxide` for a client without gzip (ADR-168).
- **(b) brotli files and a brotli decoder only:** `.br` only, served as it is to a client that sends `br`, decoded for any other client. Nothing in `Cargo.lock` decodes brotli. The only pure-Rust decoder considered is `brotli-decompressor` 5.0.3 (two small dependencies, `alloc-no-stdlib` and `alloc-stdlib`; BSD-3-Clause and MIT as its manifest states, to be confirmed with `cargo-deny`); the `brotli` crate depends on it and adds an encoder, so it can only be larger, and it was not built. No C dependency. The decoder's output is capped at the same 8 MiB as `gunzip`.
- **(c) both `.br` and `.gz`, no decoder:** `br` to a client that sends it, otherwise `gzip`, otherwise the `.gz` inflated by the existing code.
- The variants compiled; their behaviour was not run or tested (no request was served, no test was run).

### Result (x86_64 musl, release, stripped)

| | (a) today | (b) `.br` + decoder | (c) `.br` + `.gz` |
|---|---:|---:|---:|
| Embedded UI bytes | 511,305 (499.3 KiB) | 421,817 (411.9 KiB) | 883,370 (862.7 KiB) |
| Embedded change | | -89,488 B (-87.4 KiB) | +372,065 B (+363.3 KiB) |
| Release binary, stripped | 39,543,928 B (37.71 MiB) | 39,635,064 B (37.80 MiB) | 39,923,320 B (38.07 MiB) |
| Binary change | | +91,136 B (+0.09 MiB) | +379,392 B (+0.36 MiB) |
| of which code | | +180,624 B (the decoder and its static dictionary) | +7,327 B |
| Binary, gzip -9 (layer stand-in) | 16,612,687 B (15.84 MiB) | 16,611,316 B (15.84 MiB) | 16,985,957 B (16.20 MiB) |
| **Estimated image change** | | **-1,371 B (none)** | **+373,270 B (+0.36 MiB)** |
| Stand-in against the 25 MiB gate | 15.84 MiB (9.16 MiB left) | 15.84 MiB (9.16 MiB left) | 16.20 MiB (8.80 MiB left) |

Reading it: the decoder's 177 KiB of code and tables compresses in the layer, so it costs the image about what the smaller embedded files save: (b) is neutral on the image (-1.3 KiB, inside the noise of the stand-in). (c) keeps both copies, and a `.br` does not compress further, so the image grows by about the size of the `.br` files, 0.36 MiB. The stand-in covers only the binary and is a floor for the image. The other two architectures were not built (the embedded bytes are the same on each; the decoder's code would differ a little). The gate is not the constraint: even (c) leaves 8.8 MiB of the 25 MiB (ADR-916, `docs/v1-gate.md`; the 0.1.0 release measured 11.1 MiB on amd64). Not measured: request time and CPU of decoding, memory, the other architectures, and the real zigbuild image.

### Who sends `br`

Browsers advertise `br` in `Accept-Encoding` only on HTTPS. On plain HTTP they send `gzip, deflate`. Chrome has done this since it shipped brotli (version 50) and Firefox since 44; the reason given by the Chromium and Brotli teams is that proxies and middleboxes had corrupted codings other than gzip and deflate, and Firefox also declines to decode `br` from a plain-HTTP response (a 2016 comparison). Wikipedia states the rule for browsers in general ("with the exception of Pale Moon and Basilisk, web browsers will only accept Brotli-compressed content over HTTPS"). Safari supports `br` since version 11; an HTTPS-only rule for it was not confirmed from a source. Over HTTPS the support is general: 97.37% of browsers worldwide (caniuse, "Brotli Accept-Encoding/Content-Encoding"). A browser navigation over HTTPS sends `Accept-Encoding: gzip, deflate, br, zstd` (MDN). So about 97% of HTTPS visits would send `br`, and no plain-HTTP visit would. The MDN pages fetched for this do not mention the HTTPS rule; it rests on the Brotli mailing list thread "Brotli header is only sent on HTTPS connections", the blink-dev "Intent to Ship: Brotli (Accept-encoding: br on HTTPS connection)" and Mozilla bugs 1218924 and 1670675 (found by search; the pages were not all re-read for this section).

WrenDNS serves the UI over HTTPS when `[api] tls` is set (a self-signed certificate is one setting) and otherwise over plain HTTP, the usual state on a home LAN. How many installations use HTTPS is not known, and this page does not guess.

| Client | (a) today | (b) `.br` + decoder | (c) `.br` + `.gz` |
|---|---|---|---|
| HTTPS browser (97% send `br`) | gzip, 432 KiB first load | `br`, about 358 KiB (-17%) | `br`, about 358 KiB |
| Plain-HTTP browser (`gzip, deflate`) | gzip, 432 KiB | **inflated by the server, uncompressed: about 1.2 MiB, 2.9 times today** | gzip, 432 KiB (as today) |
| Client with no coding (curl, a probe) | inflated | inflated by the decoder | inflated by `miniz_oxide` |

The brotli first-load figure is an estimate: of the 432 KiB first load, the three fonts (49.7 KiB) do not shrink; the rest (382 KiB gzipped) scales by the measured brotli-to-gzip ratio of the text files (362.1 over 449.5 KiB, 0.806). The uncompressed figure is the raw size of the first-load files (about 1.19 MiB of script, style and SVG, plus the fonts). Hashed `assets/*` are `immutable`, so this is the first visit only, not every page load. On a LAN, 1.2 MiB is a small transfer; over a slow link or a VPN to a remote node it is not.

### Recommendation

**Owner decision, 2026-11-26: brotli is not shipped.** The reasons are points 1 and 2 below. The saving held in reserve for the day a feature reaches the budget is the glossary on demand (idea 1, point 4 below). The points are kept as measured.

1. **Do not ship (b) while the UI is mostly opened over plain HTTP.** It is image-neutral and gives 87 KiB under the UI budget, but every plain-HTTP browser, the default on a LAN, would get the file uncompressed: a first load 2.9 times larger than today, to buy headroom that the image gate does not need (9.2 MiB left). It also adds a crate (a `cargo-deny` and supply-chain check) and decoding on the request path (up to about 1 MB of output per file; not measured), where today's inflate is the cheap path.
2. **(c) is the safe way to get brotli** if the HTTPS first load matters (about 17% smaller, about 358 KiB against 432). It adds no dependency and changes nothing for plain-HTTP clients, but it costs 0.36 MiB of image and gives no headroom on the embedded size: the 512 KiB budget in `postbuild.mjs` would have to count what is embedded (about 863 KiB for both copies), or stay as the transfer budget with the embedded size as a second figure. Either is a change to ADR-168 and to the budget's measure in `spec/07` §3.
3. **Conditions for either:** most installations open the UI over HTTPS (the owner's call, or a measure; no counter records the transport today); the other two architectures built for the size; a request-time and memory measurement of the decoder if (b) is still wanted; an ADR amending ADR-168 and the budget's measure.
4. **If headroom under the 512 KiB budget is the goal,** the glossary on demand (idea 1, -46.9 KiB) lowers the first load for every client on every transport and needs no server coding, so it does not depend on this question.

Nothing here is open after that decision. If brotli is looked at again, the questions are the ones above: (b) or (c), what the UI budget measures afterwards, and a measurement on the real image build.

## Implemented: the glossary on demand (2026-11-26)

Idea 1 was built, not as a lazy chunk (the gate counts every file in `ui/dist`, so that would save nothing) but as data fetched from the node: the glossary is embedded in the server outside `ui/dist` and served at `/help/topics.json`. Gate: 508.0 KiB before, 459.2 KiB after (-48.8 KiB). See the ADR-1020 amendment in `spec/11-decisions.md`. The first load still fetches the file (161,052 bytes (157 KiB) raw and 51,659 bytes (about 50 KiB) at `gzip -9`, not gzipped on the wire), after first paint and once per page load, because the "?" tooltips need the titles.
