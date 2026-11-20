// REQ: API-005, DOC-006 (T33.6, ADR-1043) — keeps the UI on-brand (brand/README.md). Fails `npm run check` on:
//   colour     a hard-coded colour (hex, rgb()/hsl()/oklch()..., or a named colour, in CSS, an SVG
//              attribute or a canvas style) outside the token files: colours come from
//              brand/tokens.json through src/brand.css and app.css's names
//   outline    `outline: none` (or 0, 0px) on a selector that no `var(--focus)` rule in the same file
//              stands in for (the two share a class or an element), unless it is
//              `:focus:not(:focus-visible)`; or in an inline style, where nothing can stand in
//   case       `text-transform: uppercase` or small caps (headings and labels are sentence case)
//   disabled   a disabled control faded with `opacity` (disabled is ink-muted with a line border)
//   edge       a coloured or thick left border (no coloured left-border cards; a hairline divider
//              in a line colour is fine)
//   voice      an emoji, or an exclamation mark, in a UI string or a help topic (the product never
//              exclaims; the tagline stays out of it)
//   gradient   a CSS or canvas gradient (the brand is flat: no gradients, no glows)
//   name       the old name, "Telltale", anywhere in the UI or the help topics
//   flock      the group colours' Day values in src/lib/flock.ts or the server differ from tokens.json
// A justified exception goes in scripts/brand-allowlist.txt, one per line:
//   <check> | <file under ui/, or docs/help/topics.json> | <text on the offending line> | <why>
// An entry nothing needs any more fails the check too, so the list stays short.
//
//   node scripts/check-brand.mjs
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

const UI = fileURLToPath(new URL('../', import.meta.url));
const REPO = join(UI, '..');
// Generated or third-party data, not UI code: the tokens, the API types, other brands' marks.
const SKIP = new Set(['src/brand.css', 'src/lib/api-types.ts', 'src/lib/icons/brands.ts']);

const allow = readFileSync(join(UI, 'scripts/brand-allowlist.txt'), 'utf8')
  .split('\n')
  .map((l) => l.trim())
  .filter((l) => l && !l.startsWith('#'))
  .map((l) => {
    const [check, file, text, why] = l.split('|').map((x) => x.trim());
    if (!check || !file || !text || !why) throw new Error(`brand-allowlist.txt: needs "check | file | text | why": ${l}`);
    return { check, file, text, used: false };
  });

const problems = [];
function report(check, file, lineNo, line) {
  const a = allow.find((x) => x.check === check && x.file === file && line.includes(x.text));
  if (a) {
    a.used = true;
    return;
  }
  problems.push(`${file}:${lineNo}: ${check}: ${line.trim().slice(0, 160)}`);
}

function* walk(dir) {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) yield* walk(p);
    else yield p;
  }
}

const blank = (m) => m.replace(/[^\n]/g, ' ');
/** The text with comments blanked out (line numbers kept). */
const uncomment = (text) =>
  text
    .replace(/\/\*[\s\S]*?\*\//g, blank)
    .replace(/<!--[\s\S]*?-->/g, blank)
    .replace(/(^|[\s;{}(,])\/\/[^\n]*/gm, (m, p) => p + blank(m.slice(p.length)));

const HEX = /(?<![\w&%/-])#(?:[0-9a-fA-F]{8}|[0-9a-fA-F]{6}|[0-9a-fA-F]{3,4})(?![\w-])/;
const FUNC = /(?<![\w-])(?:rgba?|hsla?|hwb|lab|lch|oklab|oklch)\(/;
const NAMES = String.raw`(?:white|black|red|green|blue|orange|yellow|purple|gr[ae]y|crimson|darkorange|gold|pink|brown|navy|silver|teal)`;
const NAMED = new RegExp(
  // CSS (`fill: white`) and a `var(--x, white)` fallback;
  String.raw`(?:\b(?:color|background(?:-color)?|fill|stroke|border(?:-[a-z]+)?|outline(?:-color)?|accent-color)\s*:[^;{}\n]*|var\(--[\w-]+,\s*)\b${NAMES}\b` +
    // SVG and Svelte attributes (`fill="white"`, `style:color={'white'}`) and canvas (`fillStyle = 'white'`).
    String.raw`|(?:(?<![\w-])(?:fill|stroke|stop-color|flood-color|color|style:[\w-]+)|\b(?:fillStyle|strokeStyle|shadowColor))\s*=\s*\{?\s*['"${'`'}]?${NAMES}\b`,
);
const GRADIENT = /(?:linear|radial|conic)-gradient\(|create(?:Linear|Radial|Conic)Gradient|<(?:linear|radial)Gradient/;
const OUTLINE_NONE = /\boutline(?:-style|-width)?\s*:\s*(?:none|0(?:px)?)(?![\w.%])/;
const UPPER = /\btext-transform\s*:\s*uppercase\b|\bfont-variant(?:-caps)?\s*:[^;{}\n]*\b(?:all-)?small-caps\b/;
const FADED = /(?<![\w-])opacity\s*:\s*(?:0?\.\d+|0(?![\w.%])|\d{1,2}%)/;
const DISABLED_SEL = /:disabled|\[disabled\]|\[aria-disabled/;
const LEFT_EDGE = /\bborder-(?:left|inline-start)(?:-color|-width)?\s*:([^;{}\n]*)/;
// A hairline in a neutral line colour is a divider, not a coloured card edge.
const NEUTRAL_EDGE = /^\s*(?:0|none|1px|(?:1px\s+solid\s+)?var\(--(?:border|border-strong|card-border|brand-line|brand-line-strong)\))\s*$/;

/** CSS rules as { sel, body, start } (start: the body's offset in `code`), from a .css file or a .svelte file's <style>. */
function cssRules(file, code) {
  const regions = [];
  if (file.endsWith('.css')) regions.push([0, code.length]);
  else if (file.endsWith('.svelte'))
    for (const m of code.matchAll(/(<style\b[^>]*>)([\s\S]*?)<\/style>/g)) regions.push([m.index + m[1].length, m.index + m[1].length + m[2].length]);
  const out = [];
  for (const [a, b] of regions) {
    for (const m of code.slice(a, b).matchAll(/([^{}]+)\{([^{}]*)\}/g)) {
      const sel = m[1].trim();
      if (!sel.startsWith('@')) out.push({ sel, body: m[2], start: a + m.index + m[1].length + 1 });
    }
  }
  return out;
}
/** The classes and elements a selector names (pseudo-classes and attribute tests taken out). */
function selTokens(sel) {
  const bare = sel.replace(/::?[\w-]+(?:\([^)]*\))?/g, ' ').replace(/\[[^\]]*\]/g, ' ');
  return [...bare.matchAll(/\.[\w-]+|(?:^|[\s>+~])([a-zA-Z][\w-]*)/g)].map((m) => m[1] ?? m[0]);
}
const EMOJI = /(?![©®™])[\p{Extended_Pictographic}️]/u;
// An exclamation mark ending a word or a sentence ("Saved!"), not `!=`, `!x` or `!important`.
const BANG = /(?<=[\p{L}\p{N})'"’])!(?![=!\w])/u;
const OLD = /telltale/i;

/** Blanks `{expressions}` out of Svelte markup (nested, across lines), keeping the line breaks. */
function blankExpressions(text) {
  let depth = 0;
  let out = '';
  for (const ch of text) {
    if (ch === '{') depth++;
    out += depth > 0 && ch !== '\n' ? ' ' : ch;
    if (ch === '}' && depth > 0) depth--;
  }
  return out;
}

const LITERALS = /'((?:[^'\\\n]|\\.)*)'|"((?:[^"\\\n]|\\.)*)"|`((?:[^`\\]|\\.)*)`/g;
/** String literals on a line of script, with `${...}` taken out of template literals. */
const literals = (line) => [...line.matchAll(LITERALS)].map((m) => m[1] ?? m[2] ?? (m[3] ?? '').replace(/\$\{[^}]*\}/g, ' '));

/** UI strings as [line, text]: string literals in script, and text and quoted attribute values in markup. */
function uiStrings(file, text) {
  const out = [];
  if (!file.endsWith('.svelte')) {
    text.split('\n').forEach((line, i) => literals(line).forEach((s) => out.push([i + 1, s])));
    return out;
  }
  // Scripts and styles come out of the markup; the scripts' strings are read on their own.
  const markup = text.replace(/<(script|style)\b[^>]*>[\s\S]*?<\/\1>/g, (m, tag, at) => {
    if (tag === 'script') {
      const first = text.slice(0, at).split('\n').length;
      m.split('\n').forEach((line, i) => literals(line).forEach((s) => out.push([first + i, s])));
    }
    return blank(m);
  });
  let inTag = false;
  blankExpressions(markup)
    .split('\n')
    .forEach((line, i) => {
      let words = '';
      for (const m of line.matchAll(/"([^"]*)"/g)) out.push([i + 1, m[1]]);
      for (const ch of line.replace(/"[^"]*"/g, '""')) {
        if (ch === '<') inTag = true;
        else if (ch === '>') inTag = false;
        else if (!inTag) words += ch;
      }
      if (words.trim()) out.push([i + 1, words]);
    });
  return out;
}

const SOURCES = [...walk(join(UI, 'src'))].filter((p) => /\.(svelte|ts|css|js)$/.test(p));
for (const abs of SOURCES) {
  const file = relative(UI, abs).replace(/\\/g, '/');
  if (SKIP.has(file)) continue;
  const text = readFileSync(abs, 'utf8');
  const code = uncomment(text);
  const raw = text.split('\n');
  // Rule by rule: what stands in for a removed outline, faded disabled controls, coloured left edges.
  const rules = cssRules(file, code);
  const focusTokens = new Set(rules.filter((r) => /var\(--focus\)/.test(r.body)).flatMap((r) => selTokens(r.sel)));
  const inRules = new Set();
  for (const r of rules) {
    let n = code.slice(0, r.start).split('\n').length;
    for (const l of r.body.split('\n')) {
      inRules.add(n);
      if (OUTLINE_NONE.test(l)) {
        const alone = r.sel
          .split(',')
          .some((s) => !/:focus:not\(:focus-visible\)/.test(s) && !selTokens(s).some((t) => focusTokens.has(t)));
        if (alone) report('outline', file, n, raw[n - 1]);
      }
      if (FADED.test(l) && DISABLED_SEL.test(r.sel)) report('disabled', file, n, raw[n - 1]);
      const e = LEFT_EDGE.exec(l);
      if (e && !NEUTRAL_EDGE.test(e[1])) report('edge', file, n, raw[n - 1]);
      n++;
    }
  }
  code.split('\n').forEach((line, i) => {
    if (HEX.test(line) || FUNC.test(line) || NAMED.test(line)) report('colour', file, i + 1, raw[i]);
    if (GRADIENT.test(line)) report('gradient', file, i + 1, raw[i]);
    // Outside a style rule (an inline style), nothing stands in for the ring.
    if (OUTLINE_NONE.test(line) && !inRules.has(i + 1)) report('outline', file, i + 1, raw[i]);
    if (UPPER.test(line)) report('case', file, i + 1, raw[i]);
    if (EMOJI.test(line)) report('voice', file, i + 1, raw[i]);
    if (OLD.test(raw[i])) report('name', file, i + 1, raw[i]);
  });
  if (/\.(svelte|ts)$/.test(file)) {
    for (const [n, s] of uiStrings(file, code)) if (BANG.test(s)) report('voice', file, n, raw[n - 1]);
  }
}

// The app's shell and the help topics (shared with the site).
readFileSync(join(UI, 'index.html'), 'utf8')
  .split('\n')
  .forEach((l, i) => OLD.test(l) && report('name', 'index.html', i + 1, l));
const TOPICS = 'docs/help/topics.json';
readFileSync(join(REPO, TOPICS), 'utf8')
  .split('\n')
  .forEach((l, i) => {
    if (OLD.test(l)) report('name', TOPICS, i + 1, l);
    if (EMOJI.test(l)) report('voice', TOPICS, i + 1, l);
    for (const m of l.matchAll(/"((?:[^"\\]|\\.)*)"/g)) if (BANG.test(m[1])) report('voice', TOPICS, i + 1, l);
  });

// The flock's Day values, copied where the token CSS can't reach: the UI's lookup (src/lib/flock.ts)
// and the server's default group colours. Both must match brand/tokens.json, in order (ADR-1040).
const tokens = JSON.parse(readFileSync(join(REPO, 'brand/tokens.json'), 'utf8'));
const day = (n) => tokens.color.tokens.find((t) => t.name === n)?.value.light.toLowerCase();
const FLOCK_DAY = ['flock-1', 'flock-2', 'flock-3', 'flock-4', 'flock-5', 'flock-other'].map(day);
const hexes = (s) => (s ?? '').match(/#[0-9a-fA-F]{6}/g)?.map((h) => h.toLowerCase()) ?? [];
const uiDay = hexes(/const DAY = \[([^\]]*)\]/.exec(readFileSync(join(UI, 'src/lib/flock.ts'), 'utf8'))?.[1]);
if (uiDay.join() !== FLOCK_DAY.join()) problems.push(`src/lib/flock.ts: flock: DAY is [${uiDay}], brand/tokens.json has [${FLOCK_DAY}]`);
const RUST = 'crates/wrendns/src/api_backend.rs';
const rs = readFileSync(join(REPO, RUST), 'utf8');
const rsDay = [...hexes(/const FLOCK: \[&str; 5\] = \[([^\]]*)\]/.exec(rs)?.[1]), ...hexes(/const OTHER: &str = ("[^"]*")/.exec(rs)?.[1])];
if (rsDay.join() !== FLOCK_DAY.join()) problems.push(`${RUST}: flock: the server's group colours are [${rsDay}], brand/tokens.json has [${FLOCK_DAY}]`);

for (const a of allow.filter((x) => !x.used)) problems.push(`scripts/brand-allowlist.txt: unused entry (${a.check} | ${a.file} | ${a.text}): remove it`);

if (problems.length) {
  console.error(`check-brand: ${problems.length} problem(s) (brand/README.md; exceptions go in scripts/brand-allowlist.txt):`);
  for (const p of problems) console.error('  ' + p);
  process.exit(1);
}
console.log(`check-brand: ${SOURCES.length} source files and the help topics are on-brand`);
