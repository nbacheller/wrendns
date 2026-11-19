// REQ: API-005, DOC-006 (T33.6, ADR-1043) — keeps the UI on-brand (brand/README.md). Fails `npm run check` on:
//   colour     a hard-coded colour (hex, rgb()/hsl()/oklch()..., or a named colour) outside the token
//              files: colours come from brand/tokens.json through src/brand.css and app.css's names
//   outline    `outline: none` (or 0) in a file that draws no replacement focus style (`var(--focus)`)
//   voice      an emoji, or an exclamation mark, in a UI string or a help topic (the product never
//              exclaims; the tagline stays out of it)
//   gradient   a CSS or canvas gradient (the brand is flat: no gradients, no glows)
//   name       the old name, "Telltale", anywhere in the UI or the help topics
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
const NAMED =
  /(?:\b(?:color|background(?:-color)?|fill|stroke|border(?:-[a-z]+)?|outline(?:-color)?|accent-color)\s*:[^;{}\n]*|var\(--[\w-]+,\s*)\b(?:white|black|red|green|blue|orange|yellow|purple|gr[ae]y|crimson|darkorange|gold|pink|brown|navy|silver|teal)\b/;
const GRADIENT = /(?:linear|radial|conic)-gradient\(|create(?:Linear|Radial|Conic)Gradient|<(?:linear|radial)Gradient/;
const OUTLINE_NONE = /\boutline\s*:\s*(?:none|0)\b/;
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
  const drawsFocus = /var\(--focus\)/.test(code);
  code.split('\n').forEach((line, i) => {
    if (HEX.test(line) || FUNC.test(line) || NAMED.test(line)) report('colour', file, i + 1, raw[i]);
    if (GRADIENT.test(line)) report('gradient', file, i + 1, raw[i]);
    if (OUTLINE_NONE.test(line) && !drawsFocus) report('outline', file, i + 1, raw[i]);
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

for (const a of allow.filter((x) => !x.used)) problems.push(`scripts/brand-allowlist.txt: unused entry (${a.check} | ${a.file} | ${a.text}): remove it`);

if (problems.length) {
  console.error(`check-brand: ${problems.length} problem(s) (brand/README.md; exceptions go in scripts/brand-allowlist.txt):`);
  for (const p of problems) console.error('  ' + p);
  process.exit(1);
}
console.log(`check-brand: ${SOURCES.length} source files and the help topics are on-brand`);
