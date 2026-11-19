// REQ: API-007, DSC-901 (T35.1, ADR-1032) - the UI prints every name and comment as text. Names are
// decoded once where they enter (the Pi-hole importer, the router readers), and a decoded `<` is
// only safe because nothing in ui/src renders text as markup. This guard fails if any file in
// ui/src uses {@html ...} or sets innerHTML / outerHTML / insertAdjacentHTML.
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';

const root = new URL('../src', import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1');
const files = [];
const walk = (dir) => {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) walk(p);
    else if (/\.(svelte|ts|js|mjs)$/.test(p)) files.push(p);
  }
};
walk(root);

const forbidden = [
  [/\{@html\b/, '{@html}'],
  [/(\.|\[['"])(innerHTML|outerHTML)(['"]\])?\s*\+?=/, 'innerHTML / outerHTML assignment'],
  [/document\.write(ln)?\s*\(/, 'document.write()'],
  [/createContextualFragment\s*\(/, 'createContextualFragment()'],
  [/srcdoc/, 'srcdoc'],
  [/\binsertAdjacentHTML\s*\(/, 'insertAdjacentHTML()'],
];
const bad = [];
for (const file of files) {
  const lines = readFileSync(file, 'utf8').split('\n');
  lines.forEach((text, i) => {
    for (const [re, what] of forbidden) {
      if (re.test(text)) bad.push(`${file}:${i + 1}: ${what}: ${text.trim()}`);
    }
  });
}
if (bad.length) {
  console.error('Markup from text is forbidden in ui/src (names are text; ADR-1032):');
  for (const b of bad) console.error('  ' + b);
  process.exit(1);
}
console.log(`check-no-html: ${files.length} source files clean`);
