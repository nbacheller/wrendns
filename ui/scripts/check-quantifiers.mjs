// REQ: UI-AUTH (upstream #64) - Svelte 5 parses a bare {n} inside a quoted
// attribute value as an expression, so pattern="[0-9]{6}" reaches the browser
// as "[0-9]6". This guard fails if any quoted attribute (double or single
// quoted, on one line or split across lines) in ui/src contains a regex
// quantifier in braces. Use pattern={"[0-9]{6}"} instead.
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';

const root = new URL('../src', import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1');
const files = [];
const walk = (dir) => {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) walk(p);
    else if (p.endsWith('.svelte')) files.push(p);
  }
};
walk(root);

// name="..." or name='...' matched against the whole file, so values that span lines are caught.
const attr = /\s[\w:-]+=(?:"([^"]*)"|'([^']*)')/g;
const quant = /\{\d+(,\d*)?\}/;
const bad = [];
for (const file of files) {
  const text = readFileSync(file, 'utf8');
  let m;
  attr.lastIndex = 0;
  while ((m = attr.exec(text))) {
    const value = m[1] ?? m[2];
    if (quant.test(value)) {
      const line = text.slice(0, m.index).split('\n').length;
      bad.push(`${file}:${line}: ${m[0].trim().replace(/\s+/g, ' ')}`);
    }
  }
}
if (bad.length) {
  console.error('Quantifier swallowed by Svelte attribute parsing (use {"..."}):');
  for (const b of bad) console.error('  ' + b);
  process.exit(1);
}
console.log(`check-quantifiers: ${files.length} svelte files clean`);
