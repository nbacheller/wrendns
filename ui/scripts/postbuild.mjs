// Precompresses dist/ for the embedded server and enforces the bundle budget: ≤ 400 KiB gzipped
// in total (`spec/07` §3, API-005). A text file that gzip shrinks is kept only as `x.gz`: the
// binary embeds that, serves it to browsers that accept gzip, and inflates it for the rest
// (REQ: NFR-001, ADR-915), so the raw copy is removed. Binary files stay as they are.
import { readdirSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { join, relative } from 'node:path';
import { gzipSync, constants } from 'node:zlib';
import { fileURLToPath } from 'node:url';

const DIST = fileURLToPath(new URL('../dist/', import.meta.url));
const BUDGET = 400 * 1024;
const TEXT = /\.(html|js|css|svg|json|txt|map)$/;

function* walk(dir) {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) yield* walk(p);
    else yield p;
  }
}

let total = 0;
const rows = [];
for (const file of [...walk(DIST)]) {
  if (file.endsWith('.gz')) continue;
  const raw = readFileSync(file);
  let size = raw.length;
  if (TEXT.test(file)) {
    const gz = gzipSync(raw, { level: constants.Z_BEST_COMPRESSION });
    size = gz.length;
    if (gz.length < raw.length) {
      writeFileSync(`${file}.gz`, gz);
      rmSync(file);
    }
  }
  total += size;
  rows.push([relative(DIST, file), raw.length, size]);
}
rows.sort((a, b) => b[2] - a[2]);
for (const [f, raw, gz] of rows) {
  console.log(`${f.padEnd(40)} ${String(raw).padStart(9)} B  ${String(gz).padStart(8)} B gz`);
}
const kib = (n) => (n / 1024).toFixed(1);
console.log(`total ${kib(total)} KiB gzipped (budget ${kib(BUDGET)} KiB)`);
if (total > BUDGET) {
  console.error('error: the UI is over its size budget');
  process.exit(1);
}
