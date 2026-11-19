// Precompresses dist/ for the embedded server and enforces the bundle budget: ≤ 512 KiB gzipped
// in total (`spec/07` §3, API-005; ADR-1020 raised it from 400 KiB). A text file is replaced by
// its `x.gz` (when that is smaller): the binary embeds what dist/ holds, so a raw copy beside its `.gz` cost about the file's gzip
// size again in the image (NFR-001, ADR-168). The server sends the `.gz` to a browser that accepts
// gzip, and inflates it for any other client.
import { readdirSync, readFileSync, statSync, unlinkSync, writeFileSync } from 'node:fs';
import { join, relative } from 'node:path';
import { gzipSync, constants } from 'node:zlib';
import { fileURLToPath } from 'node:url';

const DIST = fileURLToPath(new URL('../dist/', import.meta.url));
const BUDGET = 512 * 1024;
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
      unlinkSync(file);
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
