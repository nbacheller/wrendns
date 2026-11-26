// REQ: API-005 (T35.8) — reports what the build would weigh under brotli, beside the gzip budget measure.
// Reads ui/dist after `npm run build` (inflating each `x.gz`), then sums every file under gzip level 9
// (the budget measure) and under brotli quality 11 (Node's built-in zlib; no dependency). A file that
// does not compress smaller is counted raw, as postbuild.mjs does. Read-only: it changes nothing.
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';
import { gunzipSync, gzipSync, brotliCompressSync, constants } from 'node:zlib';
import { fileURLToPath } from 'node:url';

const DIST = fileURLToPath(new URL('../dist/', import.meta.url));
const TEXT = /\.(html|js|css|svg|json|txt)$/;

function* walk(dir) {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) yield* walk(p);
    else yield p;
  }
}

const brotli = (buf) =>
  brotliCompressSync(buf, {
    params: {
      [constants.BROTLI_PARAM_QUALITY]: 11,
      [constants.BROTLI_PARAM_LGWIN]: 24,
      [constants.BROTLI_PARAM_SIZE_HINT]: buf.length,
    },
  }).length;

let gzTotal = 0;
let brTotal = 0;
const rows = [];
for (const file of walk(DIST)) {
  if (file.endsWith('.map')) continue;
  const stored = readFileSync(file);
  const isGz = file.endsWith('.gz');
  const name = relative(DIST, isGz ? file.slice(0, -3) : file);
  const raw = isGz ? gunzipSync(stored) : stored;
  let gz = raw.length;
  let br = raw.length;
  if (TEXT.test(name)) {
    gz = Math.min(raw.length, gzipSync(raw, { level: constants.Z_BEST_COMPRESSION }).length);
    br = Math.min(raw.length, brotli(raw));
  }
  gzTotal += gz;
  brTotal += br;
  rows.push([name, raw.length, gz, br]);
}
rows.sort((a, b) => b[2] - a[2]);
for (const [f, raw, gz, br] of rows) {
  console.log(`${f.padEnd(44)} ${String(raw).padStart(9)} raw ${String(gz).padStart(8)} gz ${String(br).padStart(8)} br`);
}
const kib = (n) => (n / 1024).toFixed(1);
console.log(`total gzip ${kib(gzTotal)} KiB, brotli ${kib(brTotal)} KiB, saving ${kib(gzTotal - brTotal)} KiB`);
