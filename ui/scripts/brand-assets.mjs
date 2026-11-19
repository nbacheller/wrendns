// Copies the logo files the UI serves from brand/logos/ (spec/10 T33.2). They are copied
// byte for byte: the logo is never redrawn, recoloured or retyped (brand/README.md).
//
//   node scripts/brand-assets.mjs           copies them into public/
//   node scripts/brand-assets.mjs --check   fails when a copy differs from brand/logos/ (npm run check)
import { copyFileSync, existsSync, mkdirSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const root = new URL('../', import.meta.url);
const logos = (n) => fileURLToPath(new URL(`../brand/logos/${n}`, root));
const pub = (n) => fileURLToPath(new URL(`public/${n}`, root));

// [file in brand/logos, where it goes in public/]
const FILES = [
  ['wrendns-lockup-day.svg', 'brand/wrendns-lockup-day.svg'],
  ['wrendns-lockup-night.svg', 'brand/wrendns-lockup-night.svg'],
  ['wrendns-mark-day.svg', 'brand/wrendns-mark-day.svg'],
  ['wrendns-mark-night.svg', 'brand/wrendns-mark-night.svg'],
  // the app icon is the favicon
  ['wrendns-app-icon.svg', 'favicon.svg'],
];

const check = process.argv.includes('--check');
let stale = 0;
for (const [src, dst] of FILES) {
  const same = existsSync(pub(dst)) && readFileSync(pub(dst)).equals(readFileSync(logos(src)));
  if (check) {
    if (!same) {
      console.error(`public/${dst} differs from brand/logos/${src}: run \`node scripts/brand-assets.mjs\``);
      stale++;
    }
  } else if (!same) {
    mkdirSync(fileURLToPath(new URL('public/brand/', root)), { recursive: true });
    copyFileSync(logos(src), pub(dst));
    console.log(`public/${dst}`);
  }
}
if (check) {
  if (stale) process.exit(1);
  console.log('the brand assets are up to date');
}
