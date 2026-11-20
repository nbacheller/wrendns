// Generates src/brand.css from brand/tokens.json (spec/10 T33.2; the brand book is brand/README.md).
// Day (`light`, the default) is :root; Night (`dark`) follows `prefers-color-scheme` unless the
// viewer chose Day, and is forced by `data-theme="dark"` (the header's theme toggle sets it).
// Fonts are Figtree and IBM Plex Mono from @fontsource (SIL OFL), latin subset only.
//
//   node scripts/brand-css.mjs           writes src/brand.css
//   node scripts/brand-css.mjs --check   fails when src/brand.css is out of date (npm run check)
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const root = new URL('../', import.meta.url);
const tokens = JSON.parse(readFileSync(new URL('../brand/tokens.json', root), 'utf8'));
const out = fileURLToPath(new URL('src/brand.css', root));

const byName = new Map(tokens.color.tokens.map((t) => [t.name, t]));
function resolve(name, theme) {
  const v = byName.get(name).value[theme];
  const m = /^\{(.+)\}$/.exec(v);
  return m ? resolve(m[1], theme) : v;
}
const colorVars = (theme) => tokens.color.tokens.map((t) => `  --brand-${t.name}: ${resolve(t.name, theme)};`);

const type = [];
for (const g of tokens.type.groups) {
  for (const s of g.styles) {
    const fam = g.family === 'mono' ? 'var(--brand-font-mono)' : 'var(--brand-font-sans)';
    type.push(`  --type-${s.name}-font: ${fam};`);
    type.push(`  --type-${s.name}-size: ${s.fontSize};`);
    type.push(`  --type-${s.name}-line: ${s.lineHeight};`);
    type.push(`  --type-${s.name}-weight: ${s.fontWeight};`);
    if (s.letterSpacing) type.push(`  --type-${s.name}-tracking: ${s.letterSpacing};`);
  }
}
const space = tokens.spacing.tokens.map((t) => `  --${t.name}: ${t.value};`);
const radius = tokens.radius.tokens.map((t) => `  --${t.name}: ${t.value};`);
const shadow = (theme) => tokens.shadow.tokens.map((t) => `  --${t.name}: ${t.value[theme]};`);

// The files @fontsource ships, by the names tokens.json lists. latin only (the UI budget, ADR-1020).
const FONT_DIRS = {
  Figtree: '../node_modules/@fontsource-variable/figtree/files/',
  'IBM Plex Mono': '../node_modules/@fontsource/ibm-plex-mono/files/',
};
const faces = tokens.type.fonts.map((f) => {
  const file = f.file.replace(/^fonts\//, '');
  return `@font-face {
  font-family: '${f.family}';
  font-style: ${f.style};
  font-weight: ${f.weight};
  font-display: swap;
  src: url('${FONT_DIRS[f.family]}${file}') format('woff2');
}`;
});

// REQ: T33.6 — a select's chevron is an icon in `ink-muted`; a background image can't take a CSS
// variable, so each theme gets its own, drawn from the token here rather than hard-coded in app.css.
const chevron = (theme) =>
  `  --chevron: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='10' height='6' viewBox='0 0 10 6'%3E%3Cpath d='M1 1l4 4 4-4' fill='none' stroke='%23${resolve('ink-muted', theme).slice(1)}' stroke-width='1.75' stroke-linecap='round' stroke-linejoin='round'/%3E%3C/svg%3E");`;
const night = [...colorVars('dark'), ...shadow('dark'), chevron('dark'), '  color-scheme: dark;'];
const css = `/* Generated from brand/tokens.json by scripts/brand-css.mjs. Do not edit; run \`node scripts/brand-css.mjs\`. */
${faces.join('\n')}

/* Day (the default). */
:root {
${colorVars('light').join('\n')}
${shadow('light').join('\n')}
${chevron('light')}
  --brand-font-sans: ${tokens.type.families.sans};
  --brand-font-mono: ${tokens.type.families.mono};
${type.join('\n')}
${space.join('\n')}
${radius.join('\n')}
  color-scheme: light;
}

/* Night: the system's choice, unless the viewer picked Day. */
@media (prefers-color-scheme: dark) {
  :root:not([data-theme='light']) {
${night.map((l) => '  ' + l).join('\n')}
  }
}

/* Night: the viewer's choice. */
:root[data-theme='dark'] {
${night.join('\n')}
}
`;

if (process.argv.includes('--check')) {
  if (!existsSync(out) || readFileSync(out, 'utf8') !== css) {
    console.error('src/brand.css is out of date: run `node scripts/brand-css.mjs` (it is generated from brand/tokens.json)');
    process.exit(1);
  }
  console.log('src/brand.css is up to date');
} else {
  writeFileSync(out, css);
  console.log('wrote src/brand.css');
}
