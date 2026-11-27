import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { defineConfig } from 'vite';
import { svelte } from '@sveltejs/vite-plugin-svelte';

// REQ: API-005 — built to ui/dist and embedded in the binary (ADR-009, ADR-030).
// `npm run dev` proxies the API to a local server (`wrendns run`, API on :8053).
const api = process.env.WRENDNS_API ?? 'http://127.0.0.1:8053';

// The glossary URL carries this content hash, so a cached copy from before an upgrade is never
// used with the new UI (the node still sends it with a one-hour max-age).
const helpVersion = createHash('sha256').update(readFileSync('../docs/help/topics.json')).digest('hex').slice(0, 12);

export default defineConfig({
  plugins: [svelte()],
  define: { __HELP_VERSION__: JSON.stringify(helpVersion) },
  base: '/',
  build: {
    outDir: 'dist',
    assetsDir: 'assets',
    target: 'es2022',
    sourcemap: false,
    modulePreload: { polyfill: false },
    // The binary serves these files under a strict CSP: never inline anything.
    assetsInlineLimit: 0,
  },
  server: {
    proxy: { '/api': api, '/metrics': api, '/help': api },
    // The help glossary lives in docs/help/ (shared with the site).
    fs: { allow: ['..'] },
  },
});
