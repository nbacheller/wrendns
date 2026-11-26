import { vitePreprocess } from '@sveltejs/vite-plugin-svelte';

// A scoped-style class is `s` and four characters of the style's hash, not `svelte-` and the
// full hash: the name is written on every element of a component and in every one of its
// selectors, so a shorter one saves bytes against the bundle budget (ADR-1020). Two different
// styles that meet at four characters get the longer hash, so a class never changes owner.
const seen = new Map();
const cssHash = ({ hash, css }) => {
  const full = hash(css);
  let short = full.slice(0, 4);
  if (seen.has(short) && seen.get(short) !== full) short = full;
  seen.set(short, full);
  return `s${short}`;
};

export default {
  preprocess: vitePreprocess(),
  compilerOptions: { cssHash },
};
