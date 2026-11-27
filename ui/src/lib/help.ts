// REQ: API-011, ADR-036 — the help glossary (docs/help/topics.json), shared with the site and fetched on demand from the node.
// Every "?" in the UI names a topic id; `npm run check:help` (CI) proves each id exists and
// every topic not marked `general` is used somewhere.

/** Paths through the query flow a diagram can highlight. */
export type FlowPath = 'cache' | 'local' | 'blocked' | 'route' | 'upstream' | 'refused';

export interface Topic {
  id: string;
  title: string;
  term: string;
  summary: string;
  when: string;
  example: string;
  caution: string;
  /** REQ: OBS-010 (T27.1) — a list under the topic, one line each (`alert-conditions`). */
  items?: { name: string; line: string }[];
  diagram?: FlowPath;
  docs?: string;
  general?: boolean;
}

import { writable } from 'svelte/store';

/** The content hash of docs/help/topics.json, set at build time (vite.config.ts). */
declare const __HELP_VERSION__: string;

/** The loaded glossary, shared: one successful load (or retry) fills every "?" on the page. */
export const glossary = writable<Map<string, Topic> | undefined>(undefined);

let loaded: Promise<Map<string, Topic>> | undefined;

/**
 * The glossary, fetched once from the node when the first "?" mounts (ADR-1020 amendment: the
 * file is embedded in the server outside `ui/dist`, so it is not part of the size budget). A
 * failed fetch is not kept: the next call tries again.
 */
export function loadTopics(): Promise<Map<string, Topic>> {
  loaded ??= fetch(`/help/topics.json?v=${__HELP_VERSION__}`)
    .then((r) => {
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      return r.json();
    })
    .then((j: { topics: Topic[] }) => {
      const m = new Map(j.topics.map((t) => [t.id, t]));
      glossary.set(m);
      return m;
    })
    .catch((e) => {
      loaded = undefined;
      throw e;
    });
  return loaded;
}

/** The topic, or undefined while the glossary is not loaded or when the id is missing (the CI check keeps that from shipping). */
export function topic(all: Map<string, Topic> | undefined, id: string): Topic | undefined {
  return all?.get(id);
}

/** Where a topic's full documentation lives. */
export function docsUrl(t: Topic): string | undefined {
  return t.docs ? `https://github.com/nbacheller/wrendns/blob/main/docs/running.md#${t.docs}` : undefined;
}
