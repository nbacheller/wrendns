// The e2e ports. Parallel worktrees each run their own suite, so the defaults can be
// moved per run with E2E_HTTP_PORT, E2E_DNS_PORT and E2E_MDNS_PORT (server.mjs reads the same).
export const HTTP_PORT = Number(process.env.E2E_HTTP_PORT ?? 18054);
export const DNS_PORT = Number(process.env.E2E_DNS_PORT ?? 15354);
export const MDNS_PORT = Number(process.env.E2E_MDNS_PORT ?? 15353);
export const BASE_URL = `http://127.0.0.1:${HTTP_PORT}`;
