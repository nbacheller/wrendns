// REQ: API-015 (T23.6, ADR-919) — the secrets head (its etag, sent as If-Match on a write) is shared by
// every secret field on the page. A write by one field moves the head; the others then reload, so a
// later write from a sibling field never sends a stale head (which would read as another admin's change).
export const secretsHead = $state<{ etag: string | undefined }>({ etag: undefined });
