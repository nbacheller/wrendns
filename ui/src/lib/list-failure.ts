// REQ: T24.27 — what a list's download error means and what the Lists page offers for it.
// The server's error is text (`larger than the N-byte limit (the server says it is M bytes; ...)`,
// `HTTP 404 Not Found`); these helpers read it so the row can offer a fix instead of a bare string.

const MIB = 1024 * 1024;

/** The largest per-list limit the page offers to set: a list this big takes the compile past
 *  what the small-device RSS budgets leave (about 20 bytes a name when running, three times
 *  that while compiling), so above it the page suggests removing or replacing the list. */
export const LIST_LIMIT_CAP_BYTES = 128 * MIB;

export type ListFailure =
  | { kind: 'too_large'; limit: number; seen: number | null; suggestedMiB: number | null }
  | { kind: 'not_found'; status: number }
  | { kind: 'other' };

/** The per-list `max_bytes` to suggest, in whole MiB: the size the server announced plus a
 *  quarter, or double the limit when the size isn't known, never above the cap. `null` when
 *  nothing above the current limit fits under the cap. */
export function suggestLimitMiB(limit: number, seen: number | null): number | null {
  const want = seen !== null && seen > limit ? seen * 1.25 : limit * 2;
  const mib = Math.min(Math.ceil(want / MIB), LIST_LIMIT_CAP_BYTES / MIB);
  return mib * MIB > limit ? mib : null;
}

export function classifyListError(error: string | null | undefined): ListFailure | null {
  if (!error) return null;
  const big = /larger than the (\d+)-byte limit/.exec(error);
  if (big) {
    const limit = Number(big[1]);
    const said = /the server says it is (\d+) bytes/.exec(error);
    const seen = said ? Number(said[1]) : null;
    return { kind: 'too_large', limit, seen, suggestedMiB: suggestLimitMiB(limit, seen) };
  }
  const http = /\bHTTP (404|410)\b/.exec(error);
  if (http) return { kind: 'not_found', status: Number(http[1]) };
  return { kind: 'other' };
}
