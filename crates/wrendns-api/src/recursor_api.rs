// SPDX-License-Identifier: AGPL-3.0-or-later
//! REQ: DNS-904 (T40.3), FLT-013, AGT-001 — the lookup trace of the built-in recursive resolver:
//! `GET /api/v1/recursor/trace`. It really resolves the name through a `recursive://` upstream
//! (so it warms that upstream's caches, like any lookup) and returns the zone cut it started
//! from and every query it sent: the server, what came back and how long it took. The trace is
//! built only for this call; ordinary lookups don't build one.

use axum::Json;
use axum::extract::{Query, State};

use crate::Shared;
use crate::model::{RecursorTrace, RecursorTraceParams};
use crate::problem::Problem;

/// Trace a recursive lookup.
///
/// Resolves `name` through the built-in recursive resolver (`recursive://` upstream `upstream`,
/// else the first) and shows how it went: where the lookup began (`start`: the root, a stub zone
/// or a cached zone cut), then every query to every authoritative server with its zone, the name
/// asked (cut down by QNAME minimization), the outcome (`referral`, `answer`, `nodata`,
/// `nxdomain`, `lame`, `timeout`, `error`, `case-mismatch`), the delegation a referral points to,
/// the transport and the time. A name whose zone cuts are cached starts below the root; flush the
/// resolver's cuts (`POST /api/v1/cache/flush` with `recursor`) to see the whole walk. The lookup
/// is real: answers are not stored in the answer cache, but the resolver's zone cuts and server
/// timings are updated. Example: `GET /api/v1/recursor/trace?name=www.example.com`.
#[utoipa::path(get, path = "/api/v1/recursor/trace", tag = "queries", params(RecursorTraceParams),
    responses((status = 200, body = RecursorTrace, description = "The lookup and its steps."),
        (status = 400, body = Problem, description = "Not a domain name, an unknown type or upstream, or no `recursive://` upstream."),
        (status = 503, body = Problem, description = "Tracing isn't available on this node.")))]
pub(crate) async fn trace(
    State(b): State<Shared>,
    Query(p): Query<RecursorTraceParams>,
) -> Result<Json<RecursorTrace>, Problem> {
    b.recursor_trace(&p).await.map(Json)
}
