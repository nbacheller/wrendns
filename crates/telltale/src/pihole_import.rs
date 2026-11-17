//! REQ: API-007 (T24.18, ADR-939, ADR-940, ADR-941) — importing a Pi-hole export from the admin
//! page. An upload is converted by a short-lived worker process (`telltale pihole-import-worker`,
//! an empty environment, no access to the state database). The conversion becomes a plan: what
//! would be added, changed or skipped, and, with `compare`, a sample resolved through both
//! servers. Applying the plan writes its entries in one configuration change. Plans live in this
//! node's memory for ten minutes, like agent plans (AGT-007).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use serde::Deserialize;
use serde_json::{Value, json};
use telltale_api::problem::{Code, Problem};
use telltale_api::{ManagedKind, PiholeImportRequest};
use telltale_config::{Config, Loader, RateLimitConfig, SpecialConfig};

use crate::http::Sources;
use crate::managed::{self, Entries, Forward, Ovr, RecordValue};
use crate::pihole;
use crate::pihole::compare;
use crate::settings_kinds;

/// Most bytes an upload may have (the API refuses a larger body first).
pub(crate) const UPLOAD_LIMIT: usize = 64 << 20;
/// How long the worker may take.
const WORKER_TIMEOUT: Duration = Duration::from_secs(60);
/// Most bytes the worker may print.
const WORKER_OUTPUT_LIMIT: usize = 64 << 20;
/// How long a plan can be applied.
const PLAN_TTL: u64 = 600;
/// Most plans kept at once; the oldest goes first.
const MAX_PLANS: usize = 8;
/// Most items listed in a preview (the counts cover all of them).
const MAX_ITEMS: usize = 1000;

/// The worker's answer: the conversion, or why there isn't one.
#[derive(Debug, Deserialize)]
pub(crate) struct Wire {
    pub(crate) ok: bool,
    #[serde(default)]
    pub(crate) error: Option<String>,
    #[serde(default)]
    pub(crate) toml: String,
    #[serde(default)]
    pub(crate) version: String,
    #[serde(default)]
    pub(crate) notes: Vec<String>,
    #[serde(default)]
    pub(crate) counts: String,
    #[serde(default)]
    pub(crate) samples: Vec<String>,
}

/// One thing the import would do, for the preview.
#[derive(Debug, Clone)]
pub(crate) struct Item {
    pub(crate) kind: &'static str,
    pub(crate) name: String,
    /// `add`, `change` (replaces an entry of that name), or `skip` (it wouldn't be imported).
    pub(crate) action: &'static str,
    pub(crate) reason: String,
}

/// One stored entry the apply writes: its kind, name, and body (as the store keeps it).
#[derive(Debug, Clone)]
pub(crate) struct Write {
    pub(crate) kind: &'static str,
    pub(crate) name: String,
    pub(crate) body: String,
}

/// A preview kept for applying (REQ: API-007, ADR-940).
#[derive(Debug, Clone)]
pub(crate) struct Plan {
    pub(crate) id: String,
    pub(crate) expires: u64,
    pub(crate) config_version: u64,
    pub(crate) source: String,
    pub(crate) counts: String,
    pub(crate) notes: Vec<String>,
    pub(crate) items: Vec<Item>,
    pub(crate) writes: Vec<Write>,
    pub(crate) compare: Option<Value>,
    pub(crate) samples: usize,
}

static PLANS: Mutex<Vec<Plan>> = Mutex::new(Vec::new());
static COUNTER: AtomicU64 = AtomicU64::new(0);

fn plans() -> MutexGuard<'static, Vec<Plan>> {
    PLANS.lock().unwrap_or_else(PoisonError::into_inner)
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Keeps `plan`, dropping expired plans and the oldest beyond [`MAX_PLANS`].
fn keep(plan: Plan, now: u64) {
    let mut m = plans();
    m.retain(|p| p.expires > now);
    while m.len() >= MAX_PLANS {
        m.remove(0);
    }
    m.push(plan);
}

fn take(id: &str, now: u64) -> Option<Plan> {
    let m = plans();
    m.iter().find(|p| p.id == id && p.expires > now).cloned()
}

fn forget(id: &str) {
    plans().retain(|p| p.id != id);
}

/// REQ: API-007 — a plan's ID: unguessable enough for a single admin's session.
fn new_id(now: u64) -> String {
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let pid = u64::from(std::process::id());
    let h = blake3::hash(format!("{now}:{pid}:{n}").as_bytes());
    h.to_hex().as_str()[..32].to_owned()
}

/// The upload, as a private temporary file the worker reads; removed when dropped.
struct Upload(PathBuf);

impl Upload {
    fn write(data: &[u8]) -> Result<Self, Problem> {
        use std::io::Write as _;
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let p = std::env::temp_dir().join(format!(
            "telltale-pihole-{}-{}-{n}.upload",
            std::process::id(),
            now()
        ));
        let mut o = std::fs::OpenOptions::new();
        o.write(true).create_new(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut o, 0o600);
        let up = Self(p);
        o.open(&up.0)
            .and_then(|mut f| f.write_all(data))
            .map_err(|e| Problem::internal(format!("can't store the upload: {e}")))?;
        Ok(up)
    }
}

impl Drop for Upload {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// `telltale pihole-import-worker PATH`: converts the file and prints one JSON object. Exits 0
/// whenever it could print its answer (the answer says whether the conversion worked).
pub(crate) fn run_worker(path: &Path) -> std::process::ExitCode {
    use std::io::Write as _;
    let out = match pihole::Source::load(path)
        .and_then(|src| pihole::convert(&src, "the uploaded export"))
    {
        Ok(im) => json!({
            "ok": true,
            "toml": im.toml,
            "version": im.version,
            "notes": im.notes,
            "counts": im.counts,
            "samples": im.samples,
        }),
        Err(e) => json!({ "ok": false, "error": e }),
    };
    let _ = writeln!(std::io::stdout().lock(), "{out}");
    std::process::ExitCode::SUCCESS
}

/// Runs the worker on `path` in a child process with an empty environment, under a timeout and
/// an output limit (ADR-939).
async fn run_worker_process(path: &Path) -> Result<Wire, Problem> {
    let exe = std::env::current_exe().map_err(|e| {
        Problem::internal(format!("can't find this program to run the import: {e}"))
    })?;
    let child = tokio::process::Command::new(exe)
        .arg("pihole-import-worker")
        .arg(path)
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| Problem::internal(format!("the import worker didn't start: {e}")))?;
    let out = tokio::time::timeout(WORKER_TIMEOUT, child.wait_with_output())
        .await
        .map_err(|_| {
            Problem::new(
                Code::InvalidConfig,
                "the import took longer than a minute; the file is too large or damaged",
            )
        })?
        .map_err(|e| Problem::internal(format!("the import worker failed: {e}")))?;
    if out.stdout.len() > WORKER_OUTPUT_LIMIT {
        return Err(Problem::new(
            Code::InvalidConfig,
            "the import's conversion is too large to show",
        ));
    }
    let wire: Wire = serde_json::from_slice(&out.stdout).map_err(|_| {
        Problem::new(
            Code::InvalidConfig,
            "the import worker stopped without an answer (the file is damaged or too large)",
        )
    })?;
    if !wire.ok {
        return Err(Problem::new(
            Code::InvalidConfig,
            format!(
                "this isn't a Pi-hole export the import can read: {}",
                wire.error.unwrap_or_default()
            ),
        ));
    }
    Ok(wire)
}

fn lower(s: &str) -> String {
    s.to_ascii_lowercase()
}

/// Upstreams and upstream groups the conversion makes for a conditional forward: the routes
/// become forward entries instead (`match_suffix` plus the servers), so these aren't written.
fn route_only(name: &str) -> bool {
    name.starts_with("pihole-forward-")
}

fn json_of<T: serde::Serialize>(v: &T) -> Result<String, Problem> {
    serde_json::to_string(v).map_err(|e| Problem::internal(format!("can't store an entry: {e}")))
}

/// The item for an entry the import would write: a change when an entry of that name exists.
#[allow(clippy::too_many_arguments)] // one call per kind of entry
fn write_item(
    items: &mut Vec<Item>,
    writes: &mut Vec<Write>,
    kind: &'static str,
    managed_kind: &'static str,
    name: &str,
    exists: bool,
    in_files: bool,
    body: String,
) {
    let reason = if in_files {
        "replaces the config file's entry of that name (the file's is back when this is deleted)"
            .to_owned()
    } else if exists {
        "replaces an entry of that name made earlier".to_owned()
    } else {
        String::new()
    };
    items.push(Item {
        kind,
        name: name.to_owned(),
        action: if exists { "change" } else { "add" },
        reason,
    });
    writes.push(Write {
        kind: managed_kind,
        name: name.to_owned(),
        body,
    });
}

/// Turns a worker's conversion into a plan: the items, the writes, and the checks that the
/// result would load (ADR-940). Nothing is stored.
// One block per kind of entry, then the checks that the result loads.
#[allow(clippy::too_many_lines)]
pub(crate) fn build(
    file: &Config,
    state: &telltale_store::state::State,
    wire: Wire,
    compare: Option<Value>,
    at: u64,
) -> Result<Plan, Problem> {
    let cfg = Loader::new()
        .toml_str("import", wire.toml.clone())
        .load()
        .map_err(|errs| {
            Problem::new(
                Code::InvalidConfig,
                errs.iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join("; "),
            )
        })?
        .config;
    let stored = managed::entries(state);
    let current = managed::merge(file, &stored)
        .map_err(|errs| Problem::new(Code::InvalidConfig, errs.join("; ")))?;
    let mut items = Vec::new();
    let mut writes = Vec::new();

    for u in cfg.upstream.iter().filter(|u| !route_only(u.name.as_str())) {
        let name = u.name.as_str();
        let exists = current.upstream.iter().any(|x| x.name.as_str() == name);
        let in_files = file.upstream.iter().any(|x| x.name.as_str() == name);
        write_item(
            &mut items,
            &mut writes,
            "upstream",
            managed::UPSTREAM,
            name,
            exists,
            in_files,
            json_of(u)?,
        );
    }
    for g in cfg
        .upstream_group
        .iter()
        .filter(|g| !route_only(g.name.as_str()))
    {
        let name = g.name.as_str();
        let cur = current
            .upstream_group
            .iter()
            .find(|x| x.name.as_str() == name);
        // The default group keeps its own strategy: Pi-hole's upstreams join its members.
        let merged = match cur {
            Some(c) if name == "default" => {
                let mut m = c.clone();
                for member in &g.members {
                    if !m.members.iter().any(|x| x.as_str() == member.as_str()) {
                        m.members.push(member.clone());
                    }
                }
                m
            }
            _ => g.clone(),
        };
        let in_files = file.upstream_group.iter().any(|x| x.name.as_str() == name);
        write_item(
            &mut items,
            &mut writes,
            "upstream group",
            managed::UPSTREAM_GROUP,
            name,
            cur.is_some(),
            in_files,
            json_of(&merged)?,
        );
        if name == "default" {
            set_reason(
                &mut items,
                "adds Pi-hole's upstreams to the default group; its strategy stays",
            );
        }
    }
    for l in &cfg.list {
        let name = l.name.as_str();
        let exists = current.list.iter().any(|x| x.name.as_str() == name);
        let in_files = file.list.iter().any(|x| x.name.as_str() == name);
        write_item(
            &mut items,
            &mut writes,
            "list",
            managed::LIST,
            name,
            exists,
            in_files,
            json_of(l)?,
        );
    }
    for g in &cfg.group {
        let name = g.name.as_str();
        let cur = current.group.iter().find(|x| x.name.as_str() == name);
        // The default group keeps its own settings: Pi-hole's lists join its list. Omitted
        // lists mean every list already, so they stay omitted.
        let merged = match cur {
            Some(c) if name == "default" => {
                let mut m = c.clone();
                if let (Some(mine), Some(theirs)) = (m.lists.as_mut(), g.lists.as_ref()) {
                    for l in theirs {
                        if !mine.iter().any(|x| x.as_str() == l.as_str()) {
                            mine.push(l.clone());
                        }
                    }
                }
                m
            }
            _ => g.clone(),
        };
        let in_files = file.group.iter().any(|x| x.name.as_str() == name);
        write_item(
            &mut items,
            &mut writes,
            "group",
            managed::GROUP,
            name,
            cur.is_some(),
            in_files,
            json_of(&merged)?,
        );
        if name == "default" {
            set_reason(
                &mut items,
                "adds Pi-hole's lists to the default group; its other settings stay",
            );
        }
    }
    for c in &cfg.client {
        let name = c.name.as_str();
        let exists = current.client.iter().any(|x| x.name.as_str() == name);
        let in_files = file.client.iter().any(|x| x.name.as_str() == name);
        write_item(
            &mut items,
            &mut writes,
            "device",
            managed::CLIENT,
            name,
            exists,
            in_files,
            json_of(c)?,
        );
    }

    // Local names: the file's own names are read-only through the API (ADR-040), so the
    // import leaves them out.
    let mut by_name: BTreeMap<String, Vec<RecordValue>> = BTreeMap::new();
    for r in &cfg.record {
        by_name
            .entry(lower(r.name.as_str()))
            .or_default()
            .push(RecordValue {
                rtype: r.rtype.as_str().to_owned(),
                value: r.value.as_str().to_owned(),
                ttl: r.ttl,
            });
    }
    for (name, recs) in by_name {
        if file
            .record
            .iter()
            .any(|r| r.name.as_str().eq_ignore_ascii_case(&name))
        {
            items.push(skip("record", &name, "the config files define this name"));
            continue;
        }
        let exists = stored.records.iter().any(|(n, _)| *n == name);
        write_item(
            &mut items,
            &mut writes,
            "record",
            managed::RECORD,
            &name,
            exists,
            false,
            json_of(&recs)?,
        );
    }

    // Conditional forwards: each route's suffixes, sent to the servers of its group.
    for route in &cfg.route {
        let servers: Vec<String> = cfg
            .upstream_group
            .iter()
            .find(|g| g.name.as_str() == route.upstream_group.as_str())
            .into_iter()
            .flat_map(|g| g.members.iter())
            .filter_map(|m| {
                cfg.upstream
                    .iter()
                    .find(|u| u.name.as_str() == m.as_str())
                    .map(|u| u.url.as_str().to_owned())
            })
            .collect();
        for suffix in &route.match_suffix {
            let name = lower(suffix.as_str());
            if file.route.iter().any(|r| {
                r.match_suffix
                    .iter()
                    .any(|s| s.as_str().eq_ignore_ascii_case(&name))
            }) {
                items.push(skip(
                    "forward",
                    &name,
                    "the config files forward this domain",
                ));
                continue;
            }
            let exists = stored.forwards.iter().any(|(n, _)| *n == name);
            let f = Forward {
                servers: servers.clone(),
                stub: false,
            };
            write_item(
                &mut items,
                &mut writes,
                "forward",
                managed::FORWARD,
                &name,
                exists,
                false,
                json_of(&f)?,
            );
        }
    }

    if cfg.ratelimit != RateLimitConfig::default() {
        write_item(
            &mut items,
            &mut writes,
            "rate limit",
            managed::RATELIMIT,
            "default",
            stored.ratelimit.is_some(),
            false,
            json_of(&cfg.ratelimit)?,
        );
    }
    if cfg.special != SpecialConfig::default() {
        let kind = ManagedKind::Special;
        let section = settings_kinds::section_json(kind, &cfg);
        let file_section = settings_kinds::section_json(kind, file);
        let body = settings_kinds::prepare(kind, &section, &file_section, file)?;
        write_item(
            &mut items,
            &mut writes,
            "special names",
            managed::SPECIAL,
            "default",
            stored.special.is_some(),
            false,
            body.to_string(),
        );
    }
    if cfg.dnssec != file.dnssec {
        items.push(skip(
            "dnssec",
            "dnssec",
            "DNSSEC mode is set in the config file, not through the API: add `[dnssec] mode = \"validate\"` there",
        ));
    }

    // The writes must leave a configuration that loads (the same check the API's writes make).
    let mut candidate = managed::entries(state);
    for w in &writes {
        overlay(&mut candidate, w)?;
    }
    let merged = managed::merge(file, &candidate)
        .map_err(|errs| Problem::new(Code::InvalidConfig, errs.join("; ")))?;
    let mut notes = wire.notes;
    if let Ok(warnings) = telltale_config::validate_config(&merged) {
        notes.extend(warnings.into_iter().map(|w| format!("warning: {w}")));
    }
    Ok(Plan {
        id: new_id(at),
        expires: at + PLAN_TTL,
        config_version: state
            .config_version()
            .map_err(|e| Problem::internal(e.to_string()))?,
        source: wire.version,
        counts: wire.counts,
        notes,
        items,
        writes,
        compare,
        samples: wire.samples.len(),
    })
}

/// Gives the item just added its reason (the default groups' merges say what they keep).
fn set_reason(items: &mut [Item], reason: &str) {
    if let Some(i) = items.last_mut() {
        reason.clone_into(&mut i.reason);
    }
}

fn skip(kind: &'static str, name: &str, reason: &str) -> Item {
    Item {
        kind,
        name: name.to_owned(),
        action: "skip",
        reason: reason.to_owned(),
    }
}

/// Puts one stored write into `e`, decoded as the store's reader decodes it.
fn overlay(e: &mut Entries, w: &Write) -> Result<(), Problem> {
    let bad =
        |err: serde_json::Error| Problem::new(Code::InvalidConfig, format!("`{}`: {err}", w.name));
    match w.kind {
        managed::UPSTREAM => {
            let v = serde_json::from_str(&w.body).map_err(bad)?;
            e.upstreams.retain(|(n, _)| *n != w.name);
            e.upstreams.push((w.name.clone(), Ovr::Set(v)));
        }
        managed::UPSTREAM_GROUP => {
            let v = serde_json::from_str(&w.body).map_err(bad)?;
            e.upstream_groups.retain(|(n, _)| *n != w.name);
            e.upstream_groups.push((w.name.clone(), Ovr::Set(v)));
        }
        managed::LIST => {
            let v = serde_json::from_str(&w.body).map_err(bad)?;
            e.lists.retain(|(n, _)| *n != w.name);
            e.lists.push((w.name.clone(), Ovr::Set(v)));
        }
        managed::GROUP => {
            let v = serde_json::from_str(&w.body).map_err(bad)?;
            e.groups.retain(|(n, _)| *n != w.name);
            e.groups.push((w.name.clone(), Ovr::Set(v)));
        }
        managed::CLIENT => {
            let v: telltale_config::ClientConfig = serde_json::from_str(&w.body).map_err(bad)?;
            e.clients.retain(|c| c.name.as_str() != w.name);
            e.clients.push(v);
        }
        managed::RECORD => {
            let v = serde_json::from_str(&w.body).map_err(bad)?;
            e.records.retain(|(n, _)| *n != w.name);
            e.records.push((w.name.clone(), v));
        }
        managed::FORWARD => {
            let v = serde_json::from_str(&w.body).map_err(bad)?;
            e.forwards.retain(|(n, _)| *n != w.name);
            e.forwards.push((w.name.clone(), v));
        }
        managed::RATELIMIT => {
            e.ratelimit = Some(serde_json::from_str(&w.body).map_err(bad)?);
        }
        managed::SPECIAL => {
            e.special = Some(serde_json::from_str(&w.body).map_err(bad)?);
        }
        other => {
            return Err(Problem::internal(format!(
                "the import can't write a `{other}` entry"
            )));
        }
    }
    Ok(())
}

/// The preview as the API answers it. Items are capped; the counts cover all of them.
pub(crate) fn preview_json(p: &Plan) -> Value {
    let (mut add, mut change, mut skip) = (0usize, 0usize, 0usize);
    for i in &p.items {
        match i.action {
            "add" => add += 1,
            "change" => change += 1,
            _ => skip += 1,
        }
    }
    let items: Vec<Value> = p
        .items
        .iter()
        .take(MAX_ITEMS)
        .map(|i| json!({ "kind": i.kind, "name": i.name, "action": i.action, "reason": i.reason }))
        .collect();
    json!({
        "planId": p.id,
        "expiresUnixSeconds": p.expires,
        "configVersion": p.config_version,
        "source": p.source,
        "counts": p.counts,
        "summary": { "add": add, "change": change, "skip": skip, "samples": p.samples },
        "items": items,
        "itemsTotal": p.items.len(),
        "notes": p.notes,
        "compare": p.compare,
    })
}

/// The upload's preview (REQ: API-007, T24.18): changes nothing. With `compare`, resolves the
/// sample through the Pi-hole and TelltaleDNS (ADR-941).
pub(crate) async fn preview(src: Arc<Sources>, req: PiholeImportRequest) -> Result<Value, Problem> {
    if req.data.len() > UPLOAD_LIMIT {
        return Err(Problem::new(
            Code::InvalidConfig,
            "the upload is larger than 64 MiB",
        ));
    }
    let servers = match req.compare.as_deref() {
        Some(p) => {
            let pihole = compare::parse_server(p).map_err(Problem::invalid)?;
            let ours = compare::parse_server(req.telltale.as_deref().unwrap_or("127.0.0.1:53"))
                .map_err(Problem::invalid)?;
            Some((pihole, ours))
        }
        None => None,
    };
    let upload = Upload::write(&req.data)?;
    let wire = run_worker_process(&upload.0).await?;
    drop(upload);
    let mut names = wire.samples.clone();
    names.extend(req.samples.iter().cloned());
    let compare_json = match servers {
        Some((p, t)) => {
            let rep = tokio::task::spawn_blocking(move || compare::compare(p, t, &names))
                .await
                .map_err(|e| Problem::internal(format!("the comparison failed: {e}")))?;
            Some(serde_json::to_value(rep).map_err(|e| Problem::internal(e.to_string()))?)
        }
        None => None,
    };
    let state = src
        .auth
        .get()
        .map(|a| Arc::clone(a.state()))
        .ok_or_else(|| Problem::unavailable("the state database isn't open yet"))?;
    let file = src.file_config.load_full();
    let at = now();
    let plan = build(&file, &state, wire, compare_json, at)?;
    let out = preview_json(&plan);
    keep(plan, at);
    Ok(out)
}

/// Discards a plan (REQ: API-007). Unknown IDs are a 404.
pub(crate) fn discard(id: &str) -> Result<Value, Problem> {
    if take(id, now()).is_none() {
        return Err(Problem::not_found(
            "no import plan by that ID (it expired, or was applied or discarded)",
        ));
    }
    forget(id);
    Ok(json!({ "discarded": true }))
}

/// The write of a plan, checked and stored as one change (REQ: API-007, ADR-940): the
/// configuration must still be the one the preview saw, and must load with the plan's entries.
/// Returns the new configuration version.
pub(crate) fn commit(
    state: &telltale_store::state::State,
    file: &Config,
    plan: &Plan,
    by: &str,
    at: u64,
) -> Result<u64, Problem> {
    let current = state
        .config_version()
        .map_err(|e| Problem::internal(e.to_string()))?;
    if current != plan.config_version {
        return Err(Problem::new(
            Code::Conflict,
            "the configuration changed since the preview: preview the import again",
        ));
    }
    let mut entries = managed::entries(state);
    for w in &plan.writes {
        overlay(&mut entries, w)?;
    }
    managed::merge(file, &entries)
        .map_err(|errs| Problem::new(Code::InvalidConfig, errs.join("; ")))?;
    let rows: Vec<(&str, &str, &str)> = plan
        .writes
        .iter()
        .map(|w| (w.kind, w.name.as_str(), w.body.as_str()))
        .collect();
    state
        .put_managed_batch(&rows, Some(plan.config_version), at, by)
        .map_err(|e| match e {
            telltale_store::state::ManagedError::VersionConflict { .. } => Problem::new(
                Code::Conflict,
                "the configuration changed since the preview: preview the import again",
            ),
            other => Problem::internal(other.to_string()),
        })
}

/// Applies a plan as one configuration change (REQ: API-007, ADR-940), then reloads the node.
pub(crate) async fn apply(src: Arc<Sources>, id: String, by: String) -> Result<Value, Problem> {
    let at = now();
    let plan = take(&id, at).ok_or_else(|| {
        Problem::not_found(
            "no import plan by that ID (it expired, or was applied or discarded): preview the import again",
        )
    })?;
    let one_at_a_time = src.config_writes.lock().await;
    let state = src
        .auth
        .get()
        .map(|a| Arc::clone(a.state()))
        .ok_or_else(|| Problem::unavailable("the state database isn't open yet"))?;
    let file = src.file_config.load_full();
    let version = {
        let state = Arc::clone(&state);
        let file = Arc::clone(&file);
        let by = by.clone();
        let plan = plan.clone();
        tokio::task::spawn_blocking(move || commit(&state, &file, &plan, &by, now()))
            .await
            .map_err(|e| Problem::internal(format!("request worker failed: {e}")))??
    };
    crate::api_backend::provenance(&by, version);
    let (tx, rx) = tokio::sync::oneshot::channel();
    let applied = src.reload.send(tx).await.is_ok() && rx.await.unwrap_or(false);
    if !applied {
        return Err(Problem::internal(
            "the change was saved but couldn't be applied; the server log says why",
        ));
    }
    forget(&id);
    drop(one_at_a_time);
    let (mut added, mut changed, mut skipped) = (0usize, 0usize, 0usize);
    for i in &plan.items {
        match i.action {
            "add" => added += 1,
            "change" => changed += 1,
            _ => skipped += 1,
        }
    }
    Ok(json!({
        "applied": true,
        "configVersion": version,
        "added": added,
        "changed": changed,
        "skipped": skipped,
        "entries": plan.writes.len(),
        "counts": plan.counts,
        "source": plan.source,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A conversion of a small v5 export: one upstream, one local name, one group.
    fn wire() -> Wire {
        let mut e = crate::archive::Entries::new();
        e.insert("setupVars.conf".into(), b"PIHOLE_DNS_1=9.9.9.9\n".to_vec());
        e.insert("custom.list".into(), b"192.168.1.10 nas.lan\n".to_vec());
        let src = pihole::Source::from_entries(e).unwrap();
        let im = pihole::convert(&src, "test.tar.gz").unwrap();
        Wire {
            ok: true,
            error: None,
            toml: im.toml,
            version: im.version.to_owned(),
            notes: im.notes,
            counts: im.counts,
            samples: im.samples,
        }
    }

    fn file(toml: &str) -> Config {
        Loader::new().toml_str("file", toml).load().unwrap().config
    }

    // REQ: API-007 (T24.18) — a preview lists what would change, and writes nothing.
    #[test]
    fn api_007_pihole_import_preview_changes_nothing() {
        let state = telltale_store::state::State::in_memory().unwrap();
        let plan = build(&file(""), &state, wire(), None, 1_000).unwrap();
        assert_eq!(state.config_version().unwrap(), 0);
        assert_eq!(managed::entries(&state).upstreams.len(), 0);
        let has = |kind: &str, name: &str, action: &str| {
            plan.items
                .iter()
                .any(|i| i.kind == kind && i.name == name && i.action == action)
        };
        assert!(has("upstream", "pihole-1", "add"), "{:?}", plan.items);
        assert!(has("record", "nas.lan", "add"), "{:?}", plan.items);
        let v = preview_json(&plan);
        let adds = plan.items.iter().filter(|i| i.action == "add").count();
        assert_eq!(v["summary"]["add"], json!(adds));
    }

    // REQ: API-007 (T24.18, ADR-940) — applying the plan writes its entries in one change, and
    // the plan can't be applied twice (the second is stale).
    #[test]
    fn api_007_pihole_import_applies_as_plan() {
        let state = telltale_store::state::State::in_memory().unwrap();
        let f = file("");
        let plan = build(&f, &state, wire(), None, 1_000).unwrap();
        let version = commit(&state, &f, &plan, "admin", 1_000).unwrap();
        assert_eq!(version, 1, "one change, one version");
        let stored = managed::entries(&state);
        assert!(stored.upstreams.iter().any(|(n, _)| n == "pihole-1"));
        assert!(stored.records.iter().any(|(n, _)| n == "nas.lan"));
        let merged = managed::merge(&f, &stored).unwrap();
        assert!(
            merged
                .upstream
                .iter()
                .any(|u| u.name.as_str() == "pihole-1")
        );
        // The same plan again: the configuration moved on, so it's refused.
        let again = commit(&state, &f, &plan, "admin", 1_001).unwrap_err();
        assert_eq!(again.code_status(), axum::http::StatusCode::CONFLICT);
    }

    // REQ: API-007 (T24.18) — a name the config files define is skipped, not written.
    #[test]
    fn api_007_pihole_import_skips_names_the_files_define() {
        let state = telltale_store::state::State::in_memory().unwrap();
        let f = file("[[record]]\nname = \"nas.lan\"\ntype = \"A\"\nvalue = \"10.0.0.2\"\n");
        let plan = build(&f, &state, wire(), None, 1_000).unwrap();
        assert!(
            plan.items
                .iter()
                .any(|i| i.kind == "record" && i.name == "nas.lan" && i.action == "skip"),
            "{:?}",
            plan.items
        );
        assert!(
            !plan
                .writes
                .iter()
                .any(|w| w.kind == managed::RECORD && w.name == "nas.lan")
        );
    }

    // REQ: API-007 (T24.18) — a malformed archive or gravity.db is refused with an error, not a
    // panic (the worker's answer says so, and DNS isn't involved).
    #[test]
    fn api_007_pihole_import_worker_limits() {
        let dir = tempfile::tempdir().unwrap();
        let zip = dir.path().join("bad.zip");
        std::fs::write(&zip, b"PK\x03\x04 not really a zip at all").unwrap();
        assert!(pihole::Source::load(&zip).is_err());
        let db = dir.path().join("bad.db");
        let mut junk = b"SQLite format 3\0".to_vec();
        junk.extend_from_slice(&[7u8; 64]);
        std::fs::write(&db, junk).unwrap();
        assert!(pihole::Source::load(&db).is_err());
        let text = dir.path().join("notes.txt");
        std::fs::write(&text, b"hello").unwrap();
        assert!(pihole::Source::load(&text).is_err());
    }
}
