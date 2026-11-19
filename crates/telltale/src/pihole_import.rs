//! REQ: API-007 (T24.18, ADR-939, ADR-940, ADR-941) — importing a Pi-hole export from the admin
//! page. An upload is converted by a short-lived worker process (`telltale pihole-import-worker`,
//! hardened like a discovery worker, with an empty environment and no access to the state
//! database). The conversion becomes a plan: what would be added, changed or skipped, and, with
//! `compare`, a sample resolved through both servers. Applying the plan writes its entries in one
//! configuration change. Plans live in this node's memory for ten minutes, like agent plans
//! (AGT-007), and belong to the admin who made them.

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
use tokio::io::AsyncReadExt as _;
use tokio::sync::Semaphore;

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
/// The worker's `RLIMIT_DATA` (ADR-939): an archive's unpacked size is capped at 256 MiB by the
/// reader, and the rest of the conversion is small.
const WORKER_MEMORY: u64 = 1024 << 20;
/// How many previews are read at once: each holds an upload and a worker (ADR-939).
static PREVIEWS: Semaphore = Semaphore::const_new(2);
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
    /// Where the entry points: a URL or file, the servers, the members, the record values.
    pub(crate) detail: String,
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
    /// The admin who asked for the preview; only that admin may apply or discard it.
    pub(crate) by: String,
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

/// The live plan `id` of the admin `by`. Another admin's plan is not found (REQ: API-007).
fn take(id: &str, now: u64, by: &str) -> Option<Plan> {
    let m = plans();
    m.iter()
        .find(|p| p.id == id && p.expires > now && p.by == by)
        .cloned()
}

fn forget(id: &str) {
    plans().retain(|p| p.id != id);
}

/// REQ: API-007 (ADR-940) — a plan's ID: 32 random bytes, so it can't be guessed.
fn new_id() -> String {
    telltale_api::auth::crypto::random_secret()
}

/// The upload, as a private file in a private scratch directory the worker reads; the directory
/// and everything in it is removed when this is dropped.
///
/// REQ: API-007 (ADR-989) — the directory is made under the node's data directory, the one path
/// every install can write (the scratch image has no `/tmp`, and the worker unpacks an archive's
/// `gravity.db` next to the upload). It is `<data_dir>/import-tmp/<unique>`, mode 0700; when the
/// data directory can't be written it falls back to the system's temporary directory.
struct Upload {
    dir: PathBuf,
    file: PathBuf,
}

/// The directory under the data directory that holds the scratch directories.
const SCRATCH_PARENT: &str = "import-tmp";
/// The prefix of every scratch directory name (the sweep touches only these).
const SCRATCH_PREFIX: &str = "up-";
/// A scratch directory older than this is left over from a crash and is removed.
const SCRATCH_STALE: Duration = Duration::from_secs(3600);

impl Upload {
    fn write(data_dir: &Path, data: &[u8]) -> Result<Self, Problem> {
        use std::io::Write as _;
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let rand: String = new_id()
            .chars()
            .filter(char::is_ascii_alphanumeric)
            .take(16)
            .collect();
        let name = format!(
            "{SCRATCH_PREFIX}{}-{}-{n}-{rand}",
            std::process::id(),
            now()
        );
        let fail = |what: &str, e: std::io::Error| {
            Problem::internal(format!("can't store the upload ({what}): {e}"))
        };
        let dir = match Self::make_dir(&data_dir.join(SCRATCH_PARENT), &name) {
            Ok(d) => d,
            // The system temporary directory is shared: only a fresh directory of ours is made in
            // it; the temporary directory itself is never changed or swept.
            Err(_) => {
                Self::private_dir(&std::env::temp_dir().join(format!("telltale-import-{rand}-{n}")))
                    .map_err(|e| fail("no writable scratch directory", e))?
            }
        };
        let up = Self {
            file: dir.join("upload"),
            dir,
        };
        let mut o = std::fs::OpenOptions::new();
        o.write(true).create_new(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut o, 0o600);
        o.open(&up.file)
            .and_then(|mut f| f.write_all(data))
            .map_err(|e| fail("writing it", e))?;
        Ok(up)
    }

    /// Creates `p` (which must not exist), mode 0700, and checks it is a real directory.
    fn private_dir(p: &Path) -> std::io::Result<PathBuf> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt as _;
            std::fs::DirBuilder::new().mode(0o700).create(p)?;
        }
        #[cfg(not(unix))]
        std::fs::create_dir(p)?;
        if !std::fs::symlink_metadata(p)?.is_dir() {
            return Err(std::io::Error::other("not a directory"));
        }
        Ok(p.to_path_buf())
    }

    /// Makes `<parent>/<name>` under the data directory (and `parent`, private to this user),
    /// and clears stale siblings.
    fn make_dir(parent: &Path, name: &str) -> std::io::Result<PathBuf> {
        std::fs::create_dir_all(parent)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))?;
        }
        Self::sweep(parent);
        Self::private_dir(&parent.join(name))
    }

    /// Removes scratch directories a crashed worker or server left behind (best effort); only
    /// directories this code names, and only under the data directory.
    fn sweep(parent: &Path) {
        let Ok(list) = std::fs::read_dir(parent) else {
            return;
        };
        for e in list.flatten() {
            let ours = e.file_name().to_str().is_some_and(|n| {
                n.strip_prefix(SCRATCH_PREFIX).is_some_and(|r| {
                    !r.is_empty() && r.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
                })
            });
            let old = ours
                && e.metadata()
                    .and_then(|m| m.modified())
                    .ok()
                    .and_then(|t| t.elapsed().ok())
                    .is_some_and(|age| age > SCRATCH_STALE);
            if old {
                let _ = std::fs::remove_dir_all(e.path());
            }
        }
    }
}

impl Drop for Upload {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// `telltale pihole-import-worker PATH`: converts the file and prints one JSON object. Exits 0
/// whenever it could print its answer (the answer says whether the conversion worked). The
/// worker applies the same limits as a discovery worker first (REQ: API-007, ADR-939): the memory
/// limit, no capability, no `bind`/`listen`/`ptrace`, and not dumpable. If it can't, it says so
/// and converts nothing.
pub(crate) fn run_worker(path: &Path, scratch: Option<&Path>) -> std::process::ExitCode {
    use std::io::Write as _;
    let out = match telltale_net::worker::harden(WORKER_MEMORY) {
        Ok(()) => worker_answer(path, scratch),
        Err(e) => json!({
            "ok": false,
            "error": format!("the import worker can't apply its limits: {e}"),
        }),
    };
    let _ = writeln!(std::io::stdout().lock(), "{out}");
    std::process::ExitCode::SUCCESS
}

/// The worker's answer for the file at `path`: the conversion, or the reason there isn't one.
fn worker_answer(path: &Path, scratch: Option<&Path>) -> Value {
    let loaded = match scratch {
        Some(dir) => pihole::Source::load_in(path, dir),
        None => pihole::Source::load(path),
    };
    match loaded.and_then(|src| pihole::convert(&src, "the uploaded export")) {
        Ok(im) => json!({
            "ok": true,
            "toml": im.toml,
            "version": im.version,
            "notes": im.notes,
            "counts": im.counts,
            "samples": im.samples,
        }),
        Err(e) => json!({ "ok": false, "error": e }),
    }
}

/// Runs `cmd` to completion, reading its stdout up to `cap` bytes, and gives up after `limit`.
/// The child is killed when this returns early (REQ: API-007, ADR-939): an over-large answer
/// stops the read at the cap, and a worker that takes too long is dropped with its timeout.
async fn run_capped(
    mut cmd: tokio::process::Command,
    limit: Duration,
    cap: usize,
) -> Result<Vec<u8>, Problem> {
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    let mut child = cmd
        .spawn()
        .map_err(|e| Problem::internal(format!("the import worker didn't start: {e}")))?;
    let Some(stdout) = child.stdout.take() else {
        return Err(Problem::internal("the import worker has no output to read"));
    };
    let read = async {
        let mut buf = Vec::new();
        // One byte past the cap tells an answer over the cap from one exactly at it.
        stdout
            .take(cap as u64 + 1)
            .read_to_end(&mut buf)
            .await
            .map_err(|e| Problem::internal(format!("the import worker failed: {e}")))?;
        if buf.len() > cap {
            return Err(Problem::new(
                Code::InvalidConfig,
                "the import's conversion is too large to show",
            ));
        }
        child
            .wait()
            .await
            .map_err(|e| Problem::internal(format!("the import worker failed: {e}")))?;
        Ok(buf)
    };
    tokio::time::timeout(limit, read).await.map_err(|_| {
        Problem::new(
            Code::InvalidConfig,
            format!(
                "the import took longer than {} seconds; the file is too large or damaged",
                limit.as_secs()
            ),
        )
    })?
}

/// The worker's answer, as the API reports it: a conversion, or a 422 with the reason.
fn wire_from_bytes(out: &[u8]) -> Result<Wire, Problem> {
    let wire: Wire = serde_json::from_slice(out).map_err(|_| {
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

/// Runs the worker on `path` in a child process with an empty environment, under a timeout and
/// an output limit (ADR-939), with the spawn preparation a discovery worker gets (no ambient
/// capability, the parent not dumpable).
async fn run_worker_process(path: &Path, scratch: &Path) -> Result<Wire, Problem> {
    let exe = std::env::current_exe().map_err(|e| {
        Problem::internal(format!("can't find this program to run the import: {e}"))
    })?;
    let mut cmd = tokio::process::Command::new(exe);
    cmd.arg("pihole-import-worker")
        .arg(path)
        .arg("--scratch")
        .arg(scratch)
        .env_clear();
    telltale_net::worker::prepare_spawn(cmd.as_std_mut())
        .map_err(|e| Problem::internal(format!("can't prepare the import worker: {e}")))?;
    let out = run_capped(cmd, WORKER_TIMEOUT, WORKER_OUTPUT_LIMIT).await?;
    wire_from_bytes(&out)
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
        detail: String::new(),
    });
    writes.push(Write {
        kind: managed_kind,
        name: name.to_owned(),
        body,
    });
}

/// The names of `items` joined for a detail line.
fn joined<'a>(items: impl IntoIterator<Item = &'a str>) -> String {
    items.into_iter().collect::<Vec<_>>().join(", ")
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
    by: &str,
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
    // Notes about the entries themselves (not the conversion's): what to check before applying.
    let mut flags = Vec::new();

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
        set_detail(&mut items, u.url.as_str());
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
        set_detail(
            &mut items,
            &joined(g.members.iter().map(telltale_config::SafeString::as_str)),
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
        // REQ: API-007 (ADR-940) — a file list reads a file on this machine, not a URL; an export
        // from someone else can name any path, so the admin is told which.
        let detail = match (&l.url, &l.path) {
            (_, Some(p)) => {
                flags.push(format!(
                    "List `{name}` reads the file `{}` on this machine, not a URL. Apply it only if that file is yours to read.",
                    p.as_str()
                ));
                format!("file {}", p.as_str())
            }
            (Some(u), None) => u.as_str().to_owned(),
            (None, None) => String::new(),
        };
        set_detail(&mut items, &detail);
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
        set_detail(
            &mut items,
            &g.lists.as_ref().map_or_else(
                || "every list".to_owned(),
                |ls| joined(ls.iter().map(telltale_config::SafeString::as_str)),
            ),
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
        // REQ: API-007 (ADR-040) — a device the config files define is theirs: the API stores
        // nothing under that name, so the import leaves it out, as it does local names.
        if file.client.iter().any(|x| x.name.as_str() == name) {
            items.push(skip(
                "device",
                name,
                "the config files define this device (files win over the API, ADR-040)",
            ));
            continue;
        }
        let exists = current.client.iter().any(|x| x.name.as_str() == name);
        write_item(
            &mut items,
            &mut writes,
            "device",
            managed::CLIENT,
            name,
            exists,
            false,
            json_of(c)?,
        );
        set_detail(
            &mut items,
            &joined(c.match_keys.iter().map(telltale_config::SafeString::as_str)),
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
                node_only: false,
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
        let detail = joined_owned(recs.iter().map(|r| format!("{} {}", r.rtype, r.value)));
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
        set_detail(&mut items, &detail);
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
                match_group: Vec::new(),
                match_qtype: Vec::new(),
                dnssec_nta: true,
                node_only: false,
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
            set_detail(&mut items, &servers.join(", "));
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
        // REQ: API-007 — the stored rate limit replaces the config file's `[ratelimit]` section
        // as a whole (ADR-069), so the file's values stop applying while it lasts.
        if file.ratelimit != RateLimitConfig::default() {
            set_reason(
                &mut items,
                "replaces the config file's [ratelimit] section while this stored setting lasts",
            );
        }
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
    notes.extend(flags);
    if let Ok(warnings) = telltale_config::validate_config(&merged) {
        notes.extend(warnings.into_iter().map(|w| format!("warning: {w}")));
    }
    Ok(Plan {
        id: new_id(),
        expires: at + PLAN_TTL,
        by: by.to_owned(),
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

/// [`joined`] for owned strings.
fn joined_owned(items: impl IntoIterator<Item = String>) -> String {
    items.into_iter().collect::<Vec<_>>().join("; ")
}

/// Gives the item just added its reason (the default groups' merges say what they keep).
fn set_reason(items: &mut [Item], reason: &str) {
    if let Some(i) = items.last_mut() {
        reason.clone_into(&mut i.reason);
    }
}

/// Gives the item just added its detail: where the entry points.
fn set_detail(items: &mut [Item], detail: &str) {
    if let Some(i) = items.last_mut() {
        detail.clone_into(&mut i.detail);
    }
}

fn skip(kind: &'static str, name: &str, reason: &str) -> Item {
    Item {
        kind,
        name: name.to_owned(),
        action: "skip",
        reason: reason.to_owned(),
        detail: String::new(),
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
        .map(|i| {
            json!({
                "kind": i.kind,
                "name": i.name,
                "action": i.action,
                "reason": i.reason,
                "detail": i.detail,
            })
        })
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
/// sample through the Pi-hole and TelltaleDNS (ADR-941). At most two previews run at once.
pub(crate) async fn preview(src: Arc<Sources>, req: PiholeImportRequest) -> Result<Value, Problem> {
    let _slot = PREVIEWS
        .try_acquire()
        .map_err(|_| Problem::unavailable("another import is being read; try again in a moment"))?;
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
    let by = req.by.clone();
    let data = req.data;
    // The write is blocking I/O of up to 64 MiB: it runs off the request's thread.
    let data_dir = PathBuf::from(src.config.load().node.data_dir.as_str());
    let upload = tokio::task::spawn_blocking(move || Upload::write(&data_dir, &data))
        .await
        .map_err(|e| Problem::internal(format!("the upload failed: {e}")))??;
    let wire = run_worker_process(&upload.file, &upload.dir).await?;
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
    let file = crate::api_backend::plan_files(&src);
    let at = now();
    let plan = build(&file, &state, wire, compare_json, at, &by)?;
    let out = preview_json(&plan);
    keep(plan, at);
    Ok(out)
}

/// Discards a plan of `by` (REQ: API-007). Unknown IDs, and other admins' plans, are a 404.
pub(crate) fn discard(id: &str, by: &str) -> Result<Value, Problem> {
    if take(id, now(), by).is_none() {
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
/// When the change is stored but the reload fails, the answer says so with `applied: false` and
/// the stored version, so the caller can audit the change (the API turns that answer into a 500).
pub(crate) async fn apply(src: Arc<Sources>, id: String, by: String) -> Result<Value, Problem> {
    let at = now();
    let plan = take(&id, at, &by).ok_or_else(|| {
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
    let file = crate::api_backend::plan_files(&src);
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
    // The plan is spent once its change is stored, whatever the reload says.
    forget(&id);
    let (tx, rx) = tokio::sync::oneshot::channel();
    let applied = src.reload.send(tx).await.is_ok() && rx.await.unwrap_or(false);
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
        "applied": applied,
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

    /// A worker answer for a conversion's TOML (what the worker would print).
    fn wire_of(toml: &str) -> Wire {
        Wire {
            ok: true,
            error: None,
            toml: toml.to_owned(),
            version: "v5".into(),
            notes: Vec::new(),
            counts: String::new(),
            samples: Vec::new(),
        }
    }

    // REQ: API-007 (T24.18) — a preview lists what would change, and writes nothing.
    #[test]
    fn api_007_pihole_import_preview_changes_nothing() {
        let state = telltale_store::state::State::in_memory().unwrap();
        let plan = build(&file(""), &state, wire(), None, 1_000, "admin").unwrap();
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
        // Where entries point is shown: the upstream's address, the record's value.
        let up = plan.items.iter().find(|i| i.name == "pihole-1").unwrap();
        assert!(up.detail.contains("9.9.9.9"), "{}", up.detail);
    }

    // REQ: API-007 (T24.18, ADR-940) — applying the plan writes its entries in one change, and
    // the plan can't be applied twice (the second is stale).
    #[test]
    fn api_007_pihole_import_applies_as_plan() {
        let state = telltale_store::state::State::in_memory().unwrap();
        let f = file("");
        let plan = build(&f, &state, wire(), None, 1_000, "admin").unwrap();
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
        let plan = build(&f, &state, wire(), None, 1_000, "admin").unwrap();
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

    // REQ: API-007 (T24.18, ADR-040) — a device the config files define is skipped too: the
    // merge ignores a stored device of that name, so writing it would store a dead row.
    #[test]
    fn api_007_pihole_import_skips_devices_the_files_define() {
        let state = telltale_store::state::State::in_memory().unwrap();
        let toml =
            "[[client]]\nname = \"laptop\"\nmatch = [\"10.0.0.5\"]\ngroups = [\"default\"]\n";
        let f = file(toml);
        let plan = build(&f, &state, wire_of(toml), None, 1_000, "admin").unwrap();
        let item = plan
            .items
            .iter()
            .find(|i| i.kind == "device" && i.name == "laptop")
            .expect("a device item");
        assert_eq!(item.action, "skip", "{:?}", plan.items);
        assert!(!plan.writes.iter().any(|w| w.kind == managed::CLIENT));
    }

    // REQ: API-007 (ADR-940) — a file list is flagged in the notes, and its item shows the path.
    #[test]
    fn api_007_pihole_import_flags_file_lists() {
        let state = telltale_store::state::State::in_memory().unwrap();
        let toml =
            "[[list]]\nname = \"local\"\npath = \"/srv/secret/list.txt\"\nkind = \"block\"\n";
        let plan = build(&file(""), &state, wire_of(toml), None, 1_000, "admin").unwrap();
        assert!(
            plan.notes
                .iter()
                .any(|n| n.contains("/srv/secret/list.txt")),
            "{:?}",
            plan.notes
        );
        let item = plan.items.iter().find(|i| i.name == "local").unwrap();
        assert!(
            item.detail.contains("/srv/secret/list.txt"),
            "{}",
            item.detail
        );
    }

    // REQ: API-007 (ADR-989) — the upload lives in a private directory under the data directory
    // (the image has no /tmp), and the whole directory goes when the upload does.
    #[test]
    fn api_007_upload_scratch_is_private_and_removed() {
        let data = tempfile::tempdir().unwrap();
        let up = Upload::write(data.path(), b"hello").unwrap();
        assert!(up.dir.starts_with(data.path().join(SCRATCH_PARENT)));
        assert_eq!(std::fs::read(&up.file).unwrap(), b"hello");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode(&up.dir), 0o700);
            assert_eq!(mode(&data.path().join(SCRATCH_PARENT)), 0o700);
            assert_eq!(mode(&up.file), 0o600);
        }
        let dir = up.dir.clone();
        drop(up);
        assert!(!dir.exists(), "the scratch directory is removed");
    }

    // REQ: API-007 (ADR-989) — a data directory that can't be written falls back to a fresh
    // directory in the system's temporary directory, which is itself left alone.
    #[test]
    fn api_007_upload_scratch_falls_back_to_temp_dir() {
        let data = tempfile::tempdir().unwrap();
        let blocked = data.path().join("not-a-dir");
        std::fs::write(&blocked, b"a file where the data directory should be").unwrap();
        let tmp = std::env::temp_dir();
        let other = tmp.join(format!("telltale-fallback-test-{}", std::process::id()));
        std::fs::create_dir_all(&other).unwrap();
        #[cfg(unix)]
        let before = {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::metadata(&tmp).unwrap().permissions().mode()
        };
        let up = Upload::write(&blocked, b"x").unwrap();
        assert!(up.dir.starts_with(&tmp));
        assert_eq!(std::fs::read(&up.file).unwrap(), b"x");
        assert!(other.exists(), "other directories in the temp dir survive");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                std::fs::metadata(&tmp).unwrap().permissions().mode(),
                before
            );
        }
        drop(up);
        let _ = std::fs::remove_dir_all(&other);
    }

    // REQ: API-007 (ADR-989) — the sweep removes only old directories it named itself.
    #[test]
    fn api_007_sweep_leaves_fresh_and_foreign_directories() {
        let data = tempfile::tempdir().unwrap();
        let parent = data.path().join(SCRATCH_PARENT);
        std::fs::create_dir_all(parent.join("up-1-2-3-abc")).unwrap();
        std::fs::create_dir_all(parent.join("keep-me")).unwrap();
        Upload::sweep(&parent);
        assert!(parent.join("up-1-2-3-abc").exists());
        assert!(parent.join("keep-me").exists());
    }

    // REQ: API-007 (T24.18) — a damaged archive, gravity.db or text file is refused with the reason
    // (422), by the worker's answer; the worker's own process limits are the child's concern.
    #[test]
    fn api_007_pihole_import_worker_limits() {
        let dir = tempfile::tempdir().unwrap();
        let zip = dir.path().join("bad.zip");
        std::fs::write(&zip, b"PK\x03\x04 not really a zip at all").unwrap();
        let db = dir.path().join("bad.db");
        let mut junk = b"SQLite format 3\0".to_vec();
        junk.extend_from_slice(&[7u8; 64]);
        std::fs::write(&db, junk).unwrap();
        let text = dir.path().join("notes.txt");
        std::fs::write(&text, b"hello").unwrap();
        for path in [&zip, &db, &text] {
            let answer = worker_answer(path, None).to_string();
            let Err(err) = wire_from_bytes(answer.as_bytes()) else {
                panic!("{} should be refused", path.display())
            };
            assert_eq!(
                err.code_status(),
                axum::http::StatusCode::UNPROCESSABLE_ENTITY
            );
        }
        // A worker that printed nothing it could read is refused the same way.
        let err = wire_from_bytes(b"").expect_err("refused");
        assert_eq!(
            err.code_status(),
            axum::http::StatusCode::UNPROCESSABLE_ENTITY
        );
    }

    // REQ: API-007 (ADR-939) — the worker's output is capped: an answer over the cap is refused, and
    // the child is stopped (the read stops at the cap).
    #[cfg(unix)]
    #[tokio::test]
    async fn api_007_pihole_import_worker_output_cap() {
        let mut cmd = tokio::process::Command::new("sh");
        cmd.args(["-c", "head -c 4096 /dev/zero"]);
        let err = run_capped(cmd, Duration::from_secs(20), 1024)
            .await
            .expect_err("refused");
        assert_eq!(
            err.code_status(),
            axum::http::StatusCode::UNPROCESSABLE_ENTITY
        );
        // An answer under the cap comes back whole.
        let mut ok = tokio::process::Command::new("sh");
        ok.args(["-c", "printf '{\"ok\":false}'"]);
        assert_eq!(
            run_capped(ok, Duration::from_secs(20), 1024)
                .await
                .expect("under the cap"),
            b"{\"ok\":false}"
        );
    }

    // REQ: API-007 (ADR-939) — a worker that takes too long is stopped at the limit (422), and
    // nothing waits for it.
    #[cfg(unix)]
    #[tokio::test]
    async fn api_007_pihole_import_worker_timeout() {
        let mut cmd = tokio::process::Command::new("sh");
        cmd.args(["-c", "sleep 30"]);
        let started = std::time::Instant::now();
        let err = run_capped(cmd, Duration::from_millis(200), 1024)
            .await
            .expect_err("refused");
        assert_eq!(
            err.code_status(),
            axum::http::StatusCode::UNPROCESSABLE_ENTITY
        );
        assert!(started.elapsed() < Duration::from_secs(20));
    }

    // REQ: API-007 (ADR-940) — a plan is the admin's: another admin can't apply or discard it.
    #[test]
    fn api_007_pihole_import_plan_belongs_to_its_admin() {
        let state = telltale_store::state::State::in_memory().unwrap();
        let at = now();
        let plan = build(&file(""), &state, wire(), None, at, "alice").unwrap();
        let id = plan.id.clone();
        keep(plan, at);
        assert!(take(&id, at + 1, "bob").is_none());
        assert!(take(&id, at + 1, "alice").is_some());
        let err = discard(&id, "bob").expect_err("not bob's");
        assert_eq!(err.code_status(), axum::http::StatusCode::NOT_FOUND);
        assert!(discard(&id, "alice").is_ok());
    }
}
