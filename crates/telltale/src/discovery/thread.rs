//! The `telltale-inventory` thread (DSC-002, ADR-910). It is an OS thread of its own, with a
//! current-thread runtime, so the merge never runs on the query runtime. It polls the local
//! neighbour table each minute, reads the router and mDNS lease views the other tasks keep,
//! merges, sweeps retention, and saves `inventory.json` on the write cadence. Nothing here
//! answers a query, and a failure here only logs (CLU-004).
//!
//! Nothing starts this thread yet: `[discovery]` (T25.2) is the switch, and it is off by default.

use std::io;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, mpsc};
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use arc_swap::ArcSwap;

use crate::devices::Leases;

use super::inventory::{Inventory, Source};
use super::sources::{Ipv4Subnet, ifindex_names, lease_observations, neighbour_observations};
use super::store;

/// How often the sources are read.
pub(crate) const POLL_SECS: u64 = 60;
/// Routers are read every few minutes (`devices.rs`), so their bindings last longer.
pub(crate) const ROUTER_MAX_AGE_SECS: u64 = 900;
/// Entries with only weak sources age out this long after `last_seen` (ADR-910).
pub(crate) const RETENTION_SECS: u64 = 7 * 86_400;
/// Import rows age out this long after their import (`[discovery.import]`, ADR-910).
pub(crate) const IMPORT_RETENTION_SECS: u64 = 30 * 86_400;
/// The interface table the neighbour source maps indexes through.
pub(crate) const SYS_NET: &str = "/sys/class/net";

/// The sources the thread reads. A `None` view is not read.
#[derive(Clone, Default)]
pub(crate) struct Providers {
    /// The routers' lease view (`devices::Leases`, written by the router poller).
    pub(crate) routers: Option<Arc<ArcSwap<Leases>>>,
    /// The passive mDNS lease view.
    pub(crate) mdns: Option<Arc<ArcSwap<Leases>>>,
    /// The subnets whose neighbours count (ADR-910).
    pub(crate) subnets: Vec<Ipv4Subnet>,
    /// Whether to read the kernel neighbour table.
    pub(crate) neighbours: bool,
    /// The interface table root. `None` means [`SYS_NET`].
    pub(crate) ifindex_root: Option<PathBuf>,
}

/// A running inventory thread.
pub(crate) struct Handle {
    /// The latest inventory, for readers (the API, T25.12).
    pub(crate) shared: Arc<ArcSwap<Inventory>>,
    /// Set to make the next save follow the one-minute cadence (after an import or `public`).
    pub(crate) fast_write: Arc<AtomicBool>,
    stop: mpsc::Sender<()>,
    join: JoinHandle<()>,
}

impl Handle {
    /// Asks the thread to save and exit, and waits for it.
    pub(crate) fn stop(self) {
        let _ = self.stop.send(());
        let _ = self.join.join();
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Starts the thread. It loads `<data_dir>/inventory.json` first (an empty start if missing).
pub(crate) fn spawn(data_dir: PathBuf, providers: Providers) -> io::Result<Handle> {
    let inv = store::load(&data_dir, unix_now());
    let shared = Arc::new(ArcSwap::from_pointee(inv.clone()));
    let fast_write = Arc::new(AtomicBool::new(false));
    let (stop, stop_rx) = mpsc::channel();
    let thread_shared = Arc::clone(&shared);
    let thread_fast = Arc::clone(&fast_write);
    let join = thread::Builder::new()
        .name("telltale-inventory".into())
        .spawn(move || {
            telltale_net::background_thread();
            let rt = match tokio::runtime::Builder::new_current_thread()
                .enable_time()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    tracing::warn!(error = %e, "inventory thread: no runtime; not running");
                    return;
                }
            };
            rt.block_on(run(
                data_dir,
                providers,
                inv,
                thread_shared,
                thread_fast,
                stop_rx,
            ));
        })?;
    Ok(Handle {
        shared,
        fast_write,
        stop,
        join,
    })
}

async fn run(
    data_dir: PathBuf,
    providers: Providers,
    mut inv: Inventory,
    shared: Arc<ArcSwap<Inventory>>,
    fast_write: Arc<AtomicBool>,
    stop: mpsc::Receiver<()>,
) {
    let mut next_poll = 0u64;
    let mut last_write = unix_now();
    loop {
        let now = unix_now();
        if now >= next_poll {
            tick(&mut inv, &providers, now);
            next_poll = now.saturating_add(POLL_SECS);
            shared.store(Arc::new(inv.clone()));
        }
        let fast = fast_write.swap(false, Ordering::AcqRel);
        if store::write_due(inv.is_dirty(), now, last_write, fast) {
            save(&data_dir, &mut inv);
            last_write = now;
        }
        match stop.try_recv() {
            Ok(()) | Err(mpsc::TryRecvError::Disconnected) => {
                save(&data_dir, &mut inv);
                return;
            }
            Err(mpsc::TryRecvError::Empty) => {}
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

fn save(data_dir: &std::path::Path, inv: &mut Inventory) {
    if !inv.is_dirty() {
        return;
    }
    match store::save(data_dir, inv) {
        Ok(()) => inv.clear_dirty(),
        Err(e) => tracing::warn!(error = %e, "inventory.json could not be saved"),
    }
}

/// One poll: read each source, merge, expire what a source stopped reporting, then sweep.
pub(crate) fn tick(inv: &mut Inventory, providers: &Providers, now: u64) {
    if providers.neighbours {
        match telltale_net::neighbors() {
            Ok(neigh) => {
                let root = providers
                    .ifindex_root
                    .clone()
                    .unwrap_or_else(|| PathBuf::from(SYS_NET));
                let names = ifindex_names(&root);
                let obs = neighbour_observations(&neigh, &names, &providers.subnets, now);
                inv.apply(&obs, now);
                inv.expire_source(Source::Neighbor, now, POLL_SECS.saturating_mul(2));
            }
            Err(e) => tracing::warn!(error = %e, "inventory: neighbour table unreadable"),
        }
    }
    if let Some(view) = &providers.routers {
        let leases = view.load();
        inv.apply(&lease_observations(&leases, Source::Router, now), now);
        inv.expire_source(Source::Router, now, ROUTER_MAX_AGE_SECS);
    }
    if let Some(view) = &providers.mdns {
        let leases = view.load();
        inv.apply(&lease_observations(&leases, Source::Mdns, now), now);
        inv.expire_source(Source::Mdns, now, ROUTER_MAX_AGE_SECS);
    }
    inv.sweep(now, RETENTION_SECS, IMPORT_RETENTION_SECS);
}
