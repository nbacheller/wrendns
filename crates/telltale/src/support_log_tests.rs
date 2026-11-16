// REQ: OPS-011 (ADR-156) — the support package's own log: a bounded ring, rotating files that
// survive a restart, a channel that drops instead of blocking, and a directory that can't be
// written leaving the ring alone.

use super::*;
use tracing::level_filters::LevelFilter;
use tracing_subscriber::Layer as _;
use tracing_subscriber::layer::SubscriberExt as _;

/// Runs `f` with `log`'s layer as the thread's subscriber, filtered as the binary filters it.
fn with_log<R>(log: &Arc<SupportLog>, f: impl FnOnce() -> R) -> R {
    let sub = tracing_subscriber::registry()
        .with(SupportLayer(Arc::clone(log)).with_filter(filter(LevelFilter::OFF)));
    tracing::subscriber::with_default(sub, f)
}

#[test]
fn ops_011_the_ring_keeps_the_newest_lines() {
    let log = Arc::new(SupportLog::new(FILE_BYTES));
    with_log(&log, || {
        for i in 0..2_500 {
            tracing::info!("line {i}");
        }
    });
    let s = log.snapshot();
    assert_eq!(s.lines.len(), RING_LINES);
    assert!(s.lines[0].ends_with("line 500"), "{}", s.lines[0]);
    assert!(s.lines[RING_LINES - 1].ends_with("line 2499"));
    assert_eq!(s.files, Files::Off);
    assert_eq!(s.dropped, 0);
}

#[test]
fn ops_011_info_and_above_with_their_fields_on_one_line() {
    let log = Arc::new(SupportLog::new(FILE_BYTES));
    with_log(&log, || {
        tracing::debug!("not kept");
        tracing::trace!("not kept either");
        tracing::info!(n = 3, name = %"lg-tv", "started\nsecond line");
        tracing::warn!(error = ?"boom", "went wrong");
        // The DNSSEC library's per-answer lines stay out, as on the console.
        tracing::warn!(target: "hickory_net::dnssec", "unsigned");
    });
    let s = log.snapshot();
    assert_eq!(s.lines.len(), 2, "{:?}", s.lines);
    assert!(
        s.lines[0].contains(" INFO started second line n=3 name=lg-tv"),
        "{}",
        s.lines[0]
    );
    assert!(
        s.lines[1].contains(" WARN went wrong error=\"boom\""),
        "{}",
        s.lines[1]
    );
    // `2026-11-16T04:56:32.123Z`, then the level.
    assert_eq!(s.lines[0].as_bytes()[10], b'T');
    assert!(s.lines.iter().all(|l| !l.contains('\n')));
}

#[test]
fn ops_011_a_long_line_is_cut_on_a_character_boundary() {
    let log = Arc::new(SupportLog::new(FILE_BYTES));
    let text = "é".repeat(5_000);
    with_log(&log, || tracing::error!("{text}"));
    let l = log.snapshot().lines.remove(0);
    assert!(l.len() <= MAX_LINE, "{}", l.len());
    assert!(l.is_char_boundary(l.len()));
}

#[test]
fn ops_011_files_rotate_and_the_last_run_reaches_the_next_one() {
    let dir = tempfile::tempdir().unwrap();
    let first = Arc::new(SupportLog::new(4096));
    with_log(&first, || tracing::info!("before the files exist"));
    first.attach(dir.path(), true);
    assert_eq!(first.snapshot().files, Files::On);
    with_log(&first, || {
        for i in 0..200 {
            tracing::info!("run one, line {i:03} with some padding to fill the file up");
        }
    });
    let logs = dir.path().join("logs");
    // `flush` waits at most two seconds for the writer; a test machine that is busy with other
    // tests can need longer, so ask again until the rotation has happened.
    for _ in 0..100 {
        first.flush();
        if logs.join(format!("{FILE}.1")).exists() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    let current = std::fs::metadata(logs.join(FILE)).unwrap().len();
    let older = std::fs::metadata(logs.join(format!("{FILE}.1")))
        .unwrap()
        .len();
    assert!(current > 0 && current <= 4096, "{current}");
    assert!(older > 0 && older <= 4096, "{older}");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&logs), 0o750);
        assert_eq!(mode(&logs.join(FILE)), 0o640);
    }

    // The next run: the last run's newest lines come first, then its own (the early ones are kept).
    let second = Arc::new(SupportLog::new(4096));
    with_log(&second, || tracing::info!("run two, early"));
    second.attach(dir.path(), true);
    with_log(&second, || tracing::info!("run two, later"));
    let lines = second.snapshot().lines;
    let pos = |needle: &str| lines.iter().position(|l| l.contains(needle));
    let last_of_one = pos("run one, line 199").expect("the last run's last line");
    let early = pos("run two, early").expect("the early line");
    let later = pos("run two, later").expect("the later line");
    assert!(
        last_of_one < early && early < later,
        "{last_of_one} {early} {later}"
    );
    second.flush();
    // Either file may hold them, depending on when the second run rotated.
    let text = [format!("{FILE}.1"), FILE.to_owned()]
        .iter()
        .filter_map(|n| std::fs::read_to_string(logs.join(n)).ok())
        .collect::<String>();
    assert!(
        text.contains("run two, early") && text.contains("run two, later"),
        "{text}"
    );
}

#[test]
fn ops_011_a_full_channel_drops_and_counts_instead_of_blocking() {
    let log = Arc::new(SupportLog::new(FILE_BYTES));
    // Nobody reads this: after two lines it is full.
    let (tx, _rx) = sync_channel::<Msg>(2);
    log.attach_channel(tx);
    with_log(&log, || {
        for i in 0..10 {
            tracing::info!("line {i}");
        }
    });
    let s = log.snapshot();
    assert_eq!(s.lines.len(), 10, "the ring has all of them");
    assert_eq!(s.dropped, 8);
}

#[test]
fn ops_011_a_directory_that_cant_be_written_leaves_the_ring() {
    let dir = tempfile::tempdir().unwrap();
    // `data_dir` is a regular file, so `logs/` can't be made under it.
    let blocker = dir.path().join("not-a-directory");
    std::fs::write(&blocker, b"x").unwrap();
    let log = Arc::new(SupportLog::new(FILE_BYTES));
    with_log(&log, || tracing::info!("early"));
    log.attach(&blocker, true);
    with_log(&log, || tracing::info!("later"));
    let s = log.snapshot();
    assert!(matches!(s.files, Files::Failed(_)), "{:?}", s.files);
    assert!(s.lines.iter().any(|l| l.ends_with("early")));
    assert!(s.lines.iter().any(|l| l.ends_with("later")));
    log.flush(); // nothing to wait for, and it returns
}

#[test]
fn ops_011_persist_logs_off_writes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let log = Arc::new(SupportLog::new(FILE_BYTES));
    log.attach(dir.path(), false);
    with_log(&log, || tracing::info!("kept in memory only"));
    assert!(!dir.path().join("logs").exists());
    let s = log.snapshot();
    assert_eq!(s.files, Files::Off);
    assert_eq!(s.lines.len(), 1);
}
