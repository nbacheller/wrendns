#![allow(
    clippy::redundant_closure_for_method_calls,
    clippy::manual_assert,
    clippy::cast_possible_wrap,
    clippy::too_many_lines,
    clippy::explicit_counter_loop,
    clippy::collapsible_if,
    clippy::map_unwrap_or,
    clippy::type_complexity,
    clippy::items_after_statements,
    dead_code
)]
//! REQ: DSC-903 (T31.2, rule R1) - the manual link, unlink, merge and split.

use wrendns_store::cmdb::{CiRow, RecordRow};

use super::engine::Engine;
use super::engine::test_support::{batch, engine, host};
use super::manual::{ManualError, ManualOp, RecRef};
use super::model::{RecKind, Record};

const T0: i64 = 1_000_000;

fn rec_of(e: &Engine, source: &str, key: &str) -> RecordRow {
    e.db()
        .read(|o| o.record_get(source, key))
        .unwrap()
        .unwrap_or_else(|| panic!("no record {source}/{key}"))
}

fn devices(e: &Engine) -> Vec<CiRow> {
    e.db()
        .read(|o| o.ci_list(Some("device"), None, None, 500))
        .unwrap()
}

fn children(e: &Engine, device: &str) -> Vec<CiRow> {
    e.db().read(|o| o.ci_children(device)).unwrap()
}

fn proposals(e: &Engine, kind: &str) -> usize {
    e.db()
        .read(|o| o.proposals(Some("open"), None))
        .unwrap()
        .iter()
        .filter(|p| p.kind == kind)
        .count()
}

fn with(mut r: Record, name: &str, value: &str) -> Record {
    r.text(name, value);
    r
}

fn ingest(e: &mut Engine, source: &str, records: Vec<Record>, at: i64) {
    e.ingest(batch(source, records, true, at), at).unwrap();
}

fn rr(source: &str, key: &str) -> RecRef {
    RecRef {
        source: source.to_owned(),
        key: key.to_owned(),
    }
}

fn with_ip(mut r: Record, ip: &str) -> Record {
    r.list("addresses", vec![ip.to_owned()]);
    r
}

/// REQ: DSC-903 (AC 2) - an unlink writes a never-match pin that survives the next batch; the record
/// is not matched to that device again even when the device's own records change.
#[test]
fn dsc_903_unlink_pins_and_survives_the_next_batch() {
    let (_d, mut e) = engine();
    ingest(
        &mut e,
        "neighbor",
        vec![with_ip(
            host("neighbor", "n1", "aa:bb:cc:00:00:01", T0),
            "192.168.1.10",
        )],
        T0,
    );
    let q = || {
        with_ip(
            Record::new("queries", "192.168.1.10", RecKind::Device, T0 + 5),
            "192.168.1.10",
        )
    };
    ingest(&mut e, "queries", vec![q()], T0 + 5);
    let dev = rec_of(&e, "neighbor", "n1").dci.unwrap();
    assert_eq!(
        rec_of(&e, "queries", "192.168.1.10").dci.as_deref(),
        Some(dev.as_str())
    );
    let op = ManualOp::Unlink {
        record: rr("queries", "192.168.1.10"),
    };
    let dry = e.manual(&op, "alice", "wrong", T0 + 6, true).unwrap();
    assert!(!dry.applied && dry.preview.moves.len() == 1);
    assert_eq!(
        rec_of(&e, "queries", "192.168.1.10").dci.as_deref(),
        Some(dev.as_str()),
        "a dry run changes nothing"
    );
    let out = e.manual(&op, "alice", "wrong", T0 + 7, false).unwrap();
    assert!(out.applied);
    let after = rec_of(&e, "queries", "192.168.1.10");
    assert_ne!(after.dci.as_deref(), Some(dev.as_str()), "unlinked");
    assert!(after.dci.is_some(), "and its own unconfirmed CI");
    // The next batches: the same record again, and the device's record changing its name.
    ingest(&mut e, "queries", vec![q()], T0 + 70);
    ingest(
        &mut e,
        "neighbor",
        vec![with(
            with_ip(
                host("neighbor", "n1", "aa:bb:cc:00:00:01", T0 + 70),
                "192.168.1.10",
            ),
            "name",
            "renamed",
        )],
        T0 + 71,
    );
    assert_ne!(
        rec_of(&e, "queries", "192.168.1.10").dci.as_deref(),
        Some(dev.as_str()),
        "the pin survives"
    );
    let pins = e.db().read(|o| o.pins()).unwrap();
    assert!(
        pins.iter()
            .any(|p| p.kind == "rec_never" && p.by == "alice" && p.reason == "wrong")
    );
}

/// REQ: DSC-903 (AC 2) - a merge leaves the losing id as an alias that redirects, moves every
/// interface and record, and is not undone by the next batch.
#[test]
fn dsc_903_merge_leaves_a_redirecting_alias() {
    let (_d, mut e) = engine();
    ingest(
        &mut e,
        "unifi:home",
        vec![
            host("unifi:home", "a", "aa:bb:cc:00:00:01", T0),
            host("unifi:home", "b", "aa:bb:cc:00:00:02", T0 + 1),
        ],
        T0,
    );
    let a = rec_of(&e, "unifi:home", "a");
    let b = rec_of(&e, "unifi:home", "b");
    let (da, db) = (a.dci.clone().unwrap(), b.dci.clone().unwrap());
    assert_ne!(da, db);
    let op = ManualOp::Merge {
        from: db.clone(),
        into: da.clone(),
    };
    let pv = e.manual(&op, "bob", "same laptop", T0 + 5, true).unwrap();
    assert_eq!(pv.preview.moves.len(), 1);
    assert!(pv.preview.notes.iter().any(|n| n.contains("alias")));
    e.manual(&op, "bob", "same laptop", T0 + 6, false).unwrap();
    assert_eq!(
        rec_of(&e, "unifi:home", "b").dci.as_deref(),
        Some(da.as_str())
    );
    assert_eq!(
        children(&e, &da).len(),
        2,
        "both interfaces under the survivor"
    );
    assert!(
        e.db().read(|o| o.ci_get(&db)).unwrap().is_none(),
        "the loser is gone"
    );
    assert_eq!(
        e.db()
            .read(|o| o.resolve_id(&db, T0 + 10))
            .unwrap()
            .as_deref(),
        Some(da.as_str()),
        "its id redirects"
    );
    assert_eq!(
        e.db()
            .read(|o| o.resolve_id(&db, T0 + 91 * 86_400))
            .unwrap(),
        None,
        "for 90 days"
    );
    // A later batch does not undo it.
    ingest(
        &mut e,
        "unifi:home",
        vec![
            host("unifi:home", "b", "aa:bb:cc:00:00:02", T0 + 100),
            host("unifi:home", "a", "aa:bb:cc:00:00:01", T0 + 100),
        ],
        T0 + 100,
    );
    assert_eq!(devices(&e).len(), 1);
}

/// REQ: DSC-903 - a split gives chosen records a new device and pins them there, so a shared serial
/// does not join them back; unlinking an interface gives it a device of its own the same way.
#[test]
fn dsc_903_split_and_interface_unlink_are_pinned() {
    let (_d, mut e) = engine();
    let two = |at: i64| {
        vec![
            with(
                host("unifi:home", "w", "aa:bb:cc:00:00:01", at),
                "serial",
                "SN-SHARED-1",
            ),
            with(
                host("unifi:home", "e", "aa:bb:cc:00:00:02", at),
                "serial",
                "SN-SHARED-1",
            ),
        ]
    };
    ingest(&mut e, "unifi:home", two(T0), T0);
    let dev = rec_of(&e, "unifi:home", "w").dci.unwrap();
    assert_eq!(devices(&e).len(), 1);
    let err = e
        .manual(
            &ManualOp::Split {
                device: dev.clone(),
                records: vec![rr("unifi:home", "w"), rr("unifi:home", "e")],
            },
            "a",
            "x",
            T0 + 1,
            false,
        )
        .unwrap_err();
    assert!(
        matches!(err, ManualError::Invalid(_)),
        "not every interface: {err:?}"
    );
    let out = e
        .manual(
            &ManualOp::Unlink {
                record: rr("unifi:home", "e"),
            },
            "a",
            "two devices",
            T0 + 2,
            false,
        )
        .unwrap();
    let new_dev = out.result.unwrap();
    assert_ne!(new_dev, dev);
    assert_eq!(
        rec_of(&e, "unifi:home", "e").dci.as_deref(),
        Some(new_dev.as_str())
    );
    assert_eq!(
        rec_of(&e, "unifi:home", "w").dci.as_deref(),
        Some(dev.as_str())
    );
    // The same serial again: the pinned interface stays apart, and nothing is asked again (the
    // owner decided).
    ingest(&mut e, "unifi:home", two(T0 + 60), T0 + 60);
    assert_eq!(
        rec_of(&e, "unifi:home", "e").dci.as_deref(),
        Some(new_dev.as_str())
    );
    assert_eq!(
        rec_of(&e, "unifi:home", "w").dci.as_deref(),
        Some(dev.as_str())
    );
    assert_eq!(devices(&e).len(), 2);
    assert_eq!(proposals(&e, "level_disagreement"), 0);
}

/// REQ: DSC-903 - a manual link moves a keyless record, or a whole interface, to a device; a bad
/// target is refused and nothing is written.
#[test]
fn dsc_903_manual_link_moves_and_refuses() {
    let (_d, mut e) = engine();
    ingest(
        &mut e,
        "neighbor",
        vec![
            host("neighbor", "n1", "aa:bb:cc:00:00:01", T0),
            host("neighbor", "n2", "aa:bb:cc:00:00:02", T0 + 1),
        ],
        T0,
    );
    ingest(
        &mut e,
        "mdns",
        vec![with_ip(
            Record::new("mdns", "printer", RecKind::Device, T0),
            "192.168.1.50",
        )],
        T0,
    );
    let d1 = rec_of(&e, "neighbor", "n1").dci.unwrap();
    let d2 = rec_of(&e, "neighbor", "n2").dci.unwrap();
    e.manual(
        &ManualOp::Link {
            record: rr("mdns", "printer"),
            to: d1.clone(),
        },
        "a",
        "it is that one",
        T0 + 5,
        false,
    )
    .unwrap();
    assert_eq!(
        rec_of(&e, "mdns", "printer").dci.as_deref(),
        Some(d1.as_str())
    );
    assert_eq!(rec_of(&e, "mdns", "printer").link, "manual");
    // The interface of n2 moves to d1; d2 is left with nothing and is folded in.
    e.manual(
        &ManualOp::Link {
            record: rr("neighbor", "n2"),
            to: d1.clone(),
        },
        "a",
        "same machine",
        T0 + 6,
        false,
    )
    .unwrap();
    assert_eq!(
        rec_of(&e, "neighbor", "n2").dci.as_deref(),
        Some(d1.as_str())
    );
    assert_eq!(children(&e, &d1).len(), 2);
    assert_eq!(
        e.db()
            .read(|o| o.resolve_id(&d2, T0 + 10))
            .unwrap()
            .as_deref(),
        Some(d1.as_str())
    );
    let err = e
        .manual(
            &ManualOp::Link {
                record: rr("neighbor", "n1"),
                to: "ci_00000000000000000000000000000000".into(),
            },
            "a",
            "x",
            T0 + 7,
            false,
        )
        .unwrap_err();
    assert!(matches!(err, ManualError::NotFound(_)));
    let err = e
        .manual(
            &ManualOp::Link {
                record: rr("neighbor", "n1"),
                to: d1,
            },
            "a",
            "x",
            T0 + 8,
            false,
        )
        .unwrap_err();
    assert!(matches!(err, ManualError::Invalid(_)), "already there");
}
