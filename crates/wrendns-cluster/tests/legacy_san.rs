//! REQ: CLU-001 (ADR-1028) — a node's ID is read from either spelling of its certificate name,
//! so a cluster of nodes from before and after the rename keeps working through a rolling upgrade.

use wrendns_cluster::net::peer_node_id;

fn id_of(san: &str) -> Option<String> {
    let ck = rcgen::generate_simple_self_signed(vec![san.to_owned()]).ok()?;
    peer_node_id(ck.cert.der())
}

#[test]
fn clu_001_node_id_from_the_pre_rename_certificate_name() {
    assert_eq!(
        id_of("abc123.node.telltale.invalid").as_deref(),
        Some("abc123")
    );
}

#[test]
fn clu_001_node_id_from_the_new_certificate_name() {
    assert_eq!(
        id_of("abc123.node.wrendns.invalid").as_deref(),
        Some("abc123")
    );
}

#[test]
fn clu_001_other_names_name_no_node() {
    assert_eq!(id_of("abc123.node.example.com"), None);
}
