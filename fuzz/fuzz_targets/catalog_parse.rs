//! NFR-004 / REQ: FLT-901 — the category catalog parser never panics on any text, and what it
//! accepts can be checked, selected from and costed without panicking.
#![no_main]

use libfuzzer_sys::fuzz_target;
use telltale_config::categories::{Catalog, budget};
use telltale_config::{AdsTier, ContentLevel, GroupContent, SafeString};

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(cat) = Catalog::parse(&[text]) else {
        return;
    };
    let _ = cat.problems();
    for c in &cat.categories {
        let _ = cat.all_source_ids(c);
        let _ = cat.service_ids(c);
        let content = GroupContent {
            level: ContentLevel::Enhanced,
            categories: SafeString::new(c.id.clone()).into_iter().collect(),
            ..GroupContent::default()
        };
        let _ = cat.category_sources(c, &content, AdsTier::Pro);
    }
    let sources: Vec<_> = cat.sources.iter().collect();
    let _ = budget(&sources, 1_000_000, Some(128 << 20), 128 << 20);
});
