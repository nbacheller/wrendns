//! REQ: OPS-011 (ADR-156), NFR-004 — arbitrary text through the support package's redactor at
//! every level: it must never panic, a secret planted in the middle of the input (next to whatever
//! bytes the fuzzer chose) must not survive, and the same input and key must give the same output.
#![no_main]

use libfuzzer_sys::fuzz_target;
use wrendns_support::Level;
use wrendns_support::pseudo::{Category, Pseudonyms};
use wrendns_support::redact::{Known, Redactor};

const SECRET: &str = "Zq9-planted-SECRET-77";

fn redact(level: Level, text: &str) -> String {
    let mut known = Known::new();
    known.add_secret(SECRET);
    known.add(Category::Device, "tv-room");
    let mut r = Redactor::new(level, Pseudonyms::new([7; 32]));
    r.set_known(&known).expect("two known values fit one search");
    r.text(text)
}

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let mut mid = text.len() / 2;
    while !text.is_char_boundary(mid) {
        mid -= 1;
    }
    let planted = format!("{}{SECRET}{}", &text[..mid], &text[mid..]);
    for level in [Level::Strict, Level::Standard, Level::Off] {
        let out = redact(level, &planted);
        assert!(!out.contains(SECRET), "{level:?}: the planted secret survived in {out:?}");
        assert_eq!(out, redact(level, &planted), "{level:?}: not deterministic");
    }
});
