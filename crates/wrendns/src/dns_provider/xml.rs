// SPDX-License-Identifier: AGPL-3.0-or-later
//! REQ: CLD-904 (T36.10b step b4; ADR-1084 point 6) - a small, strict XML reader for the few
//! documents a provider answers with (Route 53's responses): elements, character data, the five
//! predefined entities and numeric references, and attributes that are read and dropped. No XML
//! crate is in the tree.
//!
//! It is strict on purpose. A document type, an entity declaration, a CDATA section, a comment or a
//! processing instruction other than the leading declaration is refused, so there is nothing to
//! expand and nothing to loop on. Depth, node count and size are bounded.

use std::fmt;

/// The deepest nesting accepted.
const MAX_DEPTH: usize = 16;
/// The most elements accepted.
const MAX_NODES: usize = 200_000;
/// The longest input accepted (the HTTP client's cap is below this).
const MAX_INPUT: usize = 4 * 1024 * 1024;

/// An element: its local name (any namespace prefix dropped), its character data and its children.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Node {
    pub(crate) name: String,
    pub(crate) text: String,
    pub(crate) children: Vec<Node>,
}

/// Why a document was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct XmlError(&'static str);

impl fmt::Display for XmlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "not a document WrenDNS reads: {}", self.0)
    }
}

impl Node {
    /// The first child of this name.
    pub(crate) fn child(&self, name: &str) -> Option<&Node> {
        self.children.iter().find(|c| c.name == name)
    }

    /// Every child of this name.
    pub(crate) fn all<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a Node> {
        self.children.iter().filter(move |c| c.name == name)
    }

    /// The trimmed text of the element at this path of child names.
    pub(crate) fn text_at(&self, path: &[&str]) -> Option<&str> {
        let mut n = self;
        for p in path {
            n = n.child(p)?;
        }
        Some(n.text.trim())
    }
}

/// `s` as XML character data or an attribute value: the five characters that matter, escaped.
pub(crate) fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            c => out.push(c),
        }
    }
    out
}

struct Parser<'a> {
    s: &'a [u8],
    p: usize,
    nodes: usize,
}

fn name_start(b: u8) -> bool {
    b.is_ascii_alphabetic() || b == b'_'
}

fn name_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.' | b':')
}

impl Parser<'_> {
    fn eof(&self) -> bool {
        self.p >= self.s.len()
    }

    fn peek(&self) -> Option<u8> {
        self.s.get(self.p).copied()
    }

    fn starts(&self, t: &[u8]) -> bool {
        self.s[self.p..].starts_with(t)
    }

    fn skip_space(&mut self) {
        while self.peek().is_some_and(|b| b.is_ascii_whitespace()) {
            self.p += 1;
        }
    }

    fn name(&mut self) -> Result<String, XmlError> {
        let start = self.p;
        if !self.peek().is_some_and(name_start) {
            return Err(XmlError("a name was expected"));
        }
        while self.peek().is_some_and(name_char) {
            self.p += 1;
        }
        let full = std::str::from_utf8(&self.s[start..self.p]).map_err(|_| XmlError("a name"))?;
        // The namespace prefix is dropped: the documents are matched by local name.
        Ok(full.rsplit(':').next().unwrap_or(full).to_owned())
    }

    /// Decodes character data (or an attribute value) up to `stop`.
    fn text_until(&mut self, stop: u8) -> Result<String, XmlError> {
        let mut out: Vec<u8> = Vec::new();
        while let Some(b) = self.peek() {
            if b == stop {
                break;
            }
            if b == b'<' {
                return Err(XmlError("a `<` inside text"));
            }
            if b == b'&' {
                let rest = &self.s[self.p..];
                let end = rest
                    .iter()
                    .take(12)
                    .position(|c| *c == b';')
                    .ok_or(XmlError("an unfinished entity"))?;
                let ent = std::str::from_utf8(&rest[1..end]).map_err(|_| XmlError("an entity"))?;
                let ch = match ent {
                    "amp" => '&',
                    "lt" => '<',
                    "gt" => '>',
                    "quot" => '"',
                    "apos" => '\'',
                    _ => {
                        let n = if let Some(h) = ent.strip_prefix("#x") {
                            u32::from_str_radix(h, 16).ok()
                        } else if let Some(d) = ent.strip_prefix('#') {
                            d.parse::<u32>().ok()
                        } else {
                            None
                        };
                        n.and_then(char::from_u32)
                            .filter(|c| !c.is_control() || matches!(c, '\t' | '\n' | '\r'))
                            .ok_or(XmlError("an unknown entity"))?
                    }
                };
                let mut buf = [0u8; 4];
                out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
                self.p += end + 1;
                continue;
            }
            out.push(b);
            self.p += 1;
        }
        String::from_utf8(out).map_err(|_| XmlError("text that is not UTF-8"))
    }

    fn attributes(&mut self) -> Result<(), XmlError> {
        loop {
            self.skip_space();
            match self.peek() {
                Some(b'>' | b'/') => return Ok(()),
                Some(_) => {
                    self.name()?;
                    self.skip_space();
                    if self.peek() != Some(b'=') {
                        return Err(XmlError("an attribute without a value"));
                    }
                    self.p += 1;
                    self.skip_space();
                    let q = self.peek().ok_or(XmlError("an unfinished attribute"))?;
                    if q != b'"' && q != b'\'' {
                        return Err(XmlError("an unquoted attribute"));
                    }
                    self.p += 1;
                    self.text_until(q)?;
                    if self.peek() != Some(q) {
                        return Err(XmlError("an unfinished attribute"));
                    }
                    self.p += 1;
                }
                None => return Err(XmlError("an unfinished tag")),
            }
        }
    }

    fn element(&mut self, depth: usize) -> Result<Node, XmlError> {
        if depth > MAX_DEPTH {
            return Err(XmlError("nested too deeply"));
        }
        self.nodes += 1;
        if self.nodes > MAX_NODES {
            return Err(XmlError("too many elements"));
        }
        // At the `<`.
        self.p += 1;
        let name = self.name()?;
        self.attributes()?;
        let mut node = Node {
            name,
            ..Node::default()
        };
        if self.starts(b"/>") {
            self.p += 2;
            return Ok(node);
        }
        if self.peek() != Some(b'>') {
            return Err(XmlError("a malformed tag"));
        }
        self.p += 1;
        loop {
            if self.eof() {
                return Err(XmlError("an element is not closed"));
            }
            if self.starts(b"</") {
                self.p += 2;
                let close = self.name()?;
                self.skip_space();
                if self.peek() != Some(b'>') || close != node.name {
                    return Err(XmlError("a closing tag that does not match"));
                }
                self.p += 1;
                return Ok(node);
            }
            if self.starts(b"<!") || self.starts(b"<?") {
                return Err(XmlError("a comment, CDATA section or instruction"));
            }
            if self.peek() == Some(b'<') {
                let child = self.element(depth + 1)?;
                node.children.push(child);
            } else {
                let t = self.text_until(b'<')?;
                node.text.push_str(&t);
            }
        }
    }
}

/// Reads one document.
pub(crate) fn parse(input: &[u8]) -> Result<Node, XmlError> {
    if input.len() > MAX_INPUT {
        return Err(XmlError("too long"));
    }
    let mut p = Parser {
        s: input,
        p: 0,
        nodes: 0,
    };
    // A byte-order mark, then the one declaration allowed.
    if p.starts(b"\xEF\xBB\xBF") {
        p.p += 3;
    }
    p.skip_space();
    if p.starts(b"<?xml") {
        let end = input[p.p..]
            .windows(2)
            .position(|w| w == b"?>")
            .ok_or(XmlError("an unfinished declaration"))?;
        p.p += end + 2;
    }
    p.skip_space();
    if p.starts(b"<!") || p.starts(b"<?") {
        return Err(XmlError("a document type or instruction"));
    }
    if p.peek() != Some(b'<') {
        return Err(XmlError("no root element"));
    }
    let root = p.element(0)?;
    p.skip_space();
    if !p.eof() {
        return Err(XmlError("text after the root element"));
    }
    Ok(root)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// REQ: CLD-904 - the reader takes a Route 53 style answer and refuses what could expand or loop.
    #[test]
    fn cld_904_xml_reads_a_document_and_refuses_the_dangerous_ones() {
        let doc = br#"<?xml version="1.0" encoding="UTF-8"?>
<ListResourceRecordSetsResponse xmlns="https://route53.amazonaws.com/doc/2013-04-01/"><ResourceRecordSets><ResourceRecordSet><Name>a.example.net.</Name><Value>&quot;x&quot; &amp; &#65;&#x42;</Value><Empty/></ResourceRecordSet></ResourceRecordSets></ListResourceRecordSetsResponse>"#;
        let n = parse(doc).unwrap();
        assert_eq!(n.name, "ListResourceRecordSetsResponse");
        let s = n
            .child("ResourceRecordSets")
            .unwrap()
            .child("ResourceRecordSet")
            .unwrap();
        assert_eq!(s.text_at(&["Name"]), Some("a.example.net."));
        assert_eq!(s.text_at(&["Value"]), Some("\"x\" & AB"));
        assert!(s.child("Empty").is_some());
        for bad in [
            &b"<!DOCTYPE a [<!ENTITY x \"y\">]><a/>"[..],
            b"<a><![CDATA[x]]></a>",
            b"<a><!-- c --></a>",
            b"<a>&unknown;</a>",
            b"<a>&#0;</a>",
            b"<a><b></a></b>",
            b"<a>",
            b"<a/><b/>",
            b"<a x=1/>",
            b"text",
            b"<a><?pi x?></a>",
        ] {
            assert!(parse(bad).is_err(), "{}", String::from_utf8_lossy(bad));
        }
        let deep = format!("{}{}", "<a>".repeat(40), "</a>".repeat(40));
        assert!(parse(deep.as_bytes()).is_err(), "depth is bounded");
        assert!(
            parse(&vec![b' '; MAX_INPUT + 1]).is_err(),
            "size is bounded"
        );
        assert_eq!(escape("a&b<c>\"d'"), "a&amp;b&lt;c&gt;&quot;d&apos;");
    }
}
