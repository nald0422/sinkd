//! The page index lookup, for the extension's service worker.
//!
//! A five-function ABI instead of wasm-bindgen. The interface is small (bytes
//! in, a string out), and this keeps the module free of imports and of
//! generated glue that must match a tool's version. The worker's side is
//! `extension/src/engine.ts`.
//!
//! 1. `input(len)` makes room for `len` bytes and returns their address;
//!    JavaScript writes the bytes there.
//! 2. `load()` reads the index from those bytes (1 on success).
//! 3. `page(mask)` looks up the hostname written as input; `generic(mask,
//!    always)` looks up `hostname\ntoken\ntoken…`. Both return the length
//!    of the result.
//! 4. `output()` returns the result's address: UTF-8, JSON for `page`, CSS
//!    for `generic`.
//!
//! The exports carry `#[unsafe(no_mangle)]`, which is how a wasm export
//! gets its name; that attribute is all the crate allows of `unsafe_code`.
//! There is no `unsafe` block: JavaScript writes into a buffer this module
//! owns and hands out, and Rust only reads it through the Vec.

use std::sync::{Mutex, MutexGuard};

use sinkhole_core::page::PageIndex;

static INPUT: Mutex<Vec<u8>> = Mutex::new(Vec::new());
static OUTPUT: Mutex<Vec<u8>> = Mutex::new(Vec::new());
static INDEX: Mutex<Option<PageIndex>> = Mutex::new(None);

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

fn set_output(bytes: Vec<u8>) -> u32 {
    let len = u32::try_from(bytes.len()).unwrap_or(0);
    *lock(&OUTPUT) = bytes;
    len
}

fn input_string() -> String {
    String::from_utf8_lossy(&lock(&INPUT)).into_owned()
}

#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub extern "C" fn input(len: u32) -> u32 {
    let mut buffer = lock(&INPUT);
    buffer.clear();
    buffer.resize(len as usize, 0);
    buffer.as_mut_ptr() as usize as u32
}

#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub extern "C" fn output() -> u32 {
    lock(&OUTPUT).as_ptr() as usize as u32
}

#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub extern "C" fn load() -> u32 {
    let bytes = std::mem::take(&mut *lock(&INPUT));
    u32::from(load_bytes(&bytes))
}

#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub extern "C" fn page(mask: u32) -> u32 {
    let hostname = input_string();
    set_output(page_json(&hostname, mask as u8).into_bytes())
}

#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub extern "C" fn generic(mask: u32, always: u32) -> u32 {
    let text = input_string();
    let mut lines = text.split('\n');
    let hostname = lines.next().unwrap_or("");
    set_output(generic_css(hostname, mask as u8, lines, always != 0).into_bytes())
}

/// Replaces the loaded index. False if the bytes are not one.
pub fn load_bytes(bytes: &[u8]) -> bool {
    match PageIndex::from_bytes(bytes) {
        Ok(index) => {
            *lock(&INDEX) = Some(index);
            true
        }
        Err(_) => false,
    }
}

/// `{"css": "…", "procedural": […], "generic": true}` for a hostname.
pub fn page_json(hostname: &str, mask: u8) -> String {
    let index = lock(&INDEX);
    let Some(index) = index.as_ref() else {
        return r#"{"css":"","procedural":[],"generic":false}"#.to_owned();
    };
    let page = index.page(hostname, mask);
    let mut json = String::with_capacity(page.css.len() + 64);
    json.push_str(r#"{"css":"#);
    push_json_string(&mut json, &page.css);
    json.push_str(r#","procedural":["#);
    // Each procedural rule is JSON already.
    json.push_str(&page.procedural.join(","));
    json.push_str(r#"],"generic":"#);
    json.push_str(if page.generic { "true" } else { "false" });
    json.push('}');
    json
}

/// Generic hiding CSS for the tokens (`.class`, `#id`) seen in a page.
pub fn generic_css<'t>(
    hostname: &str,
    mask: u8,
    tokens: impl IntoIterator<Item = &'t str>,
    always: bool,
) -> String {
    let index = lock(&INDEX);
    match index.as_ref() {
        Some(index) => index.generic_css(hostname, mask, tokens, always),
        None => String::new(),
    }
}

fn push_json_string(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;
    use sinkhole_core::page::{GENERICHIDE, PageIndexBuilder};

    fn index() -> Vec<u8> {
        let mut b = PageIndexBuilder::new();
        b.hide("example.com", "div[title=\"a \\\"quoted\\\" b\"]", 1);
        b.procedural(
            "example.com",
            r#"{"selector":{"steps":[]},"action":{"kind":"hide"}}"#,
            1,
        );
        b.generic(".ad-box", Some(".ad-box"), 1);
        b.flags("nogeneric.example", GENERICHIDE, 1);
        b.finish().to_bytes()
    }

    #[test]
    fn answers_as_json_and_css() {
        assert!(!load_bytes(b"not an index"));
        assert!(load_bytes(&index()));
        let json = page_json("www.example.com", 1);
        assert!(
            json.starts_with(
                r#"{"css":"div[title=\"a \\\"quoted\\\" b\"]{display:none!important}\n""#
            ),
            "{json}"
        );
        assert!(
            json.contains(r#""procedural":[{"selector":{"steps":[]},"action":{"kind":"hide"}}]"#)
        );
        assert!(json.ends_with(r#""generic":true}"#));
        assert!(page_json("nogeneric.example", 1).ends_with(r#""generic":false}"#));
        assert_eq!(
            generic_css("news.example", 1, [".ad-box"], false),
            ".ad-box{display:none!important}\n"
        );
        assert_eq!(
            generic_css("news.example", 2, [".ad-box"], false),
            "",
            "other ruleset"
        );
    }
}
