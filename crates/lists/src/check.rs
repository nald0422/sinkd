//! Deciding whether a download is a list worth replacing the last good copy.
//!
//! A refresh that fails outright (a network error, an HTTP error status) is
//! easy to spot. The dangerous failures arrive as `200 OK`: a captive
//! portal's login page, a CDN's error page, an empty file pushed by mistake.
//! Loading one of those would silently stop blocking, so a download must
//! look like a list before it replaces the copy in use.

use std::time::Duration;

use sinkd_filters::is_comment;

/// Largest list accepted, after decompression. The biggest DNS lists in
/// common use are around 30 MB; this leaves room and still caps the memory
/// a hostile or broken server can make us allocate.
pub const MAX_LIST_BYTES: usize = 64 << 20;

/// A list may shrink to this fraction of the previous version's rules
/// before it is treated as broken.
const MIN_KEPT: f64 = 0.10;

/// Below this many rules, any change in size is believable.
const SMALL_LIST: usize = 100;

/// How far into a list to look for a NUL byte, and for header fields.
const SNIFF_BYTES: usize = 64 << 10;
const HEADER_LINES: usize = 100;

/// `! Expires:` values are clamped to this range: lists that ask to be
/// checked every minute would hammer their host, and a list that asks for a
/// year would never get fixes.
const MIN_EXPIRES: Duration = Duration::from_secs(3600);
const MAX_EXPIRES: Duration = Duration::from_secs(14 * 86_400);

/// What a list contains, as far as scheduling and the checks care.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Summary {
    /// Lines that are neither blank nor comments.
    pub rules: usize,
    /// How often the list asks to be checked (`! Expires: 4 days`).
    pub expires: Option<Duration>,
}

/// Why a download was not accepted.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Rejection {
    #[error("got an HTML or XML page instead of a list (a captive portal or an error page?)")]
    Markup,
    #[error("got binary data instead of a list")]
    Binary,
    #[error("contains no rules")]
    Empty,
    #[error(
        "shrank from {from} to {to} rules, which looks broken; \
         `sinkd update --force` accepts it anyway"
    )]
    Shrank { from: usize, to: usize },
}

/// Counts the rules and reads the header of a list.
pub fn summarize(body: &[u8]) -> Summary {
    let text = String::from_utf8_lossy(body);
    let mut summary = Summary {
        rules: 0,
        expires: None,
    };
    for (index, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if is_comment(line) {
            if index < HEADER_LINES && summary.expires.is_none() {
                summary.expires = expires(line);
            }
        } else {
            summary.rules += 1;
        }
    }
    summary
}

/// Checks a download. `previous_rules` is the rule count of the copy it
/// would replace. `force` skips only the shrink check: markup, binary data
/// and empty files are never lists.
pub fn check(
    body: &[u8],
    previous_rules: Option<usize>,
    force: bool,
) -> Result<Summary, Rejection> {
    let head = &body[..body.len().min(SNIFF_BYTES)];
    let first = head
        .strip_prefix("\u{feff}".as_bytes())
        .unwrap_or(head)
        .iter()
        .find(|b| !b.is_ascii_whitespace());
    // No list syntax starts a line with `<`; every markup document does.
    if first == Some(&b'<') {
        return Err(Rejection::Markup);
    }
    if head.contains(&0) {
        return Err(Rejection::Binary);
    }
    let summary = summarize(body);
    if summary.rules == 0 {
        return Err(Rejection::Empty);
    }
    if let Some(from) = previous_rules
        && !force
        && from >= SMALL_LIST
        && (summary.rules as f64) < from as f64 * MIN_KEPT
    {
        return Err(Rejection::Shrank {
            from,
            to: summary.rules,
        });
    }
    Ok(summary)
}

/// Parses an `Expires` header comment: `! Expires: 4 days (update
/// frequency)`, `# Expires: 12 hours`, `! Expires: 1d`.
fn expires(line: &str) -> Option<Duration> {
    let rest = line.trim_start_matches(['!', '#']).trim_start();
    let (key, value) = rest.split_once(':')?;
    if !key.trim().eq_ignore_ascii_case("expires") {
        return None;
    }
    let value = value.trim();
    let digits = value.bytes().take_while(u8::is_ascii_digit).count();
    let n: u64 = value[..digits].parse().ok()?;
    let unit = value[digits..].trim_start();
    let unit_secs = match unit.bytes().next()?.to_ascii_lowercase() {
        b'd' => 86_400,
        b'h' => 3600,
        _ => return None,
    };
    let secs = n.checked_mul(unit_secs)?;
    Some(Duration::from_secs(secs).clamp(MIN_EXPIRES, MAX_EXPIRES))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules(n: usize) -> Vec<u8> {
        (0..n)
            .map(|i| format!("||ads{i}.example^\n"))
            .collect::<String>()
            .into_bytes()
    }

    #[test]
    fn counts_rules_not_comments() {
        let s =
            summarize(b"! Title: t\n# hosts comment\n\n0.0.0.0 a.example\n||b.example^\n##.ad\n");
        assert_eq!(s.rules, 3);
        assert_eq!(s.expires, None);
    }

    #[test]
    fn reads_expires() {
        let day = Duration::from_secs(86_400);
        let cases = [
            ("! Expires: 4 days (update frequency)", Some(day * 4)),
            ("! Expires: 1 day", Some(day)),
            ("# Expires: 12 hours", Some(Duration::from_secs(12 * 3600))),
            ("! expires: 2d", Some(day * 2)),
            ("! Expires: 5 minutes", None),
            ("! Expires: soon", None),
            ("! Expiration: 1 day", None),
            // Clamped to [1 hour, 14 days].
            ("! Expires: 0 hours", Some(MIN_EXPIRES)),
            ("! Expires: 365 days", Some(MAX_EXPIRES)),
            ("! Expires: 99999999999999999999 days", None),
        ];
        for (line, want) in cases {
            assert_eq!(expires(line), want, "{line}");
        }
        let s = summarize(b"[Adblock Plus 2.0]\n! Expires: 4 days\n||a.example^\n");
        assert_eq!(s.expires, Some(day * 4));
    }

    #[test]
    fn expires_outside_the_header_is_ignored() {
        let mut body = rules(HEADER_LINES);
        body.extend_from_slice(b"! Expires: 1 day\n");
        assert_eq!(summarize(&body).expires, None);
    }

    #[test]
    fn rejects_pages_and_binaries() {
        for page in [
            &b"<!DOCTYPE html><html><body>Log in to the Wi-Fi</body></html>"[..],
            b"\n  <html>",
            b"\xef\xbb\xbf<?xml version=\"1.0\"?><Error><Code>AccessDenied</Code></Error>",
        ] {
            assert_eq!(check(page, None, true), Err(Rejection::Markup));
        }
        assert_eq!(
            check(b"\x1f\x8b\x08\x00\x00\x00\x00\x00", None, true),
            Err(Rejection::Binary)
        );
        assert_eq!(
            check(b"! only comments\n\n# here\n", None, true),
            Err(Rejection::Empty)
        );
        assert_eq!(check(b"", None, true), Err(Rejection::Empty));
    }

    #[test]
    fn rejects_a_collapse_unless_forced() {
        let small = rules(50);
        assert_eq!(
            check(&small, Some(1000), false),
            Err(Rejection::Shrank { from: 1000, to: 50 })
        );
        assert_eq!(check(&small, Some(1000), true).map(|s| s.rules), Ok(50));
        // Shrinking to 10% or more is believable, and so is any change in a
        // small list.
        assert!(check(&rules(100), Some(1000), false).is_ok());
        assert!(check(&rules(1), Some(99), false).is_ok());
        assert!(check(&small, None, false).is_ok());
    }
}
