//! Domain lists: the `example.com,~sub.example.com##…` prefix of cosmetic
//! rules and the `$domain=a.com|~b.com` family of network options.

use std::net::IpAddr;

use serde::Serialize;
use sinkhole_core::Domain;

use crate::ParseError;

/// One hostname condition.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum HostPattern {
    /// `example.com`: the name and every name below it. Normalized (lowercase,
    /// punycode).
    Domain(String),
    /// `example.*`: `example` directly under any public suffix, e.g.
    /// `example.com` and `example.co.uk` (uBO "entity" syntax).
    Entity(String),
    /// `/^ads\d+\.example\.com$/`: a regular expression on the hostname
    /// (uBO). The source is kept as written, without the slashes.
    Regex(String),
    /// `127.0.0.1`, `[::1]`: a page or request served from an IP literal.
    /// Matches that address only.
    Ip(IpAddr),
}

/// A possibly negated hostname condition.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub struct DomainSpec {
    /// `~example.com`: the rule does *not* apply there.
    pub negated: bool,
    pub host: HostPattern,
}

/// Splits `s` on `sep`, keeping `/regex/` items whole even when the regex
/// contains `sep` (`/a|b/` in `$domain=`, `/a{1,3}/` in a cosmetic prefix).
pub(crate) fn split_items(s: &str, sep: u8) -> Vec<&str> {
    let bytes = s.as_bytes();
    let mut items = Vec::new();
    let mut start = 0;
    let mut i = 0;
    while i <= bytes.len() {
        // At an item start, a `/` (after an optional `~`) opens a regex.
        let body = start + usize::from(bytes.get(start) == Some(&b'~'));
        if i == body
            && bytes.get(i) == Some(&b'/')
            && let Some(close) = regex_end(bytes, i, sep)
        {
            i = close + 1;
            continue;
        }
        if i == bytes.len() || bytes[i] == sep {
            items.push(&s[start..i]);
            start = i + 1;
        }
        i += 1;
    }
    items
}

/// Index of the `/` closing the regex that opens at `open`: the first
/// unescaped `/` followed by `sep` or the end of input.
fn regex_end(bytes: &[u8], open: usize, sep: u8) -> Option<usize> {
    let mut i = open + 1;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' => i += 2,
            b'/' if i > open + 1 && bytes.get(i + 1).is_none_or(|&b| b == sep) => {
                return Some(i);
            }
            _ => i += 1,
        }
    }
    None
}

/// Parses a `sep`-separated domain list. `what` names the list in errors.
pub(crate) fn parse_domain_list(
    s: &str,
    sep: u8,
    what: &str,
) -> Result<Vec<DomainSpec>, ParseError> {
    split_items(s, sep)
        .into_iter()
        .map(|item| parse_domain_spec(item.trim(), what))
        .collect()
}

pub(crate) fn parse_domain_spec(item: &str, what: &str) -> Result<DomainSpec, ParseError> {
    let (negated, body) = match item.strip_prefix('~') {
        Some(rest) => (true, rest),
        None => (false, item),
    };
    if body.is_empty() {
        return Err(ParseError::invalid(format!("empty entry in {what}")));
    }
    let host = if body.len() >= 2 && body.starts_with('/') && body.ends_with('/') {
        let source = &body[1..body.len() - 1];
        if source.is_empty() {
            return Err(ParseError::invalid(format!("empty regex in {what}")));
        }
        HostPattern::Regex(source.to_owned())
    } else if let Some(entity) = body.strip_suffix(".*") {
        let name = Domain::parse(entity)
            .map_err(|e| ParseError::invalid(format!("bad entity {body:?} in {what}: {e}")))?;
        HostPattern::Entity(name.as_str().to_owned())
    } else {
        // IP literals are rare, so they are tried only once a name fails.
        match Domain::parse(body) {
            Ok(name) => HostPattern::Domain(name.as_str().to_owned()),
            Err(e) => match parse_ip(body) {
                Some(ip) => HostPattern::Ip(ip),
                None => {
                    return Err(ParseError::invalid(format!(
                        "bad domain {body:?} in {what}: {e}"
                    )));
                }
            },
        }
    };
    Ok(DomainSpec { negated, host })
}

/// `192.0.2.1`, `[2001:db8::1]` or bare `2001:db8::1`.
fn parse_ip(s: &str) -> Option<IpAddr> {
    let bare = s
        .strip_prefix('[')
        .and_then(|r| r.strip_suffix(']'))
        .unwrap_or(s);
    let ip: IpAddr = bare.parse().ok()?;
    // Brackets belong to IPv6 only.
    (bare.len() == s.len() || ip.is_ipv6()).then_some(ip)
}

/// Whether `prefix` could be the domain list in front of a cosmetic
/// separator. Used to tell `example.com##.ad` from a URL containing `##`.
pub(crate) fn plausible_cosmetic_prefix(prefix: &str) -> bool {
    split_items(prefix, b',').into_iter().all(|item| {
        let item = item.trim().strip_prefix('~').unwrap_or(item.trim());
        (item.len() >= 2 && item.starts_with('/') && item.ends_with('/'))
            || item.chars().all(|c| {
                c.is_alphanumeric() || matches!(c, '.' | '-' | '_' | '*' | '[' | ']' | ':')
            })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dom(s: &str) -> HostPattern {
        HostPattern::Domain(s.into())
    }

    #[test]
    fn splits_plain_lists() {
        assert_eq!(split_items("a.com|~b.com", b'|'), ["a.com", "~b.com"]);
        assert_eq!(split_items("", b'|'), [""]);
    }

    #[test]
    fn keeps_regex_items_whole() {
        assert_eq!(split_items("/a|b/|c.com", b'|'), ["/a|b/", "c.com"]);
        assert_eq!(split_items("~/x{1,2}/,y.com", b','), ["~/x{1,2}/", "y.com"]);
        assert_eq!(split_items("/a\\/b|c/", b'|'), ["/a\\/b|c/"]);
        // An unterminated regex is just text.
        assert_eq!(split_items("/a|b", b'|'), ["/a", "b"]);
    }

    #[test]
    fn parses_specs() {
        let l =
            parse_domain_list("Example.COM|~sub.example.com|google.*|/^ad\\d/", b'|', "t").unwrap();
        assert_eq!(
            l[0],
            DomainSpec {
                negated: false,
                host: dom("example.com")
            }
        );
        assert_eq!(
            l[1],
            DomainSpec {
                negated: true,
                host: dom("sub.example.com")
            }
        );
        assert_eq!(l[2].host, HostPattern::Entity("google".into()));
        assert_eq!(l[3].host, HostPattern::Regex("^ad\\d".into()));
    }

    #[test]
    fn ip_literals() {
        let l = parse_domain_list("~127.0.0.1|~[::1]|::|~local", b'|', "t").unwrap();
        assert_eq!(l[0].host, HostPattern::Ip("127.0.0.1".parse().unwrap()));
        assert!(l[0].negated);
        assert_eq!(l[1].host, HostPattern::Ip("::1".parse().unwrap()));
        assert_eq!(l[2].host, HostPattern::Ip("::".parse().unwrap()));
        assert_eq!(l[3].host, dom("local"));
        assert!(parse_domain_list("[127.0.0.1]", b'|', "t").is_err());
        assert!(parse_domain_list("[::1", b'|', "t").is_err());
        assert!(plausible_cosmetic_prefix("194.233.68.230,[::1]"));
    }

    #[test]
    fn idn_domains_become_punycode() {
        let l = parse_domain_list("bücher.de", b',', "t").unwrap();
        assert_eq!(l[0].host, dom("xn--bcher-kva.de"));
    }

    #[test]
    fn rejects_bad_entries() {
        assert!(parse_domain_list("a.com||b.com", b'|', "t").is_err());
        assert!(parse_domain_list("~", b'|', "t").is_err());
        assert!(parse_domain_list("a b.com", b'|', "t").is_err());
        assert!(parse_domain_list("//", b'|', "t").is_err());
    }

    #[test]
    fn cosmetic_prefix_plausibility() {
        assert!(plausible_cosmetic_prefix(""));
        assert!(plausible_cosmetic_prefix(
            "example.com,~www.example.com,google.*"
        ));
        assert!(plausible_cosmetic_prefix("bücher.de"));
        assert!(plausible_cosmetic_prefix("/^x{1,2}\\.com$/"));
        assert!(!plausible_cosmetic_prefix("||example.com/"));
        assert!(!plausible_cosmetic_prefix("example.com/path"));
    }
}
