//! Domain-name normalization.
//!
//! Every name that reaches the matcher, whether from a filter list, the config
//! file or a DNS query, is normalized the same way, so matching is plain byte
//! equality on label-aligned suffixes:
//!
//! * surrounding whitespace and one trailing dot are removed
//!   (`Example.COM.` → `example.com`);
//! * ASCII is lowercased;
//! * non-ASCII names are converted to punycode with UTS-46 (`bücher.de` →
//!   `xn--bcher-kva.de`), which is what appears on the wire;
//! * the result must look like a DNS name: labels of 1–63 bytes drawn from
//!   `[a-z0-9_-]`, at most 253 bytes in total, and not an IP address.
//!
//! Underscores are accepted because they occur in real DNS names (`_dmarc`,
//! service labels, some tracker hosts), even though they are not valid in
//! hostnames.
//!
//! [`Domain`] is the validated, owned form used for list entries. [`QueryName`]
//! is the allocation-free form used on the resolver hot path; it only folds
//! case, because a name that came off the wire has to be matched as-is.

use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

/// Longest presentation-format name without the trailing dot (RFC 1035 §2.3.4).
pub const MAX_NAME_LEN: usize = 253;
/// Longest single label (RFC 1035 §2.3.4).
pub const MAX_LABEL_LEN: usize = 63;

/// Why a string is not an acceptable domain name.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DomainError {
    #[error("empty domain name")]
    Empty,
    #[error("domain name is longer than {MAX_NAME_LEN} bytes")]
    TooLong,
    #[error("empty label (leading dot or consecutive dots)")]
    EmptyLabel,
    #[error("label is longer than {MAX_LABEL_LEN} bytes")]
    LabelTooLong,
    #[error("invalid character {0:?} in domain name")]
    InvalidChar(char),
    #[error("{0} is an IP address, not a domain name")]
    IpAddress(String),
    #[error("internationalized name could not be converted to punycode")]
    Idna,
}

/// A normalized, validated domain name: lowercase ASCII, no trailing dot.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Domain(Box<str>);

impl Domain {
    /// Normalizes and validates `input`. See the module docs for the rules.
    pub fn parse(input: &str) -> Result<Self, DomainError> {
        let trimmed = input.trim();
        let name = trimmed.strip_suffix('.').unwrap_or(trimmed);
        if name.is_empty() {
            return Err(DomainError::Empty);
        }
        // Hosts files and sloppy lists put addresses where names belong. Catch
        // them before charset validation so the error says what happened.
        if name.parse::<IpAddr>().is_ok() {
            return Err(DomainError::IpAddress(name.to_owned()));
        }

        let lowered = if name.is_ascii() {
            name.to_ascii_lowercase()
        } else {
            to_ascii_idna(name)?
        };
        // IDNA maps full-width digits and dots to ASCII, so `１.２.３.４` only
        // becomes recognizable as an address now. Checking again keeps
        // `parse(parse(x)) == parse(x)`.
        if lowered.parse::<IpAddr>().is_ok() {
            return Err(DomainError::IpAddress(lowered));
        }
        validate_ascii(&lowered)?;
        Ok(Domain(lowered.into_boxed_str()))
    }

    /// The normalized name.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The parent domain (`a.b.c` → `b.c`), or `None` for a single label.
    pub fn parent(&self) -> Option<&str> {
        self.0.split_once('.').map(|(_, rest)| rest)
    }

    /// Iterates over this name and each of its parents, most specific first:
    /// `a.b.c`, `b.c`, `c`.
    pub fn suffixes(&self) -> impl Iterator<Item = &str> {
        label_suffixes(&self.0)
    }
}

impl FromStr for Domain {
    type Err = DomainError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Domain::parse(s)
    }
}

impl AsRef<str> for Domain {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Domain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for Domain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Domain({:?})", &*self.0)
    }
}

/// Iterates over `name` and each label-aligned suffix of it, most specific
/// first. `name` is not validated.
pub fn label_suffixes(name: &str) -> impl Iterator<Item = &str> {
    let mut next = Some(name);
    std::iter::from_fn(move || {
        let current = next?;
        next = current.split_once('.').map(|(_, rest)| rest);
        Some(current)
    })
}

/// Checks an already-lowercased ASCII name against the charset and length rules.
fn validate_ascii(name: &str) -> Result<(), DomainError> {
    if name.len() > MAX_NAME_LEN {
        return Err(DomainError::TooLong);
    }
    for label in name.split('.') {
        if label.is_empty() {
            return Err(DomainError::EmptyLabel);
        }
        if label.len() > MAX_LABEL_LEN {
            return Err(DomainError::LabelTooLong);
        }
        if let Some(bad) = label
            .chars()
            .find(|c| !matches!(c, 'a'..='z' | '0'..='9' | '-' | '_'))
        {
            return Err(DomainError::InvalidChar(bad));
        }
    }
    Ok(())
}

#[cfg(feature = "idna")]
fn to_ascii_idna(name: &str) -> Result<String, DomainError> {
    // UTS-46 non-transitional processing, as browsers do (`ß` stays `ß`, then
    // becomes punycode, rather than mapping to `ss`). It also lowercases and
    // maps full-width dots.
    idna::domain_to_ascii(name).map_err(|_| DomainError::Idna)
}

#[cfg(not(feature = "idna"))]
fn to_ascii_idna(_name: &str) -> Result<String, DomainError> {
    Err(DomainError::Idna)
}

/// A query name folded to lowercase on the stack, for the resolver hot path.
///
/// Unlike [`Domain`] this does not validate the charset: a name off the wire
/// may legally contain any byte, and it still has to be matched, because a
/// blocked parent must block an oddly named child. Bytes that cannot appear in
/// a list entry simply never compare equal to one.
#[derive(Clone)]
pub struct QueryName {
    len: u8,
    buf: [u8; MAX_NAME_LEN],
}

impl QueryName {
    /// Lowercases ASCII and strips one trailing dot. Returns `None` for an empty
    /// name (the root) or one longer than 253 bytes.
    pub fn new(name: &str) -> Option<Self> {
        let name = name.strip_suffix('.').unwrap_or(name);
        if name.is_empty() || name.len() > MAX_NAME_LEN {
            return None;
        }
        let mut buf = [0u8; MAX_NAME_LEN];
        for (dst, src) in buf.iter_mut().zip(name.bytes()) {
            *dst = src.to_ascii_lowercase();
        }
        Some(QueryName {
            len: name.len() as u8,
            buf,
        })
    }

    /// The folded name.
    pub fn as_str(&self) -> &str {
        // Lowercasing ASCII bytes inside valid UTF-8 keeps it valid UTF-8, so
        // this cannot fail; fall back to "" rather than panic regardless.
        std::str::from_utf8(&self.buf[..self.len as usize]).unwrap_or_default()
    }
}

impl fmt::Debug for QueryName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "QueryName({:?})", self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn norm(s: &str) -> Result<String, DomainError> {
        Domain::parse(s).map(|d| d.as_str().to_owned())
    }

    #[test]
    fn lowercases_and_strips_trailing_dot() {
        assert_eq!(norm("Ads.Example.COM.").unwrap(), "ads.example.com");
        assert_eq!(norm("  example.com \t").unwrap(), "example.com");
    }

    #[test]
    fn only_one_trailing_dot_is_stripped() {
        assert_eq!(norm("example.com.."), Err(DomainError::EmptyLabel));
    }

    #[test]
    fn idna_to_punycode() {
        assert_eq!(norm("bücher.de").unwrap(), "xn--bcher-kva.de");
        assert_eq!(norm("BÜCHER.de").unwrap(), "xn--bcher-kva.de");
        // Full-width dot (U+3002) is a label separator under UTS-46.
        assert_eq!(norm("bücher。de").unwrap(), "xn--bcher-kva.de");
        // Non-transitional: ß is kept, not mapped to "ss".
        assert_eq!(norm("faß.de").unwrap(), "xn--fa-hia.de");
    }

    #[test]
    fn punycode_input_passes_through() {
        assert_eq!(norm("XN--BCHER-KVA.de").unwrap(), "xn--bcher-kva.de");
    }

    #[test]
    fn rejects_garbage() {
        assert_eq!(norm(""), Err(DomainError::Empty));
        assert_eq!(norm("."), Err(DomainError::Empty));
        assert_eq!(norm(".example.com"), Err(DomainError::EmptyLabel));
        assert_eq!(norm("a..b"), Err(DomainError::EmptyLabel));
        assert_eq!(norm("ex ample.com"), Err(DomainError::InvalidChar(' ')));
        assert_eq!(norm("*.example.com"), Err(DomainError::InvalidChar('*')));
        assert_eq!(norm("example.com/path"), Err(DomainError::InvalidChar('/')));
        assert_eq!(norm(&"a".repeat(64)), Err(DomainError::LabelTooLong));
        let long = vec!["a".repeat(63); 5].join(".");
        assert_eq!(norm(&long), Err(DomainError::TooLong));
    }

    #[test]
    fn rejects_ip_addresses() {
        assert!(matches!(norm("0.0.0.0"), Err(DomainError::IpAddress(_))));
        assert!(matches!(norm("127.0.0.1"), Err(DomainError::IpAddress(_))));
        assert!(matches!(norm("::1"), Err(DomainError::IpAddress(_))));
        // Numeric labels that are not a dotted quad are names (reverse zones).
        assert_eq!(
            norm("1.0.0.127.in-addr.arpa").unwrap(),
            "1.0.0.127.in-addr.arpa"
        );
    }

    #[test]
    fn accepts_underscores_and_single_labels() {
        assert_eq!(norm("_dmarc.example.com").unwrap(), "_dmarc.example.com");
        assert_eq!(norm("zip").unwrap(), "zip");
    }

    #[test]
    fn length_limits_are_inclusive() {
        let label = "a".repeat(63);
        assert!(norm(&label).is_ok());
        // 63*3 + 61 + 3 dots = 253
        let name = format!("{label}.{label}.{label}.{}", "a".repeat(61));
        assert_eq!(name.len(), 253);
        assert!(norm(&name).is_ok());
    }

    #[test]
    fn suffixes_most_specific_first() {
        let d = Domain::parse("a.b.example.com").unwrap();
        let s: Vec<_> = d.suffixes().collect();
        assert_eq!(
            s,
            ["a.b.example.com", "b.example.com", "example.com", "com"]
        );
        assert_eq!(d.parent(), Some("b.example.com"));
    }

    #[test]
    fn query_name_folds_case_only() {
        let q = QueryName::new("WWW.Example.COM.").unwrap();
        assert_eq!(q.as_str(), "www.example.com");
        // Odd bytes are kept so suffixes still match.
        let q = QueryName::new("we\\032ird.ads.example.com").unwrap();
        assert_eq!(q.as_str(), "we\\032ird.ads.example.com");
        assert!(QueryName::new(".").is_none());
        assert!(QueryName::new(&"a".repeat(254)).is_none());
    }

    fn label() -> impl Strategy<Value = String> {
        "[a-zA-Z0-9_-]{1,20}"
    }

    fn name() -> impl Strategy<Value = String> {
        prop::collection::vec(label(), 1..6).prop_map(|l| l.join("."))
    }

    proptest! {
        #[test]
        fn normalization_is_idempotent(s in "\\PC{0,40}") {
            if let Ok(d) = Domain::parse(&s) {
                prop_assert_eq!(Domain::parse(d.as_str()).unwrap(), d);
            }
        }

        #[test]
        fn normalization_ignores_case_and_trailing_dot(n in name()) {
            let a = Domain::parse(&n);
            let b = Domain::parse(&format!("{}.", n.to_ascii_uppercase()));
            prop_assert_eq!(a, b);
        }

        #[test]
        fn normalized_names_are_lowercase_ascii(s in "\\PC{0,40}") {
            if let Ok(d) = Domain::parse(&s) {
                prop_assert!(d.as_str().bytes().all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.')));
                prop_assert!(!d.as_str().ends_with('.'));
            }
        }

        #[test]
        fn query_name_agrees_with_domain_on_valid_names(n in name()) {
            if let Ok(d) = Domain::parse(&n) {
                let q = QueryName::new(&n).unwrap();
                prop_assert_eq!(q.as_str(), d.as_str());
            }
        }
    }
}
