//! Network rules: `||ads.example.com^$script,third-party`, `@@|https://x/$doc`,
//! `/^https?:\/\/ad\d+\./$image`.
//!
//! The parse is lossless with respect to semantics: everything the compiler
//! needs to emit a DNR rule (domain strings, types, party, actions) is kept as
//! structured data. Options that sinkhole does not implement make the whole
//! rule [`ParseError::Unsupported`]; dropping just the option would broaden
//! the rule, which is how ad blockers break sites.

use std::fmt;
use std::ops::{BitOr, BitOrAssign};

use serde::{Serialize, Serializer};
use sinkhole_core::Domain;

use crate::ParseError;
use crate::domains::{DomainSpec, HostPattern, parse_domain_list};

/// A parsed network rule.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct NetworkRule {
    /// `@@`: an exception (allow) rule.
    pub exception: bool,
    pub pattern: UrlPattern,
    pub options: NetworkOptions,
}

/// Where a wildcard pattern is anchored.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Anchor {
    /// Matches anywhere in the URL.
    None,
    /// `|`: at the start of the URL.
    Start,
    /// `||`: at the start of the hostname or of any of its labels.
    Hostname,
}

/// The URL-matching part of a network rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum UrlPattern {
    /// ABP wildcard syntax: `*` matches any run of characters, `^` matches a
    /// separator character or the end of the URL. Redundant leading and
    /// trailing `*` are removed and the hostname part (after `||`) is
    /// lowercased and converted to punycode. An empty body with no anchors
    /// matches every URL.
    Wildcard {
        anchor: Anchor,
        body: String,
        /// Trailing `|`: the match must end at the end of the URL.
        end_anchor: bool,
    },
    /// `/regex/`, source without the slashes, as written.
    Regex { source: String },
}

impl UrlPattern {
    /// Whether the pattern matches every URL (`*`, or an empty pattern
    /// before `$options`).
    pub fn matches_everything(&self) -> bool {
        matches!(self, UrlPattern::Wildcard { anchor: Anchor::None, body, end_anchor: false } if body.is_empty())
    }

    /// The hostname of a `||host^…` pattern whose host part has no wildcard.
    pub fn hostname(&self) -> Option<&str> {
        let UrlPattern::Wildcard {
            anchor: Anchor::Hostname,
            body,
            ..
        } = self
        else {
            return None;
        };
        let end = body.find(|c: char| !is_host_char(c)).unwrap_or(body.len());
        let (host, rest) = body.split_at(end);
        // `||142.91.159.` is the start of every address in a range, not a
        // host: a host has no empty label.
        if host.is_empty()
            || rest.starts_with('*')
            || host.starts_with('.')
            || host.ends_with('.')
            || host.contains("..")
        {
            return None;
        }
        Some(host)
    }

    /// For `||host^` (or `||host`, `||host^|`): the host. These rules match
    /// every URL on the host and its subdomains and nothing else, which is
    /// the only kind of network rule a DNS resolver can apply.
    pub fn pure_hostname(&self) -> Option<&str> {
        let host = self.hostname()?;
        let UrlPattern::Wildcard { body, .. } = self else {
            return None;
        };
        matches!(&body[host.len()..], "" | "^").then_some(host)
    }
}

fn is_host_char(c: char) -> bool {
    matches!(c, 'a'..='z' | '0'..='9' | '.' | '-' | '_')
}

/// A set of request types.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct ResourceTypes(u16);

impl ResourceTypes {
    pub const SCRIPT: Self = Self(1 << 0);
    pub const IMAGE: Self = Self(1 << 1);
    pub const STYLESHEET: Self = Self(1 << 2);
    pub const OBJECT: Self = Self(1 << 3);
    pub const XMLHTTPREQUEST: Self = Self(1 << 4);
    pub const SUBDOCUMENT: Self = Self(1 << 5);
    pub const PING: Self = Self(1 << 6);
    pub const WEBSOCKET: Self = Self(1 << 7);
    pub const WEBRTC: Self = Self(1 << 8);
    pub const FONT: Self = Self(1 << 9);
    pub const MEDIA: Self = Self(1 << 10);
    pub const OTHER: Self = Self(1 << 11);
    /// The top-level page itself (`$document`).
    pub const DOCUMENT: Self = Self(1 << 12);
    /// A new window or tab opened by the page (`$popup`).
    pub const POPUP: Self = Self(1 << 13);

    pub const NONE: Self = Self(0);
    /// Every subresource type: what a rule with no type option applies to.
    pub const SUBRESOURCES: Self = Self((1 << 12) - 1);
    pub const ALL: Self = Self((1 << 14) - 1);

    const NAMES: [(Self, &'static str); 14] = [
        (Self::SCRIPT, "script"),
        (Self::IMAGE, "image"),
        (Self::STYLESHEET, "stylesheet"),
        (Self::OBJECT, "object"),
        (Self::XMLHTTPREQUEST, "xmlhttprequest"),
        (Self::SUBDOCUMENT, "subdocument"),
        (Self::PING, "ping"),
        (Self::WEBSOCKET, "websocket"),
        (Self::WEBRTC, "webrtc"),
        (Self::FONT, "font"),
        (Self::MEDIA, "media"),
        (Self::OTHER, "other"),
        (Self::DOCUMENT, "document"),
        (Self::POPUP, "popup"),
    ];

    pub fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    pub fn intersects(self, other: Self) -> bool {
        self.0 & other.0 != 0
    }

    pub fn is_empty(self) -> bool {
        self.0 == 0
    }

    pub fn without(self, other: Self) -> Self {
        Self(self.0 & !other.0)
    }

    /// Canonical option names of the types in the set.
    pub fn names(self) -> impl Iterator<Item = &'static str> {
        Self::NAMES
            .into_iter()
            .filter(move |(t, _)| self.contains(*t))
            .map(|(_, n)| n)
    }

    /// The type an option name selects, accepting the usual aliases.
    fn from_option(name: &str) -> Option<Self> {
        Some(match name {
            "script" => Self::SCRIPT,
            "image" => Self::IMAGE,
            "stylesheet" | "css" => Self::STYLESHEET,
            "object" | "object-subrequest" => Self::OBJECT,
            "xmlhttprequest" | "xhr" => Self::XMLHTTPREQUEST,
            "subdocument" | "frame" => Self::SUBDOCUMENT,
            "ping" | "beacon" => Self::PING,
            "websocket" => Self::WEBSOCKET,
            "webrtc" => Self::WEBRTC,
            "font" => Self::FONT,
            "media" => Self::MEDIA,
            "other" => Self::OTHER,
            "document" | "doc" => Self::DOCUMENT,
            "popup" => Self::POPUP,
            _ => return None,
        })
    }
}

impl BitOr for ResourceTypes {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

impl BitOrAssign for ResourceTypes {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

impl fmt::Debug for ResourceTypes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let names: Vec<_> = self.names().collect();
        write!(f, "ResourceTypes({})", names.join("|"))
    }
}

impl Serialize for ResourceTypes {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_seq(self.names())
    }
}

/// Which requests count, by site (eTLD+1) relative to the page.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Party {
    #[default]
    Any,
    /// `$1p`, `$~third-party`: same site as the page.
    First,
    /// `$3p`, `$~first-party`: a different site.
    Third,
}

/// uBO's `$strict1p` / `$strict3p`: the same comparison by exact hostname.
/// Independent of [`Party`], so `$1p,strict3p` means "same site, another
/// host" (`cdn.example.com` requested by `www.example.com`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StrictParty {
    #[default]
    Any,
    /// `$strict1p`: same hostname as the page.
    SameHost,
    /// `$strict3p`: a different hostname.
    OtherHost,
}

/// Exception-only options that switch off parts of filtering on a page.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize)]
pub struct PageExceptions {
    /// `$elemhide`: no cosmetic filtering at all.
    pub elemhide: bool,
    /// `$generichide`: no generic (domain-less) cosmetic filters.
    pub generichide: bool,
    /// `$specifichide`: no domain-specific cosmetic filters.
    pub specifichide: bool,
    /// `$genericblock`: no generic network block rules.
    pub genericblock: bool,
}

impl PageExceptions {
    fn any(&self) -> bool {
        self.elemhide || self.generichide || self.specifichide || self.genericblock
    }
}

/// `$method=get|~post`
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MethodSpec {
    pub negated: bool,
    /// Uppercase: `GET`, `POST`, …
    pub method: String,
}

/// `$header=name:value` (uBO): match on a response header.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HeaderMatch {
    /// Lowercase header name.
    pub name: String,
    /// Value condition as written: a literal, or `/regex/`, optionally
    /// prefixed with `~` to negate. `None`: the header is present.
    pub value: Option<String>,
}

/// What `$removeparam` removes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ParamMatch {
    /// Bare `$removeparam`: the whole query string.
    All,
    /// A parameter name, matched exactly. `negated`: every parameter except it.
    Name { name: String, negated: bool },
    /// `/regex/flags`, tested against `name=value`.
    Regex {
        source: String,
        flags: String,
        negated: bool,
    },
}

/// Which cookies `$cookie` (AdGuard) applies to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum CookieName {
    All,
    Name(String),
    Regex(String),
}

/// `$cookie=name;maxAge=3600;sameSite=lax`: block or cap cookies.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CookieAction {
    pub name: CookieName,
    /// Cap the lifetime instead of removing the cookie.
    pub max_age: Option<u64>,
    pub same_site: Option<String>,
}

/// The modifying action of a rule. A rule has at most one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Action {
    /// `$redirect=noop.js[:priority]`: serve a bundled resource instead.
    /// `rule_only` (`$redirect-rule`): only redirect requests that another
    /// rule blocks. An empty `resource` (exceptions only) means every resource.
    Redirect {
        resource: String,
        priority: i32,
        rule_only: bool,
    },
    /// `$removeparam`: strip query parameters.
    RemoveParam(ParamMatch),
    /// `$csp=…`: add a Content-Security-Policy to matching documents. `None`
    /// (exceptions only) cancels every injected CSP.
    Csp(Option<String>),
    /// `$permissions=…`: add a Permissions-Policy.
    Permissions(Option<String>),
    /// `$urlskip=?url -base64` (uBO): navigate straight to the URL embedded
    /// in a link wrapper, by applying the steps in order.
    UrlSkip { steps: Vec<String> },
    /// `$cookie` (AdGuard).
    Cookie(CookieAction),
    /// `$removeheader=[request:]name` (AdGuard).
    RemoveHeader { name: String, request: bool },
}

/// Everything after the `$`.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct NetworkOptions {
    /// Request types the rule applies to; `None` when the rule names none,
    /// in which case targets apply their default (subresources).
    pub types: Option<ResourceTypes>,
    pub party: Party,
    pub strict_party: StrictParty,
    /// `$domain=` / `$from=`: pages the rule applies on.
    pub domains: Vec<DomainSpec>,
    /// `$to=`: request hostnames the rule applies to.
    pub to: Vec<DomainSpec>,
    /// `$denyallow=`: request hostnames excluded from the rule.
    pub denyallow: Vec<DomainSpec>,
    pub methods: Vec<MethodSpec>,
    pub header: Option<HeaderMatch>,
    /// `$important`: beats exceptions without `$important`.
    pub important: bool,
    /// `$match-case`: the URL pattern is case-sensitive.
    pub match_case: bool,
    /// `$badfilter`: cancels the identical rule without this option.
    pub badfilter: bool,
    /// `$cname` (exceptions only): skip CNAME uncloaking for matches.
    pub cname: bool,
    pub page: PageExceptions,
    pub action: Option<Action>,
}

/// Parses a network rule. The caller has already ruled out comments and
/// cosmetic rules.
pub(crate) fn parse_network(line: &str) -> Result<NetworkRule, ParseError> {
    let (exception, rest) = match line.strip_prefix("@@") {
        Some(rest) => (true, rest),
        None => (false, line),
    };
    let (pattern_src, options_src) = split_at_options(rest)?;
    let mut options = NetworkOptions::default();
    if let Some(src) = options_src {
        parse_options(src, exception, &mut options)?;
    }
    let pattern = parse_pattern(pattern_src)?;
    if pattern.matches_everything() && options == NetworkOptions::default() && !exception {
        return Err(ParseError::invalid("rule would block every request"));
    }
    Ok(NetworkRule {
        exception,
        pattern,
        options,
    })
}

/// Finds the `$` that starts the options. The options may contain `$`
/// (`$removeparam=/^x$/`), and so may a regex pattern (`/ads$/`), so this
/// takes the rightmost unescaped `$` whose remainder looks like an option
/// list: an option name followed by `=`, `,` or the end.
fn split_at_options(rest: &str) -> Result<(&str, Option<&str>), ParseError> {
    let bytes = rest.as_bytes();
    for i in memchr::memrchr_iter(b'$', bytes) {
        if i > 0 && bytes[i - 1] == b'\\' {
            continue;
        }
        let after = &rest[i + 1..];
        if after.is_empty() {
            if i + 1 == rest.len() && !rest.starts_with('/') {
                return Err(ParseError::invalid("empty option list"));
            }
            continue;
        }
        if looks_like_options(after) {
            return Ok((&rest[..i], Some(after)));
        }
    }
    Ok((rest, None))
}

fn looks_like_options(s: &str) -> bool {
    let s = s.strip_prefix('~').unwrap_or(s);
    let name_len = s
        .bytes()
        .take_while(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
        .count();
    name_len > 0 && matches!(s.as_bytes().get(name_len), None | Some(b'=' | b','))
}

/// Splits on commas, except ones escaped as `\,` (unescaped here) and ones
/// inside a `/regex/` value (`removeparam=/^x{1,3}/`, `header=via:/1\.1, g/`).
/// A regex opens at a `/` right after `=`, `|`, `~` or `:` and closes at the
/// next unescaped `/`; without a closing `/` it is plain text.
fn split_options(src: &str) -> Vec<String> {
    let bytes = src.as_bytes();
    let mut out = Vec::new();
    let mut current = String::new();
    // Start of the text not yet copied into `current`.
    let mut copied = 0;
    // Commas before this index are inside a regex.
    let mut regex_end = 0;
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' if bytes.get(i + 1) == Some(&b',') => {
                current.push_str(&src[copied..i]);
                current.push(',');
                i += 2;
                copied = i;
            }
            b',' if i >= regex_end => {
                current.push_str(&src[copied..i]);
                out.push(std::mem::take(&mut current));
                i += 1;
                copied = i;
            }
            b'/' if i >= regex_end
                && i > 0
                && matches!(bytes[i - 1], b'=' | b'|' | b'~' | b':') =>
            {
                if let Some(close) = regex_close(bytes, i) {
                    regex_end = close;
                }
                i += 1;
            }
            _ => i += 1,
        }
    }
    current.push_str(&src[copied..]);
    out.push(current);
    out
}

/// Index of the unescaped `/` closing the regex that opens at `open`.
fn regex_close(bytes: &[u8], open: usize) -> Option<usize> {
    let mut i = open + 1;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' => i += 2,
            b'/' => return Some(i),
            _ => i += 1,
        }
    }
    None
}

/// Options that are valid in some dialect but that sinkhole does not
/// implement, with the reason shown in compile reports.
const UNSUPPORTED_OPTIONS: &[(&str, &str)] = &[
    ("replace", "rewrites response bodies, which MV3 cannot do"),
    ("hls", "rewrites response bodies, which MV3 cannot do"),
    ("jsonprune", "rewrites response bodies, which MV3 cannot do"),
    ("xmlprune", "rewrites response bodies, which MV3 cannot do"),
    ("uritransform", "not implemented yet"),
    ("popunder", "cannot be detected reliably from an extension"),
    ("network", "AdGuard app-only option"),
    ("app", "AdGuard app-only option"),
    ("extension", "AdGuard app-only option"),
    ("content", "AdGuard app-only option"),
    ("jsinject", "AdGuard app-only option"),
    ("urlblock", "AdGuard app-only option"),
    ("stealth", "AdGuard app-only option"),
    ("referrerpolicy", "AdGuard app-only option"),
    ("client", "AdGuard Home option"),
    ("dnstype", "AdGuard Home option"),
    ("dnsrewrite", "AdGuard Home option"),
    ("ctag", "AdGuard Home option"),
    (
        "sitekey",
        "ABP sitekey allowlisting is a paid acceptable-ads mechanism",
    ),
    (
        "ipaddress",
        "needs the resolved IP, unavailable to Chromium extensions",
    ),
];

/// Headers that `$removeheader` may never touch. Lists are untrusted input:
/// removing these would weaken a site's security or break the protocol.
fn protected_header(name: &str) -> bool {
    const EXACT: &[&str] = &[
        "allow",
        "connection",
        "content-length",
        "content-security-policy",
        "content-security-policy-report-only",
        "content-type",
        "feature-policy",
        "host",
        "origin",
        "origin-agent-cluster",
        "permissions-policy",
        "referrer-policy",
        "strict-transport-security",
        "timing-allow-origin",
        "transfer-encoding",
        "upgrade",
        "upgrade-insecure-requests",
        "x-content-type-options",
        "x-frame-options",
        "x-xss-protection",
    ];
    const PREFIXES: &[&str] = &[
        "access-control-",
        "cross-origin-",
        "sec-",
        "public-key-pins",
    ];
    EXACT.contains(&name) || PREFIXES.iter().any(|p| name.starts_with(p))
}

fn parse_options(src: &str, exception: bool, opts: &mut NetworkOptions) -> Result<(), ParseError> {
    let mut include = ResourceTypes::NONE;
    let mut exclude = ResourceTypes::NONE;
    let mut all = false;

    for raw in split_options(src) {
        let raw = raw.trim();
        if raw.is_empty() {
            return Err(ParseError::invalid("empty option"));
        }
        let (negated, raw) = match raw.strip_prefix('~') {
            Some(rest) => (true, rest),
            None => (false, raw),
        };
        let (name, value) = match raw.split_once('=') {
            Some((n, v)) => (n.to_ascii_lowercase(), Some(v)),
            None => (raw.to_ascii_lowercase(), None),
        };
        let name = name.as_str();
        let o = Opt {
            name,
            value,
            negated,
        };

        if let Some(t) = ResourceTypes::from_option(name) {
            o.no_value()?;
            if negated {
                exclude |= t;
            } else {
                include |= t;
            }
            continue;
        }

        match name {
            "domain" | "from" => {
                o.no_negation()?;
                opts.domains
                    .extend(parse_domain_list(o.value()?, b'|', "$domain")?);
            }
            "to" => {
                o.no_negation()?;
                opts.to.extend(parse_domain_list(o.value()?, b'|', "$to")?);
            }
            "denyallow" => {
                o.no_negation()?;
                let list = parse_domain_list(o.value()?, b'|', "$denyallow")?;
                if list
                    .iter()
                    .any(|d| d.negated || !matches!(d.host, HostPattern::Domain(_)))
                {
                    return Err(ParseError::invalid("$denyallow takes plain domains only"));
                }
                opts.denyallow.extend(list);
            }
            "method" => {
                o.no_negation()?;
                opts.methods = parse_methods(o.value()?)?;
            }
            "header" => {
                o.no_negation()?;
                let v = o.value()?;
                let (name, value) = match v.split_once(':') {
                    Some((n, v)) => (n, Some(v.to_owned())),
                    None => (v, None),
                };
                if name.is_empty() {
                    return Err(ParseError::invalid("$header needs a header name"));
                }
                opts.header = Some(HeaderMatch {
                    name: name.to_ascii_lowercase(),
                    value,
                });
            }
            "important" => o.flag(&mut opts.important)?,
            "match-case" => o.flag(&mut opts.match_case)?,
            "badfilter" => o.flag(&mut opts.badfilter)?,
            "third-party" | "3p" => {
                o.no_value()?;
                let party = if negated { Party::First } else { Party::Third };
                set_once(&mut opts.party, party)?;
            }
            "first-party" | "1p" => {
                o.no_value()?;
                let party = if negated { Party::Third } else { Party::First };
                set_once(&mut opts.party, party)?;
            }
            "strict1p" | "strict3p" => {
                o.no_negation()?;
                o.no_value()?;
                let strict = if name == "strict1p" {
                    StrictParty::SameHost
                } else {
                    StrictParty::OtherHost
                };
                set_once(&mut opts.strict_party, strict)?;
            }
            // uBO: any run of underscores is a no-op, used to split long lines.
            _ if !name.is_empty() && name.bytes().all(|b| b == b'_') => {
                o.no_negation()?;
                o.no_value()?;
            }
            "all" => {
                o.no_negation()?;
                o.no_value()?;
                all = true;
            }
            "elemhide" | "ehide" => o.flag(&mut opts.page.elemhide)?,
            "generichide" | "ghide" => o.flag(&mut opts.page.generichide)?,
            "specifichide" | "shide" => o.flag(&mut opts.page.specifichide)?,
            "genericblock" => o.flag(&mut opts.page.genericblock)?,
            "cname" => o.flag(&mut opts.cname)?,
            "redirect" | "redirect-rule" => {
                o.no_negation()?;
                let value = o.value.unwrap_or_default();
                let (resource, priority) = match value.rsplit_once(':') {
                    Some((r, p))
                        if !r.is_empty() && p.bytes().all(|b| b.is_ascii_digit() || b == b'-') =>
                    {
                        let priority = p.parse().map_err(|_| {
                            ParseError::invalid(format!("bad redirect priority {p:?}"))
                        })?;
                        (r, priority)
                    }
                    _ => (value, 0),
                };
                validate_resource_name(resource)?;
                set_action(
                    opts,
                    Action::Redirect {
                        resource: resource.to_owned(),
                        priority,
                        rule_only: name == "redirect-rule",
                    },
                )?;
            }
            // ABP's spelling of $redirect, limited to its built-in resources.
            "rewrite" => {
                o.no_negation()?;
                let v = o.value()?;
                if !v.starts_with("abp-resource:") {
                    return Err(ParseError::unsupported(
                        "option:rewrite",
                        "only abp-resource: rewrites are supported",
                    ));
                }
                validate_resource_name(v)?;
                set_action(
                    opts,
                    Action::Redirect {
                        resource: v.to_owned(),
                        priority: 0,
                        rule_only: false,
                    },
                )?;
            }
            // Legacy uBO shorthands.
            "empty" | "mp4" => {
                o.no_negation()?;
                o.no_value()?;
                let resource = if name == "empty" {
                    "empty"
                } else {
                    "noopmp4-1s"
                };
                if name == "mp4" {
                    include |= ResourceTypes::MEDIA;
                }
                set_action(
                    opts,
                    Action::Redirect {
                        resource: resource.into(),
                        priority: 0,
                        rule_only: false,
                    },
                )?;
            }
            "removeparam" | "queryprune" => {
                o.no_negation()?;
                set_action(
                    opts,
                    Action::RemoveParam(parse_param_match(o.value.unwrap_or_default())?),
                )?;
            }
            "csp" | "permissions" => {
                o.no_negation()?;
                let value = o
                    .value
                    .filter(|v| !v.trim().is_empty())
                    .map(|v| v.trim().to_owned());
                if let Some(v) = &value {
                    // The value becomes a header; refuse header splitting.
                    if v.contains(['\r', '\n']) {
                        return Err(ParseError::invalid("line break in header value"));
                    }
                }
                set_action(
                    opts,
                    if name == "csp" {
                        Action::Csp(value)
                    } else {
                        Action::Permissions(value)
                    },
                )?;
            }
            // uBO expresses these as CSP injections on the page.
            "inline-script" | "inline-font" => {
                o.no_negation()?;
                o.no_value()?;
                let policy = if name == "inline-script" {
                    "script-src 'unsafe-eval' * blob: data:"
                } else {
                    "font-src *"
                };
                set_action(opts, Action::Csp(Some(policy.into())))?;
            }
            "urlskip" => {
                o.no_negation()?;
                let steps: Vec<String> = o.value()?.split_whitespace().map(str::to_owned).collect();
                if steps.is_empty() {
                    return Err(ParseError::invalid("$urlskip needs at least one step"));
                }
                set_action(opts, Action::UrlSkip { steps })?;
            }
            "cookie" => {
                o.no_negation()?;
                set_action(
                    opts,
                    Action::Cookie(parse_cookie(o.value.unwrap_or_default())?),
                )?;
            }
            "removeheader" => {
                o.no_negation()?;
                let v = o.value()?;
                let (request, header) = match v.strip_prefix("request:") {
                    Some(h) => (true, h),
                    None => (false, v),
                };
                let header = header.trim().to_ascii_lowercase();
                if header.is_empty()
                    || !header
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-')
                {
                    return Err(ParseError::invalid(format!("bad header name {header:?}")));
                }
                if protected_header(&header) {
                    return Err(ParseError::unsupported(
                        "option:removeheader",
                        format!(
                            "removing {header} is refused: it protects the page or the protocol"
                        ),
                    ));
                }
                set_action(
                    opts,
                    Action::RemoveHeader {
                        name: header,
                        request,
                    },
                )?;
            }
            // uBO: text for the block page. Informational only.
            "reason" => {}
            _ => {
                return Err(match UNSUPPORTED_OPTIONS.iter().find(|(n, _)| *n == name) {
                    Some((n, why)) => ParseError::unsupported(format!("option:{n}"), *why),
                    None => ParseError::unsupported("option:unknown", format!("${name}")),
                });
            }
        }
    }

    opts.types = if all {
        Some(ResourceTypes::ALL.without(exclude))
    } else if !include.is_empty() {
        Some(include.without(exclude))
    } else if !exclude.is_empty() {
        Some(ResourceTypes::SUBRESOURCES.without(exclude))
    } else {
        None
    };
    if opts.types.is_some_and(ResourceTypes::is_empty) {
        return Err(ParseError::invalid(
            "type options exclude every request type",
        ));
    }
    if opts.party == Party::Third && opts.strict_party == StrictParty::SameHost {
        return Err(ParseError::invalid(
            "$3p with $strict1p never matches: the same host is the same site",
        ));
    }

    if !exception {
        if opts.page.any() || opts.cname {
            return Err(ParseError::invalid(
                "$elemhide, $generichide, $specifichide, $genericblock and $cname are only valid on @@ exceptions",
            ));
        }
        let empty_action = matches!(
            &opts.action,
            Some(Action::Redirect { resource, .. }) if resource.is_empty()
        ) || matches!(
            &opts.action,
            Some(Action::Csp(None) | Action::Permissions(None))
        );
        if empty_action {
            return Err(ParseError::invalid(
                "this option needs a value outside @@ exceptions",
            ));
        }
    }
    Ok(())
}

/// One `name[=value]` option, for the small validation helpers.
struct Opt<'a> {
    name: &'a str,
    value: Option<&'a str>,
    negated: bool,
}

impl<'a> Opt<'a> {
    fn value(&self) -> Result<&'a str, ParseError> {
        self.value
            .filter(|v| !v.is_empty())
            .ok_or_else(|| ParseError::invalid(format!("${} needs a value", self.name)))
    }

    fn no_value(&self) -> Result<(), ParseError> {
        match self.value {
            None => Ok(()),
            Some(_) => Err(ParseError::invalid(format!(
                "${} takes no value",
                self.name
            ))),
        }
    }

    fn no_negation(&self) -> Result<(), ParseError> {
        if self.negated {
            Err(ParseError::invalid(format!(
                "${} cannot be negated",
                self.name
            )))
        } else {
            Ok(())
        }
    }

    fn flag(&self, target: &mut bool) -> Result<(), ParseError> {
        self.no_negation()?;
        self.no_value()?;
        *target = true;
        Ok(())
    }
}

/// Sets a party option, refusing a contradiction (`$1p,3p`).
fn set_once<T: Copy + Default + PartialEq>(slot: &mut T, value: T) -> Result<(), ParseError> {
    if *slot != T::default() && *slot != value {
        return Err(ParseError::invalid(
            "conflicting first-/third-party options",
        ));
    }
    *slot = value;
    Ok(())
}

fn set_action(opts: &mut NetworkOptions, action: Action) -> Result<(), ParseError> {
    if opts.action.is_some() {
        return Err(ParseError::invalid(
            "a rule can have only one of $redirect, $removeparam, $csp, $permissions, $urlskip, $cookie, $removeheader",
        ));
    }
    opts.action = Some(action);
    Ok(())
}

/// Resource names select a bundled file by name (`noop.js`,
/// `google-analytics.com/ga.js`); they are looked up, never used as paths,
/// but `..` and empty segments are refused anyway.
fn validate_resource_name(name: &str) -> Result<(), ParseError> {
    let charset = name
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b':' | b'/'));
    let segments_ok = !name.contains('/')
        || name
            .split('/')
            .all(|s| !s.is_empty() && s != "." && s != "..");
    if charset && segments_ok {
        Ok(())
    } else {
        Err(ParseError::invalid(format!("bad resource name {name:?}")))
    }
}

fn parse_methods(value: &str) -> Result<Vec<MethodSpec>, ParseError> {
    const KNOWN: &[&str] = &[
        "CONNECT", "DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT",
    ];
    let methods = value
        .split('|')
        .map(|m| {
            let (negated, m) = match m.strip_prefix('~') {
                Some(rest) => (true, rest),
                None => (false, m),
            };
            let method = m.to_ascii_uppercase();
            if KNOWN.contains(&method.as_str()) {
                Ok(MethodSpec { negated, method })
            } else {
                Err(ParseError::invalid(format!("unknown HTTP method {m:?}")))
            }
        })
        .collect::<Result<Vec<_>, _>>()?;
    let negated = methods.iter().filter(|m| m.negated).count();
    if negated != 0 && negated != methods.len() {
        return Err(ParseError::invalid(
            "$method cannot mix included and excluded methods",
        ));
    }
    Ok(methods)
}

fn parse_param_match(value: &str) -> Result<ParamMatch, ParseError> {
    if value.is_empty() {
        return Ok(ParamMatch::All);
    }
    let (negated, body) = match value.strip_prefix('~') {
        Some(rest) => (true, rest),
        None => (false, value),
    };
    if let Some(inner) = body.strip_prefix('/')
        && let Some(close) = inner.rfind('/')
        && close > 0
        && inner[close + 1..].bytes().all(|b| b.is_ascii_alphabetic())
    {
        return Ok(ParamMatch::Regex {
            source: inner[..close].to_owned(),
            flags: inner[close + 1..].to_owned(),
            negated,
        });
    }
    if body.is_empty() || body.contains(['&', '=', ' ']) {
        return Err(ParseError::invalid(format!(
            "bad $removeparam value {value:?}"
        )));
    }
    Ok(ParamMatch::Name {
        name: body.to_owned(),
        negated,
    })
}

fn parse_cookie(value: &str) -> Result<CookieAction, ParseError> {
    let mut parts = value.split(';');
    let name = match parts.next().unwrap_or_default().trim() {
        "" => CookieName::All,
        n if n.len() >= 2 && n.starts_with('/') && n.ends_with('/') => {
            CookieName::Regex(n[1..n.len() - 1].to_owned())
        }
        n => CookieName::Name(n.to_owned()),
    };
    let mut action = CookieAction {
        name,
        max_age: None,
        same_site: None,
    };
    for attr in parts {
        match attr.trim().split_once('=') {
            Some(("maxAge", v)) => {
                action.max_age = Some(
                    v.parse()
                        .map_err(|_| ParseError::invalid(format!("bad $cookie maxAge {v:?}")))?,
                );
            }
            Some(("sameSite", v)) if matches!(v, "lax" | "strict" | "none") => {
                action.same_site = Some(v.to_owned());
            }
            _ => {
                return Err(ParseError::invalid(format!(
                    "bad $cookie attribute {attr:?}"
                )));
            }
        }
    }
    Ok(action)
}

fn parse_pattern(src: &str) -> Result<UrlPattern, ParseError> {
    if src.len() > 2 && src.starts_with('/') && src.ends_with('/') {
        return Ok(UrlPattern::Regex {
            source: src[1..src.len() - 1].to_owned(),
        });
    }
    if src.chars().any(char::is_whitespace) {
        return Err(ParseError::invalid("whitespace in URL pattern"));
    }
    let (mut anchor, mut body) = if let Some(rest) = src.strip_prefix("||") {
        (Anchor::Hostname, rest)
    } else if let Some(rest) = src.strip_prefix('|') {
        (Anchor::Start, rest)
    } else {
        (Anchor::None, src)
    };
    let mut end_anchor = false;
    if let Some(rest) = body.strip_suffix('|') {
        end_anchor = true;
        body = rest;
    }
    // An anchor followed by a wildcard anchors nothing.
    if body.starts_with('*') {
        anchor = Anchor::None;
    }
    if anchor == Anchor::None {
        body = body.trim_start_matches('*');
    }
    if !end_anchor {
        body = body.trim_end_matches('*');
    }
    if body.is_empty() && (anchor != Anchor::None || end_anchor) {
        return Err(ParseError::invalid("nothing to match after the anchor"));
    }
    let mut body = collapse_stars(body);
    if anchor == Anchor::Hostname {
        body = canonical_host_part(&body)?;
    }
    Ok(UrlPattern::Wildcard {
        anchor,
        body,
        end_anchor,
    })
}

fn collapse_stars(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if !(c == '*' && out.ends_with('*')) {
            out.push(c);
        }
    }
    out
}

/// Lowercases the hostname at the start of a `||` body and converts it to
/// punycode, leaving the rest (path, which may be case-sensitive) untouched.
fn canonical_host_part(body: &str) -> Result<String, ParseError> {
    let end = body
        .find(['^', '/', ':', '?', '*', '|', '#', '='])
        .unwrap_or(body.len());
    let (host, rest) = body.split_at(end);
    let host = if host.is_ascii() || host.ends_with('.') {
        host.to_ascii_lowercase()
    } else {
        Domain::parse(host)
            .map_err(|e| ParseError::invalid(format!("bad hostname {host:?}: {e}")))?
            .as_str()
            .to_owned()
    };
    Ok(host + rest)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn net(line: &str) -> NetworkRule {
        parse_network(line).unwrap_or_else(|e| panic!("{line}: {e}"))
    }

    fn err(line: &str) -> ParseError {
        parse_network(line).expect_err(line)
    }

    fn wildcard(anchor: Anchor, body: &str, end_anchor: bool) -> UrlPattern {
        UrlPattern::Wildcard {
            anchor,
            body: body.into(),
            end_anchor,
        }
    }

    #[test]
    fn hostname_rules() {
        let r = net("||Ads.Example.com^");
        assert!(!r.exception);
        assert_eq!(
            r.pattern,
            wildcard(Anchor::Hostname, "ads.example.com^", false)
        );
        assert_eq!(r.pattern.pure_hostname(), Some("ads.example.com"));
        assert_eq!(r.options, NetworkOptions::default());
    }

    #[test]
    fn host_case_is_folded_but_path_case_is_kept() {
        let r = net("||Example.com/Ads/Banner.JS");
        assert_eq!(
            r.pattern,
            wildcard(Anchor::Hostname, "example.com/Ads/Banner.JS", false)
        );
        assert_eq!(r.pattern.hostname(), Some("example.com"));
        assert_eq!(r.pattern.pure_hostname(), None);
    }

    #[test]
    fn idn_hostnames_become_punycode() {
        let r = net("||bücher.de^");
        assert_eq!(r.pattern.pure_hostname(), Some("xn--bcher-kva.de"));
    }

    #[test]
    fn anchors_and_wildcards() {
        assert_eq!(
            net("|https://ads.").pattern,
            wildcard(Anchor::Start, "https://ads.", false)
        );
        assert_eq!(net("swf|").pattern, wildcard(Anchor::None, "swf", true));
        assert_eq!(
            net("*/ads/**banner*").pattern,
            wildcard(Anchor::None, "/ads/*banner", false)
        );
        // `||*` anchors nothing.
        assert_eq!(
            net("||*.example.com^").pattern,
            wildcard(Anchor::None, ".example.com^", false)
        );
        assert_eq!(net("||ads*.example.com^").pattern.hostname(), None);
    }

    #[test]
    fn address_prefixes_are_not_hosts() {
        for rule in [
            "||142.91.159.",
            "||142.91.159.^",
            "||ads..example^",
            "||.example^",
        ] {
            assert_eq!(net(rule).pattern.hostname(), None, "{rule}");
        }
    }

    #[test]
    fn regex_patterns() {
        let r = net("/^https?:\\/\\/ad\\d+\\./$image");
        assert_eq!(
            r.pattern,
            UrlPattern::Regex {
                source: "^https?:\\/\\/ad\\d+\\.".into()
            }
        );
        assert_eq!(r.options.types, Some(ResourceTypes::IMAGE));
        // `$` inside the regex is not the option separator.
        let r = net("/ads\\.js$/");
        assert_eq!(
            r.pattern,
            UrlPattern::Regex {
                source: "ads\\.js$".into()
            }
        );
        let r = net("/ads\\.js$/$script");
        assert_eq!(
            r.pattern,
            UrlPattern::Regex {
                source: "ads\\.js$".into()
            }
        );
        assert_eq!(r.options.types, Some(ResourceTypes::SCRIPT));
    }

    #[test]
    fn exceptions() {
        let r = net("@@||example.com^$document");
        assert!(r.exception);
        assert_eq!(r.options.types, Some(ResourceTypes::DOCUMENT));
    }

    #[test]
    fn type_options() {
        let t = |l: &str| net(l).options.types;
        assert_eq!(
            t("||x.com^$script,css"),
            Some(ResourceTypes::SCRIPT | ResourceTypes::STYLESHEET)
        );
        assert_eq!(
            t("||x.com^$xhr,frame,beacon"),
            Some(ResourceTypes::XMLHTTPREQUEST | ResourceTypes::SUBDOCUMENT | ResourceTypes::PING)
        );
        assert_eq!(
            t("||x.com^$~script"),
            Some(ResourceTypes::SUBRESOURCES.without(ResourceTypes::SCRIPT))
        );
        assert_eq!(t("||x.com^$all"), Some(ResourceTypes::ALL));
        assert_eq!(
            t("||x.com^$all,~popup"),
            Some(ResourceTypes::ALL.without(ResourceTypes::POPUP))
        );
        assert_eq!(t("||x.com^$third-party"), None);
        assert!(matches!(
            err("||x.com^$script,~script"),
            ParseError::Invalid(_)
        ));
    }

    #[test]
    fn party_options() {
        let p = |l: &str| net(l).options.party;
        assert_eq!(p("||x.com^$third-party"), Party::Third);
        assert_eq!(p("||x.com^$3p"), Party::Third);
        assert_eq!(p("||x.com^$~third-party"), Party::First);
        assert_eq!(p("||x.com^$1p"), Party::First);
        assert_eq!(p("||x.com^$~1p"), Party::Third);
        assert!(matches!(err("||x.com^$1p,3p"), ParseError::Invalid(_)));
        assert!(matches!(err("||x.com^$3p=x"), ParseError::Invalid(_)));
    }

    #[test]
    fn strict_party_is_independent_of_party() {
        let o = |l: &str| {
            let o = net(l).options;
            (o.party, o.strict_party)
        };
        assert_eq!(o("||x.com^$strict3p"), (Party::Any, StrictParty::OtherHost));
        // Same site, another host: real uBO usage.
        assert_eq!(
            o("/x/$script,1p,strict3p"),
            (Party::First, StrictParty::OtherHost)
        );
        // Redundant but valid: the same host is the same site.
        assert_eq!(o("/x/$1p,strict1p"), (Party::First, StrictParty::SameHost));
        assert!(matches!(err("/x/$3p,strict1p"), ParseError::Invalid(_)));
        assert!(matches!(
            err("/x/$strict1p,strict3p"),
            ParseError::Invalid(_)
        ));
    }

    #[test]
    fn regex_option_values_keep_their_commas() {
        let r = net("/x/$script,header=via:/1\\.1, google$/,3p");
        assert_eq!(
            r.options.header,
            Some(HeaderMatch {
                name: "via".into(),
                value: Some("/1\\.1, google$/".into())
            })
        );
        assert_eq!(r.options.party, Party::Third);
        let r = net("||x.com^$removeparam=/^utm_[a-z]{1,8}$/,doc");
        assert_eq!(
            r.options.action,
            Some(Action::RemoveParam(ParamMatch::Regex {
                source: "^utm_[a-z]{1,8}$".into(),
                flags: String::new(),
                negated: false
            }))
        );
        assert_eq!(r.options.types, Some(ResourceTypes::DOCUMENT));
        // An escaped slash does not close the regex; `\,` is still unescaped.
        let r = net("*$removeparam=/a\\/b{1,2}/");
        assert!(matches!(
            r.options.action,
            Some(Action::RemoveParam(ParamMatch::Regex { ref source, .. })) if source == "a\\/b{1,2}"
        ));
        assert_eq!(
            split_options("csp=default-src 'self'\\, https://a.com,3p"),
            ["csp=default-src 'self', https://a.com", "3p"]
        );
        // No closing slash: plain text, commas split as usual.
        assert_eq!(split_options("domain=/a,b"), ["domain=/a", "b"]);
    }

    #[test]
    fn underscore_options_are_noops() {
        let r = net("||x.com^$script,_____,domain=a.com");
        assert_eq!(r.options.types, Some(ResourceTypes::SCRIPT));
        assert_eq!(r.options.domains.len(), 1);
        assert!(matches!(err("||x.com^$~_"), ParseError::Invalid(_)));
        assert!(matches!(err("||x.com^$_=1"), ParseError::Invalid(_)));
    }

    #[test]
    fn resource_names_may_have_paths() {
        let r = net("||google-analytics.com/ga.js$script,redirect=google-analytics.com/ga.js:5");
        assert_eq!(
            r.options.action,
            Some(Action::Redirect {
                resource: "google-analytics.com/ga.js".into(),
                priority: 5,
                rule_only: false
            })
        );
        for bad in ["../x.js", "a//b.js", "/abs.js", "a/./b.js", "a/"] {
            let line = format!("||x.com^$script,redirect={bad}");
            assert!(matches!(err(&line), ParseError::Invalid(_)), "{line}");
        }
    }

    #[test]
    fn domain_options() {
        let r = net("||x.com^$domain=a.com|~b.a.com|google.*,to=cdn.x.com,denyallow=y.com");
        assert_eq!(r.options.domains.len(), 3);
        assert!(r.options.domains[1].negated);
        assert_eq!(
            r.options.domains[2].host,
            HostPattern::Entity("google".into())
        );
        assert_eq!(
            r.options.to[0].host,
            HostPattern::Domain("cdn.x.com".into())
        );
        assert_eq!(r.options.denyallow.len(), 1);
        let r = net("*$script,from=/^a\\d+\\.com$/|b.com");
        assert_eq!(
            r.options.domains[0].host,
            HostPattern::Regex("^a\\d+\\.com$".into())
        );
        assert!(matches!(err("||x.com^$domain="), ParseError::Invalid(_)));
        assert!(matches!(
            err("||x.com^$denyallow=~y.com"),
            ParseError::Invalid(_)
        ));
    }

    #[test]
    fn flags() {
        let o = net("||x.com^$important,match-case,badfilter").options;
        assert!(o.important && o.match_case && o.badfilter);
        assert!(matches!(err("||x.com^$~important"), ParseError::Invalid(_)));
        assert!(matches!(
            err("||x.com^$important=1"),
            ParseError::Invalid(_)
        ));
    }

    #[test]
    fn page_exceptions_need_at_at() {
        let o = net("@@||x.com^$generichide,elemhide,shide,genericblock").options;
        assert!(
            o.page.generichide && o.page.elemhide && o.page.specifichide && o.page.genericblock
        );
        assert!(matches!(
            err("||x.com^$generichide"),
            ParseError::Invalid(_)
        ));
        assert!(net("@@||x.com^$cname").options.cname);
    }

    #[test]
    fn redirects() {
        let a = |l: &str| net(l).options.action;
        assert_eq!(
            a("||x.com/ads.js$script,redirect=noop.js"),
            Some(Action::Redirect {
                resource: "noop.js".into(),
                priority: 0,
                rule_only: false
            })
        );
        assert_eq!(
            a("||x.com/ads.js$script,redirect-rule=noop.js:10"),
            Some(Action::Redirect {
                resource: "noop.js".into(),
                priority: 10,
                rule_only: true
            })
        );
        assert_eq!(
            a("||x.com^$rewrite=abp-resource:blank-js"),
            Some(Action::Redirect {
                resource: "abp-resource:blank-js".into(),
                priority: 0,
                rule_only: false
            })
        );
        let r = net("||x.com/v.mp4$mp4");
        assert_eq!(r.options.types, Some(ResourceTypes::MEDIA));
        assert!(
            matches!(r.options.action, Some(Action::Redirect { ref resource, .. }) if resource == "noopmp4-1s")
        );
        // Bare $redirect only cancels redirects, so it needs @@.
        assert!(matches!(err("||x.com^$redirect"), ParseError::Invalid(_)));
        net("@@||x.com^$redirect");
        assert!(matches!(
            err("||x.com^$rewrite=https://evil/"),
            ParseError::Unsupported { .. }
        ));
        assert!(matches!(
            err("||x.com^$redirect=../../etc"),
            ParseError::Invalid(_)
        ));
    }

    #[test]
    fn removeparam() {
        let a = |l: &str| net(l).options.action;
        assert_eq!(
            a("$removeparam=utm_source"),
            Some(Action::RemoveParam(ParamMatch::Name {
                name: "utm_source".into(),
                negated: false
            }))
        );
        assert_eq!(
            a("||x.com^$removeparam"),
            Some(Action::RemoveParam(ParamMatch::All))
        );
        assert_eq!(
            a("$removeparam=/^(utm_|fbclid)/i"),
            Some(Action::RemoveParam(ParamMatch::Regex {
                source: "^(utm_|fbclid)".into(),
                flags: "i".into(),
                negated: false
            }))
        );
        assert_eq!(
            a("||x.com^$removeparam=~id"),
            Some(Action::RemoveParam(ParamMatch::Name {
                name: "id".into(),
                negated: true
            }))
        );
        // `$` inside the option value.
        assert_eq!(
            a("$removeparam=/^utm$/"),
            Some(Action::RemoveParam(ParamMatch::Regex {
                source: "^utm$".into(),
                flags: "".into(),
                negated: false
            }))
        );
        // Escaped comma in a regex value.
        assert_eq!(
            a("$xhr,removeparam=/^a{1\\,3}$/"),
            Some(Action::RemoveParam(ParamMatch::Regex {
                source: "^a{1,3}$".into(),
                flags: "".into(),
                negated: false
            }))
        );
        assert_eq!(
            a("$queryprune=gclid"),
            Some(Action::RemoveParam(ParamMatch::Name {
                name: "gclid".into(),
                negated: false
            }))
        );
    }

    #[test]
    fn csp_and_friends() {
        let a = |l: &str| net(l).options.action;
        assert_eq!(
            a("||x.com^$csp=script-src 'self'"),
            Some(Action::Csp(Some("script-src 'self'".into())))
        );
        assert_eq!(a("@@||x.com^$csp"), Some(Action::Csp(None)));
        assert!(matches!(err("||x.com^$csp"), ParseError::Invalid(_)));
        assert_eq!(
            a("||x.com^$inline-script"),
            Some(Action::Csp(Some(
                "script-src 'unsafe-eval' * blob: data:".into()
            )))
        );
        assert_eq!(
            a("||x.com^$permissions=browsing-topics=()"),
            Some(Action::Permissions(Some("browsing-topics=()".into())))
        );
    }

    #[test]
    fn only_one_action() {
        assert!(matches!(
            err("||x.com^$redirect=noop.js,removeparam=a"),
            ParseError::Invalid(_)
        ));
    }

    #[test]
    fn urlskip_cookie_removeheader() {
        let a = |l: &str| net(l).options.action;
        assert_eq!(
            a("||l.example.com/l.php?$urlskip=?u -uricomponent"),
            Some(Action::UrlSkip {
                steps: vec!["?u".into(), "-uricomponent".into()]
            })
        );
        assert_eq!(
            a("||x.com^$cookie=_ga;maxAge=86400;sameSite=lax"),
            Some(Action::Cookie(CookieAction {
                name: CookieName::Name("_ga".into()),
                max_age: Some(86400),
                same_site: Some("lax".into())
            }))
        );
        assert_eq!(
            a("$cookie=/^_gid$/,3p"),
            Some(Action::Cookie(CookieAction {
                name: CookieName::Regex("^_gid$".into()),
                max_age: None,
                same_site: None
            }))
        );
        assert_eq!(
            a("||x.com^$removeheader=request:Cookie"),
            Some(Action::RemoveHeader {
                name: "cookie".into(),
                request: true
            })
        );
        assert!(matches!(
            err("||x.com^$removeheader=content-security-policy"),
            ParseError::Unsupported { .. }
        ));
        assert!(matches!(
            err("||x.com^$removeheader=Access-Control-Allow-Origin"),
            ParseError::Unsupported { .. }
        ));
    }

    #[test]
    fn methods_and_headers() {
        let o = net("||x.com^$method=get|head").options;
        assert_eq!(o.methods.len(), 2);
        assert_eq!(o.methods[0].method, "GET");
        assert!(matches!(
            err("||x.com^$method=get|~post"),
            ParseError::Invalid(_)
        ));
        assert!(matches!(
            err("||x.com^$method=brew"),
            ParseError::Invalid(_)
        ));
        let o = net("*$header=Via:/1\\.1\\s+google/").options;
        assert_eq!(
            o.header,
            Some(HeaderMatch {
                name: "via".into(),
                value: Some("/1\\.1\\s+google/".into())
            })
        );
    }

    #[test]
    fn unsupported_and_unknown_options_drop_the_rule() {
        assert_eq!(err("||x.com^$replace=/a/b/").feature(), "option:replace");
        assert_eq!(err("||x.com^$dnstype=AAAA").feature(), "option:dnstype");
        assert_eq!(err("||x.com^$frobnicate").feature(), "option:unknown");
    }

    #[test]
    fn rules_matching_everything_are_refused() {
        assert!(matches!(err("*"), ParseError::Invalid(_)));
        // Restricted by options, it is fine.
        assert!(
            net("*$popup,third-party,domain=a.com")
                .pattern
                .matches_everything()
        );
        assert!(net("$script,domain=a.com").pattern.matches_everything());
    }

    #[test]
    fn malformed() {
        assert!(matches!(err("||"), ParseError::Invalid(_)));
        assert!(matches!(err("|"), ParseError::Invalid(_)));
        assert!(matches!(err("||x.com^$"), ParseError::Invalid(_)));
        assert!(matches!(err("||x.com^$script,"), ParseError::Invalid(_)));
        assert!(matches!(err("ads banner"), ParseError::Invalid(_)));
    }

    #[test]
    fn dollar_in_path_without_options() {
        // Not option-like, so it is part of the pattern.
        assert_eq!(
            net("/ad$file.js").pattern,
            wildcard(Anchor::None, "/ad$file.js", false)
        );
    }
}
