//! Resolver configuration (`sinkhole.toml`).
//!
//! Parsing and validation are separate steps. Deserializing fills in defaults
//! for anything left out; [`Config::validate`] then enforces the safety rules
//! and reports every problem at once, so a user fixes the file in one pass.
//!
//! The rule that matters most: **sinkhole is never an open resolver.** Binding
//! anything other than loopback needs both `listen.allow_non_loopback = true`
//! and a non-empty, non-universal `listen.client_allowlist`.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;

use ipnet::IpNet;
use serde::{Deserialize, Serialize};

use crate::domain::{Domain, DomainError};
use crate::matcher::{Scope, parse_domain_pattern};

/// The whole config file.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub listen: Listen,
    pub blocking: Blocking,
    /// Tried in order; later entries are failovers.
    #[serde(rename = "upstream")]
    pub upstreams: Vec<Upstream>,
    pub cache: Cache,
    #[serde(rename = "list")]
    pub lists: Vec<ListSource>,
    pub updates: Updates,
    /// Local allowlist entries: `example.com` (and everything below it) or
    /// `*.example.com` (only names below it). These beat every blocklist.
    pub allow: Vec<String>,
    /// Local blocklist entries, same syntax as `allow`.
    pub block: Vec<String>,
    pub special_names: SpecialNames,
    pub query_log: QueryLog,
    pub metrics: Metrics,
    pub control: Control,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            listen: Listen::default(),
            blocking: Blocking::default(),
            upstreams: default_upstreams(),
            cache: Cache::default(),
            lists: Vec::new(),
            updates: Updates::default(),
            allow: Vec::new(),
            block: Vec::new(),
            special_names: SpecialNames::default(),
            query_log: QueryLog::default(),
            metrics: Metrics::default(),
            control: Control::default(),
        }
    }
}

/// Where the resolver listens and who may query it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Listen {
    /// UDP and TCP are both served on each address.
    pub addrs: Vec<SocketAddr>,
    /// Must be `true` to bind a non-loopback address. A separate switch so a
    /// typo in `addrs` cannot expose the resolver to the network.
    pub allow_non_loopback: bool,
    /// Client networks allowed to query when a non-loopback address is bound.
    pub client_allowlist: Vec<IpNet>,
}

impl Default for Listen {
    fn default() -> Self {
        Listen {
            addrs: vec![
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 53),
                SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 53),
            ],
            allow_non_loopback: false,
            client_allowlist: Vec::new(),
        }
    }
}

/// How blocked names are answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockResponse {
    /// `0.0.0.0` for A, `::` for AAAA, NODATA for other types. Clients fail
    /// fast and do not retry another resolver, which NXDOMAIN can provoke.
    #[default]
    NullAddress,
    /// NXDOMAIN for every type.
    Nxdomain,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Blocking {
    pub response: BlockResponse,
    /// TTL of block responses. Short, so an allowlist change takes effect
    /// quickly in client caches.
    pub ttl_secs: u32,
    /// Also block HTTPS/SVCB (type 65) records of blocked names. Without
    /// this, browsers can learn alternative endpoints for a blocked name.
    pub block_https_records: bool,
    /// Block an answer whose CNAME chain (or HTTPS/SVCB target) leads to a
    /// blocked name, e.g. `metrics.shop.example` → `shop.tracker.example`.
    /// A name on the allowlist is never uncloaked.
    pub cname_uncloaking: bool,
}

impl Default for Blocking {
    fn default() -> Self {
        Blocking {
            response: BlockResponse::NullAddress,
            ttl_secs: 10,
            block_https_records: true,
            cname_uncloaking: true,
        }
    }
}

/// An upstream resolver.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "protocol", rename_all = "lowercase", deny_unknown_fields)]
pub enum Upstream {
    /// DNS over HTTPS (RFC 8484).
    Doh {
        url: String,
        /// Addresses for the URL's host. Required when the host is a name:
        /// once sinkhole is the system resolver it cannot ask itself.
        #[serde(default)]
        bootstrap: Vec<IpAddr>,
    },
    /// DNS over TLS (RFC 7858).
    Dot {
        addr: SocketAddr,
        /// Name the server's certificate must carry.
        server_name: String,
    },
    /// Plain DNS over UDP, with TCP fallback on truncation. Unencrypted.
    Udp { addr: SocketAddr },
}

fn default_upstreams() -> Vec<Upstream> {
    let ip = |s: &str| s.parse().ok();
    vec![
        Upstream::Doh {
            url: "https://dns.quad9.net/dns-query".into(),
            bootstrap: ["9.9.9.9", "149.112.112.112", "2620:fe::fe"]
                .into_iter()
                .filter_map(ip)
                .collect(),
        },
        Upstream::Doh {
            url: "https://cloudflare-dns.com/dns-query".into(),
            bootstrap: ["1.1.1.1", "1.0.0.1", "2606:4700:4700::1111"]
                .into_iter()
                .filter_map(ip)
                .collect(),
        },
    ]
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Cache {
    pub max_entries: usize,
    /// Answers are cached for at least this long, even if their TTL is lower.
    pub min_ttl_secs: u32,
    pub max_ttl_secs: u32,
    /// Cap on negative-answer caching (RFC 2308 §5 suggests 1–3 hours).
    pub max_negative_ttl_secs: u32,
    /// When every upstream fails, answer from an expired entry up to this
    /// long after it expired, with a 30 s TTL (RFC 8767). 0 turns it off.
    pub serve_stale_secs: u32,
}

impl Default for Cache {
    fn default() -> Self {
        Cache {
            max_entries: 10_000,
            min_ttl_secs: 0,
            max_ttl_secs: 86_400,
            max_negative_ttl_secs: 3_600,
            serve_stale_secs: 86_400,
        }
    }
}

/// Syntax of a list. `auto` detects it per line.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ListFormat {
    #[default]
    Auto,
    /// `0.0.0.0 ads.example.com`
    Hosts,
    /// One name per line, optionally `*.`-prefixed.
    Domains,
    /// Adblock syntax; only `||name^` and `@@||name^` rules apply to DNS.
    Adblock,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ListAction {
    #[default]
    Block,
    Allow,
}

/// A filter list, fetched from `url` or read from `path`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListSource {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub path: Option<PathBuf>,
    #[serde(default)]
    pub format: ListFormat,
    #[serde(default)]
    pub action: ListAction,
    #[serde(default = "enabled")]
    pub enabled: bool,
    /// Check a `url` list for a new version this often. Overrides the
    /// list's own `! Expires:` header and `updates.interval_hours`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh_hours: Option<u32>,
}

fn enabled() -> bool {
    true
}

/// How lists fetched by URL are kept current.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Updates {
    /// Check a list for a new version this often, unless the list says how
    /// often itself (`! Expires: 4 days`) or sets `refresh_hours`.
    pub interval_hours: u32,
    /// Where downloaded lists are kept, so the resolver starts with them
    /// and keeps them when a download fails. Relative paths are resolved
    /// against the config file's directory. Unset: the platform's cache
    /// directory (`~/Library/Caches/sinkhole`, `~/.cache/sinkhole`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache_dir: Option<PathBuf>,
}

impl Default for Updates {
    fn default() -> Self {
        Updates {
            interval_hours: 24,
            cache_dir: None,
        }
    }
}

/// The range allowed for refresh intervals, in hours: an hour to 30 days.
pub const REFRESH_HOURS: std::ops::RangeInclusive<u32> = 1..=720;

/// Names that mean something only on this machine or network.
///
/// `localhost`, `.invalid`, the loopback and documentation reverse zones and
/// `resolver.arpa` are always answered locally. The private ones below are
/// too, unless `forward_private` is set.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SpecialNames {
    /// Forward reverse lookups of private addresses (RFC 6303), `.local`
    /// and `home.arpa` instead of answering NXDOMAIN. Set it when the
    /// upstream is a router or company server that knows the local names;
    /// a public upstream cannot answer them, and asking leaks them.
    pub forward_private: bool,
}

/// Per-query logging. Off by default; when on, it stays on this machine.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct QueryLog {
    pub enabled: bool,
    pub retention_hours: u32,
    pub max_entries: usize,
}

impl Default for QueryLog {
    fn default() -> Self {
        QueryLog {
            enabled: false,
            retention_hours: 24,
            max_entries: 100_000,
        }
    }
}

/// Prometheus `/metrics`. Off by default and loopback-only.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Metrics {
    pub enabled: bool,
    pub listen: SocketAddr,
}

impl Default for Metrics {
    fn default() -> Self {
        Metrics {
            enabled: false,
            listen: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9153),
        }
    }
}

/// The control socket that `sinkhole stats`, `pause` and the browser
/// bridge use.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Control {
    /// Where the socket is created. Relative paths are resolved against the
    /// config file's directory. Unset: `control.sock` in the cache
    /// directory.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub socket: Option<PathBuf>,
    /// Users (numeric ids) who may pause, resume, reload and read the
    /// query log, besides root and the user the daemon runs as. Anyone may
    /// read the counters.
    pub users: Vec<u32>,
}

/// One problem found by [`Config::validate`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConfigError {
    #[error("listen.addrs is empty")]
    NoListenAddrs,
    #[error(
        "listen.addrs: {0} is not a loopback address; to serve other machines set \
         listen.allow_non_loopback = true and list their networks in listen.client_allowlist"
    )]
    NonLoopbackListen(SocketAddr),
    #[error("listen.client_allowlist must not be empty when listen.allow_non_loopback is true")]
    EmptyClientAllowlist,
    #[error(
        "listen.client_allowlist: {0} admits every address, which makes an open resolver; \
         list the networks that should be able to query"
    )]
    ClientAllowlistTooBroad(IpNet),
    #[error("at least one [[upstream]] is required")]
    NoUpstreams,
    #[error("upstream #{index}: {reason}")]
    Upstream { index: usize, reason: String },
    #[error("list #{index}: {reason}")]
    List { index: usize, reason: String },
    #[error("{field}: {value:?} is not a valid entry: {reason}")]
    Entry {
        field: &'static str,
        value: String,
        reason: DomainError,
    },
    #[error("blocking.ttl_secs must be at most 86400")]
    BlockTtl,
    #[error("cache.min_ttl_secs is greater than cache.max_ttl_secs")]
    CacheTtlRange,
    #[error("cache.serve_stale_secs must be at most 604800 (7 days)")]
    ServeStale,
    #[error("query_log.retention_hours must be between 1 and 720")]
    Retention,
    #[error("updates.interval_hours must be between 1 and 720")]
    UpdateInterval,
    #[error("metrics.listen: {0} is not a loopback address; metrics are only served locally")]
    MetricsNotLoopback(SocketAddr),
}

/// Why a config file could not be loaded.
#[derive(Debug, thiserror::Error)]
pub enum LoadError {
    #[error(transparent)]
    Syntax(#[from] toml::de::Error),
    #[error("{}", Problems(.0))]
    Invalid(Vec<ConfigError>),
}

struct Problems<'a>(&'a [ConfigError]);

impl fmt::Display for Problems<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid config ({} problem(s)):", self.0.len())?;
        for p in self.0 {
            write!(f, "\n  - {p}")?;
        }
        Ok(())
    }
}

impl Config {
    /// Parses and validates a TOML document.
    pub fn from_toml(text: &str) -> Result<Config, LoadError> {
        let config: Config = toml::from_str(text)?;
        config.validate().map_err(LoadError::Invalid)?;
        Ok(config)
    }

    /// Serializes to TOML, e.g. to write a starter config.
    pub fn to_toml(&self) -> Result<String, toml::ser::Error> {
        toml::to_string_pretty(self)
    }

    /// The local allowlist entries, parsed. Call after [`Config::validate`].
    pub fn allow_entries(&self) -> impl Iterator<Item = Result<(Domain, Scope), DomainError>> + '_ {
        self.allow.iter().map(|s| parse_domain_pattern(s))
    }

    /// The local blocklist entries, parsed. Call after [`Config::validate`].
    pub fn block_entries(&self) -> impl Iterator<Item = Result<(Domain, Scope), DomainError>> + '_ {
        self.block.iter().map(|s| parse_domain_pattern(s))
    }

    /// Checks every safety and consistency rule, returning all violations.
    pub fn validate(&self) -> Result<(), Vec<ConfigError>> {
        let mut errors = Vec::new();
        self.validate_listen(&mut errors);
        self.validate_upstreams(&mut errors);
        self.validate_lists(&mut errors);
        for (field, entries) in [("allow", &self.allow), ("block", &self.block)] {
            for value in entries {
                if let Err(reason) = parse_domain_pattern(value) {
                    errors.push(ConfigError::Entry {
                        field,
                        value: value.clone(),
                        reason,
                    });
                }
            }
        }
        if self.blocking.ttl_secs > 86_400 {
            errors.push(ConfigError::BlockTtl);
        }
        if self.cache.min_ttl_secs > self.cache.max_ttl_secs {
            errors.push(ConfigError::CacheTtlRange);
        }
        if self.cache.serve_stale_secs > 604_800 {
            errors.push(ConfigError::ServeStale);
        }
        if !(1..=720).contains(&self.query_log.retention_hours) {
            errors.push(ConfigError::Retention);
        }
        if !REFRESH_HOURS.contains(&self.updates.interval_hours) {
            errors.push(ConfigError::UpdateInterval);
        }
        if self.metrics.enabled && !is_loopback(self.metrics.listen.ip()) {
            errors.push(ConfigError::MetricsNotLoopback(self.metrics.listen));
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    fn validate_listen(&self, errors: &mut Vec<ConfigError>) {
        let listen = &self.listen;
        if listen.addrs.is_empty() {
            errors.push(ConfigError::NoListenAddrs);
        }
        let exposed = listen.addrs.iter().any(|a| !is_loopback(a.ip()));
        if !listen.allow_non_loopback {
            for addr in listen.addrs.iter().filter(|a| !is_loopback(a.ip())) {
                errors.push(ConfigError::NonLoopbackListen(*addr));
            }
        } else if exposed && listen.client_allowlist.is_empty() {
            errors.push(ConfigError::EmptyClientAllowlist);
        }
        for net in &listen.client_allowlist {
            if net.prefix_len() == 0 {
                errors.push(ConfigError::ClientAllowlistTooBroad(*net));
            }
        }
    }

    fn validate_upstreams(&self, errors: &mut Vec<ConfigError>) {
        if self.upstreams.is_empty() {
            errors.push(ConfigError::NoUpstreams);
        }
        for (index, upstream) in self.upstreams.iter().enumerate() {
            let mut fail = |reason: String| errors.push(ConfigError::Upstream { index, reason });
            match upstream {
                Upstream::Doh { url, bootstrap } => match url_host(url) {
                    None => fail(format!("{url:?} is not an https:// URL with a host")),
                    Some(host) => {
                        let host_is_ip = host.trim_matches(['[', ']']).parse::<IpAddr>().is_ok();
                        if !host_is_ip && bootstrap.is_empty() {
                            fail(format!(
                                "{host} is a name, so `bootstrap` addresses are required \
                                 (sinkhole cannot resolve its own upstream)"
                            ));
                        }
                    }
                },
                Upstream::Dot { addr, server_name } => {
                    if let Err(e) = Domain::parse(server_name) {
                        fail(format!("server_name {server_name:?}: {e}"));
                    }
                    self.check_not_self(*addr, &mut fail);
                }
                Upstream::Udp { addr } => self.check_not_self(*addr, &mut fail),
            }
        }
    }

    /// Forwarding to an address we listen on would loop forever.
    fn check_not_self(&self, addr: SocketAddr, fail: &mut impl FnMut(String)) {
        let loops =
            self.listen.addrs.iter().any(|l| {
                l.port() == addr.port() && (l.ip() == addr.ip() || l.ip().is_unspecified())
            });
        if loops {
            fail(format!("{addr} is one of sinkhole's own listen addresses"));
        }
    }

    fn validate_lists(&self, errors: &mut Vec<ConfigError>) {
        for (index, list) in self.lists.iter().enumerate() {
            let reason = match (&list.url, &list.path) {
                (Some(_), Some(_)) => Some("set either `url` or `path`, not both".to_owned()),
                (None, None) => Some("one of `url` or `path` is required".to_owned()),
                (Some(url), None) if url_host(url).is_none() => Some(format!(
                    "{url:?} is not an https:// URL; lists are only fetched over HTTPS"
                )),
                (None, Some(_)) if list.refresh_hours.is_some() => Some(
                    "`refresh_hours` applies to `url` lists; local files are reloaded \
                     whenever they change"
                        .to_owned(),
                ),
                _ => match list.refresh_hours {
                    Some(hours) if !REFRESH_HOURS.contains(&hours) => {
                        Some("`refresh_hours` must be between 1 and 720".to_owned())
                    }
                    _ => None,
                },
            };
            if let Some(reason) = reason {
                errors.push(ConfigError::List { index, reason });
            }
        }
    }
}

/// Loopback, including IPv4-mapped IPv6 loopback (`::ffff:127.0.0.1`).
fn is_loopback(ip: IpAddr) -> bool {
    ip.to_canonical().is_loopback()
}

/// The host of an `https://` URL, or `None` if it is not one.
fn url_host(url: &str) -> Option<&str> {
    let rest = url.strip_prefix("https://")?;
    let authority = rest.split(['/', '?', '#']).next()?;
    let host_port = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    let host = if host_port.starts_with('[') {
        // [v6]:port
        &host_port[..=host_port.find(']')?]
    } else {
        host_port.split(':').next()?
    };
    (!host.is_empty()).then_some(host)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn errors(toml: &str) -> Vec<ConfigError> {
        match Config::from_toml(toml) {
            Err(LoadError::Invalid(e)) => e,
            other => panic!("expected validation errors, got {other:?}"),
        }
    }

    #[test]
    fn defaults_are_valid_and_loopback_only() {
        let c = Config::default();
        c.validate().unwrap();
        assert!(c.listen.addrs.iter().all(|a| a.ip().is_loopback()));
        assert!(!c.query_log.enabled);
        assert!(!c.metrics.enabled);
    }

    #[test]
    fn empty_file_gives_defaults() {
        assert_eq!(Config::from_toml("").unwrap(), Config::default());
    }

    #[test]
    fn default_config_round_trips_through_toml() {
        let text = Config::default().to_toml().unwrap();
        assert_eq!(Config::from_toml(&text).unwrap(), Config::default());
    }

    #[test]
    fn full_example_parses() {
        let c = Config::from_toml(
            r#"
            allow = ["cdn.example.com", "*.example.org"]
            block = ["ads.example.net"]

            [listen]
            addrs = ["127.0.0.1:5353"]

            [blocking]
            response = "nxdomain"
            ttl_secs = 30

            [[upstream]]
            protocol = "doh"
            url = "https://dns.example/dns-query"
            bootstrap = ["192.0.2.1"]

            [[upstream]]
            protocol = "dot"
            addr = "192.0.2.2:853"
            server_name = "dns.example"

            [[upstream]]
            protocol = "udp"
            addr = "192.0.2.3:53"

            [[list]]
            name = "ads"
            url = "https://lists.example/hosts.txt"
            format = "hosts"

            refresh_hours = 6

            [[list]]
            path = "/etc/sinkhole/allow.txt"
            action = "allow"
            enabled = false

            [updates]
            interval_hours = 12
            cache_dir = "cache"
            "#,
        )
        .unwrap();
        assert_eq!(c.lists[0].refresh_hours, Some(6));
        assert_eq!(c.updates.interval_hours, 12);
        assert_eq!(c.updates.cache_dir, Some(PathBuf::from("cache")));
        assert_eq!(c.blocking.response, BlockResponse::Nxdomain);
        assert_eq!(c.upstreams.len(), 3);
        assert_eq!(c.lists[1].action, ListAction::Allow);
        assert!(!c.lists[1].enabled);
        let allow: Vec<_> = c.allow_entries().map(Result::unwrap).collect();
        assert_eq!(allow[1].1, Scope::Subdomains);
    }

    #[test]
    fn unknown_fields_are_rejected() {
        assert!(matches!(
            Config::from_toml("[listen]\naddress = \"127.0.0.1:53\""),
            Err(LoadError::Syntax(_))
        ));
        assert!(matches!(
            Config::from_toml(
                "[[upstream]]\nprotocol = \"udp\"\naddr = \"192.0.2.1:53\"\nport = 1"
            ),
            Err(LoadError::Syntax(_))
        ));
    }

    #[test]
    fn non_loopback_needs_explicit_flag() {
        let e = errors("[listen]\naddrs = [\"0.0.0.0:53\"]");
        assert!(matches!(e[..], [ConfigError::NonLoopbackListen(_)]));
        let e = errors("[listen]\naddrs = [\"192.168.1.2:53\"]");
        assert!(matches!(e[..], [ConfigError::NonLoopbackListen(_)]));
    }

    #[test]
    fn non_loopback_needs_client_allowlist() {
        let e = errors("[listen]\naddrs = [\"192.168.1.2:53\"]\nallow_non_loopback = true");
        assert_eq!(e, [ConfigError::EmptyClientAllowlist]);
        Config::from_toml(
            "[listen]\naddrs = [\"192.168.1.2:53\"]\nallow_non_loopback = true\nclient_allowlist = [\"192.168.1.0/24\"]",
        )
        .unwrap();
    }

    #[test]
    fn universal_client_allowlist_is_refused() {
        let e = errors(
            "[listen]\naddrs = [\"[::]:53\"]\nallow_non_loopback = true\nclient_allowlist = [\"::/0\"]",
        );
        assert!(matches!(e[..], [ConfigError::ClientAllowlistTooBroad(_)]));
    }

    #[test]
    fn mapped_loopback_counts_as_loopback() {
        Config::from_toml("[listen]\naddrs = [\"[::ffff:127.0.0.1]:53\"]").unwrap();
    }

    #[test]
    fn doh_with_hostname_needs_bootstrap() {
        let e = errors("[[upstream]]\nprotocol = \"doh\"\nurl = \"https://dns.example/dns-query\"");
        assert!(matches!(&e[..], [ConfigError::Upstream { index: 0, .. }]));
        Config::from_toml(
            "[[upstream]]\nprotocol = \"doh\"\nurl = \"https://192.0.2.1/dns-query\"",
        )
        .unwrap();
        Config::from_toml(
            "[[upstream]]\nprotocol = \"doh\"\nurl = \"https://[2001:db8::1]:8443/q\"",
        )
        .unwrap();
    }

    #[test]
    fn doh_must_be_https() {
        let e = errors("[[upstream]]\nprotocol = \"doh\"\nurl = \"http://192.0.2.1/dns-query\"");
        assert!(matches!(&e[..], [ConfigError::Upstream { .. }]));
    }

    #[test]
    fn forwarding_to_ourselves_is_refused() {
        let e = errors("[[upstream]]\nprotocol = \"udp\"\naddr = \"127.0.0.1:53\"");
        assert!(matches!(&e[..], [ConfigError::Upstream { .. }]));
        // Same IP, different port is fine (e.g. a local unbound on 5335).
        Config::from_toml("[[upstream]]\nprotocol = \"udp\"\naddr = \"127.0.0.1:5335\"").unwrap();
    }

    #[test]
    fn lists_must_be_https_or_local() {
        let e = errors("[[list]]\nurl = \"http://lists.example/hosts\"");
        assert!(matches!(&e[..], [ConfigError::List { index: 0, .. }]));
        let e = errors("[[list]]\nformat = \"hosts\"");
        assert!(matches!(&e[..], [ConfigError::List { .. }]));
    }

    #[test]
    fn refresh_intervals_are_bounded() {
        let e = errors("[updates]\ninterval_hours = 0");
        assert_eq!(e, [ConfigError::UpdateInterval]);
        let e = errors("[[list]]\nurl = \"https://l.example/a\"\nrefresh_hours = 721");
        assert!(matches!(&e[..], [ConfigError::List { index: 0, .. }]));
        let e = errors("[[list]]\npath = \"a.txt\"\nrefresh_hours = 6");
        assert!(matches!(&e[..], [ConfigError::List { index: 0, .. }]));
    }

    #[test]
    fn bad_entries_are_reported_with_all_other_problems() {
        let e = errors(
            "allow = [\"ok.example\", \"bad entry\"]\nblock = [\"1.2.3.4\"]\n[metrics]\nenabled = true\nlisten = \"0.0.0.0:9153\"",
        );
        assert_eq!(e.len(), 3, "{e:?}");
    }

    #[test]
    fn url_host_extraction() {
        assert_eq!(url_host("https://a.example/x"), Some("a.example"));
        assert_eq!(url_host("https://a.example:8443"), Some("a.example"));
        assert_eq!(url_host("https://u:p@a.example/x"), Some("a.example"));
        assert_eq!(url_host("https://[::1]:443/"), Some("[::1]"));
        assert_eq!(url_host("https:///x"), None);
        assert_eq!(url_host("ftp://a.example"), None);
    }
}
