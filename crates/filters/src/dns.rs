//! The syntaxes the resolver reads: hosts files, plain domain lists, and the
//! subset of adblock syntax a DNS server can honor (`||name^`, `@@||name^`).
//!
//! DNS sees a hostname and nothing else: not the page, the request type or
//! the URL path. A rule that depends on any of those cannot be applied
//! faithfully, so it is reported, never applied in a broadened form. Every
//! entry blocks (or allows) the whole subtree below its name; `*.name` covers
//! only the names below. See [`sinkhole_core::matcher`].
//!
//! `$important` is accepted but has no effect: in sinkhole the allowlist
//! always wins.

use std::collections::BTreeMap;
use std::net::IpAddr;

use sinkhole_core::{
    Domain, DomainError, DomainMatcher, DomainMatcherBuilder, Scope, parse_domain_pattern,
};

use crate::network::{NetworkOptions, ResourceTypes};
use crate::preprocess::{Env, Line, Lines};
use crate::{ParseError, Rule, parse_rule};

/// Syntax of a whole list. `Auto` decides per line.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DnsFormat {
    #[default]
    Auto,
    Hosts,
    Domains,
    Adblock,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsAction {
    Block,
    Allow,
}

/// One entry for the domain matcher.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsRule {
    pub action: DnsAction,
    pub domain: Domain,
    pub scope: Scope,
    /// `$badfilter`: cancels the identical entry from any list.
    pub badfilter: bool,
}

/// Names that hosts files map to loopback for the machine's own use.
const LOCAL_NAMES: &[&str] = &[
    "localhost",
    "localhost.localdomain",
    "local",
    "broadcasthost",
    "ip6-localhost",
    "ip6-loopback",
    "ip6-localnet",
    "ip6-mcastprefix",
    "ip6-allnodes",
    "ip6-allrouters",
    "ip6-allhosts",
];

/// Parses one line. `list_action` is what plain entries mean in this list
/// (a hosts file used as an allowlist allows). Comments give an empty vec.
pub fn parse_dns_line(
    line: &str,
    format: DnsFormat,
    list_action: DnsAction,
) -> Result<Vec<DnsRule>, ParseError> {
    let line = line.trim();
    if line.is_empty() || crate::is_comment(line) {
        return Ok(Vec::new());
    }
    // `##.ad` is a cosmetic rule in an adblock list but a comment in a hosts file.
    if line.starts_with('#') && matches!(format, DnsFormat::Hosts | DnsFormat::Domains) {
        return Ok(Vec::new());
    }
    let syntax = match format {
        DnsFormat::Auto => detect(line),
        f => f,
    };
    match syntax {
        DnsFormat::Hosts => hosts_line(line, list_action),
        // In an adblock list, `.120x600.` is a URL fragment, not a bad domain.
        DnsFormat::Domains if format == DnsFormat::Auto => match domain_line(line, list_action) {
            Err(ParseError::Invalid(_)) => adblock_line(line, list_action),
            result => result,
        },
        DnsFormat::Domains => domain_line(line, list_action),
        DnsFormat::Adblock | DnsFormat::Auto => adblock_line(line, list_action),
    }
}

fn detect(line: &str) -> DnsFormat {
    let first = line.split_whitespace().next().unwrap_or_default();
    let entry = strip_comment(line);
    if first.parse::<IpAddr>().is_ok() {
        DnsFormat::Hosts
    } else if !entry.is_empty()
        && entry
            .chars()
            .all(|c| c.is_alphanumeric() || matches!(c, '.' | '-' | '_' | '*'))
    {
        DnsFormat::Domains
    } else {
        DnsFormat::Adblock
    }
}

/// Drops a trailing `# comment`. The `#` must start the line or follow
/// whitespace, so `example.com##.ad` keeps its `##`.
fn strip_comment(line: &str) -> &str {
    let bytes = line.as_bytes();
    let end = (0..bytes.len())
        .find(|&i| bytes[i] == b'#' && (i == 0 || bytes[i - 1].is_ascii_whitespace()))
        .unwrap_or(bytes.len());
    line[..end].trim()
}

fn domain_error(entry: &str, e: DomainError) -> ParseError {
    match e {
        DomainError::IpAddress(_) => ParseError::unsupported(
            "dns:ip-literal",
            format!("{entry} is an IP address, which is never looked up in DNS"),
        ),
        e => ParseError::invalid(format!("{entry:?}: {e}")),
    }
}

fn hosts_line(line: &str, action: DnsAction) -> Result<Vec<DnsRule>, ParseError> {
    let mut tokens = strip_comment(line).split_whitespace();
    let Some(ip) = tokens.next() else {
        return Ok(Vec::new());
    };
    let ip: IpAddr = ip
        .parse()
        .map_err(|_| ParseError::invalid(format!("{ip:?} is not an IP address")))?;
    if !(ip.is_unspecified() || ip.is_loopback()) {
        return Err(ParseError::unsupported(
            "dns:hosts-redirect",
            format!("maps names to {ip}; only 0.0.0.0, 127.0.0.1, :: and ::1 entries are blocks"),
        ));
    }
    tokens
        .filter(|name| !LOCAL_NAMES.contains(name) && name.parse::<IpAddr>().is_err())
        .map(|name| {
            Ok(DnsRule {
                action,
                domain: Domain::parse(name).map_err(|e| domain_error(name, e))?,
                scope: Scope::Subtree,
                badfilter: false,
            })
        })
        .collect()
}

fn domain_line(line: &str, action: DnsAction) -> Result<Vec<DnsRule>, ParseError> {
    let entry = strip_comment(line);
    if entry.is_empty() {
        return Ok(Vec::new());
    }
    if entry.split_whitespace().nth(1).is_some() {
        return Err(ParseError::invalid(
            "more than one name on a domain-list line",
        ));
    }
    if entry.trim_start_matches("*.").contains('*') {
        return Err(ParseError::unsupported(
            "dns:wildcard",
            "only a leading `*.` can be matched by DNS suffix",
        ));
    }
    let (domain, scope) = parse_domain_pattern(entry).map_err(|e| domain_error(entry, e))?;
    Ok(vec![DnsRule {
        action,
        domain,
        scope,
        badfilter: false,
    }])
}

fn adblock_line(line: &str, list_action: DnsAction) -> Result<Vec<DnsRule>, ParseError> {
    let page_rule = || {
        ParseError::unsupported(
            "dns:page-rule",
            "cosmetic and scriptlet rules need a browser",
        )
    };
    let rule = match parse_rule(line) {
        Ok(Rule::Network(rule)) => rule,
        Ok(_) => return Err(page_rule()),
        // Whether or not the browser side could use it, DNS cannot.
        Err(_) if crate::cosmetic::find_separator(line).is_some() => return Err(page_rule()),
        Err(e) => return Err(e),
    };
    let Some(host) = rule.pattern.pure_hostname() else {
        return Err(ParseError::unsupported(
            "dns:not-hostname",
            "only ||name^ rules can be decided from a hostname",
        ));
    };
    let o = &rule.options;
    // Only options that say nothing about the request beyond its host.
    let neutral = NetworkOptions {
        types: o.types.filter(|t| *t != ResourceTypes::ALL),
        important: false,
        badfilter: false,
        match_case: false,
        ..o.clone()
    };
    if neutral != NetworkOptions::default() {
        return Err(ParseError::unsupported(
            "dns:options",
            "the rule depends on the page, request type or URL, which DNS cannot see",
        ));
    }
    Ok(vec![DnsRule {
        action: if rule.exception {
            DnsAction::Allow
        } else {
            list_action
        },
        domain: Domain::parse(host).map_err(|e| domain_error(host, e))?,
        scope: Scope::Subtree,
        badfilter: o.badfilter,
    }])
}

/// What happened to a set of lists.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DnsReport {
    pub lines: usize,
    pub block_entries: usize,
    pub allow_entries: usize,
    /// Entries removed by `$badfilter`.
    pub badfiltered: usize,
    /// Lines skipped because an `!#if` around them is false.
    pub excluded: usize,
    /// Rejected lines by [`ParseError::feature`].
    pub rejected: BTreeMap<String, usize>,
    /// The first rejected line for each feature, for diagnostics.
    pub examples: BTreeMap<String, String>,
}

impl DnsReport {
    pub fn rejected_total(&self) -> usize {
        self.rejected.values().sum()
    }
}

/// Turns any number of lists into one [`DomainMatcher`].
///
/// `!#if` conditions are evaluated against [`Env::dns`] unless another
/// environment is given. `!#include` lines are skipped: the list loader
/// (`sinkhole-lists`) fetches included files and adds each one as a list of
/// its own.
#[derive(Default)]
pub struct DnsListBuilder {
    matcher: DomainMatcherBuilder,
    env: Env,
    badfilters: Vec<DnsRule>,
    local: Vec<DnsRule>,
    report: DnsReport,
}

impl DnsListBuilder {
    pub fn new() -> Self {
        Self::with_env(Env::dns())
    }

    pub fn with_env(env: Env) -> Self {
        DnsListBuilder {
            env,
            ..Self::default()
        }
    }

    /// Adds every line of a list.
    pub fn add_list(&mut self, text: &str, format: DnsFormat, action: DnsAction) {
        // Real blocklists average 20-30 bytes per line; reserving up front
        // avoids rehashing a million-entry table a dozen times.
        if action == DnsAction::Block {
            self.matcher.reserve_block(text.len() / 24, text.len());
        }
        // `add_rule` needs `&mut self` while the lines borrow the env.
        let env = std::mem::take(&mut self.env);
        let mut lines = Lines::new(text, &env);
        for (_, line) in lines.by_ref() {
            let (text, result) = match line {
                Line::Text(text) => {
                    let result = parse_dns_line(&text, format, action).and_then(|rules| {
                        rules.into_iter().try_for_each(|rule| {
                            self.add_rule(rule)
                                .map_err(|e| ParseError::invalid(e.to_string()))
                        })
                    });
                    (text, result)
                }
                Line::Invalid { text, message } => (text, Err(ParseError::invalid(message))),
                Line::Excluded => {
                    self.report.excluded += 1;
                    continue;
                }
                Line::Include(_) | Line::Directive => continue,
            };
            if let Err(e) = result {
                let feature = e.feature().to_owned();
                self.report
                    .examples
                    .entry(feature.clone())
                    .or_insert_with(|| text.into_owned());
                *self.report.rejected.entry(feature).or_default() += 1;
            }
        }
        self.report.lines += lines.lines_read();
        self.env = env;
    }

    /// Adds one entry.
    pub fn add_rule(&mut self, rule: DnsRule) -> Result<(), sinkhole_core::CapacityError> {
        if rule.badfilter {
            self.badfilters.push(rule);
            return Ok(());
        }
        match rule.action {
            DnsAction::Block => self.matcher.block(&rule.domain, rule.scope)?,
            DnsAction::Allow => self.matcher.allow(&rule.domain, rule.scope)?,
        };
        Ok(())
    }

    /// Adds an entry the user wrote themselves (the config's `allow` and
    /// `block`). A list's `$badfilter` cannot cancel it: lists are written
    /// by third parties, and the local entries are how the user overrides
    /// them.
    pub fn add_local_rule(&mut self, rule: DnsRule) -> Result<(), sinkhole_core::CapacityError> {
        let rule = DnsRule {
            badfilter: false,
            ..rule
        };
        self.add_rule(rule.clone())?;
        self.local.push(rule);
        Ok(())
    }

    /// Applies `$badfilter`s and builds the matcher.
    pub fn finish(mut self) -> (DomainMatcher, DnsReport) {
        for rule in std::mem::take(&mut self.badfilters) {
            let removed = match rule.action {
                DnsAction::Block => self.matcher.unblock(&rule.domain),
                DnsAction::Allow => self.matcher.unallow(&rule.domain),
            };
            self.report.badfiltered += usize::from(removed);
        }
        // Put back any local entry a `$badfilter` just removed. This cannot
        // run out of capacity: each one fitted before, and nothing has been
        // added since.
        for rule in std::mem::take(&mut self.local) {
            let _ = self.add_rule(rule);
        }
        self.report.block_entries = self.matcher.block_len();
        self.report.allow_entries = self.matcher.allow_len();
        (self.matcher.build(), self.report)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sinkhole_core::Verdict;

    fn line(l: &str) -> Result<Vec<(String, Scope, DnsAction)>, ParseError> {
        parse_dns_line(l, DnsFormat::Auto, DnsAction::Block).map(|v| {
            v.into_iter()
                .map(|r| (r.domain.to_string(), r.scope, r.action))
                .collect()
        })
    }

    fn one(l: &str) -> (String, Scope, DnsAction) {
        let mut v = line(l).unwrap_or_else(|e| panic!("{l}: {e}"));
        assert_eq!(v.len(), 1, "{l}");
        v.remove(0)
    }

    use DnsAction::{Allow, Block};
    use Scope::{Subdomains, Subtree};

    #[test]
    fn hosts_lines() {
        assert_eq!(
            one("0.0.0.0 Ads.Example.com"),
            ("ads.example.com".into(), Subtree, Block)
        );
        assert_eq!(
            one("127.0.0.1\tads.example.com # tracker"),
            ("ads.example.com".into(), Subtree, Block)
        );
        assert_eq!(
            one(":: ads.example.com"),
            ("ads.example.com".into(), Subtree, Block)
        );
        assert_eq!(line("0.0.0.0 a.example b.example").unwrap().len(), 2);
        assert!(line("127.0.0.1 localhost").unwrap().is_empty());
        assert!(line("::1 ip6-localhost ip6-loopback").unwrap().is_empty());
        assert!(line("0.0.0.0 0.0.0.0").unwrap().is_empty());
        assert_eq!(
            line("192.0.2.1 example.com").unwrap_err().feature(),
            "dns:hosts-redirect"
        );
        assert!(matches!(
            line("0.0.0.0 bad_name!"),
            Err(ParseError::Invalid(_))
        ));
    }

    #[test]
    fn domain_lines() {
        assert_eq!(
            one("ads.example.com"),
            ("ads.example.com".into(), Subtree, Block)
        );
        assert_eq!(
            one("*.example.com"),
            ("example.com".into(), Subdomains, Block)
        );
        assert_eq!(
            one("bücher.de # idn"),
            ("xn--bcher-kva.de".into(), Subtree, Block)
        );
        assert_eq!(
            line("ads*.example.com").unwrap_err().feature(),
            "dns:wildcard"
        );
    }

    #[test]
    fn adblock_lines() {
        assert_eq!(
            one("||ads.example.com^"),
            ("ads.example.com".into(), Subtree, Block)
        );
        assert_eq!(
            one("||ads.example.com^$important"),
            ("ads.example.com".into(), Subtree, Block)
        );
        assert_eq!(
            one("||ads.example.com^$all"),
            ("ads.example.com".into(), Subtree, Block)
        );
        assert_eq!(
            one("||ads.example.com"),
            ("ads.example.com".into(), Subtree, Block)
        );
        assert_eq!(
            one("@@||cdn.example.com^"),
            ("cdn.example.com".into(), Subtree, Allow)
        );
        assert_eq!(
            line("||ads.example.com^$third-party")
                .unwrap_err()
                .feature(),
            "dns:options"
        );
        assert_eq!(
            line("||ads.example.com^$script").unwrap_err().feature(),
            "dns:options"
        );
        assert_eq!(
            line("||example.com/ads/").unwrap_err().feature(),
            "dns:not-hostname"
        );
        assert_eq!(
            line("/banner/ads.").unwrap_err().feature(),
            "dns:not-hostname"
        );
        assert_eq!(
            line("example.com##.ad").unwrap_err().feature(),
            "dns:page-rule"
        );
        assert_eq!(line("##.ad").unwrap_err().feature(), "dns:page-rule");
        // Page rules the browser side rejects are still page rules here.
        assert_eq!(
            line("x.com##+js(no-such-scriptlet)").unwrap_err().feature(),
            "dns:page-rule"
        );
        // A domain-looking URL fragment from an adblock list.
        assert_eq!(line(".120x600.").unwrap_err().feature(), "dns:not-hostname");
        // Wildcards keep their specific reason.
        assert_eq!(
            line("ads*.example.com").unwrap_err().feature(),
            "dns:wildcard"
        );
        assert_eq!(
            line("||141.98.82.232^").unwrap_err().feature(),
            "dns:ip-literal"
        );
    }

    #[test]
    fn comments() {
        for l in [
            "",
            "# hosts comment",
            "! adblock comment",
            "[Adblock Plus 2.0]",
            "   ",
        ] {
            assert!(line(l).unwrap().is_empty(), "{l:?}");
        }
    }

    #[test]
    fn explicit_format_overrides_detection() {
        // A bare name in an adblock list is a URL substring rule, not a host.
        let r = parse_dns_line("ads.example.com", DnsFormat::Adblock, Block);
        assert_eq!(r.unwrap_err().feature(), "dns:not-hostname");
    }

    #[test]
    fn builder_end_to_end() {
        let mut b = DnsListBuilder::new();
        b.add_list(
            "# hosts\n0.0.0.0 ads.example.com\n0.0.0.0 tracker.example.net\n192.0.2.1 redirect.example\n",
            DnsFormat::Auto,
            Block,
        );
        b.add_list(
            "||cdn.example.org^\n@@||ok.cdn.example.org^\n||tracker.example.net^$badfilter\n##.ad\n||x.example^$third-party\n",
            DnsFormat::Adblock,
            Block,
        );
        b.add_list("ads.example.com\n", DnsFormat::Domains, Allow);
        let (m, report) = b.finish();

        assert!(matches!(
            m.check("ads.example.com"),
            Verdict::Allowed { .. }
        ));
        assert!(m.check("img.cdn.example.org").is_blocked());
        assert!(matches!(
            m.check("ok.cdn.example.org"),
            Verdict::Allowed { .. }
        ));
        assert_eq!(m.check("tracker.example.net"), Verdict::NotListed);

        assert_eq!(report.lines, 10);
        assert_eq!(report.badfiltered, 1);
        assert_eq!(report.block_entries, 2);
        assert_eq!(report.allow_entries, 2);
        assert_eq!(report.rejected["dns:hosts-redirect"], 1);
        assert_eq!(report.rejected["dns:page-rule"], 1);
        assert_eq!(report.rejected["dns:options"], 1);
        assert_eq!(report.examples["dns:options"], "||x.example^$third-party");
    }

    #[test]
    fn builder_evaluates_conditions() {
        let mut b = DnsListBuilder::new();
        b.add_list(
            "!#if env_firefox\n||firefox-only.example^\n!#else\n||everyone.example^\n!#endif\n\
             !#if ext_ublock\n||ubo-only.example^\n!#endif\n!#include extra.txt\n!#if (\n||broken.example^\n!#endif\n",
            DnsFormat::Adblock,
            Block,
        );
        let (m, report) = b.finish();
        assert!(m.check("everyone.example").is_blocked());
        assert_eq!(m.check("firefox-only.example"), Verdict::NotListed);
        assert_eq!(m.check("ubo-only.example"), Verdict::NotListed);
        // An unparseable condition is false, and reported.
        assert_eq!(m.check("broken.example"), Verdict::NotListed);
        assert_eq!(report.excluded, 3);
        assert_eq!(report.rejected["invalid"], 1);
        assert_eq!(report.lines, 12);
    }

    #[test]
    fn byte_order_mark_is_ignored() {
        let mut b = DnsListBuilder::new();
        b.add_list("\u{feff}ads.example.com\n", DnsFormat::Auto, Block);
        let (m, report) = b.finish();
        assert!(m.check("ads.example.com").is_blocked());
        assert_eq!(report.rejected_total(), 0);
    }

    #[test]
    fn local_entries_survive_badfilter() {
        let domain = |s: &str| Domain::parse(s).unwrap();
        let mut b = DnsListBuilder::new();
        b.add_list(
            "||ads.example^\n||ads.example^$badfilter\n@@||ok.example^$badfilter\n||gone.example^\n||gone.example^$badfilter\n",
            DnsFormat::Adblock,
            Block,
        );
        b.add_local_rule(DnsRule {
            action: Block,
            domain: domain("ads.example"),
            scope: Subdomains,
            badfilter: false,
        })
        .unwrap();
        b.add_local_rule(DnsRule {
            action: Allow,
            domain: domain("ok.example"),
            scope: Subtree,
            badfilter: true,
        })
        .unwrap();
        let (m, _) = b.finish();
        // The list's own entry is cancelled; the local one stays.
        assert_eq!(m.check("ads.example"), Verdict::NotListed);
        assert!(m.check("x.ads.example").is_blocked());
        assert!(matches!(m.check("ok.example"), Verdict::Allowed { .. }));
        assert_eq!(m.check("gone.example"), Verdict::NotListed);
    }
}
