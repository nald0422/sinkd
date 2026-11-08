//! What the lists say about one request: the network side of
//! `sinkd check <url>`.
//!
//! This evaluates the *source* filter rules, with the usual adblock
//! precedence, so the answer names the rule and the list line responsible.
//! Each deciding rule is then checked against the DNR translation, which
//! says whether the extension applies it at all (a `$popup` rule, say, it
//! cannot).
//!
//! Precedence, strongest first:
//!
//! 1. `$important` blocks, unless an `$important` exception matches;
//! 2. a `$document` exception for the page the request comes from: nothing
//!    on that page is filtered;
//! 3. exceptions (`@@`);
//! 4. blocks, served as a surrogate when a `$redirect` rule matches too.
//!
//! `$removeparam` and the other modifying rules are listed separately; an
//! exception cancels them, as it does in DNR.
//!
//! Sites (for `$third-party`) are worked out with the same short list of
//! two-label public suffixes as the extension's page code, not the full
//! Public Suffix List, so `a.github.io` and `b.github.io` count as one
//! site here.

use std::collections::HashSet;

use regex::{Regex, RegexBuilder};
use sinkd_core::page::{TWO_LABEL_SUFFIXES, host_keys};
use sinkd_filters::network::{
    Action, Anchor, ParamMatch, Party, ResourceTypes, StrictParty, UrlPattern,
};
use sinkd_filters::{DomainSpec, HostPattern};
use sinkd_filters::{Env, Line, Lines, NetworkRule, Rule, is_comment, parse_rule};

use crate::compile::ListInput;
use crate::translate::{Skip, translate_network};

/// A request to explain.
#[derive(Debug, Clone)]
pub struct Request<'a> {
    pub url: &'a str,
    /// One type: [`ResourceTypes::DOCUMENT`] for a page itself.
    pub kind: ResourceTypes,
    /// The page that makes the request; `None` for a page itself.
    pub initiator: Option<&'a str>,
    /// Upper case.
    pub method: &'a str,
}

/// One source rule, where it came from and what DNR made of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Source {
    pub list: String,
    pub ruleset: String,
    pub line: usize,
    pub text: String,
    /// `Ok` with what was dropped from it (empty: nothing), or why the
    /// extension cannot apply it.
    pub chrome: Result<Vec<&'static str>, String>,
}

/// The network verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// No rule applies.
    Unlisted,
    Blocked {
        by: Source,
        important: bool,
    },
    /// Blocked, and answered with a bundled surrogate.
    Redirected {
        by: Source,
        redirect: Source,
        resource: String,
    },
    /// An exception matched; `over` lists the blocks it overrides.
    Allowed {
        by: Source,
        over: Vec<Source>,
    },
    /// The page carries a `$document` exception: nothing on it is filtered.
    PageAllowed {
        by: Source,
    },
}

/// The full explanation of one request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Explanation {
    pub verdict: Verdict,
    /// `$removeparam` rules that apply, with the parameters they strip.
    pub params: Vec<(Source, Vec<String>)>,
    /// Other modifying rules that apply (`$csp`, `$permissions`, `$cookie`,
    /// `$removeheader`, `$urlskip`).
    pub modifiers: Vec<Source>,
}

struct Entry {
    rule: NetworkRule,
    list: usize,
    line: usize,
    text: String,
    regex: Option<Option<Regex>>,
}

/// The network rules of a set of lists, ready to explain requests.
pub struct Explainer {
    entries: Vec<Entry>,
    lists: Vec<(String, String)>,
}

impl Explainer {
    /// Parses the network rules of `lists` (as the compiler does for
    /// Chromium), dropping the ones a `$badfilter` cancels.
    pub fn new(lists: &[ListInput]) -> Self {
        let env = Env::chromium_mv3();
        let mut entries = Vec::new();
        let mut badfilters = HashSet::new();
        for (index, list) in lists.iter().enumerate() {
            for (line, item) in Lines::new(&list.text, &env) {
                let Line::Text(text) = item else {
                    continue;
                };
                if is_comment(&text) {
                    continue;
                }
                let Ok(Rule::Network(rule)) = parse_rule(&text) else {
                    continue;
                };
                if rule.options.badfilter {
                    let mut twin = rule.clone();
                    twin.options.badfilter = false;
                    badfilters.insert(format!("{twin:?}"));
                    continue;
                }
                entries.push(Entry {
                    rule,
                    list: index,
                    line,
                    text: text.into_owned(),
                    regex: None,
                });
            }
        }
        entries.retain(|e| !badfilters.contains(&format!("{:?}", e.rule)));
        Explainer {
            entries,
            lists: lists
                .iter()
                .map(|l| (l.name.clone(), l.ruleset.clone()))
                .collect(),
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    fn source(&self, i: usize) -> Source {
        let e = &self.entries[i];
        let (list, ruleset) = self.lists[e.list].clone();
        let chrome = match translate_network(&e.rule) {
            Ok(t) => Ok(t.narrowed),
            Err(Skip::Rejected { feature, reason }) => Err(format!("{feature}: {reason}")),
            Err(Skip::OtherTarget(target)) => Err(format!("applies to the {target} target only")),
        };
        Source {
            list,
            ruleset,
            line: e.line,
            text: e.text.clone(),
            chrome,
        }
    }

    /// Indexes of the rules that match `request`.
    fn matching(&mut self, request: &Request<'_>) -> Vec<usize> {
        let Some(url) = Url::parse(request.url) else {
            return Vec::new();
        };
        let page = request.initiator.and_then(Url::parse);
        // A page is its own context for `$domain=` and party.
        let context = page.as_ref().map_or(url.host, |p| p.host);
        let mut out = Vec::new();
        for (i, entry) in self.entries.iter_mut().enumerate() {
            if options_match(&entry.rule, request, &url, context) && pattern_matches(entry, &url) {
                out.push(i);
            }
        }
        out
    }

    /// Explains `request`.
    pub fn explain(&mut self, request: &Request<'_>) -> Explanation {
        let matched = self.matching(request);
        let mut blocks = Vec::new();
        let mut important_blocks = Vec::new();
        let mut exceptions = Vec::new();
        let mut important_exceptions = Vec::new();
        let mut redirects = Vec::new();
        let mut params = Vec::new();
        let mut modifiers = Vec::new();
        for &i in &matched {
            let rule = &self.entries[i].rule;
            let o = &rule.options;
            match (&o.action, rule.exception) {
                (None, false) => {
                    if o.important {
                        important_blocks.push(i);
                    } else {
                        blocks.push(i);
                    }
                }
                (None, true) => {
                    if o.important {
                        important_exceptions.push(i);
                    } else {
                        exceptions.push(i);
                    }
                }
                (Some(Action::Redirect { rule_only, .. }), false) => {
                    redirects.push(i);
                    if !rule_only {
                        blocks.push(i);
                    }
                }
                (Some(Action::RemoveParam(_)), false) => params.push(i),
                (Some(_), false) => modifiers.push(i),
                // Exceptions to modifiers: they cancel the modifier, which
                // DNR cannot express separately (see the compiler docs).
                (Some(_), true) => {}
            }
        }

        // A `$document` exception on the page switches everything off.
        let page_exception = match request.initiator {
            Some(page) if request.kind != ResourceTypes::DOCUMENT => {
                let page_request = Request {
                    url: page,
                    kind: ResourceTypes::DOCUMENT,
                    initiator: None,
                    method: "GET",
                };
                self.matching(&page_request).into_iter().find(|&i| {
                    let r = &self.entries[i].rule;
                    r.exception
                        && r.options.action.is_none()
                        && r.options
                            .types
                            .is_some_and(|t| t.contains(ResourceTypes::DOCUMENT))
                })
            }
            _ => None,
        };

        let verdict =
            if let (Some(&b), true) = (important_blocks.first(), important_exceptions.is_empty()) {
                Verdict::Blocked {
                    by: self.source(b),
                    important: true,
                }
            } else if let Some(i) = page_exception {
                Verdict::PageAllowed { by: self.source(i) }
            } else if let Some(&e) = important_exceptions.first().or(exceptions.first()) {
                let over = blocks
                    .iter()
                    .chain(&important_blocks)
                    .map(|&b| self.source(b))
                    .collect();
                Verdict::Allowed {
                    by: self.source(e),
                    over,
                }
            } else if let Some(&b) = blocks.first() {
                // The highest-priority redirect wins (uBO's `:priority`).
                let redirect = redirects.iter().copied().max_by_key(|&r| {
                    match &self.entries[r].rule.options.action {
                        Some(Action::Redirect { priority, .. }) => *priority,
                        _ => i32::MIN,
                    }
                });
                match redirect.map(|r| (r, &self.entries[r].rule.options.action)) {
                    Some((r, Some(Action::Redirect { resource, .. }))) => Verdict::Redirected {
                        by: self.source(b),
                        redirect: self.source(r),
                        resource: resource.clone(),
                    },
                    _ => Verdict::Blocked {
                        by: self.source(b),
                        important: false,
                    },
                }
            } else {
                Verdict::Unlisted
            };

        let allowed = matches!(
            verdict,
            Verdict::Allowed { .. } | Verdict::PageAllowed { .. }
        );
        let blocked = matches!(
            verdict,
            Verdict::Blocked { .. } | Verdict::Redirected { .. }
        );
        let (params, modifiers) = if allowed || blocked {
            (Vec::new(), Vec::new())
        } else {
            let url = Url::parse(request.url);
            (
                params
                    .into_iter()
                    .map(|i| {
                        let stripped = match (&self.entries[i].rule.options.action, &url) {
                            (Some(Action::RemoveParam(m)), Some(url)) => stripped(m, url.query),
                            _ => Vec::new(),
                        };
                        (self.source(i), stripped)
                    })
                    .filter(|(_, stripped)| !stripped.is_empty())
                    .collect(),
                modifiers.into_iter().map(|i| self.source(i)).collect(),
            )
        };
        Explanation {
            verdict,
            params,
            modifiers,
        }
    }
}

/// The parts of a URL the matcher needs.
#[derive(Debug, Clone, Copy)]
struct Url<'a> {
    full: &'a str,
    /// Byte range of the host within `full`.
    host_start: usize,
    host: &'a str,
    query: Option<&'a str>,
}

impl<'a> Url<'a> {
    fn parse(full: &'a str) -> Option<Url<'a>> {
        let scheme_end = full.find("://")?;
        let host_start = scheme_end + 3;
        let rest = full.get(host_start..)?;
        let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
        let authority = rest.get(..authority_end)?;
        // user:pass@host:port
        let after_user = authority.rfind('@').map_or(0, |i| i + 1);
        let hostport = authority.get(after_user..)?;
        let host = if hostport.starts_with('[') {
            hostport.get(..=hostport.find(']')?)?
        } else {
            hostport.split(':').next().unwrap_or(hostport)
        };
        if host.is_empty() {
            return None;
        }
        let query = full
            .split_once('?')
            .map(|(_, q)| q.split('#').next().unwrap_or(q));
        Some(Url {
            full,
            host_start: host_start + after_user,
            host,
            query,
        })
    }
}

/// The site of a hostname: its public suffix and one more label.
pub fn site(host: &str) -> &str {
    let host = host.trim_end_matches('.');
    if host.parse::<std::net::IpAddr>().is_ok() || host.starts_with('[') {
        return host;
    }
    let labels: Vec<&str> = host.split('.').collect();
    if labels.len() < 2 {
        return host;
    }
    let last_two = labels[labels.len() - 2..].join(".");
    let suffix = if labels.len() > 2 && TWO_LABEL_SUFFIXES.contains(&last_two.as_str()) {
        2
    } else {
        1
    };
    let keep = (suffix + 1).min(labels.len());
    let skip: usize = labels[..labels.len() - keep]
        .iter()
        .map(|l| l.len() + 1)
        .sum();
    host.get(skip..).unwrap_or(host)
}

fn options_match(rule: &NetworkRule, request: &Request<'_>, url: &Url<'_>, context: &str) -> bool {
    let o = &rule.options;
    // Page-only exceptions (`$generichide`) and resolver-only ones
    // (`$cname`) are not network rules.
    if o.cname || (rule.exception && o.types.is_none() && page_only(rule)) {
        return false;
    }
    // Without a type option, as in the DNR translation: parameter rules
    // also act on navigations, header rules only on documents.
    let types = o.types.unwrap_or(match o.action {
        Some(Action::RemoveParam(_)) => {
            ResourceTypes::DOCUMENT
                | ResourceTypes::SUBDOCUMENT
                | ResourceTypes::XMLHTTPREQUEST
                | ResourceTypes::PING
        }
        Some(Action::Csp(_) | Action::Permissions(_)) => {
            ResourceTypes::DOCUMENT | ResourceTypes::SUBDOCUMENT
        }
        _ => ResourceTypes::SUBRESOURCES,
    });
    if !types.intersects(request.kind) {
        return false;
    }
    let host = url.host;
    let third = site(host) != site(context);
    match o.party {
        Party::Any => {}
        Party::First if third => return false,
        Party::Third if !third => return false,
        _ => {}
    }
    match o.strict_party {
        StrictParty::Any => {}
        StrictParty::SameHost if host != context => return false,
        StrictParty::OtherHost if host == context => return false,
        _ => {}
    }
    if !domains_match(&o.domains, context)
        || !domains_match(&o.to, host)
        || (!o.denyallow.is_empty() && domains_match_any(&o.denyallow, host))
    {
        return false;
    }
    if !o.methods.is_empty() {
        let (negated, positive): (Vec<_>, Vec<_>) = o.methods.iter().partition(|m| m.negated);
        if negated.iter().any(|m| m.method == request.method) {
            return false;
        }
        if !positive.is_empty() && !positive.iter().any(|m| m.method == request.method) {
            return false;
        }
    }
    // A response-header condition cannot be known before the response.
    o.header.is_none()
}

fn page_only(rule: &NetworkRule) -> bool {
    let p = &rule.options.page;
    p.elemhide || p.generichide || p.specifichide || p.genericblock
}

fn host_matches(spec: &DomainSpec, host: &str) -> bool {
    match &spec.host {
        HostPattern::Domain(d) => {
            host == d
                || (host.len() > d.len()
                    && host.ends_with(d.as_str())
                    && host.as_bytes()[host.len() - d.len() - 1] == b'.')
        }
        HostPattern::Entity(e) => host_keys(host).contains(&format!("{e}.*")),
        HostPattern::Ip(ip) => host.trim_matches(['[', ']']) == ip.to_string(),
        HostPattern::Regex(source) => Regex::new(source).is_ok_and(|r| r.is_match(host)),
    }
}

/// `$domain=`-style lists: every negated entry must miss, and if there are
/// positive entries, one must match.
fn domains_match(specs: &[DomainSpec], host: &str) -> bool {
    if specs.is_empty() {
        return true;
    }
    let mut positive = false;
    let mut hit = false;
    for spec in specs {
        if spec.negated {
            if host_matches(spec, host) {
                return false;
            }
        } else {
            positive = true;
            hit |= host_matches(spec, host);
        }
    }
    !positive || hit
}

fn domains_match_any(specs: &[DomainSpec], host: &str) -> bool {
    specs.iter().any(|s| !s.negated && host_matches(s, host))
}

fn pattern_matches(entry: &mut Entry, url: &Url<'_>) -> bool {
    let case = entry.rule.options.match_case;
    match &entry.rule.pattern {
        UrlPattern::Regex { source } => {
            let regex = entry.regex.get_or_insert_with(|| {
                RegexBuilder::new(source)
                    .case_insensitive(!case)
                    .size_limit(1 << 20)
                    .build()
                    .ok()
            });
            regex.as_ref().is_some_and(|r| r.is_match(url.full))
        }
        UrlPattern::Wildcard {
            anchor,
            body,
            end_anchor,
        } => {
            let (text, body) = if case {
                (url.full.to_owned(), body.clone())
            } else {
                (url.full.to_ascii_lowercase(), body.to_ascii_lowercase())
            };
            // Cheap rejection: the longest literal piece must occur.
            let literal = body
                .split(['*', '^'])
                .max_by_key(|piece| piece.len())
                .unwrap_or_default();
            if !literal.is_empty() && !text.contains(literal) {
                return false;
            }
            let text = text.as_bytes();
            let body = body.as_bytes();
            let starts: Vec<usize> = match anchor {
                Anchor::Start => vec![0],
                Anchor::Hostname => {
                    let host_end = url.host_start + url.host.len();
                    std::iter::once(url.host_start)
                        .chain(
                            (url.host_start..host_end)
                                .filter(|&i| text.get(i) == Some(&b'.'))
                                .map(|i| i + 1),
                        )
                        .collect()
                }
                Anchor::None => (0..=text.len()).collect(),
            };
            starts
                .into_iter()
                .any(|start| glob(body, text, start, *end_anchor))
        }
    }
}

/// Whether `pattern` (ABP wildcard syntax) matches `text` from `start`.
/// `*` matches any run, `^` a separator or the end. With `to_end`, the
/// match must end at the end of `text`; otherwise it may end anywhere.
fn glob(pattern: &[u8], text: &[u8], start: usize, to_end: bool) -> bool {
    fn separator(c: u8) -> bool {
        !(c.is_ascii_alphanumeric() || matches!(c, b'_' | b'-' | b'.' | b'%'))
    }
    // Iterative matcher with one backtrack point per `*`.
    let (mut p, mut t) = (0, start);
    let mut star: Option<(usize, usize)> = None;
    loop {
        if p == pattern.len() {
            if !to_end || t == text.len() {
                return true;
            }
        } else {
            let c = pattern[p];
            if c == b'*' {
                star = Some((p, t));
                p += 1;
                continue;
            }
            if c == b'^' {
                if t == text.len() {
                    // `^` matches the end; only `*` and `^` may follow.
                    p += 1;
                    continue;
                }
                if separator(text[t]) {
                    p += 1;
                    t += 1;
                    continue;
                }
            } else if t < text.len() && text[t] == c {
                p += 1;
                t += 1;
                continue;
            }
        }
        match star {
            Some((sp, st)) if st < text.len() => {
                star = Some((sp, st + 1));
                p = sp + 1;
                t = st + 1;
            }
            _ => return false,
        }
    }
}

/// The parameters of `query` that `m` strips.
fn stripped(m: &ParamMatch, query: Option<&str>) -> Vec<String> {
    let Some(query) = query.filter(|q| !q.is_empty()) else {
        return Vec::new();
    };
    let pairs = query.split('&').filter(|p| !p.is_empty());
    match m {
        ParamMatch::All => vec![query.to_owned()],
        ParamMatch::Name { name, negated } => pairs
            .filter(|p| (p.split('=').next() == Some(name.as_str())) != *negated)
            .map(str::to_owned)
            .collect(),
        ParamMatch::Regex {
            source,
            flags,
            negated,
        } => {
            let Ok(regex) = RegexBuilder::new(source)
                .case_insensitive(flags.contains('i'))
                .build()
            else {
                return Vec::new();
            };
            pairs
                .filter(|p| regex.is_match(p) != *negated)
                .map(str::to_owned)
                .collect()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn explainer(text: &str) -> Explainer {
        Explainer::new(&[ListInput {
            name: "test".into(),
            ruleset: "ads".into(),
            text: text.into(),
        }])
    }

    fn request<'a>(url: &'a str, kind: ResourceTypes, from: Option<&'a str>) -> Request<'a> {
        Request {
            url,
            kind,
            initiator: from,
            method: "GET",
        }
    }

    const PAGE: Option<&str> = Some("https://news.example/article");

    fn verdict(e: &mut Explainer, url: &str, kind: ResourceTypes) -> Verdict {
        e.explain(&request(url, kind, PAGE)).verdict
    }

    #[test]
    fn globs() {
        let m = |p: &str, t: &str| glob(p.as_bytes(), t.as_bytes(), 0, false);
        assert!(m("ads.", "ads.example"));
        assert!(m("a*d", "abcd"));
        assert!(m("example.com^", "example.com/x"));
        assert!(m("example.com^", "example.com"));
        assert!(!m("example.com^", "example.community"));
        assert!(m("/ads/*.gif^", "/ads/x/y.gif?z"));
        assert!(!m("/ads/*.gif^", "/ads/x/y.gifz"));
        assert!(glob(b"x.gif", b"a/x.gif", 2, true));
        assert!(!glob(b"x.gif", b"a/x.gif?", 2, true));
        assert!(m("a^*^", "a"));
        assert!(!m("^", "a"));
    }

    #[test]
    fn hostname_anchor_matches_at_label_starts_only() {
        let mut e = explainer("||ads.example^");
        assert!(matches!(
            verdict(&mut e, "https://ads.example/x.js", ResourceTypes::SCRIPT),
            Verdict::Blocked { .. }
        ));
        assert!(matches!(
            verdict(
                &mut e,
                "https://cdn.ads.example/x.js",
                ResourceTypes::SCRIPT
            ),
            Verdict::Blocked { .. }
        ));
        assert_eq!(
            verdict(&mut e, "https://badads.example/x.js", ResourceTypes::SCRIPT),
            Verdict::Unlisted
        );
        assert_eq!(
            verdict(
                &mut e,
                "https://x.example/?u=ads.example",
                ResourceTypes::SCRIPT
            ),
            Verdict::Unlisted
        );
    }

    #[test]
    fn precedence() {
        let mut e = explainer(
            "||ads.example^\n@@||ads.example/ok/\n||ads.example/ok/forced^$important\n\
             ||track.example^$redirect=noop.js\n@@||news.example^$document\n",
        );
        let site = Some("https://site.example/");
        let mut verdict = |url: &str| {
            e.explain(&request(url, ResourceTypes::SCRIPT, site))
                .verdict
        };
        let Verdict::Allowed { by, over } = verdict("https://ads.example/ok/a.js") else {
            panic!("expected an exception");
        };
        assert_eq!(by.line, 2);
        assert_eq!(over.len(), 1);
        assert!(matches!(
            verdict("https://ads.example/ok/forced"),
            Verdict::Blocked {
                important: true,
                ..
            }
        ));
        // From a page with a $document exception, nothing is filtered...
        let from_news = e.explain(&request(
            "https://ads.example/a.js",
            ResourceTypes::SCRIPT,
            Some("https://news.example/"),
        ));
        assert!(matches!(from_news.verdict, Verdict::PageAllowed { .. }));
        // ...but elsewhere it is.
        let from_other = e.explain(&request(
            "https://track.example/t.js",
            ResourceTypes::SCRIPT,
            Some("https://other.example/"),
        ));
        assert!(matches!(
            from_other.verdict,
            Verdict::Redirected { ref resource, .. } if resource == "noop.js"
        ));
    }

    #[test]
    fn options() {
        let mut e = explainer(
            "||cdn.example^$third-party,script\n/banner/*$image,domain=news.example|~sub.news.example\n\
             ||api.example^$method=post\n",
        );
        let first_party = e.explain(&request(
            "https://cdn.example/a.js",
            ResourceTypes::SCRIPT,
            Some("https://www.cdn.example/"),
        ));
        assert_eq!(first_party.verdict, Verdict::Unlisted);
        assert!(matches!(
            verdict(&mut e, "https://cdn.example/a.js", ResourceTypes::SCRIPT),
            Verdict::Blocked { .. }
        ));
        assert_eq!(
            verdict(
                &mut e,
                "https://cdn.example/a.css",
                ResourceTypes::STYLESHEET
            ),
            Verdict::Unlisted
        );
        assert!(matches!(
            verdict(
                &mut e,
                "https://img.example/banner/1.png",
                ResourceTypes::IMAGE
            ),
            Verdict::Blocked { .. }
        ));
        let excluded = e.explain(&request(
            "https://img.example/banner/1.png",
            ResourceTypes::IMAGE,
            Some("https://sub.news.example/"),
        ));
        assert_eq!(excluded.verdict, Verdict::Unlisted);
        assert_eq!(
            verdict(
                &mut e,
                "https://api.example/v1",
                ResourceTypes::XMLHTTPREQUEST
            ),
            Verdict::Unlisted
        );
        let post = e.explain(&Request {
            method: "POST",
            ..request(
                "https://api.example/v1",
                ResourceTypes::XMLHTTPREQUEST,
                PAGE,
            )
        });
        assert!(matches!(post.verdict, Verdict::Blocked { .. }));
    }

    #[test]
    fn untyped_rules_spare_the_page_itself() {
        let mut e = explainer("||ads.example^\n||popup.example^$popup\n");
        let page = e.explain(&request(
            "https://ads.example/",
            ResourceTypes::DOCUMENT,
            None,
        ));
        assert_eq!(page.verdict, Verdict::Unlisted);
        let popup = e.explain(&request(
            "https://popup.example/",
            ResourceTypes::DOCUMENT,
            None,
        ));
        assert_eq!(popup.verdict, Verdict::Unlisted);
    }

    #[test]
    fn params_and_chrome_status() {
        let mut e = explainer("$removeparam=utm_source\n||ads.example^$popup,third-party\n");
        let x = e.explain(&request(
            "https://shop.example/p?utm_source=x&id=3",
            ResourceTypes::DOCUMENT,
            None,
        ));
        assert_eq!(x.verdict, Verdict::Unlisted);
        assert_eq!(x.params.len(), 1);
        assert_eq!(x.params[0].1, ["utm_source=x"]);
        assert!(x.params[0].0.chrome.is_ok());
        // A rule DNR cannot take is explained as such.
        let source = e.source(1);
        assert!(source.chrome.is_err(), "{source:?}");
    }

    #[test]
    fn badfilter_cancels() {
        let mut e = explainer("||ads.example^\n||ads.example^$badfilter\n");
        assert!(e.is_empty());
        assert_eq!(
            verdict(&mut e, "https://ads.example/", ResourceTypes::SCRIPT),
            Verdict::Unlisted
        );
    }

    #[test]
    fn sites() {
        assert_eq!(site("a.b.example.com"), "example.com");
        assert_eq!(site("www.bbc.co.uk"), "bbc.co.uk");
        assert_eq!(site("example.com"), "example.com");
        assert_eq!(site("localhost"), "localhost");
        assert_eq!(site("192.0.2.1"), "192.0.2.1");
    }
}
