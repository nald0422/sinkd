//! Differential test against Brave's `adblock` crate.
//!
//! Every rule in `corpus/rules.txt` is parsed by both parsers. Where they
//! disagree on whether a line is a usable rule (or what kind), the line must
//! appear in `EXPECTED` with the reason; a new disagreement, or a stale entry,
//! fails the test. For network rules both accept, the flags both expose must
//! agree.
//!
//! adblock-rust is a dev-dependency only: it never ships in a binary.

use std::collections::BTreeMap;

use adblock::filters::network::NetworkFilterMaskHelper;
use adblock::lists::{ParseOptions, ParsedLine, parse_filter};
use sinkhole_filters::network::Action;
use sinkhole_filters::{Rule, is_comment, parse_rule};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Network,
    Cosmetic,
    Rejected,
}

fn ours(line: &str) -> Kind {
    match parse_rule(line) {
        Ok(Rule::Network(_)) => Kind::Network,
        Ok(_) => Kind::Cosmetic,
        Err(_) => Kind::Rejected,
    }
}

fn theirs(line: &str) -> Kind {
    match parse_filter(line, true, ParseOptions::default()) {
        Ok(ParsedLine::Network(_)) => Kind::Network,
        Ok(ParsedLine::Cosmetic(_)) => Kind::Cosmetic,
        Err(_) => Kind::Rejected,
    }
}

/// Lines where the two parsers are expected to disagree, and why.
const EXPECTED: &[(&str, &str)] = &[
    // We reject; adblock-rust accepts.
    (
        "||",
        "matches every URL; refused rather than blocking everything",
    ),
    (
        "ads banner",
        "whitespace never occurs in a URL, so the rule can never match",
    ),
    (
        "||example.com^$third-party,first-party",
        "contradictory party options",
    ),
    (
        "||example.com^$domain=",
        "empty $domain would silently drop the restriction",
    ),
    ("||example.com^$tag=foo", "Brave-only $tag"),
    (
        "example.com##.a:style(background: url(https://t.example/x))",
        "security: :style() may not load resources",
    ),
    (
        "##.a{} body{x:y",
        "security: selector escapes its CSS rule block",
    ),
    (
        "example.com##+js(evil-eval, x)",
        "only bundled scriptlets may be selected",
    ),
    ("example.com##+js(set, x)", "set-constant needs a value"),
    // We accept; adblock-rust rejects. Mostly syntax it does not implement.
    (
        "/ads\\.js$/",
        "adblock-rust splits options at a `$` inside the regex",
    ),
    (
        "||example.com^$webrtc",
        "deprecated ABP type, kept so the compiler can report it",
    ),
    (
        "||example.com^$popup",
        "Brave handles popups outside its engine",
    ),
    ("||example.com^$strict1p", "uBO option"),
    ("||example.com^$strict3p", "uBO option"),
    (
        "||example.com^$denyallow=x.example,domain=a.example",
        "uBO option",
    ),
    ("||example.com^$header=via:1.1", "uBO option"),
    (
        "||example.com^$match-case",
        "adblock-rust allows $match-case on regex rules only",
    ),
    (
        "||example.com/Ads$match-case",
        "adblock-rust allows $match-case on regex rules only",
    ),
    (
        "@@||example.com^$redirect",
        "uBO: cancels every redirect on matching requests",
    ),
    (
        "||example.com^$empty",
        "legacy uBO shorthand for redirect=empty",
    ),
    (
        "||example.com^$mp4",
        "legacy uBO shorthand for redirect=noopmp4-1s",
    ),
    (
        "$removeparam=/^utm_/",
        "adblock-rust supports literal parameter names only",
    ),
    (
        "||example.com^$removeparam",
        "adblock-rust supports literal parameter names only",
    ),
    (
        "||example.com^$removeparam=~id",
        "adblock-rust supports literal parameter names only",
    ),
    (
        "@@||example.com^$removeparam",
        "adblock-rust supports literal parameter names only",
    ),
    (
        "||example.com^$queryprune=x",
        "legacy uBO name of $removeparam",
    ),
    (
        "||example.com^$inline-script",
        "uBO option (a CSP injection)",
    ),
    ("||example.com^$inline-font", "uBO option (a CSP injection)"),
    (
        "||example.com^$permissions=browsing-topics=()",
        "uBO option",
    ),
    (
        "||example.com^$urlskip=?u",
        "uBO option, used for link-wrapper unwrapping",
    ),
    (
        "||example.com^$cookie",
        "AdGuard option, used for cookie capping",
    ),
    ("||example.com^$removeheader=location", "AdGuard option"),
    (
        "@@||example.com^$elemhide",
        "exception option adblock-rust lacks",
    ),
    (
        "@@||example.com^$specifichide",
        "exception option adblock-rust lacks",
    ),
    (
        "@@||example.com^$genericblock",
        "exception option adblock-rust lacks",
    ),
    ("@@||example.com^$cname", "uBO: opt out of CNAME uncloaking"),
    ("#@#.ad", "generic cosmetic exception"),
    (
        "example.com#$#.ad { display: none !important; }",
        "AdGuard CSS injection",
    ),
    (
        "example.com#@$#.ad { display: none !important; }",
        "AdGuard CSS injection",
    ),
    (
        "example.com#$?#div:has-text(ad) { remove: true; }",
        "AdGuard extended CSS injection",
    ),
    (
        "example.com##^responseheader(refresh)",
        "uBO response-header removal",
    ),
    (
        "example.com#%#//scriptlet('set-constant', 'ads.enabled', 'false')",
        "AdGuard scriptlet syntax",
    ),
    (
        "example.com#@%#//scriptlet('set-constant', 'ads.enabled', 'false')",
        "AdGuard scriptlet syntax",
    ),
    (
        "example.com#$#abort-on-property-read ads; json-prune ad",
        "ABP snippet syntax",
    ),
];

fn corpus() -> Vec<&'static str> {
    include_str!("corpus/rules.txt")
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !is_comment(l))
        .collect()
}

#[test]
fn classification_matches_adblock_rust_except_documented_differences() {
    let expected: BTreeMap<&str, &str> = EXPECTED.iter().copied().collect();
    let mut unexpected = Vec::new();
    let mut seen = Vec::new();
    for line in corpus() {
        let (a, b) = (ours(line), theirs(line));
        if a != b {
            seen.push(line);
            if !expected.contains_key(line) {
                unexpected.push(format!("{line:<60} ours={a:?} adblock={b:?}"));
            }
        }
    }
    let stale: Vec<_> = expected.keys().filter(|l| !seen.contains(l)).collect();
    assert!(
        unexpected.is_empty() && stale.is_empty(),
        "unexpected differences:\n{}\nstale expectations: {stale:?}",
        unexpected.join("\n")
    );
}

#[test]
fn network_flags_match_where_both_parse() {
    for line in corpus() {
        let (Ok(Rule::Network(o)), Ok(ParsedLine::Network(t))) = (
            parse_rule(line),
            parse_filter(line, true, ParseOptions::default()),
        ) else {
            continue;
        };
        assert_eq!(o.exception, t.is_exception(), "exception: {line}");
        assert_eq!(o.options.important, t.is_important(), "important: {line}");
        assert_eq!(o.options.badfilter, t.is_badfilter(), "badfilter: {line}");
        assert_eq!(o.options.match_case, t.match_case(), "match-case: {line}");
        assert_eq!(
            matches!(o.options.action, Some(Action::RemoveParam(_))),
            t.is_removeparam(),
            "removeparam: {line}"
        );
        assert_eq!(
            matches!(o.options.action, Some(Action::Csp(_))),
            t.is_csp(),
            "csp: {line}"
        );
        if let (Some(host), Some(their_host)) = (o.pattern.pure_hostname(), t.hostname.as_deref()) {
            assert_eq!(host, their_host, "hostname: {line}");
        }
    }
}
