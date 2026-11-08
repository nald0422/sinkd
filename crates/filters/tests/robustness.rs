//! Lists are untrusted input: no line may panic the parser. Random strings
//! rarely reach deep code paths, so the second strategy splices together
//! fragments of real syntax.

use proptest::prelude::*;
use sinkd_filters::dns::{DnsAction, DnsFormat, parse_dns_line};
use sinkd_filters::{Env, Rule, parse_list, parse_rule};

fn rule_like() -> impl Strategy<Value = String> {
    let fragments = vec![
        "||",
        "|",
        "@@",
        "^",
        "*",
        "$",
        ",",
        "~",
        "=",
        "/",
        "\\",
        "#",
        "##",
        "#@#",
        "#?#",
        "#$#",
        "#%#",
        "#@%#",
        "$$",
        "+js(",
        "(",
        ")",
        ":has-text(",
        ":has(",
        ":not(",
        ":style(",
        ":upward(",
        ":remove()",
        ":xpath(",
        "'",
        "\"",
        "{",
        "}",
        "[",
        "]",
        ";",
        "domain=",
        "removeparam=",
        "redirect=",
        "csp=",
        "cookie=",
        "method=",
        "denyallow=",
        "3p",
        "important",
        "example.com",
        "a.example",
        ".ad",
        "a",
        "1",
        " ",
        "//scriptlet(",
        "!#if ",
        "&&",
        "ü",
        "\u{0}",
        "\t",
        "0.0.0.0 ",
        "*.",
    ];
    prop::collection::vec(prop::sample::select(fragments), 0..24).prop_map(|v| v.concat())
}

const FORMATS: [DnsFormat; 4] = [
    DnsFormat::Auto,
    DnsFormat::Hosts,
    DnsFormat::Domains,
    DnsFormat::Adblock,
];

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4096))]

    #[test]
    fn parse_rule_never_panics_on_any_text(s in "(?s).{0,120}") {
        let _ = parse_rule(&s);
    }

    #[test]
    fn parse_rule_never_panics_on_rule_like_text(s in rule_like()) {
        let _ = parse_rule(&s);
    }

    #[test]
    fn parse_list_never_panics(lines in prop::collection::vec(rule_like(), 0..20)) {
        let _ = parse_list(&lines.join("\n"), &Env::chromium_mv3());
    }

    #[test]
    fn dns_parser_never_panics(s in rule_like()) {
        for format in FORMATS {
            let _ = parse_dns_line(&s, format, DnsAction::Block);
        }
    }

    /// Any argument without a backslash survives uBO quoting.
    #[test]
    fn ublock_quoted_arguments_round_trip(args in prop::collection::vec("[^\\\\\n\r]{0,12}", 2..5)) {
        let quoted: Vec<String> = args.iter().map(|a| format!("'{}'", a.replace('\'', "\\'"))).collect();
        let line = format!("example.com##+js(set, {})", quoted.join(", "));
        let Ok(Rule::Scriptlet(rule)) = parse_rule(&line) else {
            return Err(TestCaseError::fail(format!("did not parse: {line}")));
        };
        prop_assert_eq!(&rule.calls[0].args, &args);
    }

    /// Any argument survives AdGuard quoting.
    #[test]
    fn adguard_quoted_arguments_round_trip(args in prop::collection::vec("[^\n\r]{0,12}", 2..5)) {
        let quoted: Vec<String> = args
            .iter()
            .map(|a| format!("'{}'", a.replace('\\', "\\\\").replace('\'', "\\'")))
            .collect();
        let line = format!("example.com#%#//scriptlet('set-constant', {})", quoted.join(", "));
        let Ok(Rule::Scriptlet(rule)) = parse_rule(&line) else {
            return Err(TestCaseError::fail(format!("did not parse: {line}")));
        };
        prop_assert_eq!(&rule.calls[0].args, &args);
    }
}
