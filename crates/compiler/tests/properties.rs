//! Whatever rules go in, every DNR rule that comes out is one Chrome
//! accepts, with unique IDs, and the same input gives the same output.
#![allow(clippy::unwrap_used)]

use std::collections::HashSet;

use proptest::prelude::*;
use sinkhole_compiler::{ListInput, compile, validate};

fn host() -> impl Strategy<Value = String> {
    prop::sample::select(vec![
        "ads.example",
        "x.ads.example",
        "cdn.example.org",
        "tracker.test",
        "bücher.de",
        "a-b.c-d.example",
        "127.0.0.1",
    ])
    .prop_map(String::from)
}

fn rule() -> impl Strategy<Value = String> {
    let prefix = prop::sample::select(vec!["", "@@"]);
    let pattern = prop_oneof![
        host().prop_map(|h| format!("||{h}^")),
        (host(), "[a-z/._*-]{0,12}").prop_map(|(h, p)| format!("||{h}/{p}")),
        "[a-z/._-]{1,12}".prop_map(|p| format!("/{p}")),
        Just("*".to_owned()),
        Just(String::new()),
        Just(r"/^https?:\/\/ad[0-9]+\./".to_owned()),
        Just(r"/(?!x)y/".to_owned()),
        "[a-z]{1,4}".prop_map(|p| format!("|https://{p}.example/")),
    ];
    let option = prop::sample::select(vec![
        "script",
        "image",
        "~script",
        "third-party",
        "1p",
        "document",
        "popup",
        "all",
        "domain=a.example|~b.a.example",
        "domain=example.*",
        "to=x.example",
        "important",
        "match-case",
        "redirect=noop.js",
        "redirect=googletagservices_gpt.js",
        "redirect=no-such-thing",
        "redirect-rule=noop.js",
        "removeparam=utm_source",
        "removeparam=/^utm/",
        "removeparam",
        "csp=script-src 'self'",
        "badfilter",
        "method=get|~post",
        "denyallow=x.example",
        "xhr",
        "websocket",
        "webrtc",
        "generichide",
        "removeheader=refresh",
        "strict3p",
    ]);
    (prefix, pattern, prop::collection::vec(option, 0..4)).prop_map(|(pre, pat, opts)| {
        if opts.is_empty() {
            format!("{pre}{pat}")
        } else {
            format!("{pre}{pat}${}", opts.join(","))
        }
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn output_is_always_valid(lines in prop::collection::vec(rule(), 1..40)) {
        let lists = [
            ListInput { name: "a".into(), ruleset: "ads".into(), text: lines.join("\n") },
            ListInput { name: "b".into(), ruleset: "params".into(), text: lines.iter().rev().cloned().collect::<Vec<_>>().join("\n") },
        ];
        let c = compile(&lists, Some("params"));
        prop_assert!(c.report.warnings.iter().all(|w| !w.contains("invalid rule")), "{:?}", c.report.warnings);
        for ruleset in &c.rulesets {
            let mut ids = HashSet::new();
            for rule in &ruleset.rules {
                prop_assert!(validate::check(rule).is_ok(), "{rule:?}: {:?}", validate::check(rule));
                prop_assert!(ids.insert(rule.id));
            }
            let expected: Vec<u32> = (1..=ruleset.rules.len() as u32).collect();
            let actual: Vec<u32> = ruleset.rules.iter().map(|r| r.id).collect();
            prop_assert_eq!(actual, expected);
        }
        let again = compile(&lists, Some("params"));
        prop_assert_eq!(&c.rulesets, &again.rulesets);
    }
}
