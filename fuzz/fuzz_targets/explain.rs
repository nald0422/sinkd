//! `sinkd check`'s matcher: arbitrary rules against a few requests.
#![no_main]

use libfuzzer_sys::fuzz_target;
use sinkd_compiler::ListInput;
use sinkd_compiler::explain::{Explainer, Request};
use sinkd_filters::network::ResourceTypes;

const URLS: &[&str] = &[
    "https://ads.example.com/banner/ad.js?utm_source=x&id=1",
    "http://user:pw@[2001:db8::1]:8080/a^b*c|d",
    "wss://cdn.example.co.uk/socket#frag",
    "https://xn--bcher-kva.example/%E2%82%AC",
];

fuzz_target!(|text: &str| {
    let mut explainer = Explainer::new(&[ListInput {
        name: "fuzz".into(),
        ruleset: "ads".into(),
        text: text.into(),
    }]);
    for (i, url) in URLS.iter().enumerate() {
        for kind in [
            ResourceTypes::DOCUMENT,
            ResourceTypes::SCRIPT,
            ResourceTypes::IMAGE,
        ] {
            let initiator = (i % 2 == 0).then_some("https://news.example/page");
            let _ = explainer.explain(&Request {
                url,
                kind,
                initiator,
                method: "GET",
            });
        }
    }
});
