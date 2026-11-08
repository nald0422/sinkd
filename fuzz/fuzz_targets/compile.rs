//! The compiler on a list: every DNR rule it emits must pass Chrome's
//! checks as the compiler models them and serialize, and the page index
//! must survive a round trip.
#![no_main]

use libfuzzer_sys::fuzz_target;
use sinkhole_compiler::{ListInput, compile, validate};
use sinkhole_core::page::PageIndex;

fuzz_target!(|text: &str| {
    let lists = [ListInput {
        name: "fuzz".into(),
        ruleset: "ads".into(),
        text: text.into(),
    }];
    let compiled = compile(&lists, Some("params"));
    for ruleset in &compiled.rulesets {
        for rule in &ruleset.rules {
            if let Err(e) = validate::check(rule) {
                panic!("emitted an invalid rule ({e}): {rule:?}");
            }
            serde_json::to_string(rule).expect("serializes");
        }
    }
    let bytes = compiled.page.index.to_bytes();
    let back = PageIndex::from_bytes(&bytes).expect("index round trip");
    assert_eq!(back, compiled.page.index);
    let _ = compiled.page.calls_for("www.example.com");
});
