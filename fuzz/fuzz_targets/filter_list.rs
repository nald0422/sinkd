//! A whole list through the preprocessor (`!#if`, `!#include`) and the
//! parser, for Chromium and for DNS.
#![no_main]

use libfuzzer_sys::fuzz_target;
use sinkd_filters::{Env, parse_list};

fuzz_target!(|text: &str| {
    for env in [Env::chromium_mv3(), Env::dns()] {
        let parsed = parse_list(text, &env);
        assert!(parsed.stats.lines >= parsed.rules.len());
    }
});
