//! One filter-list line: the parser, then the DNR translation of a network
//! rule and the CSS of a cosmetic one. None may panic.
#![no_main]

use libfuzzer_sys::fuzz_target;
use sinkhole_filters::{Rule, parse_rule};

fuzz_target!(|line: &str| {
    match parse_rule(line) {
        Ok(Rule::Network(rule)) => {
            let _ = sinkhole_compiler::translate::translate_network(&rule);
            let _ = rule.pattern.hostname();
            let _ = rule.pattern.pure_hostname();
        }
        Ok(Rule::ResponseHeader(rule)) => {
            let _ = sinkhole_compiler::translate::translate_response_header(&rule);
        }
        Ok(Rule::Cosmetic(rule)) => {
            let _ = rule.selector.as_css();
        }
        Ok(Rule::Scriptlet(_)) | Err(_) => {}
    }
});
