//! The `/metrics` endpoint's request parser.
#![no_main]

use libfuzzer_sys::fuzz_target;
use sinkd_resolver::metrics::route;

fuzz_target!(|head: &[u8]| {
    let _ = route(head);
});
