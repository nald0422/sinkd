//! Name normalization: parsing is idempotent, and what parses as a list
//! entry or a query name is a name.
#![no_main]

use libfuzzer_sys::fuzz_target;
use sinkhole_core::{Domain, QueryName, parse_domain_pattern};

fuzz_target!(|text: &str| {
    if let Ok(domain) = Domain::parse(text) {
        let again = Domain::parse(domain.as_str()).expect("a normalized name parses");
        assert_eq!(again, domain);
        let _ = domain.parent();
        assert!(domain.suffixes().count() >= 1);
    }
    let _ = parse_domain_pattern(text);
    // One trailing dot goes (the root label); nothing else changes but
    // ASCII case. Names off the wire never end in two.
    if let Some(name) = QueryName::new(text) {
        let stripped = text.strip_suffix('.').unwrap_or(text);
        assert_eq!(name.as_str(), stripped.to_ascii_lowercase());
    }
});
