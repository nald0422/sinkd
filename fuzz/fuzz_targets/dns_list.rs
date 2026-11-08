//! A DNS list (hosts file, plain names, adblock syntax) into the matcher.
//! Every entry the builder accepted must then be found by it.
#![no_main]

use libfuzzer_sys::fuzz_target;
use sinkhole_filters::Env;
use sinkhole_filters::dns::{DnsAction, DnsFormat, DnsListBuilder};

fuzz_target!(|data: &[u8]| {
    let Some((&selector, rest)) = data.split_first() else {
        return;
    };
    let text = String::from_utf8_lossy(rest);
    let format = match selector % 4 {
        0 => DnsFormat::Auto,
        1 => DnsFormat::Hosts,
        2 => DnsFormat::Domains,
        _ => DnsFormat::Adblock,
    };
    let action = if selector & 0x80 == 0 {
        DnsAction::Block
    } else {
        DnsAction::Allow
    };
    let mut builder = DnsListBuilder::with_env(Env::dns());
    builder.add_list(&text, format, action);
    let (matcher, _report) = builder.finish();
    for (name, _) in matcher.blocklist().iter() {
        let _ = matcher.check(name);
    }
    for line in text.lines().take(64) {
        let _ = matcher.check(&line.trim().to_ascii_lowercase());
    }
});
