//! The config file: parsing and validation never panic, and a config that
//! loads survives being written back out.
#![no_main]

use libfuzzer_sys::fuzz_target;
use sinkhole_core::config::Config;

fuzz_target!(|text: &str| {
    if let Ok(config) = Config::from_toml(text) {
        let written = config.to_toml().expect("a loaded config serializes");
        let back = Config::from_toml(&written).expect("and loads again");
        assert_eq!(back, config);
        for entry in config.allow_entries().chain(config.block_entries()) {
            entry.expect("validated entries parse");
        }
    }
});
