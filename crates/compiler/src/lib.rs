//! The rule compiler: one set of filter lists in, target-specific outputs
//! out.
#![forbid(unsafe_code)]

pub mod compile;
pub mod dnr;
pub mod explain;
pub mod resources;
pub mod translate;
pub mod validate;

pub use compile::{Compiled, DnsSet, ListInput, Report, Ruleset, compile};
pub mod manifest;
pub mod output;
pub mod page;

pub use manifest::{ListSpec, Manifest, ManifestError, RulesetSpec};
