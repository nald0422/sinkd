//! A lossless parser for ABP, uBlock Origin and AdGuard filter syntax.
//!
//! Every rule becomes structured data the compiler can translate per target
//! (DNS domain set, Chrome DNR rules, the cosmetic/scriptlet index). Nothing
//! is hashed or discarded, so `$domain=` strings, option values and selector
//! structure all survive to the compiler. Rules sinkhole cannot honor are
//! returned as errors with a reason; they are never applied in a broadened
//! form. See DESIGN.md for why this is not a wrapper around Brave's `adblock`
//! crate.
//!
//! ```
//! use sinkhole_filters::{parse_rule, Rule};
//!
//! let Rule::Network(rule) = parse_rule("||ads.example.com^$script,3p").unwrap() else {
//!     unreachable!()
//! };
//! assert_eq!(rule.pattern.pure_hostname(), Some("ads.example.com"));
//! ```
#![forbid(unsafe_code)]

mod cosmetic;
pub mod dns;
mod domains;
mod error;
mod list;
pub mod network;
mod preprocess;
pub mod scriptlet;

use serde::Serialize;

pub use cosmetic::{
    CosmeticAction, CosmeticRule, ProceduralOp, ResponseHeaderRule, Selector, SelectorStep, Upward,
};
pub use domains::{DomainSpec, HostPattern};
pub use error::ParseError;
pub use list::{Include, ListStats, ParsedList, ParsedRule, Rejected, is_comment, parse_list};
pub use network::NetworkRule;
pub use preprocess::{Env, Line, Lines};
pub use scriptlet::{Dialect, ScriptletCall, ScriptletRule};

/// One parsed rule.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Rule {
    Network(NetworkRule),
    Cosmetic(CosmeticRule),
    Scriptlet(ScriptletRule),
    ResponseHeader(ResponseHeaderRule),
}

/// Parses a single rule. Comments and `!#` directives are not rules; use
/// [`is_comment`] or [`parse_list`] for whole lists.
pub fn parse_rule(line: &str) -> Result<Rule, ParseError> {
    let line = line.trim();
    if line.is_empty() {
        return Err(ParseError::invalid("empty line"));
    }
    if line.starts_with("[$") {
        return Err(ParseError::unsupported(
            "cosmetic-modifiers",
            "AdGuard [$path=…] / [$domain=…] rule modifiers",
        ));
    }
    if let Some(found) = cosmetic::find_separator(line) {
        return cosmetic::parse_cosmetic(line, found);
    }
    if let Some(e) = cosmetic::unsupported_prefix(line) {
        return Err(e);
    }
    network::parse_network(line).map(Rule::Network)
}
