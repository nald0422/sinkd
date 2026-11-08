//! Shared building blocks for sinkhole: domain-name normalization, the DNS
//! domain matcher used by the resolver, and config types.
//!
//! This crate does no I/O and has no async code, so the resolver, the rule
//! compiler and the wasm engine can all depend on it.
#![forbid(unsafe_code)]

#[cfg(feature = "config")]
pub mod config;
pub mod domain;
pub mod matcher;
#[cfg(feature = "page")]
pub mod page;

pub use domain::{Domain, DomainError, QueryName};
pub use matcher::{
    CapacityError, DomainMatcher, DomainMatcherBuilder, DomainSet, Scope, Verdict,
    parse_domain_pattern,
};
