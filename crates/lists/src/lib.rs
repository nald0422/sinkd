//! Filter lists from the network: fetched over HTTPS, checked, and kept on
//! disk as the last known-good copy.
//!
//! - [`fetch`]: conditional HTTPS downloads ([`Fetcher`]).
//! - [`check`]: whether a download is a plausible list ([`check::check`]).
//! - [`cache`]: the copies on disk ([`Cache`]).
//! - [`update`]: refreshing a list into the cache, following `!#include`,
//!   and reading lists back for a build ([`update()`], [`load_url`],
//!   [`load_path`]).
//!
//! Nothing here parses rules or touches the resolver; the resolver reads the
//! cache and decides when to refresh.
#![forbid(unsafe_code)]

pub mod cache;
pub mod check;
pub mod fetch;
#[cfg(feature = "testing")]
pub mod testing;
pub mod update;

use std::path::{Path, PathBuf};

use sinkd_core::config::Config;

pub use cache::{Cache, Cached, Meta};
pub use check::{MAX_LIST_BYTES, Rejection, Summary};
pub use fetch::{BoxFuture, FetchError, Fetched, Fetcher, FetcherBuilder, Resolve};
pub use update::{
    MAX_INCLUDE_DEPTH, MAX_INCLUDES, Outcome, Part, ReadError, Report, load_path, load_url,
    refresh_interval, update,
};

/// The cache directory for `config`: `updates.cache_dir` (relative to
/// `base`, the config file's directory), else [`default_cache_dir`].
pub fn cache_dir(config: &Config, base: &Path) -> Option<PathBuf> {
    match &config.updates.cache_dir {
        Some(dir) => Some(base.join(dir)),
        None => default_cache_dir(),
    }
}

/// The platform's per-user cache directory, plus `sinkd`:
/// `$XDG_CACHE_HOME/sinkd` if that is set, else
/// `~/Library/Caches/sinkd` on macOS and `~/.cache/sinkd` elsewhere.
/// `None` without a home directory (a service with no `HOME`), in which
/// case the config must set `updates.cache_dir`.
pub fn default_cache_dir() -> Option<PathBuf> {
    let var = |name| {
        std::env::var_os(name)
            .map(PathBuf::from)
            .filter(|p| p.is_absolute())
    };
    if let Some(xdg) = var("XDG_CACHE_HOME") {
        return Some(xdg.join("sinkd"));
    }
    let home = var("HOME")?;
    if cfg!(target_os = "macos") {
        Some(home.join("Library/Caches/sinkd"))
    } else {
        Some(home.join(".cache/sinkd"))
    }
}
