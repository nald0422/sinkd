//! The sinkhole DNS daemon.
//!
//! [`Engine`] decides each query without I/O: blocked names are answered
//! here, malformed or unsupported queries get an error, and the rest is
//! forwarded through [`Upstreams`]. [`Server`] owns the sockets, decides who
//! may query and bounds the work any client can cause. [`Reloader`] keeps
//! the rules current while the server runs: it refreshes URL lists, watches
//! files, and swaps in each rebuilt [`Policy`].
//!
//! ```no_run
//! # async fn demo() -> Result<(), Box<dyn std::error::Error>> {
//! use std::path::PathBuf;
//! use std::sync::Arc;
//!
//! use sinkhole_core::config::Config;
//! use sinkhole_lists::{Cache, Fetcher};
//! use sinkhole_resolver::{Reloader, Server, from_config};
//!
//! let path = PathBuf::from("sinkhole.toml");
//! let config = Config::from_toml(&std::fs::read_to_string(&path)?)?;
//! let cache = Cache::new("/var/cache/sinkhole");
//! let setup = from_config(&config, std::path::Path::new("."), &cache)?;
//! let files = setup.files.clone();
//! let server = Server::bind(setup.policy(), &config.listen.addrs).await?;
//! let fetcher = Fetcher::builder().resolver(Arc::new(server.policy())).build()?;
//! let reloader = Reloader::new(path, config, files, server.policy(), fetcher, cache);
//! tokio::spawn(reloader.run());
//! server.run().await?;
//! # Ok(())
//! # }
//! ```
#![forbid(unsafe_code)]

mod cache;
#[cfg(unix)]
pub mod control;
mod engine;
pub mod metrics;
mod pause;
pub mod querylog;
mod reload;
mod server;
pub mod service;
mod setup;
mod special;
mod upstream;
mod wire;

pub use cache::{AnswerCache, Key as CacheKey, STALE_TTL};
pub use engine::{Decision, Engine, Forward, Transport, UDP_PAYLOAD, query_name, question};
pub use pause::{Pause, Paused};
pub use querylog::QueryLog;
pub use reload::{PARALLEL_CHECKS, POLL, ReloadHandle, Reloader};
pub use server::{
    ClientFilter, MAX_CONNECTIONS, MAX_FORWARDS, Policy, PolicyHandle, Server, Sockets, Stats,
    StatsSnapshot, bind_sockets,
};
pub use setup::{Setup, SetupError, from_config, from_config_with_roots, upstreams};
pub use upstream::{DEADLINE, DEFAULT_TIMEOUT, Roots, UpstreamError, UpstreamStatus, Upstreams};
