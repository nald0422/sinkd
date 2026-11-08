//! Building the resolver's parts from a [`Config`].
//!
//! This only reads: local list files, and the cached copies of URL lists.
//! Downloading is the [`crate::Reloader`]'s job, so a build never waits on
//! the network and works the same offline.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use sinkd_core::config::{Config, ListAction, ListFormat, LoadError};
use sinkd_core::{CapacityError, DomainError, DomainMatcher};
use sinkd_filters::Env;
use sinkd_filters::dns::{DnsAction, DnsFormat, DnsListBuilder, DnsReport, DnsRule};
use sinkd_lists::{Cache, Part, ReadError, load_path, load_url};

use crate::cache::AnswerCache;
use crate::engine::Engine;
use crate::querylog::QueryLog;
use crate::server::{ClientFilter, Policy};
use crate::upstream::{Roots, UpstreamError, Upstreams};

/// Why the resolver could not be set up.
#[derive(Debug, thiserror::Error)]
pub enum SetupError {
    #[error(transparent)]
    Config(#[from] LoadError),
    #[error("upstreams: {0}")]
    Upstream(#[from] UpstreamError),
    #[error("list #{index}: reading {source}")]
    ReadList { index: usize, source: ReadError },
    #[error("list #{index}: reading the cached copy of {url}: {source}")]
    ReadCache {
        index: usize,
        url: String,
        source: io::Error,
    },
    #[error("allow/block entry: {0}")]
    Entry(#[from] DomainError),
    #[error(transparent)]
    Capacity(#[from] CapacityError),
}

/// The parts [`crate::Server::bind`] needs, plus what went into them.
#[derive(Debug)]
pub struct Setup {
    pub engine: Engine,
    pub upstreams: Upstreams,
    pub cache: Arc<AnswerCache>,
    pub clients: ClientFilter,
    pub log: Arc<QueryLog>,
    pub control_users: Vec<u32>,
    pub report: DnsReport,
    /// The files the rules came from, to watch for changes: local lists
    /// and the files they include, and the cache file of every URL list,
    /// whether or not it exists yet.
    pub files: Vec<PathBuf>,
    /// URL lists (indexes into `config.lists`) with no downloaded copy yet.
    /// They contribute nothing until the first download succeeds.
    pub missing: Vec<usize>,
}

impl Setup {
    pub fn policy(self) -> Policy {
        Policy {
            engine: self.engine,
            upstreams: self.upstreams,
            cache: self.cache,
            clients: self.clients,
            log: self.log,
            control_users: self.control_users,
        }
    }
}

/// Validates `config`, reads its lists and builds the resolver's parts.
/// Relative list paths are resolved against `base`, normally the directory
/// of the config file. URL lists are read from `cache`. Encrypted upstreams
/// are checked against the system's certificate authorities.
pub fn from_config(config: &Config, base: &Path, cache: &Cache) -> Result<Setup, SetupError> {
    from_config_with_roots(config, base, cache, &Roots::System)
}

/// [`from_config`], checking encrypted upstreams against `roots`.
pub fn from_config_with_roots(
    config: &Config,
    base: &Path,
    cache: &Cache,
    roots: &Roots,
) -> Result<Setup, SetupError> {
    config
        .validate()
        .map_err(|errors| SetupError::Config(LoadError::Invalid(errors)))?;
    let upstreams = Upstreams::from_config(&config.upstreams, roots)?;
    let lists = matcher(config, base, cache)?;
    Ok(Setup {
        engine: Engine::new(lists.matcher, config.blocking.clone())
            .with_special_names(config.special_names.clone()),
        upstreams,
        cache: Arc::new(AnswerCache::new(&config.cache)),
        clients: ClientFilter::new(config.listen.client_allowlist.clone()),
        log: Arc::new(QueryLog::new(&config.query_log)),
        control_users: config.control.users.clone(),
        report: lists.report,
        files: lists.files,
        missing: lists.missing,
    })
}

/// The upstreams of `config`, without reading any list.
pub fn upstreams(config: &Config) -> Result<Upstreams, SetupError> {
    Ok(Upstreams::from_config(&config.upstreams, &Roots::System)?)
}

struct Lists {
    matcher: DomainMatcher,
    report: DnsReport,
    files: Vec<PathBuf>,
    missing: Vec<usize>,
}

fn matcher(config: &Config, base: &Path, cache: &Cache) -> Result<Lists, SetupError> {
    let env = Env::dns();
    let mut builder = DnsListBuilder::with_env(env.clone());
    let mut files = Vec::new();
    let mut missing = Vec::new();
    for (index, list) in config.lists.iter().enumerate() {
        if !list.enabled {
            continue;
        }
        // One list at a time, so only one list's text is in memory at once.
        let parts: Vec<Part> = match (&list.path, &list.url) {
            (Some(path), _) => load_path(&base.join(path), &env)
                .map_err(|source| SetupError::ReadList { index, source })?,
            (None, Some(url)) => {
                files.push(cache.path(url));
                let parts = load_url(cache, url, &env).map_err(|source| SetupError::ReadCache {
                    index,
                    url: url.clone(),
                    source,
                })?;
                if parts.is_empty() {
                    missing.push(index);
                }
                parts
            }
            // `validate` requires one of the two.
            (None, None) => continue,
        };
        for part in parts {
            // Lists in the wild are occasionally not valid UTF-8. A bad byte
            // can only spoil the line it is on.
            let text = String::from_utf8_lossy(&part.body);
            builder.add_list(&text, dns_format(list.format), dns_action(list.action));
            if !files.contains(&part.path) {
                files.push(part.path);
            }
        }
    }
    for entry in config.allow_entries() {
        let (domain, scope) = entry?;
        builder.add_local_rule(local_rule(DnsAction::Allow, domain, scope))?;
    }
    for entry in config.block_entries() {
        let (domain, scope) = entry?;
        builder.add_local_rule(local_rule(DnsAction::Block, domain, scope))?;
    }
    let (matcher, report) = builder.finish();
    Ok(Lists {
        matcher,
        report,
        files,
        missing,
    })
}

fn local_rule(action: DnsAction, domain: sinkd_core::Domain, scope: sinkd_core::Scope) -> DnsRule {
    DnsRule {
        action,
        domain,
        scope,
        badfilter: false,
    }
}

fn dns_format(format: ListFormat) -> DnsFormat {
    match format {
        ListFormat::Auto => DnsFormat::Auto,
        ListFormat::Hosts => DnsFormat::Hosts,
        ListFormat::Domains => DnsFormat::Domains,
        ListFormat::Adblock => DnsFormat::Adblock,
    }
}

fn dns_action(action: ListAction) -> DnsAction {
    match action {
        ListAction::Block => DnsAction::Block,
        ListAction::Allow => DnsAction::Allow,
    }
}
