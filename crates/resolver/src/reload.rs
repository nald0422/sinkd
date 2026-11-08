//! Keeping the rules current while the server runs.
//!
//! The [`Reloader`] is the only thing that changes a running server's
//! [`Policy`](crate::Policy). It reacts to three things:
//!
//! - **Files.** The config file, local lists (and the files they include)
//!   and the cache files of URL lists are polled every [`POLL`]: size,
//!   modification time and inode. Any change rebuilds the policy. A dozen
//!   `stat` calls every two seconds cost nothing measurable, need no
//!   platform file-watching API, and see editors that save by renaming. The
//!   cache files are watched so that `sinkhole update`, run beside the
//!   daemon, takes effect within seconds.
//! - **The schedule.** Each URL list is checked when its interval is up
//!   ([`refresh_interval`]), give or take 10% so that lists, and machines,
//!   do not all ask at once. A failed check is retried after 5 minutes,
//!   doubling each time up to the interval. Checks run in the background,
//!   [`PARALLEL_CHECKS`] at a time, so a slow server never holds up a
//!   config edit.
//! - **Requests.** [`ReloadHandle::reload`] (the CLI wires it to SIGHUP)
//!   re-reads everything now; [`ReloadHandle::refresh`] checks every URL list
//!   now.
//!
//! **Last known-good, at every level.** A download that fails or does not
//! pass the checks leaves the cached copy in use. A config edit that does
//! not parse, validate or build is logged and ignored, and the previous
//! config stays in force. A rebuild that fails (a local list deleted
//! mid-edit, say) keeps the policy that was in force. Short of removing a
//! list on purpose, nothing that goes wrong at run time makes sinkhole block
//! less than it did.

use std::collections::hash_map::RandomState;
use std::collections::{HashMap, HashSet};
use std::hash::BuildHasher;
use std::io;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use sinkhole_core::config::{Config, ListSource};
use sinkhole_filters::Env;
use sinkhole_lists::{BoxFuture, Cache, Fetcher, Outcome, Report, Resolve, refresh_interval};
use tokio::sync::{Notify, Semaphore, mpsc};
use tracing::{debug, error, info, warn};

use crate::server::PolicyHandle;
use crate::setup::from_config_with_roots;
use crate::upstream::{Roots, Upstreams};

/// How often watched files are checked for changes.
pub const POLL: Duration = Duration::from_secs(2);
/// URL lists checked at the same time.
pub const PARALLEL_CHECKS: usize = 4;
/// First retry after a failed check; it doubles with each failure.
const RETRY: Duration = Duration::from_secs(300);
/// A changed file must stay unchanged this long before it is read, so a
/// save in progress is not read half-written.
const SETTLE: Duration = Duration::from_millis(250);

/// Asks a running [`Reloader`] to act now. Clones share it.
#[derive(Debug, Clone)]
pub struct ReloadHandle(Arc<Requests>);

#[derive(Debug, Default)]
struct Requests {
    reload: Notify,
    refresh: Notify,
}

impl ReloadHandle {
    /// Re-read the config and every list file now.
    pub fn reload(&self) {
        self.0.reload.notify_one();
    }

    /// Check every URL list for a new version now.
    pub fn refresh(&self) {
        self.0.refresh.notify_one();
    }
}

/// When a URL list is next checked.
#[derive(Debug, Clone, Copy)]
struct Due {
    at: Instant,
    failures: u32,
}

/// Identifies a version of a file without reading it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Fingerprint {
    len: u64,
    modified: Option<SystemTime>,
    inode: u64,
}

fn fingerprint(path: &Path) -> Option<Fingerprint> {
    let meta = std::fs::metadata(path).ok()?;
    #[cfg(unix)]
    let inode = std::os::unix::fs::MetadataExt::ino(&meta);
    #[cfg(not(unix))]
    let inode = 0;
    Some(Fingerprint {
        len: meta.len(),
        modified: meta.modified().ok(),
        inode,
    })
}

/// A finished check of one URL list.
type Checked = (String, Vec<Report>);

/// Watches files, refreshes URL lists and swaps in rebuilt policies.
pub struct Reloader {
    config_path: PathBuf,
    base: PathBuf,
    config: Config,
    cache: Cache,
    policy: PolicyHandle,
    fetcher: Fetcher,
    roots: Roots,
    poll: Duration,
    requests: Arc<Requests>,
    config_seen: Option<Fingerprint>,
    watched: Vec<(PathBuf, Option<Fingerprint>)>,
    schedule: HashMap<String, Due>,
    checking: HashSet<String>,
    /// Files or lists changed since the last build.
    dirty: bool,
    last_build: Instant,
}

impl Reloader {
    /// `config` is what the server was started with, `files` the
    /// [`Setup::files`](crate::Setup::files) it was built from, and `cache`
    /// where its URL lists live.
    pub fn new(
        config_path: PathBuf,
        config: Config,
        files: Vec<PathBuf>,
        policy: PolicyHandle,
        fetcher: Fetcher,
        cache: Cache,
    ) -> Self {
        let base = config_path
            .parent()
            .map_or_else(|| PathBuf::from("."), Path::to_path_buf);
        let mut reloader = Reloader {
            config_seen: fingerprint(&config_path),
            config_path,
            base,
            config,
            cache,
            policy,
            fetcher,
            roots: Roots::System,
            poll: POLL,
            requests: Arc::default(),
            watched: Vec::new(),
            schedule: HashMap::new(),
            checking: HashSet::new(),
            dirty: false,
            last_build: Instant::now(),
        };
        reloader.watch(files, &[]);
        reloader.sync_schedule();
        reloader
    }

    /// Checks encrypted upstreams against `roots` after a rebuild, as the
    /// server's first build did. For tests against local servers.
    pub fn with_roots(mut self, roots: Roots) -> Self {
        self.roots = roots;
        self
    }

    /// Polls files this often instead of every [`POLL`]. For tests.
    pub fn with_poll_interval(mut self, poll: Duration) -> Self {
        self.poll = poll;
        self
    }

    pub fn handle(&self) -> ReloadHandle {
        ReloadHandle(Arc::clone(&self.requests))
    }

    /// Runs until the task is dropped.
    pub async fn run(mut self) {
        let (done_tx, mut done_rx) = mpsc::unbounded_channel::<Checked>();
        let checks = Arc::new(Semaphore::new(PARALLEL_CHECKS));
        let requests = Arc::clone(&self.requests);
        loop {
            self.start_due_checks(&done_tx, &checks);
            let next_due = self
                .schedule
                .iter()
                .filter(|(url, _)| !self.checking.contains(*url))
                .map(|(_, due)| due.at)
                .min();
            let mut reread = false;
            tokio::select! {
                () = tokio::time::sleep(self.poll) => reread = true,
                () = sleep_until(next_due) => {}
                () = requests.reload.notified() => {
                    info!("reload requested");
                    reread = true;
                    self.dirty = true;
                }
                () = requests.refresh.notified() => {
                    info!("checking every list now");
                    let now = Instant::now();
                    self.schedule.values_mut().for_each(|due| due.at = now);
                }
                Some((url, reports)) = done_rx.recv() => self.finish_check(&url, &reports),
            }
            if reread {
                if let Some(candidate) = self.changed_config().await {
                    self.rebuild(Some(candidate)).await;
                    continue;
                }
                if self.files_changed() {
                    let paths: Vec<_> = self.watched.iter().map(|(p, _)| p.clone()).collect();
                    self.settle(&paths).await;
                    self.dirty = true;
                }
            }
            // While checks are running, rebuild at most once per poll, so a
            // batch of updates costs one build rather than one each.
            if self.dirty && (self.checking.is_empty() || self.last_build.elapsed() >= self.poll) {
                self.rebuild(None).await;
            }
        }
    }

    fn url_lists(&self) -> impl Iterator<Item = (&ListSource, &str)> {
        self.config
            .lists
            .iter()
            .filter(|l| l.enabled)
            .filter_map(|l| Some((l, l.url.as_deref()?)))
    }

    /// Adds newly configured URL lists to the schedule and drops removed ones.
    fn sync_schedule(&mut self) {
        let now = Instant::now();
        let mut fresh = HashMap::new();
        for (list, url) in self.url_lists() {
            let due = self.schedule.get(url).copied().unwrap_or_else(|| {
                // First seen: due when the cached copy's interval is up, or
                // now if there is none.
                let cached = self.cache.load_meta(url).ok().flatten();
                let interval = refresh_interval(list, cached.as_ref(), &self.config.updates);
                let left = cached.map_or(Duration::ZERO, |m| interval.saturating_sub(m.age()));
                Due {
                    at: now + left,
                    failures: 0,
                }
            });
            fresh.insert(url.to_owned(), due);
        }
        self.schedule = fresh;
    }

    fn start_due_checks(&mut self, done: &mpsc::UnboundedSender<Checked>, checks: &Arc<Semaphore>) {
        let now = Instant::now();
        let due: Vec<String> = self
            .schedule
            .iter()
            .filter(|(url, due)| due.at <= now && !self.checking.contains(*url))
            .map(|(url, _)| url.clone())
            .collect();
        for url in due {
            self.checking.insert(url.clone());
            let (fetcher, cache) = (self.fetcher.clone(), self.cache.clone());
            let (done, checks) = (done.clone(), Arc::clone(checks));
            tokio::spawn(async move {
                // The semaphore is never closed.
                let _permit = checks.acquire_owned().await;
                let reports =
                    sinkhole_lists::update(&fetcher, &cache, &url, &Env::dns(), false).await;
                let _ = done.send((url, reports));
            });
        }
    }

    fn finish_check(&mut self, url: &str, reports: &[Report]) {
        self.checking.remove(url);
        let Some(list) = self
            .url_lists()
            .find(|(_, u)| *u == url)
            .map(|(l, _)| l.clone())
        else {
            return; // removed from the config meanwhile
        };
        let name = list.name.as_deref().unwrap_or(url);
        for report in reports {
            log_report(name, report);
        }
        let Some(first) = reports.first() else {
            return;
        };
        let interval = refresh_interval(&list, first.cached.as_ref(), &self.config.updates);
        let now = Instant::now();
        let due = self.schedule.entry(url.to_owned()).or_insert(Due {
            at: now,
            failures: 0,
        });
        if first.failed() {
            due.failures += 1;
            let backoff = RETRY.saturating_mul(1 << (due.failures - 1).min(16));
            due.at = now + jitter(backoff.min(interval));
        } else {
            due.failures = 0;
            due.at = now + jitter(interval);
        }
        if reports.iter().any(Report::updated) {
            self.dirty = true;
        }
    }

    /// Waits until none of `paths` has changed for [`SETTLE`] (or the poll
    /// interval, if shorter), giving up after 20 tries: a writer that never
    /// stops is caught by the check after the build instead.
    async fn settle(&self, paths: &[PathBuf]) {
        let settle = SETTLE.min(self.poll);
        let mut last: Vec<_> = paths.iter().map(|p| fingerprint(p)).collect();
        for _ in 0..20 {
            tokio::time::sleep(settle).await;
            let now: Vec<_> = paths.iter().map(|p| fingerprint(p)).collect();
            if now == last {
                return;
            }
            last = now;
        }
    }

    /// The config file, if it changed and still parses and validates.
    async fn changed_config(&mut self) -> Option<Config> {
        if fingerprint(&self.config_path) == self.config_seen {
            return None;
        }
        self.settle(std::slice::from_ref(&self.config_path)).await;
        let seen = fingerprint(&self.config_path);
        // Recorded first, so a broken config is reported once, not every poll.
        self.config_seen = seen;
        let path = self.config_path.display();
        let text = match std::fs::read_to_string(&self.config_path) {
            Ok(text) => text,
            Err(e) => {
                warn!(%path, error = %e, "cannot read the config; keeping the one in force");
                return None;
            }
        };
        match Config::from_toml(&text) {
            Ok(config) if config == self.config => None,
            Ok(config) => Some(config),
            Err(e) => {
                error!(%path, "config change rejected; keeping the one in force: {e}");
                None
            }
        }
    }

    fn files_changed(&self) -> bool {
        self.watched
            .iter()
            .any(|(path, seen)| fingerprint(path) != *seen)
    }

    /// Records the files a build read. Fingerprints taken just before the
    /// build are reused, so a change made while it ran is still noticed.
    fn watch(&mut self, files: Vec<PathBuf>, before: &[(PathBuf, Option<Fingerprint>)]) {
        self.watched = files
            .into_iter()
            .map(|path| {
                let seen = before
                    .iter()
                    .find(|(p, _)| *p == path)
                    .map_or_else(|| fingerprint(&path), |(_, f)| *f);
                (path, seen)
            })
            .collect();
    }

    /// Rebuilds the policy from the files, with `candidate` as the config
    /// if given. Puts it in force only if the build succeeds.
    async fn rebuild(&mut self, candidate: Option<Config>) {
        self.dirty = false;
        self.last_build = Instant::now();
        let before: Vec<_> = self
            .watched
            .iter()
            .map(|(path, _)| (path.clone(), fingerprint(path)))
            .collect();
        let config = candidate.clone().unwrap_or_else(|| self.config.clone());
        let cache = match &candidate {
            Some(c) => match sinkhole_lists::cache_dir(c, &self.base) {
                Some(dir) => Cache::new(dir),
                None => {
                    error!("config change rejected: no cache directory; set updates.cache_dir");
                    return;
                }
            },
            None => self.cache.clone(),
        };
        let (base, build_cache, roots) = (self.base.clone(), cache.clone(), self.roots.clone());
        let build_config = config.clone();
        let started = Instant::now();
        let built = tokio::task::spawn_blocking(move || {
            from_config_with_roots(&build_config, &base, &build_cache, &roots)
        })
        .await;
        let mut setup = match built {
            Ok(Ok(setup)) => setup,
            Ok(Err(e)) => {
                error!("reload failed; keeping the rules in force: {e}");
                // Not retried until something changes again.
                self.watched = before;
                return;
            }
            Err(e) => {
                error!("reload failed; keeping the rules in force: {e}");
                self.watched = before;
                return;
            }
        };
        // A file that changed while the build read it may have been read
        // half-written (a save that truncates, then writes). Discard the
        // build: the next poll sees the change, waits for it to settle and
        // builds again. A config edit is re-read then too.
        let raced = before
            .iter()
            .any(|(path, seen)| setup.files.contains(path) && fingerprint(path) != *seen);
        if raced {
            debug!("a file changed during the rebuild; discarding it");
            self.watched = before;
            if candidate.is_some() {
                self.config_seen = None;
            }
            return;
        }
        let report = &setup.report;
        info!(
            block = report.block_entries,
            allow = report.allow_entries,
            not_for_dns = report.rejected_total(),
            awaiting_download = setup.missing.len(),
            elapsed_ms = started.elapsed().as_millis(),
            "rules reloaded"
        );
        let files = std::mem::take(&mut setup.files);
        let mut policy = setup.policy();
        // Unchanged upstreams keep their connections and health, and an
        // unchanged cache (same upstreams, same settings) keeps its answers.
        // Answers do not depend on the lists: blocking is decided per query.
        let current = self.policy.load();
        // The query log keeps its entries across reloads, like the cache.
        policy.log = Arc::clone(&current.log);
        policy.log.configure(&config.query_log);
        if config.upstreams == self.config.upstreams {
            policy.upstreams = current.upstreams.clone();
            if config.cache == self.config.cache {
                policy.cache = Arc::clone(&current.cache);
            }
        }
        if let Some(config) = candidate {
            if config.listen != self.config.listen {
                warn!("listen settings changed; restart sinkhole to apply them");
            }
            if config.metrics != self.config.metrics
                || config.control.socket != self.config.control.socket
            {
                warn!("metrics or control socket settings changed; restart sinkhole to apply them");
            }
            info!("config change applied");
            self.config = config;
            self.cache = cache;
            self.sync_schedule();
        }

        self.policy.store(policy);
        self.watch(files, &before);
    }
}

fn log_report(list: &str, report: &Report) {
    let include = report.included.then_some(report.url.as_str());
    match &report.outcome {
        Outcome::Updated { rules, previous } => {
            info!(list, include, rules, previous, "list updated");
        }
        Outcome::NotModified => debug!(list, include, "list unchanged"),
        Outcome::Failed { reason } => {
            let kept = match &report.cached {
                Some(meta) => format!("keeping the copy from {} ago", human(meta.age())),
                None => "no copy yet, so it is not in use".to_owned(),
            };
            warn!(list, include, "list check failed: {reason}; {kept}");
        }
    }
}

/// `3d`, `5h`, `12m`, `40s`.
pub(crate) fn human(d: Duration) -> String {
    let s = d.as_secs();
    match s {
        0..60 => format!("{s}s"),
        60..3600 => format!("{}m", s / 60),
        3600..86_400 => format!("{}h", s / 3600),
        _ => format!("{}d", s / 86_400),
    }
}

/// `d`, give or take 10%. The randomness comes from std's per-instance hash
/// keys, which is plenty for spreading load.
fn jitter(d: Duration) -> Duration {
    let r = RandomState::new().hash_one(Instant::now()) % 2001;
    d.mul_f64(0.9 + r as f64 / 10_000.0)
}

async fn sleep_until(at: Option<Instant>) {
    match at {
        Some(at) => tokio::time::sleep_until(at.into()).await,
        None => std::future::pending().await,
    }
}

/// List servers are found through the upstreams, never through the system
/// resolver (which may be sinkhole itself) and never against the lists.
impl Resolve for Upstreams {
    fn resolve(&self, host: &str) -> BoxFuture<io::Result<Vec<IpAddr>>> {
        let (upstreams, host) = (self.clone(), host.to_owned());
        Box::pin(async move { upstreams.lookup_ip(&host).await })
    }
}

/// The running server's upstreams, as they are at the time of each lookup.
impl Resolve for PolicyHandle {
    fn resolve(&self, host: &str) -> BoxFuture<io::Result<Vec<IpAddr>>> {
        let (policy, host) = (self.load(), host.to_owned());
        Box::pin(async move { policy.upstreams.lookup_ip(&host).await })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jitter_stays_within_ten_percent() {
        let d = Duration::from_secs(1000);
        for _ in 0..1000 {
            let j = jitter(d);
            assert!(
                j >= Duration::from_secs(900) && j <= Duration::from_secs(1100),
                "{j:?}"
            );
        }
    }

    #[test]
    fn human_durations() {
        assert_eq!(human(Duration::from_secs(5)), "5s");
        assert_eq!(human(Duration::from_secs(600)), "10m");
        assert_eq!(human(Duration::from_secs(7200)), "2h");
        assert_eq!(human(Duration::from_secs(3 * 86_400 + 5)), "3d");
    }
}
