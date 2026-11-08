//! Refreshing lists into the cache, and reading them back for a build.
//!
//! The cache is the single source of truth for URL lists: a refresh writes
//! to it and a build reads from it. A refresh that fails, or brings back
//! something that does not pass [`check`], leaves the cached copy alone,
//! which is what keeps the last known-good list in service.
//!
//! `!#include` is followed for both URL and local lists, as uBO does: the
//! included file must sit in the including list's directory or below it
//! (and on the same origin). Each included file is cached and checked on
//! its own, and handed to the DNS builder as a list of its own.

use std::collections::{HashSet, VecDeque};
use std::io;
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use reqwest::Url;
use sinkhole_core::config::{ListSource, Updates};
use sinkhole_filters::{Env, Line, Lines};
use tracing::warn;

use crate::cache::{Cache, Meta, unix_now};
use crate::check::check;
use crate::fetch::{Fetched, Fetcher};

/// Most files one list may pull in through `!#include`, nested ones included.
pub const MAX_INCLUDES: usize = 16;
/// Deepest nesting of `!#include`s.
pub const MAX_INCLUDE_DEPTH: usize = 3;

/// What happened to one file in a refresh.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// A new version passed the checks and is now the cached copy.
    Updated {
        rules: usize,
        previous: Option<usize>,
    },
    /// The cached copy is current.
    NotModified,
    /// Nothing usable came back. The cached copy, if any, stays in use.
    Failed { reason: String },
}

/// The result of refreshing one file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    pub url: String,
    /// Pulled in by an `!#include` rather than configured.
    pub included: bool,
    pub outcome: Outcome,
    /// The cached copy in use after the refresh.
    pub cached: Option<Meta>,
}

impl Report {
    pub fn updated(&self) -> bool {
        matches!(self.outcome, Outcome::Updated { .. })
    }

    pub fn failed(&self) -> bool {
        matches!(self.outcome, Outcome::Failed { .. })
    }
}

/// Refreshes the list at `url` and every file it includes. The first report
/// is the list itself. `force` sends no validators, so the list is
/// downloaded in full, and accepts a list that shrank drastically.
pub async fn update(
    fetcher: &Fetcher,
    cache: &Cache,
    url: &str,
    env: &Env,
    force: bool,
) -> Vec<Report> {
    let mut reports = Vec::new();
    let mut seen = HashSet::from([url.to_owned()]);
    // Refused includes queue up too, so the reports follow the lists' order.
    let mut queue = VecDeque::from([(Ok(url.to_owned()), 0)]);
    while let Some((entry, depth)) = queue.pop_front() {
        let url = match entry {
            Ok(url) => url,
            Err((path, reason)) => {
                reports.push(refused(path, reason));
                continue;
            }
        };
        let report = update_file(fetcher, cache, &url, depth > 0, force).await;
        reports.push(report);
        if depth == MAX_INCLUDE_DEPTH {
            continue;
        }
        let Ok(Some(cached)) = cache.load(&url) else {
            continue;
        };
        for path in includes(&cached.body, env) {
            let entry = match include_url(&url, &path) {
                Ok(included) if seen.contains(&included) => continue,
                Ok(included) if seen.len() > MAX_INCLUDES => {
                    Err((included, "too many !#include files"))
                }
                Ok(included) => {
                    seen.insert(included.clone());
                    Ok(included)
                }
                Err(reason) => Err((path, reason)),
            };
            queue.push_back((entry, depth + 1));
        }
    }
    reports
}

fn refused(url: String, reason: &str) -> Report {
    Report {
        url,
        included: true,
        outcome: Outcome::Failed {
            reason: reason.to_owned(),
        },
        cached: None,
    }
}

async fn update_file(
    fetcher: &Fetcher,
    cache: &Cache,
    url: &str,
    included: bool,
    force: bool,
) -> Report {
    let previous = cache.load_meta(url).unwrap_or_else(|e| {
        warn!(url, error = %e, "could not read the cached copy; downloading afresh");
        None
    });
    let validators = if force { None } else { previous.as_ref() };
    let (outcome, cached) = match fetcher.fetch(url, validators).await {
        Ok(Fetched::NotModified) => (Outcome::NotModified, previous),
        Ok(Fetched::Body {
            body,
            etag,
            last_modified,
        }) => {
            let digest = format!("{:016x}", crate::cache::fnv1a(&body));
            match check(&body, previous.as_ref().map(|m| m.rules), force) {
                // A server without validators sends the whole list every
                // time; an unchanged one must not count as an update.
                Ok(_) if !force && previous.as_ref().is_some_and(|m| m.digest == digest) => {
                    (Outcome::NotModified, previous)
                }
                Ok(summary) => {
                    let meta = Meta {
                        url: url.to_owned(),
                        etag,
                        last_modified,
                        fetched_at: unix_now(),
                        rules: summary.rules,
                        expires_secs: summary.expires.map(|d| d.as_secs()),
                        digest,
                    };
                    match cache.store(&meta, &body) {
                        Ok(()) => (
                            Outcome::Updated {
                                rules: summary.rules,
                                previous: previous.as_ref().map(|m| m.rules),
                            },
                            Some(meta),
                        ),
                        Err(e) => (
                            Outcome::Failed {
                                reason: format!(
                                    "downloaded, but could not save it in {}: {e}",
                                    cache.dir().display()
                                ),
                            },
                            previous,
                        ),
                    }
                }
                Err(rejection) => (
                    Outcome::Failed {
                        reason: rejection.to_string(),
                    },
                    previous,
                ),
            }
        }
        Err(e) => (
            Outcome::Failed {
                reason: e.to_string(),
            },
            previous,
        ),
    };
    Report {
        url: url.to_owned(),
        included,
        outcome,
        cached,
    }
}

/// The paths of the live `!#include` lines of a list.
pub fn includes(body: &[u8], env: &Env) -> Vec<String> {
    let text = String::from_utf8_lossy(body);
    Lines::new(&text, env)
        .filter_map(|(_, line)| match line {
            Line::Include(path) => Some(path.to_owned()),
            _ => None,
        })
        .collect()
}

/// The URL an `!#include` in the list at `parent` refers to: resolved
/// against it, and only if it stays on the same origin and in the parent's
/// directory or below.
pub fn include_url(parent: &str, path: &str) -> Result<String, &'static str> {
    let base = Url::parse(parent).map_err(|_| "the including list's URL does not parse")?;
    let url = base
        .join(path)
        .map_err(|_| "the !#include path does not parse")?;
    let dir = &base.path()[..=base.path().rfind('/').unwrap_or(0)];
    if url.scheme() != "https" || url.origin() != base.origin() || !url.path().starts_with(dir) {
        return Err("!#include must stay in the including list's directory");
    }
    Ok(url.into())
}

/// The file an `!#include` in the local list at `parent` refers to: a
/// relative path that stays in the parent's directory.
pub fn include_path(parent: &Path, path: &str) -> Result<PathBuf, &'static str> {
    let relative = Path::new(path);
    if !relative
        .components()
        .all(|c| matches!(c, Component::Normal(_) | Component::CurDir))
    {
        return Err("!#include must stay in the including list's directory");
    }
    Ok(parent.parent().unwrap_or(Path::new(".")).join(relative))
}

/// One file of a list, read for a build.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Part {
    /// The URL or path the file came from, for messages.
    pub origin: String,
    /// The file on disk: the list itself, or its cache file.
    pub path: PathBuf,
    pub body: Vec<u8>,
}

/// Reading a local list failed.
#[derive(Debug, thiserror::Error)]
#[error("{}: {source}", path.display())]
pub struct ReadError {
    pub path: PathBuf,
    pub source: io::Error,
}

/// Reads a local list and the files it includes.
pub fn load_path(path: &Path, env: &Env) -> Result<Vec<Part>, ReadError> {
    let read = |path: &PathBuf| {
        let body = std::fs::read(path).map_err(|source| ReadError {
            path: path.clone(),
            source,
        })?;
        Ok(Some(Part {
            origin: path.display().to_string(),
            path: path.clone(),
            body,
        }))
    };
    let resolve = |parent: &PathBuf, include: &str| {
        include_path(parent, include)
            .map(Some)
            .map_err(|reason| ReadError {
                path: parent.clone(),
                source: io::Error::new(io::ErrorKind::InvalidInput, format!("{include}: {reason}")),
            })
    };
    load(path.to_path_buf(), env, read, resolve)
}

/// Reads a URL list and the files it includes from the cache. A file that
/// has never been downloaded is left out, so a list that was never
/// downloaded gives no parts at all.
pub fn load_url(cache: &Cache, url: &str, env: &Env) -> io::Result<Vec<Part>> {
    let read = |url: &String| {
        Ok(cache.load(url)?.map(|cached| Part {
            origin: url.clone(),
            path: cache.path(url),
            body: cached.body,
        }))
    };
    // A refused include was already reported by the refresh; skip it here.
    let resolve = |parent: &String, include: &str| Ok(include_url(parent, include).ok());
    load(url.to_owned(), env, read, resolve)
}

/// Breadth-first over a list and its includes, with the same limits as
/// [`update`]. `read` gives `None` for a file to skip, `resolve` gives
/// `None` for an include to skip.
fn load<K, E>(
    root: K,
    env: &Env,
    read: impl Fn(&K) -> Result<Option<Part>, E>,
    resolve: impl Fn(&K, &str) -> Result<Option<K>, E>,
) -> Result<Vec<Part>, E>
where
    K: Clone + Eq + std::hash::Hash,
{
    let mut parts = Vec::new();
    let mut seen = HashSet::from([root.clone()]);
    let mut queue = VecDeque::from([(root, 0)]);
    while let Some((key, depth)) = queue.pop_front() {
        let Some(part) = read(&key)? else {
            continue;
        };
        if depth < MAX_INCLUDE_DEPTH {
            for include in includes(&part.body, env) {
                if let Some(next) = resolve(&key, &include)?
                    && seen.len() <= MAX_INCLUDES
                    && seen.insert(next.clone())
                {
                    queue.push_back((next, depth + 1));
                }
            }
        }
        parts.push(part);
    }
    Ok(parts)
}

/// How often to check `list` for a new version: its `refresh_hours`, else
/// the list's own `! Expires:` header, else `updates.interval_hours`.
pub fn refresh_interval(list: &ListSource, cached: Option<&Meta>, updates: &Updates) -> Duration {
    let hours = |h: u32| Duration::from_secs(u64::from(h) * 3600);
    list.refresh_hours
        .map(hours)
        .or_else(|| cached.and_then(Meta::expires))
        .unwrap_or_else(|| hours(updates.interval_hours))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn include_urls_stay_beside_the_list() {
        let parent = "https://lists.example/filters/main.txt";
        let ok = |p: &str| include_url(parent, p).unwrap();
        assert_eq!(ok("sub.txt"), "https://lists.example/filters/sub.txt");
        assert_eq!(ok("./a/b.txt"), "https://lists.example/filters/a/b.txt");
        assert_eq!(
            ok("https://lists.example/filters/x.txt"),
            "https://lists.example/filters/x.txt"
        );
        for refused in [
            "../secret.txt",
            "/other/x.txt",
            "https://evil.example/filters/x.txt",
            "http://lists.example/filters/x.txt",
            "https://lists.example:8443/filters/x.txt",
            "//evil.example/x.txt",
        ] {
            assert!(include_url(parent, refused).is_err(), "{refused}");
        }
    }

    #[test]
    fn include_paths_stay_beside_the_list() {
        let parent = Path::new("/etc/sinkhole/lists/main.txt");
        assert_eq!(
            include_path(parent, "sub.txt").unwrap(),
            Path::new("/etc/sinkhole/lists/sub.txt")
        );
        assert_eq!(
            include_path(parent, "./more/x.txt").unwrap(),
            Path::new("/etc/sinkhole/lists/./more/x.txt")
        );
        for refused in ["../x.txt", "/etc/passwd", "a/../../x.txt"] {
            assert!(include_path(parent, refused).is_err(), "{refused}");
        }
    }

    #[test]
    fn local_includes_are_loaded_once_each() {
        let dir = std::env::temp_dir().join(format!("sinkhole-include-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("sub")).unwrap();
        std::fs::write(
            dir.join("main.txt"),
            "a.example\n!#include sub/b.txt\n!#if env_firefox\n!#include c.txt\n!#endif\n",
        )
        .unwrap();
        // The cycle back to main.txt is cut by the seen set.
        std::fs::write(dir.join("sub/b.txt"), "b.example\n!#include b.txt\n").unwrap();
        let parts = load_path(&dir.join("main.txt"), &Env::dns()).unwrap();
        let names: Vec<_> = parts
            .iter()
            .map(|p| p.path.strip_prefix(&dir).unwrap().to_owned())
            .collect();
        assert_eq!(
            names,
            [PathBuf::from("main.txt"), PathBuf::from("sub/b.txt")]
        );

        std::fs::write(dir.join("main.txt"), "!#include ../escape.txt\n").unwrap();
        let e = load_path(&dir.join("main.txt"), &Env::dns()).unwrap_err();
        assert_eq!(e.source.kind(), io::ErrorKind::InvalidInput);
        std::fs::write(dir.join("main.txt"), "!#include missing.txt\n").unwrap();
        let e = load_path(&dir.join("main.txt"), &Env::dns()).unwrap_err();
        assert_eq!(e.source.kind(), io::ErrorKind::NotFound);
        assert!(e.path.ends_with("missing.txt"));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn refresh_interval_precedence() {
        let hour = Duration::from_secs(3600);
        let updates = Updates {
            interval_hours: 24,
            cache_dir: None,
        };
        let mut list: ListSource = toml::from_str("url = \"https://lists.example/a.txt\"").unwrap();
        let mut meta = Meta {
            url: list.url.clone().unwrap(),
            etag: None,
            last_modified: None,
            fetched_at: 0,
            rules: 1,
            expires_secs: None,
            digest: String::new(),
        };
        assert_eq!(refresh_interval(&list, None, &updates), hour * 24);
        assert_eq!(refresh_interval(&list, Some(&meta), &updates), hour * 24);
        meta.expires_secs = Some(4 * 86_400);
        assert_eq!(refresh_interval(&list, Some(&meta), &updates), hour * 96);
        list.refresh_hours = Some(6);
        assert_eq!(refresh_interval(&list, Some(&meta), &updates), hour * 6);
    }
}
