//! The per-query log: off by default, in memory only, and capped.
//!
//! Nothing is written to disk. Entries older than `retention_hours`, or
//! beyond `max_entries`, are dropped as new ones arrive, and a restart
//! empties the log. Switching it off in the config empties it at once.
//! Only `sinkd stats` reads it, through the control socket, and only for
//! the users allowed to pause (see [`crate::control`]), since it shows
//! every name anyone on the machine looked up.

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use sinkd_core::config::QueryLog as Settings;

use crate::pause::now_ms;

/// How a query was answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Blocked,
    /// Blocked for a listed CNAME or HTTPS/SVCB target in the answer.
    Uncloaked,
    Local,
    Cached,
    Forwarded,
    Stale,
    Failed,
    Error,
    Shed,
}

impl Outcome {
    pub fn is_blocked(self) -> bool {
        matches!(self, Outcome::Blocked | Outcome::Uncloaked)
    }
}

/// One logged query.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    /// Milliseconds since the Unix epoch.
    pub at_ms: u64,
    pub name: String,
    /// `A`, `AAAA`, `HTTPS`…
    pub qtype: String,
    pub outcome: Outcome,
    /// The list entry that blocked it, for blocked queries.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule: Option<String>,
}

/// The log. Cheap to consult when off: one relaxed atomic load per query.
#[derive(Debug)]
pub struct QueryLog {
    enabled: AtomicBool,
    inner: Mutex<Inner>,
}

#[derive(Debug, Default)]
struct Inner {
    entries: VecDeque<Entry>,
    max_entries: usize,
    retention: Duration,
}

impl Default for QueryLog {
    /// A log that is off.
    fn default() -> Self {
        QueryLog::new(&Settings::default())
    }
}

impl QueryLog {
    pub fn new(settings: &Settings) -> Self {
        let log = QueryLog {
            enabled: AtomicBool::new(false),
            inner: Mutex::new(Inner::default()),
        };
        log.configure(settings);
        log
    }

    /// Applies changed settings. Turning the log off empties it.
    pub fn configure(&self, settings: &Settings) {
        let mut inner = self.lock();
        inner.max_entries = settings.max_entries;
        inner.retention = Duration::from_secs(u64::from(settings.retention_hours) * 3600);
        if !settings.enabled {
            inner.entries = VecDeque::new();
        }
        inner.prune(now_ms());
        self.enabled.store(
            settings.enabled && settings.max_entries > 0,
            Ordering::Relaxed,
        );
    }

    pub fn enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        // A panic while holding the lock leaves at worst a half-pruned
        // queue, which is still a valid one.
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Records a query, if the log is on.
    pub fn record(&self, name: &str, qtype: &str, outcome: Outcome, rule: Option<&str>) {
        if !self.enabled() {
            return;
        }
        let entry = Entry {
            at_ms: now_ms(),
            name: name.to_owned(),
            qtype: qtype.to_owned(),
            outcome,
            rule: rule.map(str::to_owned),
        };
        let mut inner = self.lock();
        let at = entry.at_ms;
        inner.entries.push_back(entry);
        inner.prune(at);
    }

    /// The most recent entries, newest first.
    pub fn recent(&self, limit: usize, blocked_only: bool) -> Vec<Entry> {
        let mut inner = self.lock();
        inner.prune(now_ms());
        inner
            .entries
            .iter()
            .rev()
            .filter(|e| !blocked_only || e.outcome.is_blocked())
            .take(limit)
            .cloned()
            .collect()
    }

    /// The most frequent names in the log, blocked ones and all, with
    /// their counts, most frequent first.
    pub fn top(&self, limit: usize) -> Top {
        let mut inner = self.lock();
        inner.prune(now_ms());
        let mut blocked: HashMap<&str, u64> = HashMap::new();
        let mut queried: HashMap<&str, u64> = HashMap::new();
        for e in &inner.entries {
            *queried.entry(&e.name).or_default() += 1;
            if e.outcome.is_blocked() {
                *blocked.entry(&e.name).or_default() += 1;
            }
        }
        let since_ms = inner.entries.front().map(|e| e.at_ms);
        Top {
            entries: inner.entries.len(),
            since_ms,
            blocked: ranked(blocked, limit),
            queried: ranked(queried, limit),
        }
    }
}

fn ranked(counts: HashMap<&str, u64>, limit: usize) -> Vec<(String, u64)> {
    let mut v: Vec<_> = counts.into_iter().collect();
    // Ties by name, so the order is stable.
    v.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(b.0)));
    v.into_iter()
        .take(limit)
        .map(|(n, c)| (n.to_owned(), c))
        .collect()
}

/// [`QueryLog::top`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Top {
    /// Entries in the log.
    pub entries: usize,
    /// When the oldest entry was logged.
    pub since_ms: Option<u64>,
    pub blocked: Vec<(String, u64)>,
    pub queried: Vec<(String, u64)>,
}

impl Inner {
    fn prune(&mut self, now_ms: u64) {
        let horizon =
            now_ms.saturating_sub(u64::try_from(self.retention.as_millis()).unwrap_or(u64::MAX));
        while self.entries.front().is_some_and(|e| e.at_ms < horizon) {
            self.entries.pop_front();
        }
        while self.entries.len() > self.max_entries {
            self.entries.pop_front();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings(enabled: bool, max_entries: usize) -> Settings {
        Settings {
            enabled,
            retention_hours: 24,
            max_entries,
        }
    }

    #[test]
    fn off_records_nothing() {
        let log = QueryLog::new(&settings(false, 10));
        log.record("a.example", "A", Outcome::Forwarded, None);
        assert!(log.recent(10, false).is_empty());
    }

    #[test]
    fn capped_newest_first_and_cleared_when_switched_off() {
        let log = QueryLog::new(&settings(true, 3));
        for name in ["a", "b", "c", "d"] {
            log.record(name, "A", Outcome::Forwarded, None);
        }
        log.record("ads", "A", Outcome::Blocked, Some("ads"));
        let names: Vec<_> = log.recent(10, false).into_iter().map(|e| e.name).collect();
        assert_eq!(names, ["ads", "d", "c"]);
        let blocked = log.recent(10, true);
        assert_eq!(blocked.len(), 1);
        assert_eq!(blocked[0].rule.as_deref(), Some("ads"));

        log.configure(&settings(false, 3));
        log.configure(&settings(true, 3));
        assert!(log.recent(10, false).is_empty());
    }

    #[test]
    fn old_entries_expire() {
        let log = QueryLog::new(&settings(true, 10));
        log.record("old", "A", Outcome::Forwarded, None);
        log.lock().entries[0].at_ms -= 25 * 3_600_000;
        log.record("new", "A", Outcome::Forwarded, None);
        let names: Vec<_> = log.recent(10, false).into_iter().map(|e| e.name).collect();
        assert_eq!(names, ["new"]);
    }

    #[test]
    fn top_counts() {
        let log = QueryLog::new(&settings(true, 100));
        for _ in 0..3 {
            log.record("ads.example", "A", Outcome::Blocked, Some("ads.example"));
        }
        log.record("cdn.example", "A", Outcome::Uncloaked, None);
        for _ in 0..5 {
            log.record("news.example", "A", Outcome::Cached, None);
        }
        let top = log.top(2);
        assert_eq!(top.entries, 9);
        assert_eq!(
            top.blocked,
            [("ads.example".to_owned(), 3), ("cdn.example".to_owned(), 1)]
        );
        assert_eq!(
            top.queried,
            [
                ("news.example".to_owned(), 5),
                ("ads.example".to_owned(), 3)
            ]
        );
    }
}
