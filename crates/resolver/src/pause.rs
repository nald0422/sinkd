//! `sinkd pause`: blocking off for a while, or until resumed.
//!
//! The pause lives in memory only. A daemon that restarts during a pause
//! comes back blocking, which is the safe way to fail.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

/// Whether blocking is paused, and until when. Shared by the server, which
/// consults it on every query, and the control socket, which sets it.
#[derive(Debug, Default)]
pub struct Pause {
    /// 0: not paused. [`u64::MAX`]: until resumed. Otherwise the end of
    /// the pause, in milliseconds since the Unix epoch.
    until_ms: AtomicU64,
}

/// The state of a pause.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Paused {
    /// When blocking resumes by itself, in milliseconds since the Unix
    /// epoch; `None` until `sinkd resume`.
    pub until_ms: Option<u64>,
}

pub(crate) fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

impl Pause {
    /// Pauses blocking for `duration`, or until [`Pause::resume`].
    pub fn pause(&self, duration: Option<Duration>) -> Paused {
        let until = match duration {
            None => u64::MAX,
            Some(d) => now_ms()
                .saturating_add(u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
                .min(u64::MAX - 1),
        };
        self.until_ms.store(until, Ordering::Relaxed);
        Paused {
            until_ms: (until != u64::MAX).then_some(until),
        }
    }

    pub fn resume(&self) {
        self.until_ms.store(0, Ordering::Relaxed);
    }

    /// Whether blocking is on. One atomic load when it is.
    pub fn blocking(&self) -> bool {
        match self.until_ms.load(Ordering::Relaxed) {
            0 => true,
            u64::MAX => false,
            until => now_ms() >= until,
        }
    }

    /// The pause in force, if any.
    pub fn state(&self) -> Option<Paused> {
        if self.blocking() {
            return None;
        }
        let until = self.until_ms.load(Ordering::Relaxed);
        Some(Paused {
            until_ms: (until != u64::MAX).then_some(until),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pause_and_resume() {
        let pause = Pause::default();
        assert!(pause.blocking());
        assert_eq!(pause.state(), None);

        let paused = pause.pause(None);
        assert_eq!(paused.until_ms, None);
        assert!(!pause.blocking());
        assert_eq!(pause.state(), Some(Paused { until_ms: None }));

        let paused = pause.pause(Some(Duration::from_secs(300)));
        let until = paused.until_ms.unwrap();
        assert!(until > now_ms() + 299_000 && until <= now_ms() + 300_000);
        assert!(!pause.blocking());

        // A pause that has run out is over.
        pause.until_ms.store(now_ms() - 1, Ordering::Relaxed);
        assert!(pause.blocking());
        assert_eq!(pause.state(), None);

        pause.pause(None);
        pause.resume();
        assert!(pause.blocking());
    }
}
