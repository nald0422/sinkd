//! Running under a service manager: readiness and the watchdogs.
//!
//! - **systemd** (Linux): with `Type=notify`, [`notify`] tells it the
//!   daemon is ready once the sockets are bound, so `systemctl start` (and
//!   the installer) wait for a resolver that answers. With `WatchdogSec=`,
//!   [`systemd_watchdog`] pings it at half the interval, but only after a
//!   self-test query passes; a daemon that stops answering stops pinging
//!   and is restarted.
//! - **Every platform**: [`HangGuard`] is a plain thread that aborts the
//!   process when the async runtime has not ticked for a minute. launchd
//!   (`KeepAlive`) and systemd (`Restart=`) then start a fresh one. A
//!   resolver that hangs takes the machine's DNS with it, so a restart is
//!   the better failure.
//!
//! The systemd protocol is a datagram to `$NOTIFY_SOCKET`; no library is
//! needed for it.

use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use hickory_proto::op::{Message, Query};
use hickory_proto::rr::{Name, RecordType};
use tracing::{error, warn};

use crate::engine::{Decision, Transport};
use crate::server::PolicyHandle;

/// Sends `state` (`READY=1`, `WATCHDOG=1`, `STOPPING=1`) to systemd.
/// `Ok(false)` when not running under systemd.
pub fn notify(state: &str) -> io::Result<bool> {
    #[cfg(unix)]
    {
        use std::os::unix::net::UnixDatagram;
        let Some(path) = std::env::var_os("NOTIFY_SOCKET") else {
            return Ok(false);
        };
        let socket = UnixDatagram::unbound()?;
        let bytes = path.as_encoded_bytes();
        if let Some(name) = bytes.strip_prefix(b"@") {
            // An abstract socket (Linux only).
            #[cfg(target_os = "linux")]
            {
                use std::os::linux::net::SocketAddrExt;
                let addr = std::os::unix::net::SocketAddr::from_abstract_name(name)?;
                socket.send_to_addr(state.as_bytes(), &addr)?;
                return Ok(true);
            }
            #[cfg(not(target_os = "linux"))]
            {
                let _ = name;
                return Err(io::Error::other("abstract NOTIFY_SOCKET outside Linux"));
            }
        }
        socket.send_to(state.as_bytes(), &path)?;
        Ok(true)
    }
    #[cfg(not(unix))]
    {
        let _ = state;
        Ok(false)
    }
}

/// How often systemd wants a watchdog ping: half of `WatchdogSec=`.
/// `None` without one, or when it is meant for another process.
pub fn watchdog_interval() -> Option<Duration> {
    if let Some(pid) = std::env::var("WATCHDOG_PID").ok()
        && pid.parse::<u32>().ok() != Some(std::process::id())
    {
        return None;
    }
    let usec: u64 = std::env::var("WATCHDOG_USEC").ok()?.parse().ok()?;
    (usec > 0).then(|| Duration::from_micros(usec / 2))
}

/// Whether the engine in force answers a query: `localhost.` must come
/// back as a local answer. Cheap; no network.
pub fn self_test(policy: &PolicyHandle) -> bool {
    let Ok(name) = Name::from_ascii("localhost.") else {
        return false;
    };
    let mut query = Message::query();
    query.add_query(Query::query(name, RecordType::A));
    query.metadata.recursion_desired = true;
    let Ok(bytes) = query.to_vec() else {
        return false;
    };
    matches!(
        policy.load().engine.decide(&bytes, Transport::Udp),
        Decision::Local(_)
    )
}

/// Pings systemd's watchdog every `interval` while [`self_test`] passes.
pub async fn systemd_watchdog(policy: PolicyHandle, interval: Duration) {
    let mut ticker = tokio::time::interval(interval);
    loop {
        ticker.tick().await;
        if self_test(&policy) {
            if let Err(e) = notify("WATCHDOG=1") {
                warn!(error = %e, "systemd watchdog ping failed");
            }
        } else {
            error!("self-test failed; not pinging the watchdog");
        }
    }
}

/// Aborts the process if the async runtime stops ticking.
#[derive(Debug, Clone)]
pub struct HangGuard {
    /// Milliseconds since `origin` at the last tick.
    last: Arc<AtomicU64>,
    origin: Instant,
}

/// How often the runtime ticks the guard.
const TICK: Duration = Duration::from_secs(1);

impl HangGuard {
    /// Starts the watching thread. The process is aborted once nothing has
    /// called [`HangGuard::run`]'s tick for `limit`.
    pub fn start(limit: Duration) -> io::Result<HangGuard> {
        let guard = HangGuard {
            last: Arc::new(AtomicU64::new(0)),
            origin: Instant::now(),
        };
        let watcher = guard.clone();
        std::thread::Builder::new()
            .name("hang-guard".into())
            .spawn(move || {
                loop {
                    std::thread::sleep(limit / 4);
                    let silent = watcher.since_tick();
                    if silent > limit {
                        error!(
                            silent_secs = silent.as_secs(),
                            "the resolver stopped responding; aborting so the service manager restarts it"
                        );
                        eprintln!("sinkhole: runtime hung for {silent:?}; aborting");
                        std::process::abort();
                    }
                }
            })?;
        Ok(guard)
    }

    fn since_tick(&self) -> Duration {
        let now = self.origin.elapsed();
        now.saturating_sub(Duration::from_millis(self.last.load(Ordering::Relaxed)))
    }

    fn tick(&self) {
        let ms = u64::try_from(self.origin.elapsed().as_millis()).unwrap_or(u64::MAX);
        self.last.store(ms, Ordering::Relaxed);
    }

    /// Ticks the guard from the runtime, forever.
    pub async fn run(self) {
        let mut ticker = tokio::time::interval(TICK);
        loop {
            ticker.tick().await;
            self.tick();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hang_guard_counts_from_the_last_tick() {
        let guard = HangGuard {
            last: Arc::new(AtomicU64::new(0)),
            origin: Instant::now() - Duration::from_secs(10),
        };
        assert!(guard.since_tick() >= Duration::from_secs(10));
        guard.tick();
        assert!(guard.since_tick() < Duration::from_secs(1));
    }

    #[test]
    fn no_systemd_no_notification() {
        // NOTIFY_SOCKET is unset in tests (unless run under systemd itself).
        if std::env::var_os("NOTIFY_SOCKET").is_none() {
            assert!(!notify("READY=1").unwrap());
        }
    }
}
