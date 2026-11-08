//! Forwarding to upstream resolvers: DNS over HTTPS (RFC 8484, the
//! default), DNS over TLS (RFC 7858), and plain DNS over UDP with TCP
//! fallback.
//!
//! **Failover is health-aware.** Upstreams are tried in config order, but
//! one that just failed (a timeout, a refused connection, a TLS or HTTP
//! error) is not asked on a client's behalf while a healthy one remains.
//! It is paused (1 s after the first failure, doubling to 30 s), and when
//! the pause ends, a query is also sent to it in the background as a
//! probe; only a successful probe puts it back first in line. A dead
//! upstream therefore costs one client one timeout, when it dies. A failed
//! upstream is still tried, last, when every healthy one fails. An upstream
//! that answers SERVFAIL is healthy (the *domain* is broken, or fails
//! DNSSEC there), so the next upstream is asked without penalty.
//!
//! **A query has a deadline**, [`DEADLINE`] across all attempts, inside the
//! 5 s stub resolvers wait before retrying, so the client gets SERVFAIL
//! rather than silence.
//!
//! **Encrypted queries are padded** to a multiple of 128 bytes (RFC 8467),
//! so the length of a query does not give away the name in it.

mod doh;
mod dot;
mod plain;
mod tls;

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use hickory_proto::ProtoError;
use hickory_proto::op::{Message, ResponseCode};
use hickory_proto::rr::rdata::opt::{EdnsCode, EdnsOption};
use hickory_proto::rr::{Name, RData, RecordType};
use hickory_proto::serialize::binary::DecodeError;
use sinkd_core::config::Upstream as UpstreamConfig;
use tracing::debug;

pub use tls::Roots;

use crate::engine::Forward;

/// Time allowed per attempt at one upstream.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(2);
/// Time allowed per query, across every upstream tried.
pub const DEADLINE: Duration = Duration::from_millis(4500);
/// Encrypted queries are padded to a multiple of this (RFC 8467 §4.1).
const PAD_BLOCK: usize = 128;
const FIRST_PAUSE: Duration = Duration::from_secs(1);
const MAX_PAUSE: Duration = Duration::from_secs(30);

/// Why an upstream could not be set up.
#[derive(Debug, thiserror::Error)]
pub enum UpstreamError {
    #[error("bad URL {0}")]
    Url(String),
    #[error("bad server name {0}")]
    ServerName(String),
    #[error("TLS setup: {0}")]
    Tls(#[from] rustls::Error),
    #[error("HTTP client setup: {0}")]
    Http(#[from] reqwest::Error),
}

/// Why one attempt at one upstream failed.
#[derive(Debug, thiserror::Error)]
pub(crate) enum ExchangeError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error("could not encode the query: {0}")]
    Encode(#[from] ProtoError),
    #[error("unparseable answer: {0}")]
    Decode(#[from] DecodeError),
    #[error("{}", chain(.0))]
    Http(#[from] reqwest::Error),
    #[error("answered HTTP {0}")]
    Status(u16),
    #[error("answered with content type {0:?}, not application/dns-message")]
    ContentType(String),
    #[error("answer larger than a DNS message can be")]
    TooLarge,
    #[error("answered a different question")]
    Mismatch,
    #[error("the connection closed")]
    Closed,
    #[error("timed out")]
    Timeout,
}

/// reqwest's own message hides the cause ("invalid peer certificate…") in
/// its sources.
fn chain(e: &reqwest::Error) -> String {
    let mut message = e.to_string();
    let mut source = std::error::Error::source(e);
    while let Some(cause) = source {
        message.push_str(": ");
        message.push_str(&cause.to_string());
        source = cause.source();
    }
    message
}

#[derive(Debug)]
enum Transport {
    Plain(SocketAddr),
    Doh(doh::Doh),
    Dot(dot::Dot),
}

impl Transport {
    async fn exchange(&self, forward: &Forward) -> Result<Message, ExchangeError> {
        match self {
            Transport::Plain(addr) => plain::exchange(*addr, forward).await,
            Transport::Doh(doh) => doh.exchange(forward).await,
            Transport::Dot(dot) => dot.exchange(forward).await,
        }
    }

    fn describe(&self) -> String {
        match self {
            Transport::Plain(addr) => format!("udp://{addr}"),
            Transport::Doh(doh) => doh.url().to_string(),
            Transport::Dot(dot) => format!("tls://{}", dot.addr()),
        }
    }
}

/// How an upstream is doing, for `sinkd stats` and `/metrics`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct UpstreamStatus {
    pub upstream: String,
    /// Failures in a row; 0 when its last attempt succeeded.
    pub failures: u32,
}

/// Recent failures of one upstream.
#[derive(Debug, Default)]
struct Health {
    failures: AtomicU32,
    /// Skipped until this many nanoseconds after [`epoch`]; 0 when healthy.
    paused_until: AtomicU64,
}

/// A fixed origin, so an instant fits in an atomic integer.
fn epoch() -> Instant {
    static EPOCH: OnceLock<Instant> = OnceLock::new();
    *EPOCH.get_or_init(Instant::now)
}

fn nanos(at: Instant) -> u64 {
    u64::try_from(at.saturating_duration_since(epoch()).as_nanos()).unwrap_or(u64::MAX)
}

impl Health {
    fn paused_until(&self) -> u64 {
        self.paused_until.load(Ordering::Relaxed)
    }

    fn succeeded(&self) {
        self.failures.store(0, Ordering::Relaxed);
        self.paused_until.store(0, Ordering::Relaxed);
    }

    fn failed(&self) {
        let failures = self.failures.fetch_add(1, Ordering::Relaxed);
        let pause = FIRST_PAUSE
            .saturating_mul(1 << failures.min(16))
            .min(MAX_PAUSE);
        self.paused_until
            .store(nanos(Instant::now() + pause), Ordering::Relaxed);
    }
}

#[derive(Debug)]
struct Upstream {
    transport: Transport,
    health: Health,
}

/// The upstream resolvers, tried in order. Clones share connections and
/// health, so a reload that keeps the upstreams keeps both.
#[derive(Debug, Clone)]
pub struct Upstreams {
    list: Arc<[Upstream]>,
    timeout: Duration,
}

impl Upstreams {
    /// Plain-DNS upstreams, for tests and benchmarks.
    pub fn new(servers: Vec<SocketAddr>, timeout: Duration) -> Self {
        Self::from_transports(servers.into_iter().map(Transport::Plain).collect(), timeout)
    }

    /// The upstreams of a config.
    pub fn from_config(configs: &[UpstreamConfig], roots: &Roots) -> Result<Self, UpstreamError> {
        let transports = configs
            .iter()
            .map(|config| {
                Ok(match config {
                    UpstreamConfig::Udp { addr } => Transport::Plain(*addr),
                    UpstreamConfig::Doh { url, bootstrap } => {
                        Transport::Doh(doh::Doh::new(url, bootstrap, roots)?)
                    }
                    UpstreamConfig::Dot { addr, server_name } => {
                        Transport::Dot(dot::Dot::new(*addr, server_name, roots)?)
                    }
                })
            })
            .collect::<Result<Vec<_>, UpstreamError>>()?;
        Ok(Self::from_transports(transports, DEFAULT_TIMEOUT))
    }

    /// Changes the time allowed per attempt.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    fn from_transports(transports: Vec<Transport>, timeout: Duration) -> Self {
        Upstreams {
            list: transports
                .into_iter()
                .map(|transport| Upstream {
                    transport,
                    health: Health::default(),
                })
                .collect(),
            timeout,
        }
    }

    /// `udp://…`, `https://…/dns-query` or `tls://…` for each, in order.
    pub fn describe(&self) -> Vec<String> {
        self.list.iter().map(|u| u.transport.describe()).collect()
    }

    /// The health of each, in order.
    pub fn status(&self) -> Vec<UpstreamStatus> {
        self.list
            .iter()
            .map(|u| UpstreamStatus {
                upstream: u.transport.describe(),
                failures: u.health.failures.load(Ordering::Relaxed),
            })
            .collect()
    }

    /// Asks the upstreams in turn, healthy ones first, until one gives a
    /// usable answer. `None` means all of them failed, or the deadline
    /// passed; the caller answers SERVFAIL rather than leave the client to
    /// time out.
    ///
    /// An upstream that failed recently is not asked on a client's behalf
    /// while a healthy one remains. Once its pause is over, the query is
    /// also sent to it in the background, as a probe: success puts it back
    /// first in line, failure pauses it again. So a dead upstream costs a
    /// client one timeout when it dies, not one every pause.
    pub async fn resolve(&self, forward: &Forward) -> Option<Message> {
        let started = Instant::now();
        let now = nanos(started);
        let healthy = |u: &Upstream| u.health.failures.load(Ordering::Relaxed) == 0;
        let have_healthy = self.list.iter().any(healthy);
        // Healthy upstreams in config order, then the others, soonest back
        // first.
        let mut order: Vec<usize> = (0..self.list.len()).collect();
        order.sort_by_key(|&i| {
            let u = &self.list[i];
            if healthy(u) {
                0
            } else {
                u.health.paused_until().max(1)
            }
        });
        if have_healthy {
            for (i, upstream) in self.list.iter().enumerate() {
                if !healthy(upstream) && upstream.health.paused_until() <= now {
                    self.probe(i, forward);
                }
            }
        }
        for i in order {
            let upstream = &self.list[i];
            if have_healthy && !healthy(upstream) {
                continue;
            }
            let left = DEADLINE.saturating_sub(started.elapsed());
            if left.is_zero() {
                break;
            }
            let attempt =
                tokio::time::timeout(left.min(self.timeout), upstream.transport.exchange(forward))
                    .await;
            match attempt.unwrap_or(Err(ExchangeError::Timeout)) {
                Ok(answer) => {
                    upstream.health.succeeded();
                    match answer.metadata.response_code {
                        ResponseCode::NoError | ResponseCode::NXDomain => return Some(answer),
                        // SERVFAIL, REFUSED and the like: the next upstream
                        // may do better, and this one is not to blame.
                        code => debug!(
                            upstream = %upstream.transport.describe(),
                            %code,
                            "upstream could not answer"
                        ),
                    }
                }
                Err(e) => {
                    upstream.health.failed();
                    debug!(upstream = %upstream.transport.describe(), error = %e, "upstream failed");
                }
            }
        }
        // Every healthy upstream failed this time: try the paused ones too,
        // rather than give up while one might answer.
        if have_healthy && started.elapsed() < DEADLINE {
            for upstream in self
                .list
                .iter()
                .filter(|u| u.health.failures.load(Ordering::Relaxed) > 0)
            {
                let left = DEADLINE.saturating_sub(started.elapsed());
                if left.is_zero() {
                    break;
                }
                let attempt = tokio::time::timeout(
                    left.min(self.timeout),
                    upstream.transport.exchange(forward),
                )
                .await;
                if let Ok(Ok(answer)) = attempt {
                    upstream.health.succeeded();
                    if matches!(
                        answer.metadata.response_code,
                        ResponseCode::NoError | ResponseCode::NXDomain
                    ) {
                        return Some(answer);
                    }
                }
            }
        }
        None
    }

    /// Sends `forward` to upstream `i` in the background, only to learn
    /// whether it is back. Its pause is extended for the probe's duration,
    /// so concurrent queries do not each start one.
    fn probe(&self, i: usize, forward: &Forward) {
        let health = &self.list[i].health;
        health
            .paused_until
            .store(nanos(Instant::now() + self.timeout), Ordering::Relaxed);
        let (list, forward, timeout) = (Arc::clone(&self.list), forward.clone(), self.timeout);
        tokio::spawn(async move {
            let upstream = &list[i];
            match tokio::time::timeout(timeout, upstream.transport.exchange(&forward)).await {
                Ok(Ok(_)) => {
                    debug!(upstream = %upstream.transport.describe(), "upstream is back");
                    upstream.health.succeeded();
                }
                _ => upstream.health.failed(),
            }
        });
    }

    /// The addresses of `host`, asked of the upstreams directly. This is how
    /// list servers are found: not through the system resolver, which may
    /// be sinkd itself, and not against the lists. IPv4 first; the HTTP
    /// client races the families anyway (Happy Eyeballs).
    pub async fn lookup_ip(&self, host: &str) -> io::Result<Vec<IpAddr>> {
        let mut name = Name::from_ascii(host)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("{host}: {e}")))?;
        name.set_fqdn(true);
        let (v4, v6) = (
            Forward::lookup(name.clone(), RecordType::A),
            Forward::lookup(name, RecordType::AAAA),
        );
        let (a, aaaa) = tokio::join!(self.resolve(&v4), self.resolve(&v6));
        if a.is_none() && aaaa.is_none() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("no upstream answered for {host}"),
            ));
        }
        let ips: Vec<IpAddr> = a
            .into_iter()
            .chain(aaaa)
            .flat_map(|answer| answer.answers)
            .filter_map(|record| match record.data {
                RData::A(a) => Some(IpAddr::V4(a.0)),
                RData::AAAA(aaaa) => Some(IpAddr::V6(aaaa.0)),
                _ => None,
            })
            .collect();
        if ips.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("{host} has no addresses"),
            ));
        }
        Ok(ips)
    }
}

/// Adds an EDNS Padding option (RFC 7830) that brings the encoded query to
/// a multiple of [`PAD_BLOCK`] bytes.
pub(crate) fn pad(query: &mut Message) -> Result<(), ProtoError> {
    let Some(edns) = query.edns.as_mut() else {
        return Ok(());
    };
    edns.options_mut().remove(EdnsCode::Padding);
    let unpadded = query.to_vec()?.len();
    // The option adds a 4-byte header before its padding bytes.
    let fill = (PAD_BLOCK - (unpadded + 4) % PAD_BLOCK) % PAD_BLOCK;
    if let Some(edns) = query.edns.as_mut() {
        edns.options_mut().insert(EdnsOption::Unknown(
            u16::from(EdnsCode::Padding),
            vec![0; fill],
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::{Edns, Query};

    #[test]
    fn padding_fills_to_the_block() {
        for name in [
            "a.example.",
            "a-much-longer-name.with.several.labels.example.",
        ] {
            let mut m = Message::query();
            m.add_query(Query::query(Name::from_ascii(name).unwrap(), RecordType::A));
            m.set_edns(Edns::new());
            pad(&mut m).unwrap();
            let bytes = m.to_vec().unwrap();
            assert_eq!(bytes.len() % PAD_BLOCK, 0, "{name}: {}", bytes.len());
            // Padding twice does not stack.
            pad(&mut m).unwrap();
            assert_eq!(m.to_vec().unwrap().len(), bytes.len());
            // It parses back.
            let back = Message::from_vec(&bytes).unwrap();
            assert!(
                back.edns
                    .unwrap()
                    .options()
                    .get(EdnsCode::Padding)
                    .is_some()
            );
        }
    }

    #[test]
    fn health_pauses_grow_and_reset() {
        let h = Health::default();
        let now = nanos(Instant::now());
        assert_eq!(h.paused_until(), 0);
        h.failed();
        let first = h.paused_until() - now;
        h.failed();
        let second = h.paused_until() - now;
        assert!((900_000_000..1_500_000_000).contains(&first), "{first}");
        assert!(second > first);
        for _ in 0..20 {
            h.failed();
        }
        assert!(h.paused_until() - now <= MAX_PAUSE.as_nanos() as u64 + 100_000_000);
        h.succeeded();
        assert_eq!(h.paused_until(), 0);
    }
}
