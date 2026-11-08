//! Prometheus `/metrics`, off by default and served on loopback only.
//!
//! A deliberately tiny HTTP/1.1 responder: it reads one request head (at
//! most [`MAX_HEAD`] bytes, within [`DEADLINE`]), answers `GET /metrics`
//! and closes the connection. No keep-alive, no bodies, no other paths:
//! a scraper needs nothing more, and there is nothing else to attack.
//! Config validation refuses a non-loopback address, and connections from
//! anywhere but loopback are closed unanswered as a second guard.
//!
//! The counters are the daemon's totals; no query names are exposed.

use std::fmt::Write as _;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio::time::timeout;
use tracing::{debug, warn};

use crate::pause::Pause;
use crate::server::{PolicyHandle, Stats};

/// The longest request head read.
pub const MAX_HEAD: usize = 8192;
/// Time allowed for the whole exchange.
pub const DEADLINE: Duration = Duration::from_secs(5);
const MAX_CLIENTS: usize = 8;

/// What `/metrics` reports on.
#[derive(Clone)]
pub struct Source {
    pub policy: PolicyHandle,
    pub stats: Arc<Stats>,
    pub pause: Arc<Pause>,
    pub started: Instant,
}

/// Serves `/metrics` on `listener` until dropped.
pub async fn serve(listener: TcpListener, source: Source) {
    let limit = Arc::new(Semaphore::new(MAX_CLIENTS));
    let source = Arc::new(source);
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(e) => {
                warn!(error = %e, "metrics accept failed");
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
        };
        if !peer.ip().to_canonical().is_loopback() {
            continue;
        }
        let Ok(permit) = Arc::clone(&limit).try_acquire_owned() else {
            continue;
        };
        let source = Arc::clone(&source);
        tokio::spawn(async move {
            if timeout(DEADLINE, exchange(stream, &source)).await.is_err() {
                debug!("metrics client too slow; closed");
            }
            drop(permit);
        });
    }
}

async fn exchange(mut stream: TcpStream, source: &Source) {
    let mut head = Vec::with_capacity(512);
    let mut buf = [0u8; 1024];
    loop {
        match stream.read(&mut buf).await {
            Ok(0) | Err(_) => return,
            Ok(n) => head.extend_from_slice(buf.get(..n).unwrap_or_default()),
        }
        if head.windows(4).any(|w| w == b"\r\n\r\n") || head.windows(2).any(|w| w == b"\n\n") {
            break;
        }
        if head.len() > MAX_HEAD {
            let _ = stream.write_all(&respond(Reply::TooLarge, "")).await;
            return;
        }
    }
    let reply = match route(&head) {
        Reply::Ok => respond(Reply::Ok, &render(source)),
        other => respond(other, ""),
    };
    let _ = stream.write_all(&reply).await;
    let _ = stream.shutdown().await;
}

/// How a request is answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reply {
    Ok,
    NotFound,
    MethodNotAllowed,
    BadRequest,
    TooLarge,
}

/// Decides a request from its head. Never panics, whatever the bytes.
pub fn route(head: &[u8]) -> Reply {
    let line_end = head.iter().position(|&b| b == b'\n').unwrap_or(head.len());
    let Ok(line) = std::str::from_utf8(head.get(..line_end).unwrap_or_default()) else {
        return Reply::BadRequest;
    };
    let mut parts = line.trim_end_matches('\r').split(' ');
    let (Some(method), Some(target), Some(version), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Reply::BadRequest;
    };
    if !version.starts_with("HTTP/1.") {
        return Reply::BadRequest;
    }
    let path = target.split('?').next().unwrap_or_default();
    match (method, path) {
        ("GET" | "HEAD", "/metrics") => Reply::Ok,
        ("GET" | "HEAD", _) => Reply::NotFound,
        _ => Reply::MethodNotAllowed,
    }
}

fn respond(reply: Reply, body: &str) -> Vec<u8> {
    let status = match reply {
        Reply::Ok => "200 OK",
        Reply::NotFound => "404 Not Found",
        Reply::MethodNotAllowed => "405 Method Not Allowed",
        Reply::BadRequest => "400 Bad Request",
        Reply::TooLarge => "431 Request Header Fields Too Large",
    };
    let content_type = if reply == Reply::Ok {
        "text/plain; version=0.0.4; charset=utf-8"
    } else {
        "text/plain; charset=utf-8"
    };
    format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

/// The exposition text.
pub fn render(source: &Source) -> String {
    let s = source.stats.snapshot();
    let policy = source.policy.load();
    let mut out = String::new();
    let mut metric = |name: &str, kind: &str, help: &str, value: u64| {
        let _ = writeln!(
            out,
            "# HELP sinkhole_{name} {help}\n# TYPE sinkhole_{name} {kind}\nsinkhole_{name} {value}"
        );
    };
    for (name, help, value) in [
        (
            "queries_total",
            "Queries received from allowed clients.",
            s.queries,
        ),
        (
            "blocked_total",
            "Queries answered with a block response for a listed name.",
            s.blocked,
        ),
        (
            "uncloaked_total",
            "Queries blocked for a listed CNAME or HTTPS/SVCB target.",
            s.uncloaked,
        ),
        ("local_total", "Special names answered locally.", s.local),
        ("cached_total", "Queries answered from the cache.", s.cached),
        (
            "forwarded_total",
            "Queries answered by an upstream.",
            s.forwarded,
        ),
        (
            "stale_total",
            "Queries answered from an expired cache entry because no upstream answered.",
            s.stale,
        ),
        (
            "upstream_failures_total",
            "Queries answered SERVFAIL because no upstream answered.",
            s.upstream_failures,
        ),
        (
            "errors_total",
            "Queries answered FORMERR, NOTIMP, REFUSED or BADVERS.",
            s.errors,
        ),
        (
            "refused_clients_total",
            "Packets and connections from clients outside the allowlist.",
            s.refused_clients,
        ),
        (
            "shed_total",
            "Queries and connections turned away at a load limit.",
            s.shed,
        ),
    ] {
        metric(name, "counter", help, value);
    }
    let matcher = policy.engine.matcher();
    metric(
        "block_entries",
        "gauge",
        "Names on the blocklist.",
        matcher.blocklist().len() as u64,
    );
    metric(
        "allow_entries",
        "gauge",
        "Names on the allowlist.",
        matcher.allowlist().len() as u64,
    );
    metric(
        "cache_entries",
        "gauge",
        "Answers in the cache.",
        policy.cache.len(),
    );
    metric(
        "paused",
        "gauge",
        "1 while blocking is paused.",
        u64::from(!source.pause.blocking()),
    );
    metric(
        "uptime_seconds",
        "gauge",
        "Seconds since the daemon started.",
        source.started.elapsed().as_secs(),
    );
    let _ = writeln!(
        out,
        "# HELP sinkhole_upstream_failures Failures in a row of each upstream; 0 when healthy.\n# TYPE sinkhole_upstream_failures gauge"
    );
    for u in policy.upstreams.status() {
        let label = u.upstream.replace('\\', "\\\\").replace('"', "\\\"");
        let _ = writeln!(
            out,
            "sinkhole_upstream_failures{{upstream=\"{label}\"}} {}",
            u.failures
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn routes() {
        assert_eq!(
            route(b"GET /metrics HTTP/1.1\r\nHost: x\r\n\r\n"),
            Reply::Ok
        );
        assert_eq!(route(b"GET /metrics?x=1 HTTP/1.0\r\n\r\n"), Reply::Ok);
        assert_eq!(route(b"HEAD /metrics HTTP/1.1\r\n\r\n"), Reply::Ok);
        assert_eq!(route(b"GET / HTTP/1.1\r\n\r\n"), Reply::NotFound);
        assert_eq!(
            route(b"POST /metrics HTTP/1.1\r\n\r\n"),
            Reply::MethodNotAllowed
        );
        assert_eq!(route(b"GET /metrics\r\n\r\n"), Reply::BadRequest);
        assert_eq!(route(b"GET /metrics SPDY/3\r\n\r\n"), Reply::BadRequest);
        assert_eq!(route(b"\xff\xfe\r\n\r\n"), Reply::BadRequest);
        assert_eq!(route(b""), Reply::BadRequest);
    }
}
