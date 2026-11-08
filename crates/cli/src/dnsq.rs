//! A one-shot DNS query, for the installer's readiness check and `doctor`.

use std::net::{IpAddr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow};
use hickory_proto::op::{Message, Query};
use hickory_proto::rr::{Name, RData, RecordType};

/// Asks `server` for `name` (A) over UDP and returns the answer.
pub fn ask(server: SocketAddr, name: &str, timeout: Duration) -> Result<Message> {
    let mut query = Message::query();
    query.metadata.recursion_desired = true;
    let fqdn = if name.ends_with('.') {
        name.to_owned()
    } else {
        format!("{name}.")
    };
    query.add_query(Query::query(Name::from_ascii(&fqdn)?, RecordType::A));
    let id = query.metadata.id;
    let bytes = query.to_vec()?;
    let bind: SocketAddr = if server.is_ipv4() {
        "0.0.0.0:0".parse()?
    } else {
        "[::]:0".parse()?
    };
    let socket = UdpSocket::bind(bind)?;
    socket.connect(server)?;
    let deadline = Instant::now() + timeout;
    socket.send(&bytes)?;
    let mut buf = [0u8; 4096];
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(anyhow!("no answer from {server} within {timeout:?}"));
        }
        socket.set_read_timeout(Some(left))?;
        let n = socket
            .recv(&mut buf)
            .with_context(|| format!("no answer from {server}"))?;
        if let Ok(reply) = Message::from_vec(buf.get(..n).unwrap_or_default())
            && reply.metadata.id == id
        {
            return Ok(reply);
        }
    }
}

/// The addresses in an answer.
pub fn addresses(message: &Message) -> Vec<IpAddr> {
    message
        .answers
        .iter()
        .filter_map(|r| match &r.data {
            RData::A(a) => Some(IpAddr::V4(a.0)),
            RData::AAAA(a) => Some(IpAddr::V6(a.0)),
            _ => None,
        })
        .collect()
}

/// Waits until `server` answers a query for `localhost.`, which sinkhole
/// answers itself, without an upstream.
pub fn wait_ready(server: SocketAddr, within: Duration) -> bool {
    let deadline = Instant::now() + within;
    while Instant::now() < deadline {
        if ask(server, "localhost", Duration::from_millis(500)).is_ok() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    false
}

/// What the system's own resolver (getaddrinfo) returns for `name`.
pub fn system_lookup(name: &str) -> Result<Vec<IpAddr>> {
    let mut ips: Vec<IpAddr> = (name, 0)
        .to_socket_addrs()
        .with_context(|| format!("looking up {name}"))?
        .map(|a| a.ip())
        .collect();
    ips.sort();
    ips.dedup();
    Ok(ips)
}

/// Whether the addresses are a null-address block answer.
pub fn is_null(ips: &[IpAddr]) -> bool {
    !ips.is_empty() && ips.iter().all(IpAddr::is_unspecified)
}
