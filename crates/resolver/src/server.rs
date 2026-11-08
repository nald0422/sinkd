//! Sockets, access control and load limits.
//!
//! Every address in `listen.addrs` is served over UDP and TCP. Each UDP
//! socket has a few receive loops; blocked and malformed queries are answered
//! inline, forwarded ones in their own task. Each TCP connection is served by
//! one task, a query at a time (RFC 7766 allows this; stub clients rarely
//! pipeline).
//!
//! The limits keep a flood from exhausting memory: at most [`MAX_FORWARDS`]
//! upstream queries in flight and [`MAX_CONNECTIONS`] TCP connections. Past
//! them, a query gets an immediate SERVFAIL and a connection is closed.
//!
//! What the server answers with, its [`Policy`], sits behind an `ArcSwap`:
//! a reload swaps in a new one without a lock or a pause, and each query
//! runs start to finish against the policy it began with.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use arc_swap::{ArcSwap, Guard};
use ipnet::IpNet;
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio::time::timeout;
use tracing::{debug, warn};

use crate::cache::AnswerCache;
use crate::engine::{Decision, Engine, Forward, Transport, question};
use crate::pause::Pause;
use crate::querylog::{Outcome, QueryLog};
use crate::upstream::Upstreams;
use crate::wire::{read_frame, write_frame};

/// Upstream queries in flight at once, across all clients.
pub const MAX_FORWARDS: usize = 1024;
/// TCP connections open at once.
pub const MAX_CONNECTIONS: usize = 256;
/// A TCP client must send each query, and accept each reply, within this
/// time, or the connection is closed (RFC 7766 §6.2.3).
const TCP_IDLE: Duration = Duration::from_secs(10);
/// Largest UDP query read. Real queries are far smaller.
const MAX_UDP_QUERY: usize = 4096;
/// Receive loops per UDP socket.
const MAX_UDP_WORKERS: usize = 4;
/// Kernel receive buffer asked for on UDP sockets, to ride out bursts.
const UDP_RECV_BUFFER: usize = 1 << 20;

/// Who may query: loopback always, other addresses only inside the
/// configured networks.
///
/// This holds whatever the sockets are bound to, so even a bind to `0.0.0.0`
/// with an empty allowlist answers only this machine. Config validation adds
/// a second guard by refusing such a config outright.
#[derive(Debug, Clone, Default)]
pub struct ClientFilter {
    networks: Vec<IpNet>,
}

impl ClientFilter {
    pub fn new(networks: Vec<IpNet>) -> Self {
        ClientFilter { networks }
    }

    pub fn allows(&self, ip: IpAddr) -> bool {
        // `::ffff:192.0.2.1` on a dual-stack socket is the IPv4 client.
        let ip = ip.to_canonical();
        ip.is_loopback() || self.networks.iter().any(|net| net.contains(&ip))
    }
}

/// What the server answers with: the rules, the upstreams, the answer
/// cache and who may ask. Replaced as a whole on reload, so no query sees
/// half of an update.
#[derive(Debug)]
pub struct Policy {
    pub engine: Engine,
    pub upstreams: Upstreams,
    pub cache: Arc<AnswerCache>,
    pub clients: ClientFilter,
    /// The query log. Like the cache, it outlives reloads.
    pub log: Arc<QueryLog>,
    /// Users (uids) who may pause, resume and read the query log through
    /// the control socket, besides root and the daemon's own user.
    pub control_users: Vec<u32>,
}

/// Swaps the [`Policy`] of a running [`Server`]. Clones share it.
#[derive(Debug, Clone)]
pub struct PolicyHandle(Arc<ArcSwap<Policy>>);

impl PolicyHandle {
    pub fn new(policy: Policy) -> Self {
        PolicyHandle(Arc::new(ArcSwap::from_pointee(policy)))
    }

    /// The policy in force now.
    pub fn load(&self) -> Arc<Policy> {
        self.0.load_full()
    }

    /// Puts `policy` in force for every query that starts from now on.
    pub fn store(&self, policy: Policy) {
        self.0.store(Arc::new(policy));
    }

    /// A cheap, short-lived borrow for the synchronous part of a query.
    fn guard(&self) -> Guard<Arc<Policy>> {
        self.0.load()
    }
}

/// Counters since start.
#[derive(Debug, Default)]
pub struct Stats {
    queries: AtomicU64,
    blocked: AtomicU64,
    uncloaked: AtomicU64,
    local: AtomicU64,
    cached: AtomicU64,
    forwarded: AtomicU64,
    stale: AtomicU64,
    upstream_failures: AtomicU64,
    errors: AtomicU64,
    refused_clients: AtomicU64,
    shed: AtomicU64,
}

/// A point-in-time copy of [`Stats`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub struct StatsSnapshot {
    /// Messages received from allowed clients.
    pub queries: u64,
    /// Answered with a block response because the name is listed.
    pub blocked: u64,
    /// Answered with a block response because a CNAME (or HTTPS/SVCB
    /// target) in the upstream's answer is listed.
    pub uncloaked: u64,
    /// Special names answered here: `localhost`, private reverse zones, the
    /// Firefox canary and the like.
    pub local: u64,
    /// Answered from the cache.
    pub cached: u64,
    /// Answered from an upstream.
    pub forwarded: u64,
    /// Answered from an expired cache entry because no upstream answered.
    pub stale: u64,
    /// Answered SERVFAIL because no upstream answered.
    pub upstream_failures: u64,
    /// Answered with FORMERR, NOTIMP, REFUSED or BADVERS.
    pub errors: u64,
    /// Packets and connections from clients outside the allowlist, dropped.
    pub refused_clients: u64,
    /// Answered SERVFAIL, or closed, because a load limit was reached.
    pub shed: u64,
}

impl Stats {
    pub fn snapshot(&self) -> StatsSnapshot {
        let get = |c: &AtomicU64| c.load(Ordering::Relaxed);
        StatsSnapshot {
            queries: get(&self.queries),
            blocked: get(&self.blocked),
            uncloaked: get(&self.uncloaked),
            local: get(&self.local),
            cached: get(&self.cached),
            forwarded: get(&self.forwarded),
            stale: get(&self.stale),
            upstream_failures: get(&self.upstream_failures),
            errors: get(&self.errors),
            refused_clients: get(&self.refused_clients),
            shed: get(&self.shed),
        }
    }
}

fn bump(counter: &AtomicU64) {
    counter.fetch_add(1, Ordering::Relaxed);
}

/// What every socket task shares.
struct Shared {
    policy: PolicyHandle,
    stats: Arc<Stats>,
    pause: Arc<Pause>,
    forwards: Arc<Semaphore>,
    connections: Arc<Semaphore>,
}

impl Shared {
    fn admits(&self, policy: &Policy, peer: SocketAddr) -> bool {
        let allowed = policy.clients.allows(peer.ip());
        if !allowed {
            bump(&self.stats.refused_clients);
            debug!(%peer, "dropped a client outside the allowlist");
        }
        allowed
    }

    fn decide(&self, policy: &Policy, packet: &[u8], transport: Transport) -> Decision {
        bump(&self.stats.queries);
        let decision = policy
            .engine
            .decide_as(packet, transport, self.pause.blocking());
        let outcome = match decision {
            Decision::Blocked(_) => {
                bump(&self.stats.blocked);
                Outcome::Blocked
            }
            Decision::Local(_) => {
                bump(&self.stats.local);
                Outcome::Local
            }
            Decision::Error(_) => {
                bump(&self.stats.errors);
                Outcome::Error
            }
            Decision::Drop | Decision::Forward(_) => return decision,
        };
        if policy.log.enabled()
            && let Some((name, qtype)) = question(packet)
        {
            let rule = match outcome {
                Outcome::Blocked => policy.engine.blocking_rule(&name),
                _ => None,
            };
            policy.log.record(&name, &qtype, outcome, rule.as_deref());
        }
        decision
    }

    /// Logs how a forwarded query was answered, if the log is on.
    fn log(&self, policy: &Policy, forward: &Forward, outcome: Outcome, rule: Option<&str>) {
        if policy.log.enabled() {
            let (name, qtype) = forward.describe();
            policy.log.record(&name, &qtype, outcome, rule);
        }
    }

    /// The reply from the cache, if there is a fresh answer. Synchronous
    /// and cheap, so it runs inline, without a task or a forwarding slot.
    fn cached(&self, policy: &Policy, forward: &Forward) -> Option<Vec<u8>> {
        let answer = policy.cache.fresh(&forward.cache_key()?)?;
        bump(&self.stats.cached);
        Some(self.finish(policy, forward, &answer, Outcome::Cached))
    }

    /// Resolves upstream, caching the answer. When no upstream answers, a
    /// stale cache entry if there is one, else SERVFAIL.
    async fn forward(&self, policy: &Policy, forward: &Forward) -> Vec<u8> {
        let key = forward.cache_key();
        match policy.upstreams.resolve(forward).await {
            Some(answer) => {
                bump(&self.stats.forwarded);
                if let Some(key) = key {
                    policy.cache.insert(key, &answer);
                }
                self.finish(policy, forward, &answer, Outcome::Forwarded)
            }
            None => match key.and_then(|key| policy.cache.stale(&key)) {
                Some(answer) => {
                    bump(&self.stats.stale);
                    self.finish(policy, forward, &answer, Outcome::Stale)
                }
                None => {
                    bump(&self.stats.upstream_failures);
                    self.log(policy, forward, Outcome::Failed, None);
                    forward.servfail()
                }
            },
        }
    }

    /// The reply for an answer: blocked if it is cloaked, else the answer.
    fn finish(
        &self,
        policy: &Policy,
        forward: &Forward,
        answer: &hickory_proto::op::Message,
        outcome: Outcome,
    ) -> Vec<u8> {
        // A pause that began after the query was decided still applies.
        let cloaked = if self.pause.blocking() {
            policy.engine.uncloak(forward, answer)
        } else {
            None
        };
        match cloaked {
            Some(blocked) => {
                bump(&self.stats.uncloaked);
                self.log(policy, forward, Outcome::Uncloaked, None);
                blocked
            }
            None => {
                self.log(policy, forward, outcome, None);
                forward.reply(answer.clone())
            }
        }
    }

    fn shed(&self, policy: &Policy, forward: &Forward) -> Vec<u8> {
        bump(&self.stats.shed);
        self.log(policy, forward, Outcome::Shed, None);
        forward.servfail()
    }
}

/// Bound sockets, ready to serve.
pub struct Server {
    udp: Vec<Arc<UdpSocket>>,
    tcp: Vec<TcpListener>,
    shared: Arc<Shared>,
}

/// Sockets bound before the server starts, by [`bind_sockets`] or by a
/// privileged parent that handed them over.
#[derive(Debug, Default)]
pub struct Sockets {
    pub udp: Vec<std::net::UdpSocket>,
    pub tcp: Vec<std::net::TcpListener>,
}

/// Binds UDP and TCP on each address, without a runtime. Port 0 picks a
/// free port, the same one for UDP and TCP.
pub fn bind_sockets(addrs: &[SocketAddr]) -> io::Result<Sockets> {
    let mut sockets = Sockets::default();
    for &addr in addrs {
        let socket = udp_socket(addr).map_err(|e| context(e, "UDP", addr))?;
        let addr = socket.local_addr()?;
        sockets
            .tcp
            .push(tcp_listener(addr).map_err(|e| context(e, "TCP", addr))?);
        sockets.udp.push(socket);
    }
    Ok(sockets)
}

impl Server {
    /// Binds UDP and TCP on each address. Port 0 picks a free port, the same
    /// one for UDP and TCP.
    pub async fn bind(policy: Policy, addrs: &[SocketAddr]) -> io::Result<Server> {
        Server::from_sockets(policy, bind_sockets(addrs)?)
    }

    /// Serves on sockets bound elsewhere. Must run inside a Tokio runtime.
    pub fn from_sockets(policy: Policy, sockets: Sockets) -> io::Result<Server> {
        let mut udp = Vec::new();
        for socket in sockets.udp {
            socket.set_nonblocking(true)?;
            udp.push(Arc::new(UdpSocket::from_std(socket)?));
        }
        let mut tcp = Vec::new();
        for listener in sockets.tcp {
            listener.set_nonblocking(true)?;
            tcp.push(TcpListener::from_std(listener)?);
        }
        Ok(Server {
            udp,
            tcp,
            shared: Arc::new(Shared {
                policy: PolicyHandle::new(policy),
                stats: Arc::default(),
                pause: Arc::default(),
                forwards: Arc::new(Semaphore::new(MAX_FORWARDS)),
                connections: Arc::new(Semaphore::new(MAX_CONNECTIONS)),
            }),
        })
    }

    /// The bound addresses, with real ports in place of 0.
    pub fn local_addrs(&self) -> Vec<SocketAddr> {
        self.udp
            .iter()
            .filter_map(|s| s.local_addr().ok())
            .collect()
    }

    pub fn stats(&self) -> Arc<Stats> {
        Arc::clone(&self.shared.stats)
    }

    /// Pauses and resumes blocking while the server runs.
    pub fn pause(&self) -> Arc<Pause> {
        Arc::clone(&self.shared.pause)
    }

    /// Replaces the policy while the server runs.
    pub fn policy(&self) -> PolicyHandle {
        self.shared.policy.clone()
    }

    /// Serves until dropped. Returns only if a socket task dies, which only a
    /// bug can cause; the service manager then restarts the daemon.
    pub async fn run(self) -> io::Result<()> {
        let workers = std::thread::available_parallelism()
            .map_or(1, |n| n.get())
            .min(MAX_UDP_WORKERS);
        let mut tasks = JoinSet::new();
        for socket in &self.udp {
            for _ in 0..workers {
                tasks.spawn(serve_udp(Arc::clone(socket), Arc::clone(&self.shared)));
            }
        }
        for listener in self.tcp {
            tasks.spawn(serve_tcp(listener, Arc::clone(&self.shared)));
        }
        match tasks.join_next().await {
            Some(Err(e)) => Err(io::Error::other(format!("a server task died: {e}"))),
            _ => Err(io::Error::other("a server task stopped")),
        }
    }
}

fn context(e: io::Error, what: &str, addr: SocketAddr) -> io::Error {
    io::Error::new(e.kind(), format!("binding {what} {addr}: {e}"))
}

fn udp_socket(addr: SocketAddr) -> io::Result<std::net::UdpSocket> {
    let socket = Socket::new(Domain::for_address(addr), Type::DGRAM, Some(Protocol::UDP))?;
    if addr.is_ipv6() {
        // Otherwise `[::]` would also claim IPv4 on Linux and collide with
        // a separate `0.0.0.0` entry.
        socket.set_only_v6(true)?;
    }
    if let Err(e) = socket.set_recv_buffer_size(UDP_RECV_BUFFER) {
        debug!(error = %e, "could not enlarge the UDP receive buffer");
    }
    socket.bind(&addr.into())?;
    Ok(socket.into())
}

fn tcp_listener(addr: SocketAddr) -> io::Result<std::net::TcpListener> {
    let socket = Socket::new(Domain::for_address(addr), Type::STREAM, Some(Protocol::TCP))?;
    if addr.is_ipv6() {
        socket.set_only_v6(true)?;
    }
    // A restarted daemon can rebind while old connections sit in TIME_WAIT.
    socket.set_reuse_address(true)?;
    socket.bind(&addr.into())?;
    socket.listen(1024)?;
    Ok(socket.into())
}

async fn serve_udp(socket: Arc<UdpSocket>, shared: Arc<Shared>) {
    let mut buf = vec![0; MAX_UDP_QUERY];
    loop {
        let (len, peer) = match socket.recv_from(&mut buf).await {
            Ok(received) => received,
            // Per-datagram errors (e.g. a reported ICMP error); keep serving.
            Err(e) => {
                debug!(error = %e, "UDP receive failed");
                continue;
            }
        };
        let Some(packet) = buf.get(..len) else {
            continue;
        };
        // The guard is dropped before the send below: it is meant for
        // short, synchronous use.
        let reply = {
            let policy = shared.policy.guard();
            if !shared.admits(&policy, peer) {
                continue;
            }
            match shared.decide(&policy, packet, Transport::Udp) {
                Decision::Drop => continue,
                Decision::Blocked(reply) | Decision::Local(reply) | Decision::Error(reply) => reply,
                Decision::Forward(forward) => {
                    if let Some(reply) = shared.cached(&policy, &forward) {
                        reply
                    } else {
                        match Arc::clone(&shared.forwards).try_acquire_owned() {
                            Ok(permit) => {
                                let policy = Guard::into_inner(policy);
                                let (socket, shared) = (Arc::clone(&socket), Arc::clone(&shared));
                                tokio::spawn(async move {
                                    let reply = shared.forward(&policy, &forward).await;
                                    send_udp(&socket, &reply, peer).await;
                                    drop(permit);
                                });
                                continue;
                            }
                            Err(_) => shared.shed(&policy, &forward),
                        }
                    }
                }
            }
        };
        send_udp(&socket, &reply, peer).await;
    }
}

async fn send_udp(socket: &UdpSocket, reply: &[u8], peer: SocketAddr) {
    if let Err(e) = socket.send_to(reply, peer).await {
        debug!(%peer, error = %e, "UDP send failed");
    }
}

async fn serve_tcp(listener: TcpListener, shared: Arc<Shared>) {
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(e) => {
                // Usually out of file descriptors. Back off instead of
                // spinning; existing connections will free some.
                warn!(error = %e, "TCP accept failed");
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
        };
        if !shared.admits(&shared.policy.guard(), peer) {
            continue;
        }
        let Ok(permit) = Arc::clone(&shared.connections).try_acquire_owned() else {
            bump(&shared.stats.shed);
            continue;
        };
        let shared = Arc::clone(&shared);
        tokio::spawn(async move {
            serve_connection(stream, &shared).await;
            drop(permit);
        });
    }
}

async fn serve_connection(mut stream: TcpStream, shared: &Shared) {
    if let Err(e) = stream.set_nodelay(true) {
        debug!(error = %e, "could not set TCP_NODELAY");
    }
    loop {
        let Ok(Ok(query)) = timeout(TCP_IDLE, read_frame(&mut stream)).await else {
            return;
        };
        let policy = shared.policy.load();
        let reply = match shared.decide(&policy, &query, Transport::Tcp) {
            Decision::Drop => return,
            Decision::Blocked(reply) | Decision::Local(reply) | Decision::Error(reply) => reply,
            Decision::Forward(forward) => match shared.cached(&policy, &forward) {
                Some(reply) => reply,
                None => match shared.forwards.try_acquire() {
                    Ok(_permit) => shared.forward(&policy, &forward).await,
                    Err(_) => shared.shed(&policy, &forward),
                },
            },
        };
        if !matches!(
            timeout(TCP_IDLE, write_frame(&mut stream, &reply)).await,
            Ok(Ok(()))
        ) {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_filter() {
        let open = ClientFilter::default();
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        assert!(open.allows(ip("127.0.0.1")));
        assert!(open.allows(ip("127.8.9.10")));
        assert!(open.allows(ip("::1")));
        assert!(open.allows(ip("::ffff:127.0.0.1")));
        assert!(!open.allows(ip("192.168.1.5")));
        assert!(!open.allows(ip("::ffff:192.168.1.5")));
        assert!(!open.allows(ip("fe80::1")));

        let lan = ClientFilter::new(vec!["192.168.1.0/24".parse().unwrap()]);
        assert!(lan.allows(ip("192.168.1.5")));
        assert!(lan.allows(ip("::ffff:192.168.1.5")));
        assert!(!lan.allows(ip("192.168.2.5")));
        assert!(lan.allows(ip("::1")));
    }
}
