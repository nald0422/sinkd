//! Encrypted upstreams and failover, against local DoH and DoT servers
//! behind a throwaway CA.
#![allow(clippy::unwrap_used)]

mod support;

use std::net::{Ipv4Addr, SocketAddr};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use hickory_proto::op::{Message, Query, ResponseCode};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{Name, RData, RecordType};
use sinkd_core::config::Config;
use sinkd_lists::Cache;
use sinkd_resolver::{Roots, Server, Stats, from_config_with_roots};
use support::{DohMode, DohServer, DotServer, ca};
use tokio::net::UdpSocket;

struct Sinkd {
    addr: SocketAddr,
    stats: Arc<Stats>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Sinkd {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn trust(ca: &sinkd_lists::testing::TestCa) -> Roots {
    Roots::Only(Arc::new(vec![ca.ca_der()]))
}

/// A sinkhole with these upstreams and no cache, so every query reaches
/// an upstream.
async fn start(upstreams: &str, roots: Roots, timeout: Option<Duration>) -> Sinkd {
    let config = Config::from_toml(&format!(
        "[listen]\naddrs = [\"127.0.0.1:0\"]\n[cache]\nmax_entries = 0\n{upstreams}"
    ))
    .unwrap();
    let mut setup =
        from_config_with_roots(&config, Path::new("."), &Cache::new("/nonexistent"), &roots)
            .unwrap();
    if let Some(timeout) = timeout {
        setup.upstreams = setup.upstreams.with_timeout(timeout);
    }
    let server = Server::bind(setup.policy(), &config.listen.addrs)
        .await
        .unwrap();
    let addr = server.local_addrs()[0];
    let stats = server.stats();
    let task = tokio::spawn(async move {
        let _ = server.run().await;
    });
    Sinkd { addr, stats, task }
}

async fn ask(s: &Sinkd, name: &str, rtype: RecordType) -> Message {
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    socket.connect(s.addr).await.unwrap();
    let mut q = Message::query();
    q.metadata.recursion_desired = true;
    q.add_query(Query::query(Name::from_ascii(name).unwrap(), rtype));
    socket.send(&q.to_vec().unwrap()).await.unwrap();
    let mut buf = vec![0; 4096];
    let len = tokio::time::timeout(Duration::from_secs(8), socket.recv(&mut buf))
        .await
        .unwrap()
        .unwrap();
    let reply = Message::from_vec(&buf[..len]).unwrap();
    assert_eq!(reply.metadata.id, q.metadata.id);
    reply
}

fn address(m: &Message) -> Option<Ipv4Addr> {
    m.answers.iter().find_map(|r| match r.data {
        RData::A(A(ip)) => Some(ip),
        _ => None,
    })
}

#[tokio::test]
async fn doh_queries_are_padded_with_id_zero_over_one_http2_connection() {
    let ca = ca();
    let doh = DohServer::start(&ca).await;
    let s = start(&doh.upstream_toml(), trust(&ca), None).await;
    for i in 0..10 {
        let r = ask(&s, &format!("host{i}.example."), RecordType::A).await;
        assert_eq!(address(&r), Some(Ipv4Addr::new(192, 0, 2, 1)));
    }
    let seen = doh.log.all();
    assert_eq!(seen.len(), 10);
    for q in &seen {
        assert_eq!(q.id, 0, "RFC 8484 §4.1");
        assert!(q.padded && q.len % 128 == 0, "padded to 128: {q:?}");
    }
    assert_eq!(
        doh.connections.load(Ordering::SeqCst),
        1,
        "one connection, reused"
    );
    assert!(doh.versions.lock().unwrap().iter().all(|v| v == "HTTP/2.0"));
    assert_eq!(s.stats.snapshot().forwarded, 10);
}

#[tokio::test]
async fn doh_errors_fail_over_to_the_next_upstream() {
    let ca = ca();
    for mode in [DohMode::Status(503), DohMode::ContentType("text/html")] {
        let doh = DohServer::start(&ca).await;
        let dot = DotServer::start(&ca, None).await;
        doh.set_mode(mode.clone());
        let s = start(
            &format!("{}{}", doh.upstream_toml(), dot.upstream_toml()),
            trust(&ca),
            None,
        )
        .await;
        let r = ask(&s, "a.example.", RecordType::A).await;
        assert_eq!(address(&r), Some(Ipv4Addr::new(192, 0, 2, 1)), "{mode:?}");
        assert_eq!(doh.log.count("a.example."), 1, "{mode:?}");
        assert_eq!(dot.log.count("a.example."), 1, "{mode:?}");
        // DoH is paused now: the next query goes straight to DoT.
        ask(&s, "b.example.", RecordType::A).await;
        assert_eq!(doh.log.count("b.example."), 0, "{mode:?}");
    }
}

#[tokio::test]
async fn untrusted_certificates_are_refused() {
    let ca = ca();
    let doh = DohServer::start(&ca).await;
    // The system's roots do not include the throwaway CA.
    let s = start(&doh.upstream_toml(), Roots::System, None).await;
    let r = ask(&s, "a.example.", RecordType::A).await;
    assert_eq!(r.metadata.response_code, ResponseCode::ServFail);
    assert!(
        doh.log.all().is_empty(),
        "nothing sent before the handshake"
    );
    assert_eq!(s.stats.snapshot().upstream_failures, 1);
}

#[tokio::test]
async fn dot_pipelines_queries_on_one_connection() {
    let ca = ca();
    let dot = DotServer::start(&ca, None).await;
    let s = Arc::new(start(&dot.upstream_toml(), trust(&ca), None).await);
    // Warm the connection, then send a slow query and 20 fast ones at once.
    ask(&s, "warm.example.", RecordType::A).await;
    let slow = {
        let s = Arc::clone(&s);
        tokio::spawn(async move {
            let started = Instant::now();
            let r = ask(&s, "slow.test.", RecordType::A).await;
            (address(&r), started.elapsed())
        })
    };
    tokio::time::sleep(Duration::from_millis(20)).await;
    let started = Instant::now();
    let fast: Vec<_> = (0..20)
        .map(|i| {
            let s = Arc::clone(&s);
            tokio::spawn(async move {
                address(&ask(&s, &format!("f{i}.example."), RecordType::A).await)
            })
        })
        .collect();
    for f in fast {
        assert_eq!(f.await.unwrap(), Some(Ipv4Addr::new(192, 0, 2, 1)));
    }
    let fast_elapsed = started.elapsed();
    let (slow_answer, slow_elapsed) = slow.await.unwrap();
    assert_eq!(slow_answer, Some(Ipv4Addr::new(192, 0, 2, 1)));
    assert!(
        fast_elapsed < slow_elapsed,
        "answers overtook the slow one: fast {fast_elapsed:?}, slow {slow_elapsed:?}"
    );
    assert_eq!(dot.connections.load(Ordering::SeqCst), 1);
    assert_eq!(dot.log.all().len(), 22);
}

#[tokio::test]
async fn dot_reconnects_when_the_server_hangs_up() {
    let ca = ca();
    let dot = DotServer::start(&ca, Some(2)).await;
    let s = start(&dot.upstream_toml(), trust(&ca), None).await;
    for i in 0..6 {
        let r = ask(&s, &format!("q{i}.example."), RecordType::A).await;
        assert_eq!(address(&r), Some(Ipv4Addr::new(192, 0, 2, 1)), "query {i}");
    }
    assert!(dot.connections.load(Ordering::SeqCst) >= 3);
    assert_eq!(s.stats.snapshot().upstream_failures, 0);
}

/// A plain UDP upstream that can be switched between silent and answering,
/// counting what it receives.
struct Switchable {
    addr: SocketAddr,
    answering: Arc<AtomicBool>,
    received: Arc<AtomicUsize>,
    names: Arc<std::sync::Mutex<Vec<String>>>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Switchable {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Switchable {
    async fn start() -> Switchable {
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = socket.local_addr().unwrap();
        let answering = Arc::new(AtomicBool::new(false));
        let received = Arc::new(AtomicUsize::new(0));
        let names = Arc::new(std::sync::Mutex::new(Vec::new()));
        let task = tokio::spawn({
            let (answering, received, names) = (
                Arc::clone(&answering),
                Arc::clone(&received),
                Arc::clone(&names),
            );
            async move {
                let mut buf = vec![0; 4096];
                while let Ok((len, peer)) = socket.recv_from(&mut buf).await {
                    received.fetch_add(1, Ordering::SeqCst);
                    let Ok(query) = Message::from_vec(&buf[..len]) else {
                        continue;
                    };
                    if let Some(q) = query.queries.first() {
                        names.lock().unwrap().push(q.name().to_ascii());
                    }
                    if answering.load(Ordering::SeqCst) {
                        let reply = support::answer(&query).to_vec().unwrap();
                        let _ = socket.send_to(&reply, peer).await;
                    }
                }
            }
        });
        Switchable {
            addr,
            answering,
            received,
            names,
            task,
        }
    }
}

#[tokio::test]
async fn a_dead_upstream_costs_one_timeout_and_is_probed_in_the_background() {
    let ca = ca();
    let doh = DohServer::start(&ca).await;
    let first = Switchable::start().await;
    let s = start(
        &format!(
            "[[upstream]]\nprotocol = \"udp\"\naddr = \"{}\"\n{}",
            first.addr,
            doh.upstream_toml()
        ),
        trust(&ca),
        Some(Duration::from_millis(300)),
    )
    .await;

    // The first query discovers the silent upstream and pays its timeout.
    let started = Instant::now();
    let r = ask(&s, "first.example.", RecordType::A).await;
    assert_eq!(address(&r), Some(Ipv4Addr::new(192, 0, 2, 1)));
    assert!(started.elapsed() >= Duration::from_millis(300));

    // After that, no query waits on it, even after its pause ends: it is
    // probed in the background instead.
    let until = Instant::now() + Duration::from_millis(1500);
    let mut i = 0;
    while Instant::now() < until {
        let started = Instant::now();
        ask(&s, &format!("next{i}.example."), RecordType::A).await;
        assert!(
            started.elapsed() < Duration::from_millis(200),
            "{:?}",
            started.elapsed()
        );
        i += 1;
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        first.received.load(Ordering::SeqCst) >= 2,
        "probed after the pause"
    );

    // Once it answers a probe, it is first in line again.
    first.answering.store(true, Ordering::SeqCst);
    let deadline = Instant::now() + Duration::from_secs(8);
    loop {
        let name = format!("back{i}.example.");
        ask(&s, &name, RecordType::A).await;
        if doh.log.count(&name.to_lowercase()) == 0 {
            break;
        }
        assert!(Instant::now() < deadline, "the upstream never came back");
        i += 1;
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        first
            .names
            .lock()
            .unwrap()
            .iter()
            .any(|n| n.starts_with("back"))
    );
}

#[tokio::test]
async fn servfail_moves_on_without_pausing_the_upstream() {
    let ca = ca();
    let doh = DohServer::start(&ca).await;
    let dot = DotServer::start(&ca, None).await;
    let s = start(
        &format!("{}{}", doh.upstream_toml(), dot.upstream_toml()),
        trust(&ca),
        None,
    )
    .await;
    let r = ask(&s, "fail.test.", RecordType::A).await;
    assert_eq!(r.metadata.response_code, ResponseCode::ServFail);
    assert_eq!(
        (doh.log.count("fail.test."), dot.log.count("fail.test.")),
        (1, 1)
    );
    // DoH is still first in line.
    ask(&s, "after.example.", RecordType::A).await;
    assert_eq!(doh.log.count("after.example."), 1);
    assert_eq!(dot.log.count("after.example."), 0);
}

#[tokio::test]
async fn every_upstream_down_gives_a_prompt_servfail() {
    let silent_a = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let silent_b = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let toml = format!(
        "[[upstream]]\nprotocol = \"udp\"\naddr = \"{}\"\n[[upstream]]\nprotocol = \"udp\"\naddr = \"{}\"\n",
        silent_a.local_addr().unwrap(),
        silent_b.local_addr().unwrap()
    );
    let s = start(&toml, Roots::System, None).await;
    let started = Instant::now();
    let r = ask(&s, "a.example.", RecordType::A).await;
    assert_eq!(r.metadata.response_code, ResponseCode::ServFail);
    // Two 2 s attempts, inside the 4.5 s deadline and the client's 5 s.
    assert!(
        started.elapsed() < Duration::from_millis(4600),
        "{:?}",
        started.elapsed()
    );
}
