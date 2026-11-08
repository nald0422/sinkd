//! End-to-end tests: a real server on a random loopback port, forwarding to
//! a scripted upstream on another one. Nothing leaves the machine.
#![allow(clippy::unwrap_used)]

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use hickory_proto::op::{Edns, Message, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::opt::{ClientSubnet, EdnsOption};
use hickory_proto::rr::rdata::{A, AAAA, TXT};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use sinkd_core::config::{BlockResponse, Blocking};
use sinkd_core::{Domain, DomainMatcher, Scope};
use sinkd_resolver::{AnswerCache, ClientFilter, Engine, Policy, Server, Stats, Upstreams};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

const UPSTREAM_A: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
const SPOOFED_A: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 66);

#[derive(Clone, Copy, PartialEq)]
enum Behavior {
    Answer,
    /// Receives and never answers.
    Silent,
    ServFail,
    /// Sends a forged answer with the wrong ID before the real one.
    SpoofFirst,
}

/// A scripted upstream resolver. Answers A/AAAA for any name, NXDOMAIN for
/// `nxdomain.test`, and a ~3 KB TXT set for `big.test` (truncated over UDP).
struct Upstream {
    addr: SocketAddr,
    seen: Arc<Mutex<Vec<Message>>>,
}

impl Upstream {
    async fn start(behavior: Behavior) -> Upstream {
        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = udp.local_addr().unwrap();
        let tcp = TcpListener::bind(addr).await.unwrap();
        let seen = Arc::new(Mutex::new(Vec::new()));

        let log = Arc::clone(&seen);
        tokio::spawn(async move {
            let mut buf = vec![0; 4096];
            loop {
                let (len, peer) = udp.recv_from(&mut buf).await.unwrap();
                let query = Message::from_vec(&buf[..len]).unwrap();
                log.lock().unwrap().push(query.clone());
                for reply in answers(&query, behavior, true) {
                    udp.send_to(&reply, peer).await.unwrap();
                }
            }
        });
        let log = Arc::clone(&seen);
        tokio::spawn(async move {
            loop {
                let (mut stream, _) = tcp.accept().await.unwrap();
                let log = Arc::clone(&log);
                tokio::spawn(async move {
                    while let Ok(frame) = read_frame(&mut stream).await {
                        let query = Message::from_vec(&frame).unwrap();
                        log.lock().unwrap().push(query.clone());
                        for reply in answers(&query, behavior, false) {
                            write_frame(&mut stream, &reply).await.unwrap();
                        }
                    }
                });
            }
        });
        Upstream { addr, seen }
    }

    fn seen(&self) -> Vec<Message> {
        self.seen.lock().unwrap().clone()
    }
}

fn answers(query: &Message, behavior: Behavior, udp: bool) -> Vec<Vec<u8>> {
    let q = query.queries[0].clone();
    let mut r = Message::response(query.metadata.id, OpCode::Query);
    r.metadata.recursion_desired = query.metadata.recursion_desired;
    r.metadata.recursion_available = true;
    r.add_query(q.clone());
    if query.edns.is_some() {
        let mut edns = Edns::new();
        edns.set_max_payload(1232);
        r.set_edns(edns);
    }
    let name = q.name().to_ascii().to_ascii_lowercase();
    let record = |rdata| Record::from_rdata(q.name().clone(), 300, rdata);
    match (behavior, name.as_str(), q.query_type()) {
        (Behavior::Silent, ..) => return Vec::new(),
        (Behavior::ServFail, ..) => r.metadata.response_code = ResponseCode::ServFail,
        (_, "nxdomain.test.", _) => r.metadata.response_code = ResponseCode::NXDomain,
        (_, "big.test.", _) if udp => r.metadata.truncation = true,
        (_, "big.test.", _) => {
            for i in 0..12 {
                let text = format!("{i:02}{}", "x".repeat(250));
                r.add_answer(record(RData::TXT(TXT::new(vec![text]))));
            }
        }
        (_, _, RecordType::A) => {
            r.add_answer(record(RData::A(A(UPSTREAM_A))));
        }
        (_, _, RecordType::AAAA) => {
            r.add_answer(record(RData::AAAA(AAAA("2001:db8::1".parse().unwrap()))));
        }
        _ => {}
    }
    let mut out = Vec::new();
    if behavior == Behavior::SpoofFirst {
        let mut forged = r.clone();
        forged.metadata.id = query.metadata.id.wrapping_add(1);
        forged.answers = vec![record(RData::A(A(SPOOFED_A)))];
        out.push(forged.to_vec().unwrap());
    }
    out.push(r.to_vec().unwrap());
    out
}

async fn read_frame(stream: &mut TcpStream) -> std::io::Result<Vec<u8>> {
    let len = stream.read_u16().await?;
    let mut buf = vec![0; usize::from(len)];
    stream.read_exact(&mut buf).await?;
    Ok(buf)
}

async fn write_frame(stream: &mut TcpStream, msg: &[u8]) -> std::io::Result<()> {
    let mut frame = (msg.len() as u16).to_be_bytes().to_vec();
    frame.extend_from_slice(msg);
    stream.write_all(&frame).await
}

struct Running {
    addr: SocketAddr,
    stats: Arc<Stats>,
}

/// Blocks `ads.test` and below, except `ok.ads.test`.
async fn start(upstreams: &[SocketAddr], timeout: Duration, response: BlockResponse) -> Running {
    let mut b = DomainMatcher::builder();
    b.block(&Domain::parse("ads.test").unwrap(), Scope::Subtree)
        .unwrap();
    b.allow(&Domain::parse("ok.ads.test").unwrap(), Scope::Subtree)
        .unwrap();
    let blocking = Blocking {
        response,
        ..Blocking::default()
    };
    let policy = Policy {
        engine: Engine::new(b.build(), blocking),
        upstreams: Upstreams::new(upstreams.to_vec(), timeout),
        // These tests count what reaches the upstream; caching has its own.
        cache: Arc::new(AnswerCache::disabled()),
        clients: ClientFilter::default(),
        log: Arc::default(),
        control_users: Vec::new(),
    };
    let server = Server::bind(policy, &["127.0.0.1:0".parse().unwrap()])
        .await
        .unwrap();
    let addr = server.local_addrs()[0];
    let stats = server.stats();
    tokio::spawn(server.run());
    Running { addr, stats }
}

async fn start_default(upstream: &Upstream) -> Running {
    start(
        &[upstream.addr],
        Duration::from_secs(2),
        BlockResponse::NullAddress,
    )
    .await
}

fn query(name: &str, rtype: RecordType) -> Message {
    let mut m = Message::query();
    m.metadata.recursion_desired = true;
    m.add_query(Query::query(Name::from_ascii(name).unwrap(), rtype));
    m
}

async fn ask_udp(server: SocketAddr, query: &Message) -> Message {
    try_udp(server, &query.to_vec().unwrap(), Duration::from_secs(5))
        .await
        .expect("no UDP reply")
}

async fn try_udp(server: SocketAddr, bytes: &[u8], wait: Duration) -> Option<Message> {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    socket.connect(server).await.unwrap();
    socket.send(bytes).await.unwrap();
    let mut buf = vec![0; 65535];
    let len = tokio::time::timeout(wait, socket.recv(&mut buf))
        .await
        .ok()?
        .unwrap();
    Some(Message::from_vec(&buf[..len]).unwrap())
}

async fn ask_tcp(server: SocketAddr, query: &Message) -> Message {
    let mut stream = TcpStream::connect(server).await.unwrap();
    write_frame(&mut stream, &query.to_vec().unwrap())
        .await
        .unwrap();
    let frame = tokio::time::timeout(Duration::from_secs(5), read_frame(&mut stream))
        .await
        .unwrap()
        .unwrap();
    Message::from_vec(&frame).unwrap()
}

fn first_a(m: &Message) -> Option<Ipv4Addr> {
    m.answers.iter().find_map(|r| match r.data {
        RData::A(A(ip)) => Some(ip),
        _ => None,
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn blocked_names_are_answered_locally() {
    let upstream = Upstream::start(Behavior::Answer).await;
    let s = start_default(&upstream).await;

    let r = ask_udp(s.addr, &query("ads.test.", RecordType::A)).await;
    assert_eq!(r.metadata.response_code, ResponseCode::NoError);
    assert_eq!(first_a(&r), Some(Ipv4Addr::UNSPECIFIED));
    assert_eq!(r.answers[0].ttl, 10);

    let r = ask_udp(s.addr, &query("x.y.ADS.test.", RecordType::AAAA)).await;
    assert_eq!(r.answers[0].data, RData::AAAA(AAAA(Ipv6Addr::UNSPECIFIED)));

    // HTTPS records (type 65) of blocked names: NODATA with a cacheable SOA.
    let r = ask_udp(s.addr, &query("cdn.ads.test.", RecordType::HTTPS)).await;
    assert_eq!(r.metadata.response_code, ResponseCode::NoError);
    assert!(r.answers.is_empty());
    assert_eq!(r.authorities[0].record_type(), RecordType::SOA);

    assert!(
        upstream.seen().is_empty(),
        "blocked names must not reach the upstream"
    );
    let stats = s.stats.snapshot();
    assert_eq!((stats.queries, stats.blocked, stats.forwarded), (3, 3, 0));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn nxdomain_block_mode() {
    let upstream = Upstream::start(Behavior::Answer).await;
    let s = start(
        &[upstream.addr],
        Duration::from_secs(2),
        BlockResponse::Nxdomain,
    )
    .await;
    let r = ask_udp(s.addr, &query("ads.test.", RecordType::A)).await;
    assert_eq!(r.metadata.response_code, ResponseCode::NXDomain);
    assert!(r.answers.is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn allowed_and_unlisted_names_are_forwarded() {
    let upstream = Upstream::start(Behavior::Answer).await;
    let s = start_default(&upstream).await;

    let q = query("ok.ads.test.", RecordType::A);
    let r = ask_udp(s.addr, &q).await;
    assert_eq!(
        first_a(&r),
        Some(UPSTREAM_A),
        "the allowlist beats the blocked parent"
    );
    assert_eq!(r.metadata.id, q.metadata.id);
    assert!(r.metadata.recursion_available);

    // The client's spelling survives the round trip (0x20 randomization).
    let q = query("ExAmple.TEST.", RecordType::A);
    let r = ask_udp(s.addr, &q).await;
    assert_eq!(first_a(&r), Some(UPSTREAM_A));
    assert!(r.queries[0].name().eq_case(q.queries[0].name()));

    let seen = upstream.seen();
    assert_eq!(seen.len(), 2);
    assert!(
        seen.iter().all(|m| m.edns.is_some()),
        "upstream queries use EDNS"
    );

    let r = ask_udp(s.addr, &query("nxdomain.test.", RecordType::A)).await;
    assert_eq!(r.metadata.response_code, ResponseCode::NXDomain);
    assert_eq!(s.stats.snapshot().forwarded, 3);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tcp_queries() {
    let upstream = Upstream::start(Behavior::Answer).await;
    let s = start_default(&upstream).await;
    let r = ask_tcp(s.addr, &query("ads.test.", RecordType::A)).await;
    assert_eq!(first_a(&r), Some(Ipv4Addr::UNSPECIFIED));
    let r = ask_tcp(s.addr, &query("example.test.", RecordType::A)).await;
    assert_eq!(first_a(&r), Some(UPSTREAM_A));

    // Several queries on one connection.
    let mut stream = TcpStream::connect(s.addr).await.unwrap();
    for name in ["a.test.", "ads.test.", "b.test."] {
        let q = query(name, RecordType::A);
        write_frame(&mut stream, &q.to_vec().unwrap())
            .await
            .unwrap();
        let r = Message::from_vec(&read_frame(&mut stream).await.unwrap()).unwrap();
        assert_eq!(r.metadata.id, q.metadata.id);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn truncation_and_tcp_fallback() {
    let upstream = Upstream::start(Behavior::Answer).await;
    let s = start_default(&upstream).await;

    // The upstream truncates over UDP; the resolver retries it over TCP and
    // gets all 12 records. A TCP client receives them all.
    let r = ask_tcp(s.addr, &query("big.test.", RecordType::TXT)).await;
    assert!(!r.metadata.truncation);
    assert_eq!(r.answers.len(), 12);
    let seen = upstream.seen();
    assert_eq!(seen.len(), 2, "one UDP attempt, one TCP retry");

    // A UDP client gets TC and no records: ~3 KB does not fit in 1232 bytes.
    let mut q = query("big.test.", RecordType::TXT);
    q.set_edns(Edns::new());
    q.edns.as_mut().unwrap().set_max_payload(4096);
    let r = ask_udp(s.addr, &q).await;
    assert!(r.metadata.truncation);
    assert!(r.answers.is_empty());
    assert_eq!(r.edns.as_ref().unwrap().max_payload(), 1232);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn edns_is_hop_by_hop() {
    let upstream = Upstream::start(Behavior::Answer).await;
    let s = start_default(&upstream).await;

    let mut q = query("example.test.", RecordType::A);
    let mut edns = Edns::new();
    edns.set_max_payload(4096);
    edns.set_dnssec_ok(true);
    edns.options_mut()
        .insert(EdnsOption::Subnet(ClientSubnet::new(
            "198.51.100.0".parse().unwrap(),
            24,
            0,
        )));
    q.set_edns(edns);
    let r = ask_udp(s.addr, &q).await;
    let reply_edns = r.edns.as_ref().expect("an EDNS query gets an EDNS reply");
    assert_eq!(reply_edns.max_payload(), 1232);
    assert!(reply_edns.flags().dnssec_ok);

    let sent = &upstream.seen()[0];
    let sent_edns = sent.edns.as_ref().unwrap();
    assert!(sent_edns.flags().dnssec_ok, "DO is passed on");
    assert!(
        sent_edns.options().options.is_empty(),
        "client subnet is not"
    );

    // No EDNS in, no EDNS out.
    let r = ask_udp(s.addr, &query("example.test.", RecordType::A)).await;
    assert!(r.edns.is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dead_upstream_fails_fast() {
    // A port with nothing behind it: the kernel answers "port unreachable".
    let dead = {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        socket.local_addr().unwrap()
    };
    let s = start(&[dead], Duration::from_secs(2), BlockResponse::NullAddress).await;
    let started = Instant::now();
    let r = ask_udp(s.addr, &query("example.test.", RecordType::A)).await;
    assert_eq!(r.metadata.response_code, ResponseCode::ServFail);
    assert!(
        started.elapsed() < Duration::from_millis(500),
        "took {:?}",
        started.elapsed()
    );
    assert_eq!(s.stats.snapshot().upstream_failures, 1);

    // Blocking keeps working with no upstream at all.
    let r = ask_udp(s.addr, &query("ads.test.", RecordType::A)).await;
    assert_eq!(first_a(&r), Some(Ipv4Addr::UNSPECIFIED));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn silent_upstream_times_out_to_servfail() {
    let silent = Upstream::start(Behavior::Silent).await;
    let s = start(
        &[silent.addr],
        Duration::from_millis(200),
        BlockResponse::NullAddress,
    )
    .await;
    let started = Instant::now();
    let r = ask_udp(s.addr, &query("example.test.", RecordType::A)).await;
    let took = started.elapsed();
    assert_eq!(r.metadata.response_code, ResponseCode::ServFail);
    assert!(
        took >= Duration::from_millis(190) && took < Duration::from_secs(1),
        "took {took:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn failover_to_the_next_upstream() {
    let silent = Upstream::start(Behavior::Silent).await;
    let broken = Upstream::start(Behavior::ServFail).await;
    let good = Upstream::start(Behavior::Answer).await;
    let s = start(
        &[silent.addr, broken.addr, good.addr],
        Duration::from_millis(200),
        BlockResponse::NullAddress,
    )
    .await;
    let r = ask_udp(s.addr, &query("example.test.", RecordType::A)).await;
    assert_eq!(first_a(&r), Some(UPSTREAM_A));
    assert_eq!(silent.seen().len(), 1);
    assert_eq!(broken.seen().len(), 1);
    assert_eq!(good.seen().len(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn forged_upstream_answers_are_ignored() {
    let upstream = Upstream::start(Behavior::SpoofFirst).await;
    let s = start_default(&upstream).await;
    let r = ask_udp(s.addr, &query("example.test.", RecordType::A)).await;
    assert_eq!(first_a(&r), Some(UPSTREAM_A));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn malformed_queries() {
    let upstream = Upstream::start(Behavior::Answer).await;
    let s = start_default(&upstream).await;
    let quiet = Duration::from_millis(300);

    // Header, then garbage: FORMERR with the same ID.
    let mut garbage = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    garbage.extend_from_slice(b"\xff\xff\xff");
    let r = try_udp(s.addr, &garbage, quiet)
        .await
        .expect("FORMERR expected");
    assert_eq!(
        (r.metadata.id, r.metadata.response_code),
        (0x1234, ResponseCode::FormErr)
    );

    // Too short to answer, and responses: silence.
    assert!(try_udp(s.addr, &[1, 2, 3], quiet).await.is_none());
    let mut response = query("example.test.", RecordType::A);
    response.metadata.message_type = hickory_proto::op::MessageType::Response;
    assert!(
        try_udp(s.addr, &response.to_vec().unwrap(), quiet)
            .await
            .is_none()
    );

    // The server is still healthy.
    let r = ask_udp(s.addr, &query("ads.test.", RecordType::A)).await;
    assert_eq!(first_a(&r), Some(Ipv4Addr::UNSPECIFIED));
    assert!(upstream.seen().is_empty());
    assert_eq!(s.stats.snapshot().errors, 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn idle_tcp_connections_do_not_block_others() {
    let upstream = Upstream::start(Behavior::Answer).await;
    let s = start_default(&upstream).await;
    // A connection that sends half a length prefix and stalls.
    let mut stalled = TcpStream::connect(s.addr).await.unwrap();
    stalled.write_all(&[0]).await.unwrap();
    let r = ask_tcp(s.addr, &query("ads.test.", RecordType::A)).await;
    assert_eq!(first_a(&r), Some(Ipv4Addr::UNSPECIFIED));
}
