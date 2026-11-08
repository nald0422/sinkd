//! What clients get back: cached answers, negative caching, stale answers,
//! CNAME uncloaking, HTTPS/SVCB (type 65) and special names. The upstream is
//! a local DoH server, as in the default config.
#![allow(clippy::unwrap_used)]

mod support;

use std::net::{Ipv4Addr, SocketAddr};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use hickory_proto::op::{Message, Query, ResponseCode};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{Name, RData, RecordType};
use sinkd_core::config::Config;
use sinkd_lists::Cache;
use sinkd_resolver::{
    Policy, PolicyHandle, Roots, STALE_TTL, Server, Stats, from_config_with_roots,
};
use support::{DohMode, DohServer, ca};
use tokio::net::UdpSocket;

struct Sinkd {
    addr: SocketAddr,
    stats: Arc<Stats>,
    policy: PolicyHandle,
    roots: Roots,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Sinkd {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn config(doh: &DohServer, top: &str) -> Config {
    Config::from_toml(&format!(
        "{top}\n[listen]\naddrs = [\"127.0.0.1:0\"]\n{}",
        doh.upstream_toml()
    ))
    .unwrap()
}

/// `top` holds top-level config keys, e.g. `block = [...]`.
async fn start(doh: &DohServer, ca: &sinkd_lists::testing::TestCa, top: &str) -> Sinkd {
    let config = config(doh, top);
    let roots = Roots::Only(Arc::new(vec![ca.ca_der()]));
    let setup =
        from_config_with_roots(&config, Path::new("."), &Cache::new("/nonexistent"), &roots)
            .unwrap();
    let server = Server::bind(setup.policy(), &config.listen.addrs)
        .await
        .unwrap();
    let addr = server.local_addrs()[0];
    let (stats, policy) = (server.stats(), server.policy());
    let task = tokio::spawn(async move {
        let _ = server.run().await;
    });
    Sinkd {
        addr,
        stats,
        policy,
        roots,
        task,
    }
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
    Message::from_vec(&buf[..len]).unwrap()
}

fn address(m: &Message) -> Option<Ipv4Addr> {
    m.answers.iter().find_map(|r| match r.data {
        RData::A(A(ip)) => Some(ip),
        _ => None,
    })
}

#[tokio::test]
async fn answers_are_cached_with_counting_down_ttls() {
    let ca = ca();
    let doh = DohServer::start(&ca).await;
    let s = start(&doh, &ca, "").await;
    let first = ask(&s, "www.example.", RecordType::A).await;
    assert_eq!(first.answers[0].ttl, 300);
    let second = ask(&s, "WWW.Example.", RecordType::A).await;
    assert_eq!(address(&second), Some(Ipv4Addr::new(192, 0, 2, 1)));
    assert_eq!(
        second.queries[0].name().to_ascii(),
        "WWW.Example.",
        "the client's spelling comes back"
    );
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let later = ask(&s, "www.example.", RecordType::A).await;
    assert!(
        later.answers[0].ttl < 300,
        "TTL counts down: {}",
        later.answers[0].ttl
    );
    assert_eq!(doh.log.count("www.example."), 1);
    let stats = s.stats.snapshot();
    assert_eq!((stats.forwarded, stats.cached), (1, 2));
}

#[tokio::test]
async fn negative_answers_are_cached() {
    let ca = ca();
    let doh = DohServer::start(&ca).await;
    let s = start(&doh, &ca, "").await;
    for _ in 0..3 {
        let r = ask(&s, "missing.test.", RecordType::A).await;
        assert_eq!(r.metadata.response_code, ResponseCode::NXDomain);
        assert_eq!(r.authorities.len(), 1, "with its SOA");
    }
    assert_eq!(doh.log.count("missing.test."), 1);
}

#[tokio::test]
async fn expired_answers_are_fetched_again() {
    let ca = ca();
    let doh = DohServer::start(&ca).await;
    let s = start(&doh, &ca, "").await;
    ask(&s, "short.test.", RecordType::A).await;
    ask(&s, "short.test.", RecordType::A).await;
    assert_eq!(doh.log.count("short.test."), 1);
    tokio::time::sleep(Duration::from_millis(1100)).await;
    ask(&s, "short.test.", RecordType::A).await;
    assert_eq!(doh.log.count("short.test."), 2);
}

#[tokio::test]
async fn stale_answers_stand_in_when_every_upstream_fails() {
    let ca = ca();
    let doh = DohServer::start(&ca).await;
    let s = start(&doh, &ca, "").await;
    ask(&s, "short.test.", RecordType::A).await;
    doh.set_mode(DohMode::Status(500));
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let r = ask(&s, "short.test.", RecordType::A).await;
    assert_eq!(address(&r), Some(Ipv4Addr::new(192, 0, 2, 2)));
    assert_eq!(r.answers[0].ttl, STALE_TTL);
    // Never seen before: nothing stale to give.
    let r = ask(&s, "never.example.", RecordType::A).await;
    assert_eq!(r.metadata.response_code, ResponseCode::ServFail);
    let stats = s.stats.snapshot();
    assert_eq!((stats.stale, stats.upstream_failures), (1, 1));
}

#[tokio::test]
async fn cloaked_cnames_are_blocked_cached_or_not() {
    let ca = ca();
    let doh = DohServer::start(&ca).await;
    let s = start(&doh, &ca, "block = [\"tracker.test\"]").await;
    for _ in 0..2 {
        let r = ask(&s, "cloaked.test.", RecordType::A).await;
        assert_eq!(address(&r), Some(Ipv4Addr::UNSPECIFIED));
        assert_eq!(r.answers.len(), 1, "no CNAME chain in the block answer");
    }
    assert_eq!(
        doh.log.count("cloaked.test."),
        1,
        "the second came from the cache"
    );
    assert_eq!(s.stats.snapshot().uncloaked, 2);
}

#[tokio::test]
async fn an_allowlisted_name_is_never_uncloaked() {
    let ca = ca();
    let doh = DohServer::start(&ca).await;
    let s = start(
        &doh,
        &ca,
        "allow = [\"cloaked.test\"]\nblock = [\"tracker.test\"]",
    )
    .await;
    let r = ask(&s, "cloaked.test.", RecordType::A).await;
    assert_eq!(address(&r), Some(Ipv4Addr::new(192, 0, 2, 3)));
}

#[tokio::test]
async fn a_list_change_applies_to_cached_answers() {
    let ca = ca();
    let doh = DohServer::start(&ca).await;
    let s = start(&doh, &ca, "").await;
    let r = ask(&s, "cloaked.test.", RecordType::A).await;
    assert_eq!(address(&r), Some(Ipv4Addr::new(192, 0, 2, 3)));

    // A reload that blocks the tracker, keeping upstreams and cache as the
    // reloader does.
    let current = s.policy.load();
    let blocking = config(&doh, "block = [\"tracker.test\"]");
    let setup = from_config_with_roots(
        &blocking,
        Path::new("."),
        &Cache::new("/nonexistent"),
        &s.roots,
    )
    .unwrap();
    s.policy.store(Policy {
        upstreams: current.upstreams.clone(),
        cache: Arc::clone(&current.cache),
        ..setup.policy()
    });
    let r = ask(&s, "cloaked.test.", RecordType::A).await;
    assert_eq!(address(&r), Some(Ipv4Addr::UNSPECIFIED));
    assert_eq!(
        doh.log.count("cloaked.test."),
        1,
        "still served from the cache"
    );
}

#[tokio::test]
async fn https_records() {
    let ca = ca();
    let doh = DohServer::start(&ca).await;
    let s = start(&doh, &ca, "block = [\"tracker.test\", \"blocked.test\"]").await;

    // A blocked name's HTTPS record: NODATA, without asking upstream.
    let r = ask(&s, "www.blocked.test.", RecordType::HTTPS).await;
    assert_eq!(r.metadata.response_code, ResponseCode::NoError);
    assert!(r.answers.is_empty());
    assert!(matches!(r.authorities[0].data, RData::SOA(_)));
    assert_eq!(doh.log.count("www.blocked.test."), 0);

    // An HTTPS record pointing at a blocked target is uncloaked.
    let r = ask(&s, "svc.test.", RecordType::HTTPS).await;
    assert!(r.answers.is_empty(), "{r:?}");
    assert_eq!(s.stats.snapshot().uncloaked, 1);
    // The name's own A record is fine.
    let r = ask(&s, "svc.test.", RecordType::A).await;
    assert_eq!(address(&r), Some(Ipv4Addr::new(192, 0, 2, 4)));
}

#[tokio::test]
async fn special_names_never_leave_the_machine() {
    let ca = ca();
    let doh = DohServer::start(&ca).await;
    let s = start(&doh, &ca, "").await;
    let r = ask(&s, "localhost.", RecordType::A).await;
    assert_eq!(address(&r), Some(Ipv4Addr::LOCALHOST));
    for (name, rtype, code) in [
        (
            "use-application-dns.net.",
            RecordType::A,
            ResponseCode::NXDomain,
        ),
        (
            "5.1.168.192.in-addr.arpa.",
            RecordType::PTR,
            ResponseCode::NXDomain,
        ),
        ("printer.local.", RecordType::A, ResponseCode::NXDomain),
        (
            "_dns.resolver.arpa.",
            RecordType::SVCB,
            ResponseCode::NoError,
        ),
    ] {
        let r = ask(&s, name, rtype).await;
        assert_eq!(r.metadata.response_code, code, "{name}");
    }
    assert!(doh.log.all().is_empty(), "{:?}", doh.log.all());
    assert_eq!(s.stats.snapshot().local, 5);
}
