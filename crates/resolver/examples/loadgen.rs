//! Throughput and latency of the resolver over real loopback sockets.
//!
//! ```text
//! cargo run --release -p sinkd-resolver --example loadgen [-- --clients 64 --seconds 5 --query-log 1]
//! ```
//!
//! Starts, in this process and on separate runtimes, scripted upstreams
//! (plain UDP, and DoH over HTTP/2 with a throwaway CA), sinkd servers
//! forwarding to them, and closed-loop UDP clients (each sends a query and
//! waits for its reply before the next). It measures five workloads:
//!
//! - **blocked**: names on the blocklist, answered by sinkd itself.
//! - **cached**: 1,000 names asked over and over, so every answer comes
//!   from the cache after the first.
//! - **fwd-udp** / **fwd-doh**: names never asked before, relayed to the
//!   UDP or the DoH upstream every time.
//! - **direct**: the fwd-udp queries sent straight to the UDP upstream, as
//!   a baseline; `fwd-udp − direct` is what sinkd adds.
//!
//! Load generator, server and upstream share the machine's cores, so these
//! numbers understate what the server alone can do. `--query-log 1` runs
//! the servers with the query log on, to measure what it costs.
#![allow(clippy::unwrap_used)]

#[path = "../tests/support/mod.rs"]
mod support;

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use hickory_proto::op::{Message, OpCode, Query};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{Name, RData, Record, RecordType};
use sinkd_core::config::{
    Blocking, Cache as CacheSettings, QueryLog as QueryLogSettings, Upstream,
};
use sinkd_core::{Domain, DomainMatcher, Scope};
use sinkd_resolver::{
    AnswerCache, ClientFilter, Engine, Policy, QueryLog, Roots, Server, Stats, StatsSnapshot,
    Upstreams,
};
use tokio::net::UdpSocket;
use tokio::runtime::{Builder, Runtime};

/// Which name client `c` asks in its `n`th query.
type Names = Arc<dyn Fn(usize, u64) -> String + Send + Sync>;

struct Args {
    clients: usize,
    seconds: u64,
    query_log: bool,
}

fn args() -> Args {
    let mut a = Args {
        clients: 64,
        seconds: 5,
        query_log: false,
    };
    let mut it = std::env::args().skip(1);
    while let Some(flag) = it.next() {
        let value = it.next().and_then(|v| v.parse().ok());
        match (flag.as_str(), value) {
            ("--clients", Some(v)) => a.clients = v,
            ("--seconds", Some(v)) => a.seconds = v as u64,
            ("--query-log", Some(v)) => a.query_log = v != 0,
            _ => {
                eprintln!("usage: loadgen [--clients N] [--seconds S] [--query-log 0|1]");
                std::process::exit(2);
            }
        }
    }
    a
}

fn runtime(threads: usize) -> Runtime {
    Builder::new_multi_thread()
        .worker_threads(threads)
        .enable_all()
        .build()
        .unwrap()
}

/// Answers every query with one A record, as fast as it can.
async fn upstream(socket: UdpSocket) {
    let socket = Arc::new(socket);
    let mut buf = vec![0; 4096];
    loop {
        let (len, peer) = socket.recv_from(&mut buf).await.unwrap();
        let Ok(q) = Message::from_vec(&buf[..len]) else {
            continue;
        };
        let mut r = Message::response(q.metadata.id, OpCode::Query);
        r.metadata.recursion_available = true;
        r.add_queries(q.queries.iter().cloned());
        if let Some(query) = q.queries.first() {
            r.add_answer(Record::from_rdata(
                query.name().clone(),
                300,
                RData::A(A(Ipv4Addr::new(192, 0, 2, 1))),
            ));
        }
        r.edns = q.edns.clone();
        let _ = socket.send_to(&r.to_vec().unwrap(), peer).await;
    }
}

struct Outcome {
    latencies: Vec<Duration>,
    errors: usize,
    elapsed: Duration,
}

/// `clients` closed-loop clients asking `names(i)` for `seconds`.
async fn load(target: SocketAddr, clients: usize, seconds: u64, names: Names) -> Outcome {
    let stop = Arc::new(AtomicBool::new(false));
    let mut tasks = Vec::new();
    for client in 0..clients {
        let (stop, names) = (Arc::clone(&stop), Arc::clone(&names));
        tasks.push(tokio::spawn(async move {
            let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            socket.connect(target).await.unwrap();
            let mut buf = vec![0; 4096];
            let mut latencies = Vec::with_capacity(1 << 16);
            let mut errors = 0;
            let mut n = 0u64;
            while !stop.load(Ordering::Relaxed) {
                let mut q = Message::query();
                q.metadata.recursion_desired = true;
                let name = Name::from_ascii(names(client, n)).unwrap();
                q.add_query(Query::query(name, RecordType::A));
                let bytes = q.to_vec().unwrap();
                n += 1;
                let sent = Instant::now();
                socket.send(&bytes).await.unwrap();
                let reply =
                    tokio::time::timeout(Duration::from_secs(1), socket.recv(&mut buf)).await;
                match reply {
                    Ok(Ok(len)) if buf[..2] == bytes[..2] && len >= 12 && buf[3] & 0x0f == 0 => {
                        latencies.push(sent.elapsed());
                    }
                    _ => errors += 1,
                }
            }
            (latencies, errors)
        }));
    }
    let started = Instant::now();
    tokio::time::sleep(Duration::from_secs(seconds)).await;
    stop.store(true, Ordering::Relaxed);
    let mut outcome = Outcome {
        latencies: Vec::new(),
        errors: 0,
        elapsed: started.elapsed(),
    };
    for t in tasks {
        let (l, e) = t.await.unwrap();
        outcome.latencies.extend(l);
        outcome.errors += e;
    }
    outcome
}

fn report(label: &str, mut o: Outcome) {
    o.latencies.sort_unstable();
    let pct = |p: f64| {
        let i = ((o.latencies.len() as f64 * p) as usize).min(o.latencies.len().saturating_sub(1));
        o.latencies.get(i).copied().unwrap_or_default()
    };
    let qps = o.latencies.len() as f64 / o.elapsed.as_secs_f64();
    println!(
        "{label:<10} {qps:>9.0} q/s   p50 {:>7.1?}   p99 {:>7.1?}   p99.9 {:>7.1?}   max {:>7.1?}   errors {}",
        pct(0.50),
        pct(0.99),
        pct(0.999),
        o.latencies.last().copied().unwrap_or_default(),
        o.errors,
    );
}

fn delta(before: StatsSnapshot, after: StatsSnapshot) -> String {
    format!(
        "server: {} blocked, {} cached, {} forwarded, {} upstream failures, {} shed",
        after.blocked - before.blocked,
        after.cached - before.cached,
        after.forwarded - before.forwarded,
        after.upstream_failures - before.upstream_failures,
        after.shed - before.shed,
    )
}

fn main() {
    let args = args();
    let cores = std::thread::available_parallelism().map_or(4, |n| n.get());
    println!(
        "{} clients, {} s per workload, {cores} cores shared by load generator, server and upstream\n",
        args.clients, args.seconds
    );

    let upstream_rt = runtime(2);
    let upstream_addr = upstream_rt.block_on(async {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        tokio::spawn(upstream(socket));
        addr
    });

    let ca = support::ca();
    let doh_server = upstream_rt.block_on(support::DohServer::start(&ca));

    let blocklist = || {
        let mut b = DomainMatcher::builder();
        for i in 0..100_000 {
            let name = format!("ads{i}.tracker{}.example", i % 997);
            b.block(&Domain::parse(&name).unwrap(), Scope::Subtree)
                .unwrap();
        }
        Engine::new(b.build(), Blocking::default())
    };
    let server_rt = runtime(4);
    let query_log = args.query_log;
    let start = |upstreams: Upstreams| {
        let engine = blocklist();
        server_rt.block_on(async move {
            let policy = Policy {
                engine,
                upstreams,
                cache: Arc::new(AnswerCache::new(&CacheSettings::default())),
                clients: ClientFilter::default(),
                log: Arc::new(QueryLog::new(&QueryLogSettings {
                    enabled: query_log,
                    ..QueryLogSettings::default()
                })),
                control_users: Vec::new(),
            };
            let server = Server::bind(policy, &["127.0.0.1:0".parse().unwrap()])
                .await
                .unwrap();
            let addr = server.local_addrs()[0];
            let stats = server.stats();
            tokio::spawn(server.run());
            (addr, stats)
        })
    };
    let (server_addr, stats) = start(Upstreams::new(vec![upstream_addr], Duration::from_secs(2)));
    let doh = Upstream::Doh {
        url: format!(
            "https://{}:{}/dns-query",
            support::DOH_HOST,
            doh_server.port
        ),
        bootstrap: vec!["127.0.0.1".parse().unwrap()],
    };
    let roots = Roots::Only(Arc::new(vec![ca.ca_der()]));
    let (doh_addr, doh_stats) = start(Upstreams::from_config(&[doh], &roots).unwrap());

    let load_rt = runtime(4);
    let blocked: Names = Arc::new(|c, n| {
        let i = (c as u64 * 7919 + n * 31) % 100_000;
        format!("x{n}.ads{i}.tracker{}.example.", i % 997)
    });
    let unlisted: Names = Arc::new(|c, n| format!("host{n}.client{c}.example.com."));
    let unlisted_doh: Names = Arc::new(|c, n| format!("doh{n}.client{c}.example.com."));
    let popular: Names =
        Arc::new(|c, n| format!("site{}.example.org.", (c as u64 * 7919 + n) % 1000));

    // Warm up sockets, allocator and branch predictors; fill the cache.
    load_rt.block_on(load(server_addr, args.clients, 1, Arc::clone(&blocked)));
    load_rt.block_on(load(server_addr, args.clients, 1, Arc::clone(&popular)));
    // Opens the HTTP/2 connection, with names the measured run will not reuse.
    let warm_doh: Names = Arc::new(|c, n| format!("warm{n}.client{c}.example.com."));
    load_rt.block_on(load(doh_addr, args.clients, 1, warm_doh));

    let workloads: [(&str, SocketAddr, &Names, Option<&Arc<Stats>>); 5] = [
        ("blocked", server_addr, &blocked, Some(&stats)),
        ("cached", server_addr, &popular, Some(&stats)),
        ("fwd-udp", server_addr, &unlisted, Some(&stats)),
        ("fwd-doh", doh_addr, &unlisted_doh, Some(&doh_stats)),
        ("direct", upstream_addr, &unlisted, None),
    ];
    for (label, target, names, stats) in workloads {
        let before = stats.map(|s| s.snapshot());
        let outcome = load_rt.block_on(load(target, args.clients, args.seconds, Arc::clone(names)));
        report(label, outcome);
        if let (Some(before), Some(stats)) = (before, stats) {
            println!("{:>10} {}", "", delta(before, stats.snapshot()));
        }
    }
    drop(server_rt);
    drop(upstream_rt);
}
