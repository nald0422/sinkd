//! What a reload costs: build time, memory over repeated reloads, and query
//! latency while reloads run.
//!
//! ```text
//! cargo run --release -p sinkd-resolver --example reload [-- --entries 1000000 --reloads 10]
//! ```
//!
//! Writes a hosts file of `--entries` names, builds the rules from it the way
//! the reloader does (`from_config` on a blocking thread, then
//! `PolicyHandle::store`), and keeps `--clients` closed-loop UDP clients
//! asking for blocked names the whole time. Latency is reported for an idle
//! phase and for the phase with back-to-back reloads; RSS is sampled every
//! 10 ms to catch the peak while old and new rules coexist.
#![allow(clippy::unwrap_used)]

use std::io::{BufWriter, Write as _};
use std::net::{Ipv4Addr, SocketAddr};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use hickory_proto::op::{Message, Query};
use hickory_proto::rr::{Name, RecordType};
use sinkd_core::config::Config;
use sinkd_lists::Cache;
use sinkd_resolver::{Server, from_config};
use tokio::net::UdpSocket;

struct Args {
    entries: usize,
    reloads: usize,
    clients: usize,
}

fn args() -> Args {
    let mut a = Args {
        entries: 1_000_000,
        reloads: 10,
        clients: 4,
    };
    let mut it = std::env::args().skip(1);
    while let Some(flag) = it.next() {
        let value = it.next().and_then(|v| v.parse().ok());
        match (flag.as_str(), value) {
            ("--entries", Some(v)) => a.entries = v,
            ("--reloads", Some(v)) => a.reloads = v,
            ("--clients", Some(v)) => a.clients = v,
            _ => {
                eprintln!("usage: reload [--entries N] [--reloads N] [--clients N]");
                std::process::exit(2);
            }
        }
    }
    a
}

fn rss_mib() -> f64 {
    let out = std::process::Command::new("ps")
        .args(["-o", "rss=", "-p", &std::process::id().to_string()])
        .output()
        .unwrap();
    String::from_utf8_lossy(&out.stdout)
        .trim()
        .parse::<f64>()
        .unwrap_or(0.0)
        / 1024.0
}

fn name(i: usize) -> String {
    format!("ads{i}.tracker{}.example", i % 9973)
}

/// Streamed to disk, so generating the list does not inflate RSS.
fn write_list(path: &Path, entries: usize) {
    let mut out = BufWriter::new(std::fs::File::create(path).unwrap());
    for i in 0..entries {
        writeln!(out, "0.0.0.0 {}", name(i)).unwrap();
    }
    out.flush().unwrap();
}

/// Latencies in 1 µs buckets up to 100 ms: a fixed 400 KB per phase, so the
/// load generator's memory does not grow with the number of queries.
#[derive(Clone)]
struct Histogram {
    buckets: Vec<u32>,
    max: Duration,
}

const BUCKETS: usize = 100_000;

impl Histogram {
    fn new() -> Self {
        Histogram {
            buckets: vec![0; BUCKETS],
            max: Duration::ZERO,
        }
    }

    fn record(&mut self, d: Duration) {
        let us = usize::try_from(d.as_micros()).unwrap_or(usize::MAX);
        self.buckets[us.min(BUCKETS - 1)] += 1;
        self.max = self.max.max(d);
    }

    fn merge(&mut self, other: &Histogram) {
        for (a, b) in self.buckets.iter_mut().zip(&other.buckets) {
            *a += b;
        }
        self.max = self.max.max(other.max);
    }

    fn count(&self) -> u64 {
        self.buckets.iter().map(|&c| u64::from(c)).sum()
    }

    fn percentile(&self, p: f64) -> Duration {
        let target = (self.count() as f64 * p).ceil() as u64;
        let mut seen = 0;
        for (us, &c) in self.buckets.iter().enumerate() {
            seen += u64::from(c);
            if seen >= target.max(1) {
                return Duration::from_micros(us as u64);
            }
        }
        self.max
    }
}

/// Closed-loop clients asking for blocked names until `stop`; each latency
/// lands in the histogram of the phase it fell in.
async fn client(
    target: SocketAddr,
    seed: usize,
    entries: usize,
    stop: Arc<AtomicBool>,
    phase: Arc<AtomicU64>,
) -> ([Histogram; 2], usize) {
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    socket.connect(target).await.unwrap();
    let mut buf = vec![0; 1500];
    let mut out = [Histogram::new(), Histogram::new()];
    let mut errors = 0;
    let mut n = seed;
    while !stop.load(Ordering::Relaxed) {
        n = n
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        let mut q = Message::query();
        q.metadata.recursion_desired = true;
        let qname = Name::from_ascii(format!("x.{}.", name(n % entries))).unwrap();
        q.add_query(Query::query(qname, RecordType::A));
        let bytes = q.to_vec().unwrap();
        let sent = Instant::now();
        socket.send(&bytes).await.unwrap();
        match tokio::time::timeout(Duration::from_secs(1), socket.recv(&mut buf)).await {
            Ok(Ok(len)) if len >= 12 && buf[..2] == bytes[..2] && buf[3] & 0x0f == 0 => {
                if let Some(h) = out.get_mut(phase.load(Ordering::Relaxed) as usize) {
                    h.record(sent.elapsed());
                }
            }
            _ => errors += 1,
        }
    }
    (out, errors)
}

fn percentiles(label: &str, h: &Histogram) {
    println!(
        "  {label:<16} {:>8} queries   p50 {:>7.1?}   p99 {:>7.1?}   p99.9 {:>7.1?}   max {:>7.1?}",
        h.count(),
        h.percentile(0.50),
        h.percentile(0.99),
        h.percentile(0.999),
        h.max
    );
}

fn main() {
    let args = args();
    let dir = std::env::temp_dir().join(format!("sinkd-reload-bench-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    write_list(&dir.join("list.txt"), args.entries);
    let config = Config::from_toml(
        "[listen]\naddrs = [\"127.0.0.1:0\"]\n[[upstream]]\nprotocol = \"udp\"\naddr = \"127.0.0.1:1\"\n\
         [[list]]\npath = \"list.txt\"\nformat = \"hosts\"\n",
    )
    .unwrap();
    let cache = Cache::new(dir.join("cache"));
    let rss_start = rss_mib();

    let started = Instant::now();
    let setup = from_config(&config, &dir, &cache).unwrap();
    let first_build = started.elapsed();
    let entries = setup.report.block_entries;
    println!(
        "{entries} entries; first build {first_build:.0?}; RSS {rss_start:.0} MiB at start, {:.0} MiB after",
        rss_mib()
    );

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .unwrap();
    let (addr, policy, server_task) = rt.block_on(async {
        let server = Server::bind(setup.policy(), &config.listen.addrs)
            .await
            .unwrap();
        let addr = server.local_addrs()[0];
        let policy = server.policy();
        (addr, policy, tokio::spawn(server.run()))
    });

    let stop = Arc::new(AtomicBool::new(false));
    let phase = Arc::new(AtomicU64::new(0));
    let clients: Vec<_> = (0..args.clients)
        .map(|c| {
            rt.spawn(client(
                addr,
                c * 7919 + 1,
                args.entries,
                Arc::clone(&stop),
                Arc::clone(&phase),
            ))
        })
        .collect();

    // RSS sampler, for the peak while two rule sets coexist.
    let peak = Arc::new(AtomicU64::new(0));
    let sampler = {
        let (stop, peak) = (Arc::clone(&stop), Arc::clone(&peak));
        std::thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                peak.fetch_max((rss_mib() * 10.0) as u64, Ordering::Relaxed);
                std::thread::sleep(Duration::from_millis(10));
            }
        })
    };

    std::thread::sleep(Duration::from_secs(3));
    let rss_idle = rss_mib();
    phase.store(1, Ordering::Relaxed);
    let mut builds = Vec::new();
    let mut rss_after = Vec::new();
    for _ in 0..args.reloads {
        let started = Instant::now();
        // The reloader builds on a blocking thread; this does the same.
        let build = rt.spawn_blocking({
            let (config, dir, cache) = (config.clone(), dir.clone(), cache.clone());
            move || from_config(&config, &dir, &cache)
        });
        let setup = rt.block_on(build).unwrap().unwrap();
        policy.store(setup.policy());
        builds.push(started.elapsed());
        rss_after.push(rss_mib());
    }
    phase.store(2, Ordering::Relaxed);
    std::thread::sleep(Duration::from_secs(1));
    stop.store(true, Ordering::Relaxed);
    sampler.join().unwrap();

    let mut idle = Histogram::new();
    let mut reloading = Histogram::new();
    let mut errors = 0;
    for c in clients {
        let ([i, r], e) = rt.block_on(c).unwrap();
        idle.merge(&i);
        reloading.merge(&r);
        errors += e;
    }
    server_task.abort();

    builds.sort_unstable();
    println!(
        "{} reloads: build + swap min {:.0?}, median {:.0?}, max {:.0?}",
        builds.len(),
        builds[0],
        builds[builds.len() / 2],
        builds[builds.len() - 1]
    );
    let trend: Vec<String> = rss_after.iter().map(|r| format!("{r:.0}")).collect();
    println!(
        "RSS: {rss_idle:.0} MiB before reloads; after each: {} MiB; sampled peak {:.0} MiB",
        trend.join(" "),
        peak.load(Ordering::Relaxed) as f64 / 10.0
    );
    println!(
        "Queries for blocked names ({} clients, {errors} errors):",
        args.clients
    );
    percentiles("idle", &idle);
    percentiles("during reloads", &reloading);
    let _ = std::fs::remove_dir_all(dir);
}
