//! Checks the resolver matcher against its budgets on synthetic data:
//! 1M names at RSS < 150 MB, cold load < 2 s, lookup p99 < 1 µs.
//!
//! ```text
//! cargo run --release -p sinkhole-filters --example dns_budget [-- <names> [--load-only]]
//! ```
//!
//! "Cold load" is the real path: hosts-format text → parse → normalize →
//! insert → build. Steady-state RSS comes from `ps` once the list text is
//! freed and before any test queries exist, so it is what a resolver holding
//! these lists would use. Run under `/usr/bin/time -l` with `--load-only` to
//! see the peak during load. Per-lookup times are measured one call at a
//! time with `Instant`, so they include the timer's own cost (printed
//! separately).
#![allow(clippy::unwrap_used)]

use std::fmt::Write as _;
use std::hint::black_box;
use std::process::Command;
use std::time::{Duration, Instant};

use sinkhole_filters::dns::{DnsAction, DnsFormat, DnsListBuilder};

/// splitmix64: deterministic and dependency-free.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }

    fn label(&mut self) -> String {
        const CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
        let len = 3 + self.below(10);
        (0..len)
            .map(|_| CHARS[self.below(CHARS.len())] as char)
            .collect()
    }

    /// Shaped like real blocklists: mostly 2-4 labels, and about a third of
    /// entries are subdomains of a recent entry (ad networks list many).
    fn name(&mut self, earlier: &[String]) -> String {
        const TLDS: &[&str] = &[
            "com", "net", "org", "io", "co", "de", "ru", "info", "xyz", "top", "site", "app",
        ];
        if !earlier.is_empty() && self.below(3) == 0 {
            return format!("{}.{}", self.label(), earlier[self.below(earlier.len())]);
        }
        let labels = 1 + self.below(3);
        let mut parts: Vec<String> = (0..labels).map(|_| self.label()).collect();
        parts.push(TLDS[self.below(TLDS.len())].to_owned());
        parts.join(".")
    }
}

fn rss_mib() -> Option<f64> {
    let out = Command::new("ps")
        .args(["-o", "rss=", "-p", &std::process::id().to_string()])
        .output()
        .ok()?;
    let kib: f64 = String::from_utf8_lossy(&out.stdout).trim().parse().ok()?;
    Some(kib / 1024.0)
}

fn percentile(sorted: &[u32], p: f64) -> u32 {
    sorted[((sorted.len() - 1) as f64 * p).round() as usize]
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let n: usize = args
        .iter()
        .find_map(|a| a.parse().ok())
        .unwrap_or(1_000_000);
    let load_only = args.iter().any(|a| a == "--load-only");
    let rss_start = rss_mib();
    let mut rng = Rng(0x5eed);

    // Build the hosts text directly; only a window of recent names is kept
    // for generating subdomains, so the generator does not inflate RSS.
    let mut recent: Vec<String> = Vec::with_capacity(10_000);
    let mut hosts = String::with_capacity(n * 32);
    let mut allow = String::new();
    hosts.push_str("# synthetic hosts file\n127.0.0.1 localhost\n");
    for i in 0..n {
        let name = rng.name(&recent);
        writeln!(hosts, "0.0.0.0 {name}").unwrap();
        if i % (n / 1_000).max(1) == 0 {
            writeln!(allow, "{name}").unwrap();
        }
        if recent.len() < 10_000 {
            recent.push(name);
        } else {
            let slot = rng.below(recent.len());
            recent[slot] = name;
        }
    }
    drop(recent);
    let text_mib = hosts.len() as f64 / (1024.0 * 1024.0);

    let start = Instant::now();
    let mut builder = DnsListBuilder::new();
    builder.add_list(&hosts, DnsFormat::Auto, DnsAction::Block);
    builder.add_list(&allow, DnsFormat::Domains, DnsAction::Allow);
    let (matcher, report) = builder.finish();
    let load = start.elapsed();
    drop(hosts);
    drop(allow);
    let rss_loaded = rss_mib();

    let ms = |d: Duration| d.as_secs_f64() * 1e3;
    println!("names generated        {n}");
    println!("hosts text             {text_mib:.1} MiB");
    println!(
        "entries                block {}  allow {}  (rejected lines {})",
        report.block_entries,
        report.allow_entries,
        report.rejected_total()
    );
    println!(
        "cold load              {:.0} ms   (budget 2000 ms)",
        ms(load)
    );
    println!(
        "matcher heap           {:.1} MiB",
        matcher.heap_bytes() as f64 / (1024.0 * 1024.0)
    );
    if let (Some(a), Some(b)) = (rss_start, rss_loaded) {
        println!(
            "steady-state RSS       {b:.1} MiB after load, list text freed (process started at {a:.1} MiB; budget 150 MiB)"
        );
    }
    if load_only {
        return;
    }

    // Queries: a quarter exact hits, a quarter 1-3 labels below a listed
    // name, half names that are not listed at all.
    let listed: Vec<&str> = matcher.blocklist().iter().map(|(name, _)| name).collect();
    let queries: Vec<String> = (0..1_000_000)
        .map(|_| match rng.below(4) {
            0 => listed[rng.below(listed.len())].to_owned(),
            1 => {
                let depth = 1 + rng.below(3);
                let prefix: Vec<String> = (0..depth).map(|_| rng.label()).collect();
                format!("{}.{}", prefix.join("."), listed[rng.below(listed.len())])
            }
            _ => format!("www.{}.{}.example", rng.label(), rng.label()),
        })
        .collect();
    drop(listed);

    // Warm up caches and branch predictors.
    let mut blocked = 0usize;
    for q in &queries {
        blocked += usize::from(matcher.check(q).is_blocked());
    }

    let mut timer_cost: Vec<u32> = (0..100_000)
        .map(|_| {
            let t = Instant::now();
            black_box(());
            t.elapsed().as_nanos() as u32
        })
        .collect();
    timer_cost.sort_unstable();

    let mut times: Vec<u32> = queries
        .iter()
        .map(|q| {
            let t = Instant::now();
            black_box(matcher.check(black_box(q)));
            t.elapsed().as_nanos() as u32
        })
        .collect();
    times.sort_unstable();

    let batch_start = Instant::now();
    for q in &queries {
        black_box(matcher.check(black_box(q)));
    }
    let batch = batch_start.elapsed();

    println!(
        "blocked queries        {:.1}%",
        100.0 * blocked as f64 / queries.len() as f64
    );
    println!(
        "lookup (per call)      p50 {} ns  p99 {} ns  p99.9 {} ns  max {} ns   (budget p99 1000 ns)",
        percentile(&times, 0.50),
        percentile(&times, 0.99),
        percentile(&times, 0.999),
        times[times.len() - 1]
    );
    println!(
        "timer overhead         p50 {} ns  p99 {} ns",
        percentile(&timer_cost, 0.50),
        percentile(&timer_cost, 0.99)
    );
    println!(
        "lookup (batched mean)  {:.0} ns   ({:.1} M lookups/s on one core)",
        batch.as_nanos() as f64 / queries.len() as f64,
        queries.len() as f64 / batch.as_secs_f64() / 1e6
    );
}
