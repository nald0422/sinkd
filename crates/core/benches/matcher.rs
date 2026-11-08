//! Micro-benchmarks for normalization and the domain matcher.
//!
//! `cargo bench -p sinkd-core`. The end-to-end budget check (1M names,
//! load time, RSS, p99) is `cargo run --release -p sinkd-filters
//! --example dns_budget`.

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use sinkd_core::{Domain, DomainMatcher, QueryName, Scope};

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

    fn name(&mut self) -> String {
        const TLDS: &[&str] = &["com", "net", "org", "io", "de", "xyz", "info"];
        let labels = 1 + self.below(3);
        let mut parts: Vec<String> = (0..labels).map(|_| self.label()).collect();
        parts.push(TLDS[self.below(TLDS.len())].to_owned());
        parts.join(".")
    }
}

fn bench_matcher(c: &mut Criterion) {
    let mut rng = Rng(42);
    let names: Vec<String> = (0..100_000).map(|_| rng.name()).collect();
    let mut builder = DomainMatcher::builder();
    for n in &names {
        builder
            .block(&Domain::parse(n).expect("valid"), Scope::Subtree)
            .expect("capacity");
    }
    for _ in 0..1_000 {
        builder
            .allow(&Domain::parse(&rng.name()).expect("valid"), Scope::Subtree)
            .expect("capacity");
    }
    let matcher = builder.build();

    let exact = names[777].clone();
    let deep = format!("a.b.c.{}", names[555]);
    let miss = "www.not-listed-anywhere.example.com".to_owned();

    let mut g = c.benchmark_group("matcher/100k");
    g.bench_function("hit_exact", |b| b.iter(|| matcher.check(black_box(&exact))));
    g.bench_function("hit_3_labels_below", |b| {
        b.iter(|| matcher.check(black_box(&deep)))
    });
    g.bench_function("miss_4_labels", |b| {
        b.iter(|| matcher.check(black_box(&miss)))
    });
    g.finish();
}

fn bench_normalize(c: &mut Criterion) {
    let mut g = c.benchmark_group("normalize");
    g.bench_function("domain_ascii", |b| {
        b.iter(|| Domain::parse(black_box("Ads.Tracker.Example.COM.")))
    });
    g.bench_function("domain_idn", |b| {
        b.iter(|| Domain::parse(black_box("werbung.bücher.de")))
    });
    g.bench_function("query_name", |b| {
        b.iter(|| QueryName::new(black_box("Ads.Tracker.Example.COM.")))
    });
    g.finish();
}

criterion_group!(benches, bench_matcher, bench_normalize);
criterion_main!(benches);
