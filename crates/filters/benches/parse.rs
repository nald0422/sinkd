//! Parser throughput. `cargo bench -p sinkd-filters`.

use std::hint::black_box;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use sinkd_filters::dns::{DnsAction, DnsFormat, parse_dns_line};
use sinkd_filters::{Env, parse_list, parse_rule};

const SAMPLES: &[(&str, &str)] = &[
    ("network_hostname", "||ads.example.com^"),
    (
        "network_options",
        "||cdn.example.net/ads/*.js$script,3p,domain=a.example|~b.a.example,redirect=noop.js",
    ),
    ("network_removeparam", "$removeparam=/^(utm_|fbclid)/i,doc"),
    (
        "cosmetic_plain",
        "example.com,~www.example.com##.ad-banner > div[id^=\"ad-\"]",
    ),
    (
        "cosmetic_procedural",
        "example.com##div.post:has-text(/Sponsored|Promoted/i):upward(2)",
    ),
    (
        "scriptlet_ublock",
        "example.com##+js(set, ads.enabled, false)",
    ),
    (
        "scriptlet_adguard",
        "example.com#%#//scriptlet('prevent-fetch', 'pagead2.googlesyndication.com')",
    ),
];

fn bench_rules(c: &mut Criterion) {
    let mut g = c.benchmark_group("parse_rule");
    for (name, line) in SAMPLES {
        g.bench_function(*name, |b| b.iter(|| parse_rule(black_box(line))));
    }
    g.bench_function("dns_hosts_line", |b| {
        b.iter(|| {
            parse_dns_line(
                black_box("0.0.0.0 ads.tracker.example.com"),
                DnsFormat::Auto,
                DnsAction::Block,
            )
        })
    });
    g.finish();
}

fn bench_list(c: &mut Criterion) {
    // A synthetic list shaped roughly like EasyList: mostly network rules,
    // a third cosmetic, a few scriptlets and comments.
    let mut text = String::new();
    for i in 0..20_000 {
        let line = match i % 12 {
            0 => format!("! comment {i}"),
            1..=5 => format!("||ads{i}.example.com^$third-party"),
            6 => format!("/banner{i}/*$image,domain=site{i}.example"),
            7 | 8 => format!("site{i}.example##.ad-{i}"),
            9 => format!("###ad-slot-{i}"),
            10 => format!("site{i}.example##div:has-text(Sponsored {i})"),
            _ => format!("site{i}.example##+js(set, ads{i}.enabled, false)"),
        };
        text.push_str(&line);
        text.push('\n');
    }
    let env = Env::chromium_mv3();
    let mut g = c.benchmark_group("parse_list");
    g.throughput(Throughput::Elements(20_000));
    g.bench_function("synthetic_20k_lines", |b| {
        b.iter(|| parse_list(black_box(&text), &env))
    });
    g.finish();
}

criterion_group!(benches, bench_rules, bench_list);
criterion_main!(benches);
