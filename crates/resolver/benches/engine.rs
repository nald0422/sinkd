//! Per-query CPU cost of the engine, without sockets.
//!
//! `cargo bench -p sinkhole-resolver`. Throughput and latency over real
//! sockets: `cargo run --release -p sinkhole-resolver --example loadgen`.

use std::hint::black_box;
use std::net::Ipv4Addr;

use criterion::{Criterion, criterion_group, criterion_main};
use hickory_proto::op::{Edns, Message, OpCode, Query};
use hickory_proto::rr::rdata::{A, CNAME};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use sinkhole_core::config::Blocking;
use sinkhole_core::config::Cache as CacheSettings;
use sinkhole_core::{Domain, DomainMatcher, Scope};
use sinkhole_resolver::{AnswerCache, Decision, Engine, Transport};

fn engine() -> Engine {
    let mut b = DomainMatcher::builder();
    for i in 0..100_000 {
        let name = format!("ads{i}.tracker{}.example", i % 997);
        b.block(&Domain::parse(&name).expect("valid"), Scope::Subtree)
            .expect("capacity");
    }
    b.block(
        &Domain::parse("doubleclick.net").expect("valid"),
        Scope::Subtree,
    )
    .expect("capacity");
    Engine::new(b.build(), Blocking::default())
}

fn query(name: &str, edns: bool) -> Vec<u8> {
    let mut m = Message::query();
    m.metadata.recursion_desired = true;
    m.add_query(Query::query(
        Name::from_ascii(name).expect("valid"),
        RecordType::A,
    ));
    if edns {
        let mut e = Edns::new();
        e.set_max_payload(1232);
        m.set_edns(e);
    }
    m.to_vec().expect("encodes")
}

fn bench(c: &mut Criterion) {
    let engine = engine();
    let blocked = query("stats.g.doubleclick.net.", true);
    let unlisted = query("www.example.com.", true);

    c.bench_function("decide/blocked", |b| {
        b.iter(|| black_box(engine.decide(black_box(&blocked), Transport::Udp)))
    });
    c.bench_function("decide/forward", |b| {
        b.iter(|| black_box(engine.decide(black_box(&unlisted), Transport::Udp)))
    });

    let Decision::Forward(forward) = engine.decide(&unlisted, Transport::Udp) else {
        panic!("unlisted names are forwarded");
    };
    c.bench_function("forward/upstream_query", |b| {
        b.iter(|| black_box(forward.upstream_query().to_vec()))
    });

    // A typical CDN answer: one CNAME and two addresses.
    let up = forward.upstream_query();
    let mut answer = Message::response(up.metadata.id, OpCode::Query);
    answer.add_query(up.queries[0].clone());
    let name = |s: &str| Name::from_ascii(s).expect("valid");
    answer.add_answer(Record::from_rdata(
        name("www.example.com."),
        300,
        RData::CNAME(CNAME(name("edge.cdn.example.net."))),
    ));
    for i in 1..=2 {
        answer.add_answer(Record::from_rdata(
            name("edge.cdn.example.net."),
            60,
            RData::A(A(Ipv4Addr::new(192, 0, 2, i))),
        ));
    }
    answer.set_edns(Edns::new());
    let answer_bytes = answer.to_vec().expect("encodes");
    c.bench_function("forward/parse_check_reply", |b| {
        b.iter(|| {
            let parsed = Message::from_vec(black_box(&answer_bytes)).expect("parses");
            black_box(forward.is_answer(&up, &parsed));
            black_box(forward.reply(parsed))
        })
    });

    // The whole cache-hit path after `decide`: key, lookup, TTL count-down,
    // uncloaking check, reply.
    let cache = AnswerCache::new(&CacheSettings::default());
    let key = forward.cache_key().expect("cacheable");
    cache.insert(key, &answer);
    c.bench_function("cache/hit_to_reply", |b| {
        b.iter(|| {
            let key = forward.cache_key().expect("cacheable");
            let hit = cache.fresh(black_box(&key)).expect("cached");
            if engine.uncloak(&forward, &hit).is_none() {
                black_box(forward.reply(hit));
            }
        })
    });
    let special = query("localhost.", false);
    c.bench_function("decide/special_name", |b| {
        b.iter(|| black_box(engine.decide(black_box(&special), Transport::Udp)))
    });
}

criterion_group!(benches, bench);
criterion_main!(benches);
