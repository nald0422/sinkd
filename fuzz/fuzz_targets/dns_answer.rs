//! An upstream's answer: uncloaking, the reply to the client and the
//! cache must cope with anything that parses.
#![no_main]

use hickory_proto::op::{Message, Query};
use hickory_proto::rr::{Name, RecordType};
use libfuzzer_sys::fuzz_target;
use sinkd_core::config::{Blocking, Cache as CacheSettings};
use sinkd_core::{Domain, DomainMatcher, Scope};
use sinkd_resolver::{AnswerCache, Decision, Engine, Forward, Transport};
use std::sync::OnceLock;

fn setup() -> &'static (Engine, Vec<Forward>, AnswerCache) {
    static SETUP: OnceLock<(Engine, Vec<Forward>, AnswerCache)> = OnceLock::new();
    SETUP.get_or_init(|| {
        let mut b = DomainMatcher::builder();
        b.block(
            &Domain::parse("tracker.example").expect("domain"),
            Scope::Subtree,
        )
        .expect("block");
        let engine = Engine::new(b.build(), Blocking::default());
        let mut forwards = Vec::new();
        for (name, kind) in [
            ("metrics.shop.example.", RecordType::A),
            ("www.example.com.", RecordType::HTTPS),
            ("Mixed.Case.Example.", RecordType::AAAA),
        ] {
            let mut query = Message::query();
            query.metadata.recursion_desired = true;
            query.add_query(Query::query(Name::from_ascii(name).expect("name"), kind));
            let bytes = query.to_vec().expect("query");
            for transport in [Transport::Udp, Transport::Tcp] {
                if let Decision::Forward(f) = engine.decide(&bytes, transport) {
                    forwards.push(f);
                }
            }
        }
        let cache = AnswerCache::new(&CacheSettings::default());
        (engine, forwards, cache)
    })
}

fuzz_target!(|data: &[u8]| {
    let Ok(answer) = Message::from_vec(data) else {
        return;
    };
    let (engine, forwards, cache) = setup();
    for forward in forwards {
        let query = forward.upstream_query();
        let _ = forward.is_answer(&query, &answer);
        let reply = match engine.uncloak(forward, &answer) {
            Some(blocked) => blocked,
            None => forward.reply(answer.clone()),
        };
        Message::from_vec(&reply).expect("our replies parse");
        if let Some(key) = forward.cache_key() {
            cache.insert(key.clone(), &answer);
            let _ = cache.fresh(&key);
            let _ = cache.stale(&key);
        }
    }
});
