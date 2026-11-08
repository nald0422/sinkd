//! No input from the network may panic the resolver, and every reply it
//! does send is a well-formed response to the query it came from.
#![allow(clippy::unwrap_used)]

use hickory_proto::op::{Edns, Message, MessageType, Query};
use hickory_proto::rr::{Name, RecordType};
use proptest::prelude::*;
use sinkhole_core::config::Blocking;
use sinkhole_core::{Domain, DomainMatcher, Scope};
use sinkhole_resolver::{Decision, Engine, Transport};

fn engine() -> Engine {
    let mut b = DomainMatcher::builder();
    b.block(&Domain::parse("ads.test").unwrap(), Scope::Subtree)
        .unwrap();
    b.allow(&Domain::parse("ok.ads.test").unwrap(), Scope::Subtree)
        .unwrap();
    Engine::new(b.build(), Blocking::default())
}

/// Valid queries to mutate: blocked, allowed and unlisted names, with and
/// without EDNS.
fn seed_queries() -> Vec<Vec<u8>> {
    let mut seeds = Vec::new();
    for name in ["ads.test.", "a.ok.ads.test.", "example.test.", "."] {
        for rtype in [
            RecordType::A,
            RecordType::AAAA,
            RecordType::HTTPS,
            RecordType::TXT,
        ] {
            let mut m = Message::query();
            m.add_query(Query::query(Name::from_ascii(name).unwrap(), rtype));
            seeds.push(m.to_vec().unwrap());
            m.set_edns(Edns::new());
            seeds.push(m.to_vec().unwrap());
        }
    }
    seeds
}

/// Checks a reply against the query bytes it answers.
fn check(packet: &[u8], decision: Decision) {
    let reply = match decision {
        Decision::Blocked(r) | Decision::Local(r) | Decision::Error(r) => r,
        Decision::Drop | Decision::Forward(_) => return,
    };
    let parsed = Message::from_vec(&reply).expect("replies always parse");
    assert_eq!(parsed.metadata.message_type, MessageType::Response);
    assert_eq!(parsed.metadata.id.to_be_bytes(), packet[..2]);
    assert!(
        reply.len() <= 512 || parsed.edns.is_some(),
        "UDP size limit"
    );
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4096))]

    #[test]
    fn random_bytes(packet in proptest::collection::vec(any::<u8>(), 0..600)) {
        let e = engine();
        check(&packet, e.decide(&packet, Transport::Udp));
    }

    #[test]
    fn mutated_queries(
        seed in proptest::sample::select(seed_queries()),
        flips in proptest::collection::vec((any::<prop::sample::Index>(), any::<u8>()), 1..6),
        cut in any::<prop::sample::Index>(),
        truncate in any::<bool>(),
    ) {
        let mut packet = seed;
        for (at, byte) in flips {
            let i = at.index(packet.len());
            packet[i] = byte;
        }
        if truncate {
            packet.truncate(cut.index(packet.len() + 1));
        }
        let e = engine();
        for transport in [Transport::Udp, Transport::Tcp] {
            check(&packet, e.decide(&packet, transport));
        }
    }

    /// Upstream answers are untrusted too: whatever parses must turn into a
    /// well-formed reply. Mutating a rich valid answer reaches far more of
    /// the decoder than random bytes, which rarely parse at all.
    #[test]
    fn mutated_upstream_answers(
        flips in proptest::collection::vec((any::<prop::sample::Index>(), any::<u8>()), 1..8),
    ) {
        let e = engine();
        let mut m = Message::query();
        m.add_query(Query::query(Name::from_ascii("example.test.").unwrap(), RecordType::A));
        let query = m.to_vec().unwrap();
        let Decision::Forward(forward) = e.decide(&query, Transport::Udp) else {
            panic!("unlisted names are forwarded");
        };
        let mut answer = rich_answer(&forward.upstream_query()).to_vec().unwrap();
        for (at, byte) in flips {
            let i = at.index(answer.len());
            answer[i] = byte;
        }
        if let Ok(upstream) = Message::from_vec(&answer) {
            let _ = forward.is_answer(&forward.upstream_query(), &upstream);
            let reply = forward.reply(upstream);
            let parsed = Message::from_vec(&reply).expect("replies always parse");
            prop_assert_eq!(&parsed.metadata.id.to_be_bytes()[..], &query[..2]);
        }
    }
}

/// An answer with a CNAME chain, addresses, text, an SOA and EDNS options.
fn rich_answer(query: &Message) -> Message {
    use hickory_proto::op::OpCode;
    use hickory_proto::rr::rdata::opt::EdnsOption;
    use hickory_proto::rr::rdata::{A, AAAA, CNAME, SOA, TXT};
    use hickory_proto::rr::{RData, Record};
    let name = |s: &str| Name::from_ascii(s).unwrap();
    let mut r = Message::response(query.metadata.id, OpCode::Query);
    r.add_query(query.queries[0].clone());
    r.add_answer(Record::from_rdata(
        name("example.test."),
        60,
        RData::CNAME(CNAME(name("edge.cdn.test."))),
    ));
    r.add_answer(Record::from_rdata(
        name("edge.cdn.test."),
        60,
        RData::A(A::new(192, 0, 2, 7)),
    ));
    r.add_answer(Record::from_rdata(
        name("edge.cdn.test."),
        60,
        RData::AAAA(AAAA("2001:db8::7".parse().unwrap())),
    ));
    r.add_additional(Record::from_rdata(
        name("edge.cdn.test."),
        60,
        RData::TXT(TXT::new(vec!["v=1".into()])),
    ));
    r.add_authority(Record::from_rdata(
        name("cdn.test."),
        60,
        RData::SOA(SOA::new(
            name("ns.cdn.test."),
            name("admin.cdn.test."),
            7,
            3600,
            600,
            86400,
            60,
        )),
    ));
    let mut edns = Edns::new();
    edns.options_mut()
        .insert(EdnsOption::Unknown(15, vec![0, 3])); // Extended DNS Error
    r.set_edns(edns);
    r
}
