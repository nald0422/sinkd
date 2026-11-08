//! A DNS query as a client sends it, over UDP and TCP, blocking on and
//! off: the engine must decide it without panicking, and whatever it
//! answers must parse as a DNS response to that query.
#![no_main]

use hickory_proto::op::Message;
use libfuzzer_sys::fuzz_target;
use sinkd_core::config::{Blocking, SpecialNames};
use sinkd_core::{Domain, DomainMatcher, Scope};
use sinkd_resolver::{Decision, Engine, Transport, UDP_PAYLOAD};
use std::sync::OnceLock;

fn engine() -> &'static Engine {
    static ENGINE: OnceLock<Engine> = OnceLock::new();
    ENGINE.get_or_init(|| {
        let mut b = DomainMatcher::builder();
        let d = |s| Domain::parse(s).expect("domain");
        b.block(&d("ads.example"), Scope::Subtree).expect("block");
        b.block(&d("tracker.example"), Scope::Subdomains)
            .expect("block");
        b.allow(&d("ok.ads.example"), Scope::Subtree)
            .expect("allow");
        Engine::new(b.build(), Blocking::default()).with_special_names(SpecialNames::default())
    })
}

fuzz_target!(|packet: &[u8]| {
    for transport in [Transport::Udp, Transport::Tcp] {
        for blocking in [true, false] {
            match engine().decide_as(packet, transport, blocking) {
                Decision::Drop => {}
                Decision::Blocked(bytes) | Decision::Local(bytes) | Decision::Error(bytes) => {
                    if transport == Transport::Udp {
                        assert!(
                            bytes.len() <= usize::from(UDP_PAYLOAD),
                            "{} bytes",
                            bytes.len()
                        );
                    }
                    let reply = Message::from_vec(&bytes).expect("our replies parse");
                    assert_eq!(&reply.metadata.id.to_be_bytes()[..], &packet[..2]);
                }
                Decision::Forward(forward) => {
                    let query = forward.upstream_query();
                    let bytes = query.to_vec().expect("upstream queries serialize");
                    Message::from_vec(&bytes).expect("upstream queries parse");
                    let _ = forward.cache_key();
                    let _ = forward.servfail();
                    let _ = forward.describe();
                }
            }
        }
    }
});
