//! Deciding what to do with one query, without I/O.
//!
//! [`Engine::decide`] turns the bytes of a query into a [`Decision`]: answer
//! it here (blocked names; malformed or unsupported queries), forward it, or
//! drop it. A forwarded query carries what is needed to build the upstream
//! query and to turn the upstream's answer into the reply ([`Forward`]).

use std::net::{Ipv4Addr, Ipv6Addr};

use hickory_proto::op::{Edns, Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA, PTR, SOA};
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};
use sinkd_core::config::{BlockResponse, Blocking, SpecialNames};
use sinkd_core::{DomainMatcher, QueryName, Verdict};
use tracing::debug;

use crate::cache::Key;
use crate::special::{Special, classify, soa_owner};

/// The UDP payload size sinkd advertises upstream and to clients, and the
/// most it sends a client over UDP: the DNS Flag Day 2020 value. It fits one
/// packet on any common path, so nothing is ever fragmented (fragments are
/// lost often and are a spoofing vector). Larger answers go over TCP.
pub const UDP_PAYLOAD: u16 = 1232;

/// RFC 1035 limit for UDP replies to clients that do not speak EDNS.
const CLASSIC_UDP: usize = 512;
const HEADER_LEN: usize = 12;
/// TTL of answers about special names (`localhost`, private reverse zones).
const LOCAL_TTL: u32 = 300;

/// How the reply travels back to the client, which bounds its size.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    Udp,
    Tcp,
}

/// What to do with one query.
#[derive(Debug)]
pub enum Decision {
    /// Send nothing: the message is too short to carry an ID, or it is itself
    /// a response (answering responses can make two resolvers loop).
    Drop,
    /// A blocked name, answered here.
    Blocked(Vec<u8>),
    /// A special name answered here: `localhost`, a private reverse zone,
    /// the Firefox canary and the like (see [`crate::special`]).
    Local(Vec<u8>),
    /// An error answered here: FORMERR, NOTIMP, REFUSED or BADVERS.
    Error(Vec<u8>),
    /// Resolve upstream.
    Forward(Forward),
}

/// Decides queries against the lists. Immutable: a reload builds a new
/// engine and swaps it in (see [`crate::PolicyHandle`]).
#[derive(Debug)]
pub struct Engine {
    matcher: DomainMatcher,
    blocking: Blocking,
    special: SpecialNames,
    soa_mname: Name,
    soa_rname: Name,
}

impl Engine {
    pub fn new(matcher: DomainMatcher, blocking: Blocking) -> Self {
        // `.invalid` (RFC 6761) can never exist, so the SOA of a block answer
        // cannot be mistaken for a real zone's.
        let name = |s: &str| Name::from_ascii(s).unwrap_or_else(|_| Name::root());
        Engine {
            matcher,
            blocking,
            special: SpecialNames::default(),
            soa_mname: name("sinkd.invalid."),
            soa_rname: name("blocked.sinkd.invalid."),
        }
    }

    pub fn with_special_names(mut self, special: SpecialNames) -> Self {
        self.special = special;
        self
    }

    pub fn matcher(&self) -> &DomainMatcher {
        &self.matcher
    }

    /// The list entry that blocks `name` (lower case, no trailing dot).
    pub fn blocking_rule(&self, name: &str) -> Option<String> {
        match self.matcher.check(name) {
            Verdict::Blocked { rule, .. } => Some(rule.to_owned()),
            _ => None,
        }
    }

    /// Decides one query that arrived over `transport`. Never panics,
    /// whatever the bytes.
    pub fn decide(&self, packet: &[u8], transport: Transport) -> Decision {
        self.decide_as(packet, transport, true)
    }

    /// [`Engine::decide`], with blocking switched off when `blocking` is
    /// false (`sinkd pause`): listed names are forwarded and answers are
    /// not uncloaked. Special names are still answered here, the Firefox
    /// canary included, so pausing does not send Firefox to its own DoH.
    pub fn decide_as(&self, packet: &[u8], transport: Transport, blocking: bool) -> Decision {
        let Some(&[id_hi, id_lo, flags, ..]) = packet.get(..HEADER_LEN) else {
            return Decision::Drop;
        };
        if flags & 0x80 != 0 {
            return Decision::Drop;
        }
        let raw = |code| Decision::Error(raw_error([id_hi, id_lo], flags, code));
        // Standard queries only. NOTIFY, UPDATE and the rest are for
        // authoritative servers.
        if (flags >> 3) & 0x0f != 0 {
            return raw(ResponseCode::NotImp);
        }
        let Ok(message) = Message::from_vec(packet) else {
            return raw(ResponseCode::FormErr);
        };
        let [query] = message.queries.as_slice() else {
            return raw(ResponseCode::FormErr);
        };
        let request = Request {
            id: message.metadata.id,
            recursion_desired: message.metadata.recursion_desired,
            checking_disabled: message.metadata.checking_disabled,
            authentic_data: message.metadata.authentic_data,
            query: query.clone(),
            edns: message.edns.as_ref().map(|e| ClientEdns {
                dnssec_ok: e.flags().dnssec_ok,
                max_payload: e.max_payload(),
            }),
            transport,
        };
        let error = |code| Decision::Error(request.encode(request.response(code)));
        // RFC 6891 §6.1.3: we speak EDNS version 0 only.
        if message.edns.as_ref().is_some_and(|e| e.version() > 0) {
            return error(ResponseCode::BADVERS);
        }
        // Zone transfers are for secondary servers, not stub clients.
        if matches!(query.query_type(), RecordType::AXFR | RecordType::IXFR) {
            return error(ResponseCode::Refused);
        }
        let internet = matches!(query.query_class(), DNSClass::IN | DNSClass::ANY);
        let name = internet.then(|| query_name(query.name())).flatten();
        let listed = match &name {
            Some(name) if self.blockable(query) => self.matcher.check(name.as_str()),
            _ => Verdict::NotListed,
        };
        let listed = match listed {
            Verdict::Blocked { .. } if !blocking => Verdict::NotListed,
            listed => listed,
        };
        let allowed = matches!(listed, Verdict::Allowed { .. });
        if let Some(special) = name.as_ref().and_then(|n| classify(n.as_str()))
            && let Some(answer) = self.special_answer(&request, special, allowed)
        {
            return Decision::Local(request.encode(answer));
        }
        if let Verdict::Blocked { rule, .. } = listed {
            let owner = soa_name(rule).unwrap_or_else(|| request.query.name().clone());
            return Decision::Blocked(request.encode(self.block_response(&request, owner)));
        }
        let uncloak = blocking
            && self.blocking.cname_uncloaking
            && name.is_some()
            && self.blockable(query)
            && !allowed;
        Decision::Forward(Forward { request, uncloak })
    }

    /// Whether the lists apply to this query type at all.
    fn blockable(&self, query: &Query) -> bool {
        self.blocking.block_https_records
            || !matches!(query.query_type(), RecordType::HTTPS | RecordType::SVCB)
    }

    /// The local answer for a special name, or `None` to forward it.
    fn special_answer(
        &self,
        request: &Request,
        special: Special,
        allowed: bool,
    ) -> Option<Message> {
        let qtype = request.query.query_type();
        let name = request.query.name().clone();
        let local = |rdata: RData| {
            let mut m = request.response(ResponseCode::NoError);
            m.add_answer(Record::from_rdata(name.clone(), LOCAL_TTL, rdata));
            m
        };
        let negative = |code: ResponseCode, ttl: u32| {
            let mut m = request.response(code);
            let owner = soa_name(soa_owner(special)).unwrap_or_else(|| name.clone());
            m.add_authority(self.soa(owner, ttl));
            m
        };
        Some(match special {
            Special::Localhost => match qtype {
                RecordType::A => local(RData::A(A(Ipv4Addr::LOCALHOST))),
                RecordType::AAAA => local(RData::AAAA(AAAA(Ipv6Addr::LOCALHOST))),
                _ => negative(ResponseCode::NoError, LOCAL_TTL),
            },
            Special::LoopbackReverse => match (qtype, soa_name("localhost")) {
                (RecordType::PTR, Some(localhost)) => local(RData::PTR(PTR(localhost))),
                _ => negative(ResponseCode::NoError, LOCAL_TTL),
            },
            Special::Never { .. } => negative(ResponseCode::NXDomain, LOCAL_TTL),
            Special::Private { .. } if self.special.forward_private => return None,
            Special::Private { .. } => negative(ResponseCode::NXDomain, LOCAL_TTL),
            // An explicit allow means the user wants Firefox's own DoH.
            Special::Canary if allowed => return None,
            Special::Canary => negative(ResponseCode::NXDomain, self.blocking.ttl_secs),
            Special::Ddr => negative(ResponseCode::NoError, LOCAL_TTL),
        })
    }

    /// The block answer for `forward` if its upstream answer is cloaked: a
    /// CNAME in the chain, or an HTTPS/SVCB target, is a blocked name. Run
    /// on every answer served, cached or fresh, so it follows the lists in
    /// force. Names on the allowlist are never uncloaked.
    pub fn uncloak(&self, forward: &Forward, answer: &Message) -> Option<Vec<u8>> {
        if !forward.uncloak {
            return None;
        }
        for record in &answer.answers {
            let target = match &record.data {
                RData::CNAME(cname) => &cname.0,
                RData::HTTPS(https) => &https.0.target_name,
                RData::SVCB(svcb) => &svcb.target_name,
                _ => continue,
            };
            // An HTTPS target of "." means the owner itself.
            let Some(target_name) = query_name(target) else {
                continue;
            };
            if let Verdict::Blocked { rule, .. } = self.matcher.check(target_name.as_str()) {
                debug!(query = %forward.query().name(), via = %target, rule, "uncloaked");
                let request = &forward.request;
                // The SOA owner must enclose the query name; the rule names
                // the CNAME target instead.
                let owner = request.query.name().clone();
                return Some(request.encode(self.block_response(request, owner)));
            }
        }
        None
    }

    fn block_response(&self, request: &Request, soa_owner: Name) -> Message {
        let ttl = self.blocking.ttl_secs;
        let name = request.query.name().clone();
        let address = match request.query.query_type() {
            RecordType::A => Some(RData::A(A(Ipv4Addr::UNSPECIFIED))),
            RecordType::AAAA => Some(RData::AAAA(AAAA(Ipv6Addr::UNSPECIFIED))),
            _ => None,
        };
        match (self.blocking.response, address) {
            (BlockResponse::NullAddress, Some(rdata)) => {
                let mut m = request.response(ResponseCode::NoError);
                m.add_answer(Record::from_rdata(name, ttl, rdata));
                m
            }
            // NODATA: the name exists but has no records of this type. This
            // also covers HTTPS/SVCB, so browsers learn no alternative
            // endpoints or ECH keys for a blocked name.
            (BlockResponse::NullAddress, None) => {
                let mut m = request.response(ResponseCode::NoError);
                m.add_authority(self.soa(soa_owner, ttl));
                m
            }
            (BlockResponse::Nxdomain, _) => {
                let mut m = request.response(ResponseCode::NXDomain);
                m.add_authority(self.soa(soa_owner, ttl));
                m
            }
        }
    }

    /// The SOA record that lets clients cache a negative answer for `ttl`
    /// (RFC 2308 §5). Its owner stands in for the zone apex: for a block,
    /// the list entry that matched, which is the query name or a parent of
    /// it.
    fn soa(&self, owner: Name, ttl: u32) -> Record {
        let soa = SOA::new(
            self.soa_mname.clone(),
            self.soa_rname.clone(),
            1,
            3_600,
            600,
            86_400,
            ttl,
        );
        Record::from_rdata(owner, ttl, RData::SOA(soa))
    }
}

/// The name and type a query asks, for the query log: `None` if the bytes
/// are not a query with one question.
pub fn question(packet: &[u8]) -> Option<(String, String)> {
    let message = Message::from_vec(packet).ok()?;
    let [query] = message.queries.as_slice() else {
        return None;
    };
    Some(describe(query))
}

fn describe(query: &Query) -> (String, String) {
    let name = query_name(query.name()).map_or_else(
        || query.name().to_lowercase().to_ascii(),
        |n| n.as_str().to_owned(),
    );
    (name, query.query_type().to_string())
}

/// `name` as a fully qualified DNS name.
fn soa_name(name: &str) -> Option<Name> {
    let mut name = Name::from_ascii(name).ok()?;
    name.set_fqdn(true);
    Some(name)
}

/// A query to resolve upstream, with what is needed to reply to the client.
#[derive(Debug, Clone)]
pub struct Forward {
    request: Request,
    /// Check the answer's CNAMEs against the lists (see [`Engine::uncloak`]).
    uncloak: bool,
}

impl Forward {
    /// A query sinkd makes on its own behalf, such as the address of a
    /// list server. It never passes the lists (a list must not be able to
    /// block its own updates) and goes straight to the upstreams.
    pub fn lookup(name: Name, record_type: RecordType) -> Forward {
        Forward {
            request: Request {
                id: 0,
                recursion_desired: true,
                checking_disabled: false,
                authentic_data: false,
                query: Query::query(name, record_type),
                edns: None,
                transport: Transport::Tcp,
            },
            uncloak: false,
        }
    }

    /// Where an answer to this query is cached, or `None` if it is not
    /// cacheable: a client that sets RD=0 wants what the upstream has
    /// without recursion, which is not what other clients want.
    pub fn cache_key(&self) -> Option<Key> {
        let r = &self.request;
        r.recursion_desired.then(|| Key {
            name: r.query.name().to_lowercase().to_ascii().into_boxed_str(),
            record_type: u16::from(r.query.query_type()),
            class: u16::from(r.query.query_class()),
            dnssec_ok: r.edns.is_some_and(|e| e.dnssec_ok),
            checking_disabled: r.checking_disabled,
        })
    }

    pub fn query(&self) -> &Query {
        &self.request.query
    }

    /// The name (lower case, no trailing dot) and type asked, for the
    /// query log.
    pub fn describe(&self) -> (String, String) {
        describe(&self.request.query)
    }

    /// The message to send upstream, with a fresh random ID.
    ///
    /// It carries the client's question (in the client's spelling) and its
    /// RD, CD and AD bits, the DO bit included, so DNSSEC-aware clients get
    /// what they asked for. The EDNS record is our own: options such as EDNS
    /// Client Subnet and cookies are hop-by-hop (RFC 6891 §6.1.1), and Client
    /// Subnet would tell the upstream which network the client is on.
    pub fn upstream_query(&self) -> Message {
        let r = &self.request;
        // The ID comes from rand's thread-local CSPRNG. With the random source
        // port of a fresh socket, it is what stops off-path spoofing of plain
        // DNS answers until the upstream link is encrypted (milestone 4).
        let mut m = Message::query();
        m.metadata.recursion_desired = r.recursion_desired;
        m.metadata.checking_disabled = r.checking_disabled;
        m.metadata.authentic_data = r.authentic_data;
        m.add_query(r.query.clone());
        m.edns = Some(our_edns(r.edns.is_some_and(|e| e.dnssec_ok)));
        m
    }

    /// Whether `response` is the upstream's answer to `query`: the same ID, a
    /// response to a standard query, and the same question. Anything else is
    /// ignored, whatever it claims.
    pub fn is_answer(&self, query: &Message, response: &Message) -> bool {
        let meta = &response.metadata;
        if meta.id != query.metadata.id
            || meta.message_type != MessageType::Response
            || meta.op_code != OpCode::Query
        {
            return false;
        }
        let asked = &self.request.query;
        match response.queries.as_slice() {
            // Name comparison is case-insensitive, as DNS is.
            [q] => {
                q.name() == asked.name()
                    && q.query_type() == asked.query_type()
                    && q.query_class() == asked.query_class()
            }
            // Some servers leave the question out of error responses.
            [] => !matches!(
                meta.response_code,
                ResponseCode::NoError | ResponseCode::NXDomain
            ),
            _ => false,
        }
    }

    /// Turns the upstream's answer into the reply for the client: the
    /// client's ID, flags and spelling of the question (so 0x20 case
    /// randomization checks pass), and our EDNS record if the client sent one.
    pub fn reply(&self, upstream: Message) -> Vec<u8> {
        let r = &self.request;
        if r.edns.is_none() && upstream.metadata.response_code.high() != 0 {
            // An extended RCODE cannot be expressed without EDNS.
            return self.servfail();
        }
        let mut m = upstream;
        m.metadata.id = r.id;
        m.metadata.recursion_desired = r.recursion_desired;
        m.metadata.recursion_available = true;
        m.metadata.checking_disabled = r.checking_disabled;
        m.metadata.truncation = false;
        // RFC 6840 §5.8: AD only for clients that asked with AD or DO. A
        // cached answer may have been fetched for one that did.
        m.metadata.authentic_data &= r.authentic_data || r.edns.is_some_and(|e| e.dnssec_ok);
        m.queries = vec![r.query.clone()];
        m.signature = None;
        m.edns = r.edns.map(|e| our_edns(e.dnssec_ok));
        r.encode(m)
    }

    /// The reply when no upstream could answer. Prompt SERVFAIL lets the
    /// client give up or try elsewhere instead of waiting out its timeout.
    pub fn servfail(&self) -> Vec<u8> {
        self.request
            .encode(self.request.response(ResponseCode::ServFail))
    }
}

/// The parts of a query needed to answer it.
#[derive(Debug, Clone)]
struct Request {
    id: u16,
    recursion_desired: bool,
    checking_disabled: bool,
    authentic_data: bool,
    query: Query,
    edns: Option<ClientEdns>,
    transport: Transport,
}

#[derive(Debug, Clone, Copy)]
struct ClientEdns {
    dnssec_ok: bool,
    max_payload: u16,
}

impl Request {
    /// A reply skeleton: the client's ID, question and flags, and our EDNS
    /// record if the client sent one (RFC 6891 §6.1.1 requires it).
    fn response(&self, code: ResponseCode) -> Message {
        let mut m = Message::response(self.id, OpCode::Query);
        m.metadata.recursion_desired = self.recursion_desired;
        m.metadata.recursion_available = true;
        m.metadata.checking_disabled = self.checking_disabled;
        m.metadata.response_code = code;
        m.add_query(self.query.clone());
        m.edns = self.edns.map(|e| our_edns(e.dnssec_ok));
        m
    }

    /// The largest reply this client accepts.
    fn reply_limit(&self) -> usize {
        match self.transport {
            Transport::Tcp => usize::from(u16::MAX),
            Transport::Udp => self.edns.map_or(CLASSIC_UDP, |e| {
                usize::from(e.max_payload.clamp(CLASSIC_UDP as u16, UDP_PAYLOAD))
            }),
        }
    }

    /// Encodes `message`. One too big for the client is cut down to header,
    /// question and OPT with TC set, and the client retries over TCP
    /// (RFC 7766 §5). Records are never partially dropped: a partial answer
    /// would be cached as if complete.
    fn encode(&self, message: Message) -> Vec<u8> {
        match message.to_vec() {
            Ok(bytes) if bytes.len() <= self.reply_limit() => return bytes,
            Ok(_) => match message.truncate().to_vec() {
                Ok(bytes) => return bytes,
                Err(e) => debug!(error = %e, "could not encode truncated reply"),
            },
            Err(e) => debug!(error = %e, "could not encode reply"),
        }
        // A header and one question always encode; this is a last resort.
        let flags = u8::from(self.recursion_desired);
        raw_error(self.id.to_be_bytes(), flags, ResponseCode::ServFail)
    }
}

fn our_edns(dnssec_ok: bool) -> Edns {
    let mut edns = Edns::new();
    edns.set_max_payload(UDP_PAYLOAD);
    edns.set_dnssec_ok(dnssec_ok);
    edns
}

/// A header-only error reply for a query too broken to parse. `flags` is
/// byte 2 of the query header; its opcode and RD bit are echoed.
fn raw_error(id: [u8; 2], flags: u8, code: ResponseCode) -> Vec<u8> {
    let mut reply = vec![0; HEADER_LEN];
    reply[..2].copy_from_slice(&id);
    reply[2] = 0x80 | (flags & 0x79); // QR, opcode, RD
    reply[3] = 0x80 | code.low(); // RA, RCODE
    reply
}

/// A wire name as the matcher sees it: labels joined by dots, lowercased.
///
/// A label may legally contain any byte, dots included. Bytes that cannot
/// occur in a list entry (and dots inside a label, which would shift label
/// boundaries) become `\x01`. The matcher never probes a suffix containing
/// one, so `a\.b.ads.example` still matches `ads.example` but can never match
/// `b.ads.example`. `None` for the root.
pub fn query_name(name: &Name) -> Option<QueryName> {
    let mut text = String::with_capacity(name.len());
    for (i, label) in name.iter().enumerate() {
        if i > 0 {
            text.push('.');
        }
        text.extend(label.iter().map(|&b| {
            if b.is_ascii_graphic() && b != b'.' {
                char::from(b)
            } else {
                '\u{1}'
            }
        }));
    }
    QueryName::new(&text)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::rr::rdata::opt::{ClientSubnet, EdnsOption};
    use sinkd_core::{Domain, Scope};

    fn engine(response: BlockResponse) -> Engine {
        let mut b = DomainMatcher::builder();
        let d = |s| Domain::parse(s).unwrap();
        b.block(&d("ads.example"), Scope::Subtree).unwrap();
        b.block(&d("track.example"), Scope::Subdomains).unwrap();
        b.allow(&d("ok.ads.example"), Scope::Subtree).unwrap();
        Engine::new(
            b.build(),
            Blocking {
                response,
                ..Blocking::default()
            },
        )
    }

    fn query(name: &str, rtype: RecordType) -> Message {
        let mut m = Message::query();
        m.metadata.recursion_desired = true;
        m.add_query(Query::query(Name::from_ascii(name).unwrap(), rtype));
        m
    }

    fn decide(e: &Engine, m: &Message) -> Decision {
        e.decide(&m.to_vec().unwrap(), Transport::Udp)
    }

    fn blocked(e: &Engine, m: &Message) -> Message {
        match decide(e, m) {
            Decision::Blocked(bytes) => Message::from_vec(&bytes).unwrap(),
            other => panic!("expected a block answer, got {other:?}"),
        }
    }

    fn error_code(d: Decision) -> ResponseCode {
        match d {
            Decision::Error(bytes) => Message::from_vec(&bytes).unwrap().metadata.response_code,
            other => panic!("expected an error, got {other:?}"),
        }
    }

    #[test]
    fn query_names_as_the_matcher_sees_them() {
        let n = |s: &str| query_name(&Name::from_ascii(s).unwrap()).map(|q| q.as_str().to_owned());
        assert_eq!(n("WWW.Example.COM.").as_deref(), Some("www.example.com"));
        assert_eq!(n(".").as_deref(), None);
        let labels: [&[u8]; 3] = [b"a.b", b"ads", b"example"];
        let dotted = Name::from_labels(labels).unwrap();
        assert_eq!(query_name(&dotted).unwrap().as_str(), "a\u{1}b.ads.example");
        let binary = Name::from_labels([&b"x\0 y"[..], b"example"]).unwrap();
        assert_eq!(
            query_name(&binary).unwrap().as_str(),
            "x\u{1}\u{1}y.example"
        );
    }

    #[test]
    fn escaped_labels_cannot_forge_a_match() {
        let e = engine(BlockResponse::NullAddress);
        // `x.ads\.example` is two labels, `x` and `ads.example`: not a child
        // of `ads.example`.
        let labels: [&[u8]; 2] = [b"x", b"ads.example"];
        let mut m = Message::query();
        m.add_query(Query::query(
            Name::from_labels(labels).unwrap(),
            RecordType::A,
        ));
        assert!(matches!(decide(&e, &m), Decision::Forward(_)));
        // But a strange label below a blocked name is still blocked.
        let labels: [&[u8]; 3] = [b"a b", b"ads", b"example"];
        let mut m = Message::query();
        m.add_query(Query::query(
            Name::from_labels(labels).unwrap(),
            RecordType::A,
        ));
        assert!(matches!(decide(&e, &m), Decision::Blocked(_)));
    }

    #[test]
    fn null_address_answers() {
        let e = engine(BlockResponse::NullAddress);
        let r = blocked(&e, &query("Ads.Example.", RecordType::A));
        assert_eq!(r.metadata.response_code, ResponseCode::NoError);
        assert!(r.metadata.recursion_available && r.metadata.recursion_desired);
        assert_eq!(r.answers.len(), 1);
        assert_eq!(r.answers[0].data, RData::A(A(Ipv4Addr::UNSPECIFIED)));
        assert_eq!(r.answers[0].ttl, 10);
        // The question comes back in the client's spelling.
        assert!(
            r.queries[0]
                .name()
                .eq_case(&Name::from_ascii("Ads.Example.").unwrap())
        );

        let r = blocked(&e, &query("deep.sub.ads.example.", RecordType::AAAA));
        assert_eq!(r.answers[0].data, RData::AAAA(AAAA(Ipv6Addr::UNSPECIFIED)));
    }

    #[test]
    fn other_types_get_nodata_with_soa() {
        let e = engine(BlockResponse::NullAddress);
        for rtype in [
            RecordType::HTTPS,
            RecordType::SVCB,
            RecordType::MX,
            RecordType::TXT,
        ] {
            let r = blocked(&e, &query("x.ads.example.", rtype));
            assert_eq!(r.metadata.response_code, ResponseCode::NoError);
            assert!(r.answers.is_empty());
            let soa = &r.authorities[0];
            assert_eq!(soa.name, Name::from_ascii("ads.example.").unwrap());
            let RData::SOA(soa_data) = &soa.data else {
                panic!("not an SOA")
            };
            assert_eq!((soa.ttl, soa_data.minimum), (10, 10));
        }
    }

    #[test]
    fn nxdomain_mode() {
        let e = engine(BlockResponse::Nxdomain);
        let r = blocked(&e, &query("ads.example.", RecordType::A));
        assert_eq!(r.metadata.response_code, ResponseCode::NXDomain);
        assert!(r.answers.is_empty());
        assert_eq!(r.authorities[0].record_type(), RecordType::SOA);
    }

    #[test]
    fn https_records_can_be_left_alone() {
        let mut e = engine(BlockResponse::NullAddress);
        e.blocking.block_https_records = false;
        assert!(matches!(
            decide(&e, &query("ads.example.", RecordType::HTTPS)),
            Decision::Forward(_)
        ));
        assert!(matches!(
            decide(&e, &query("ads.example.", RecordType::A)),
            Decision::Blocked(_)
        ));
    }

    #[test]
    fn allowlist_and_scopes() {
        let e = engine(BlockResponse::NullAddress);
        let forwarded = |name| {
            matches!(
                decide(&e, &query(name, RecordType::A)),
                Decision::Forward(_)
            )
        };
        assert!(forwarded("ok.ads.example."));
        assert!(forwarded("a.ok.ads.example."));
        assert!(forwarded("track.example."));
        assert!(!forwarded("x.track.example."));
        assert!(forwarded("example."));
        assert!(forwarded("."));
    }

    #[test]
    fn non_internet_classes_are_forwarded() {
        let e = engine(BlockResponse::NullAddress);
        let mut m = query("ads.example.", RecordType::TXT);
        m.queries[0].set_query_class(DNSClass::CH);
        assert!(matches!(decide(&e, &m), Decision::Forward(_)));
    }

    #[test]
    fn broken_and_unsupported_queries() {
        let e = engine(BlockResponse::NullAddress);
        assert!(matches!(e.decide(b"", Transport::Udp), Decision::Drop));
        assert!(matches!(e.decide(&[0; 11], Transport::Udp), Decision::Drop));

        // Garbage after a valid header: FORMERR, same ID.
        let mut garbage = vec![0xab, 0xcd, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        garbage.extend_from_slice(&[0xff; 7]);
        let Decision::Error(bytes) = e.decide(&garbage, Transport::Udp) else {
            panic!()
        };
        let r = Message::from_vec(&bytes).unwrap();
        assert_eq!(
            (r.metadata.id, r.metadata.response_code),
            (0xabcd, ResponseCode::FormErr)
        );
        assert!(r.metadata.recursion_desired);

        // A response is never answered.
        let mut m = query("example.", RecordType::A);
        m.metadata.message_type = MessageType::Response;
        assert!(matches!(decide(&e, &m), Decision::Drop));

        // Two questions.
        let mut m = query("a.example.", RecordType::A);
        m.add_query(Query::query(
            Name::from_ascii("b.example.").unwrap(),
            RecordType::A,
        ));
        assert_eq!(error_code(decide(&e, &m)), ResponseCode::FormErr);

        // No question.
        let m = Message::query();
        assert_eq!(error_code(decide(&e, &m)), ResponseCode::FormErr);

        // NOTIFY.
        let mut m = query("example.", RecordType::SOA);
        m.metadata.op_code = OpCode::Notify;
        assert_eq!(error_code(decide(&e, &m)), ResponseCode::NotImp);

        // Zone transfer.
        assert_eq!(
            error_code(decide(&e, &query("example.", RecordType::AXFR))),
            ResponseCode::Refused
        );
    }

    #[test]
    fn edns_versions() {
        let e = engine(BlockResponse::NullAddress);
        let mut m = query("example.", RecordType::A);
        let mut edns = Edns::new();
        edns.set_version(1);
        m.set_edns(edns);
        let Decision::Error(bytes) = decide(&e, &m) else {
            panic!()
        };
        let r = Message::from_vec(&bytes).unwrap();
        // BADVERS shares code 16 with TSIG's BADSIG, which is what decoding
        // picks; the wire value is what matters.
        assert_eq!(u16::from(r.metadata.response_code), 16);
        assert_eq!(r.edns.as_ref().map(Edns::version), Some(0));
    }

    #[test]
    fn upstream_query_drops_client_options() {
        let e = engine(BlockResponse::NullAddress);
        let mut m = query("Example.", RecordType::A);
        m.metadata.checking_disabled = true;
        let mut edns = Edns::new();
        edns.set_max_payload(4096);
        edns.set_dnssec_ok(true);
        edns.options_mut()
            .insert(EdnsOption::Subnet(ClientSubnet::new(
                "192.0.2.0".parse().unwrap(),
                24,
                0,
            )));
        m.set_edns(edns);
        let Decision::Forward(f) = decide(&e, &m) else {
            panic!()
        };
        let up = f.upstream_query();
        // A fresh random ID for each upstream query.
        let ids: std::collections::HashSet<u16> =
            (0..8).map(|_| f.upstream_query().metadata.id).collect();
        assert!(ids.len() > 1);
        assert!(up.metadata.checking_disabled && up.metadata.recursion_desired);
        let edns = up.edns.as_ref().unwrap();
        assert!(edns.flags().dnssec_ok);
        assert_eq!(edns.max_payload(), UDP_PAYLOAD);
        assert!(
            edns.options().options.is_empty(),
            "client subnet must not leak"
        );
        assert!(
            up.queries[0]
                .name()
                .eq_case(&Name::from_ascii("Example.").unwrap())
        );
    }

    #[test]
    fn upstream_answers_are_checked() {
        let e = engine(BlockResponse::NullAddress);
        let Decision::Forward(f) = decide(&e, &query("example.", RecordType::A)) else {
            panic!()
        };
        let up = f.upstream_query();
        let answer = |id, name: &str, rtype| {
            let mut r = Message::response(id, OpCode::Query);
            r.add_query(Query::query(Name::from_ascii(name).unwrap(), rtype));
            r
        };
        let id = up.metadata.id;
        assert!(f.is_answer(&up, &answer(id, "EXAMPLE.", RecordType::A)));
        assert!(!f.is_answer(&up, &answer(id.wrapping_add(1), "example.", RecordType::A)));
        assert!(!f.is_answer(&up, &answer(id, "other.", RecordType::A)));
        assert!(!f.is_answer(&up, &answer(id, "example.", RecordType::AAAA)));
        let mut bare = Message::response(id, OpCode::Query);
        assert!(!f.is_answer(&up, &bare), "NOERROR without a question");
        bare.metadata.response_code = ResponseCode::Refused;
        assert!(f.is_answer(&up, &bare));
    }

    #[test]
    fn replies_fit_the_client() {
        let e = engine(BlockResponse::NullAddress);
        let big = || {
            let mut r = Message::response(1, OpCode::Query);
            for i in 0..60u8 {
                r.add_answer(Record::from_rdata(
                    Name::from_ascii("example.").unwrap(),
                    60,
                    RData::A(A(Ipv4Addr::new(192, 0, 2, i))),
                ));
            }
            r
        };
        // 60 A records are ~1 KB: too big for 512, fine for EDNS 1232.
        let Decision::Forward(f) = decide(&e, &query("example.", RecordType::A)) else {
            panic!()
        };
        let r = Message::from_vec(&f.reply(big())).unwrap();
        assert!(r.metadata.truncation && r.answers.is_empty());
        assert_eq!(r.queries.len(), 1);

        let mut m = query("example.", RecordType::A);
        m.set_edns(Edns::new());
        m.edns.as_mut().unwrap().set_max_payload(4096);
        let Decision::Forward(f) = decide(&e, &m) else {
            panic!()
        };
        let r = Message::from_vec(&f.reply(big())).unwrap();
        assert!(!r.metadata.truncation);
        assert_eq!(r.answers.len(), 60);
        assert_eq!(r.edns.as_ref().unwrap().max_payload(), UDP_PAYLOAD);

        let bytes = query("example.", RecordType::A).to_vec().unwrap();
        let Decision::Forward(f) = e.decide(&bytes, Transport::Tcp) else {
            panic!()
        };
        let r = Message::from_vec(&f.reply(big())).unwrap();
        assert!(!r.metadata.truncation && r.edns.is_none());
        assert_eq!(r.answers.len(), 60);
    }

    fn local(e: &Engine, m: &Message) -> Message {
        match decide(e, m) {
            Decision::Local(bytes) => Message::from_vec(&bytes).unwrap(),
            other => panic!("expected a local answer, got {other:?}"),
        }
    }

    fn forward(e: &Engine, m: &Message) -> Forward {
        match decide(e, m) {
            Decision::Forward(f) => f,
            other => panic!("expected a forward, got {other:?}"),
        }
    }

    #[test]
    fn special_names_are_answered_here() {
        let e = engine(BlockResponse::NullAddress);
        let r = local(&e, &query("app.localhost.", RecordType::A));
        assert_eq!(r.answers[0].data, RData::A(A(Ipv4Addr::LOCALHOST)));
        let r = local(&e, &query("localhost.", RecordType::AAAA));
        assert_eq!(r.answers[0].data, RData::AAAA(AAAA(Ipv6Addr::LOCALHOST)));
        let r = local(&e, &query("localhost.", RecordType::MX));
        assert_eq!(r.metadata.response_code, ResponseCode::NoError);
        assert!(r.answers.is_empty() && r.authorities.len() == 1);

        let r = local(&e, &query("1.0.0.127.in-addr.arpa.", RecordType::PTR));
        assert_eq!(
            r.answers[0].data,
            RData::PTR(PTR(Name::from_ascii("localhost.").unwrap()))
        );
        for name in [
            "x.invalid.",
            "5.1.168.192.in-addr.arpa.",
            "printer.local.",
            "use-application-dns.net.",
        ] {
            let r = local(&e, &query(name, RecordType::A));
            assert_eq!(r.metadata.response_code, ResponseCode::NXDomain, "{name}");
            assert!(matches!(r.authorities[0].data, RData::SOA(_)), "{name}");
        }
        let r = local(&e, &query("_dns.resolver.arpa.", RecordType::SVCB));
        assert_eq!(r.metadata.response_code, ResponseCode::NoError);
        assert!(r.answers.is_empty());
        // Public reverse lookups and other classes go upstream.
        forward(&e, &query("8.8.8.8.in-addr.arpa.", RecordType::PTR));
        let mut chaos = query("localhost.", RecordType::TXT);
        chaos.queries[0].set_query_class(DNSClass::CH);
        forward(&e, &chaos);
    }

    #[test]
    fn private_names_can_be_forwarded() {
        let e = engine(BlockResponse::NullAddress).with_special_names(SpecialNames {
            forward_private: true,
        });
        forward(&e, &query("5.1.168.192.in-addr.arpa.", RecordType::PTR));
        forward(&e, &query("nas.home.arpa.", RecordType::A));
        // Never-existing and loopback names stay local.
        local(&e, &query("x.invalid.", RecordType::A));
        local(&e, &query("localhost.", RecordType::A));
    }

    #[test]
    fn an_allowlisted_canary_is_forwarded() {
        let mut b = DomainMatcher::builder();
        b.allow(
            &Domain::parse("use-application-dns.net").unwrap(),
            Scope::Subtree,
        )
        .unwrap();
        let e = Engine::new(b.build(), Blocking::default());
        forward(&e, &query("use-application-dns.net.", RecordType::A));
    }

    fn cname_answer(f: &Forward, chain: &[&str]) -> Message {
        let up = f.upstream_query();
        let mut m = Message::response(up.metadata.id, OpCode::Query);
        m.add_query(up.queries[0].clone());
        let name = |s: &str| Name::from_ascii(s).unwrap();
        for pair in chain.windows(2) {
            m.add_answer(Record::from_rdata(
                name(pair[0]),
                300,
                RData::CNAME(hickory_proto::rr::rdata::CNAME(name(pair[1]))),
            ));
        }
        m.add_answer(Record::from_rdata(
            name(chain[chain.len() - 1]),
            300,
            RData::A(A(Ipv4Addr::new(192, 0, 2, 1))),
        ));
        m
    }

    #[test]
    fn cloaked_cnames_are_blocked() {
        let e = engine(BlockResponse::NullAddress);
        let f = forward(&e, &query("metrics.shop.test.", RecordType::A));
        let cloaked = cname_answer(
            &f,
            &["metrics.shop.test.", "edge.cdn.test.", "x.ads.example."],
        );
        let r = Message::from_vec(&e.uncloak(&f, &cloaked).unwrap()).unwrap();
        assert_eq!(r.answers.len(), 1);
        assert_eq!(
            r.answers[0].name,
            Name::from_ascii("metrics.shop.test.").unwrap()
        );
        assert_eq!(r.answers[0].data, RData::A(A(Ipv4Addr::UNSPECIFIED)));

        let clean = cname_answer(&f, &["metrics.shop.test.", "edge.cdn.test."]);
        assert!(e.uncloak(&f, &clean).is_none());
        // An allowed target is not blocked.
        let allowed = cname_answer(&f, &["metrics.shop.test.", "ok.ads.example."]);
        assert!(e.uncloak(&f, &allowed).is_none());
    }

    #[test]
    fn uncloaking_respects_the_allowlist_and_the_switch() {
        let e = engine(BlockResponse::NullAddress);
        // The query name itself is allowlisted: never uncloaked.
        let f = forward(&e, &query("ok.ads.example.", RecordType::A));
        let cloaked = cname_answer(&f, &["ok.ads.example.", "x.ads.example."]);
        assert!(e.uncloak(&f, &cloaked).is_none());

        let mut b = DomainMatcher::builder();
        b.block(&Domain::parse("ads.example").unwrap(), Scope::Subtree)
            .unwrap();
        let off = Engine::new(
            b.build(),
            Blocking {
                cname_uncloaking: false,
                ..Blocking::default()
            },
        );
        let f = forward(&off, &query("metrics.shop.test.", RecordType::A));
        let cloaked = cname_answer(&f, &["metrics.shop.test.", "x.ads.example."]);
        assert!(off.uncloak(&f, &cloaked).is_none());
    }

    #[test]
    fn https_targets_are_uncloaked() {
        use hickory_proto::rr::rdata::{HTTPS, SVCB};
        let e = engine(BlockResponse::NullAddress);
        let f = forward(&e, &query("www.shop.test.", RecordType::HTTPS));
        let up = f.upstream_query();
        let mut m = Message::response(up.metadata.id, OpCode::Query);
        m.add_query(up.queries[0].clone());
        let svcb = |target: &str| {
            RData::HTTPS(HTTPS(SVCB::new(
                1,
                Name::from_ascii(target).unwrap(),
                Vec::new(),
            )))
        };
        m.add_answer(Record::from_rdata(
            Name::from_ascii("www.shop.test.").unwrap(),
            300,
            svcb("."),
        ));
        assert!(e.uncloak(&f, &m).is_none(), "target . is the owner");
        m.answers[0].data = svcb("svc.ads.example.");
        let r = Message::from_vec(&e.uncloak(&f, &m).unwrap()).unwrap();
        assert!(r.answers.is_empty(), "HTTPS gets NODATA");
        assert!(matches!(r.authorities[0].data, RData::SOA(_)));
    }

    #[test]
    fn cache_keys() {
        let e = engine(BlockResponse::NullAddress);
        let key = |m: &Message| forward(&e, m).cache_key();
        let a = key(&query("Www.Example.", RecordType::A)).unwrap();
        assert_eq!(a, key(&query("www.example.", RecordType::A)).unwrap());
        assert_ne!(a, key(&query("www.example.", RecordType::AAAA)).unwrap());
        let mut with_do = query("www.example.", RecordType::A);
        let mut edns = Edns::new();
        edns.set_dnssec_ok(true);
        with_do.set_edns(edns);
        assert_ne!(a, key(&with_do).unwrap());
        let mut cd = query("www.example.", RecordType::A);
        cd.metadata.checking_disabled = true;
        assert_ne!(a, key(&cd).unwrap());
        let mut no_rd = query("www.example.", RecordType::A);
        no_rd.metadata.recursion_desired = false;
        assert_eq!(key(&no_rd), None, "RD=0 is not cached");
    }

    #[test]
    fn ad_bit_only_for_clients_that_ask() {
        let e = engine(BlockResponse::NullAddress);
        let f = forward(&e, &query("example.", RecordType::A));
        let up = f.upstream_query();
        let mut answer = Message::response(up.metadata.id, OpCode::Query);
        answer.add_query(up.queries[0].clone());
        answer.metadata.authentic_data = true;
        let r = Message::from_vec(&f.reply(answer.clone())).unwrap();
        assert!(!r.metadata.authentic_data);
        let mut asks = query("example.", RecordType::A);
        asks.metadata.authentic_data = true;
        let f = forward(&e, &asks);
        let r = Message::from_vec(&f.reply(answer)).unwrap();
        assert!(r.metadata.authentic_data);
    }
}
