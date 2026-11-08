//! Caching upstream answers: TTL-respecting (RFC 1035 §7.4), with negative
//! caching (RFC 2308) and serving stale answers when every upstream fails
//! (RFC 8767).
//!
//! - **Key**: the question (name in lower case, type, class) plus the DO
//!   and CD bits, which change what an upstream sends back.
//! - **TTL**: the lowest TTL in the answer section, clamped to
//!   `cache.min_ttl_secs`..`cache.max_ttl_secs`. A negative answer
//!   (NXDOMAIN, or NOERROR with no answer) lives for the lesser of its SOA's
//!   TTL and MINIMUM, capped at `cache.max_negative_ttl_secs`; one without an
//!   SOA is not cached (RFC 2308 §5). Nothing with TTL 0 is cached, and
//!   neither are truncated answers or errors such as SERVFAIL.
//! - **Served** TTLs count down: an answer cached 100 s ago with TTL 300
//!   goes out with 200.
//! - **Stale**: an expired entry is kept for `cache.serve_stale_secs` more.
//!   It is used only when no upstream answers, with a 30 s TTL, so the
//!   client asks again soon.
//!
//! Blocking is never cached here: the name in the question is checked on
//! every query, and CNAME uncloaking runs on every answer served, cached
//! or not. A list change therefore applies to cached names at once.
//!
//! The store is moka (TinyLFU admission, per-entry expiry), bounded by
//! `cache.max_entries`.

use std::sync::Arc;
use std::time::{Duration, Instant};

use hickory_proto::op::{Message, ResponseCode};
use hickory_proto::rr::{RData, Record};
use moka::Expiry;
use moka::sync::Cache;
use sinkhole_core::config::Cache as Settings;

/// TTL of a stale answer (RFC 8767 §4 recommends 30 s).
pub const STALE_TTL: u32 = 30;

/// What a cached answer is filed under.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Key {
    /// The question's name in lower case, in presentation form.
    pub(crate) name: Box<str>,
    pub(crate) record_type: u16,
    pub(crate) class: u16,
    pub(crate) dnssec_ok: bool,
    pub(crate) checking_disabled: bool,
}

#[derive(Debug)]
struct Entry {
    answer: Message,
    stored: Instant,
    ttl: u32,
}

impl Entry {
    fn age(&self) -> u32 {
        u32::try_from(self.stored.elapsed().as_secs()).unwrap_or(u32::MAX)
    }
}

/// How long moka keeps an entry: its TTL plus the stale window.
struct Lifetime {
    stale: u32,
}

impl Expiry<Key, Arc<Entry>> for Lifetime {
    fn expire_after_create(&self, _: &Key, entry: &Arc<Entry>, _: Instant) -> Option<Duration> {
        Some(Duration::from_secs(
            u64::from(entry.ttl) + u64::from(self.stale),
        ))
    }

    fn expire_after_update(
        &self,
        key: &Key,
        entry: &Arc<Entry>,
        updated_at: Instant,
        _: Option<Duration>,
    ) -> Option<Duration> {
        self.expire_after_create(key, entry, updated_at)
    }
}

/// The answer cache. Cheap to share; a reload that keeps the upstreams and
/// the cache settings keeps the cache.
pub struct AnswerCache {
    entries: Option<Cache<Key, Arc<Entry>>>,
    settings: Settings,
}

impl std::fmt::Debug for AnswerCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AnswerCache")
            .field("entries", &self.len())
            .field("settings", &self.settings)
            .finish()
    }
}

impl AnswerCache {
    /// `max_entries = 0` turns the cache off.
    pub fn new(settings: &Settings) -> Self {
        let entries = (settings.max_entries > 0).then(|| {
            Cache::builder()
                .max_capacity(settings.max_entries as u64)
                .expire_after(Lifetime {
                    stale: settings.serve_stale_secs,
                })
                .build()
        });
        AnswerCache {
            entries,
            settings: settings.clone(),
        }
    }

    /// A cache that stores nothing.
    pub fn disabled() -> Self {
        Self::new(&Settings {
            max_entries: 0,
            ..Settings::default()
        })
    }

    pub fn settings(&self) -> &Settings {
        &self.settings
    }

    /// Entries held, fresh or stale. Approximate: moka evicts lazily.
    pub fn len(&self) -> u64 {
        self.entries.as_ref().map_or(0, |c| {
            c.run_pending_tasks();
            c.entry_count()
        })
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// A fresh answer, with its TTLs counted down.
    pub fn fresh(&self, key: &Key) -> Option<Message> {
        let entry = self.entries.as_ref()?.get(key)?;
        let age = entry.age();
        (age < entry.ttl).then(|| aged(&entry.answer, age, entry.ttl - age))
    }

    /// Any answer still held: fresh ones as from [`fresh`](Self::fresh),
    /// expired ones with every TTL set to [`STALE_TTL`]. For when no
    /// upstream answers.
    pub fn stale(&self, key: &Key) -> Option<Message> {
        let entry = self.entries.as_ref()?.get(key)?;
        let age = entry.age();
        if age < entry.ttl {
            return Some(aged(&entry.answer, age, entry.ttl - age));
        }
        let mut answer = entry.answer.clone();
        for record in records_mut(&mut answer) {
            record.ttl = STALE_TTL;
        }
        Some(answer)
    }

    /// Stores `answer` if it is cacheable.
    pub fn insert(&self, key: Key, answer: &Message) {
        let Some(entries) = &self.entries else {
            return;
        };
        let Some(ttl) = cache_ttl(answer, &self.settings) else {
            return;
        };
        let mut answer = answer.clone();
        // Per hop; set again for each client.
        answer.metadata.id = 0;
        answer.edns = None;
        answer.signature = None;
        entries.insert(
            key,
            Arc::new(Entry {
                answer,
                stored: Instant::now(),
                ttl,
            }),
        );
    }
}

fn records_mut(answer: &mut Message) -> impl Iterator<Item = &mut Record> {
    answer
        .answers
        .iter_mut()
        .chain(answer.authorities.iter_mut())
        .chain(answer.additionals.iter_mut())
}

/// `answer` as it looks `age` seconds after it was cached: each TTL lowered
/// by the age and never above what is left of the entry. At least 1, so a
/// clamped-up entry does not go out with TTL 0.
fn aged(answer: &Message, age: u32, left: u32) -> Message {
    let mut answer = answer.clone();
    for record in records_mut(&mut answer) {
        record.ttl = record.ttl.saturating_sub(age).min(left).max(1);
    }
    answer
}

/// How long `answer` may be cached, or `None` if it may not.
pub(crate) fn cache_ttl(answer: &Message, settings: &Settings) -> Option<u32> {
    if answer.metadata.truncation {
        return None;
    }
    if !matches!(
        answer.metadata.response_code,
        ResponseCode::NoError | ResponseCode::NXDomain
    ) {
        return None;
    }
    let ttl = if answer.answers.is_empty() {
        // RFC 2308 §5: the lesser of the SOA record's TTL and its MINIMUM.
        let negative = answer.authorities.iter().find_map(|r| match &r.data {
            RData::SOA(soa) => Some(r.ttl.min(soa.minimum)),
            _ => None,
        })?;
        negative.min(settings.max_negative_ttl_secs)
    } else {
        let lowest = answer.answers.iter().map(|r| r.ttl).min()?;
        lowest.max(settings.min_ttl_secs).min(settings.max_ttl_secs)
    };
    (ttl > 0).then_some(ttl)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::{OpCode, Query};
    use hickory_proto::rr::rdata::{A, CNAME, SOA};
    use hickory_proto::rr::{Name, RecordType};
    use std::net::Ipv4Addr;

    fn name(s: &str) -> Name {
        Name::from_ascii(s).unwrap()
    }

    fn key(n: &str) -> Key {
        Key {
            name: n.into(),
            record_type: 1,
            class: 1,
            dnssec_ok: false,
            checking_disabled: false,
        }
    }

    fn response(code: ResponseCode) -> Message {
        let mut m = Message::response(7, OpCode::Query);
        m.metadata.response_code = code;
        m.add_query(Query::query(name("a.example."), RecordType::A));
        m
    }

    fn a(owner: &str, ttl: u32) -> Record {
        Record::from_rdata(name(owner), ttl, RData::A(A(Ipv4Addr::new(192, 0, 2, 1))))
    }

    fn soa(ttl: u32, minimum: u32) -> Record {
        Record::from_rdata(
            name("example."),
            ttl,
            RData::SOA(SOA::new(
                name("ns.example."),
                name("host.example."),
                1,
                3600,
                600,
                86400,
                minimum,
            )),
        )
    }

    #[test]
    fn positive_ttl_is_the_lowest_clamped() {
        let s = Settings::default();
        let mut m = response(ResponseCode::NoError);
        m.add_answer(Record::from_rdata(
            name("a.example."),
            300,
            RData::CNAME(CNAME(name("b.example."))),
        ));
        m.add_answer(a("b.example.", 60));
        assert_eq!(cache_ttl(&m, &s), Some(60));
        let clamped = Settings {
            min_ttl_secs: 120,
            max_ttl_secs: 200,
            ..Settings::default()
        };
        assert_eq!(cache_ttl(&m, &clamped), Some(120));
        m.answers[1].ttl = 0;
        assert_eq!(cache_ttl(&m, &s), None, "TTL 0 is not cached");
        assert_eq!(cache_ttl(&m, &clamped), Some(120), "unless min_ttl says so");
        m.answers[1].ttl = 100_000;
        m.answers[0].ttl = 100_000;
        assert_eq!(cache_ttl(&m, &clamped), Some(200));
    }

    #[test]
    fn negative_ttl_follows_rfc_2308() {
        let s = Settings::default();
        let mut m = response(ResponseCode::NXDomain);
        assert_eq!(cache_ttl(&m, &s), None, "no SOA, not cached");
        m.add_authority(soa(900, 300));
        assert_eq!(cache_ttl(&m, &s), Some(300));
        m.authorities[0] = soa(120, 300);
        assert_eq!(cache_ttl(&m, &s), Some(120));
        m.authorities[0] = soa(86_400, 86_400);
        assert_eq!(cache_ttl(&m, &s), Some(s.max_negative_ttl_secs));
        // NODATA is negative too.
        let mut nodata = response(ResponseCode::NoError);
        nodata.add_authority(soa(60, 60));
        assert_eq!(cache_ttl(&nodata, &s), Some(60));
    }

    #[test]
    fn errors_and_truncated_answers_are_not_cached() {
        let s = Settings::default();
        let mut m = response(ResponseCode::ServFail);
        m.add_answer(a("a.example.", 300));
        assert_eq!(cache_ttl(&m, &s), None);
        let mut m = response(ResponseCode::NoError);
        m.add_answer(a("a.example.", 300));
        m.metadata.truncation = true;
        assert_eq!(cache_ttl(&m, &s), None);
    }

    #[test]
    fn served_ttls_count_down() {
        let mut m = response(ResponseCode::NoError);
        m.add_answer(a("a.example.", 300));
        m.add_authority(soa(900, 300));
        let aged = aged(&m, 100, 200);
        assert_eq!(aged.answers[0].ttl, 200);
        assert_eq!(aged.authorities[0].ttl, 200, "never above what is left");
        let late = super::aged(&m, 299, 1);
        assert_eq!(late.answers[0].ttl, 1);
        let clamped = super::aged(&m, 400, 20);
        assert_eq!(clamped.answers[0].ttl, 1, "at least 1");
    }

    #[test]
    fn store_and_fetch() {
        let cache = AnswerCache::new(&Settings::default());
        let mut m = response(ResponseCode::NoError);
        m.add_answer(a("a.example.", 300));
        m.set_edns(hickory_proto::op::Edns::new());
        cache.insert(key("a.example."), &m);
        let hit = cache.fresh(&key("a.example.")).unwrap();
        assert_eq!(hit.answers, m.answers);
        assert_eq!(hit.metadata.id, 0);
        assert!(hit.edns.is_none(), "EDNS is per hop");
        assert!(cache.fresh(&key("b.example.")).is_none());
        let other_flags = Key {
            dnssec_ok: true,
            ..key("a.example.")
        };
        assert!(
            cache.fresh(&other_flags).is_none(),
            "DO bit is part of the key"
        );

        let off = AnswerCache::disabled();
        off.insert(key("a.example."), &m);
        assert!(off.fresh(&key("a.example.")).is_none());
        assert!(off.is_empty());
    }

    #[test]
    fn stale_entries_need_a_window() {
        let mut m = response(ResponseCode::NoError);
        m.add_answer(a("a.example.", 1));
        let cache = AnswerCache::new(&Settings::default());
        cache.insert(key("a.example."), &m);
        std::thread::sleep(Duration::from_millis(1100));
        assert!(cache.fresh(&key("a.example.")).is_none(), "expired");
        let stale = cache.stale(&key("a.example.")).unwrap();
        assert_eq!(stale.answers[0].ttl, STALE_TTL);

        let no_stale = AnswerCache::new(&Settings {
            serve_stale_secs: 0,
            ..Settings::default()
        });
        no_stale.insert(key("a.example."), &m);
        std::thread::sleep(Duration::from_millis(1100));
        assert!(no_stale.stale(&key("a.example.")).is_none());
    }

    #[test]
    fn bounded_by_max_entries() {
        let cache = AnswerCache::new(&Settings {
            max_entries: 100,
            ..Settings::default()
        });
        for i in 0..1000 {
            let mut m = response(ResponseCode::NoError);
            m.add_answer(a("a.example.", 300));
            cache.insert(key(&format!("n{i}.example.")), &m);
        }
        assert!(cache.len() <= 100, "{}", cache.len());
    }
}
