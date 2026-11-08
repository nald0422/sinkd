//! The DNS domain matcher.
//!
//! Semantics, in order:
//!
//! 1. **The allowlist always wins.** If the queried name or any parent of it is
//!    allowlisted, the name is allowed, even if a more specific entry blocks it.
//! 2. **A blocked parent blocks its children.** A [`Scope::Subtree`] entry for
//!    `example.com` blocks `example.com` and every name below it.
//!    [`Scope::Subdomains`] (from `*.example.com`) blocks only the names below.
//! 3. Otherwise the name is not listed and gets forwarded upstream.
//!
//! # Representation
//!
//! A lookup walks the label-aligned suffixes of the query (`a.b.example.com`,
//! `b.example.com`, `example.com`, `com`) and probes a hash table once per
//! suffix. Each suffix is hashed once and that hash is used for both the allow
//! and the block table, which share one randomly seeded hasher.
//!
//! The tables are built for a million entries: every name lives once in a
//! single byte arena, each followed by a one-byte scope tag, and the hash table
//! stores only a `u32` arena offset per entry. That is about 23 bytes per name
//! in the arena plus about 5 bytes per name in the table, against about 60 for
//! a `HashSet<String>`. Tag bytes (0 and 1) never occur in a normalized name,
//! so they double as terminators: a stored name equals the probe exactly when
//! the arena bytes at its offset equal the probe and are followed by a tag.
//!
//! The hasher is seeded randomly per process, so a hostile list or query
//! stream cannot precompute collisions to degrade lookups.

use std::fmt;

use ahash::RandomState;
use hashbrown::HashTable;
use hashbrown::hash_table::Entry;

use crate::domain::Domain;

/// Which names an entry covers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Scope {
    /// The name and everything below it: `example.com` covers `example.com`
    /// and `ads.example.com`.
    Subtree,
    /// Only names strictly below it: `*.example.com` covers `ads.example.com`
    /// but not `example.com`.
    Subdomains,
}

const TAG_SUBTREE: u8 = 0;
const TAG_SUBDOMAINS: u8 = 1;

impl Scope {
    fn tag(self) -> u8 {
        match self {
            Scope::Subtree => TAG_SUBTREE,
            Scope::Subdomains => TAG_SUBDOMAINS,
        }
    }

    fn from_tag(tag: u8) -> Option<Scope> {
        match tag {
            TAG_SUBTREE => Some(Scope::Subtree),
            TAG_SUBDOMAINS => Some(Scope::Subdomains),
            _ => None,
        }
    }

    /// Whether an entry with this scope covers the query, given whether the
    /// query is the entry's own name or a name below it.
    fn covers(self, is_own_name: bool) -> bool {
        !(is_own_name && self == Scope::Subdomains)
    }
}

/// Parses a list or config entry: `example.com` is a [`Scope::Subtree`]
/// entry, `*.example.com` a [`Scope::Subdomains`] one. Other wildcards are not
/// expressible as a suffix match and are rejected by [`Domain::parse`].
pub fn parse_domain_pattern(entry: &str) -> Result<(Domain, Scope), crate::DomainError> {
    let entry = entry.trim();
    match entry.strip_prefix("*.") {
        Some(rest) => Ok((Domain::parse(rest)?, Scope::Subdomains)),
        None => Ok((Domain::parse(entry)?, Scope::Subtree)),
    }
}

/// Returned when a set would need more than 4 GiB of arena, which `u32`
/// offsets cannot address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("domain set is full: names would exceed 4 GiB")]
pub struct CapacityError;

/// A compact set of domain names, each with a [`Scope`].
#[derive(Clone)]
pub struct DomainSet {
    /// Names back to back, each followed by its scope tag.
    arena: Vec<u8>,
    /// Arena offsets of live entries. Removed entries leave their bytes in
    /// the arena; removal is rare (`$badfilter`, `sinkd block rm`).
    table: HashTable<u32>,
    hasher: RandomState,
}

impl Default for DomainSet {
    fn default() -> Self {
        Self::new()
    }
}

impl DomainSet {
    /// An empty set with a randomly seeded hasher.
    pub fn new() -> Self {
        Self::with_hasher(RandomState::new())
    }

    fn with_hasher(hasher: RandomState) -> Self {
        DomainSet {
            arena: Vec::new(),
            table: HashTable::new(),
            hasher,
        }
    }

    /// Pre-sizes for `entries` names totalling about `name_bytes` bytes.
    pub fn reserve(&mut self, entries: usize, name_bytes: usize) {
        self.arena.reserve(name_bytes + entries);
        let Self {
            arena,
            table,
            hasher,
        } = self;
        table.reserve(entries, |&off| hasher.hash_one(name_at(arena, off)));
    }

    /// Adds `domain` with `scope`. Adding a name that is already present keeps
    /// the broader scope. Returns whether the set changed.
    pub fn insert(&mut self, domain: &Domain, scope: Scope) -> Result<bool, CapacityError> {
        let name = domain.as_str().as_bytes();
        let hash = self.hasher.hash_one(name);
        let Self {
            arena,
            table,
            hasher,
        } = self;
        match table.entry(
            hash,
            |&off| stored_eq(arena, off, name),
            |&off| hasher.hash_one(name_at(arena, off)),
        ) {
            Entry::Occupied(entry) => {
                let tag_at = *entry.get() as usize + name.len();
                let widened = scope == Scope::Subtree && arena[tag_at] == TAG_SUBDOMAINS;
                if widened {
                    arena[tag_at] = TAG_SUBTREE;
                }
                Ok(widened)
            }
            Entry::Vacant(entry) => {
                let off = u32::try_from(arena.len()).map_err(|_| CapacityError)?;
                if arena.len() + name.len() + 1 > u32::MAX as usize {
                    return Err(CapacityError);
                }
                arena.extend_from_slice(name);
                arena.push(scope.tag());
                entry.insert(off);
                Ok(true)
            }
        }
    }

    /// Removes `domain` whatever its scope. Returns whether it was present.
    pub fn remove(&mut self, domain: &Domain) -> bool {
        let name = domain.as_str().as_bytes();
        let hash = self.hasher.hash_one(name);
        let Self { arena, table, .. } = self;
        match table.find_entry(hash, |&off| stored_eq(arena, off, name)) {
            Ok(entry) => {
                entry.remove();
                true
            }
            Err(_) => false,
        }
    }

    /// The scope stored for exactly `name`, if any.
    pub fn get(&self, name: &str) -> Option<Scope> {
        let name = name.as_bytes();
        self.find(self.hasher.hash_one(name), name)
    }

    /// Probes with a precomputed hash from this set's hasher.
    #[inline]
    fn find(&self, hash: u64, name: &[u8]) -> Option<Scope> {
        let arena = &self.arena;
        let off = *self.table.find(hash, |&off| stored_eq(arena, off, name))?;
        arena
            .get(off as usize + name.len())
            .copied()
            .and_then(Scope::from_tag)
    }

    /// Number of names in the set.
    pub fn len(&self) -> usize {
        self.table.len()
    }

    /// Whether the set is empty.
    pub fn is_empty(&self) -> bool {
        self.table.is_empty()
    }

    /// Iterates over the entries in arbitrary order.
    pub fn iter(&self) -> impl Iterator<Item = (&str, Scope)> + '_ {
        self.table.iter().filter_map(|&off| {
            let name = name_at(&self.arena, off);
            let scope = Scope::from_tag(*self.arena.get(off as usize + name.len())?)?;
            Some((std::str::from_utf8(name).ok()?, scope))
        })
    }

    /// Heap memory held by the set, in bytes.
    pub fn heap_bytes(&self) -> usize {
        self.arena.capacity() + self.table.allocation_size()
    }

    /// Releases spare capacity after a bulk load.
    pub fn shrink_to_fit(&mut self) {
        self.arena.shrink_to_fit();
        let Self {
            arena,
            table,
            hasher,
        } = self;
        table.shrink_to_fit(|&off| hasher.hash_one(name_at(arena, off)));
    }
}

impl fmt::Debug for DomainSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DomainSet")
            .field("len", &self.len())
            .field("heap_bytes", &self.heap_bytes())
            .finish()
    }
}

/// Whether the entry stored at `off` is exactly `name`.
#[inline]
fn stored_eq(arena: &[u8], off: u32, name: &[u8]) -> bool {
    let off = off as usize;
    arena.get(off..off + name.len()) == Some(name)
        && matches!(
            arena.get(off + name.len()),
            Some(&(TAG_SUBTREE | TAG_SUBDOMAINS))
        )
}

/// The name stored at `off`, without its tag.
fn name_at(arena: &[u8], off: u32) -> &[u8] {
    let rest = arena.get(off as usize..).unwrap_or_default();
    let end = memchr::memchr2(TAG_SUBTREE, TAG_SUBDOMAINS, rest).unwrap_or(rest.len());
    &rest[..end]
}

/// The outcome of [`DomainMatcher::check`]. `rule` is the suffix of the
/// queried name that matched, which is the list entry's name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict<'a> {
    /// An allowlist entry covers the name. This beats any block entry.
    Allowed { rule: &'a str, scope: Scope },
    /// A blocklist entry covers the name and no allowlist entry does. `rule`
    /// is the most specific matching block entry.
    Blocked { rule: &'a str, scope: Scope },
    /// No entry covers the name.
    NotListed,
}

impl Verdict<'_> {
    /// Whether the query should be answered with a block response.
    pub fn is_blocked(&self) -> bool {
        matches!(self, Verdict::Blocked { .. })
    }
}

/// Allowlist and blocklist with the semantics described in the module docs.
#[derive(Clone, Default)]
pub struct DomainMatcher {
    allow: DomainSet,
    block: DomainSet,
}

impl DomainMatcher {
    /// Starts building a matcher.
    pub fn builder() -> DomainMatcherBuilder {
        DomainMatcherBuilder::default()
    }

    /// Decides `name`, which must already be lowercase without a trailing dot
    /// (see [`crate::QueryName`]).
    pub fn check<'a>(&self, name: &'a str) -> Verdict<'a> {
        let bytes = name.as_bytes();
        // A label containing control bytes can never be a list entry, and a
        // probe containing tag bytes could falsely match across an arena
        // terminator. Only suffixes after the last such label are probed.
        let mut start = match bytes.iter().rposition(|&b| b < 0x20) {
            None => 0,
            Some(i) => match memchr::memchr(b'.', &bytes[i..]) {
                Some(dot) => i + dot + 1,
                None => return Verdict::NotListed,
            },
        };
        let check_allow = !self.allow.is_empty();
        let mut blocked = Verdict::NotListed;
        loop {
            let suffix = &name[start..];
            let is_own_name = start == 0;
            let hash = self.block.hasher.hash_one(suffix.as_bytes());
            if check_allow
                && let Some(scope) = self.allow.find(hash, suffix.as_bytes())
                && scope.covers(is_own_name)
            {
                return Verdict::Allowed {
                    rule: suffix,
                    scope,
                };
            }
            if blocked == Verdict::NotListed
                && let Some(scope) = self.block.find(hash, suffix.as_bytes())
                && scope.covers(is_own_name)
            {
                blocked = Verdict::Blocked {
                    rule: suffix,
                    scope,
                };
                // Without an allowlist nothing can override this.
                if !check_allow {
                    return blocked;
                }
            }
            match memchr::memchr(b'.', suffix.as_bytes()) {
                Some(dot) => start += dot + 1,
                None => return blocked,
            }
        }
    }

    /// The allowlist.
    pub fn allowlist(&self) -> &DomainSet {
        &self.allow
    }

    /// The blocklist.
    pub fn blocklist(&self) -> &DomainSet {
        &self.block
    }

    /// Heap memory held by both lists, in bytes.
    pub fn heap_bytes(&self) -> usize {
        self.allow.heap_bytes() + self.block.heap_bytes()
    }
}

impl fmt::Debug for DomainMatcher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DomainMatcher")
            .field("allow", &self.allow)
            .field("block", &self.block)
            .finish()
    }
}

/// Builds a [`DomainMatcher`]. Both lists share one hasher, so each suffix is
/// hashed once per lookup.
pub struct DomainMatcherBuilder {
    allow: DomainSet,
    block: DomainSet,
}

impl Default for DomainMatcherBuilder {
    fn default() -> Self {
        let hasher = RandomState::new();
        DomainMatcherBuilder {
            allow: DomainSet::with_hasher(hasher.clone()),
            block: DomainSet::with_hasher(hasher),
        }
    }
}

impl DomainMatcherBuilder {
    /// Pre-sizes the blocklist for a bulk load.
    pub fn reserve_block(&mut self, entries: usize, name_bytes: usize) {
        self.block.reserve(entries, name_bytes);
    }

    /// Adds a blocklist entry. Returns whether the list changed.
    pub fn block(&mut self, domain: &Domain, scope: Scope) -> Result<bool, CapacityError> {
        self.block.insert(domain, scope)
    }

    /// Adds an allowlist entry. Returns whether the list changed.
    pub fn allow(&mut self, domain: &Domain, scope: Scope) -> Result<bool, CapacityError> {
        self.allow.insert(domain, scope)
    }

    /// Removes a blocklist entry (for `$badfilter`). Returns whether it existed.
    pub fn unblock(&mut self, domain: &Domain) -> bool {
        self.block.remove(domain)
    }

    /// Removes an allowlist entry. Returns whether it existed.
    pub fn unallow(&mut self, domain: &Domain) -> bool {
        self.allow.remove(domain)
    }

    /// Number of blocklist entries so far.
    pub fn block_len(&self) -> usize {
        self.block.len()
    }

    /// Number of allowlist entries so far.
    pub fn allow_len(&self) -> usize {
        self.allow.len()
    }

    /// Finishes the matcher, releasing spare capacity.
    pub fn build(mut self) -> DomainMatcher {
        self.allow.shrink_to_fit();
        self.block.shrink_to_fit();
        DomainMatcher {
            allow: self.allow,
            block: self.block,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::collections::HashMap;

    fn d(s: &str) -> Domain {
        Domain::parse(s).unwrap()
    }

    fn matcher(block: &[(&str, Scope)], allow: &[(&str, Scope)]) -> DomainMatcher {
        let mut b = DomainMatcher::builder();
        for (n, s) in block {
            b.block(&d(n), *s).unwrap();
        }
        for (n, s) in allow {
            b.allow(&d(n), *s).unwrap();
        }
        b.build()
    }

    use Scope::{Subdomains, Subtree};

    #[test]
    fn subtree_blocks_name_and_children() {
        let m = matcher(&[("example.com", Subtree)], &[]);
        assert_eq!(
            m.check("example.com"),
            Verdict::Blocked {
                rule: "example.com",
                scope: Subtree
            }
        );
        assert_eq!(
            m.check("a.b.example.com"),
            Verdict::Blocked {
                rule: "example.com",
                scope: Subtree
            }
        );
        assert_eq!(m.check("notexample.com"), Verdict::NotListed);
        assert_eq!(m.check("example.com.evil"), Verdict::NotListed);
        assert_eq!(m.check("com"), Verdict::NotListed);
    }

    #[test]
    fn wildcard_blocks_only_children() {
        let m = matcher(&[("example.com", Subdomains)], &[]);
        assert_eq!(m.check("example.com"), Verdict::NotListed);
        assert!(m.check("ads.example.com").is_blocked());
        assert!(m.check("a.ads.example.com").is_blocked());
    }

    #[test]
    fn most_specific_block_is_reported() {
        let m = matcher(
            &[("example.com", Subtree), ("ads.example.com", Subtree)],
            &[],
        );
        assert_eq!(
            m.check("x.ads.example.com"),
            Verdict::Blocked {
                rule: "ads.example.com",
                scope: Subtree
            }
        );
    }

    #[test]
    fn allow_on_parent_beats_block_on_child() {
        let m = matcher(&[("ads.example.com", Subtree)], &[("example.com", Subtree)]);
        assert_eq!(
            m.check("x.ads.example.com"),
            Verdict::Allowed {
                rule: "example.com",
                scope: Subtree
            }
        );
    }

    #[test]
    fn allow_on_child_beats_block_on_parent() {
        let m = matcher(&[("example.com", Subtree)], &[("cdn.example.com", Subtree)]);
        assert!(matches!(
            m.check("img.cdn.example.com"),
            Verdict::Allowed { .. }
        ));
        assert!(m.check("ads.example.com").is_blocked());
        assert!(m.check("example.com").is_blocked());
    }

    #[test]
    fn wildcard_allow_does_not_cover_apex() {
        let m = matcher(&[("example.com", Subtree)], &[("example.com", Subdomains)]);
        assert!(m.check("example.com").is_blocked());
        assert!(matches!(
            m.check("www.example.com"),
            Verdict::Allowed { .. }
        ));
    }

    #[test]
    fn duplicate_insert_keeps_broader_scope() {
        let mut s = DomainSet::new();
        assert!(s.insert(&d("example.com"), Subdomains).unwrap());
        assert!(!s.insert(&d("example.com"), Subdomains).unwrap());
        assert!(s.insert(&d("example.com"), Subtree).unwrap());
        assert!(!s.insert(&d("example.com"), Subdomains).unwrap());
        assert_eq!(s.get("example.com"), Some(Subtree));
        assert_eq!(s.len(), 1);
    }

    #[test]
    fn remove_and_iterate() {
        let mut s = DomainSet::new();
        for n in ["a.com", "b.com", "c.com"] {
            s.insert(&d(n), Subtree).unwrap();
        }
        assert!(s.remove(&d("b.com")));
        assert!(!s.remove(&d("b.com")));
        let mut names: Vec<_> = s.iter().map(|(n, _)| n.to_owned()).collect();
        names.sort();
        assert_eq!(names, ["a.com", "c.com"]);
        assert_eq!(s.get("b.com"), None);
    }

    #[test]
    fn prefix_and_extension_names_do_not_collide() {
        // "ab.com" stored right after "a.com" in the arena must not let
        // "a.com" + tag + ... confuse a probe.
        let m = matcher(&[("a.com", Subtree), ("ab.com", Subtree)], &[]);
        assert!(m.check("a.com").is_blocked());
        assert!(m.check("ab.com").is_blocked());
        assert_eq!(m.check("a.co"), Verdict::NotListed);
        assert_eq!(m.check("b.com"), Verdict::NotListed);
    }

    #[test]
    fn control_bytes_in_query_are_handled() {
        let m = matcher(&[("example.com", Subtree), ("a.com", Subtree)], &[]);
        // Tag bytes inside a label must not fake a match across entries.
        assert_eq!(m.check("a.com\u{0}ab.com"), Verdict::NotListed);
        assert_eq!(m.check("a.com\u{1}"), Verdict::NotListed);
        // But a weird label below a blocked parent is still blocked.
        assert!(m.check("we\u{0}ird.example.com").is_blocked());
    }

    #[test]
    fn empty_matcher_lists_nothing() {
        let m = DomainMatcher::default();
        assert_eq!(m.check("example.com"), Verdict::NotListed);
    }

    // ---- property tests ----------------------------------------------------

    /// Names over a tiny alphabet so random entries and queries overlap a lot.
    fn small_name() -> impl Strategy<Value = String> {
        prop::collection::vec(prop::sample::select(vec!["a", "b", "ads", "x"]), 1..5)
            .prop_map(|l| l.join("."))
    }

    fn scope() -> impl Strategy<Value = Scope> {
        prop_oneof![Just(Subtree), Just(Subdomains)]
    }

    fn entries() -> impl Strategy<Value = Vec<(String, Scope)>> {
        prop::collection::vec((small_name(), scope()), 0..12)
    }

    /// Straightforward reference implementation of the module semantics.
    fn widest(entries: &[(String, Scope)]) -> HashMap<&str, Scope> {
        let mut m: HashMap<&str, Scope> = HashMap::new();
        for (n, s) in entries {
            let e = m.entry(n.as_str()).or_insert(*s);
            if *s == Subtree {
                *e = Subtree;
            }
        }
        m
    }

    fn model(block: &[(String, Scope)], allow: &[(String, Scope)], q: &str) -> (bool, bool) {
        let (block, allow) = (widest(block), widest(allow));
        let covered = |m: &HashMap<&str, Scope>| {
            crate::domain::label_suffixes(q)
                .enumerate()
                .any(|(depth, sfx)| m.get(sfx).is_some_and(|s| depth > 0 || *s == Subtree))
        };
        let allowed = covered(&allow);
        (allowed, !allowed && covered(&block))
    }

    fn build(block: &[(String, Scope)], allow: &[(String, Scope)]) -> DomainMatcher {
        let mut b = DomainMatcher::builder();
        for (n, s) in block {
            b.block(&d(n), *s).unwrap();
        }
        for (n, s) in allow {
            b.allow(&d(n), *s).unwrap();
        }
        b.build()
    }

    proptest! {
        #[test]
        fn agrees_with_reference_model(block in entries(), allow in entries(), q in small_name()) {
            let m = build(&block, &allow);
            let (allowed, blocked) = model(&block, &allow, &q);
            let v = m.check(&q);
            prop_assert_eq!(matches!(v, Verdict::Allowed { .. }), allowed, "{:?}", v);
            prop_assert_eq!(v.is_blocked(), blocked, "{:?}", v);
        }

        #[test]
        fn blocked_parent_blocks_every_child(
            block in entries(),
            parent in small_name(),
            child_labels in prop::collection::vec("[a-z0-9-]{1,8}", 1..4),
        ) {
            let mut block = block;
            block.push((parent.clone(), Subtree));
            let m = build(&block, &[]);
            let child = format!("{}.{}", child_labels.join("."), parent);
            prop_assert!(m.check(&parent).is_blocked());
            prop_assert!(m.check(&child).is_blocked());
        }

        #[test]
        fn allowlist_always_wins(
            block in entries(),
            allow in entries(),
            allowed in small_name(),
            child_labels in prop::collection::vec("[a-z0-9-]{1,8}", 0..3),
        ) {
            // Block everything we can think of, then allow one subtree.
            let mut block = block;
            block.push((allowed.clone(), Subtree));
            let mut allow = allow;
            allow.push((allowed.clone(), Subtree));
            let m = build(&block, &allow);
            let q = if child_labels.is_empty() {
                allowed.clone()
            } else {
                format!("{}.{}", child_labels.join("."), allowed)
            };
            let allowed_verdict = matches!(m.check(&q), Verdict::Allowed { .. });
            prop_assert!(allowed_verdict);
        }

        #[test]
        fn reported_rule_is_a_suffix_of_the_query(block in entries(), allow in entries(), q in small_name()) {
            let m = build(&block, &allow);
            if let Verdict::Allowed { rule, .. } | Verdict::Blocked { rule, .. } = m.check(&q) {
                let dotted = format!(".{rule}");
                prop_assert!(q == rule || q.ends_with(&dotted));
            }
        }
    }
}
