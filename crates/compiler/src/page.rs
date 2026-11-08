//! The page target: what the extension applies inside pages.
//!
//! - Cosmetic rules go into one [`PageIndex`] shared by every ruleset, each
//!   entry tagged with its ruleset's bit, for the wasm engine in the
//!   service worker.
//! - Scriptlet rules become scripts per ruleset: the bundled library plus a
//!   table of which calls run on which sites, registered as content scripts
//!   in the page's MAIN world at document_start. Sites are bucketed into
//!   files registered for exactly those sites; entities (`example.*`), which
//!   no match pattern can express, go into one file that runs everywhere.
//!
//! **What registration costs.** Chrome checks a page's URL against every
//! registered match pattern, one by one, on each navigation and in each
//! frame: about 0.1 µs a pattern on an M-series Mac. So each site gets one
//! pattern (none when its parent is listed). An entity needs a pattern per
//! TLD, so a ruleset with many puts them in a file that runs on every page
//! instead, behind a check (prelude.js); that file costs each page about
//! 0.6 ms (mostly V8 pre-parsing the library), which beats the patterns
//! only past a few hundred entities.
//!
//! **Bait-safe generic hiding.** Ad-blocker detectors create bait elements
//! (`<div class="adsbox pub_300x250">`) and check whether they got hidden.
//! Generic hiding is what hides them, so generic selectors that target a
//! known bait name are left out ([`BAIT`]). Site-specific rules still
//! apply, and scriptlets defuse the detectors themselves.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::json;
use sinkd_core::page::{
    ELEMHIDE, GENERICHIDE, Mask, PageIndex, PageIndexBuilder, SPECIFICHIDE, TWO_LABEL_SUFFIXES,
    host_keys,
};
use sinkd_filters::network::ResourceTypes;
use sinkd_filters::scriptlet::Dialect;
use sinkd_filters::{
    CosmeticAction, CosmeticRule, DomainSpec, HostPattern, NetworkRule, ScriptletRule,
};

/// The scriptlet library, whose leading comment block is dropped.
const LIBRARY: &str = include_str!("../scriptlets/library.js");
/// What runs before the library: the page's keys, and the check that the
/// file has anything for them.
const PRELUDE: &str = include_str!("../scriptlets/prelude.js");

/// Class and id names ad-blocker detectors use as bait. Generic hiding
/// never targets them. Drawn from the bait FuckAdBlock, BlockAdBlock and
/// common custom detectors create, and AdSense's own slot class.
pub const BAIT: &[&str] = &[
    "ad",
    "ads",
    "adsbox",
    "ad-box",
    "adbox",
    "ad_box",
    "ad-banner",
    "adbanner",
    "adBanner",
    "banner_ad",
    "banner-ad",
    "bannerAd",
    "ad-placement",
    "ad_placement",
    "ad-placeholder",
    "adsbygoogle",
    "adsense",
    "advert",
    "advertisement",
    "advertising",
    "afs_ads",
    "ad-unit",
    "pub_300x250",
    "pub_300x250m",
    "pub_728x90",
    "text-ad",
    "textAd",
    "text_ad",
    "text_ads",
    "text-ads",
    "text-ad-links",
    "doubleclick",
    "ad-slot",
    "adSlot",
    "ad-zone",
    "adzone",
    "sponsorAd",
    "ad-container",
    "ad_container",
    "adContainer",
    "ads-banner",
    "AdBox",
];

/// TLDs an `example.*` entity is registered for, when its ruleset has too
/// few entities for a file of their own. The script matches any public
/// suffix; registration needs concrete patterns, so these entities are
/// missed on rarer TLDs (never over-matched).
const ENTITY_TLDS: &[&str] = &[
    "com", "net", "org", "info", "biz", "io", "co", "me", "tv", "cc", "to", "ws", "xyz", "top",
    "site", "online", "club", "live", "pro", "vip",
];

/// Entities a ruleset needs before they get a file that runs on every
/// page: 20 patterns each cost about 2 µs a navigation; the file, 600 µs.
const ENTITY_FILE_MIN: usize = 300;

/// Sites per scriptlet file. A page loads the one file holding its site,
/// so smaller buckets mean less to parse per page, at the cost of more
/// files (each carrying the library).
const SITES_PER_FILE: usize = 500;

/// One rule the page target could not take.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PageSkip {
    pub feature: String,
    pub reason: String,
}

fn skip(feature: impl Into<String>, reason: impl Into<String>) -> PageSkip {
    PageSkip {
        feature: feature.into(),
        reason: reason.into(),
    }
}

#[derive(Debug, Clone, Default)]
struct ScriptletTable {
    calls: Vec<Vec<String>>,
    ids: BTreeMap<Vec<String>, u32>,
    hosts: BTreeMap<String, BTreeSet<u32>>,
}

/// A scriptlet file: one bucket of one ruleset's sites.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScriptletFile {
    pub ruleset: String,
    /// `<ruleset>-<bucket>`.
    pub name: String,
    pub js: String,
    /// Where to register it.
    pub matches: Vec<String>,
    pub calls: usize,
}

/// What the page target produces.
#[derive(Debug, Clone, Default)]
pub struct PageOutput {
    pub index: PageIndex,
    pub scriptlets: Vec<ScriptletFile>,
    /// Each ruleset's bit in the index's masks.
    pub masks: BTreeMap<String, Mask>,
    /// The scriptlet calls behind the files, for [`PageOutput::calls_for`].
    tables: BTreeMap<String, ScriptletTable>,
    except: BTreeMap<String, Option<BTreeSet<Vec<String>>>>,
}

impl PageOutput {
    /// The scriptlet calls that run on a page at `hostname`, per ruleset,
    /// as the scriptlet files decide: the calls filed under the hostname,
    /// its parents and its entities, less the exceptions filed there. Each
    /// call is the scriptlet name followed by its arguments.
    pub fn calls_for(&self, hostname: &str) -> Vec<(String, Vec<String>)> {
        let keys = host_keys(hostname);
        let mut excepted: BTreeSet<&Vec<String>> = BTreeSet::new();
        for key in &keys {
            match self.except.get(key) {
                Some(None) => return Vec::new(),
                Some(Some(calls)) => excepted.extend(calls),
                None => {}
            }
        }
        let mut out = Vec::new();
        for (ruleset, table) in &self.tables {
            let ids: BTreeSet<u32> = keys
                .iter()
                .filter_map(|k| table.hosts.get(k))
                .flatten()
                .copied()
                .collect();
            for id in ids {
                if let Some(call) = table.calls.get(id as usize)
                    && !excepted.contains(call)
                {
                    out.push((ruleset.clone(), call.clone()));
                }
            }
        }
        out
    }
}

/// Builds the page target.
#[derive(Debug, Default)]
pub struct PageTarget {
    builder: PageIndexBuilder,
    masks: BTreeMap<String, Mask>,
    tables: BTreeMap<String, ScriptletTable>,
    /// Scriptlet exceptions apply to every ruleset's calls: host → calls
    /// (empty set: every call).
    except: BTreeMap<String, Option<BTreeSet<Vec<String>>>>,
}

impl PageTarget {
    /// `rulesets`, in order, get bits 0..8. Rules from a ninth ruleset on
    /// are skipped (and reported) for the page target.
    pub fn new<'a>(rulesets: impl IntoIterator<Item = &'a str>) -> Self {
        let mut target = PageTarget::default();
        for (i, id) in rulesets.into_iter().enumerate().take(8) {
            target.masks.insert(id.to_owned(), 1 << i);
        }
        target
    }

    fn mask(&self, ruleset: &str) -> Result<Mask, PageSkip> {
        self.masks.get(ruleset).copied().ok_or_else(|| {
            skip(
                "page:too-many-rulesets",
                "only 8 rulesets can carry page rules",
            )
        })
    }

    pub fn cosmetic(&mut self, ruleset: &str, rule: &CosmeticRule) -> Result<(), PageSkip> {
        let mask = self.mask(ruleset)?;
        let (positive, negative) = hosts(&rule.domains)?;
        let css = rule.selector.as_css();
        if positive.is_empty() {
            let Some(css) = css else {
                return Err(skip(
                    "page:generic-procedural",
                    "procedural rules need a site",
                ));
            };
            if rule.action != CosmeticAction::Hide {
                return Err(skip(
                    "page:generic-style",
                    ":style and :remove rules need a site",
                ));
            }
            let parts = selector_list(css);
            if rule.exception {
                if negative.is_empty() {
                    for part in &parts {
                        self.builder.cancel_generic(part);
                    }
                }
                return Ok(());
            }
            let mut kept = 0;
            for part in &parts {
                if is_bait(part) {
                    continue;
                }
                kept += 1;
                self.builder.generic(part, token(part).as_deref(), mask);
                for host in &negative {
                    self.builder.unhide(host, part, mask);
                }
            }
            if kept == 0 {
                return Err(skip(
                    "page:bait-generic",
                    "generic hiding of a detector's bait class or id is left out",
                ));
            }
            return Ok(());
        }
        match (css, &rule.action) {
            (Some(css), CosmeticAction::Hide) => {
                for host in &positive {
                    if rule.exception {
                        self.builder.unhide(host, css, mask);
                    } else {
                        self.builder.hide(host, css, mask);
                    }
                }
                if !rule.exception {
                    for host in &negative {
                        self.builder.unhide(host, css, mask);
                    }
                }
            }
            (Some(css), CosmeticAction::Style(declarations)) => {
                for host in &positive {
                    if rule.exception {
                        self.builder.unhide(host, css, mask);
                    } else {
                        self.builder.style(host, css, declarations, mask);
                    }
                }
            }
            _ => {
                // Procedural selectors and :remove/:remove-attr/:remove-class
                // run in the content script.
                let json = json!({ "selector": rule.selector, "action": rule.action }).to_string();
                for host in &positive {
                    if rule.exception {
                        self.builder.unprocedural(host, &json, mask);
                    } else {
                        self.builder.procedural(host, &json, mask);
                    }
                }
                if !rule.exception {
                    for host in &negative {
                        self.builder.unprocedural(host, &json, mask);
                    }
                }
            }
        }
        Ok(())
    }

    pub fn scriptlet(&mut self, ruleset: &str, rule: &ScriptletRule) -> Result<(), PageSkip> {
        self.mask(ruleset)?;
        let (positive, negative) = hosts(&rule.domains)?;
        if positive.is_empty() {
            return Err(skip("page:generic-scriptlet", "scriptlets need a site"));
        }
        if rule.exception {
            for host in &positive {
                let entry = self
                    .except
                    .entry(host.clone())
                    .or_insert_with(|| Some(BTreeSet::new()));
                match (rule.calls.is_empty(), entry.as_mut()) {
                    (true, _) => *entry = None,
                    (false, Some(calls)) => calls.extend(rule.calls.iter().map(call_key)),
                    (false, None) => {}
                }
            }
            return Ok(());
        }
        let table = self.tables.entry(ruleset.to_owned()).or_default();
        for call in &rule.calls {
            let key = call_key(call);
            let next = u32::try_from(table.calls.len()).unwrap_or(u32::MAX);
            let id = *table.ids.entry(key.clone()).or_insert(next);
            if id == next {
                table.calls.push(key.clone());
            }
            for host in &positive {
                table.hosts.entry(host.clone()).or_default().insert(id);
            }
            for host in &negative {
                self.except
                    .entry(host.clone())
                    .or_insert_with(|| Some(BTreeSet::new()))
                    .as_mut()
                    .map(|calls| calls.insert(key.clone()));
            }
        }
        Ok(())
    }

    /// `@@||example.com^$generichide` and friends, and `@@||example.com^$document`,
    /// which switches off everything on the page, scriptlets included.
    pub fn page_exception(&mut self, ruleset: &str, rule: &NetworkRule) -> Result<(), PageSkip> {
        let mask = self.mask(ruleset)?;
        let o = &rule.options;
        let document = rule.exception
            && o.action.is_none()
            && o.types.is_some_and(|t| {
                t.without(ResourceTypes::POPUP | ResourceTypes::SUBDOCUMENT)
                    == ResourceTypes::DOCUMENT
            });
        let mut flags = 0;
        if o.page.elemhide || document {
            flags |= ELEMHIDE;
        }
        if o.page.generichide {
            flags |= GENERICHIDE;
        }
        if o.page.specifichide {
            flags |= SPECIFICHIDE;
        }
        if flags == 0 {
            return Ok(());
        }
        let host = rule.pattern.pure_hostname().ok_or_else(|| {
            skip(
                "page:exception-pattern",
                "page exceptions are applied to whole hosts only",
            )
        })?;
        self.builder.flags(host, flags, mask);
        if document {
            self.except.insert(host.to_owned(), None);
        }
        Ok(())
    }

    pub fn finish(self) -> PageOutput {
        let PageTarget {
            builder,
            masks,
            tables,
            except,
        } = self;
        let library = strip_comments(LIBRARY);
        let prelude = strip_comments(PRELUDE);
        let suffixes = serde_json::to_string(TWO_LABEL_SUFFIXES).unwrap_or_default();
        let mut scriptlets = Vec::new();
        for (ruleset, table) in &tables {
            if table.calls.is_empty() {
                continue;
            }
            let (mut entities, mut plain): (Vec<&String>, Vec<&String>) =
                table.hosts.keys().partition(|k| k.ends_with(".*"));
            if entities.len() < ENTITY_FILE_MIN {
                plain.append(&mut entities);
            }
            let emit = |name: String,
                        keys: &[&String],
                        matches: Vec<String>,
                        owns: &dyn Fn(&str) -> bool| {
                // Renumber the calls this file uses. A site's calls that
                // its entity also has are left to the entity file.
                let mut local: BTreeMap<u32, u32> = BTreeMap::new();
                let mut calls = Vec::new();
                let mut hosts: BTreeMap<&String, Vec<u32>> = BTreeMap::new();
                for &key in keys {
                    let from_entities: BTreeSet<u32> = if key.ends_with(".*") {
                        BTreeSet::new()
                    } else {
                        host_keys(key)
                            .iter()
                            .filter(|k| k.ends_with(".*"))
                            .filter_map(|k| table.hosts.get(k))
                            .flatten()
                            .copied()
                            .collect()
                    };
                    for &id in &table.hosts[key] {
                        if from_entities.contains(&id) {
                            continue;
                        }
                        let next = u32::try_from(calls.len()).unwrap_or(u32::MAX);
                        let local_id = *local.entry(id).or_insert_with(|| {
                            calls.push(table.calls[id as usize].clone());
                            next
                        });
                        hosts.entry(key).or_default().push(local_id);
                    }
                }
                if hosts.is_empty() {
                    return None;
                }
                let mut except_ids: BTreeMap<&String, serde_json::Value> = BTreeMap::new();
                for (host, excepted) in &except {
                    if !owns(host) {
                        continue;
                    }
                    match excepted {
                        None => {
                            except_ids.insert(host, json!("*"));
                        }
                        Some(excepted) => {
                            let ids: Vec<u32> = excepted
                                .iter()
                                .filter_map(|c| table.ids.get(c))
                                .filter_map(|id| local.get(id).copied())
                                .collect();
                            if !ids.is_empty() {
                                except_ids.insert(host, json!(ids));
                            }
                        }
                    }
                }
                let data = json!({ "calls": calls, "hosts": hosts, "except": except_ids });
                let literal = serde_json::to_string(&data.to_string()).unwrap_or_default();
                // The library is parsed lazily and runs only when the
                // prelude finds this page's keys in the table.
                let js = format!(
                    "(function () {{\n'use strict';\nconst data = {literal};\nconst suffixes = {suffixes};\n\
                     {prelude}\n(function () {{\n{library}\nrun(JSONParse(data), keys);\n}})();\n}})();\n"
                );
                Some(ScriptletFile {
                    name,
                    matches,
                    calls: calls.len(),
                    ruleset: ruleset.clone(),
                    js,
                })
            };

            // Bucket by site, so a page's hostname, its parents and the
            // exceptions for them all land in one file.
            let mut sites: BTreeMap<String, Vec<&String>> = BTreeMap::new();
            for &host in &plain {
                sites.entry(site_label(host)).or_default().push(host);
            }
            let buckets = sites.len().div_ceil(SITES_PER_FILE).max(1);
            let mut keys_by_bucket: Vec<Vec<&String>> = vec![Vec::new(); buckets];
            for (site, keys) in &sites {
                keys_by_bucket[bucket_of(site, buckets)].extend(keys.iter().copied());
            }
            for (n, keys) in keys_by_bucket.iter().enumerate() {
                let owns = |host: &str| bucket_of(&site_label(host), buckets) == n;
                let matches = match_patterns(keys.iter().copied());
                scriptlets.extend(emit(format!("{ruleset}-{n}"), keys, matches, &owns));
            }
            if !entities.is_empty() {
                let labels: BTreeSet<String> = entities.iter().map(|k| site_label(k)).collect();
                let owns = |host: &str| labels.contains(&site_label(host));
                let matches = vec!["*://*/*".to_owned()];
                scriptlets.extend(emit(
                    format!("{ruleset}-entities"),
                    &entities,
                    matches,
                    &owns,
                ));
            }
        }
        PageOutput {
            index: builder.finish(),
            scriptlets,
            masks,
            tables,
            except,
        }
    }
}

/// Script source without its comments and indentation: shorter to parse
/// on every page it lands on, and the leading block names the project.
/// Only whole comment lines go, which cannot change what the code means.
fn strip_comments(source: &str) -> String {
    let mut out = Vec::new();
    let mut in_block = false;
    for line in source.lines() {
        let t = line.trim();
        if in_block {
            in_block = !t.ends_with("*/");
            continue;
        }
        if t.starts_with("/*") {
            in_block = !t.ends_with("*/");
            continue;
        }
        if t.is_empty() || t.starts_with("//") {
            continue;
        }
        out.push(t);
    }
    out.join("\n")
}

/// The site a host key belongs to: the label left of its public suffix
/// (`news.example.co.uk` and `example.*` → `example`).
fn site_label(key: &str) -> String {
    if let Some(base) = key.strip_suffix(".*") {
        return base.rsplit('.').next().unwrap_or(base).to_owned();
    }
    let labels: Vec<&str> = key.split('.').collect();
    if labels.len() < 2 || key.parse::<std::net::IpAddr>().is_ok() {
        return key.to_owned();
    }
    let last_two = labels[labels.len() - 2..].join(".");
    let suffix = if TWO_LABEL_SUFFIXES.contains(&last_two.as_str()) {
        2
    } else {
        1
    };
    if labels.len() <= suffix {
        return key.to_owned();
    }
    labels[labels.len() - suffix - 1].to_owned()
}

/// A stable bucket for a site (FNV-1a), the same on every build.
fn bucket_of(site: &str, buckets: usize) -> usize {
    let hash = site.bytes().fold(0xcbf2_9ce4_8422_2325_u64, |h, b| {
        (h ^ u64::from(b)).wrapping_mul(0x0000_0100_0000_01b3)
    });
    (hash % buckets as u64) as usize
}

fn call_key(call: &sinkd_filters::ScriptletCall) -> Vec<String> {
    let dialect = match call.dialect {
        Dialect::Ublock => "u",
        Dialect::Adguard => "a",
        Dialect::Abp => "b",
    };
    let mut key = vec![call.name.to_owned(), dialect.to_owned()];
    key.extend(call.args.iter().cloned());
    key
}

/// Host keys (`example.com`, `example.*`) a domain list includes and excludes.
fn hosts(specs: &[DomainSpec]) -> Result<(Vec<String>, Vec<String>), PageSkip> {
    let mut positive = Vec::new();
    let mut negative = Vec::new();
    for spec in specs {
        let key = match &spec.host {
            HostPattern::Domain(d) => d.clone(),
            HostPattern::Entity(e) => format!("{e}.*"),
            HostPattern::Ip(ip) => ip.to_string(),
            HostPattern::Regex(_) => {
                return Err(skip(
                    "page:domain-regex",
                    "hostname regexes are not supported",
                ));
            }
        };
        if spec.negated {
            negative.push(key);
        } else {
            positive.push(key);
        }
    }
    Ok((positive, negative))
}

/// Splits a selector list at top-level commas.
fn selector_list(css: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut depth = 0i32;
    let mut quote = None;
    let mut start = 0;
    let bytes = css.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        match quote {
            Some(q) if b == q => quote = None,
            Some(_) if b == b'\\' => i += 1,
            Some(_) => {}
            None => match b {
                b'"' | b'\'' => quote = Some(b),
                b'\\' => i += 1,
                b'(' | b'[' => depth += 1,
                b')' | b']' => depth -= 1,
                b',' if depth == 0 => {
                    parts.push(css[start..i].trim().to_owned());
                    start = i + 1;
                }
                _ => {}
            },
        }
        i += 1;
    }
    parts.push(css[start..].trim().to_owned());
    parts.retain(|p| !p.is_empty());
    parts
}

/// The class and id names a selector requires, outside attribute brackets,
/// pseudo-class arguments and strings.
fn tokens(selector: &str) -> Option<Vec<String>> {
    let mut found = Vec::new();
    let mut depth = 0i32;
    let mut quote = None;
    let chars: Vec<char> = selector.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if let Some(q) = quote {
            if c == q {
                quote = None;
            }
            i += 1;
            continue;
        }
        match c {
            '"' | '\'' => quote = Some(c),
            '\\' => return None,
            '(' | '[' => depth += 1,
            ')' | ']' => depth -= 1,
            '.' | '#' if depth == 0 => {
                let start = i + 1;
                let mut end = start;
                while end < chars.len()
                    && (chars[end].is_ascii_alphanumeric()
                        || chars[end] == '-'
                        || chars[end] == '_')
                {
                    end += 1;
                }
                if end > start {
                    found.push(format!(
                        "{c}{}",
                        chars[start..end].iter().collect::<String>()
                    ));
                }
                i = end;
                continue;
            }
            _ => {}
        }
        i += 1;
    }
    Some(found)
}

/// The token a generic selector is filed under: its rightmost class or id,
/// which a matching element (or its ancestor) must carry.
fn token(selector: &str) -> Option<String> {
    tokens(selector)?.pop()
}

fn is_bait(selector: &str) -> bool {
    tokens(selector)
        .unwrap_or_default()
        .iter()
        .any(|t| BAIT.contains(&&t[1..]))
}

/// Match patterns for a file's sites: one per site, and none for a site
/// whose parent is listed (`*.example.com` covers `www.example.com`).
/// Entities that get here are expanded over [`ENTITY_TLDS`].
fn match_patterns<'a>(keys: impl Iterator<Item = &'a String>) -> Vec<String> {
    let valid = |h: &str| {
        !h.is_empty()
            && h.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-')
    };
    let keys: BTreeSet<&str> = keys.map(String::as_str).collect();
    let mut out = BTreeSet::new();
    for &key in &keys {
        if let Some(base) = key.strip_suffix(".*") {
            if valid(base) {
                for tld in ENTITY_TLDS {
                    out.insert(format!("*://*.{base}.{tld}/*"));
                }
            }
        } else if key.parse::<std::net::Ipv4Addr>().is_ok() {
            out.insert(format!("*://{key}/*"));
        } else if valid(key) && key.contains('.') {
            let covered = key
                .match_indices('.')
                .any(|(i, _)| keys.contains(&key[i + 1..]) && key[i + 1..].contains('.'));
            if !covered {
                out.insert(format!("*://*.{key}/*"));
            }
        }
    }
    out.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use sinkd_filters::{Rule, parse_rule};

    fn target() -> PageTarget {
        PageTarget::new(["ads", "fixes"])
    }

    fn add(t: &mut PageTarget, ruleset: &str, line: &str) -> Result<(), PageSkip> {
        match parse_rule(line).unwrap_or_else(|e| panic!("{line}: {e}")) {
            Rule::Cosmetic(c) => t.cosmetic(ruleset, &c),
            Rule::Scriptlet(s) => t.scriptlet(ruleset, &s),
            Rule::Network(n) => t.page_exception(ruleset, &n),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn selectors_split_and_tokenize() {
        assert_eq!(
            selector_list(".a, div[title=\"x,y\"] , :is(.b, .c)"),
            [".a", "div[title=\"x,y\"]", ":is(.b, .c)"]
        );
        assert_eq!(token(".ad-box"), Some(".ad-box".into()));
        assert_eq!(token("#main .ad > div"), Some(".ad".into()));
        assert_eq!(token("div.x:not(.y)"), Some(".x".into()));
        assert_eq!(token("a[href^=\"https://ad.example/\"]"), None);
        assert_eq!(token(".a\\:b"), None);
        assert!(is_bait(".pub_300x250"));
        assert!(is_bait("ins.adsbygoogle"));
        assert!(!is_bait(".ad-wrapper-xyz"));
    }

    #[test]
    fn cosmetic_rules_land_in_the_index() {
        let mut t = target();
        add(&mut t, "ads", "example.com,~shop.example.com##.banner").unwrap();
        add(&mut t, "ads", "news.*##.promo").unwrap();
        add(&mut t, "ads", "##.sticky-ad-unit").unwrap();
        add(&mut t, "ads", "~example.org##.floating-ad").unwrap();
        add(&mut t, "fixes", "example.com#@#.sticky-ad-unit").unwrap();
        add(
            &mut t,
            "ads",
            "example.com##body:style(overflow: auto !important)",
        )
        .unwrap();
        add(&mut t, "ads", "example.com##div:has-text(Sponsored)").unwrap();
        add(&mut t, "fixes", "@@||nohide.example^$generichide").unwrap();
        let skipped = add(&mut t, "ads", "##.pub_300x250").unwrap_err();
        assert_eq!(skipped.feature, "page:bait-generic");
        assert_eq!(
            add(&mut t, "ads", "##div:has-text(Ad)")
                .unwrap_err()
                .feature,
            "page:generic-procedural"
        );
        let out = t.finish();
        let all = 0b11;
        let page = out.index.page("www.example.com", all);
        assert!(page.css.contains(".banner{"));
        assert!(page.css.contains("body{overflow: auto !important}"));
        assert_eq!(page.procedural.len(), 1);
        assert!(page.procedural[0].contains("has-text"));
        assert!(
            !out.index
                .page("shop.example.com", all)
                .css
                .contains(".banner")
        );
        assert!(out.index.page("news.de", all).css.contains(".promo"));
        assert_eq!(
            out.index
                .generic_css("example.com", all, [".sticky-ad-unit"], false),
            ""
        );
        assert!(
            out.index
                .generic_css("example.net", all, [".sticky-ad-unit"], false)
                .contains(".sticky-ad-unit")
        );
        assert!(
            !out.index
                .generic_css("www.example.org", all, [".floating-ad"], false)
                .contains(".floating-ad")
        );
        assert!(!out.index.page("nohide.example", all).generic);
        assert_eq!(out.masks["ads"], 1);
        assert_eq!(out.masks["fixes"], 2);
    }

    #[test]
    fn scriptlet_tables_and_exceptions() {
        let mut t = target();
        add(
            &mut t,
            "ads",
            "example.com,news.*##+js(set-constant, ads.on, false)",
        )
        .unwrap();
        add(&mut t, "ads", "example.com##+js(nostif, adblock)").unwrap();
        add(&mut t, "ads", "example.com,~quiet.example.com#%#//scriptlet('abort-current-inline-script', 'onload', 'detect')").unwrap();
        add(&mut t, "fixes", "shop.example.com#@#+js(nostif, adblock)").unwrap();
        add(&mut t, "fixes", "off.example.com#@#+js()").unwrap();
        add(&mut t, "fixes", "@@||whole.example.com^$document").unwrap();
        let out = t.finish();
        let names: Vec<&str> = out.scriptlets.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(names, ["ads-0"], "one entity: no file of its own");
        let file = &out.scriptlets[0];
        assert_eq!(file.ruleset, "ads");
        assert_eq!(file.calls, 3);
        assert!(file.js.contains(r#"\"news.*\":[0]"#));
        assert!(file.matches.contains(&"*://*.example.com/*".to_owned()));
        assert!(file.matches.contains(&"*://*.news.io/*".to_owned()));
        assert!(
            !file.matches.contains(&"*://*.news.de/*".to_owned()),
            "rarer TLDs are left out"
        );
        for f in &out.scriptlets {
            assert!(
                !f.js.to_lowercase().contains("sinkd"),
                "the script names nothing"
            );
        }
        assert!(
            file.js
                .starts_with("(function () {\n'use strict';\nconst data = ")
        );
        assert!(file.js.contains("run(JSONParse(data), keys);"));
        assert!(!file.js.contains("\n//"), "comment lines are dropped");
        assert!(
            file.js
                .contains(r#"[\"prevent-setTimeout\",\"u\",\"adblock\"]"#)
        );
        assert!(
            file.js
                .contains(r#"[\"abort-current-script\",\"a\",\"onload\",\"detect\"]"#)
        );
        assert!(file.js.contains(r#"\"off.example.com\":\"*\""#));
        assert!(file.js.contains(r#"\"whole.example.com\":\"*\""#));
        assert!(
            file.js.contains(r#"\"shop.example.com\":[1]"#),
            "{}",
            &file.js[file.js.len() - 600..]
        );
        assert!(file.js.contains(r#"\"quiet.example.com\":[2]"#));
    }

    #[test]
    fn sites_and_buckets() {
        assert_eq!(site_label("www.news.example.co.uk"), "example");
        assert_eq!(site_label("example.com"), "example");
        assert_eq!(site_label("news.example.*"), "example");
        assert_eq!(site_label("com"), "com");
        assert_eq!(site_label("co.uk"), "co.uk");
        assert_eq!(bucket_of("example", 40), bucket_of("example", 40));
        assert!(bucket_of("example", 40) < 40);
    }

    #[test]
    fn a_site_and_its_exceptions_share_a_file() {
        let mut t = target();
        for i in 0..1200 {
            add(&mut t, "ads", &format!("site{i}.com##+js(nostif, x{i})")).unwrap();
        }
        add(&mut t, "ads", "example.com##+js(nostif, here)").unwrap();
        add(&mut t, "ads", "example.*##+js(nostif, ad)").unwrap();
        // Also the entity's: filed once, under the entity.
        add(&mut t, "ads", "example.com##+js(nostif, ad)").unwrap();
        add(&mut t, "fixes", "shop.example.com#@#+js(nostif, here)").unwrap();
        let out = t.finish();
        assert!(out.scriptlets.len() >= 3, "{}", out.scriptlets.len());
        let holding: Vec<_> = out
            .scriptlets
            .iter()
            .filter(|f| f.js.contains(r#"\"example.com\""#))
            .collect();
        assert_eq!(holding.len(), 1);
        let file = holding[0];
        assert!(file.js.contains(r#"\"example.*\""#));
        assert!(file.js.contains(r#"\"shop.example.com\""#));
        assert!(file.matches.contains(&"*://*.example.com/*".to_owned()));
        assert!(file.matches.contains(&"*://*.example.io/*".to_owned()));
        let data = &file.js[file.js.find("const data").unwrap_or(0)..];
        assert!(data.contains(r#"\"example.com\":["#));
        let ids = data
            .split(r#"\"example.com\":["#)
            .nth(1)
            .and_then(|r| r.split(']').next());
        assert_eq!(ids.map(|i| i.split(',').count()), Some(1), "{ids:?}");
    }

    #[test]
    fn many_entities_get_a_file_that_runs_everywhere() {
        let mut t = target();
        for i in 0..ENTITY_FILE_MIN {
            add(&mut t, "ads", &format!("e{i}.*##+js(nostif, e{i})")).unwrap();
        }
        add(&mut t, "ads", "example.*##+js(nostif, ad)").unwrap();
        add(&mut t, "ads", "example.com##+js(nostif, here)").unwrap();
        add(&mut t, "fixes", "shop.example.com#@#+js(nostif, ad)").unwrap();
        let out = t.finish();
        let (entities, sites): (Vec<_>, Vec<_>) = out
            .scriptlets
            .iter()
            .partition(|f| f.name == "ads-entities");
        let [entities] = entities.as_slice() else {
            panic!("one entity file")
        };
        assert_eq!(entities.matches, ["*://*/*"]);
        assert!(entities.js.contains(r#"\"example.*\""#));
        assert!(
            entities.js.contains(r#"\"shop.example.com\""#),
            "its exceptions travel with it"
        );
        assert!(!entities.js.contains(r#"\"example.com\""#));
        assert_eq!(sites.len(), 1);
        assert_eq!(sites[0].matches, ["*://*.example.com/*"]);
        assert!(!sites[0].js.contains(r#"\"example.*\""#));
    }

    #[test]
    fn every_bundled_scriptlet_is_implemented() {
        for spec in sinkd_filters::scriptlet::SCRIPTLETS {
            let quoted = format!("'{}'", spec.name);
            let bare = format!("\n  {}(", spec.name);
            assert!(
                LIBRARY.contains(&format!("{quoted}("))
                    || LIBRARY.contains(&format!("{quoted}:"))
                    || LIBRARY.contains(&bare),
                "{} has no implementation in library.js",
                spec.name
            );
        }
    }

    #[test]
    fn each_site_gets_one_pattern() {
        let keys = [
            "example.com".to_owned(),
            "www.example.com".to_owned(),
            "a.b.example.com".to_owned(),
            "news.example.org".to_owned(),
            "192.0.2.1".to_owned(),
            "bad_host.com".to_owned(),
        ];
        assert_eq!(
            match_patterns(keys.iter()),
            [
                "*://*.example.com/*",
                "*://*.news.example.org/*",
                "*://192.0.2.1/*"
            ]
        );
    }
}
