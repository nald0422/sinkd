//! The page index: what the extension applies inside pages, per hostname.
//!
//! - **Specific** entries, keyed by hostname (`example.com`, matching it and
//!   its subdomains) or entity (`example.*`, any public suffix): selectors
//!   to hide, selectors whose hiding is cancelled there (`#@#`, or
//!   `~example.com` in a rule's domain list), `:style()` rules, procedural
//!   rules, and page exceptions (`$generichide`, `$elemhide`,
//!   `$specifichide`).
//! - **Generic** hiding, keyed by a class or id the selector needs
//!   (`.ad-banner` → `.ad-banner`, `.ad > div` → `.ad`). The extension
//!   collects the classes and ids present in a page and asks only for the
//!   selectors that could match, instead of injecting thousands.
//!
//! Every entry carries a mask of the rulesets it came from (bit *n* for the
//! *n*-th ruleset), and lookups take the mask of rulesets switched on. So
//! turning off "Ads" stops its hiding, while an exception from "Fixes"
//! still cancels hiding from "Ads".
//!
//! The compiler builds the index ([`PageIndexBuilder`]); the wasm engine
//! and `sinkhole check` look things up ([`PageIndex::page`],
//! [`PageIndex::generic_css`]). No I/O here, so it builds for wasm32.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

/// No cosmetic filtering at all on the page (`$elemhide`).
pub const ELEMHIDE: u8 = 1;
/// No generic hiding (`$generichide`).
pub const GENERICHIDE: u8 = 2;
/// No site-specific hiding (`$specifichide`).
pub const SPECIFICHIDE: u8 = 4;

/// A ruleset mask: bit *n* is the *n*-th ruleset.
pub type Mask = u8;

/// Everything known about one hostname or entity. Each item carries the
/// mask of rulesets it came from.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostEntry {
    /// Selectors (indexes into [`PageIndex::selectors`]) to hide here.
    pub hide: Vec<(u32, Mask)>,
    /// Selectors not to hide here, whether generic or specific.
    pub unhide: Vec<(u32, Mask)>,
    /// `:style()` rules: selector and declarations.
    pub styles: Vec<(u32, String, Mask)>,
    /// Procedural rules (indexes into [`PageIndex::procedural`]).
    pub procedural: Vec<(u32, Mask)>,
    /// Procedural rules cancelled here.
    pub unprocedural: Vec<(u32, Mask)>,
    /// [`ELEMHIDE`] | [`GENERICHIDE`] | [`SPECIFICHIDE`], per ruleset.
    pub flags: Vec<(u8, Mask)>,
}

/// The index, serialized with postcard into the extension.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PageIndex {
    /// Every selector, once.
    pub selectors: Vec<String>,
    /// Procedural rules, as JSON for the content script that runs them.
    pub procedural: Vec<String>,
    /// Keyed by hostname (`example.com`) or entity (`example.*`).
    pub hosts: BTreeMap<String, HostEntry>,
    /// Generic hiding: `.class` or `#id` → selectors that need it.
    pub generic: BTreeMap<String, Vec<(u32, Mask)>>,
    /// Generic selectors with no class or id to key on; applied wherever
    /// generic hiding is.
    pub generic_always: Vec<(u32, Mask)>,
}

/// What applies on one page, apart from generic hiding.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Page {
    /// A user stylesheet: specific hiding and styles.
    pub css: String,
    /// Procedural rules, as JSON.
    pub procedural: Vec<String>,
    /// Whether generic hiding applies here.
    pub generic: bool,
}

/// Two-label public suffixes common enough to matter for `example.*`
/// rules. Without a full Public Suffix List, a hostname's public suffix is
/// taken to be its last label, or its last two when they are one of these.
pub const TWO_LABEL_SUFFIXES: &[&str] = &[
    "ac.uk", "co.uk", "gov.uk", "ltd.uk", "me.uk", "net.uk", "org.uk", "plc.uk", "com.au",
    "net.au", "org.au", "co.nz", "net.nz", "org.nz", "co.za", "co.jp", "ne.jp", "or.jp", "co.kr",
    "or.kr", "co.in", "net.in", "org.in", "co.id", "co.il", "co.th", "com.ar", "com.br", "com.cn",
    "com.co", "com.hk", "com.mx", "com.my", "com.pe", "com.ph", "com.pk", "com.sg", "com.tr",
    "com.tw", "com.ua", "com.vn", "net.br", "org.br",
];

/// Keys an entry for `hostname` may be filed under, most specific first:
/// the hostname and its parent domains, then its entities.
pub fn host_keys(hostname: &str) -> Vec<String> {
    let host = hostname.trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty() {
        return Vec::new();
    }
    let labels: Vec<&str> = host.split('.').collect();
    let mut keys = Vec::with_capacity(labels.len() * 2);
    for i in 0..labels.len() {
        keys.push(labels[i..].join("."));
    }
    // An IP address has no entity.
    if host.parse::<std::net::IpAddr>().is_ok() || labels.len() < 2 {
        return keys;
    }
    let last_two = labels[labels.len() - 2..].join(".");
    let suffix = if labels.len() > 2 && TWO_LABEL_SUFFIXES.contains(&last_two.as_str()) {
        2
    } else {
        1
    };
    let rest = &labels[..labels.len() - suffix];
    for i in 0..rest.len() {
        keys.push(format!("{}.*", rest[i..].join(".")));
    }
    keys
}

impl PageIndex {
    pub fn to_bytes(&self) -> Vec<u8> {
        postcard::to_allocvec(self).unwrap_or_default()
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<PageIndex, postcard::Error> {
        postcard::from_bytes(bytes)
    }

    fn entries<'a>(&'a self, hostname: &str) -> impl Iterator<Item = &'a HostEntry> + 'a {
        host_keys(hostname)
            .into_iter()
            .filter_map(move |k| self.hosts.get(&k))
    }

    fn flags(&self, hostname: &str, on: Mask) -> u8 {
        self.entries(hostname)
            .flat_map(|e| &e.flags)
            .filter(|(_, m)| m & on != 0)
            .fold(0, |f, (flags, _)| f | flags)
    }

    fn unhidden(&self, hostname: &str, on: Mask) -> BTreeSet<u32> {
        self.entries(hostname)
            .flat_map(|e| &e.unhide)
            .filter(|(_, m)| m & on != 0)
            .map(|(s, _)| *s)
            .collect()
    }

    /// The site-specific part of a page, from the rulesets in `on`:
    /// hiding, styles, procedural rules.
    pub fn page(&self, hostname: &str, on: Mask) -> Page {
        let flags = self.flags(hostname, on);
        let mut page = Page {
            generic: flags & (ELEMHIDE | GENERICHIDE) == 0,
            ..Page::default()
        };
        if flags & (ELEMHIDE | SPECIFICHIDE) != 0 {
            return page;
        }
        let unhide = self.unhidden(hostname, on);
        let live = |&(id, mask): &(u32, Mask)| (mask & on != 0).then_some(id);
        let mut hide = BTreeSet::new();
        let mut styles = BTreeSet::new();
        let mut procedural = BTreeSet::new();
        let mut unprocedural = BTreeSet::new();
        for entry in self.entries(hostname) {
            hide.extend(
                entry
                    .hide
                    .iter()
                    .filter_map(live)
                    .filter(|s| !unhide.contains(s)),
            );
            styles.extend(
                entry
                    .styles
                    .iter()
                    .filter(|(s, _, m)| m & on != 0 && !unhide.contains(s))
                    .map(|(s, d, _)| (*s, d.as_str())),
            );
            procedural.extend(entry.procedural.iter().filter_map(live));
            unprocedural.extend(entry.unprocedural.iter().filter_map(live));
        }
        page.css = hide_css(hide.into_iter().filter_map(|s| self.selector(s)));
        for (selector, declarations) in styles {
            if let Some(selector) = self.selector(selector) {
                page.css
                    .push_str(&format!("{selector}{{{declarations}}}\n"));
            }
        }
        page.procedural = procedural
            .difference(&unprocedural)
            .filter_map(|&p| self.procedural.get(p as usize).cloned())
            .collect();
        page
    }

    /// Generic hiding from the rulesets in `on`, for a page whose elements
    /// carry `tokens` (`.class`, `#id`), less what the page cancels. Empty
    /// if generic hiding is off there. With `always`, includes the
    /// selectors that have no token.
    pub fn generic_css<'t>(
        &self,
        hostname: &str,
        on: Mask,
        tokens: impl IntoIterator<Item = &'t str>,
        always: bool,
    ) -> String {
        if self.flags(hostname, on) & (ELEMHIDE | GENERICHIDE) != 0 {
            return String::new();
        }
        let unhide = self.unhidden(hostname, on);
        let live =
            |&(id, mask): &(u32, Mask)| (mask & on != 0 && !unhide.contains(&id)).then_some(id);
        let mut ids = BTreeSet::new();
        for token in tokens {
            if let Some(found) = self.generic.get(token) {
                ids.extend(found.iter().filter_map(live));
            }
        }
        if always {
            ids.extend(self.generic_always.iter().filter_map(live));
        }
        hide_css(ids.into_iter().filter_map(|s| self.selector(s)))
    }

    fn selector(&self, id: u32) -> Option<&str> {
        self.selectors.get(id as usize).map(String::as_str)
    }
}

/// One rule per selector: a selector Chrome does not understand drops only
/// its own rule, not a whole group.
fn hide_css<'a>(selectors: impl Iterator<Item = &'a str>) -> String {
    let mut css = String::new();
    for selector in selectors {
        css.push_str(selector);
        css.push_str("{display:none!important}\n");
    }
    css
}

/// Builds a [`PageIndex`], interning selectors. Every item is added with
/// the mask of the ruleset it comes from; the same item from several
/// rulesets ends up with their masks combined.
#[derive(Debug, Default)]
pub struct PageIndexBuilder {
    index: PageIndex,
    selector_ids: BTreeMap<String, u32>,
    procedural_ids: BTreeMap<String, u32>,
    generic: BTreeMap<u32, (Option<String>, Mask)>,
    cancelled: BTreeSet<u32>,
}

impl PageIndexBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    fn intern(&mut self, selector: &str) -> u32 {
        if let Some(&id) = self.selector_ids.get(selector) {
            return id;
        }
        let id = u32::try_from(self.index.selectors.len()).unwrap_or(u32::MAX);
        self.index.selectors.push(selector.to_owned());
        self.selector_ids.insert(selector.to_owned(), id);
        id
    }

    fn intern_procedural(&mut self, json: &str) -> u32 {
        if let Some(&id) = self.procedural_ids.get(json) {
            return id;
        }
        let id = u32::try_from(self.index.procedural.len()).unwrap_or(u32::MAX);
        self.index.procedural.push(json.to_owned());
        self.procedural_ids.insert(json.to_owned(), id);
        id
    }

    fn entry(&mut self, host: &str) -> &mut HostEntry {
        self.index.hosts.entry(host.to_owned()).or_default()
    }

    pub fn hide(&mut self, host: &str, selector: &str, mask: Mask) {
        let id = self.intern(selector);
        self.entry(host).hide.push((id, mask));
    }

    pub fn unhide(&mut self, host: &str, selector: &str, mask: Mask) {
        let id = self.intern(selector);
        self.entry(host).unhide.push((id, mask));
    }

    pub fn style(&mut self, host: &str, selector: &str, declarations: &str, mask: Mask) {
        let id = self.intern(selector);
        self.entry(host)
            .styles
            .push((id, declarations.to_owned(), mask));
    }

    pub fn procedural(&mut self, host: &str, json: &str, mask: Mask) {
        let id = self.intern_procedural(json);
        self.entry(host).procedural.push((id, mask));
    }

    pub fn unprocedural(&mut self, host: &str, json: &str, mask: Mask) {
        let id = self.intern_procedural(json);
        self.entry(host).unprocedural.push((id, mask));
    }

    pub fn flags(&mut self, host: &str, flags: u8, mask: Mask) {
        self.entry(host).flags.push((flags, mask));
    }

    /// A generic hiding selector, keyed by `token` (`.class` or `#id`), or
    /// applied everywhere when it has none.
    pub fn generic(&mut self, selector: &str, token: Option<&str>, mask: Mask) {
        let id = self.intern(selector);
        let entry = self
            .generic
            .entry(id)
            .or_insert_with(|| (token.map(str::to_owned), 0));
        entry.1 |= mask;
    }

    /// Removes a generic selector everywhere (`#@#.ad` with no domain).
    pub fn cancel_generic(&mut self, selector: &str) {
        let id = self.intern(selector);
        self.cancelled.insert(id);
    }

    pub fn finish(mut self) -> PageIndex {
        for (id, (token, mask)) in std::mem::take(&mut self.generic) {
            if self.cancelled.contains(&id) {
                continue;
            }
            match token {
                Some(token) => self
                    .index
                    .generic
                    .entry(token)
                    .or_default()
                    .push((id, mask)),
                None => self.index.generic_always.push((id, mask)),
            }
        }
        fn merge(list: &mut Vec<(u32, Mask)>) {
            let mut by_id: BTreeMap<u32, Mask> = BTreeMap::new();
            for &(id, mask) in list.iter() {
                *by_id.entry(id).or_default() |= mask;
            }
            *list = by_id.into_iter().collect();
        }
        for entry in self.index.hosts.values_mut() {
            merge(&mut entry.hide);
            merge(&mut entry.unhide);
            merge(&mut entry.procedural);
            merge(&mut entry.unprocedural);
            entry.styles.sort();
            entry.styles.dedup();
            let mut flags: BTreeMap<u8, Mask> = BTreeMap::new();
            for &(f, m) in &entry.flags {
                *flags.entry(f).or_default() |= m;
            }
            entry.flags = flags.into_iter().collect();
        }
        self.index
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_cover_parents_and_entities() {
        assert_eq!(
            host_keys("www.News.example.co.uk"),
            [
                "www.news.example.co.uk",
                "news.example.co.uk",
                "example.co.uk",
                "co.uk",
                "uk",
                "www.news.example.*",
                "news.example.*",
                "example.*",
            ]
        );
        assert_eq!(
            host_keys("example.com"),
            ["example.com", "com", "example.*"]
        );
        assert_eq!(host_keys("192.0.2.1"), ["192.0.2.1", "0.2.1", "2.1", "1"]);
        assert_eq!(host_keys("localhost"), ["localhost"]);
        assert!(host_keys("").is_empty());
    }

    const ADS: Mask = 1;
    const FIXES: Mask = 2;
    const ALL: Mask = ADS | FIXES;

    fn index() -> PageIndex {
        let mut b = PageIndexBuilder::new();
        b.hide("example.com", ".banner", ADS);
        b.hide("example.*", "#sponsor", ADS);
        b.unhide("shop.example.com", ".banner", FIXES);
        b.style("example.com", "body", "overflow:auto!important", ADS);
        b.procedural("example.com", r#"{"sel":"div","has-text":"Ad"}"#, ADS);
        b.unprocedural(
            "quiet.example.com",
            r#"{"sel":"div","has-text":"Ad"}"#,
            FIXES,
        );
        b.generic(".ad-box", Some(".ad-box"), ADS);
        b.generic(".ad > div", Some(".ad"), ADS);
        b.generic("a[href*=\"/ads/\"]", None, ADS);
        b.generic("#gone", Some("#gone"), ADS);
        b.cancel_generic("#gone");
        b.unhide("example.org", ".ad-box", FIXES);
        b.flags("nogeneric.example", GENERICHIDE, FIXES);
        b.flags("nothing.example", ELEMHIDE, FIXES);
        b.finish()
    }

    #[test]
    fn specific_hiding_follows_hosts_entities_and_exceptions() {
        let i = index();
        let page = i.page("www.example.com", ALL);
        assert!(page.css.contains(".banner{display:none!important}"));
        assert!(page.css.contains("#sponsor{display:none!important}"));
        assert!(page.css.contains("body{overflow:auto!important}"));
        assert_eq!(page.procedural.len(), 1);
        assert!(page.generic);
        // Entity: any public suffix.
        assert!(i.page("example.de", ALL).css.contains("#sponsor"));
        assert!(!i.page("example.de", ALL).css.contains(".banner"));
        // Exception on a subdomain.
        assert!(!i.page("shop.example.com", ALL).css.contains(".banner"));
        assert!(i.page("quiet.example.com", ALL).procedural.is_empty());
        assert_eq!(
            i.page("unrelated.test", ALL),
            Page {
                generic: true,
                ..Page::default()
            }
        );
    }

    #[test]
    fn rulesets_switch_their_own_items() {
        let i = index();
        // Ads off: its hiding stops.
        assert_eq!(i.page("www.example.com", FIXES).css, "");
        // Fixes off: its exception no longer cancels Ads' hiding.
        assert!(i.page("shop.example.com", ADS).css.contains(".banner"));
        assert!(
            i.generic_css("www.example.org", ADS, [".ad-box"], false)
                .contains(".ad-box")
        );
        assert!(i.page("a.nogeneric.example", ADS).generic);
    }

    #[test]
    fn generic_hiding_by_token() {
        let i = index();
        let css = i.generic_css("site.example.net", ALL, [".ad-box", ".unrelated"], false);
        assert_eq!(css, ".ad-box{display:none!important}\n");
        let css = i.generic_css("site.example.net", ALL, [".ad", "#gone"], true);
        assert!(css.contains(".ad > div{"));
        assert!(css.contains("a[href*=\"/ads/\"]{"));
        assert!(!css.contains("#gone"), "cancelled everywhere");
        assert_eq!(
            i.generic_css("www.example.org", ALL, [".ad-box"], false),
            "",
            "cancelled here"
        );
        assert_eq!(
            i.generic_css("a.nogeneric.example", ALL, [".ad-box"], true),
            ""
        );
        assert!(!i.page("a.nogeneric.example", ALL).generic);
        assert_eq!(i.page("nothing.example", ALL), Page::default());
    }

    #[test]
    fn masks_combine_across_rulesets() {
        let mut b = PageIndexBuilder::new();
        b.hide("example.com", ".x", ADS);
        b.hide("example.com", ".x", FIXES);
        b.generic(".g", Some(".g"), ADS);
        b.generic(".g", Some(".g"), FIXES);
        let i = b.finish();
        assert_eq!(i.hosts["example.com"].hide, [(0, ALL)]);
        assert_eq!(i.generic[".g"], [(1, ALL)]);
    }

    #[test]
    fn round_trips_through_bytes() {
        let i = index();
        assert_eq!(PageIndex::from_bytes(&i.to_bytes()).unwrap(), i);
        assert!(PageIndex::from_bytes(b"\xff\xff\xff").is_err());
    }
}
