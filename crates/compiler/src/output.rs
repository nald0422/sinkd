//! Writing a build: rulesets, surrogates, the domain set and the report.
//!
//! ```text
//! <out>/rulesets/<id>.json   DNR rules, one per line
//! <out>/rulesets.json        index: id, name, enabled, path, counts
//! <out>/popups.json          per ruleset, its rules for the tabs pages open
//!                            (`$popup`), which the extension applies itself
//! <out>/war/*                surrogates (web-accessible resources)
//! <out>/dns/block.txt        the resolver's domain set ("domains" format)
//! <out>/dns/allow.txt
//! <out>/page/index.bin       the page index (cosmetic rules), for the wasm engine
//! <out>/scriptlets/<id>-<n>.js  a ruleset's scriptlets for a bucket of sites,
//!                            registered as MAIN-world content scripts
//! <out>/scriptlets.json      where to register each of them
//! <out>/report.json          everything a target could not take, and why
//! <out>/NOTICES.txt          the lists a build includes, with their licenses
//! ```

use std::collections::BTreeSet;
use std::fs;
use std::io;
use std::path::Path;

use serde::Serialize;

use crate::compile::Compiled;
use crate::manifest::Manifest;
use crate::resources::{self, WAR_DIR};

/// An entry of `rulesets.json`, which the extension build turns into the
/// manifest's `rule_resources` and the popup shows.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IndexEntry<'a> {
    pub id: &'a str,
    pub name: &'a str,
    pub description: &'a str,
    pub enabled: bool,
    pub path: String,
    pub rules: usize,
    pub regex_rules: usize,
    /// The ruleset's bit in the page index's masks; 0 if it has none.
    pub mask: u8,
}

/// An entry of `uncloak.json`: a ruleset's hosts (see [`crate::compile::Hosts`]).
#[derive(Debug, Serialize)]
pub struct UncloakEntry<'a> {
    pub ruleset: &'a str,
    pub block: &'a [String],
    pub exempt: &'a [String],
    pub documents: &'a [String],
}

/// An entry of `popups.json`: a ruleset's rules for new tabs, numbered and
/// shaped as DNR rules (see [`crate::translate::translate_popup`]).
#[derive(Debug, Serialize)]
pub struct PopupEntry<'a> {
    pub ruleset: &'a str,
    pub rules: &'a [crate::dnr::Rule],
}

/// An entry of `scriptlets.json`.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScriptletEntry<'a> {
    pub ruleset: &'a str,
    pub file: String,
    pub matches: &'a [String],
    pub calls: usize,
}

pub fn write(compiled: &Compiled, manifest: &Manifest, out: &Path) -> io::Result<()> {
    let rulesets_dir = out.join("rulesets");
    fs::create_dir_all(&rulesets_dir)?;
    let mut index = Vec::new();
    for ruleset in &compiled.rulesets {
        let mut json = String::from("[\n");
        for (i, rule) in ruleset.rules.iter().enumerate() {
            if i > 0 {
                json.push_str(",\n");
            }
            json.push_str(&serde_json::to_string(rule).map_err(io::Error::other)?);
        }
        json.push_str("\n]\n");
        let path = format!("rulesets/{}.json", ruleset.id);
        fs::write(out.join(&path), json)?;
        let spec = manifest.rulesets.iter().find(|r| r.id == ruleset.id);
        let report = compiled.report.rulesets.iter().find(|r| r.id == ruleset.id);
        index.push(IndexEntry {
            id: &ruleset.id,
            name: spec.map_or(ruleset.id.as_str(), |s| s.name.as_str()),
            description: spec.map_or("", |s| s.description.as_str()),
            enabled: spec.is_none_or(|s| s.enabled),
            path,
            rules: ruleset.rules.len(),
            regex_rules: report.map_or(0, |r| r.regex_rules),
            mask: compiled.page.masks.get(&ruleset.id).copied().unwrap_or(0),
        });
    }
    fs::write(out.join("rulesets.json"), pretty(&index)?)?;
    let popups: Vec<PopupEntry> = compiled
        .popups
        .iter()
        .map(|r| PopupEntry {
            ruleset: &r.id,
            rules: &r.rules,
        })
        .collect();
    fs::write(out.join("popups.json"), serde_json::to_string(&popups)?)?;

    // Third-party trackers, for the extension's cookie and Referer rules.
    let mut trackers: BTreeSet<&str> = BTreeSet::new();
    for spec in manifest.rulesets.iter().filter(|r| r.trackers) {
        if let Some(hosts) = compiled.hosts.get(&spec.id) {
            trackers.extend(hosts.block.iter().map(String::as_str));
        }
    }
    fs::write(out.join("trackers.json"), pretty(&trackers)?)?;
    // Every ruleset's hosts, for CNAME uncloaking (Firefox).
    let uncloak: Vec<UncloakEntry> = compiled
        .hosts
        .iter()
        .map(|(id, hosts)| UncloakEntry {
            ruleset: id,
            block: &hosts.block,
            exempt: &hosts.exempt,
            documents: &hosts.documents,
        })
        .collect();
    fs::write(out.join("uncloak.json"), serde_json::to_string(&uncloak)?)?;
    // How the extension tells a site from its public suffix.
    fs::write(
        out.join("suffixes.json"),
        pretty(&sinkd_core::page::TWO_LABEL_SUFFIXES)?,
    )?;

    let page = out.join("page");
    fs::create_dir_all(&page)?;
    fs::write(page.join("index.bin"), compiled.page.index.to_bytes())?;
    let scriptlets = out.join("scriptlets");
    // Files of rulesets that no longer have scriptlets must not linger.
    if scriptlets.exists() {
        fs::remove_dir_all(&scriptlets)?;
    }
    fs::create_dir_all(&scriptlets)?;
    let mut entries = Vec::new();
    for file in &compiled.page.scriptlets {
        let path = format!("scriptlets/{}.js", file.name);
        fs::write(out.join(&path), &file.js)?;
        entries.push(ScriptletEntry {
            ruleset: &file.ruleset,
            file: path,
            matches: &file.matches,
            calls: file.calls,
        });
    }
    fs::write(out.join("scriptlets.json"), pretty(&entries)?)?;

    let war = out.join(WAR_DIR);
    fs::create_dir_all(&war)?;
    for resource in resources::all() {
        fs::write(war.join(resource.name), resource.body)?;
    }

    let dns = out.join("dns");
    fs::create_dir_all(&dns)?;
    let lines = |names: &[String]| {
        let mut text = names.join("\n");
        text.push('\n');
        text
    };
    fs::write(dns.join("block.txt"), lines(&compiled.dns.block))?;
    fs::write(dns.join("allow.txt"), lines(&compiled.dns.allow))?;

    fs::write(out.join("report.json"), pretty(&compiled.report)?)?;
    fs::write(out.join("NOTICES.txt"), notices(manifest))?;
    Ok(())
}

/// Attribution for every list the rules came from. The rules are compiled
/// from these lists, so their licenses apply to a build that ships them.
fn notices(manifest: &Manifest) -> String {
    let mut text = String::from(
        "The blocking rules in this extension are compiled from the filter lists\n\
         below. Each list's license applies to the rules compiled from it.\n\n",
    );
    for list in &manifest.lists {
        text.push_str(&format!("{}\n", list.name));
        if let Some(url) = &list.url {
            text.push_str(&format!("  source:   {url}\n"));
        }
        if let Some(homepage) = &list.homepage {
            text.push_str(&format!("  homepage: {homepage}\n"));
        }
        let license = list.license.as_deref().unwrap_or("not stated");
        text.push_str(&format!("  license:  {license}\n\n"));
    }
    text.push_str(
        "The surrogate scripts under war/ are original implementations,\n\
         licensed MIT OR Apache-2.0.\n",
    );
    text
}

fn pretty<T: Serialize>(value: &T) -> io::Result<String> {
    let mut json = serde_json::to_string_pretty(value).map_err(io::Error::other)?;
    json.push('\n');
    Ok(json)
}
