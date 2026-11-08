//! `sinkhole check <domain|url>`: what the resolver and the extension would
//! do, and which rule decides it.
//!
//! It reads only what is on disk: the resolver's config and its cached
//! lists, and the extension's lists from the compile cache. Nothing is
//! downloaded, and no query is sent.

use std::path::{Path, PathBuf};

use anyhow::{Result, anyhow};
use sinkhole_compiler::explain::{Explainer, Request, Source, Verdict as NetVerdict, site};
use sinkhole_compiler::{ListInput, Manifest};
use sinkhole_core::{Domain, Verdict};
use sinkhole_filters::network::ResourceTypes;
use sinkhole_lists::Cache;
use sinkhole_resolver::from_config;

use crate::{list_inputs, load_config};

pub struct CheckOptions<'a> {
    pub target: &'a str,
    pub kind: Option<&'a str>,
    pub from: Option<&'a str>,
    pub rulesets: &'a Path,
    pub cache: Option<PathBuf>,
}

/// Request type names, as in filter lists and DNR.
const TYPES: &[(&str, ResourceTypes)] = &[
    ("document", ResourceTypes::DOCUMENT),
    ("main_frame", ResourceTypes::DOCUMENT),
    ("subdocument", ResourceTypes::SUBDOCUMENT),
    ("sub_frame", ResourceTypes::SUBDOCUMENT),
    ("script", ResourceTypes::SCRIPT),
    ("image", ResourceTypes::IMAGE),
    ("stylesheet", ResourceTypes::STYLESHEET),
    ("css", ResourceTypes::STYLESHEET),
    ("xmlhttprequest", ResourceTypes::XMLHTTPREQUEST),
    ("xhr", ResourceTypes::XMLHTTPREQUEST),
    ("fetch", ResourceTypes::XMLHTTPREQUEST),
    ("font", ResourceTypes::FONT),
    ("media", ResourceTypes::MEDIA),
    ("ping", ResourceTypes::PING),
    ("websocket", ResourceTypes::WEBSOCKET),
    ("object", ResourceTypes::OBJECT),
    ("other", ResourceTypes::OTHER),
];

fn parse_kind(name: &str) -> Result<ResourceTypes> {
    TYPES
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case(name))
        .map(|(_, t)| *t)
        .ok_or_else(|| {
            let names: Vec<&str> = TYPES.iter().map(|(n, _)| *n).collect();
            anyhow!("unknown request type {name:?}; one of {}", names.join(", "))
        })
}

/// A likely request type from the path's extension.
fn guess_kind(url: &str) -> (ResourceTypes, &'static str) {
    let path = url.split(['?', '#']).next().unwrap_or(url);
    let ext = path
        .rsplit('/')
        .next()
        .and_then(|f| f.rsplit_once('.'))
        .map(|(_, e)| e.to_ascii_lowercase())
        .unwrap_or_default();
    match ext.as_str() {
        "js" | "mjs" => (ResourceTypes::SCRIPT, "script"),
        "css" => (ResourceTypes::STYLESHEET, "stylesheet"),
        "png" | "jpg" | "jpeg" | "gif" | "webp" | "avif" | "svg" | "ico" => {
            (ResourceTypes::IMAGE, "image")
        }
        "woff" | "woff2" | "ttf" | "otf" => (ResourceTypes::FONT, "font"),
        "mp4" | "webm" | "mp3" | "m4a" | "ogg" | "m3u8" => (ResourceTypes::MEDIA, "media"),
        "html" | "htm" => (ResourceTypes::SUBDOCUMENT, "subdocument"),
        _ => (ResourceTypes::XMLHTTPREQUEST, "xmlhttprequest"),
    }
}

fn type_name(kind: ResourceTypes) -> &'static str {
    TYPES
        .iter()
        .find(|(_, t)| *t == kind)
        .map_or("other", |(n, _)| *n)
}

/// The host of a URL, or the target itself if it is a name.
fn host_of(target: &str) -> Result<String> {
    let rest = target.split_once("://").map_or(target, |(_, r)| r);
    let authority = rest.split(['/', '?', '#']).next().unwrap_or(rest);
    let hostport = authority.rsplit('@').next().unwrap_or(authority);
    let host = if hostport.starts_with('[') {
        hostport
            .split(']')
            .next()
            .unwrap_or(hostport)
            .trim_start_matches('[')
    } else {
        hostport.split(':').next().unwrap_or(hostport)
    };
    if host.is_empty() {
        return Err(anyhow!("{target:?} has no host"));
    }
    Ok(host.to_owned())
}

pub fn check(config_path: &Path, o: &CheckOptions<'_>) -> Result<()> {
    let is_url = o.target.contains("://");
    let host = host_of(o.target)?;
    let name = Domain::parse(&host)
        .map(|d| d.as_str().to_owned())
        .unwrap_or_else(|_| host.to_ascii_lowercase());

    let (url, kind, kind_note) = if is_url {
        match (o.kind, o.from) {
            (Some(kind), _) => (o.target.to_owned(), parse_kind(kind)?, ""),
            (None, None) => (o.target.to_owned(), ResourceTypes::DOCUMENT, ""),
            (None, Some(_)) => {
                let (kind, _) = guess_kind(o.target);
                (
                    o.target.to_owned(),
                    kind,
                    " (guessed from the URL; set --type)",
                )
            }
        }
    } else {
        let kind = o.kind.map(parse_kind).transpose()?;
        (
            format!("https://{name}/"),
            kind.unwrap_or(ResourceTypes::SCRIPT),
            "",
        )
    };
    let from = match (o.from, is_url, kind) {
        (Some(from), _, _) => Some(from.to_owned()),
        // A bare name is checked as a third-party request.
        (None, false, _) => Some("https://example.org/".to_owned()),
        (None, true, k) if k != ResourceTypes::DOCUMENT => Some("https://example.org/".to_owned()),
        _ => None,
    };
    let context = match &from {
        Some(from) => format!(
            "{} request from {}",
            type_name(kind),
            host_of(from).unwrap_or_default()
        ),
        None => "page".to_owned(),
    };
    println!("{url} ({context}{kind_note})\n");

    resolver(config_path, &name);
    let lists = match extension_lists(o) {
        Ok(lists) => lists,
        Err(e) => {
            println!("Extension: {e:#}");
            return Ok(());
        }
    };
    network(&lists, &url, kind, from.as_deref());
    if kind == ResourceTypes::DOCUMENT {
        page(&lists, o.rulesets, &name);
    }
    Ok(())
}

fn resolver(config_path: &Path, name: &str) {
    println!("Resolver (every app; DNS name {name}):");
    let loaded = load_config(config_path).and_then(|(config, base, cache)| {
        let setup = from_config(&config, &base, &cache)?;
        Ok((config, setup))
    });
    let (config, setup) = match loaded {
        Ok(loaded) => loaded,
        Err(e) => {
            println!("  not checked: {e:#}\n");
            return;
        }
    };
    let matcher = setup.engine.matcher();
    let local = |entries: &[String], rule: &str| {
        entries
            .iter()
            .filter_map(|e| crate::edit::normalize(e).ok())
            .any(|e| e.trim_start_matches("*.") == rule)
    };
    match matcher.check(name) {
        Verdict::Blocked { rule, .. } => {
            let from = if local(&config.block, rule) {
                "the local blocklist"
            } else {
                "a blocklist"
            };
            let answer = match config.blocking.response {
                sinkhole_core::config::BlockResponse::NullAddress => "0.0.0.0 / ::",
                sinkhole_core::config::BlockResponse::Nxdomain => "NXDOMAIN",
            };
            println!("  BLOCKED by `{rule}` in {from}: answered {answer}");
            println!("  unblock it with `sinkhole allow add {name}`");
        }
        Verdict::Allowed { rule, .. } => {
            let from = if local(&config.allow, rule) {
                "the local allowlist"
            } else {
                "an allowlist"
            };
            println!("  allowed by `{rule}` in {from}, which beats every blocklist");
        }
        Verdict::NotListed => {
            let upstream = setup
                .upstreams
                .describe()
                .into_iter()
                .next()
                .unwrap_or_default();
            println!("  not listed: forwarded to {upstream}");
            if config.blocking.cname_uncloaking {
                println!(
                    "  (blocked after all if its answer is an alias, a CNAME, of a listed name)"
                );
            }
        }
    }
    if !setup.missing.is_empty() {
        println!(
            "  note: {} list(s) not downloaded yet; run `sinkhole update`",
            setup.missing.len()
        );
    }
    println!();
}

/// The extension's lists, from the compile cache.
fn extension_lists(o: &CheckOptions<'_>) -> Result<Vec<ListInput>> {
    let text = std::fs::read_to_string(o.rulesets).map_err(|e| {
        anyhow!(
            "not checked: reading {}: {e} (pass --rulesets, or run from the repository)",
            o.rulesets.display()
        )
    })?;
    let manifest = Manifest::from_toml(&text)?;
    let cache = Cache::new(match &o.cache {
        Some(dir) => dir.clone(),
        None => sinkhole_lists::default_cache_dir()
            .ok_or_else(|| anyhow!("no home directory for the list cache; pass --cache"))?,
    });
    let base = o.rulesets.parent().unwrap_or(Path::new("."));
    let (inputs, missing) = list_inputs(&manifest, base, &cache)?;
    for name in &missing {
        println!("note: {name} is not in the list cache; run `sinkhole compile` once");
    }
    Ok(inputs)
}

fn describe_source(s: &Source) -> String {
    let chrome = match &s.chrome {
        Ok(narrowed) if narrowed.is_empty() => "the extension applies it".to_owned(),
        Ok(narrowed) => format!("the extension applies it, without {}", narrowed.join(", ")),
        Err(reason) => format!("the extension CANNOT apply it ({reason})"),
    };
    format!(
        "`{}`\n    {}, line {} (ruleset \"{}\"); {chrome}",
        s.text, s.list, s.line, s.ruleset
    )
}

fn network(lists: &[ListInput], url: &str, kind: ResourceTypes, from: Option<&str>) {
    println!("Extension, network (browser only):");
    let mut explainer = Explainer::new(lists);
    let x = explainer.explain(&Request {
        url,
        kind,
        initiator: from,
        method: "GET",
    });
    match &x.verdict {
        NetVerdict::Unlisted => println!("  not blocked: no rule matches"),
        NetVerdict::Blocked { by, important } => {
            let important = if *important { " ($important)" } else { "" };
            println!("  BLOCKED{important} by {}", describe_source(by));
        }
        NetVerdict::Redirected {
            by,
            redirect,
            resource,
        } if by == redirect => {
            println!(
                "  BLOCKED and answered with the surrogate {resource}, by {}",
                describe_source(by)
            );
        }
        NetVerdict::Redirected {
            by,
            redirect,
            resource,
        } => {
            println!("  BLOCKED by {}", describe_source(by));
            println!(
                "  and answered with the surrogate {resource}, by {}",
                describe_source(redirect)
            );
        }
        NetVerdict::Allowed { by, over } => {
            println!("  allowed by the exception {}", describe_source(by));
            for b in over {
                println!("  over {}", describe_source(b));
            }
        }
        NetVerdict::PageAllowed { by } => {
            println!(
                "  allowed: the page has filtering switched off by {}",
                describe_source(by)
            );
        }
    }
    for (rule, stripped) in &x.params {
        println!(
            "  strips {} by {}",
            stripped.join(", "),
            describe_source(rule)
        );
    }
    // Header rules ($permissions, $csp) come by the dozen; show a few.
    const SHOWN: usize = 3;
    for rule in x.modifiers.iter().take(SHOWN) {
        println!("  modified by {}", describe_source(rule));
    }
    if x.modifiers.len() > SHOWN {
        let applied = x.modifiers.iter().filter(|m| m.chrome.is_ok()).count();
        println!(
            "  … and {} more modifying rules ({applied} of all {} applied by the extension)",
            x.modifiers.len() - SHOWN,
            x.modifiers.len()
        );
    }
    if let Some(from) = from {
        let third =
            site(&host_of(url).unwrap_or_default()) != site(&host_of(from).unwrap_or_default());
        println!(
            "  ({} for privacy rules: cookies and Referer are stripped from third-party tracker requests)",
            if third { "third-party" } else { "first-party" }
        );
    }
    println!();
}

fn page(lists: &[ListInput], rulesets: &Path, host: &str) {
    println!("Extension, page rules on {host}:");
    let Ok(manifest) = std::fs::read_to_string(rulesets)
        .map_err(anyhow::Error::from)
        .and_then(|t| Ok(Manifest::from_toml(&t)?))
    else {
        return;
    };
    let compiled = sinkhole_compiler::compile(lists, manifest.params_ruleset.as_deref());
    let page = &compiled.page;
    let mask = manifest
        .rulesets
        .iter()
        .filter(|r| r.enabled)
        .filter_map(|r| page.masks.get(&r.id))
        .fold(0u8, |m, bit| m | bit);
    let view = page.index.page(host, mask);
    let selectors: Vec<&str> = view
        .css
        .lines()
        .filter_map(|l| l.split('{').next())
        .flat_map(|s| s.split(", "))
        .filter(|s| !s.is_empty())
        .collect();
    println!(
        "  hiding: {} site-specific selector(s){}",
        selectors.len(),
        if selectors.is_empty() { "" } else { ":" }
    );
    for s in selectors.iter().take(10) {
        println!("    {s}");
    }
    if selectors.len() > 10 {
        println!("    … and {} more", selectors.len() - 10);
    }
    if !view.procedural.is_empty() {
        println!("  procedural rules: {}", view.procedural.len());
    }
    println!(
        "  generic hiding: {}",
        if view.generic {
            "on (selectors applied as matching elements appear)"
        } else {
            "off on this site ($generichide or $elemhide)"
        }
    );
    let calls = page.calls_for(host);
    println!("  scriptlets: {}", calls.len());
    for (ruleset, call) in calls.iter().take(15) {
        let (name, args) = call
            .split_first()
            .map_or(("?", &[][..]), |(n, a)| (n.as_str(), a));
        let args: Vec<String> = args.iter().map(|a| format!("{a:?}")).collect();
        println!("    {name}({}) [{ruleset}]", args.join(", "));
    }
    if calls.len() > 15 {
        println!("    … and {} more", calls.len() - 15);
    }
    println!();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hosts_and_types() {
        assert_eq!(host_of("https://a.example:8443/x?y").unwrap(), "a.example");
        assert_eq!(host_of("https://u:p@a.example/").unwrap(), "a.example");
        assert_eq!(host_of("http://[::1]:80/").unwrap(), "::1");
        assert_eq!(host_of("ads.example").unwrap(), "ads.example");
        assert!(host_of("https:///x").is_err());
        assert_eq!(guess_kind("https://x/a.js?v=1").1, "script");
        assert_eq!(guess_kind("https://x/pixel.GIF").1, "image");
        assert_eq!(guess_kind("https://x/api/v1").1, "xmlhttprequest");
        assert!(parse_kind("Script").is_ok());
        assert!(parse_kind("popunder").is_err());
    }
}
