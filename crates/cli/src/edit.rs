//! `sinkhole allow` and `sinkhole block`: editing the config's local
//! entries.
//!
//! The file is edited in place with its comments and layout kept, checked
//! as a whole before it is written, and replaced atomically (write a
//! sibling, then rename), so a running daemon never reads it half-written.
//! The daemon applies the change within seconds by itself; when it is
//! running, it is also asked to reload at once. The browser bridge passes
//! the same entries to the extension.

use std::path::Path;

use anyhow::{Context, Result, anyhow, bail};
use sinkhole_core::Scope;
use sinkhole_core::config::Config;
use sinkhole_core::matcher::parse_domain_pattern;
use toml_edit::{Array, DocumentMut, Item, Value};

use crate::ctl::reload_if_running;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Which {
    Allow,
    Block,
}

impl Which {
    fn key(self) -> &'static str {
        match self {
            Which::Allow => "allow",
            Which::Block => "block",
        }
    }

    fn other(self) -> Which {
        match self {
            Which::Allow => Which::Block,
            Which::Block => Which::Allow,
        }
    }

    fn noun(self) -> &'static str {
        match self {
            Which::Allow => "allowlist",
            Which::Block => "blocklist",
        }
    }
}

/// An entry as the config stores it: lower case, punycode, `*.` for
/// "below this name only".
pub fn normalize(entry: &str) -> Result<String> {
    let (domain, scope) =
        parse_domain_pattern(entry).map_err(|e| anyhow!("{entry:?} is not a domain: {e}"))?;
    Ok(match scope {
        Scope::Subtree => domain.as_str().to_owned(),
        Scope::Subdomains => format!("*.{}", domain.as_str()),
    })
}

fn read(path: &Path) -> Result<DocumentMut> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    text.parse::<DocumentMut>()
        .with_context(|| format!("in {}", path.display()))
}

/// The entries of `which`, normalized where they parse.
fn entries(doc: &DocumentMut, which: Which) -> Vec<String> {
    doc.get(which.key())
        .and_then(Item::as_array)
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

fn array_mut(doc: &mut DocumentMut, which: Which) -> Result<&mut Array> {
    let item = doc
        .entry(which.key())
        .or_insert_with(|| Item::Value(Value::Array(Array::new())));
    item.as_array_mut().ok_or_else(|| {
        anyhow!(
            "`{}` in the config is not a list of names; fix it by hand",
            which.key()
        )
    })
}

fn same(a: &str, b: &str) -> bool {
    match (normalize(a), normalize(b)) {
        (Ok(a), Ok(b)) => a == b,
        _ => a == b,
    }
}

pub fn add(path: &Path, which: Which, new: &[String]) -> Result<()> {
    let mut doc = read(path)?;
    let existing = entries(&doc, which);
    let others = entries(&doc, which.other());
    let mut added = Vec::new();
    for entry in new {
        let entry = normalize(entry)?;
        if existing.iter().chain(&added).any(|e| same(e, &entry)) {
            println!("{entry} is already on the {}.", which.noun());
            continue;
        }
        if which == Which::Block && others.iter().any(|e| same(e, &entry)) {
            println!("note: {entry} is also on the allowlist, which wins.");
        }
        added.push(entry);
    }
    if added.is_empty() {
        return Ok(());
    }
    let array = array_mut(&mut doc, which)?;
    for entry in &added {
        array.push(entry.as_str());
    }
    write(path, &doc)?;
    for entry in &added {
        println!("Added {entry} to the {}.", which.noun());
    }
    applied(path);
    Ok(())
}

pub fn remove(path: &Path, which: Which, gone: &[String]) -> Result<()> {
    let mut doc = read(path)?;
    let array = array_mut(&mut doc, which)?;
    let mut removed = Vec::new();
    let mut missing = Vec::new();
    for entry in gone {
        let before = array.len();
        array.retain(|v| !v.as_str().is_some_and(|s| same(s, entry)));
        if array.len() < before {
            removed.push(entry.as_str());
        } else {
            missing.push(entry.as_str());
        }
    }
    if !removed.is_empty() {
        write(path, &doc)?;
        for entry in &removed {
            println!("Removed {entry} from the {}.", which.noun());
        }
        applied(path);
    }
    for entry in &missing {
        println!(
            "{entry} is not on the {} in {}.",
            which.noun(),
            path.display()
        );
    }
    if removed.is_empty() {
        bail!("nothing removed");
    }
    Ok(())
}

pub fn show(path: &Path, which: Which) -> Result<()> {
    let doc = read(path)?;
    let list = entries(&doc, which);
    if list.is_empty() {
        println!("The local {} is empty ({}).", which.noun(), path.display());
    }
    for entry in list {
        println!("{entry}");
    }
    Ok(())
}

/// Checks the edited config as the daemon would, then replaces the file.
fn write(path: &Path, doc: &DocumentMut) -> Result<()> {
    let text = doc.to_string();
    Config::from_toml(&text).context("the edited config would not load; nothing was written")?;
    let dir = path.parent().unwrap_or(Path::new("."));
    let name = path
        .file_name()
        .ok_or_else(|| anyhow!("{} is not a file", path.display()))?;
    let tmp = dir.join(format!(".{}.tmp", name.to_string_lossy()));
    std::fs::write(&tmp, &text).with_context(|| {
        format!(
            "writing {} (editing the installed config needs sudo)",
            tmp.display()
        )
    })?;
    let permissions = std::fs::metadata(path)?.permissions();
    std::fs::set_permissions(&tmp, permissions)?;
    std::fs::rename(&tmp, path).with_context(|| format!("replacing {}", path.display()))?;
    Ok(())
}

fn applied(path: &Path) {
    if reload_if_running(path) {
        println!("Applied: the running resolver reloaded its rules.");
    } else {
        println!(
            "It applies when sinkhole runs (a running resolver picks up edits within seconds)."
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entries_normalize() {
        assert_eq!(normalize("Ads.Example.COM.").unwrap(), "ads.example.com");
        assert_eq!(normalize("*.example.com").unwrap(), "*.example.com");
        assert_eq!(
            normalize("bücher.example").unwrap(),
            "xn--bcher-kva.example"
        );
        assert!(normalize("not a domain").is_err());
        assert!(normalize("a*b.example").is_err());
    }

    #[test]
    fn edits_keep_comments_and_check_the_result() {
        let dir = std::env::temp_dir().join(format!("sinkhole-edit-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("sinkhole.toml");
        let original = "# my settings\nallow = [\"keep.example\"] # mine\n\n[listen]\naddrs = [\"127.0.0.1:5300\"]\n";
        std::fs::write(&path, original).unwrap();

        add(
            &path,
            Which::Block,
            &["Ads.Example".into(), "ads.example".into()],
        )
        .unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.starts_with("# my settings\nallow = [\"keep.example\"] # mine\n"));
        assert!(text.contains("block = [\"ads.example\"]"));
        let config = Config::from_toml(&text).unwrap();
        assert_eq!(config.block, ["ads.example"]);

        remove(&path, Which::Block, &["ADS.example".into()]).unwrap();
        let config = Config::from_toml(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert!(config.block.is_empty());
        assert!(remove(&path, Which::Block, &["ads.example".into()]).is_err());
        assert!(add(&path, Which::Allow, &["bad name".into()]).is_err());
        assert_eq!(
            Config::from_toml(&std::fs::read_to_string(&path).unwrap())
                .unwrap()
                .allow,
            ["keep.example"]
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
