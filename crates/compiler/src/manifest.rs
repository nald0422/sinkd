//! The build manifest (`rulesets.toml`): which lists make up which ruleset.
//!
//! ```toml
//! params_ruleset = "params"
//!
//! [[ruleset]]
//! id = "ads"
//! name = "Ads"
//! lists = ["easylist", "surrogates"]
//!
//! [[list]]
//! name = "easylist"
//! url = "https://easylist.to/easylist/easylist.txt"
//! license = "GPL-3.0-or-later OR CC-BY-SA-3.0"
//!
//! [[list]]
//! name = "surrogates"
//! path = "lists/surrogates.txt"
//! ```

use std::collections::HashSet;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    /// The ruleset every `$removeparam` rule goes to, whatever its list.
    #[serde(default)]
    pub params_ruleset: Option<String>,
    #[serde(rename = "ruleset")]
    pub rulesets: Vec<RulesetSpec>,
    #[serde(rename = "list")]
    pub lists: Vec<ListSpec>,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RulesetSpec {
    /// `[a-z0-9_-]+`: the ruleset's id in the extension.
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub description: String,
    /// Enabled when the extension is installed.
    #[serde(default = "yes")]
    pub enabled: bool,
    pub lists: Vec<String>,
    /// The hosts its `||host^` block rules name are third-party trackers:
    /// the extension strips cookies and `Referer` from requests to them
    /// that are not blocked (an exception, or this ruleset switched off).
    #[serde(default)]
    pub trackers: bool,
}

fn yes() -> bool {
    true
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ListSpec {
    pub name: String,
    #[serde(default)]
    pub url: Option<String>,
    /// Relative to the manifest's directory.
    #[serde(default)]
    pub path: Option<PathBuf>,
    /// SPDX expression, recorded in the build's notices.
    #[serde(default)]
    pub license: Option<String>,
    #[serde(default)]
    pub homepage: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum ManifestError {
    #[error(transparent)]
    Syntax(#[from] toml::de::Error),
    #[error("{0}")]
    Invalid(String),
}

impl Manifest {
    pub fn from_toml(text: &str) -> Result<Manifest, ManifestError> {
        let manifest: Manifest = toml::from_str(text)?;
        manifest.validate().map_err(ManifestError::Invalid)?;
        Ok(manifest)
    }

    /// The ruleset a list belongs to.
    pub fn ruleset_of(&self, list: &str) -> Option<&RulesetSpec> {
        self.rulesets
            .iter()
            .find(|r| r.lists.iter().any(|l| l == list))
    }

    fn validate(&self) -> Result<(), String> {
        let mut ids = HashSet::new();
        for r in &self.rulesets {
            let id_ok = !r.id.is_empty()
                && r.id.bytes().all(|b| {
                    b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-'
                });
            if !id_ok {
                return Err(format!("ruleset id {:?} must match [a-z0-9_-]+", r.id));
            }
            if !ids.insert(r.id.as_str()) {
                return Err(format!("ruleset {:?} is defined twice", r.id));
            }
        }
        if let Some(params) = &self.params_ruleset
            && !ids.contains(params.as_str())
        {
            return Err(format!("params_ruleset {params:?} is not a ruleset"));
        }
        let mut names = HashSet::new();
        for l in &self.lists {
            if !names.insert(l.name.as_str()) {
                return Err(format!("list {:?} is defined twice", l.name));
            }
            match (&l.url, &l.path) {
                (Some(url), None) if url.starts_with("https://") => {}
                (Some(url), None) => {
                    return Err(format!("list {:?}: {url} is not https://", l.name));
                }
                (None, Some(_)) => {}
                _ => {
                    return Err(format!(
                        "list {:?}: set exactly one of url and path",
                        l.name
                    ));
                }
            }
            let owners = self
                .rulesets
                .iter()
                .filter(|r| r.lists.contains(&l.name))
                .count();
            if owners != 1 {
                return Err(format!(
                    "list {:?} must belong to exactly one ruleset (it is in {owners})",
                    l.name
                ));
            }
        }
        for r in &self.rulesets {
            for l in &r.lists {
                if !names.contains(l.as_str()) {
                    return Err(format!("ruleset {:?} names unknown list {l:?}", r.id));
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOOD: &str = r#"
        params_ruleset = "params"
        [[ruleset]]
        id = "ads"
        name = "Ads"
        lists = ["easylist", "local"]
        [[ruleset]]
        id = "params"
        name = "Tracking parameters"
        lists = []
        [[list]]
        name = "easylist"
        url = "https://easylist.to/easylist/easylist.txt"
        [[list]]
        name = "local"
        path = "lists/local.txt"
    "#;

    #[test]
    fn parses_and_validates() {
        let m = Manifest::from_toml(GOOD).unwrap();
        assert_eq!(m.ruleset_of("local").unwrap().id, "ads");
        assert!(m.rulesets[0].enabled);
        for (from, to) in [
            ("id = \"ads\"", "id = \"Ads!\""),
            ("params_ruleset = \"params\"", "params_ruleset = \"nope\""),
            ("https://easylist.to", "http://easylist.to"),
            (
                "lists = [\"easylist\", \"local\"]",
                "lists = [\"easylist\"]",
            ),
            ("lists = []", "lists = [\"ghost\"]"),
        ] {
            let bad = GOOD.replace(from, to);
            assert!(Manifest::from_toml(&bad).is_err(), "{to}");
        }
    }
}
