//! The bundled surrogates: what `$redirect=` can name.
//!
//! Names follow uBlock Origin's resource names, aliases included, so
//! community lists select them unchanged. The files themselves are
//! sinkhole's own (see `resources/README.md`). They are compiled into the
//! binary, so the compiler and the extension can never disagree about which
//! resources exist.

/// Where surrogates live inside the extension, as web-accessible resources.
pub const WAR_DIR: &str = "war";

/// One bundled resource.
#[derive(Debug)]
pub struct Resource {
    /// The file name, under [`WAR_DIR`].
    pub name: &'static str,
    /// Other names lists use for it.
    pub aliases: &'static [&'static str],
    pub body: &'static [u8],
}

impl Resource {
    /// The path a DNR redirect uses: `/war/<name>`.
    pub fn extension_path(&self) -> String {
        format!("/{WAR_DIR}/{}", self.name)
    }
}

macro_rules! resources {
    ($($name:literal => [$($alias:literal),*]),* $(,)?) => {
        &[$(Resource {
            name: $name,
            aliases: &[$($alias),*],
            body: include_bytes!(concat!("../resources/", $name)),
        }),*]
    };
}

static RESOURCES: &[Resource] = resources! {
    "noop.js" => ["noopjs", "abp-resource:blank-js"],
    "noop.txt" => ["nooptext"],
    "noop.html" => ["noopframe", "abp-resource:blank-html"],
    "noop.css" => ["noopcss", "abp-resource:blank-css"],
    "noop.json" => ["noopjson"],
    "noop-0.1s.mp3" => ["noopmp3-0.1s", "abp-resource:blank-mp3"],
    "1x1.gif" => ["1x1-transparent.gif", "abp-resource:1x1-transparent-gif"],
    "2x2.png" => ["2x2-transparent.png", "abp-resource:2x2-transparent-png"],
    "3x2.png" => ["3x2-transparent.png", "abp-resource:3x2-transparent-png"],
    "32x32.png" => ["32x32-transparent.png", "abp-resource:32x32-transparent-png"],
    "googletagservices_gpt.js" => ["googletagservices.com/gpt.js", "googletagservices-gpt"],
    "googlesyndication_adsbygoogle.js" => [
        "googlesyndication.com/adsbygoogle.js",
        "googlesyndication-adsbygoogle"
    ],
    "google-analytics_analytics.js" => ["google-analytics.com/analytics.js"],
    "google-analytics_ga.js" => ["google-analytics.com/ga.js"],
    "googletagmanager_gtm.js" => [
        "googletagmanager.com/gtm.js",
        "googletagmanager_gtag.js",
        "googletagmanager.com/gtag/js"
    ],
    "amazon_apstag.js" => ["amazon-adsystem.com/aax2/apstag.js"],
    "scorecardresearch_beacon.js" => ["scorecardresearch.com/beacon.js"],
    "doubleclick_instream_ad_status.js" => ["doubleclick.net/instream/ad_status.js"],
};

/// Every bundled resource.
pub fn all() -> &'static [Resource] {
    RESOURCES
}

/// The resource a `$redirect=` name selects, by name or alias.
pub fn find(name: &str) -> Option<&'static Resource> {
    RESOURCES
        .iter()
        .find(|r| r.name == name || r.aliases.contains(&name))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_and_aliases_resolve() {
        assert_eq!(find("noop.js").unwrap().name, "noop.js");
        assert_eq!(find("noopjs").unwrap().name, "noop.js");
        assert_eq!(
            find("googletagservices.com/gpt.js")
                .unwrap()
                .extension_path(),
            "/war/googletagservices_gpt.js"
        );
        assert!(find("noop-1s.mp4").is_none());
    }

    #[test]
    fn names_are_unique_and_files_plausible() {
        let mut seen = std::collections::HashSet::new();
        for r in all() {
            for n in std::iter::once(&r.name).chain(r.aliases) {
                assert!(seen.insert(*n), "duplicate name {n}");
            }
            assert!(!r.name.contains('/'), "{}", r.name);
        }
        assert!(find("1x1.gif").unwrap().body.starts_with(b"GIF89a"));
        assert!(find("2x2.png").unwrap().body.starts_with(b"\x89PNG"));
        let gpt = std::str::from_utf8(find("googletagservices_gpt.js").unwrap().body).unwrap();
        assert!(gpt.contains("cmd.push"));
        for r in all() {
            assert!(
                !String::from_utf8_lossy(r.body)
                    .to_lowercase()
                    .contains("sinkhole"),
                "{} names the extension",
                r.name
            );
        }
    }
}
