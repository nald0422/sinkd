//! Building a resolver from a config file and lists on disk.
#![allow(clippy::unwrap_used)]

use std::path::{Path, PathBuf};

use sinkd_core::config::Config;
use sinkd_lists::{Cache, Meta};
use sinkd_resolver::{Setup, SetupError};

/// A scratch directory removed on drop.
struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Scratch {
        let dir = std::env::temp_dir().join(format!("sinkd-{name}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        Scratch(dir)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

const UDP_UPSTREAM: &str = "[[upstream]]\nprotocol = \"udp\"\naddr = \"192.0.2.53:53\"\n";

/// Builds with a cache directory that holds nothing.
fn from_config(config: &Config, base: &Path) -> Result<Setup, SetupError> {
    sinkd_resolver::from_config(config, base, &Cache::new("/nonexistent/cache"))
}

fn blocked(setup: &Setup, name: &str) -> bool {
    setup.engine.matcher().check(name).is_blocked()
}

#[test]
fn lists_and_local_entries() {
    let dir = Scratch::new("lists");
    std::fs::write(
        dir.0.join("hosts.txt"),
        "# comment\n0.0.0.0 ads.example\n127.0.0.1 localhost\n0.0.0.0 tracker.example\n",
    )
    .unwrap();
    std::fs::write(
        dir.0.join("adblock.txt"),
        b"||metrics.example^\n@@||ok.tracker.example^\n##.banner\n\xff\xfe broken line\n"
            .as_slice(),
    )
    .unwrap();
    std::fs::write(dir.0.join("off.txt"), "everything.example\n").unwrap();
    let config = Config::from_toml(&format!(
        "allow = [\"cdn.ads.example\"]
        block = [\"*.local-block.example\"]
        {UDP_UPSTREAM}
        [[list]]
        path = \"hosts.txt\"
        format = \"hosts\"
        [[list]]
        path = \"adblock.txt\"
        [[list]]
        path = \"off.txt\"
        enabled = false
        "
    ))
    .unwrap();
    let setup = from_config(&config, &dir.0).unwrap();

    assert!(blocked(&setup, "ads.example"));
    assert!(blocked(&setup, "x.ads.example"));
    assert!(
        !blocked(&setup, "cdn.ads.example"),
        "local allow beats the list"
    );
    assert!(blocked(&setup, "metrics.example"));
    assert!(
        !blocked(&setup, "ok.tracker.example"),
        "list @@ beats list block"
    );
    assert!(blocked(&setup, "a.local-block.example"));
    assert!(!blocked(&setup, "local-block.example"));
    assert!(!blocked(&setup, "localhost"));
    assert!(
        !blocked(&setup, "everything.example"),
        "disabled lists are skipped"
    );

    let r = &setup.report;
    assert_eq!(r.block_entries, 4);
    assert_eq!(r.allow_entries, 2);
    assert!(r.rejected.contains_key("dns:page-rule"), "{:?}", r.rejected);
    assert_eq!(setup.upstreams.describe(), ["udp://192.0.2.53:53"]);
}

#[test]
fn absolute_list_paths_ignore_the_base() {
    let dir = Scratch::new("abs");
    let list = dir.0.join("domains.txt");
    std::fs::write(&list, "ads.example\n").unwrap();
    let config = Config::from_toml(&format!(
        "{UDP_UPSTREAM}[[list]]\npath = {:?}\n",
        list.display().to_string()
    ))
    .unwrap();
    let setup = from_config(&config, std::path::Path::new("/nonexistent")).unwrap();
    assert!(blocked(&setup, "ads.example"));
}

#[test]
fn missing_list_file_is_an_error() {
    let config =
        Config::from_toml(&format!("{UDP_UPSTREAM}[[list]]\npath = \"nope.txt\"\n")).unwrap();
    let e = from_config(&config, std::path::Path::new("/nonexistent")).unwrap_err();
    assert!(matches!(e, SetupError::ReadList { index: 0, .. }), "{e}");
    assert!(e.to_string().contains("nope.txt"));
}

#[test]
fn the_default_config_uses_doh() {
    let setup = from_config(&Config::default(), Path::new(".")).unwrap();
    assert_eq!(
        setup.upstreams.describe(),
        [
            "https://dns.quad9.net/dns-query",
            "https://cloudflare-dns.com/dns-query"
        ]
    );
}

#[test]
fn dot_upstreams_need_a_valid_server_name() {
    let config = Config::from_toml(
        "[[upstream]]\nprotocol = \"dot\"\naddr = \"192.0.2.1:853\"\nserver_name = \"dns.example\"\n",
    )
    .unwrap();
    let setup = from_config(&config, Path::new(".")).unwrap();
    assert_eq!(setup.upstreams.describe(), ["tls://192.0.2.1:853"]);
}

#[test]
fn url_lists_come_from_the_cache() {
    let dir = Scratch::new("url-lists");
    let cache = Cache::new(dir.0.join("cache"));
    let (a, b) = ("https://lists.example/a.txt", "https://lists.example/b.txt");
    let config = Config::from_toml(&format!(
        "{UDP_UPSTREAM}[[list]]\nurl = \"{a}\"\n[[list]]\nurl = \"{b}\"\nformat = \"hosts\"\n"
    ))
    .unwrap();

    // Nothing downloaded yet: not an error, and both are watched.
    let setup = sinkd_resolver::from_config(&config, &dir.0, &cache).unwrap();
    assert_eq!(setup.missing, [0, 1]);
    assert_eq!(setup.files, [cache.path(a), cache.path(b)]);
    assert!(!blocked(&setup, "ads.example"));

    let meta = |url: &str| Meta {
        url: url.into(),
        etag: None,
        last_modified: None,
        fetched_at: 0,
        rules: 2,
        expires_secs: None,
        digest: String::new(),
    };
    cache
        .store(&meta(a), b"||ads.example^\n!#include sub.txt\n")
        .unwrap();
    cache
        .store(&meta("https://lists.example/sub.txt"), b"||sub.example^\n")
        .unwrap();
    let setup = sinkd_resolver::from_config(&config, &dir.0, &cache).unwrap();
    assert_eq!(setup.missing, [1]);
    assert!(blocked(&setup, "ads.example"));
    assert!(blocked(&setup, "sub.example"), "cached includes are loaded");
    assert!(
        setup
            .files
            .contains(&cache.path("https://lists.example/sub.txt"))
    );
}

#[test]
fn local_lists_follow_includes_and_preprocessor() {
    let dir = Scratch::new("includes");
    std::fs::write(
        dir.0.join("main.txt"),
        "||main.example^\n!#include extra.txt\n!#if env_firefox\n||firefox.example^\n!#endif\n",
    )
    .unwrap();
    std::fs::write(dir.0.join("extra.txt"), "||extra.example^\n").unwrap();
    let config =
        Config::from_toml(&format!("{UDP_UPSTREAM}[[list]]\npath = \"main.txt\"\n")).unwrap();
    let setup = from_config(&config, &dir.0).unwrap();
    assert!(blocked(&setup, "main.example"));
    assert!(blocked(&setup, "extra.example"));
    assert!(!blocked(&setup, "firefox.example"));
    assert_eq!(setup.report.excluded, 1);
    assert_eq!(
        setup.files,
        [dir.0.join("main.txt"), dir.0.join("extra.txt")]
    );
}

#[test]
fn local_entries_beat_a_lists_badfilter() {
    let dir = Scratch::new("badfilter");
    std::fs::write(
        dir.0.join("list.txt"),
        "||ads.example^\n||ads.example^$badfilter\n||mine.example^$badfilter\n",
    )
    .unwrap();
    let config = Config::from_toml(&format!(
        "block = [\"mine.example\"]\n{UDP_UPSTREAM}[[list]]\npath = \"list.txt\"\n"
    ))
    .unwrap();
    let setup = from_config(&config, &dir.0).unwrap();
    assert!(!blocked(&setup, "ads.example"));
    assert!(blocked(&setup, "mine.example"));
}

#[test]
fn unvalidated_configs_are_validated() {
    let mut config = Config::from_toml(UDP_UPSTREAM).unwrap();
    config.listen.addrs = vec!["0.0.0.0:53".parse().unwrap()];
    let e = from_config(&config, std::path::Path::new(".")).unwrap_err();
    assert!(matches!(e, SetupError::Config(_)), "{e}");
}
