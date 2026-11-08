//! Downloaded lists on disk: the last known-good copy of each.
//!
//! Each list is one file holding a magic line, a line of JSON metadata and
//! the list body exactly as downloaded:
//!
//! ```text
//! sinkd-list-cache 1
//! {"url":"https://…","etag":"\"abc\"","fetched_at":1762500000,"rules":51234,…}
//! [Adblock Plus 2.0]
//! …
//! ```
//!
//! One file per list means one atomic rename per update: a reader (the
//! daemon, or `sinkd update` running beside it) sees either the old copy
//! with its old ETag or the new copy with its new one, never a mix. A file
//! that does not parse, or that belongs to another URL, reads as absent, so
//! the list is downloaded afresh and the file replaced.

use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use tracing::debug;

const MAGIC: &str = "sinkd-list-cache 1";

/// What is known about a cached copy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Meta {
    pub url: String,
    /// Validators for the next conditional request.
    pub etag: Option<String>,
    pub last_modified: Option<String>,
    /// When this copy was downloaded, in seconds since the Unix epoch.
    pub fetched_at: u64,
    /// Rules in this copy; a new version is compared against it.
    pub rules: usize,
    /// The list's own `! Expires:` header, in seconds.
    pub expires_secs: Option<u64>,
    /// FNV-1a of the body, in hex. Not a security measure: it only spots an
    /// unchanged download from a server that sends no validators.
    #[serde(default)]
    pub digest: String,
}

impl Meta {
    /// Time since this copy was downloaded. Zero if the clock went back.
    pub fn age(&self) -> Duration {
        Duration::from_secs(unix_now().saturating_sub(self.fetched_at))
    }

    pub fn expires(&self) -> Option<Duration> {
        self.expires_secs.map(Duration::from_secs)
    }
}

/// A cached list and its metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cached {
    pub meta: Meta,
    pub body: Vec<u8>,
}

/// A directory of cached lists. Nothing is created until the first store.
#[derive(Debug, Clone)]
pub struct Cache {
    dir: PathBuf,
}

impl Cache {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Cache { dir: dir.into() }
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// The file that holds `url`: its host and file name, for people
    /// looking in the directory, plus a hash of the whole URL, so two lists
    /// named `hosts.txt` do not collide.
    pub fn path(&self, url: &str) -> PathBuf {
        let rest = url.trim_start_matches("https://");
        let host = rest.split(['/', '?', '#']).next().unwrap_or("");
        let file = rest
            .split(['?', '#'])
            .next()
            .and_then(|path| path.rsplit('/').next())
            .unwrap_or("");
        let readable = |part: &str| -> String {
            part.chars()
                .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
                .map(|c| c.to_ascii_lowercase())
                .take(40)
                .collect()
        };
        self.dir.join(format!(
            "{}_{}-{:016x}.list",
            readable(host),
            readable(file),
            fnv1a(url.as_bytes())
        ))
    }

    /// The cached copy of `url`, or `None` if there is none (or only an
    /// unreadable one).
    pub fn load(&self, url: &str) -> io::Result<Option<Cached>> {
        let Some(mut reader) = self.open(url)? else {
            return Ok(None);
        };
        let Some(meta) = read_meta(&mut reader, url)? else {
            return Ok(None);
        };
        let mut body = Vec::new();
        reader.read_to_end(&mut body)?;
        Ok(Some(Cached { meta, body }))
    }

    /// Just the metadata of the cached copy of `url`, without reading the body.
    pub fn load_meta(&self, url: &str) -> io::Result<Option<Meta>> {
        match self.open(url)? {
            Some(mut reader) => read_meta(&mut reader, url),
            None => Ok(None),
        }
    }

    /// Replaces the cached copy of `meta.url`, atomically.
    pub fn store(&self, meta: &Meta, body: &[u8]) -> io::Result<()> {
        fs::create_dir_all(&self.dir)?;
        let path = self.path(&meta.url);
        let json = serde_json::to_string(meta).map_err(io::Error::other)?;
        // Unique per process and call, so concurrent writers (the daemon
        // and `sinkd update`) never share a temporary file.
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let tmp = path.with_extension(format!(
            "tmp.{}.{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        let result = (|| {
            let mut file = File::create(&tmp)?;
            file.write_all(format!("{MAGIC}\n{json}\n").as_bytes())?;
            file.write_all(body)?;
            // On disk before the rename, so a crash cannot leave a renamed
            // but empty file behind.
            file.sync_all()?;
            fs::rename(&tmp, &path)
        })();
        if result.is_err() {
            let _ = fs::remove_file(&tmp);
        }
        result?;
        // Make the rename itself durable. Best effort: not every platform
        // can open a directory.
        if let Ok(dir) = File::open(&self.dir) {
            let _ = dir.sync_all();
        }
        Ok(())
    }

    fn open(&self, url: &str) -> io::Result<Option<BufReader<File>>> {
        match File::open(self.path(url)) {
            Ok(file) => Ok(Some(BufReader::new(file))),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }
}

fn read_meta(reader: &mut impl BufRead, url: &str) -> io::Result<Option<Meta>> {
    let mut line = String::new();
    reader.read_line(&mut line)?;
    if line.trim_end() != MAGIC {
        debug!(url, "ignoring a cache file with an unknown format");
        return Ok(None);
    }
    line.clear();
    reader.read_line(&mut line)?;
    match serde_json::from_str::<Meta>(&line) {
        Ok(meta) if meta.url == url => Ok(Some(meta)),
        Ok(_) => {
            debug!(url, "ignoring a cache file that belongs to another URL");
            Ok(None)
        }
        Err(e) => {
            debug!(url, error = %e, "ignoring a cache file with unreadable metadata");
            Ok(None)
        }
    }
}

/// Seconds since the Unix epoch.
pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// FNV-1a, 64 bits: stable across releases and platforms, unlike std's
/// hasher, so file names stay the same after an upgrade.
pub(crate) fn fnv1a(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0xcbf2_9ce4_8422_2325, |hash, &b| {
        (hash ^ u64::from(b)).wrapping_mul(0x0000_0100_0000_01b3)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn meta(url: &str) -> Meta {
        Meta {
            url: url.into(),
            etag: Some("W/\"a\\\"b\"".into()),
            last_modified: Some("Fri, 06 Nov 2026 10:00:00 GMT".into()),
            fetched_at: 1_762_500_000,
            rules: 2,
            expires_secs: Some(86_400),
            digest: "0123456789abcdef".into(),
        }
    }

    fn temp_dir(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("sinkd-cache-test-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn round_trip() {
        let dir = temp_dir("round-trip");
        let cache = Cache::new(dir.join("nested"));
        let url = "https://lists.example/hosts.txt";
        assert_eq!(cache.load(url).unwrap(), None);

        let body = b"0.0.0.0 a.example\n\n0.0.0.0 b.example\n\xff\n";
        cache.store(&meta(url), body).unwrap();
        let cached = cache.load(url).unwrap().unwrap();
        assert_eq!(cached.meta, meta(url));
        assert_eq!(cached.body, body);
        assert_eq!(cache.load_meta(url).unwrap(), Some(meta(url)));

        // Replaced in place, with no temporary files left behind.
        let mut newer = meta(url);
        newer.etag = None;
        cache.store(&newer, b"x\n").unwrap();
        assert_eq!(cache.load(url).unwrap().unwrap().body, b"x\n");
        let files: Vec<_> = fs::read_dir(cache.dir()).unwrap().collect();
        assert_eq!(files.len(), 1);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn file_names_are_readable_and_distinct() {
        let cache = Cache::new("/c");
        let a = cache.path("https://lists.example/a/hosts.txt");
        let b = cache.path("https://lists.example/b/hosts.txt");
        assert_ne!(a, b);
        let name = a.file_name().unwrap().to_str().unwrap();
        assert!(name.starts_with("lists.example_hosts.txt-"), "{name}");
        assert!(name.ends_with(".list"));
        let long = cache.path(&format!(
            "https://l.example/{}{}?x=1&y=/2",
            "d/".repeat(100),
            "f".repeat(100)
        ));
        let name = long.file_name().unwrap().to_str().unwrap();
        assert!(
            name.starts_with(&format!("l.example_{}-", "f".repeat(40))),
            "{name}"
        );
        assert!(name.len() < 120, "{name}");
        let odd = cache.path("https://user:pass@l.example:8443/../x y.txt");
        let name = odd.file_name().unwrap().to_str().unwrap();
        assert!(!name.contains(['/', '?', ' ', ':', '@']), "{name}");
    }

    #[test]
    fn unreadable_or_foreign_files_read_as_absent() {
        let dir = temp_dir("foreign");
        let cache = Cache::new(&dir);
        let url = "https://lists.example/a.txt";
        fs::create_dir_all(&dir).unwrap();
        for junk in [
            &b""[..],
            b"0.0.0.0 a.example\n",
            b"sinkd-list-cache 1\nnot json\nbody",
            b"sinkd-list-cache 2\n{}\nbody",
        ] {
            fs::write(cache.path(url), junk).unwrap();
            assert_eq!(cache.load(url).unwrap(), None);
            assert_eq!(cache.load_meta(url).unwrap(), None);
        }
        // A file renamed into another list's place.
        cache
            .store(&meta("https://lists.example/b.txt"), b"x")
            .unwrap();
        fs::rename(cache.path("https://lists.example/b.txt"), cache.path(url)).unwrap();
        assert_eq!(cache.load(url).unwrap(), None);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn fnv_is_stable() {
        // Pinned: changing it would orphan every cached file on upgrade.
        assert_eq!(fnv1a(b""), 0xcbf2_9ce4_8422_2325);
        assert_eq!(fnv1a(b"a"), 0xaf63_dc4c_8601_ec8c);
    }
}
