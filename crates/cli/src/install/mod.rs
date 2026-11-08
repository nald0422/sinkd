//! `sinkhole install` and `sinkhole uninstall`: the resolver as a system
//! service, and the system's DNS settings pointed at it.
//!
//! **Order matters.** Install starts the service and waits until it answers
//! before it touches the DNS settings, so the machine is never pointed at
//! a resolver that is not there. Uninstall restores the DNS settings
//! first, so the machine keeps working even if a later step fails.
//!
//! **Exact restoration.** The DNS settings found at install are saved
//! before anything changes, and uninstall puts back exactly those. A
//! setting the user changed since install (it no longer points at
//! sinkhole) is left as it is. A shell script that restores them without
//! sinkhole is written next to the backup, for the one-line recovery in
//! the README.
//!
//! Every change goes through [`System`], which has three implementations:
//! the real one, a dry run that runs only read-only commands and prints the
//! rest (`--dry-run`), and a fake for the tests.

pub mod linux;
pub mod macos;

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use sinkhole_core::config::Config;

/// What a command printed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Output {
    pub ok: bool,
    pub stdout: String,
    pub stderr: String,
}

/// Everything the installer does to the machine.
pub trait System {
    /// Runs a command that only reads (always run, even in a dry run).
    fn query(&mut self, program: &str, args: &[&str]) -> Result<Output>;
    /// Runs a command that changes the machine.
    fn run(&mut self, program: &str, args: &[&str]) -> Result<Output>;
    fn read(&mut self, path: &Path) -> Option<Vec<u8>>;
    /// The target of a symbolic link, if `path` is one.
    fn read_link(&mut self, path: &Path) -> Option<PathBuf>;
    fn exists(&mut self, path: &Path) -> bool;
    fn write(&mut self, path: &Path, contents: &[u8], mode: u32) -> Result<()>;
    fn copy(&mut self, from: &Path, to: &Path, mode: u32) -> Result<()>;
    fn mkdir(&mut self, path: &Path, mode: u32) -> Result<()>;
    fn chown(&mut self, path: &Path, uid: u32, gid: u32) -> Result<()>;
    /// Removes a file or link; nothing if it is not there.
    fn remove(&mut self, path: &Path) -> Result<()>;
    /// Removes a directory and everything in it; nothing if it is not there.
    fn remove_dir_all(&mut self, path: &Path) -> Result<()>;
    /// Waits until a DNS server answers on `addr`.
    fn wait_ready(&mut self, addr: SocketAddr, within: Duration) -> bool;
    /// After the DNS change: whether the system's lookups now go through
    /// the daemon of `config`. `None` when not checked.
    fn verify(&mut self, config: &Path) -> Option<Result<String>>;
    fn dry_run(&self) -> bool;
    /// Progress for the user.
    fn note(&mut self, message: &str) {
        println!("{message}");
    }
}

/// Runs commands and touches files for real.
pub struct Real;

fn command(program: &str, args: &[&str]) -> Result<Output> {
    let out = std::process::Command::new(program)
        .args(args)
        .output()
        .with_context(|| format!("running {program}"))?;
    Ok(Output {
        ok: out.status.success(),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    })
}

impl System for Real {
    fn query(&mut self, program: &str, args: &[&str]) -> Result<Output> {
        command(program, args)
    }

    fn run(&mut self, program: &str, args: &[&str]) -> Result<Output> {
        command(program, args)
    }

    fn read(&mut self, path: &Path) -> Option<Vec<u8>> {
        std::fs::read(path).ok()
    }

    fn read_link(&mut self, path: &Path) -> Option<PathBuf> {
        std::fs::read_link(path).ok()
    }

    fn exists(&mut self, path: &Path) -> bool {
        std::fs::symlink_metadata(path).is_ok()
    }

    fn write(&mut self, path: &Path, contents: &[u8], mode: u32) -> Result<()> {
        use std::os::unix::fs::PermissionsExt;
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        // Write a sibling, then rename: never a half-written file.
        let tmp = path.with_extension("sinkhole-tmp");
        std::fs::write(&tmp, contents).with_context(|| format!("writing {}", tmp.display()))?;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(mode))?;
        std::fs::rename(&tmp, path).with_context(|| format!("writing {}", path.display()))?;
        Ok(())
    }

    fn copy(&mut self, from: &Path, to: &Path, mode: u32) -> Result<()> {
        let bytes = std::fs::read(from).with_context(|| format!("reading {}", from.display()))?;
        self.write(to, &bytes, mode)
    }

    fn mkdir(&mut self, path: &Path, mode: u32) -> Result<()> {
        use std::os::unix::fs::PermissionsExt;
        std::fs::create_dir_all(path).with_context(|| format!("creating {}", path.display()))?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))?;
        Ok(())
    }

    fn chown(&mut self, path: &Path, uid: u32, gid: u32) -> Result<()> {
        std::os::unix::fs::chown(path, Some(uid), Some(gid))
            .with_context(|| format!("chown {}", path.display()))
    }

    fn remove(&mut self, path: &Path) -> Result<()> {
        match std::fs::remove_file(path) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
                Err(e).with_context(|| format!("removing {}", path.display()))
            }
            _ => Ok(()),
        }
    }

    fn remove_dir_all(&mut self, path: &Path) -> Result<()> {
        match std::fs::remove_dir_all(path) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
                Err(e).with_context(|| format!("removing {}", path.display()))
            }
            _ => Ok(()),
        }
    }

    fn wait_ready(&mut self, addr: SocketAddr, within: Duration) -> bool {
        crate::dnsq::wait_ready(addr, within)
    }

    fn verify(&mut self, config: &Path) -> Option<Result<String>> {
        let sample = sample_blocked(config, Duration::from_secs(20));
        Some(verify_system_dns(sample.as_deref()))
    }

    fn dry_run(&self) -> bool {
        false
    }
}

/// Reads the machine, prints what it would change.
pub struct DryRun;

impl System for DryRun {
    fn query(&mut self, program: &str, args: &[&str]) -> Result<Output> {
        command(program, args)
    }

    fn run(&mut self, program: &str, args: &[&str]) -> Result<Output> {
        println!("  would run: {}", shell_line(program, args));
        Ok(Output {
            ok: true,
            ..Output::default()
        })
    }

    fn read(&mut self, path: &Path) -> Option<Vec<u8>> {
        std::fs::read(path).ok()
    }

    fn read_link(&mut self, path: &Path) -> Option<PathBuf> {
        std::fs::read_link(path).ok()
    }

    fn exists(&mut self, path: &Path) -> bool {
        std::fs::symlink_metadata(path).is_ok()
    }

    fn write(&mut self, path: &Path, contents: &[u8], mode: u32) -> Result<()> {
        println!(
            "  would write: {} (mode {mode:o}, {} bytes)",
            path.display(),
            contents.len()
        );
        Ok(())
    }

    fn copy(&mut self, from: &Path, to: &Path, mode: u32) -> Result<()> {
        println!(
            "  would copy: {} -> {} (mode {mode:o})",
            from.display(),
            to.display()
        );
        Ok(())
    }

    fn mkdir(&mut self, path: &Path, mode: u32) -> Result<()> {
        println!("  would create: {} (mode {mode:o})", path.display());
        Ok(())
    }

    fn chown(&mut self, path: &Path, uid: u32, gid: u32) -> Result<()> {
        println!("  would chown: {} to {uid}:{gid}", path.display());
        Ok(())
    }

    fn remove(&mut self, path: &Path) -> Result<()> {
        if self.exists(path) {
            println!("  would remove: {}", path.display());
        }
        Ok(())
    }

    fn remove_dir_all(&mut self, path: &Path) -> Result<()> {
        if self.exists(path) {
            println!("  would remove: {} and everything in it", path.display());
        }
        Ok(())
    }

    fn wait_ready(&mut self, addr: SocketAddr, _within: Duration) -> bool {
        println!("  would wait until the resolver answers on {addr}");
        true
    }

    fn verify(&mut self, _config: &Path) -> Option<Result<String>> {
        None
    }

    fn dry_run(&self) -> bool {
        true
    }
}

/// `program args…` as one would type it.
pub fn shell_line(program: &str, args: &[&str]) -> String {
    let mut line = program.to_owned();
    for a in args {
        line.push(' ');
        line.push_str(&shell_word(a));
    }
    line
}

/// A shell word: bare when safe, else single-quoted.
pub fn shell_word(s: &str) -> String {
    let safe = !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_./:=@%+,".contains(&b));
    if safe {
        s.to_owned()
    } else {
        format!("'{}'", s.replace('\'', r"'\''"))
    }
}

/// Fails unless a command succeeded.
pub fn must(out: Output, what: &str) -> Result<Output> {
    if out.ok {
        Ok(out)
    } else {
        Err(anyhow!(
            "{what} failed: {}",
            if out.stderr.trim().is_empty() {
                out.stdout.trim()
            } else {
                out.stderr.trim()
            }
        ))
    }
}

/// Where things go on this platform.
#[derive(Debug, Clone)]
pub struct Paths {
    pub binary: PathBuf,
    pub config: PathBuf,
    pub cache: PathBuf,
    /// Root-owned: the DNS backup and the restore script.
    pub state: PathBuf,
    pub control_socket: Option<PathBuf>,
}

impl Paths {
    pub fn backup(&self) -> PathBuf {
        self.state.join("dns-backup.json")
    }

    pub fn restore_script(&self) -> PathBuf {
        self.state.join("restore-dns.sh")
    }
}

/// The installed config's path on this platform.
pub fn default_config() -> PathBuf {
    if cfg!(target_os = "macos") {
        macos::paths().config
    } else {
        linux::paths().config
    }
}

/// What the user asked for.
#[derive(Debug, Clone, Default)]
pub struct Options {
    pub dry_run: bool,
    /// Install and start the service, but leave the DNS settings alone.
    pub no_dns: bool,
    /// Uninstall: also remove the config.
    pub purge: bool,
}

/// The config the installer writes when there is none.
pub fn starter_config(paths: &Paths, control_user: Option<u32>) -> String {
    let users = control_user.map_or_else(String::new, |u| u.to_string());
    let socket = paths
        .control_socket
        .as_ref()
        .map(|s| format!("socket = \"{}\"\n", s.display()))
        .unwrap_or_default();
    format!(
        r#"# sinkhole resolver config, written by `sinkhole install`.
#
# Edit freely: the resolver applies changes within seconds. `sinkhole allow
# add NAME` and `sinkhole block add NAME` edit the two lists below, and
# `sinkhole check NAME` explains what happens to a name.

# Local entries: `example.com` (and everything below it) or `*.example.com`
# (only names below it). The allowlist beats every blocklist.
allow = []
block = []

[listen]
addrs = ["127.0.0.1:53", "[::1]:53"]

[blocking]
response = "null_address"

[updates]
interval_hours = 24
cache_dir = "{cache}"

[control]
{socket}# Users (numeric ids) who may pause, resume and read the query log
# without sudo. Anyone may read the counters (`sinkhole stats`).
users = [{users}]

# Off by default. When on, the last queries are kept in memory only.
[query_log]
enabled = false
retention_hours = 24
max_entries = 100000

# Quad9 over DNS-over-HTTPS, then Cloudflare. The bootstrap addresses reach
# them without a DNS lookup.
[[upstream]]
protocol = "doh"
url = "https://dns.quad9.net/dns-query"
bootstrap = ["9.9.9.9", "149.112.112.112", "2620:fe::fe"]

[[upstream]]
protocol = "doh"
url = "https://cloudflare-dns.com/dns-query"
bootstrap = ["1.1.1.1", "1.0.0.1", "2606:4700:4700::1111"]

# The extension's network lists, applied to every app. Downloaded on first
# start and checked daily. EasyList and EasyPrivacy are dual-licensed
# GPLv3 / CC BY-SA 3.0; uBlock Origin's lists are GPLv3.
[[list]]
name = "EasyList"
url = "https://easylist.to/easylist/easylist.txt"

[[list]]
name = "EasyPrivacy"
url = "https://easylist.to/easylist/easyprivacy.txt"

[[list]]
name = "uBlock Origin badware"
url = "https://ublockorigin.github.io/uAssets/filters/badware.txt"
"#,
        cache = paths.cache.display(),
    )
}

/// The config to install: the one already there if any, else the starter.
/// Either way it must load, listen on port 53 of loopback (the DNS settings
/// can name no other port) and say where to keep its lists.
pub fn config_text(sys: &mut dyn System, paths: &Paths) -> Result<(String, bool)> {
    let control_user = std::env::var("SUDO_UID")
        .ok()
        .and_then(|u| u.parse().ok())
        .filter(|&u: &u32| u != 0);
    let (text, existing) = match sys.read(&paths.config) {
        Some(bytes) => (
            String::from_utf8(bytes)
                .with_context(|| format!("{} is not UTF-8", paths.config.display()))?,
            true,
        ),
        None => (starter_config(paths, control_user), false),
    };
    let config = Config::from_toml(&text).with_context(|| {
        format!(
            "in {}; fix it or move it away and install again",
            paths.config.display()
        )
    })?;
    let v4: SocketAddr = "127.0.0.1:53".parse()?;
    if !config.listen.addrs.contains(&v4) {
        bail!(
            "{} must listen on 127.0.0.1:53 for the system to use it (listen.addrs)",
            paths.config.display()
        );
    }
    if config.updates.cache_dir.is_none() {
        bail!(
            "{} must set updates.cache_dir (the service has no home directory); {} is the usual place",
            paths.config.display(),
            paths.cache.display()
        );
    }
    Ok((text, existing))
}

/// The DNS answer `doctor` and the installer test with.
pub fn verify_system_dns(sample: Option<&str>) -> Result<String> {
    let Some(name) = sample else {
        return Ok("no blocked name to test with yet (lists still downloading?)".into());
    };
    let ips = crate::dnsq::system_lookup(name).unwrap_or_default();
    if ips.is_empty() {
        return Err(anyhow!(
            "the system could not resolve the blocked name {name}, so its lookups do not go through sinkhole              (sinkhole answers it with 0.0.0.0)"
        ));
    }
    if crate::dnsq::is_null(&ips) {
        Ok(format!(
            "the system resolves the blocked name {name} to 0.0.0.0: lookups go through sinkhole"
        ))
    } else {
        Err(anyhow!(
            "the system resolves the blocked name {name} to {ips:?}: lookups bypass sinkhole \
             (a VPN, or a network service still set to another server?)"
        ))
    }
}

/// The sample blocked name from a running daemon, waiting a little for
/// its lists if they are still downloading.
pub fn sample_blocked(config: &Path, wait: Duration) -> Option<String> {
    let deadline = std::time::Instant::now() + wait;
    loop {
        if let Ok(status) = crate::ctl::status(config)
            && let Some(sample) = status.sample_blocked
        {
            return Some(sample);
        }
        if std::time::Instant::now() >= deadline {
            return None;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
}

pub fn install(options: &Options) -> Result<()> {
    let mut real = Real;
    let mut dry = DryRun;
    let sys: &mut dyn System = if options.dry_run { &mut dry } else { &mut real };
    if !options.dry_run && !crate::daemon::is_root() {
        bail!(
            "installing needs root: sudo sinkhole install (or --dry-run to see what it would do)"
        );
    }
    if cfg!(target_os = "macos") {
        macos::install(sys, &macos::paths(), options)
    } else if cfg!(target_os = "linux") {
        linux::install(sys, &linux::paths(), options)
    } else {
        bail!("install supports macOS and Linux")
    }
}

pub fn uninstall(options: &Options) -> Result<()> {
    let mut real = Real;
    let mut dry = DryRun;
    let sys: &mut dyn System = if options.dry_run { &mut dry } else { &mut real };
    if !options.dry_run && !crate::daemon::is_root() {
        bail!(
            "uninstalling needs root: sudo sinkhole uninstall (or --dry-run to see what it would do)"
        );
    }
    if cfg!(target_os = "macos") {
        macos::uninstall(sys, &macos::paths(), options)
    } else if cfg!(target_os = "linux") {
        linux::uninstall(sys, &linux::paths(), options)
    } else {
        bail!("uninstall supports macOS and Linux")
    }
}

#[cfg(test)]
pub mod fake {
    //! A scripted machine for the installer's tests.

    use std::collections::{BTreeMap, BTreeSet};

    use super::*;

    #[derive(Debug, Default)]
    pub struct Fake {
        pub files: BTreeMap<PathBuf, Vec<u8>>,
        pub links: BTreeMap<PathBuf, PathBuf>,
        pub dirs: BTreeSet<PathBuf>,
        /// Answers to commands, by command line; unscripted ones succeed
        /// with no output.
        pub answers: BTreeMap<String, Output>,
        /// Every change made, in order.
        pub log: Vec<String>,
        pub ready: bool,
        pub dry: bool,
    }

    impl Fake {
        pub fn answer(&mut self, line: &str, stdout: &str) {
            self.answers.insert(
                line.to_owned(),
                Output {
                    ok: true,
                    stdout: stdout.to_owned(),
                    stderr: String::new(),
                },
            );
        }

        pub fn fail(&mut self, line: &str) {
            self.answers.insert(line.to_owned(), Output::default());
        }

        fn respond(&self, line: &str) -> Output {
            self.answers.get(line).cloned().unwrap_or(Output {
                ok: true,
                ..Output::default()
            })
        }

        pub fn ran(&self, line: &str) -> bool {
            self.log.iter().any(|l| l == &format!("run {line}"))
        }
    }

    impl System for Fake {
        fn query(&mut self, program: &str, args: &[&str]) -> Result<Output> {
            Ok(self.respond(&shell_line(program, args)))
        }

        fn run(&mut self, program: &str, args: &[&str]) -> Result<Output> {
            let line = shell_line(program, args);
            self.log.push(format!("run {line}"));
            Ok(self.respond(&line))
        }

        fn read(&mut self, path: &Path) -> Option<Vec<u8>> {
            self.files.get(path).cloned()
        }

        fn read_link(&mut self, path: &Path) -> Option<PathBuf> {
            self.links.get(path).cloned()
        }

        fn exists(&mut self, path: &Path) -> bool {
            self.files.contains_key(path)
                || self.links.contains_key(path)
                || self.dirs.contains(path)
        }

        fn write(&mut self, path: &Path, contents: &[u8], mode: u32) -> Result<()> {
            self.log.push(format!("write {} {mode:o}", path.display()));
            self.links.remove(path);
            self.files.insert(path.to_path_buf(), contents.to_vec());
            Ok(())
        }

        fn copy(&mut self, from: &Path, to: &Path, mode: u32) -> Result<()> {
            self.log
                .push(format!("copy {} {} {mode:o}", from.display(), to.display()));
            self.files.insert(to.to_path_buf(), b"binary".to_vec());
            Ok(())
        }

        fn mkdir(&mut self, path: &Path, mode: u32) -> Result<()> {
            self.log.push(format!("mkdir {} {mode:o}", path.display()));
            self.dirs.insert(path.to_path_buf());
            Ok(())
        }

        fn chown(&mut self, path: &Path, uid: u32, gid: u32) -> Result<()> {
            self.log
                .push(format!("chown {} {uid}:{gid}", path.display()));
            Ok(())
        }

        fn remove(&mut self, path: &Path) -> Result<()> {
            if self.files.remove(path).is_some() || self.links.remove(path).is_some() {
                self.log.push(format!("remove {}", path.display()));
            }
            Ok(())
        }

        fn remove_dir_all(&mut self, path: &Path) -> Result<()> {
            if self.dirs.remove(path) {
                self.log.push(format!("rmdir {}", path.display()));
            }
            self.files.retain(|p, _| !p.starts_with(path));
            Ok(())
        }

        fn wait_ready(&mut self, _addr: SocketAddr, _within: Duration) -> bool {
            self.ready
        }

        fn verify(&mut self, _config: &Path) -> Option<Result<String>> {
            None
        }

        fn dry_run(&self) -> bool {
            self.dry
        }

        fn note(&mut self, _message: &str) {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn words() {
        assert_eq!(shell_word("Wi-Fi"), "Wi-Fi");
        assert_eq!(shell_word("USB 10/100/1000 LAN"), "'USB 10/100/1000 LAN'");
        assert_eq!(shell_word("it's"), r"'it'\''s'");
        assert_eq!(shell_word(""), "''");
    }

    #[test]
    fn starter_configs_load() {
        for paths in [macos::paths(), linux::paths()] {
            let text = starter_config(&paths, Some(501));
            let config = Config::from_toml(&text).unwrap();
            assert_eq!(config.control.users, [501]);
            assert_eq!(config.lists.len(), 3);
            assert_eq!(
                config.updates.cache_dir.as_deref(),
                Some(paths.cache.as_path())
            );
            assert!(Config::from_toml(&starter_config(&paths, None)).is_ok());
        }
    }
}
