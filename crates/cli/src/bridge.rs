//! The browser bridge: a native-messaging host, so that `sinkhole allow`,
//! `block` and `pause` reach the extension too.
//!
//! The browser starts `sinkhole native-host` when the extension connects
//! (it needs the optional `nativeMessaging` permission, which the user
//! grants from the popup). The host sends the extension the local
//! allowlist and blocklist from the resolver's config, and whether the
//! running resolver is paused, then again whenever either changes (checked
//! every [`POLL`]). The extension turns them into dynamic rules.
//!
//! **One way only.** The host reads; it accepts no command from the
//! extension except "send the state again". A compromised extension, or a
//! page that subverts one, can learn the local lists through it but cannot
//! change them or pause blocking for the machine.
//!
//! Messages are JSON, each preceded by its length as a native-endian u32,
//! on stdin and stdout (the browser's protocol). Logging goes to stderr,
//! which the browser keeps out of the channel.

use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sinkhole_core::config::Config;
use sinkhole_resolver::Paused;

/// The host's name, as the extension and the manifests know it.
pub const HOST_NAME: &str = "sinkhole.bridge";
/// The Firefox add-on ID (see `extension/scripts/build.mjs`).
pub const FIREFOX_ID: &str = "sinkhole@sinkhole.invalid";
/// How often the config and the daemon are checked for changes.
const POLL: Duration = Duration::from_secs(2);
/// The longest message read from the browser. Ours are a few bytes.
const MAX_INCOMING: u32 = 64 * 1024;
/// Chrome refuses messages from a host over 1 MiB; leave room.
const MAX_OUTGOING: usize = 1_000_000;
/// Entries sent per list, at most: the extension turns each into a
/// dynamic rule, and dynamic rules are a shared quota.
pub const MAX_ENTRIES: usize = 5000;

/// What the host tells the extension.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub version: String,
    /// Whether a resolver answered on its control socket.
    pub running: bool,
    pub paused: Option<Paused>,
    /// Normalized entries: `example.com`, or `*.example.com` for names
    /// below it only.
    pub allow: Vec<String>,
    pub block: Vec<String>,
    /// Entries left out over [`MAX_ENTRIES`], per list.
    pub truncated: bool,
    /// Why the config could not be read, if it could not.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

fn normalized(entries: &[String]) -> Vec<String> {
    let mut out: Vec<String> = entries
        .iter()
        .filter_map(|e| crate::edit::normalize(e).ok())
        .collect();
    out.sort();
    out.dedup();
    out
}

/// Reads the state now. Never fails: problems are reported in it.
pub fn read_state(config_path: &Path) -> State {
    let mut state = State {
        version: env!("CARGO_PKG_VERSION").to_owned(),
        running: false,
        paused: None,
        allow: Vec::new(),
        block: Vec::new(),
        truncated: false,
        error: None,
    };
    let text = match std::fs::read_to_string(config_path) {
        Ok(text) => text,
        Err(e) => {
            state.error = Some(format!("reading {}: {e}", config_path.display()));
            return state;
        }
    };
    let config = match Config::from_toml(&text) {
        Ok(config) => config,
        Err(e) => {
            state.error = Some(format!("in {}: {e}", config_path.display()));
            return state;
        }
    };
    state.allow = normalized(&config.allow);
    state.block = normalized(&config.block);
    for list in [&mut state.allow, &mut state.block] {
        if list.len() > MAX_ENTRIES {
            list.truncate(MAX_ENTRIES);
            state.truncated = true;
        }
    }
    if let Ok(status) = crate::ctl::status(config_path) {
        state.running = true;
        state.paused = status.paused;
    }
    state
}

fn write_message(out: &mut impl Write, value: &serde_json::Value) -> io::Result<()> {
    let bytes = serde_json::to_vec(value)?;
    if bytes.len() > MAX_OUTGOING {
        return Err(io::Error::other("message too large for the browser"));
    }
    let len = u32::try_from(bytes.len()).map_err(io::Error::other)?;
    out.write_all(&len.to_ne_bytes())?;
    out.write_all(&bytes)?;
    out.flush()
}

/// Reads one message. `Ok(None)` at the end of input: the browser hung up.
pub fn read_message(input: &mut impl Read) -> io::Result<Option<serde_json::Value>> {
    let mut len = [0u8; 4];
    match input.read_exact(&mut len) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let len = u32::from_ne_bytes(len);
    if len > MAX_INCOMING {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("message of {len} bytes; at most {MAX_INCOMING}"),
        ));
    }
    let mut body = vec![0u8; len as usize];
    input.read_exact(&mut body)?;
    serde_json::from_slice(&body)
        .map(Some)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

fn state_message(state: &State) -> serde_json::Value {
    let mut value = serde_json::to_value(state).unwrap_or_default();
    if let Some(map) = value.as_object_mut() {
        map.insert("type".into(), json!("state"));
    }
    value
}

/// `sinkhole native-host`: serves one browser connection until the browser
/// closes it.
pub fn native_host(config_path: &Path) -> Result<()> {
    // Requests from the extension arrive on a thread of their own, so the
    // poll below never waits on stdin.
    let (tx, rx) = mpsc::channel::<Option<serde_json::Value>>();
    std::thread::spawn(move || {
        let mut stdin = io::stdin().lock();
        loop {
            match read_message(&mut stdin) {
                Ok(Some(message)) => {
                    if tx.send(Some(message)).is_err() {
                        return;
                    }
                }
                Ok(None) | Err(_) => {
                    let _ = tx.send(None);
                    return;
                }
            }
        }
    });
    let mut out = io::stdout().lock();
    let mut last = read_state(config_path);
    write_message(&mut out, &state_message(&last))?;
    loop {
        match rx.recv_timeout(POLL) {
            // The browser closed the connection, or sent garbage.
            Ok(None) | Err(mpsc::RecvTimeoutError::Disconnected) => return Ok(()),
            Ok(Some(message)) => {
                if message.get("type").and_then(|t| t.as_str()) == Some("get") {
                    last = read_state(config_path);
                    write_message(&mut out, &state_message(&last))?;
                }
                // Anything else is ignored: the host takes no orders.
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                let now = read_state(config_path);
                if now != last {
                    write_message(&mut out, &state_message(&now))?;
                    last = now;
                }
            }
        }
    }
}

/// A browser that can run the extension, and where it looks for hosts.
#[derive(Debug, Clone)]
pub struct Browser {
    pub name: &'static str,
    pub firefox: bool,
    /// The browser's own directory: the hosts directory is created in it
    /// only if the browser is installed (the directory exists).
    pub home: PathBuf,
    pub hosts: PathBuf,
}

/// The browsers sinkhole supports, for the current user.
pub fn browsers() -> Result<Vec<Browser>> {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| anyhow!("no HOME"))?;
    let b = |name, firefox, home: PathBuf, sub: &str| Browser {
        name,
        firefox,
        hosts: home.join(sub),
        home,
    };
    Ok(if cfg!(target_os = "macos") {
        let support = home.join("Library/Application Support");
        vec![
            b(
                "Chrome",
                false,
                support.join("Google/Chrome"),
                "NativeMessagingHosts",
            ),
            b(
                "Chromium",
                false,
                support.join("Chromium"),
                "NativeMessagingHosts",
            ),
            b(
                "Edge",
                false,
                support.join("Microsoft Edge"),
                "NativeMessagingHosts",
            ),
            b(
                "Brave",
                false,
                support.join("BraveSoftware/Brave-Browser"),
                "NativeMessagingHosts",
            ),
            b(
                "Arc",
                false,
                support.join("Arc/User Data"),
                "NativeMessagingHosts",
            ),
            b(
                "Firefox",
                true,
                support.join("Mozilla"),
                "NativeMessagingHosts",
            ),
        ]
    } else {
        let config = std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| home.join(".config"));
        vec![
            b(
                "Chrome",
                false,
                config.join("google-chrome"),
                "NativeMessagingHosts",
            ),
            b(
                "Chromium",
                false,
                config.join("chromium"),
                "NativeMessagingHosts",
            ),
            b(
                "Edge",
                false,
                config.join("microsoft-edge"),
                "NativeMessagingHosts",
            ),
            b(
                "Brave",
                false,
                config.join("BraveSoftware/Brave-Browser"),
                "NativeMessagingHosts",
            ),
            b(
                "Firefox",
                true,
                home.join(".mozilla"),
                "native-messaging-hosts",
            ),
        ]
    })
}

/// Where the launcher script lives, per user.
fn launcher_path() -> Result<PathBuf> {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| anyhow!("no HOME"))?;
    Ok(if cfg!(target_os = "macos") {
        home.join("Library/Application Support/sinkhole/native-host")
    } else {
        std::env::var_os("XDG_DATA_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| home.join(".local/share"))
            .join("sinkhole/native-host")
    })
}

/// A shell word that the shell takes literally.
fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

/// The launcher: the browser cannot pass arguments to a host, so this
/// script adds the config path.
pub fn launcher(binary: &Path, config: &Path) -> String {
    format!(
        "#!/bin/sh\n# Started by the browser when the sinkhole extension connects (native messaging).\n# Written by `sinkhole bridge install`; removed by `sinkhole bridge uninstall`.\nexec {} native-host --config {} \"$@\"\n",
        shell_quote(&binary.to_string_lossy()),
        shell_quote(&config.to_string_lossy())
    )
}

/// A host manifest for one browser family.
pub fn manifest(launcher: &Path, firefox: bool, chrome_ids: &[String]) -> serde_json::Value {
    let description =
        "sinkhole: passes the resolver's allowlist, blocklist and pause to the extension";
    if firefox {
        json!({
            "name": HOST_NAME,
            "description": description,
            "path": launcher,
            "type": "stdio",
            "allowed_extensions": [FIREFOX_ID],
        })
    } else {
        let origins: Vec<String> = chrome_ids
            .iter()
            .map(|id| format!("chrome-extension://{id}/"))
            .collect();
        json!({
            "name": HOST_NAME,
            "description": description,
            "path": launcher,
            "type": "stdio",
            "allowed_origins": origins,
        })
    }
}

fn valid_chrome_id(id: &str) -> bool {
    id.len() == 32 && id.bytes().all(|b| (b'a'..=b'p').contains(&b))
}

pub struct InstallOptions<'a> {
    pub chrome_ids: &'a [String],
    /// Write only into this hosts directory (a test profile, say).
    pub dir: Option<&'a Path>,
    pub firefox_dir: bool,
    pub dry_run: bool,
}

pub fn install(config_path: &Path, o: &InstallOptions<'_>) -> Result<()> {
    if crate::daemon::is_root() {
        bail!(
            "run `sinkhole bridge install` as yourself, without sudo: it writes into your browsers' settings"
        );
    }
    for id in o.chrome_ids {
        if !valid_chrome_id(id) {
            bail!(
                "{id:?} is not a Chrome extension ID (32 letters a to p; see chrome://extensions)"
            );
        }
    }
    let binary = std::env::current_exe().context("finding the sinkhole binary")?;
    let config = std::path::absolute(config_path)?;
    let launcher_path = launcher_path()?;
    let mut writes: Vec<(String, PathBuf, String)> = Vec::new();
    let targets: Vec<(String, PathBuf, bool)> = match o.dir {
        Some(dir) => vec![(
            "the given directory".into(),
            dir.to_path_buf(),
            o.firefox_dir,
        )],
        None => browsers()?
            .into_iter()
            .filter(|b| b.home.is_dir())
            .map(|b| (b.name.to_owned(), b.hosts, b.firefox))
            .collect(),
    };
    if targets.is_empty() {
        bail!("no supported browser found for this user");
    }
    for (name, dir, firefox) in targets {
        if !firefox && o.chrome_ids.is_empty() {
            println!(
                "skipping {name}: pass --chrome-id with the extension's ID from {}",
                if name == "Edge" {
                    "edge://extensions"
                } else {
                    "chrome://extensions"
                }
            );
            continue;
        }
        let manifest = manifest(&launcher_path, firefox, o.chrome_ids);
        let text = serde_json::to_string_pretty(&manifest)? + "\n";
        writes.push((name, dir.join(format!("{HOST_NAME}.json")), text));
    }
    if writes.is_empty() {
        bail!("nothing to install");
    }
    let script = launcher(&binary, &config);
    if o.dry_run {
        println!(
            "Would write {} (mode 755):\n{script}",
            launcher_path.display()
        );
        for (name, path, text) in &writes {
            println!("Would write {} for {name}:\n{text}", path.display());
        }
        return Ok(());
    }
    if let Some(dir) = launcher_path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    std::fs::write(&launcher_path, &script)?;
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&launcher_path, std::fs::Permissions::from_mode(0o755))?;
    }
    println!("Wrote {}", launcher_path.display());
    for (name, path, text) in &writes {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        std::fs::write(path, text)?;
        println!("Wrote {} ({name})", path.display());
    }
    println!(
        "\nIn the extension's popup, choose \"Connect\" under \"sinkhole on this computer\".\nUndo with: sinkhole bridge uninstall"
    );
    Ok(())
}

/// Whether `path` is a host manifest of ours.
fn ours(path: &Path) -> bool {
    std::fs::read(path)
        .ok()
        .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
        .is_some_and(|v| v.get("name").and_then(|n| n.as_str()) == Some(HOST_NAME))
}

pub fn uninstall(dir: Option<&Path>, dry_run: bool) -> Result<()> {
    let mut paths: Vec<PathBuf> = match dir {
        Some(dir) => vec![dir.join(format!("{HOST_NAME}.json"))],
        None => browsers()?
            .into_iter()
            .map(|b| b.hosts.join(format!("{HOST_NAME}.json")))
            .collect(),
    };
    paths.retain(|p| ours(p));
    let launcher = launcher_path()?;
    if launcher.exists() {
        paths.push(launcher);
    }
    if paths.is_empty() {
        println!("The browser bridge is not installed for this user.");
        return Ok(());
    }
    for path in paths {
        if dry_run {
            println!("Would remove {}", path.display());
        } else {
            std::fs::remove_file(&path).with_context(|| format!("removing {}", path.display()))?;
            println!("Removed {}", path.display());
        }
    }
    Ok(())
}

pub fn status(config_path: &Path) -> Result<()> {
    let launcher = launcher_path()?;
    println!(
        "Launcher: {}",
        if launcher.exists() {
            launcher.display().to_string()
        } else {
            "not installed".to_owned()
        }
    );
    for b in browsers()? {
        if !b.home.is_dir() {
            continue;
        }
        let path = b.hosts.join(format!("{HOST_NAME}.json"));
        println!(
            "{:<9} {}",
            b.name,
            if ours(&path) {
                format!("installed ({})", path.display())
            } else {
                "not installed".to_owned()
            }
        );
    }
    let state = read_state(config_path);
    println!(
        "\nWhat the extension would receive: {} allowed, {} blocked, resolver {}{}",
        state.allow.len(),
        state.block.len(),
        if state.running {
            "running"
        } else {
            "not running"
        },
        match (state.paused, &state.error) {
            (_, Some(e)) => format!("; error: {e}"),
            (Some(_), _) => ", paused".to_owned(),
            _ => String::new(),
        }
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn framing_round_trips_and_caps() {
        let mut buf = Vec::new();
        write_message(&mut buf, &json!({"type": "get"})).unwrap();
        let mut cursor = io::Cursor::new(buf);
        assert_eq!(
            read_message(&mut cursor).unwrap(),
            Some(json!({"type": "get"}))
        );
        assert_eq!(read_message(&mut cursor).unwrap(), None);

        let mut huge = (MAX_INCOMING + 1).to_ne_bytes().to_vec();
        huge.extend_from_slice(b"{}");
        assert!(read_message(&mut io::Cursor::new(huge)).is_err());
        let mut short = 10u32.to_ne_bytes().to_vec();
        short.extend_from_slice(b"{}");
        assert!(read_message(&mut io::Cursor::new(short)).is_err());
    }

    #[test]
    fn launcher_quotes_paths() {
        let script = launcher(
            Path::new("/opt/it's here/sinkhole"),
            Path::new("/etc/s.toml"),
        );
        assert!(
            script
                .contains(r"exec '/opt/it'\''s here/sinkhole' native-host --config '/etc/s.toml' ")
        );
    }

    #[test]
    fn manifests() {
        let chrome = manifest(Path::new("/x"), false, &["a".repeat(32)]);
        assert_eq!(
            chrome["allowed_origins"][0],
            format!("chrome-extension://{}/", "a".repeat(32))
        );
        assert!(chrome.get("allowed_extensions").is_none());
        let firefox = manifest(Path::new("/x"), true, &[]);
        assert_eq!(firefox["allowed_extensions"][0], FIREFOX_ID);
        assert!(valid_chrome_id(&"p".repeat(32)));
        assert!(!valid_chrome_id(&"q".repeat(32)));
        assert!(!valid_chrome_id("abc"));
    }

    #[test]
    fn state_of_a_config() {
        let dir = std::env::temp_dir().join(format!("sinkhole-bridge-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("s.toml");
        std::fs::write(
            &path,
            "allow = [\"OK.example\", \"ok.example\"]\nblock = [\"*.ads.example\"]\n[updates]\ncache_dir = \"c\"\n",
        )
        .unwrap();
        let state = read_state(&path);
        assert_eq!(state.allow, ["ok.example"]);
        assert_eq!(state.block, ["*.ads.example"]);
        assert!(!state.running);
        assert_eq!(state.error, None);
        let missing = read_state(&dir.join("none.toml"));
        assert!(missing.error.is_some());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
