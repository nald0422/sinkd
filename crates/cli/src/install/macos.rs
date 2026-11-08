//! macOS: a launchd daemon running as `_sinkhole`, and every network
//! service's DNS servers set to 127.0.0.1 and ::1.
//!
//! launchd starts `sinkhole run --user _sinkhole` as root; it binds port
//! 53 and hands the sockets to an unprivileged child (see `daemon.rs`).
//! `KeepAlive` restarts it if it exits, and the hang guard makes it exit if
//! it stops responding.
//!
//! The DNS servers are a per-service setting (`networksetup`). "Empty"
//! means "whatever DHCP or the VPN says", which is saved as an empty list
//! and restored as `Empty`.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};

use super::{Options, Paths, System, config_text, must, shell_line, shell_word};

pub const LABEL: &str = "sinkhole.resolver";
pub const USER: &str = "_sinkhole";
const NETWORKSETUP: &str = "/usr/sbin/networksetup";
const DSCL: &str = "/usr/bin/dscl";
const LAUNCHCTL: &str = "/bin/launchctl";
/// What every service is set to.
const OURS: [&str; 2] = ["127.0.0.1", "::1"];
/// Where a new user and group id is looked for: below 500, so the account
/// stays out of the login window, as system accounts do.
const IDS: std::ops::RangeInclusive<u32> = 200..=400;

pub fn paths() -> Paths {
    Paths {
        binary: "/usr/local/bin/sinkhole".into(),
        config: "/usr/local/etc/sinkhole/sinkhole.toml".into(),
        cache: "/Library/Caches/sinkhole".into(),
        state: "/Library/Application Support/sinkhole".into(),
        control_socket: None,
    }
}

fn plist_path() -> PathBuf {
    PathBuf::from(format!("/Library/LaunchDaemons/{LABEL}.plist"))
}

const LOG: &str = "/Library/Logs/sinkhole.log";

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

pub fn plist(paths: &Paths) -> String {
    let args = [
        paths.binary.to_string_lossy().into_owned(),
        "run".into(),
        "--config".into(),
        paths.config.to_string_lossy().into_owned(),
        "--user".into(),
        USER.into(),
    ];
    let args: String = args
        .iter()
        .map(|a| format!("\t\t<string>{}</string>\n", xml_escape(a)))
        .collect();
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<!-- Written by `sinkhole install`; removed by `sinkhole uninstall`. -->
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>{LABEL}</string>
	<key>ProgramArguments</key>
	<array>
{args}	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<true/>
	<key>ThrottleInterval</key>
	<integer>5</integer>
	<key>StandardErrorPath</key>
	<string>{LOG}</string>
	<key>EnvironmentVariables</key>
	<dict>
		<key>RUST_LOG</key>
		<string>info</string>
	</dict>
	<key>SoftResourceLimits</key>
	<dict>
		<key>NumberOfFiles</key>
		<integer>4096</integer>
	</dict>
</dict>
</plist>
"#
    )
}

/// The DNS servers of one network service, as found before install.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceDns {
    pub name: String,
    /// Empty: none set by hand (DHCP or the VPN decides).
    pub servers: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Backup {
    pub version: u32,
    pub services: Vec<ServiceDns>,
}

impl Backup {
    fn find(&self, name: &str) -> Option<&ServiceDns> {
        self.services.iter().find(|s| s.name == name)
    }
}

/// Every network service, disabled ones included (a service enabled later
/// should use sinkhole too).
pub fn services(sys: &mut dyn System) -> Result<Vec<String>> {
    let out = must(
        sys.query(NETWORKSETUP, &["-listallnetworkservices"])?,
        "networksetup -listallnetworkservices",
    )?;
    let names: Vec<String> = out
        .stdout
        .lines()
        .skip(1)
        .map(|l| l.trim_start_matches('*').trim().to_owned())
        .filter(|l| !l.is_empty())
        .collect();
    if names.is_empty() {
        bail!("no network services found");
    }
    Ok(names)
}

/// The DNS servers set on a service; empty when none are.
pub fn dns_of(sys: &mut dyn System, service: &str) -> Result<Vec<String>> {
    let out = sys.query(NETWORKSETUP, &["-getdnsservers", service])?;
    if out.stdout.contains("aren't any DNS Servers") {
        return Ok(Vec::new());
    }
    let mut servers = Vec::new();
    for line in out.stdout.lines().map(str::trim).filter(|l| !l.is_empty()) {
        if line.parse::<std::net::IpAddr>().is_err() {
            bail!("networksetup -getdnsservers {service:?}: {line}");
        }
        servers.push(line.to_owned());
    }
    Ok(servers)
}

fn is_ours(servers: &[String]) -> bool {
    servers.len() == OURS.len() && servers.iter().zip(OURS).all(|(a, b)| a == b)
}

fn set_dns(sys: &mut dyn System, service: &str, servers: &[String]) -> Result<()> {
    let mut args = vec!["-setdnsservers", service];
    if servers.is_empty() {
        args.push("Empty");
    } else {
        args.extend(servers.iter().map(String::as_str));
    }
    must(sys.run(NETWORKSETUP, &args)?, "networksetup -setdnsservers")?;
    Ok(())
}

fn flush(sys: &mut dyn System) -> Result<()> {
    sys.run("/usr/bin/dscacheutil", &["-flushcache"])?;
    // mDNSResponder is the system resolver; HUP empties its cache.
    sys.run("/usr/bin/killall", &["-HUP", "mDNSResponder"])?;
    Ok(())
}

fn read_backup(sys: &mut dyn System, paths: &Paths) -> Result<Option<Backup>> {
    match sys.read(&paths.backup()) {
        None => Ok(None),
        Some(bytes) => {
            Ok(Some(serde_json::from_slice(&bytes).with_context(|| {
                format!("reading {}", paths.backup().display())
            })?))
        }
    }
}

/// A script that puts the saved settings back, without sinkhole.
pub fn restore_script(backup: &Backup) -> String {
    let mut s = String::from(
        "#!/bin/sh\n# Puts back the DNS settings found when sinkhole was installed.\n# Written by `sinkhole install`. Run it with: sudo sh restore-dns.sh\n",
    );
    for service in &backup.services {
        let mut args = vec!["-setdnsservers", service.name.as_str()];
        if service.servers.is_empty() {
            args.push("Empty");
        } else {
            args.extend(service.servers.iter().map(String::as_str));
        }
        s.push_str(&shell_line(NETWORKSETUP, &args));
        s.push('\n');
    }
    s.push_str("/usr/bin/dscacheutil -flushcache\n/usr/bin/killall -HUP mDNSResponder\n");
    s
}

/// Saves the current settings (keeping an earlier backup, so a reinstall
/// never saves sinkhole's own settings as "the original"), then points
/// every service at sinkhole.
pub fn point_dns(sys: &mut dyn System, paths: &Paths) -> Result<Backup> {
    let services = services(sys)?;
    let mut backup = read_backup(sys, paths)?.unwrap_or(Backup {
        version: 1,
        services: Vec::new(),
    });
    let mut current = Vec::new();
    for name in &services {
        let servers = dns_of(sys, name)?;
        if backup.find(name).is_none() {
            // Already ours without a backup: the original is unknown, and
            // "automatic" is the safe guess.
            let saved = if is_ours(&servers) {
                Vec::new()
            } else {
                servers.clone()
            };
            backup.services.push(ServiceDns {
                name: name.clone(),
                servers: saved,
            });
        }
        current.push((name.clone(), servers));
    }
    sys.mkdir(&paths.state, 0o755)?;
    sys.write(&paths.backup(), &serde_json::to_vec_pretty(&backup)?, 0o644)?;
    sys.write(
        &paths.restore_script(),
        restore_script(&backup).as_bytes(),
        0o755,
    )?;
    let ours: Vec<String> = OURS.iter().map(|s| (*s).to_owned()).collect();
    for (name, servers) in &current {
        if !is_ours(servers) {
            set_dns(sys, name, &ours)?;
            sys.note(&format!(
                "  {name}: DNS {} -> 127.0.0.1, ::1",
                describe(servers)
            ));
        }
    }
    flush(sys)?;
    Ok(backup)
}

fn describe(servers: &[String]) -> String {
    if servers.is_empty() {
        "automatic".to_owned()
    } else {
        servers.join(", ")
    }
}

/// Puts back the saved settings where they still point at sinkhole.
pub fn restore_dns(sys: &mut dyn System, paths: &Paths) -> Result<()> {
    let backup = read_backup(sys, paths)?.unwrap_or_default();
    for name in services(sys)? {
        let current = dns_of(sys, &name)?;
        let saved = backup.find(&name).map(|s| s.servers.clone());
        if !is_ours(&current) {
            if saved.as_ref().is_some_and(|s| *s != current) {
                sys.note(&format!(
                    "  {name}: left at {} (changed since install)",
                    describe(&current)
                ));
            }
            continue;
        }
        let target = saved.unwrap_or_default();
        set_dns(sys, &name, &target)?;
        sys.note(&format!(
            "  {name}: DNS 127.0.0.1, ::1 -> {}",
            describe(&target)
        ));
    }
    flush(sys)?;
    sys.remove(&paths.backup())?;
    sys.remove(&paths.restore_script())?;
    Ok(())
}

fn loaded(sys: &mut dyn System) -> Result<bool> {
    Ok(sys
        .query(LAUNCHCTL, &["print", &format!("system/{LABEL}")])?
        .ok)
}

/// Ids in use, from `dscl . -list /Users UniqueID` and the like.
fn ids_in_use(sys: &mut dyn System, path: &str, key: &str) -> Result<Vec<u32>> {
    let out = must(sys.query(DSCL, &[".", "-list", path, key])?, "dscl -list")?;
    Ok(out
        .stdout
        .lines()
        .filter_map(|l| l.split_whitespace().last()?.parse().ok())
        .collect())
}

/// The id of a dscl record, if it exists.
fn record_id(sys: &mut dyn System, path: &str, key: &str) -> Result<Option<u32>> {
    let out = sys.query(DSCL, &[".", "-read", path, key])?;
    if !out.ok {
        return Ok(None);
    }
    Ok(out
        .stdout
        .split_whitespace()
        .last()
        .and_then(|id| id.parse().ok()))
}

/// The `_sinkhole` user and group, created if missing. Returns (uid, gid).
fn ensure_user(sys: &mut dyn System) -> Result<(u32, u32)> {
    let user_path = format!("/Users/{USER}");
    let group_path = format!("/Groups/{USER}");
    let gid = match record_id(sys, &group_path, "PrimaryGroupID")? {
        Some(gid) => gid,
        None => {
            let used = ids_in_use(sys, "/Groups", "PrimaryGroupID")?;
            let users = ids_in_use(sys, "/Users", "UniqueID")?;
            let gid = IDS
                .clone()
                .find(|id| !used.contains(id) && !users.contains(id))
                .ok_or_else(|| anyhow!("no free group id in {IDS:?}"))?;
            for args in [
                vec![".", "-create", &group_path],
                vec![
                    ".",
                    "-create",
                    &group_path,
                    "PrimaryGroupID",
                    &gid.to_string(),
                ],
                vec![
                    ".",
                    "-create",
                    &group_path,
                    "RealName",
                    "sinkhole DNS resolver",
                ],
                vec![".", "-create", &group_path, "Password", "*"],
            ] {
                must(sys.run(DSCL, &args)?, "dscl -create (group)")?;
            }
            if !sys.dry_run() {
                sys.note(&format!("  created group {USER} ({gid})"));
            }
            gid
        }
    };
    let uid = match record_id(sys, &user_path, "UniqueID")? {
        Some(uid) => uid,
        None => {
            let used = ids_in_use(sys, "/Users", "UniqueID")?;
            let uid = if used.contains(&gid) {
                IDS.clone()
                    .find(|id| !used.contains(id))
                    .ok_or_else(|| anyhow!("no free user id in {IDS:?}"))?
            } else {
                gid
            };
            for args in [
                vec![".", "-create", &user_path],
                vec![".", "-create", &user_path, "UniqueID", &uid.to_string()],
                vec![
                    ".",
                    "-create",
                    &user_path,
                    "PrimaryGroupID",
                    &gid.to_string(),
                ],
                vec![".", "-create", &user_path, "UserShell", "/usr/bin/false"],
                vec![".", "-create", &user_path, "NFSHomeDirectory", "/var/empty"],
                vec![
                    ".",
                    "-create",
                    &user_path,
                    "RealName",
                    "sinkhole DNS resolver",
                ],
                vec![".", "-create", &user_path, "Password", "*"],
                vec![".", "-create", &user_path, "IsHidden", "1"],
            ] {
                must(sys.run(DSCL, &args)?, "dscl -create (user)")?;
            }
            if !sys.dry_run() {
                sys.note(&format!("  created user {USER} ({uid})"));
            }
            uid
        }
    };
    Ok((uid, gid))
}

pub fn install(sys: &mut dyn System, paths: &Paths, options: &Options) -> Result<()> {
    sys.note(if sys.dry_run() {
        "Dry run: nothing below is changed.\n"
    } else {
        "Installing sinkhole as a system service.\n"
    });
    let (config, existing) = config_text(sys, paths)?;
    let exe = std::env::current_exe().context("finding the sinkhole binary")?;
    if exe != paths.binary {
        if let Some(dir) = paths.binary.parent() {
            sys.mkdir(dir, 0o755)?;
        }
        sys.copy(&exe, &paths.binary, 0o755)?;
    }
    let (uid, gid) = ensure_user(sys)?;
    sys.mkdir(&paths.cache, 0o755)?;
    sys.chown(&paths.cache, uid, gid)?;
    if existing {
        sys.note(&format!(
            "  keeping the config at {}",
            paths.config.display()
        ));
    } else if let Some(dir) = paths.config.parent() {
        sys.mkdir(dir, 0o755)?;
        sys.write(&paths.config, config.as_bytes(), 0o644)?;
    }
    let plist_path = plist_path();
    if loaded(sys)? {
        sys.run(LAUNCHCTL, &["bootout", &format!("system/{LABEL}")])?;
    }
    sys.write(&plist_path, plist(paths).as_bytes(), 0o644)?;
    must(
        sys.run(
            LAUNCHCTL,
            &["bootstrap", "system", &plist_path.to_string_lossy()],
        )?,
        "launchctl bootstrap",
    )?;
    let addr = "127.0.0.1:53".parse()?;
    if !sys.wait_ready(addr, Duration::from_secs(15)) {
        sys.run(LAUNCHCTL, &["bootout", &format!("system/{LABEL}")])?;
        bail!(
            "the resolver did not start, so the DNS settings were left alone; see {LOG}. \
             Remove what was installed with: sudo sinkhole uninstall"
        );
    }
    if !sys.dry_run() {
        sys.note("  the resolver answers on 127.0.0.1:53");
    }
    if options.no_dns {
        sys.note("\nDNS settings left alone (--no-dns). Point them at sinkhole later with: sudo sinkhole install");
    } else {
        sys.note("\nPointing the system's DNS at sinkhole:");
        point_dns(sys, paths)?;
        match sys.verify(&paths.config) {
            Some(Ok(message)) => sys.note(&format!("  check: {message}")),
            Some(Err(e)) => sys.note(&format!("  WARNING: {e}")),
            None => {}
        }
    }
    if sys.dry_run() {
        sys.note("\nThat is everything install would do. Run it with sudo, without --dry-run.");
        return Ok(());
    }
    sys.note(&format!(
        "\nInstalled. Undo everything with:\n  sudo sinkhole uninstall\n\
         If sinkhole itself is broken, this restores the DNS settings alone:\n  sudo sh {}\n\
         Logs: {LOG}",
        shell_word(&paths.restore_script().to_string_lossy())
    ));
    Ok(())
}

pub fn uninstall(sys: &mut dyn System, paths: &Paths, options: &Options) -> Result<()> {
    sys.note(if sys.dry_run() {
        "Dry run: nothing below is changed.\n"
    } else {
        "Uninstalling sinkhole.\n"
    });
    sys.note("Restoring the DNS settings:");
    restore_dns(sys, paths)?;
    if loaded(sys)? {
        sys.run(LAUNCHCTL, &["bootout", &format!("system/{LABEL}")])?;
        sys.note("  stopped the service");
    }
    sys.remove(&plist_path())?;
    sys.remove(&paths.binary)?;
    sys.remove_dir_all(&paths.cache)?;
    sys.remove_dir_all(&paths.state)?;
    sys.remove(Path::new(LOG))?;
    if options.purge {
        if let Some(dir) = paths.config.parent() {
            sys.remove_dir_all(dir)?;
        }
    } else if sys.exists(&paths.config) {
        sys.note(&format!(
            "  kept the config at {} (--purge removes it)",
            paths.config.display()
        ));
    }
    if record_id(sys, &format!("/Users/{USER}"), "UniqueID")?.is_some() {
        sys.run(DSCL, &[".", "-delete", &format!("/Users/{USER}")])?;
    }
    if record_id(sys, &format!("/Groups/{USER}"), "PrimaryGroupID")?.is_some() {
        sys.run(DSCL, &[".", "-delete", &format!("/Groups/{USER}")])?;
    }
    if sys.dry_run() {
        sys.note("\nThat is everything uninstall would do.");
        return Ok(());
    }
    sys.note(
        "\nUninstalled. The browser bridge, if you set it up, is per user: \
         remove it with `sinkhole bridge uninstall` before this binary goes, or delete \
         sinkhole.bridge.json from your browsers' NativeMessagingHosts folders.",
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::fake::Fake;
    use super::*;

    const LIST: &str = "/usr/sbin/networksetup -listallnetworkservices";

    fn machine() -> Fake {
        let mut sys = Fake {
            ready: true,
            ..Fake::default()
        };
        sys.answer(
            LIST,
            "An asterisk (*) denotes that a network service is disabled.\nWi-Fi\n*USB 10/100/1000 LAN\n",
        );
        sys.answer(
            "/usr/sbin/networksetup -getdnsservers Wi-Fi",
            "8.8.8.8\n1.1.1.1\n",
        );
        sys.answer(
            "/usr/sbin/networksetup -getdnsservers 'USB 10/100/1000 LAN'",
            "There aren't any DNS Servers set on USB 10/100/1000 LAN.\n",
        );
        sys.fail("/bin/launchctl print system/sinkhole.resolver");
        sys.fail("/usr/bin/dscl . -read /Users/_sinkhole UniqueID");
        sys.fail("/usr/bin/dscl . -read /Groups/_sinkhole PrimaryGroupID");
        sys.answer(
            "/usr/bin/dscl . -list /Users UniqueID",
            "root 0\n_www 70\nme 501\n",
        );
        sys.answer(
            "/usr/bin/dscl . -list /Groups PrimaryGroupID",
            "wheel 0\nstaff 20\n_x 200\n",
        );
        sys
    }

    #[test]
    fn install_saves_then_points_every_service() {
        let mut sys = machine();
        let paths = paths();
        install(&mut sys, &paths, &Options::default()).unwrap();

        let backup: Backup = serde_json::from_slice(&sys.files[&paths.backup()]).unwrap();
        assert_eq!(
            backup.services,
            [
                ServiceDns {
                    name: "Wi-Fi".into(),
                    servers: vec!["8.8.8.8".into(), "1.1.1.1".into()]
                },
                ServiceDns {
                    name: "USB 10/100/1000 LAN".into(),
                    servers: vec![]
                },
            ]
        );
        let script = String::from_utf8(sys.files[&paths.restore_script()].clone()).unwrap();
        assert!(script.contains("/usr/sbin/networksetup -setdnsservers Wi-Fi 8.8.8.8 1.1.1.1\n"));
        assert!(
            script.contains("/usr/sbin/networksetup -setdnsservers 'USB 10/100/1000 LAN' Empty\n")
        );
        assert!(sys.ran("/usr/sbin/networksetup -setdnsservers Wi-Fi 127.0.0.1 ::1"));
        assert!(
            sys.ran("/usr/sbin/networksetup -setdnsservers 'USB 10/100/1000 LAN' 127.0.0.1 ::1")
        );
        // The user and group get the first id free in both.
        assert!(sys.ran("/usr/bin/dscl . -create /Groups/_sinkhole PrimaryGroupID 201"));
        assert!(sys.ran("/usr/bin/dscl . -create /Users/_sinkhole UniqueID 201"));
        // The service ran before any DNS change.
        let bootstrap = sys
            .log
            .iter()
            .position(|l| l.contains("bootstrap"))
            .unwrap();
        let first_dns = sys
            .log
            .iter()
            .position(|l| l.contains("-setdnsservers"))
            .unwrap();
        assert!(bootstrap < first_dns);
        let plist = String::from_utf8(sys.files[&plist_path()].clone()).unwrap();
        assert!(plist.contains("<string>--user</string>\n\t\t<string>_sinkhole</string>"));
    }

    #[test]
    fn a_resolver_that_does_not_start_leaves_dns_alone() {
        let mut sys = machine();
        sys.ready = false;
        assert!(install(&mut sys, &paths(), &Options::default()).is_err());
        assert!(!sys.log.iter().any(|l| l.contains("-setdnsservers")));
        assert!(sys.ran("/bin/launchctl bootout system/sinkhole.resolver"));
    }

    #[test]
    fn reinstall_keeps_the_original_backup() {
        let mut sys = machine();
        let paths = paths();
        install(&mut sys, &paths, &Options::default()).unwrap();
        // Now everything points at sinkhole.
        sys.answer(
            "/usr/sbin/networksetup -getdnsservers Wi-Fi",
            "127.0.0.1\n::1\n",
        );
        sys.answer(
            "/usr/sbin/networksetup -getdnsservers 'USB 10/100/1000 LAN'",
            "127.0.0.1\n::1\n",
        );
        sys.log.clear();
        install(&mut sys, &paths, &Options::default()).unwrap();
        let backup: Backup = serde_json::from_slice(&sys.files[&paths.backup()]).unwrap();
        assert_eq!(backup.services[0].servers, ["8.8.8.8", "1.1.1.1"]);
        assert!(!sys.log.iter().any(|l| l.contains("-setdnsservers")));
    }

    #[test]
    fn uninstall_restores_exactly_and_respects_later_changes() {
        let mut sys = machine();
        let paths = paths();
        install(&mut sys, &paths, &Options::default()).unwrap();
        // Wi-Fi still points at sinkhole; the user set the LAN by hand since.
        sys.answer(
            "/usr/sbin/networksetup -getdnsservers Wi-Fi",
            "127.0.0.1\n::1\n",
        );
        sys.answer(
            "/usr/sbin/networksetup -getdnsservers 'USB 10/100/1000 LAN'",
            "9.9.9.9\n",
        );
        sys.answer(
            "/bin/launchctl print system/sinkhole.resolver",
            "state = running",
        );
        sys.answer(
            "/usr/bin/dscl . -read /Users/_sinkhole UniqueID",
            "UniqueID: 201",
        );
        sys.log.clear();
        uninstall(&mut sys, &paths, &Options::default()).unwrap();
        assert!(sys.ran("/usr/sbin/networksetup -setdnsservers Wi-Fi 8.8.8.8 1.1.1.1"));
        assert!(!sys.log.iter().any(|l| l.contains("'USB 10/100/1000 LAN'")));
        assert!(!sys.files.contains_key(&paths.backup()));
        assert!(sys.ran("/bin/launchctl bootout system/sinkhole.resolver"));
        assert!(sys.ran("/usr/bin/dscl . -delete /Users/_sinkhole"));
        // DNS first, then the service.
        let dns = sys
            .log
            .iter()
            .position(|l| l.contains("-setdnsservers"))
            .unwrap();
        let stop = sys.log.iter().position(|l| l.contains("bootout")).unwrap();
        assert!(dns < stop);
        // The config stays unless purged.
        assert!(sys.files.contains_key(&paths.config));
    }

    #[test]
    fn no_dns_installs_the_service_only() {
        let mut sys = machine();
        let options = Options {
            no_dns: true,
            ..Options::default()
        };
        install(&mut sys, &paths(), &options).unwrap();
        assert!(
            sys.ran(
                "/bin/launchctl bootstrap system /Library/LaunchDaemons/sinkhole.resolver.plist"
            )
        );
        assert!(!sys.log.iter().any(|l| l.contains("-setdnsservers")));
    }
}
