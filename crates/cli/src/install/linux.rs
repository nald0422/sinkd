//! Linux: a systemd service under a dynamic user, and the system resolver
//! pointed at it.
//!
//! The unit never runs sinkhole as root. systemd gives an unprivileged,
//! per-boot user `CAP_NET_BIND_SERVICE` (port 53) and nothing else, and
//! sandboxes it: read-only system, no home directories, its own `/tmp`,
//! no devices, a system-call allowlist. `Type=notify` makes `systemctl
//! start` wait until the sockets are bound; `WatchdogSec` restarts a daemon
//! that stops answering its self-test.
//!
//! DNS, by what the machine uses:
//!
//! - **systemd-resolved** (`/etc/resolv.conf` is its stub): a drop-in sets
//!   sinkhole as the global server with the `~.` routing domain, which
//!   makes resolved prefer it for every name over the servers DHCP hands
//!   each link. Uninstall deletes the drop-in.
//! - **A plain `/etc/resolv.conf` file**: saved byte for byte, then
//!   replaced. Uninstall writes the saved bytes back.
//! - **Anything else** (a symbolic link to NetworkManager's file, say):
//!   left alone, with instructions, since whatever owns it would undo the
//!   change.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

use super::{Options, Paths, System, config_text, must, shell_word};

const UNIT: &str = "sinkhole.service";
const SYSTEMCTL: &str = "/usr/bin/systemctl";
const RESOLV: &str = "/etc/resolv.conf";

pub fn paths() -> Paths {
    Paths {
        binary: "/usr/local/bin/sinkhole".into(),
        config: "/etc/sinkhole/sinkhole.toml".into(),
        cache: "/var/cache/sinkhole".into(),
        state: "/var/lib/sinkhole".into(),
        control_socket: Some("/run/sinkhole/control.sock".into()),
    }
}

fn unit_path() -> PathBuf {
    PathBuf::from(format!("/etc/systemd/system/{UNIT}"))
}

fn dropin_path() -> PathBuf {
    PathBuf::from("/etc/systemd/resolved.conf.d/sinkhole.conf")
}

pub fn unit(paths: &Paths) -> String {
    format!(
        r#"# Written by `sinkhole install`; removed by `sinkhole uninstall`.
[Unit]
Description=sinkhole DNS resolver
After=network.target
Before=nss-lookup.target
Wants=nss-lookup.target

[Service]
Type=notify
ExecStart={bin} run --config {config}
ExecReload=/bin/kill -HUP $MAINPID
Restart=always
RestartSec=2
WatchdogSec=30
Environment=RUST_LOG=info

# An unprivileged user made for this service, allowed to bind port 53 and
# nothing more.
DynamicUser=yes
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=yes
CacheDirectory=sinkhole
RuntimeDirectory=sinkhole
RuntimeDirectoryMode=0755

ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectClock=yes
ProtectHostname=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectProc=invisible
ProcSubset=pid
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallFilter=~@privileged
SystemCallErrorNumber=EPERM
UMask=0022
MemoryMax=512M
LimitNOFILE=4096

[Install]
WantedBy=multi-user.target
"#,
        bin = paths.binary.display(),
        config = paths.config.display(),
    )
}

const DROPIN: &str = "# Written by `sinkhole install`; removed by `sinkhole uninstall`.\n\
# `~.` routes every name to these servers in preference to the ones\n\
# each network link was given.\n\
[Resolve]\nDNS=127.0.0.1 ::1\nDomains=~.\n";

const RESOLV_CONF: &str = "# Written by `sinkhole install`; `sinkhole uninstall` restores the original.\n\
nameserver 127.0.0.1\nnameserver ::1\noptions edns0 trust-ad\n";

/// How the DNS settings were changed, for uninstall.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "method", rename_all = "snake_case")]
pub enum Backup {
    /// A systemd-resolved drop-in was added.
    Resolved,
    /// `/etc/resolv.conf` was replaced; the original is in `resolv.conf.orig`.
    ResolvConf { mode: u32 },
}

fn original_path(paths: &Paths) -> PathBuf {
    paths.state.join("resolv.conf.orig")
}

/// How this machine resolves names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resolver {
    Resolved,
    File,
    Other(PathBuf),
}

pub fn detect(sys: &mut dyn System) -> Result<Resolver> {
    let resolv = Path::new(RESOLV);
    if let Some(target) = sys.read_link(resolv) {
        let t = target.to_string_lossy();
        if t.contains("systemd/resolve/stub-resolv.conf")
            || t.contains("systemd/resolve/resolv.conf")
        {
            let active = sys.query(SYSTEMCTL, &["is-active", "systemd-resolved"])?;
            if active.stdout.trim() == "active" {
                return Ok(Resolver::Resolved);
            }
        }
        return Ok(Resolver::Other(target));
    }
    match sys.read(resolv) {
        // A file that resolved writes (some distributions copy it).
        Some(bytes) if String::from_utf8_lossy(&bytes).contains("127.0.0.53") => {
            let active = sys.query(SYSTEMCTL, &["is-active", "systemd-resolved"])?;
            Ok(if active.stdout.trim() == "active" {
                Resolver::Resolved
            } else {
                Resolver::File
            })
        }
        Some(_) => Ok(Resolver::File),
        None => Ok(Resolver::File),
    }
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

fn restore_script(backup: &Backup, paths: &Paths) -> String {
    let body = match backup {
        Backup::Resolved => format!(
            "rm -f {}\nsystemctl restart systemd-resolved\n",
            shell_word(&dropin_path().to_string_lossy())
        ),
        Backup::ResolvConf { mode } => format!(
            "cp {} {RESOLV}\nchmod {mode:o} {RESOLV}\n",
            shell_word(&original_path(paths).to_string_lossy())
        ),
    };
    format!(
        "#!/bin/sh\n# Puts back the DNS settings found when sinkhole was installed.\n# Written by `sinkhole install`. Run it with: sudo sh restore-dns.sh\n{body}"
    )
}

pub fn point_dns(sys: &mut dyn System, paths: &Paths) -> Result<()> {
    if let Some(backup) = read_backup(sys, paths)? {
        sys.note(&format!("  already pointed at sinkhole ({backup:?})"));
        return Ok(());
    }
    let backup = match detect(sys)? {
        Resolver::Resolved => {
            let dropin = dropin_path();
            if sys.exists(&dropin) {
                bail!(
                    "{} exists and is not sinkhole's; move it away first",
                    dropin.display()
                );
            }
            sys.write(&dropin, DROPIN.as_bytes(), 0o644)?;
            must(
                sys.run(SYSTEMCTL, &["restart", "systemd-resolved"])?,
                "systemctl restart systemd-resolved",
            )?;
            sys.note(&format!(
                "  systemd-resolved: {} makes 127.0.0.1 and ::1 the servers for every name",
                dropin.display()
            ));
            Backup::Resolved
        }
        Resolver::File => {
            let resolv = Path::new(RESOLV);
            let original = sys.read(resolv).unwrap_or_default();
            sys.mkdir(&paths.state, 0o755)?;
            sys.write(&original_path(paths), &original, 0o644)?;
            sys.write(resolv, RESOLV_CONF.as_bytes(), 0o644)?;
            sys.note("  /etc/resolv.conf now names 127.0.0.1 and ::1 (the original is saved)");
            Backup::ResolvConf { mode: 0o644 }
        }
        Resolver::Other(target) => bail!(
            "/etc/resolv.conf links to {}, which another program manages, so sinkhole leaves it alone. \
             The service is installed; point that program's DNS at 127.0.0.1 and ::1 (for NetworkManager: \
             `nmcli connection modify <name> ipv4.dns 127.0.0.1 ipv4.ignore-auto-dns yes`), \
             or run `sudo sinkhole uninstall` to remove it",
            target.display()
        ),
    };
    sys.mkdir(&paths.state, 0o755)?;
    sys.write(&paths.backup(), &serde_json::to_vec_pretty(&backup)?, 0o644)?;
    sys.write(
        &paths.restore_script(),
        restore_script(&backup, paths).as_bytes(),
        0o755,
    )?;
    Ok(())
}

pub fn restore_dns(sys: &mut dyn System, paths: &Paths) -> Result<()> {
    match read_backup(sys, paths)? {
        None => sys.note("  nothing to restore (the DNS settings were not changed)"),
        Some(Backup::Resolved) => {
            sys.remove(&dropin_path())?;
            sys.run(SYSTEMCTL, &["restart", "systemd-resolved"])?;
            sys.note(&format!("  removed {}", dropin_path().display()));
        }
        Some(Backup::ResolvConf { mode }) => {
            let resolv = Path::new(RESOLV);
            let ours = sys
                .read(resolv)
                .is_some_and(|b| b == RESOLV_CONF.as_bytes());
            if ours {
                let original = sys
                    .read(&original_path(paths))
                    .with_context(|| format!("{} is missing", original_path(paths).display()))?;
                sys.write(resolv, &original, mode)?;
                sys.note("  /etc/resolv.conf restored");
            } else {
                sys.note("  /etc/resolv.conf left as it is (changed since install)");
            }
        }
    }
    sys.remove(&paths.backup())?;
    sys.remove(&paths.restore_script())?;
    sys.remove(&original_path(paths))?;
    Ok(())
}

pub fn install(sys: &mut dyn System, paths: &Paths, options: &Options) -> Result<()> {
    sys.note(if sys.dry_run() {
        "Dry run: nothing below is changed.\n"
    } else {
        "Installing sinkhole as a system service.\n"
    });
    if !sys.exists(Path::new("/run/systemd/system")) {
        bail!("install needs systemd; without it, run `sinkhole run` from your init system");
    }
    let (config, existing) = config_text(sys, paths)?;
    let exe = std::env::current_exe().context("finding the sinkhole binary")?;
    if exe != paths.binary {
        sys.copy(&exe, &paths.binary, 0o755)?;
    }
    if existing {
        sys.note(&format!(
            "  keeping the config at {}",
            paths.config.display()
        ));
    } else if let Some(dir) = paths.config.parent() {
        sys.mkdir(dir, 0o755)?;
        sys.write(&paths.config, config.as_bytes(), 0o644)?;
    }
    sys.write(&unit_path(), unit(paths).as_bytes(), 0o644)?;
    must(
        sys.run(SYSTEMCTL, &["daemon-reload"])?,
        "systemctl daemon-reload",
    )?;
    // Type=notify: this returns once the sockets are bound.
    let started = sys.run(SYSTEMCTL, &["enable", "--now", UNIT])?;
    let addr = "127.0.0.1:53".parse()?;
    if !started.ok || !sys.wait_ready(addr, Duration::from_secs(15)) {
        sys.run(SYSTEMCTL, &["disable", "--now", UNIT])?;
        bail!(
            "the resolver did not start, so the DNS settings were left alone; see `journalctl -u sinkhole`. \
             Remove what was installed with: sudo sinkhole uninstall"
        );
    }
    if !sys.dry_run() {
        sys.note("  the resolver answers on 127.0.0.1:53");
    }
    if options.no_dns {
        sys.note("\nDNS settings left alone (--no-dns).");
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
         Logs: journalctl -u sinkhole",
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
    if sys.exists(&unit_path()) {
        sys.run(SYSTEMCTL, &["disable", "--now", UNIT])?;
        sys.remove(&unit_path())?;
        sys.run(SYSTEMCTL, &["daemon-reload"])?;
        sys.note("  stopped and removed the service");
    }
    sys.remove(&paths.binary)?;
    // A dynamic user's cache lives under /var/cache/private.
    sys.remove(&paths.cache)?;
    sys.remove_dir_all(&paths.cache)?;
    sys.remove_dir_all(Path::new("/var/cache/private/sinkhole"))?;
    sys.remove_dir_all(&paths.state)?;
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
    sys.note(if sys.dry_run() {
        "\nThat is everything uninstall would do."
    } else {
        "\nUninstalled."
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::fake::Fake;
    use super::*;

    fn machine(resolver: &str) -> Fake {
        let mut sys = Fake {
            ready: true,
            ..Fake::default()
        };
        sys.dirs.insert("/run/systemd/system".into());
        match resolver {
            "resolved" => {
                sys.links.insert(
                    RESOLV.into(),
                    "../run/systemd/resolve/stub-resolv.conf".into(),
                );
                sys.answer("/usr/bin/systemctl is-active systemd-resolved", "active\n");
            }
            "file" => {
                sys.files.insert(
                    RESOLV.into(),
                    b"nameserver 192.168.1.1\nsearch lan\n".to_vec(),
                );
            }
            _ => {
                sys.links
                    .insert(RESOLV.into(), "/run/NetworkManager/resolv.conf".into());
            }
        }
        sys
    }

    #[test]
    fn resolved_gets_a_dropin_and_loses_it() {
        let mut sys = machine("resolved");
        let paths = paths();
        install(&mut sys, &paths, &Options::default()).unwrap();
        assert_eq!(sys.files[&dropin_path()], DROPIN.as_bytes());
        assert!(sys.ran("/usr/bin/systemctl restart systemd-resolved"));
        let start = sys
            .log
            .iter()
            .position(|l| l.contains("enable --now"))
            .unwrap();
        let dns = sys
            .log
            .iter()
            .position(|l| l.contains("resolved.conf.d"))
            .unwrap();
        assert!(start < dns);
        let unit = String::from_utf8(sys.files[&unit_path()].clone()).unwrap();
        assert!(unit.contains("DynamicUser=yes"));
        assert!(unit.contains(
            "ExecStart=/usr/local/bin/sinkhole run --config /etc/sinkhole/sinkhole.toml"
        ));

        sys.log.clear();
        uninstall(&mut sys, &paths, &Options::default()).unwrap();
        assert!(!sys.files.contains_key(&dropin_path()));
        assert!(sys.ran("/usr/bin/systemctl disable --now sinkhole.service"));
        assert!(!sys.files.contains_key(&paths.backup()));
    }

    #[test]
    fn a_plain_file_is_restored_byte_for_byte() {
        let mut sys = machine("file");
        let paths = paths();
        install(&mut sys, &paths, &Options::default()).unwrap();
        assert_eq!(sys.files[Path::new(RESOLV)], RESOLV_CONF.as_bytes());
        uninstall(&mut sys, &paths, &Options::default()).unwrap();
        assert_eq!(
            sys.files[Path::new(RESOLV)],
            b"nameserver 192.168.1.1\nsearch lan\n"
        );
        assert!(!sys.files.contains_key(&original_path(&paths)));
    }

    #[test]
    fn a_managed_link_is_left_alone() {
        let mut sys = machine("networkmanager");
        let err = install(&mut sys, &paths(), &Options::default()).unwrap_err();
        assert!(format!("{err:#}").contains("NetworkManager"), "{err:#}");
        assert!(sys.links.contains_key(Path::new(RESOLV)));
        // The service itself was installed and runs.
        assert!(sys.ran("/usr/bin/systemctl enable --now sinkhole.service"));
    }

    #[test]
    fn a_failed_start_changes_no_dns() {
        let mut sys = machine("resolved");
        sys.ready = false;
        assert!(install(&mut sys, &paths(), &Options::default()).is_err());
        assert!(!sys.files.contains_key(&dropin_path()));
    }
}
