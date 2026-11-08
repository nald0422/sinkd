//! `sinkd doctor`: is everything wired up, and if not, what to do.
//!
//! Each check prints one line: `ok`, `warn` (works, but worth a look) or
//! `FAIL` (broken), with the fix. It changes nothing. It sends a few DNS
//! queries: to the daemon directly, and one through the system's resolver.

use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;

use anyhow::Result;
use hickory_proto::op::ResponseCode;

use crate::dnsq;
use crate::install;

#[derive(Default)]
struct Report {
    failures: usize,
}

impl Report {
    fn ok(&mut self, what: &str, detail: impl AsRef<str>) {
        println!("  ok    {what}: {}", detail.as_ref());
    }

    fn warn(&mut self, what: &str, detail: impl AsRef<str>) {
        println!("  warn  {what}: {}", detail.as_ref());
    }

    fn fail(&mut self, what: &str, detail: impl AsRef<str>) {
        self.failures += 1;
        println!("  FAIL  {what}: {}", detail.as_ref());
    }
}

pub fn doctor(config_path: &Path) -> Result<()> {
    let mut r = Report::default();
    println!("sinkd doctor\n");

    let config = match crate::load_config(config_path) {
        Ok((config, _, _)) => {
            let addrs: Vec<String> = config
                .listen
                .addrs
                .iter()
                .map(ToString::to_string)
                .collect();
            r.ok(
                "config",
                format!(
                    "{} loads; listens on {}",
                    config_path.display(),
                    addrs.join(", ")
                ),
            );
            for problem in crate::daemon::writable_by_others(config_path, true) {
                r.warn(
                    "config permissions",
                    format!("{problem}; whoever can edit it controls every lookup (chmod go-w)"),
                );
            }
            Some(config)
        }
        Err(e) => {
            r.fail(
                "config",
                format!("{e:#}; install with `sudo sinkd install`, or pass --config"),
            );
            None
        }
    };

    service(&mut r);

    let status = match crate::ctl::status(config_path) {
        Ok(status) => {
            let pause = crate::ctl::describe_pause(status.paused);
            let line = format!(
                "running (pid {}, version {}), blocking {pause}; {} blocked names",
                status.pid, status.version, status.block_entries
            );
            if status.paused.is_some() {
                r.warn(
                    "resolver",
                    format!("{line}; `sinkd resume` turns it back on"),
                );
            } else if status.block_entries == 0 {
                r.warn(
                    "resolver",
                    format!("{line}; lists not downloaded yet? `sinkd update`"),
                );
            } else {
                r.ok("resolver", line);
            }
            for u in &status.upstreams {
                if u.failures > 0 {
                    r.warn(
                        "upstream",
                        format!("{} failed {} time(s) in a row", u.upstream, u.failures),
                    );
                }
            }
            Some(status)
        }
        Err(e) => {
            r.fail("resolver", format!("{e:#}"));
            None
        }
    };

    if let Some(config) = &config
        && let Some(&addr) = config.listen.addrs.first()
    {
        queries(
            &mut r,
            addr,
            status.as_ref().and_then(|s| s.sample_blocked.as_deref()),
        );
    }

    // The system's resolver settings can name no port but 53.
    let on_53 = config
        .as_ref()
        .is_none_or(|c| c.listen.addrs.iter().any(|a| a.port() == 53));
    if on_53 {
        system_dns(&mut r);
        match install::verify_system_dns(status.as_ref().and_then(|s| s.sample_blocked.as_deref()))
        {
            Ok(message) => r.ok("system lookups", message),
            Err(e) => r.fail("system lookups", format!("{e:#}")),
        }
    } else {
        println!(
            "  info  system DNS: not checked; this config listens on a port other than 53, which the system cannot use"
        );
    }

    bridge(&mut r);

    println!();
    if r.failures == 0 {
        println!("Everything checks out.");
        Ok(())
    } else {
        anyhow::bail!("{} check(s) failed", r.failures)
    }
}

fn service(r: &mut Report) {
    if cfg!(target_os = "macos") {
        let label = format!("system/{}", install::macos::LABEL);
        match std::process::Command::new("/bin/launchctl")
            .args(["print", &label])
            .output()
        {
            Ok(out) if out.status.success() => {
                let text = String::from_utf8_lossy(&out.stdout);
                let state = text
                    .lines()
                    .find_map(|l| l.trim().strip_prefix("state = "))
                    .unwrap_or("?");
                if state == "running" {
                    r.ok(
                        "service",
                        format!("launchd job {} is running", install::macos::LABEL),
                    );
                } else {
                    r.fail(
                        "service",
                        format!("launchd job is {state}; see /Library/Logs/sinkd.log"),
                    );
                }
            }
            _ => r.warn(
                "service",
                "not installed as a service (`sudo sinkd install`)",
            ),
        }
    } else {
        match std::process::Command::new("systemctl")
            .args(["is-active", "sinkd.service"])
            .output()
        {
            Ok(out) => {
                let state = String::from_utf8_lossy(&out.stdout).trim().to_owned();
                match state.as_str() {
                    "active" => r.ok("service", "systemd unit sinkd.service is active"),
                    "inactive" | "unknown" | "" => r.warn(
                        "service",
                        "not installed as a service (`sudo sinkd install`)",
                    ),
                    other => r.fail(
                        "service",
                        format!("sinkd.service is {other}; see `journalctl -u sinkd`"),
                    ),
                }
            }
            Err(_) => r.warn("service", "no systemctl"),
        }
    }
}

fn queries(r: &mut Report, addr: SocketAddr, sample: Option<&str>) {
    let timeout = Duration::from_secs(3);
    match dnsq::ask(addr, "localhost", timeout) {
        Ok(_) => r.ok("listening", format!("answers on {addr}")),
        Err(e) => {
            r.fail("listening", format!("{e:#}"));
            return;
        }
    }
    match dnsq::ask(addr, "example.com", Duration::from_secs(6)) {
        Ok(m) if m.metadata.response_code == ResponseCode::NoError => {
            r.ok("upstream", "example.com resolves through the upstreams")
        }
        Ok(m) => r.fail(
            "upstream",
            format!(
                "example.com: {:?}; no upstream answers (network down, or DoH blocked?)",
                m.metadata.response_code
            ),
        ),
        Err(e) => r.fail("upstream", format!("{e:#}")),
    }
    if let Some(name) = sample {
        match dnsq::ask(addr, name, timeout) {
            Ok(m) => {
                let ips = dnsq::addresses(&m);
                if dnsq::is_null(&ips) || m.metadata.response_code == ResponseCode::NXDomain {
                    r.ok("blocking", format!("{name} is blocked"));
                } else {
                    r.fail(
                        "blocking",
                        format!("{name} answered {ips:?}; is blocking paused?"),
                    );
                }
            }
            Err(e) => r.fail("blocking", format!("{e:#}")),
        }
    }
    match dnsq::ask(addr, "use-application-dns.net", timeout) {
        Ok(m) if m.metadata.response_code == ResponseCode::NXDomain => r.ok(
            "Firefox canary",
            "use-application-dns.net is NXDOMAIN, so Firefox keeps to the system resolver",
        ),
        Ok(_) => r.warn(
            "Firefox canary",
            "use-application-dns.net resolves: Firefox may use its own DNS-over-HTTPS and bypass sinkd",
        ),
        Err(e) => r.warn("Firefox canary", format!("{e:#}")),
    }
}

fn system_dns(r: &mut Report) {
    let mut sys = install::DryRun;
    if cfg!(target_os = "macos") {
        let Ok(services) = install::macos::services(&mut sys) else {
            r.warn("system DNS", "could not list the network services");
            return;
        };
        let mut ours = Vec::new();
        let mut other = Vec::new();
        for s in services {
            match install::macos::dns_of(&mut sys, &s) {
                Ok(servers) if servers.first().map(String::as_str) == Some("127.0.0.1") => {
                    ours.push(s)
                }
                Ok(servers) => other.push(format!(
                    "{s} ({})",
                    if servers.is_empty() {
                        "automatic".to_owned()
                    } else {
                        servers.join(", ")
                    }
                )),
                Err(_) => {}
            }
        }
        if other.is_empty() {
            r.ok(
                "system DNS",
                format!("every service uses 127.0.0.1: {}", ours.join(", ")),
            );
        } else if ours.is_empty() {
            r.fail(
                "system DNS",
                format!(
                    "no service uses sinkd: {}; `sudo sinkd install`",
                    other.join(", ")
                ),
            );
        } else {
            r.warn(
                "system DNS",
                format!(
                    "not using sinkd: {}; `sudo sinkd install` points them too",
                    other.join(", ")
                ),
            );
        }
    } else {
        match install::linux::detect(&mut sys) {
            Ok(install::linux::Resolver::Resolved) => {
                if Path::new("/etc/systemd/resolved.conf.d/sinkd.conf").exists() {
                    r.ok(
                        "system DNS",
                        "systemd-resolved forwards every name to sinkd",
                    );
                } else {
                    r.fail(
                        "system DNS",
                        "systemd-resolved does not use sinkd; `sudo sinkd install`",
                    );
                }
            }
            Ok(install::linux::Resolver::File) => {
                let text = std::fs::read_to_string("/etc/resolv.conf").unwrap_or_default();
                if text.lines().find(|l| l.starts_with("nameserver"))
                    == Some("nameserver 127.0.0.1")
                {
                    r.ok("system DNS", "/etc/resolv.conf names 127.0.0.1 first");
                } else {
                    r.fail(
                        "system DNS",
                        "/etc/resolv.conf does not name 127.0.0.1 first",
                    );
                }
            }
            Ok(install::linux::Resolver::Other(target)) => r.warn(
                "system DNS",
                format!(
                    "/etc/resolv.conf links to {}; set that program's DNS to 127.0.0.1",
                    target.display()
                ),
            ),
            Err(e) => r.warn("system DNS", format!("{e:#}")),
        }
    }
}

fn bridge(r: &mut Report) {
    let Ok(browsers) = crate::bridge::browsers() else {
        return;
    };
    let installed: Vec<&str> = browsers
        .iter()
        .filter(|b| {
            b.hosts
                .join(format!("{}.json", crate::bridge::HOST_NAME))
                .exists()
        })
        .map(|b| b.name)
        .collect();
    if installed.is_empty() {
        println!("  info  browser bridge: not set up (optional; `sinkd bridge install`)");
    } else {
        r.ok(
            "browser bridge",
            format!("set up for {}", installed.join(", ")),
        );
    }
}
