//! `sinkd stats`, `pause` and `resume`: requests to the running daemon
//! over its control socket.

use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use sinkd_resolver::Paused;
use sinkd_resolver::control::{self, Request, Response, Status};
use sinkd_resolver::querylog::Entry;

use crate::{ago, load_config};

/// The daemon's control socket, from its config.
pub fn socket(config_path: &Path) -> Result<PathBuf> {
    let (config, base, _) = load_config(config_path)?;
    control::socket_path(&config, &base)
        .ok_or_else(|| anyhow!("no control socket: set control.socket or updates.cache_dir"))
}

/// Sends one request and returns the answer, turning daemon errors into
/// errors.
#[tokio::main(flavor = "current_thread")]
pub async fn ask(config_path: &Path, request: Request) -> Result<Response> {
    let path = socket(config_path)?;
    let response = control::ask(&path, &request).await.map_err(|e| match e.kind() {
        io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused => anyhow!(
            "sinkd is not running (nothing answers on {}); start it with `sinkd run`, or install it with `sudo sinkd install`",
            path.display()
        ),
        io::ErrorKind::PermissionDenied => anyhow!(
            "no access to {}; try again with sudo",
            path.display()
        ),
        _ => anyhow!(e).context(format!("asking the daemon on {}", path.display())),
    })?;
    match response {
        Response::Error { message } => Err(anyhow!(message)),
        response => Ok(response),
    }
}

pub fn status(config_path: &Path) -> Result<Status> {
    match ask(config_path, Request::Status)? {
        Response::Status(status) => Ok(*status),
        other => Err(unexpected(&other)),
    }
}

fn unexpected(response: &Response) -> anyhow::Error {
    anyhow!("unexpected answer from the daemon: {response:?}")
}

pub struct StatsOptions {
    pub top: Option<usize>,
    pub recent: Option<usize>,
    pub blocked_only: bool,
    pub json: bool,
}

pub fn stats(config_path: &Path, options: &StatsOptions) -> Result<()> {
    let status = status(config_path)?;
    if options.json {
        println!("{}", serde_json::to_string_pretty(&status)?);
    } else {
        print_status(&status);
    }
    if let Some(limit) = options.top {
        if !status.query_log {
            bail!(
                "the query log is off; set [query_log] enabled = true in the config to see top names"
            );
        }
        let Response::Top(top) = ask(config_path, Request::Top { limit })? else {
            bail!("unexpected answer from the daemon");
        };
        if options.json {
            println!("{}", serde_json::to_string_pretty(&top)?);
        } else {
            let since = top
                .since_ms
                .map(|ms| format!(", since {}", ago(age(ms))))
                .unwrap_or_default();
            println!("\nTop names ({} queries logged{since}):", top.entries);
            print_ranked("Blocked", &top.blocked);
            print_ranked("Queried", &top.queried);
        }
    }
    if let Some(limit) = options.recent {
        if !status.query_log {
            bail!(
                "the query log is off; set [query_log] enabled = true in the config to see queries"
            );
        }
        let Response::Log { entries } = ask(
            config_path,
            Request::Log {
                limit,
                blocked_only: options.blocked_only,
            },
        )?
        else {
            bail!("unexpected answer from the daemon");
        };
        if options.json {
            println!("{}", serde_json::to_string_pretty(&entries)?);
        } else {
            print_entries(&entries);
        }
    }
    Ok(())
}

fn age(at_ms: u64) -> Duration {
    let now = sinkd_now_ms();
    Duration::from_millis(now.saturating_sub(at_ms))
}

fn sinkd_now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

fn print_status(s: &Status) {
    let listen: Vec<String> = s.listen.iter().map(ToString::to_string).collect();
    println!(
        "sinkd {} (pid {}), up {}, listening on {}",
        s.version,
        s.pid,
        uptime(s.uptime_secs),
        listen.join(", ")
    );
    println!("Blocking:  {}", describe_pause(s.paused));
    println!(
        "Rules:     {} blocked names, {} allowed",
        thousands(s.block_entries as u64),
        thousands(s.allow_entries as u64)
    );
    let t = &s.stats;
    let pct = |n: u64| {
        if t.queries == 0 {
            String::new()
        } else {
            format!(" ({:.1}%)", n as f64 * 100.0 / t.queries as f64)
        }
    };
    println!(
        "Queries:   {} — blocked {}{}, uncloaked {}, cached {}{}, forwarded {}, local {}",
        thousands(t.queries),
        thousands(t.blocked),
        pct(t.blocked + t.uncloaked),
        thousands(t.uncloaked),
        thousands(t.cached),
        pct(t.cached),
        thousands(t.forwarded),
        thousands(t.local),
    );
    let trouble = t.stale + t.upstream_failures + t.errors + t.shed + t.refused_clients;
    if trouble > 0 {
        println!(
            "           stale {}, upstream failures {}, errors {}, shed {}, refused clients {}",
            t.stale, t.upstream_failures, t.errors, t.shed, t.refused_clients
        );
    }
    println!("Cache:     {} answers", thousands(s.cache_entries));
    for (i, u) in s.upstreams.iter().enumerate() {
        let label = if i == 0 { "Upstreams:" } else { "          " };
        let health = match u.failures {
            0 => "ok".to_owned(),
            n => format!("{n} failure(s) in a row"),
        };
        println!("{label} {} — {health}", u.upstream);
    }
    println!(
        "Query log: {}",
        if s.query_log {
            "on (in memory only; `sinkd stats --top 10`, `--recent 20`)"
        } else {
            "off"
        }
    );
}

pub fn describe_pause(paused: Option<Paused>) -> String {
    match paused {
        None => "on".to_owned(),
        Some(Paused { until_ms: None }) => "PAUSED until `sinkd resume`".to_owned(),
        Some(Paused {
            until_ms: Some(until),
        }) => {
            let left = Duration::from_millis(until.saturating_sub(sinkd_now_ms()));
            format!("PAUSED for {} more", human(left))
        }
    }
}

fn print_ranked(label: &str, ranked: &[(String, u64)]) {
    println!("  {label}:");
    if ranked.is_empty() {
        println!("    (none)");
    }
    for (name, count) in ranked {
        println!("    {count:>8}  {name}");
    }
}

fn print_entries(entries: &[Entry]) {
    println!();
    if entries.is_empty() {
        println!("(no queries logged)");
    }
    for e in entries {
        let rule = e
            .rule
            .as_deref()
            .filter(|r| *r != e.name)
            .map(|r| format!(" (by {r})"))
            .unwrap_or_default();
        println!(
            "{:>10}  {:<9} {:<6} {}{rule}",
            ago(age(e.at_ms)),
            format!("{:?}", e.outcome).to_lowercase(),
            e.qtype,
            e.name
        );
    }
}

pub fn pause(config_path: &Path, duration: Option<Duration>) -> Result<()> {
    let secs = duration.map(|d| d.as_secs().max(1));
    match ask(config_path, Request::Pause { secs })? {
        Response::Done { paused } => {
            match paused.and_then(|p| p.until_ms) {
                Some(until) => {
                    let left = Duration::from_millis(until.saturating_sub(sinkd_now_ms()));
                    println!(
                        "Blocking paused for {}; it comes back by itself, or with `sinkd resume`.",
                        human(left)
                    );
                }
                None => println!("Blocking paused. Turn it back on with `sinkd resume`."),
            }
            Ok(())
        }
        other => Err(unexpected(&other)),
    }
}

pub fn resume(config_path: &Path) -> Result<()> {
    match ask(config_path, Request::Resume)? {
        Response::Done { .. } => {
            println!("Blocking is on.");
            Ok(())
        }
        other => Err(unexpected(&other)),
    }
}

/// Asks a running daemon to re-read its config now, if one is running.
/// Returns whether it did.
pub fn reload_if_running(config_path: &Path) -> bool {
    matches!(ask(config_path, Request::Reload), Ok(Response::Done { .. }))
}

/// Parses `90s`, `5m`, `1h30m`, `2d`.
pub fn parse_duration(text: &str) -> Result<Duration> {
    let text = text.trim();
    if text.is_empty() {
        bail!("empty duration");
    }
    let mut total = 0u64;
    let mut number = String::new();
    for c in text.chars() {
        if c.is_ascii_digit() {
            number.push(c);
            continue;
        }
        let unit = match c {
            's' => 1,
            'm' => 60,
            'h' => 3600,
            'd' => 86_400,
            _ => bail!("{text:?}: unknown unit {c:?}; use s, m, h or d (e.g. 5m, 1h30m)"),
        };
        if number.is_empty() {
            bail!("{text:?}: a number must come before {c:?}");
        }
        let n: u64 = number.parse().context("duration too long")?;
        total = total
            .checked_add(n.checked_mul(unit).context("duration too long")?)
            .context("duration too long")?;
        number.clear();
    }
    if !number.is_empty() {
        bail!("{text:?}: give a unit, e.g. {number}m or {number}s");
    }
    if total == 0 {
        bail!("{text:?} is no time at all");
    }
    Ok(Duration::from_secs(total))
}

pub fn human(d: Duration) -> String {
    let s = d.as_secs();
    match s {
        0..60 => format!("{s} s"),
        60..3600 => format!("{} min", s.div_ceil(60)),
        _ => format!("{} h {} min", s / 3600, (s % 3600) / 60),
    }
}

fn uptime(secs: u64) -> String {
    match secs {
        0..60 => format!("{secs} s"),
        60..3600 => format!("{} min", secs / 60),
        3600..86_400 => format!("{} h {} min", secs / 3600, (secs % 3600) / 60),
        _ => format!("{} days {} h", secs / 86_400, (secs % 86_400) / 3600),
    }
}

fn thousands(n: u64) -> String {
    let digits = n.to_string();
    let mut out = String::new();
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations() {
        assert_eq!(parse_duration("90s").unwrap(), Duration::from_secs(90));
        assert_eq!(parse_duration("5m").unwrap(), Duration::from_secs(300));
        assert_eq!(parse_duration("1h30m").unwrap(), Duration::from_secs(5400));
        assert_eq!(parse_duration("2d").unwrap(), Duration::from_secs(172_800));
        for bad in ["", "5", "m", "5x", "0m", "99999999999999999999h"] {
            assert!(parse_duration(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn numbers() {
        assert_eq!(thousands(0), "0");
        assert_eq!(thousands(999), "999");
        assert_eq!(thousands(1000), "1,000");
        assert_eq!(thousands(1_234_567), "1,234,567");
        assert_eq!(human(Duration::from_secs(299)), "5 min");
        assert_eq!(human(Duration::from_secs(3_660)), "1 h 1 min");
    }
}
