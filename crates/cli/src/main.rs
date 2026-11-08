//! The `sinkd` command.
#![forbid(unsafe_code)]

mod bridge;
mod check;
mod ctl;
mod daemon;
mod dnsq;
mod doctor;
mod edit;
mod install;

use std::io::{self, IsTerminal};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow};
use clap::{Parser, Subcommand};
use sinkd_compiler::{ListInput, Manifest};
use sinkd_core::config::Config;
use sinkd_filters::Env;
use sinkd_lists::{Cache, Fetcher, Outcome, Report};
use sinkd_resolver::{PARALLEL_CHECKS, upstreams};
use tokio::sync::Semaphore;
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(
    name = "sinkd",
    version,
    about = "A local DNS sinkhole for ads and trackers, and the tools around it"
)]
struct Cli {
    /// The resolver's config file. Default: the installed one
    /// (/usr/local/etc/sinkd/sinkd.toml on macOS,
    /// /etc/sinkd/sinkd.toml on Linux).
    #[arg(short, long, global = true, env = "SINKD_CONFIG")]
    config: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run the resolver in the foreground until interrupted.
    ///
    /// This only listens on the configured addresses. It does not change the
    /// system's DNS settings, so nothing uses it unless pointed at it.
    ///
    /// Lists, the config file and downloaded copies are watched while it
    /// runs: edits apply within seconds, and SIGHUP applies them at once.
    Run {
        /// Bind as root, then serve as this unprivileged user (macOS; the
        /// installed service uses it).
        #[arg(long)]
        user: Option<String>,
        /// Sockets handed down by a privileged parent (internal).
        #[arg(long, hide = true)]
        inherited: Option<String>,
    },
    /// Check every URL list for a new version now.
    ///
    /// Downloads go to the cache directory, where a running resolver picks
    /// them up within seconds. A list that fails to download, or comes back
    /// broken, keeps its last good copy.
    Update {
        /// Download in full, ignoring the cached copy's ETag, and accept a
        /// list even if it shrank drastically.
        #[arg(long)]
        force: bool,
    },
    /// Compile filter lists into the extension's DNR rulesets and the
    /// resolver's domain set, with a report of what each cannot use.
    Compile {
        /// The build manifest: which lists make up which ruleset.
        #[arg(long, default_value = "extension/rulesets.toml")]
        rulesets: PathBuf,
        /// Where to write rulesets/, war/, dns/ and report.json.
        #[arg(long, default_value = "extension/build/compiled")]
        out: PathBuf,
        /// Cache for downloaded lists. Default: the per-user cache.
        #[arg(long)]
        cache: Option<PathBuf>,
        /// Use cached copies only; download nothing.
        #[arg(long)]
        offline: bool,
    },
    /// Explain what the resolver and the extension do with a name or a URL,
    /// and which rule decides it.
    ///
    /// A URL with no --from is checked as a page: its network verdict, then
    /// the hiding rules and scriptlets that would run on it. Reads cached
    /// lists only; downloads nothing.
    Check {
        /// A domain (`ads.example.com`) or a URL (`https://site.com/page`).
        target: String,
        /// The request type: script, image, stylesheet, xhr, subdocument,
        /// document… Default: a page for a URL without --from, else guessed.
        #[arg(long = "type")]
        kind: Option<String>,
        /// The page making the request, for subresources.
        #[arg(long)]
        from: Option<String>,
        /// The extension's build manifest.
        #[arg(long, default_value = "extension/rulesets.toml")]
        rulesets: PathBuf,
        /// The extension's list cache. Default: the per-user cache or
        /// `build/list-cache` beside the manifest, whichever has the lists.
        #[arg(long)]
        cache: Option<PathBuf>,
    },
    /// Counters from the running resolver, and with the query log on, the
    /// most frequent and the latest names.
    Stats {
        /// The N most frequent names, blocked and queried (query log).
        #[arg(long, value_name = "N")]
        top: Option<usize>,
        /// The N latest queries (query log).
        #[arg(long, value_name = "N")]
        recent: Option<usize>,
        /// With --recent: blocked queries only.
        #[arg(long)]
        blocked: bool,
        /// Machine-readable output.
        #[arg(long)]
        json: bool,
    },
    /// Pause blocking, for everything on the machine and in the browser
    /// (with the bridge set up).
    Pause {
        /// For how long: 30s, 5m, 1h30m. Default: until `sinkd resume`.
        #[arg(long = "for", value_parser = ctl::parse_duration)]
        duration: Option<Duration>,
    },
    /// Turn blocking back on.
    Resume,
    /// The local allowlist: names never blocked, whatever the lists say.
    Allow {
        #[command(subcommand)]
        action: ListAction,
    },
    /// The local blocklist.
    Block {
        #[command(subcommand)]
        action: ListAction,
    },
    /// Install the resolver as a system service and point the system's DNS
    /// at it. Needs sudo. `sinkd uninstall` undoes all of it.
    Install {
        /// Print every change without making it.
        #[arg(long)]
        dry_run: bool,
        /// Install and start the service, but leave the DNS settings alone.
        #[arg(long)]
        no_dns: bool,
    },
    /// Restore the DNS settings found at install, then remove the service
    /// and everything install created. Needs sudo.
    Uninstall {
        /// Print every change without making it.
        #[arg(long)]
        dry_run: bool,
        /// Also remove the config file.
        #[arg(long)]
        purge: bool,
    },
    /// Check the installation end to end and say what to fix.
    Doctor,
    /// The browser bridge: lets `allow`, `block` and `pause` reach the
    /// extension. Per user; no sudo.
    Bridge {
        #[command(subcommand)]
        action: BridgeAction,
    },
    /// The browser bridge's host, started by the browser (internal).
    #[command(hide = true)]
    NativeHost {
        /// What the browser passes (its origin, or Firefox's manifest path
        /// and add-on ID); not used.
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        _browser_args: Vec<String>,
    },
}

#[derive(Subcommand)]
enum ListAction {
    /// Add entries: `example.com` (and everything below it) or
    /// `*.example.com` (only names below it).
    Add {
        #[arg(required = true)]
        entries: Vec<String>,
    },
    /// Remove entries.
    Rm {
        #[arg(required = true)]
        entries: Vec<String>,
    },
    /// Show the entries.
    List,
}

#[derive(Subcommand)]
enum BridgeAction {
    /// Register the host with every installed browser.
    Install {
        /// The extension's ID in a Chromium browser (chrome://extensions);
        /// repeat for several. Firefox needs none.
        #[arg(long = "chrome-id")]
        chrome_ids: Vec<String>,
        /// Write the host manifest into this NativeMessagingHosts directory
        /// only (a test profile, say).
        #[arg(long)]
        dir: Option<PathBuf>,
        /// With --dir: write Firefox's kind of manifest.
        #[arg(long, requires = "dir")]
        firefox: bool,
        #[arg(long)]
        dry_run: bool,
    },
    /// Remove the host manifests and the launcher.
    Uninstall {
        #[arg(long)]
        dir: Option<PathBuf>,
        #[arg(long)]
        dry_run: bool,
    },
    /// Where the bridge is set up, and what it would send.
    Status,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    // The native host's stdout is the browser's channel, and the browser
    // shows its stderr nowhere useful: keep it quiet unless asked.
    let default_level = match cli.command {
        Command::NativeHost { .. } => "warn",
        _ => "info",
    };
    // Per-query detail is logged at debug level only, so it stays off unless
    // RUST_LOG asks for it.
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default_level));
    // Colour only on a terminal; a service manager's log file gets plain text.
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(io::stderr)
        .with_ansi(io::stderr().is_terminal())
        .init();
    let config = cli.config.unwrap_or_else(install::default_config);
    let result = match cli.command {
        Command::Run { user, inherited } => {
            daemon::run(&config, user.as_deref(), inherited.as_deref())
        }
        Command::Update { force } => update(&config, force),
        Command::Compile {
            rulesets,
            out,
            cache,
            offline,
        } => compile(&rulesets, &out, cache, offline),
        Command::Check {
            target,
            kind,
            from,
            rulesets,
            cache,
        } => check::check(
            &config,
            &check::CheckOptions {
                target: &target,
                kind: kind.as_deref(),
                from: from.as_deref(),
                rulesets: &rulesets,
                cache,
            },
        ),
        Command::Stats {
            top,
            recent,
            blocked,
            json,
        } => ctl::stats(
            &config,
            &ctl::StatsOptions {
                top,
                recent,
                blocked_only: blocked,
                json,
            },
        ),
        Command::Pause { duration } => ctl::pause(&config, duration),
        Command::Resume => ctl::resume(&config),
        Command::Allow { action } => list_action(&config, edit::Which::Allow, action),
        Command::Block { action } => list_action(&config, edit::Which::Block, action),
        Command::Install { dry_run, no_dns } => install::install(&install::Options {
            dry_run,
            no_dns,
            purge: false,
        }),
        Command::Uninstall { dry_run, purge } => install::uninstall(&install::Options {
            dry_run,
            no_dns: false,
            purge,
        }),
        Command::Doctor => doctor::doctor(&config),
        Command::Bridge { action } => match action {
            BridgeAction::Install {
                chrome_ids,
                dir,
                firefox,
                dry_run,
            } => bridge::install(
                &config,
                &bridge::InstallOptions {
                    chrome_ids: &chrome_ids,
                    dir: dir.as_deref(),
                    firefox_dir: firefox,
                    dry_run,
                },
            ),
            BridgeAction::Uninstall { dir, dry_run } => bridge::uninstall(dir.as_deref(), dry_run),
            BridgeAction::Status => bridge::status(&config),
        },
        Command::NativeHost { .. } => bridge::native_host(&config),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::FAILURE
        }
    }
}

fn list_action(config: &Path, which: edit::Which, action: ListAction) -> Result<()> {
    match action {
        ListAction::Add { entries } => edit::add(config, which, &entries),
        ListAction::Rm { entries } => edit::remove(config, which, &entries),
        ListAction::List => edit::show(config, which),
    }
}

pub(crate) fn load_config(path: &Path) -> Result<(Config, PathBuf, Cache)> {
    let text = std::fs::read_to_string(path).with_context(|| {
        format!(
            "reading {}{}",
            path.display(),
            if path == install::default_config() {
                " (sinkd is not installed; pass --config)"
            } else {
                ""
            }
        )
    })?;
    let config = Config::from_toml(&text).with_context(|| format!("in {}", path.display()))?;
    let base = path.parent().unwrap_or(Path::new(".")).to_path_buf();
    let dir = sinkd_lists::cache_dir(&config, &base).ok_or_else(|| {
        anyhow!("no home directory to keep downloaded lists in; set updates.cache_dir")
    })?;
    Ok((config, base, Cache::new(dir)))
}

#[tokio::main]
async fn update(config_path: &Path, force: bool) -> Result<()> {
    let (config, _, cache) = load_config(config_path)?;
    // The upstreams find the list servers, as in the daemon.
    let fetcher = Fetcher::builder()
        .resolver(Arc::new(upstreams(&config)?))
        .build()?;
    let lists: Vec<_> = config
        .lists
        .iter()
        .filter(|l| l.enabled)
        .filter_map(|l| Some((l.name.as_deref(), l.url.as_deref()?)))
        .collect();
    if lists.is_empty() {
        println!("No URL lists in {}.", config_path.display());
        return Ok(());
    }
    println!("Cache: {}", cache.dir().display());
    // Checked a few at a time, as the daemon does, and reported in config order.
    let checks = Arc::new(Semaphore::new(PARALLEL_CHECKS));
    let tasks: Vec<_> = lists
        .into_iter()
        .map(|(name, url)| {
            let (fetcher, cache, checks) = (fetcher.clone(), cache.clone(), Arc::clone(&checks));
            let (name, url) = (name.map(str::to_owned), url.to_owned());
            tokio::spawn(async move {
                let _permit = checks.acquire_owned().await;
                let reports = sinkd_lists::update(&fetcher, &cache, &url, &Env::dns(), force).await;
                (name.unwrap_or(url), reports)
            })
        })
        .collect();
    let mut failed = 0;
    for task in tasks {
        let (name, reports) = task.await?;
        for report in &reports {
            let label = if report.included {
                format!("  + {}", report.url)
            } else {
                name.clone()
            };
            println!("{label}: {}", describe(report));
            failed += usize::from(report.failed());
        }
    }
    // A running resolver sees the new files within seconds anyway.
    ctl::reload_if_running(config_path);
    if failed > 0 {
        return Err(anyhow!("{failed} list(s) could not be updated"));
    }
    Ok(())
}

/// The lists of a build manifest, read from `cache` (URL lists) or disk.
/// Returns the inputs and the names of URL lists with no cached copy.
pub(crate) fn list_inputs(
    manifest: &Manifest,
    base: &Path,
    cache: &Cache,
) -> Result<(Vec<ListInput>, Vec<String>)> {
    let env = Env::chromium_mv3();
    let mut inputs = Vec::new();
    let mut missing = Vec::new();
    for list in &manifest.lists {
        let ruleset = manifest
            .ruleset_of(&list.name)
            .map(|r| r.id.clone())
            .unwrap_or_default();
        let parts = match (&list.url, &list.path) {
            (Some(url), _) => {
                let parts = sinkd_lists::load_url(cache, url, &env)?;
                if parts.is_empty() {
                    missing.push(list.name.clone());
                }
                parts
            }
            (None, Some(path)) => sinkd_lists::load_path(&base.join(path), &env)?,
            (None, None) => continue,
        };
        for (i, part) in parts.into_iter().enumerate() {
            let name = if i == 0 {
                list.name.clone()
            } else {
                let file = part.origin.rsplit('/').next().unwrap_or(&part.origin);
                format!("{} + {file}", list.name)
            };
            inputs.push(ListInput {
                name,
                ruleset: ruleset.clone(),
                text: String::from_utf8_lossy(&part.body).into_owned(),
            });
        }
    }
    Ok((inputs, missing))
}

#[tokio::main]
async fn compile(rulesets: &Path, out: &Path, cache: Option<PathBuf>, offline: bool) -> Result<()> {
    let text = std::fs::read_to_string(rulesets)
        .with_context(|| format!("reading {}", rulesets.display()))?;
    let manifest =
        Manifest::from_toml(&text).with_context(|| format!("in {}", rulesets.display()))?;
    let base = rulesets.parent().unwrap_or(Path::new("."));
    let cache = Cache::new(match cache {
        Some(dir) => dir,
        None => sinkd_lists::default_cache_dir()
            .ok_or_else(|| anyhow!("no home directory for the list cache; pass --cache"))?,
    });
    let env = Env::chromium_mv3();
    // A build machine resolves list servers the ordinary way.
    if !offline {
        let fetcher = Fetcher::builder().build()?;
        for url in manifest.lists.iter().filter_map(|l| l.url.as_deref()) {
            for report in sinkd_lists::update(&fetcher, &cache, url, &env, false).await {
                if report.failed() {
                    eprintln!("{}: {}", report.url, describe(&report));
                }
            }
        }
    }
    let (inputs, missing) = list_inputs(&manifest, base, &cache)?;
    if let Some(name) = missing.first() {
        return Err(anyhow!(
            "{name}: no copy in {}{}",
            cache.dir().display(),
            if offline {
                "; run without --offline"
            } else {
                ""
            }
        ));
    }

    let started = Instant::now();
    let compiled = sinkd_compiler::compile(&inputs, manifest.params_ruleset.as_deref());
    let elapsed = started.elapsed();
    sinkd_compiler::output::write(&compiled, &manifest, out)
        .with_context(|| format!("writing {}", out.display()))?;

    let r = &compiled.report;
    println!(
        "Compiled {} lists in {} ms:",
        inputs.len(),
        elapsed.as_millis()
    );
    let mut total = 0;
    for rs in &r.rulesets {
        total += rs.rules;
        println!(
            "  {:<10} {:>6} DNR rules ({} regex) from {} filter rules",
            rs.id, rs.rules, rs.regex_rules, rs.source_rules
        );
    }
    println!(
        "  static rules: {total} of the {} Chrome guarantees",
        sinkd_compiler::validate::GUARANTEED_STATIC_RULES
    );
    let trackers: usize = manifest
        .rulesets
        .iter()
        .filter(|r| r.trackers)
        .filter_map(|r| compiled.hosts.get(&r.id))
        .map(|h| h.block.len())
        .sum();
    println!("  tracker hosts for cookie and Referer stripping: {trackers}");
    let chrome = &r.chrome;
    println!(
        "Chrome: {} rules translated ({} narrowed), {} not translatable:",
        chrome.translated, chrome.narrowed, chrome.rejected
    );
    let mut features: Vec<_> = chrome.by_feature.iter().collect();
    features.sort_by(|a, b| b.1.cmp(a.1));
    for (feature, count) in features.iter().take(12) {
        println!("  {count:>6}  {feature}");
    }
    let page = &compiled.page;
    let calls: usize = page.scriptlets.iter().map(|s| s.calls).sum();
    let index_bytes = page.index.to_bytes().len();
    println!(
        "Page: {} cosmetic and scriptlet rules taken, {} not; index {} KiB ({} selectors, {} sites, {} generic), {calls} scriptlet calls in {} files",
        r.page.translated,
        r.page.rejected,
        index_bytes / 1024,
        page.index.selectors.len(),
        page.index.hosts.len(),
        page.index.generic.values().map(Vec::len).sum::<usize>() + page.index.generic_always.len(),
        page.scriptlets.len(),
    );
    let mut features: Vec<_> = r.page.by_feature.iter().collect();
    features.sort_by(|a, b| b.1.cmp(a.1));
    for (feature, count) in features.iter().take(8) {
        println!("  {count:>6}  {feature}");
    }
    println!(
        "DNS: {} blocked names, {} allowed",
        compiled.dns.block.len(),
        compiled.dns.allow.len()
    );
    for warning in &r.warnings {
        println!("warning: {warning}");
    }
    println!("Wrote {} (full report: report.json)", out.display());
    Ok(())
}

/// One line about one refreshed file.
fn describe(report: &Report) -> String {
    let age = |meta: &sinkd_lists::Meta| ago(meta.age());
    match (&report.outcome, &report.cached) {
        (Outcome::Updated { rules, previous }, _) => match previous {
            Some(previous) => format!("updated, {rules} rules (was {previous})"),
            None => format!("downloaded, {rules} rules"),
        },
        (Outcome::NotModified, Some(meta)) => {
            format!("unchanged, {} rules (downloaded {})", meta.rules, age(meta))
        }
        (Outcome::NotModified, None) => "unchanged".to_owned(),
        (Outcome::Failed { reason }, Some(meta)) => format!(
            "FAILED: {reason}; keeping the copy downloaded {} ({} rules)",
            age(meta),
            meta.rules
        ),
        (Outcome::Failed { reason }, None) => {
            format!("FAILED: {reason}; no copy yet, so it is not in use")
        }
    }
}

pub(crate) fn ago(d: Duration) -> String {
    let s = d.as_secs();
    match s {
        0..60 => "just now".to_owned(),
        60..3600 => format!("{} min ago", s / 60),
        3600..86_400 => format!("{} h ago", s / 3600),
        _ => format!("{} days ago", s / 86_400),
    }
}

/// Adds the likely fix to the common bind failures.
pub(crate) fn bind_hint(e: io::Error, config: &Config) -> anyhow::Error {
    let low_port = config.listen.addrs.iter().any(|a| a.port() < 1024);
    let hint = match e.kind() {
        io::ErrorKind::PermissionDenied if low_port => {
            "\nhint: port 53 needs root (macOS: `sudo sinkd run --user nobody`) or \
             CAP_NET_BIND_SERVICE (Linux); `sudo sinkd install` sets either up. \
             For a trial run, listen on a high port such as 5300"
        }
        io::ErrorKind::AddrInUse => {
            "\nhint: another DNS server already listens there \
             (`sudo lsof -nP -i :53` shows which)"
        }
        _ => "",
    };
    anyhow::anyhow!("{e}{hint}")
}

/// Ctrl-C, or SIGTERM from a service manager. SIGHUP calls `on_hangup` and
/// keeps running.
pub(crate) async fn shutdown_signal(on_hangup: impl Fn()) -> io::Result<()> {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut term = signal(SignalKind::terminate())?;
        let mut hangup = signal(SignalKind::hangup())?;
        loop {
            tokio::select! {
                result = tokio::signal::ctrl_c() => return result,
                _ = term.recv() => return Ok(()),
                _ = hangup.recv() => on_hangup(),
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = on_hangup;
        tokio::signal::ctrl_c().await
    }
}
