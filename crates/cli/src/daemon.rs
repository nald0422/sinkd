//! `sinkhole run`: the daemon, with its control socket, metrics, watchdogs
//! and, on macOS, privilege separation.
//!
//! **Privilege separation (`--user`).** Port 53 on 127.0.0.1 needs root on
//! macOS, and a resolver that parses untrusted answers should not run as
//! root. So a root `sinkhole run --user _sinkhole` binds the sockets, then
//! starts a second `sinkhole run` as that user, handing the bound sockets
//! down (they are the only descriptors it leaves inheritable), and waits.
//! The root parent never reads a packet; it only passes signals on and
//! exits with the child's status. Rust's `Command::uid` drops the
//! supplementary groups as well as the uid, so the child keeps nothing of
//! root's. The child takes the sockets over by opening `/dev/fd/N`, which
//! duplicates them without `unsafe` code.
//!
//! On Linux the systemd unit grants `CAP_NET_BIND_SERVICE` to an
//! unprivileged dynamic user instead, so the daemon never runs as root and
//! `--user` is not needed.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use sinkhole_core::config::Config;
use sinkhole_lists::Fetcher;
use sinkhole_resolver::control::{Control, ControlSocket};
use sinkhole_resolver::service::{self, HangGuard};
use sinkhole_resolver::{Reloader, Server, Sockets, bind_sockets, from_config, metrics};
use tracing::{debug, info, warn};

use crate::{bind_hint, load_config, shutdown_signal};

/// The runtime must tick at least this often, or the process is aborted
/// and the service manager restarts it.
const HANG_LIMIT: Duration = Duration::from_secs(60);

pub fn run(config_path: &Path, user: Option<&str>, inherited: Option<&str>) -> Result<()> {
    // As root (the service's parent) a writable config is refused outright;
    // the child it starts has been through the same check.
    let problems = writable_by_others(config_path, user.is_some());
    if !problems.is_empty() {
        let message = format!(
            "{}: anyone who can edit the config can send every lookup to a server of their choosing",
            problems.join("; ")
        );
        if user.is_some() {
            bail!("{message}; fix the permissions (chmod go-w)");
        }
        warn!("{message}");
    }
    let (config, base, cache) = load_config(config_path)?;
    if let Some(user) = user {
        return privileged_parent(config_path, &config, user);
    }
    let sockets = match inherited {
        Some(spec) => adopt(spec)?,
        None => bind_sockets(&config.listen.addrs).map_err(|e| bind_hint(e, &config))?,
    };
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(serve(config_path, config, base, cache, sockets))
}

async fn serve(
    config_path: &Path,
    config: Config,
    base: PathBuf,
    cache: sinkhole_lists::Cache,
    sockets: Sockets,
) -> Result<()> {
    let started = Instant::now();
    let setup = from_config(&config, &base, &cache)?;
    let report = &setup.report;
    info!(
        block = report.block_entries,
        allow = report.allow_entries,
        not_for_dns = report.rejected_total(),
        elapsed_ms = started.elapsed().as_millis(),
        "lists loaded"
    );
    for (feature, count) in &report.rejected {
        let example = report.examples.get(feature).map_or("", String::as_str);
        debug!(feature, count, example, "lines not applicable to DNS");
    }
    for &index in &setup.missing {
        let list = &config.lists[index];
        let name = list.name.as_deref().or(list.url.as_deref()).unwrap_or("?");
        info!(
            list = name,
            "not downloaded yet; it applies once the download finishes"
        );
    }
    let files = setup.files.clone();
    let upstreams = setup.upstreams.describe();
    let server = Server::from_sockets(setup.policy(), sockets)?;
    let listen = server.local_addrs();
    info!(addrs = ?listen, ?upstreams, "listening");

    let guard = HangGuard::start(HANG_LIMIT)?;
    tokio::spawn(guard.run());

    // List servers are looked up through the upstreams in force, not the
    // system resolver: once sinkhole is the system resolver, that would be
    // asking itself.
    let policy = server.policy();
    let fetcher = Fetcher::builder()
        .resolver(Arc::new(policy.clone()))
        .build()?;
    let socket_path = sinkhole_resolver::control::socket_path(&config, &base);
    let metrics_listen = config.metrics.enabled.then_some(config.metrics.listen);
    let reloader = Reloader::new(
        config_path.to_path_buf(),
        config,
        files,
        policy.clone(),
        fetcher,
        cache,
    );
    let reload = reloader.handle();
    let stats = server.stats();
    let pause = server.pause();

    // The control socket is removed when this binding is dropped, at exit.
    let _control = match socket_path {
        None => {
            warn!("no control socket: set control.socket or updates.cache_dir");
            None
        }
        Some(path) => match ControlSocket::bind(&path) {
            Ok(socket) => {
                info!(path = %socket.path().display(), "control socket");
                let control = Control {
                    policy: policy.clone(),
                    stats: Arc::clone(&stats),
                    pause: Arc::clone(&pause),
                    reload: reload.clone(),
                    listen,
                    started,
                };
                let path = socket.path().to_path_buf();
                tokio::spawn(socket.run(control));
                Some(Cleanup(path))
            }
            Err(e) => {
                warn!(path = %path.display(), error = %e, "no control socket; stats and pause will not work");
                None
            }
        },
    };
    if let Some(addr) = metrics_listen {
        match tokio::net::TcpListener::bind(addr).await {
            Ok(listener) => {
                info!(%addr, "metrics at /metrics");
                tokio::spawn(metrics::serve(
                    listener,
                    metrics::Source {
                        policy: policy.clone(),
                        stats: Arc::clone(&stats),
                        pause,
                        started,
                    },
                ));
            }
            Err(e) => warn!(%addr, error = %e, "metrics not served"),
        }
    }
    if let Err(e) = service::notify("READY=1") {
        warn!(error = %e, "could not tell systemd the daemon is ready");
    }
    if let Some(interval) = service::watchdog_interval() {
        tokio::spawn(service::systemd_watchdog(policy, interval));
    }
    tokio::spawn(reloader.run());
    tokio::select! {
        result = server.run() => result?,
        result = shutdown_signal(move || reload.reload()) => result?,
    }
    let _ = service::notify("STOPPING=1");
    info!(stats = ?stats.snapshot(), "stopped");
    Ok(())
}

/// Who besides its owner can change the config: the file, or its
/// directory (where it could be replaced). A sticky directory (`/tmp`)
/// does not let others replace a file they don't own. With `strict`, write
/// access for the group counts too.
pub fn writable_by_others(config: &Path, strict: bool) -> Vec<String> {
    use std::os::unix::fs::PermissionsExt;
    let mask = if strict { 0o022 } else { 0o002 };
    let mut problems = Vec::new();
    let dir = config
        .parent()
        .filter(|d| !d.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    for (path, is_dir) in [(config, false), (dir, true)] {
        let Ok(meta) = std::fs::metadata(path) else {
            continue;
        };
        let mode = meta.permissions().mode();
        let sticky = is_dir && mode & 0o1000 != 0;
        if mode & mask != 0 && !sticky {
            problems.push(format!(
                "{} is writable by {} (mode {:o})",
                path.display(),
                if mode & 0o002 != 0 {
                    "every user"
                } else {
                    "its group"
                },
                mode & 0o7777
            ));
        }
    }
    problems
}

/// Removes the control socket file at exit, after the socket task is gone.
struct Cleanup(PathBuf);

impl Drop for Cleanup {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// The output of `id` with `args`, trimmed.
fn id(args: &[&str]) -> Result<String> {
    let out = std::process::Command::new("/usr/bin/id")
        .args(args)
        .output()
        .context("running /usr/bin/id")?;
    if !out.status.success() {
        bail!(
            "id {}: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_owned())
}

pub fn is_root() -> bool {
    id(&["-u"]).is_ok_and(|uid| uid == "0")
}

/// Binds as root, then serves as `user` in a child process.
fn privileged_parent(config_path: &Path, config: &Config, user: &str) -> Result<()> {
    if !cfg!(target_os = "macos") {
        bail!(
            "--user is for macOS; on Linux, run sinkhole from the systemd unit `sinkhole install` writes, \
             which binds port 53 without root"
        );
    }
    if !is_root() {
        bail!("--user needs root: it binds the sockets, then drops to {user}");
    }
    let uid: u32 = id(&["-u", user])?
        .parse()
        .with_context(|| format!("uid of {user}"))?;
    let gid: u32 = id(&["-g", user])?
        .parse()
        .with_context(|| format!("gid of {user}"))?;
    if uid == 0 {
        bail!("--user {user} is root; name an unprivileged user");
    }
    let sockets = bind_sockets(&config.listen.addrs).map_err(|e| bind_hint(e, config))?;
    let spec = inheritable(&sockets)?;
    let exe = std::env::current_exe().context("finding the sinkhole binary")?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let code = runtime.block_on(async {
        let mut command = tokio::process::Command::new(&exe);
        command
            .arg("run")
            .arg("--config")
            .arg(config_path)
            .arg("--inherited")
            .arg(&spec)
            .uid(uid)
            .gid(gid)
            .env_clear()
            .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin");
        if let Ok(filter) = std::env::var("RUST_LOG") {
            command.env("RUST_LOG", filter);
        }
        let mut child = command
            .spawn()
            .context("starting the unprivileged daemon")?;
        // The child has its own copies now.
        drop(sockets);
        let pid = child
            .id()
            .ok_or_else(|| anyhow!("the daemon exited at once"))?;
        info!(user, uid, pid, "serving as an unprivileged user");
        forward_signals(&mut child, pid).await
    })?;
    std::process::exit(code);
}

/// Passes SIGTERM, SIGINT and SIGHUP on to the child until it exits, and
/// returns its exit code.
async fn forward_signals(child: &mut tokio::process::Child, pid: u32) -> Result<i32> {
    use tokio::signal::unix::{SignalKind, signal};
    let mut term = signal(SignalKind::terminate())?;
    let mut int = signal(SignalKind::interrupt())?;
    let mut hup = signal(SignalKind::hangup())?;
    let send = |name: &str| {
        let _ = std::process::Command::new("/bin/kill")
            .args([&format!("-{name}"), &pid.to_string()])
            .status();
    };
    loop {
        tokio::select! {
            status = child.wait() => {
                let status = status?;
                return Ok(status.code().unwrap_or(1));
            }
            _ = term.recv() => send("TERM"),
            _ = int.recv() => send("INT"),
            _ = hup.recv() => send("HUP"),
        }
    }
}

/// Marks the sockets inheritable and describes them for `--inherited`:
/// `udp=5,tcp=6,…`.
fn inheritable(sockets: &Sockets) -> Result<String> {
    use std::os::fd::{AsFd, AsRawFd};
    let mut parts = Vec::new();
    let mut mark = |kind: &str, fd: std::os::fd::BorrowedFd<'_>| -> Result<()> {
        socket2::SockRef::from(&fd).set_cloexec(false)?;
        parts.push(format!("{kind}={}", fd.as_raw_fd()));
        Ok(())
    };
    for s in &sockets.udp {
        mark("udp", s.as_fd())?;
    }
    for s in &sockets.tcp {
        mark("tcp", s.as_fd())?;
    }
    Ok(parts.join(","))
}

/// Takes over sockets bound by a privileged parent (see the module docs).
fn adopt(spec: &str) -> Result<Sockets> {
    let mut sockets = Sockets::default();
    for part in spec.split(',').filter(|p| !p.is_empty()) {
        let (kind, fd) = part
            .split_once('=')
            .ok_or_else(|| anyhow!("--inherited: {part:?} is not kind=fd"))?;
        let fd: u32 = fd
            .parse()
            .with_context(|| format!("--inherited: {part:?}"))?;
        // Opening /dev/fd/N duplicates descriptor N (macOS).
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(format!("/dev/fd/{fd}"))
            .with_context(|| format!("taking over inherited socket {fd}"))?;
        let socket = socket2::Socket::from(std::os::fd::OwnedFd::from(file));
        let expected = match kind {
            "udp" => socket2::Type::DGRAM,
            "tcp" => socket2::Type::STREAM,
            _ => bail!("--inherited: unknown socket kind {kind:?}"),
        };
        if socket.r#type()? != expected {
            bail!("--inherited: descriptor {fd} is not a {kind} socket");
        }
        socket.set_cloexec(true)?;
        match kind {
            "udp" => sockets.udp.push(socket.into()),
            _ => sockets.tcp.push(socket.into()),
        }
    }
    if sockets.udp.is_empty() {
        bail!("--inherited: no UDP socket");
    }
    Ok(sockets)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "macos")]
    #[test]
    fn sockets_survive_the_handover() {
        let sockets = bind_sockets(&["127.0.0.1:0".parse().unwrap()]).unwrap();
        let addr = sockets.udp[0].local_addr().unwrap();
        let spec = inheritable(&sockets).unwrap();
        let adopted = adopt(&spec).unwrap();
        assert_eq!(adopted.udp[0].local_addr().unwrap(), addr);
        assert_eq!(adopted.tcp[0].local_addr().unwrap().port(), addr.port());
    }

    #[test]
    fn writable_configs_are_found() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("sinkhole-perm-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        let config = dir.join("s.toml");
        std::fs::write(&config, "").unwrap();
        let set = |mode| {
            std::fs::set_permissions(&config, std::fs::Permissions::from_mode(mode)).unwrap()
        };
        set(0o644);
        assert!(writable_by_others(&config, true).is_empty());
        set(0o664);
        assert!(writable_by_others(&config, false).is_empty());
        assert_eq!(writable_by_others(&config, true).len(), 1);
        set(0o666);
        assert_eq!(writable_by_others(&config, false).len(), 1);
        set(0o644);
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o1777)).unwrap();
        assert!(writable_by_others(&config, true).is_empty(), "sticky");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert_eq!(writable_by_others(&config, false).len(), 1);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn bad_specs() {
        assert!(adopt("").is_err());
        assert!(adopt("udp").is_err());
        assert!(adopt("udp=x").is_err());
        assert!(adopt("sctp=0").is_err());
        // Standard input is not a socket.
        assert!(adopt("udp=0").is_err());
    }
}
