//! The control socket: how `sinkhole stats`, `pause`, `resume` and the
//! browser bridge talk to a running daemon.
//!
//! A Unix stream socket, one JSON request line in, one JSON response line
//! out, then the daemon closes the connection. The socket is mode 0666, so
//! any local user may ask for the counters ([`Request::Status`]). Every
//! other request changes what the daemon does or reads the query log,
//! which shows what everyone on the machine looked up. Those are answered
//! only for root, the user the daemon runs as and the users listed in
//! `control.users`; the daemon learns who is asking from the kernel
//! (`SO_PEERCRED` / `getpeereid`), not from anything the client says.
//!
//! A local socket rather than a TCP port: a web page can reach a port on
//! localhost, and nothing on another machine can reach a Unix socket.

use std::io;
use std::net::SocketAddr;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Semaphore;
use tokio::time::timeout;
use tracing::{debug, info, warn};

use crate::pause::{Pause, Paused};
use crate::querylog::{Entry, Top};
use crate::reload::ReloadHandle;
use crate::server::{PolicyHandle, Stats, StatsSnapshot};
use crate::upstream::UpstreamStatus;

/// The longest request line read. Requests are a few dozen bytes.
const MAX_REQUEST: u64 = 4096;
/// The longest response read by [`ask`]: a full query log fits.
const MAX_RESPONSE: u64 = 64 << 20;
/// Time allowed for a whole exchange, either side.
const EXCHANGE: Duration = Duration::from_secs(5);
/// Connections served at once.
const MAX_CLIENTS: usize = 16;
/// Longest Unix socket path (`sun_path`, 104 bytes on macOS, with the NUL).
const MAX_PATH: usize = 103;

/// What a client asks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case", deny_unknown_fields)]
pub enum Request {
    /// Counters, rule counts, upstream health, the pause. Anyone may ask.
    Status,
    /// Pause blocking for `secs`, or until resumed.
    Pause {
        #[serde(default)]
        secs: Option<u64>,
    },
    Resume,
    /// Re-read the config and the lists now.
    Reload,
    /// Check every URL list for a new version now.
    Refresh,
    /// The newest query log entries.
    Log {
        limit: usize,
        #[serde(default)]
        blocked_only: bool,
    },
    /// The most frequent names in the query log.
    Top {
        limit: usize,
    },
}

impl Request {
    /// Whether only the allowed users may make this request.
    pub fn privileged(&self) -> bool {
        !matches!(self, Request::Status)
    }
}

/// What the daemon answers.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Response {
    Status(Box<Status>),
    /// A pause, resume, reload or refresh was done. `paused` is the pause
    /// in force afterwards.
    Done {
        paused: Option<Paused>,
    },
    Log {
        entries: Vec<Entry>,
    },
    Top(Top),
    Error {
        message: String,
    },
}

/// [`Request::Status`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Status {
    pub version: String,
    pub pid: u32,
    pub uptime_secs: u64,
    pub listen: Vec<SocketAddr>,
    pub paused: Option<Paused>,
    pub stats: StatsSnapshot,
    pub block_entries: usize,
    pub allow_entries: usize,
    pub cache_entries: u64,
    pub upstreams: Vec<UpstreamStatus>,
    pub query_log: bool,
    /// A name the lists block, for `sinkhole doctor` to look up through
    /// the system's resolver.
    pub sample_blocked: Option<String>,
}

/// Where the daemon of `config` puts its control socket: `control.socket`
/// (relative to `base`, the config file's directory), else `control.sock`
/// in the cache directory. `None` when neither can be worked out.
pub fn socket_path(config: &sinkhole_core::config::Config, base: &Path) -> Option<PathBuf> {
    match &config.control.socket {
        Some(path) => Some(base.join(path)),
        None => sinkhole_lists::cache_dir(config, base).map(|dir| dir.join("control.sock")),
    }
}

/// What the control socket needs from the daemon.
#[derive(Clone)]
pub struct Control {
    pub policy: PolicyHandle,
    pub stats: Arc<Stats>,
    pub pause: Arc<Pause>,
    pub reload: ReloadHandle,
    pub listen: Vec<SocketAddr>,
    pub started: Instant,
}

/// A bound control socket. Removes its file when dropped.
pub struct ControlSocket {
    listener: UnixListener,
    path: PathBuf,
    /// The daemon's own user, from the socket file it just created.
    own_uid: u32,
}

impl ControlSocket {
    /// Binds `path`. A socket file left behind by a daemon that died is
    /// replaced; one that a running daemon still answers on is an error.
    /// Anything at `path` that is not a socket is left alone.
    pub fn bind(path: &Path) -> io::Result<ControlSocket> {
        if path.as_os_str().len() > MAX_PATH {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "control socket path {} is longer than {MAX_PATH} bytes; set control.socket to a shorter one",
                    path.display()
                ),
            ));
        }
        if let Ok(meta) = std::fs::symlink_metadata(path) {
            if !meta.file_type().is_socket() {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    format!("{} exists and is not a socket", path.display()),
                ));
            }
            if std::os::unix::net::UnixStream::connect(path).is_ok() {
                return Err(io::Error::new(
                    io::ErrorKind::AddrInUse,
                    format!("another sinkhole answers on {}", path.display()),
                ));
            }
            std::fs::remove_file(path)?;
        }
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let listener = UnixListener::bind(path)?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o666))?;
        let own_uid = std::fs::metadata(path)?.uid();
        Ok(ControlSocket {
            listener,
            path: path.to_path_buf(),
            own_uid,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Serves until dropped.
    pub async fn run(self, control: Control) {
        let limit = Arc::new(Semaphore::new(MAX_CLIENTS));
        let control = Arc::new(control);
        loop {
            let stream = match self.listener.accept().await {
                Ok((stream, _)) => stream,
                Err(e) => {
                    warn!(error = %e, "control socket accept failed");
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                }
            };
            let Ok(permit) = Arc::clone(&limit).try_acquire_owned() else {
                continue;
            };
            let (control, own_uid) = (Arc::clone(&control), self.own_uid);
            tokio::spawn(async move {
                if timeout(EXCHANGE, serve(stream, &control, own_uid))
                    .await
                    .is_err()
                {
                    debug!("control client too slow; closed");
                }
                drop(permit);
            });
        }
    }
}

impl Drop for ControlSocket {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

async fn serve(stream: UnixStream, control: &Control, own_uid: u32) {
    let uid = match stream.peer_cred() {
        Ok(cred) => cred.uid(),
        Err(e) => {
            debug!(error = %e, "no peer credentials; closed");
            return;
        }
    };
    let (read, mut write) = stream.into_split();
    let mut line = String::new();
    let mut reader = BufReader::new(read.take(MAX_REQUEST));
    if reader.read_line(&mut line).await.is_err() {
        return;
    }
    let response = match serde_json::from_str::<Request>(line.trim()) {
        Err(e) => Response::Error {
            message: format!("bad request: {e}"),
        },
        Ok(request) => {
            let allowed =
                uid == 0 || uid == own_uid || control.policy.load().control_users.contains(&uid);
            if request.privileged() && !allowed {
                Response::Error {
                    message: format!(
                        "user {uid} may not do that; run it with sudo, or add the user's id to control.users in the config"
                    ),
                }
            } else {
                answer(control, request, uid)
            }
        }
    };
    let mut out = serde_json::to_vec(&response).unwrap_or_default();
    out.push(b'\n');
    let _ = write.write_all(&out).await;
    let _ = write.shutdown().await;
}

fn answer(control: &Control, request: Request, uid: u32) -> Response {
    let policy = control.policy.load();
    let done = || Response::Done {
        paused: control.pause.state(),
    };
    match request {
        Request::Status => {
            let matcher = policy.engine.matcher();
            Response::Status(Box::new(Status {
                version: env!("CARGO_PKG_VERSION").to_owned(),
                pid: std::process::id(),
                uptime_secs: control.started.elapsed().as_secs(),
                listen: control.listen.clone(),
                paused: control.pause.state(),
                stats: control.stats.snapshot(),
                block_entries: matcher.blocklist().len(),
                allow_entries: matcher.allowlist().len(),
                cache_entries: policy.cache.len(),
                upstreams: policy.upstreams.status(),
                query_log: policy.log.enabled(),
                sample_blocked: sample_blocked(&policy.engine),
            }))
        }
        Request::Pause { secs } => {
            let paused = control.pause.pause(secs.map(Duration::from_secs));
            match secs {
                Some(secs) => info!(uid, secs, "blocking paused"),
                None => info!(uid, "blocking paused until resumed"),
            }
            Response::Done {
                paused: Some(paused),
            }
        }
        Request::Resume => {
            control.pause.resume();
            info!(uid, "blocking resumed");
            done()
        }
        Request::Reload => {
            control.reload.reload();
            done()
        }
        Request::Refresh => {
            control.reload.refresh();
            done()
        }
        Request::Log {
            limit,
            blocked_only,
        } => Response::Log {
            entries: policy.log.recent(limit, blocked_only),
        },
        Request::Top { limit } => Response::Top(policy.log.top(limit)),
    }
}

/// A blocked name to test with: the first exact entry that the allowlist
/// does not override. Deterministic for a given set of lists.
fn sample_blocked(engine: &crate::Engine) -> Option<String> {
    let matcher = engine.matcher();
    matcher
        .blocklist()
        .iter()
        .filter(|(name, scope)| *scope != sinkhole_core::Scope::Subdomains && name.contains('.'))
        .map(|(name, _)| name)
        .find(|name| matcher.check(name).is_blocked())
        .map(str::to_owned)
}

/// Sends `request` to the daemon listening on `path` and reads its answer.
pub async fn ask(path: &Path, request: &Request) -> io::Result<Response> {
    timeout(EXCHANGE, exchange(path, request))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "the daemon did not answer"))?
}

async fn exchange(path: &Path, request: &Request) -> io::Result<Response> {
    let mut stream = UnixStream::connect(path).await?;
    let mut line = serde_json::to_vec(request)?;
    line.push(b'\n');
    stream.write_all(&line).await?;
    stream.shutdown().await?;
    let mut buf = Vec::new();
    stream.take(MAX_RESPONSE).read_to_end(&mut buf).await?;
    serde_json::from_slice(&buf).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_parse_strictly() {
        let parse = |s: &str| serde_json::from_str::<Request>(s);
        assert_eq!(parse(r#"{"cmd":"status"}"#).unwrap(), Request::Status);
        assert_eq!(
            parse(r#"{"cmd":"pause","secs":300}"#).unwrap(),
            Request::Pause { secs: Some(300) }
        );
        assert_eq!(
            parse(r#"{"cmd":"pause"}"#).unwrap(),
            Request::Pause { secs: None }
        );
        assert!(parse(r#"{"cmd":"pause","secs":300,"as":"root"}"#).is_err());
        assert!(parse(r#"{"cmd":"shutdown"}"#).is_err());
        assert!(!Request::Status.privileged());
        assert!(Request::Resume.privileged());
        assert!(Request::Top { limit: 1 }.privileged());
    }
}
