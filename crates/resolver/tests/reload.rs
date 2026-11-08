//! Hot reload: a running server picks up edited files, refreshed URL lists
//! and config changes, and keeps its rules when any of them goes wrong.
#![allow(clippy::unwrap_used)]

use std::future::Future;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use hickory_proto::op::{Message, Query};
use hickory_proto::rr::{Name, RData, RecordType};
use sinkhole_core::config::Config;
use sinkhole_filters::Env;
use sinkhole_lists::testing::{Response, TestServer};
use sinkhole_lists::{Cache, Fetcher};
use sinkhole_resolver::{ReloadHandle, Reloader, Server, from_config};
use tokio::net::UdpSocket;
use tokio::task::JoinHandle;

const POLL: Duration = Duration::from_millis(50);
/// Long enough for many polls and a rebuild; the waits below return as soon
/// as the condition holds, so this only bounds a failing test.
const PATIENCE: Duration = Duration::from_secs(10);

/// Upstream on a port nothing listens on: forwarded names fail fast with
/// SERVFAIL, which is all these tests need to tell "not blocked".
const CONFIG_TAIL: &str = r#"
[listen]
addrs = ["127.0.0.1:0"]

[[upstream]]
protocol = "udp"
addr = "127.0.0.1:1"
"#;

/// A scratch directory removed on drop.
struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Scratch {
        let dir = std::env::temp_dir().join(format!(
            "sinkhole-reload-{name}-{}-{:?}",
            std::process::id(),
            Instant::now()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        Scratch(dir)
    }

    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }

    fn write(&self, name: &str, text: &str) {
        std::fs::write(self.path(name), text).unwrap();
    }

    /// Saves the way many editors do: write a temporary file, rename it over.
    fn replace(&self, name: &str, text: &str) {
        let tmp = self.path(&format!("{name}.swp"));
        std::fs::write(&tmp, text).unwrap();
        std::fs::rename(tmp, self.path(name)).unwrap();
    }

    fn cache(&self) -> Cache {
        Cache::new(self.path("cache"))
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct Daemon {
    addr: SocketAddr,
    reload: ReloadHandle,
    tasks: Vec<JoinHandle<()>>,
}

impl Drop for Daemon {
    fn drop(&mut self) {
        self.tasks.iter().for_each(JoinHandle::abort);
    }
}

async fn start(dir: &Scratch, fetcher: Fetcher) -> Daemon {
    let config_path = dir.path("sinkhole.toml");
    let config = Config::from_toml(&std::fs::read_to_string(&config_path).unwrap()).unwrap();
    let cache = dir.cache();
    let setup = from_config(&config, &dir.0, &cache).unwrap();
    let files = setup.files.clone();
    let server = Server::bind(setup.policy(), &config.listen.addrs)
        .await
        .unwrap();
    let addr = server.local_addrs()[0];
    let reloader = Reloader::new(config_path, config, files, server.policy(), fetcher, cache)
        .with_poll_interval(POLL);
    let reload = reloader.handle();
    let tasks = vec![
        tokio::spawn(async move {
            let _ = server.run().await;
        }),
        tokio::spawn(reloader.run()),
    ];
    Daemon {
        addr,
        reload,
        tasks,
    }
}

/// A fetcher for tests that never touch a list server.
fn no_fetcher() -> Fetcher {
    Fetcher::builder().build().unwrap()
}

async fn blocked(daemon: &Daemon, name: &str) -> bool {
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    socket.connect(daemon.addr).await.unwrap();
    let mut query = Message::query();
    query.metadata.recursion_desired = true;
    query.add_query(Query::query(
        Name::from_ascii(format!("{name}.")).unwrap(),
        RecordType::A,
    ));
    socket.send(&query.to_vec().unwrap()).await.unwrap();
    let mut buf = vec![0; 4096];
    let len = tokio::time::timeout(Duration::from_secs(5), socket.recv(&mut buf))
        .await
        .unwrap()
        .unwrap();
    let reply = Message::from_vec(&buf[..len]).unwrap();
    reply
        .answers
        .iter()
        .any(|r| matches!(&r.data, RData::A(a) if a.0 == Ipv4Addr::UNSPECIFIED))
}

/// Waits until `condition` holds, failing the test after [`PATIENCE`].
async fn eventually<F, Fut>(what: &str, mut condition: F)
where
    F: FnMut() -> Fut,
    Fut: Future<Output = bool>,
{
    let deadline = Instant::now() + PATIENCE;
    while !condition().await {
        assert!(Instant::now() < deadline, "timed out waiting for: {what}");
        tokio::time::sleep(POLL / 2).await;
    }
}

/// Lets several polls pass, for checking that something did *not* change.
async fn settle() {
    tokio::time::sleep(POLL * 8).await;
}

fn local_list_config(dir: &Scratch, block: &str) {
    dir.write(
        "sinkhole.toml",
        &format!("block = [{block}]\n{CONFIG_TAIL}\n[[list]]\npath = \"list.txt\"\n"),
    );
}

#[tokio::test]
async fn local_list_edits_apply_without_a_restart() {
    let dir = Scratch::new("local");
    local_list_config(&dir, "");
    dir.write("list.txt", "ads.example\n");
    let daemon = start(&dir, no_fetcher()).await;
    assert!(blocked(&daemon, "ads.example").await);
    assert!(!blocked(&daemon, "new.example").await);

    dir.write("list.txt", "ads.example\nnew.example\n");
    eventually("an appended entry blocks", || {
        blocked(&daemon, "new.example")
    })
    .await;

    // An editor-style save (rename over the file) is seen too.
    dir.replace("list.txt", "new.example\n");
    eventually("a removed entry unblocks", || async {
        !blocked(&daemon, "ads.example").await
    })
    .await;
    assert!(blocked(&daemon, "new.example").await);
}

#[tokio::test]
async fn a_list_deleted_mid_edit_keeps_the_rules_in_force() {
    let dir = Scratch::new("deleted");
    local_list_config(&dir, "");
    dir.write("list.txt", "ads.example\n");
    let daemon = start(&dir, no_fetcher()).await;
    assert!(blocked(&daemon, "ads.example").await);

    std::fs::remove_file(dir.path("list.txt")).unwrap();
    settle().await;
    assert!(
        blocked(&daemon, "ads.example").await,
        "last known-good rules stay"
    );

    dir.write("list.txt", "ads.example\nback.example\n");
    eventually("the restored list loads", || {
        blocked(&daemon, "back.example")
    })
    .await;
}

#[tokio::test]
async fn config_edits_apply_and_broken_ones_are_ignored() {
    let dir = Scratch::new("config");
    local_list_config(&dir, "\"a.example\"");
    dir.write("list.txt", "listed.example\n");
    let daemon = start(&dir, no_fetcher()).await;
    assert!(blocked(&daemon, "a.example").await);

    local_list_config(&dir, "\"b.example\"");
    eventually("the new block entry applies", || {
        blocked(&daemon, "b.example")
    })
    .await;
    assert!(!blocked(&daemon, "a.example").await);

    // Broken in three ways: syntax, validation, and a build error (a list
    // file that does not exist). Each is rejected and the config in force
    // stays.
    for broken in [
        "block = [\"c.example\"\n".to_owned(),
        format!("block = [\"c.example\", \"not a name\"]\n{CONFIG_TAIL}"),
        format!("block = [\"c.example\"]\n{CONFIG_TAIL}\n[[list]]\npath = \"missing.txt\"\n"),
    ] {
        dir.write("sinkhole.toml", &broken);
        settle().await;
        assert!(blocked(&daemon, "b.example").await, "kept after: {broken}");
        assert!(blocked(&daemon, "listed.example").await);
        assert!(!blocked(&daemon, "c.example").await);
    }

    // Fixing the file applies it.
    local_list_config(&dir, "\"d.example\"");
    eventually("a fixed config applies", || blocked(&daemon, "d.example")).await;
    assert!(!blocked(&daemon, "b.example").await);
}

#[tokio::test]
async fn reload_request_rereads_files() {
    let dir = Scratch::new("request");
    local_list_config(&dir, "");
    dir.write("list.txt", "ads.example\n");
    let daemon = start(&dir, no_fetcher()).await;
    daemon.reload.reload();
    settle().await;
    assert!(blocked(&daemon, "ads.example").await);
}

fn url_list_config(dir: &Scratch, server: &TestServer) {
    dir.write(
        "sinkhole.toml",
        &format!(
            "{CONFIG_TAIL}\n[[list]]\nname = \"remote\"\nurl = \"{}\"\n",
            server.url("/list.txt")
        ),
    );
}

#[tokio::test]
async fn url_lists_download_refresh_and_survive_failures() {
    let server = TestServer::start().await;
    server.set("/list.txt", Response::list("||remote.example^\n"));
    let dir = Scratch::new("remote");
    url_list_config(&dir, &server);

    // No cached copy: the daemon starts at once and blocks the list as soon
    // as the first download lands.
    let daemon = start(&dir, server.fetcher()).await;
    eventually("the first download applies", || {
        blocked(&daemon, "remote.example")
    })
    .await;

    server.set(
        "/list.txt",
        Response::list("||remote.example^\n||second.example^\n"),
    );
    daemon.reload.refresh();
    eventually("a refreshed list applies", || {
        blocked(&daemon, "second.example")
    })
    .await;

    // Failures and junk leave the last good copy in force.
    for response in [
        Response::status(503),
        Response::plain("<html><body>Sign in to the Wi-Fi</body></html>"),
        Response::plain("! emptied by mistake\n"),
    ] {
        let checks = server.requests().len();
        server.set("/list.txt", response);
        daemon.reload.refresh();
        eventually("the check happens", || async {
            server.requests().len() > checks
        })
        .await;
        settle().await;
        assert!(blocked(&daemon, "remote.example").await);
        assert!(blocked(&daemon, "second.example").await);
    }
    // The 304 path: the second request of a pair carried the ETag.
    assert!(
        server
            .requests()
            .iter()
            .any(|r| r.header("if-none-match").is_some())
    );
}

#[tokio::test]
async fn a_restart_uses_the_cached_copy_while_the_server_is_down() {
    let server = TestServer::start().await;
    server.set("/list.txt", Response::list("||remote.example^\n"));
    let dir = Scratch::new("restart");
    url_list_config(&dir, &server);
    {
        let daemon = start(&dir, server.fetcher()).await;
        eventually("the first download applies", || {
            blocked(&daemon, "remote.example")
        })
        .await;
    }

    server.set("/list.txt", Response::status(500));
    let daemon = start(&dir, server.fetcher()).await;
    // Blocked on the very first query: loaded from the cache at startup,
    // before any check could have run.
    assert!(blocked(&daemon, "remote.example").await);
    settle().await;
    assert!(blocked(&daemon, "remote.example").await);
}

#[tokio::test]
async fn an_update_run_beside_the_daemon_takes_effect() {
    let server = TestServer::start().await;
    server.set("/list.txt", Response::list("||remote.example^\n"));
    let dir = Scratch::new("beside");
    url_list_config(&dir, &server);
    let daemon = start(&dir, server.fetcher()).await;
    eventually("the first download applies", || {
        blocked(&daemon, "remote.example")
    })
    .await;

    // What `sinkhole update` does: refresh into the same cache from another
    // process. The daemon's own schedule is a day away.
    server.set(
        "/list.txt",
        Response::list("||remote.example^\n||cli.example^\n"),
    );
    let reports = sinkhole_lists::update(
        &server.fetcher(),
        &dir.cache(),
        &server.url("/list.txt"),
        &Env::dns(),
        false,
    )
    .await;
    assert!(reports[0].updated(), "{reports:?}");
    eventually("the daemon sees the new cache file", || {
        blocked(&daemon, "cli.example")
    })
    .await;
}

#[tokio::test]
async fn swapping_policies_does_not_drop_queries() {
    let dir = Scratch::new("no-drops");
    local_list_config(&dir, "");
    dir.write("list.txt", "ads.example\n");
    let daemon = start(&dir, no_fetcher()).await;

    let started = Instant::now();
    let mut rewrites = 0;
    let mut queries = 0;
    while started.elapsed() < Duration::from_secs(2) {
        // Every reply arrives, and the always-listed name is always blocked.
        assert!(blocked(&daemon, "ads.example").await);
        queries += 1;
        if queries % 20 == 0 {
            rewrites += 1;
            dir.write("list.txt", &format!("ads.example\nx{rewrites}.example\n"));
        }
    }
    assert!(
        rewrites >= 5,
        "only {rewrites} rewrites in {queries} queries"
    );
    let last = format!("x{rewrites}.example");
    eventually("the last rewrite applies", || blocked(&daemon, &last)).await;
}
