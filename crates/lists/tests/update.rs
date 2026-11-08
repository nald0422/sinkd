//! Refreshing lists against a local HTTPS server with a throwaway CA.
#![allow(clippy::unwrap_used)]

use std::ops::Deref;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use sinkhole_filters::Env;
use sinkhole_lists::testing::{Response, StaticResolver, TestServer};
use sinkhole_lists::{Cache, Fetcher, Outcome, Report, load_url, update};

/// A cache in a scratch directory, removed on drop.
struct TempCache(Cache);

impl Deref for TempCache {
    type Target = Cache;

    fn deref(&self) -> &Cache {
        &self.0
    }
}

impl Drop for TempCache {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(self.0.dir());
    }
}

fn temp_cache(name: &str) -> TempCache {
    let dir: PathBuf = std::env::temp_dir().join(format!(
        "sinkhole-lists-{name}-{}-{:?}",
        std::process::id(),
        Instant::now()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    TempCache(Cache::new(dir))
}

async fn refresh(fetcher: &Fetcher, cache: &Cache, url: &str) -> Report {
    let mut reports = update(fetcher, cache, url, &Env::dns(), false).await;
    assert_eq!(reports.len(), 1, "{reports:?}");
    reports.remove(0)
}

fn reason(report: &Report) -> &str {
    match &report.outcome {
        Outcome::Failed { reason } => reason,
        other => panic!("expected a failure, got {other:?}"),
    }
}

fn rules(n: usize) -> String {
    (0..n).map(|i| format!("||ads{i}.example^\n")).collect()
}

#[tokio::test]
async fn downloads_then_revalidates() {
    let server = TestServer::start().await;
    let cache = temp_cache("revalidate");
    let fetcher = server.fetcher();
    let url = server.url("/hosts.txt");
    server.set(
        "/hosts.txt",
        Response::list("! Title: t\n! Expires: 2 days\n0.0.0.0 a.example\n0.0.0.0 b.example\n"),
    );

    let first = refresh(&fetcher, &cache, &url).await;
    assert_eq!(
        first.outcome,
        Outcome::Updated {
            rules: 2,
            previous: None
        }
    );
    let cached = cache.load(&url).unwrap().unwrap();
    assert!(cached.body.starts_with(b"! Title: t\n"));
    assert_eq!(cached.meta.expires_secs, Some(2 * 86_400));
    let etag = cached.meta.etag.clone().unwrap();
    assert_eq!(first.cached, Some(cached.meta.clone()));

    let second = refresh(&fetcher, &cache, &url).await;
    assert_eq!(second.outcome, Outcome::NotModified);
    let requests = server.requests();
    assert_eq!(requests[0].header("if-none-match"), None);
    assert_eq!(requests[1].header("if-none-match"), Some(etag.as_str()));
    assert!(
        requests[0]
            .header("user-agent")
            .unwrap()
            .starts_with("sinkhole/")
    );
    // Not rewritten on a 304.
    assert_eq!(cache.load(&url).unwrap().unwrap(), cached);

    server.set(
        "/hosts.txt",
        Response::list("0.0.0.0 a.example\n0.0.0.0 b.example\n0.0.0.0 c.example\n"),
    );
    let third = refresh(&fetcher, &cache, &url).await;
    assert_eq!(
        third.outcome,
        Outcome::Updated {
            rules: 3,
            previous: Some(2)
        }
    );
    assert_ne!(cache.load(&url).unwrap().unwrap().meta.etag, Some(etag));
}

#[tokio::test]
async fn gzip_is_decoded() {
    let server = TestServer::start().await;
    let cache = temp_cache("gzip");
    let url = server.url("/a.txt");
    let body = rules(500);
    server.set("/a.txt", Response::list(body.clone()).gzip());
    let report = refresh(&server.fetcher(), &cache, &url).await;
    assert!(report.updated(), "{report:?}");
    assert_eq!(cache.load(&url).unwrap().unwrap().body, body.as_bytes());
    assert!(
        server.requests()[0]
            .header("accept-encoding")
            .unwrap()
            .contains("gzip")
    );
}

#[tokio::test]
async fn failures_keep_the_last_good_copy() {
    let server = TestServer::start().await;
    let cache = temp_cache("failures");
    let fetcher = server
        .fetcher_builder()
        .timeout(Duration::from_millis(500))
        .build()
        .unwrap();
    let url = server.url("/a.txt");
    server.set("/a.txt", Response::list(rules(3)));
    assert!(refresh(&fetcher, &cache, &url).await.updated());
    let good = cache.load(&url).unwrap().unwrap();

    let cases = [
        (Response::status(500), "HTTP 500"),
        (Response::status(404), "HTTP 404"),
        (
            Response::plain("<!DOCTYPE html><title>Hotel Wi-Fi</title>Log in"),
            "HTML",
        ),
        (Response::plain("! nothing but comments\n"), "no rules"),
        (Response::plain(&b"\x1f\x8b\x08\x00binary"[..]), "binary"),
        (Response::stall(), "timed out"),
    ];
    for (response, expected) in cases {
        server.set("/a.txt", response);
        let report = refresh(&fetcher, &cache, &url).await;
        let reason = reason(&report);
        assert!(reason.contains(expected), "{expected:?} not in {reason:?}");
        // The cached copy is untouched, and reported as the one in use.
        assert_eq!(cache.load(&url).unwrap().unwrap(), good);
        assert_eq!(report.cached, Some(good.meta.clone()));
    }

    // A list that was never downloaded has nothing to keep.
    let never = server.url("/never.txt");
    let report = refresh(&fetcher, &cache, &never).await;
    assert!(report.failed());
    assert_eq!(report.cached, None);
    assert!(load_url(&cache, &never, &Env::dns()).unwrap().is_empty());
}

#[tokio::test]
async fn a_collapsed_list_needs_force() {
    let server = TestServer::start().await;
    let cache = temp_cache("collapse");
    let fetcher = server.fetcher();
    let url = server.url("/a.txt");
    server.set("/a.txt", Response::list(rules(1000)));
    assert!(refresh(&fetcher, &cache, &url).await.updated());

    server.set("/a.txt", Response::list(rules(10)));
    let report = refresh(&fetcher, &cache, &url).await;
    assert!(reason(&report).contains("shrank from 1000 to 10"));
    assert_eq!(cache.load_meta(&url).unwrap().unwrap().rules, 1000);

    let forced = update(&fetcher, &cache, &url, &Env::dns(), true).await;
    assert_eq!(
        forced[0].outcome,
        Outcome::Updated {
            rules: 10,
            previous: Some(1000)
        }
    );
    // Forced means unconditional, too.
    assert_eq!(
        server.requests().last().unwrap().header("if-none-match"),
        None
    );
}

#[tokio::test]
async fn an_unchanged_body_without_validators_is_not_an_update() {
    let server = TestServer::start().await;
    let cache = temp_cache("no-validators");
    let fetcher = server.fetcher();
    let url = server.url("/a.txt");
    server.set("/a.txt", Response::plain(rules(5)));
    assert!(refresh(&fetcher, &cache, &url).await.updated());
    let report = refresh(&fetcher, &cache, &url).await;
    assert_eq!(report.outcome, Outcome::NotModified);
    server.set("/a.txt", Response::plain(rules(6)));
    assert!(refresh(&fetcher, &cache, &url).await.updated());
}

#[tokio::test]
async fn redirects_stay_on_https() {
    let server = TestServer::start().await;
    let cache = temp_cache("redirects");
    let fetcher = server.fetcher();
    server.set("/a.txt", Response::list(rules(2)));

    server.set("/moved", Response::redirect(&server.url("/a.txt")));
    let moved = server.url("/moved");
    assert!(refresh(&fetcher, &cache, &moved).await.updated());
    // Cached under the configured URL, not the redirect target.
    assert!(cache.load(&moved).unwrap().is_some());

    let plain_http = format!("http://lists.test:{}/a.txt", server.port());
    server.set("/downgrade", Response::redirect(&plain_http));
    let report = refresh(&fetcher, &cache, &server.url("/downgrade")).await;
    assert!(reason(&report).contains("non-HTTPS"), "{report:?}");

    server.set("/loop", Response::redirect(&server.url("/loop")));
    let report = refresh(&fetcher, &cache, &server.url("/loop")).await;
    assert!(reason(&report).contains("too many redirects"), "{report:?}");
}

#[tokio::test]
async fn size_limit_applies_after_decompression() {
    let server = TestServer::start().await;
    let cache = temp_cache("size");
    let fetcher = server.fetcher_builder().max_bytes(4096).build().unwrap();
    // ~9 KB of rules gzip to well under 4 KB on the wire.
    server.set("/big.txt", Response::list(rules(500)).gzip());
    let report = refresh(&fetcher, &cache, &server.url("/big.txt")).await;
    assert!(reason(&report).contains("limit"), "{report:?}");
    server.set("/big-plain.txt", Response::list(rules(500)));
    let report = refresh(&fetcher, &cache, &server.url("/big-plain.txt")).await;
    assert!(reason(&report).contains("limit"), "{report:?}");
}

#[tokio::test]
async fn certificates_are_checked() {
    let server = TestServer::start().await;
    let cache = temp_cache("certs");
    server.set("/a.txt", Response::list(rules(2)));
    // The system's roots do not include the throwaway CA.
    let system_roots = Fetcher::builder()
        .resolver(Arc::new(StaticResolver))
        .build()
        .unwrap();
    let report = refresh(&system_roots, &cache, &server.url("/a.txt")).await;
    assert!(reason(&report).contains("certificate"), "{report:?}");
    assert!(cache.load(&server.url("/a.txt")).unwrap().is_none());
}

#[tokio::test]
async fn includes_are_followed_beside_the_list_only() {
    let server = TestServer::start().await;
    let cache = temp_cache("includes");
    let fetcher = server.fetcher();
    let cross_origin = server.url_on("other.test", "/dir/x.txt");
    server.set(
        "/dir/main.txt",
        Response::list(format!(
            "||a.example^\n!#include sub.txt\n!#include {cross_origin}\n!#include ../up.txt\n\
             !#if env_firefox\n!#include firefox.txt\n!#endif\n"
        )),
    );
    server.set(
        "/dir/sub.txt",
        Response::list("||b.example^\n!#include main.txt\n"),
    );
    server.set("/up.txt", Response::list("||up.example^\n"));
    server.set("/dir/firefox.txt", Response::list("||ff.example^\n"));

    let url = server.url("/dir/main.txt");
    let reports = update(&fetcher, &cache, &url, &Env::dns(), false).await;
    let summary: Vec<_> = reports
        .iter()
        .map(|r| (r.url.as_str(), r.included, r.updated()))
        .collect();
    let sub = server.url("/dir/sub.txt");
    assert_eq!(
        summary,
        [
            (url.as_str(), false, true),
            (sub.as_str(), true, true),
            (cross_origin.as_str(), true, false),
            ("../up.txt", true, false),
        ]
    );
    let fetched: Vec<_> = server.requests().into_iter().map(|r| r.path).collect();
    assert_eq!(fetched, ["/dir/main.txt", "/dir/sub.txt"]);

    let parts = load_url(&cache, &url, &Env::dns()).unwrap();
    let origins: Vec<_> = parts.iter().map(|p| p.origin.as_str()).collect();
    assert_eq!(origins, [url.as_str(), sub.as_str()]);
    assert_eq!(parts[1].path, cache.path(&sub));
}
