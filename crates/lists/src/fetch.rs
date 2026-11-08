//! Downloading lists: HTTPS only, conditional, size-capped.
//!
//! - **HTTPS only**, including every redirect. A redirect to `http://` is
//!   an error, not a downgrade.
//! - **Conditional.** A cached copy's ETag and Last-Modified go out as
//!   `If-None-Match` / `If-Modified-Since`, so an unchanged list costs a
//!   `304` and a few hundred bytes. gzip is accepted.
//! - **Capped** at [`MAX_LIST_BYTES`](crate::MAX_LIST_BYTES) after
//!   decompression, counted as the body streams in.
//! - **Certificates** are checked by the operating system's verifier
//!   (Security.framework on macOS), with rustls and *ring* doing the TLS.
//!   sinkhole never adds a root of its own.
//! - **Names** of list servers can be resolved by the caller (see
//!   [`Resolve`]): the resolver hands in its upstreams, because once
//!   sinkhole *is* the system resolver, asking the system would ask itself.

use std::error::Error as StdError;
use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use reqwest::header::{ETAG, HeaderValue, IF_MODIFIED_SINCE, IF_NONE_MATCH, LAST_MODIFIED};
use reqwest::{StatusCode, redirect};

use crate::cache::Meta;
use crate::check::MAX_LIST_BYTES;

/// A boxed future, as [`Resolve`] returns.
pub type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send>>;

/// Finds the addresses of a list server.
pub trait Resolve: Send + Sync + 'static {
    fn resolve(&self, host: &str) -> BoxFuture<io::Result<Vec<IpAddr>>>;
}

/// What a fetch brought back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Fetched {
    /// The cached copy is current (`304 Not Modified`).
    NotModified,
    /// A new body, not yet checked.
    Body {
        body: Vec<u8>,
        etag: Option<String>,
        last_modified: Option<String>,
    },
}

/// Why a fetch failed.
#[derive(Debug, thiserror::Error)]
pub enum FetchError {
    /// Connecting, TLS, a redirect, a timeout: the full cause chain.
    #[error("{0}")]
    Request(String),
    #[error("the server answered HTTP {0}")]
    Status(u16),
    #[error("larger than the {} MiB limit", .0 >> 20)]
    TooLarge(usize),
    #[error("the server answered 304 Not Modified to an unconditional request")]
    UnexpectedNotModified,
}

impl From<reqwest::Error> for FetchError {
    fn from(e: reqwest::Error) -> Self {
        // reqwest's own message is "error sending request for url (…)"; the
        // useful part ("invalid peer certificate: UnknownIssuer") is in
        // the sources.
        let mut message = e.to_string();
        let mut source = e.source();
        while let Some(cause) = source {
            message.push_str(": ");
            message.push_str(&cause.to_string());
            source = cause.source();
        }
        FetchError::Request(message)
    }
}

/// Builds a [`Fetcher`].
pub struct FetcherBuilder {
    resolver: Option<Arc<dyn Resolve>>,
    roots_only: Vec<Vec<u8>>,
    timeout: Duration,
    max_bytes: usize,
}

impl Default for FetcherBuilder {
    fn default() -> Self {
        FetcherBuilder {
            resolver: None,
            roots_only: Vec::new(),
            timeout: Duration::from_secs(300),
            max_bytes: MAX_LIST_BYTES,
        }
    }
}

impl FetcherBuilder {
    /// Resolve list servers with `resolver` instead of the system.
    pub fn resolver(mut self, resolver: Arc<dyn Resolve>) -> Self {
        self.resolver = Some(resolver);
        self
    }

    /// Trust only these roots (DER), not the system's. For tests against a
    /// local server.
    pub fn roots_only(mut self, der: Vec<Vec<u8>>) -> Self {
        self.roots_only = der;
        self
    }

    /// Whole-request deadline, body included. Default 5 minutes.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Body size limit. Default [`MAX_LIST_BYTES`].
    pub fn max_bytes(mut self, max_bytes: usize) -> Self {
        self.max_bytes = max_bytes;
        self
    }

    pub fn build(self) -> Result<Fetcher, FetchError> {
        // reqwest is built without a default crypto provider so that only
        // *ring* is compiled in. Installing it is process-wide; if another
        // part of the program installed one first, that one is used.
        let _ = rustls::crypto::ring::default_provider().install_default();

        let mut builder = reqwest::Client::builder()
            .user_agent(concat!("sinkhole/", env!("CARGO_PKG_VERSION")))
            .https_only(true)
            .redirect(redirect::Policy::custom(|attempt| {
                if attempt.url().scheme() != "https" {
                    attempt.error("refusing a redirect to a non-HTTPS URL")
                } else if attempt.previous().len() >= 5 {
                    attempt.error("too many redirects")
                } else {
                    attempt.follow()
                }
            }))
            .connect_timeout(Duration::from_secs(10))
            .read_timeout(Duration::from_secs(30))
            .timeout(self.timeout);
        if let Some(resolver) = self.resolver {
            builder = builder.dns_resolver(Arc::new(DnsAdapter(resolver)));
        }
        if !self.roots_only.is_empty() {
            let roots = self
                .roots_only
                .iter()
                .map(|der| reqwest::Certificate::from_der(der))
                .collect::<Result<Vec<_>, _>>()?;
            builder = builder.tls_certs_only(roots);
        }
        Ok(Fetcher {
            client: builder.build()?,
            max_bytes: self.max_bytes,
        })
    }
}

/// Downloads lists. Cheap to clone; clones share connections.
#[derive(Debug, Clone)]
pub struct Fetcher {
    client: reqwest::Client,
    max_bytes: usize,
}

impl Fetcher {
    pub fn builder() -> FetcherBuilder {
        FetcherBuilder::default()
    }

    /// Downloads `url`, conditionally if `cached` has validators.
    pub async fn fetch(&self, url: &str, cached: Option<&Meta>) -> Result<Fetched, FetchError> {
        let mut request = self.client.get(url);
        let mut conditional = false;
        if let Some(meta) = cached {
            // A validator that is not a valid header value (a hand-edited
            // cache file) is left out; the request is merely unconditional.
            for (name, value) in [
                (IF_NONE_MATCH, &meta.etag),
                (IF_MODIFIED_SINCE, &meta.last_modified),
            ] {
                if let Some(value) = value.as_deref().and_then(|v| HeaderValue::from_str(v).ok()) {
                    request = request.header(name, value);
                    conditional = true;
                }
            }
        }
        let mut response = request.send().await?;
        match response.status() {
            StatusCode::OK => {}
            StatusCode::NOT_MODIFIED if conditional => return Ok(Fetched::NotModified),
            StatusCode::NOT_MODIFIED => return Err(FetchError::UnexpectedNotModified),
            status => return Err(FetchError::Status(status.as_u16())),
        }
        let header = |name| {
            response
                .headers()
                .get(name)
                .and_then(|v: &HeaderValue| v.to_str().ok())
                .map(str::to_owned)
        };
        let etag = header(ETAG);
        let last_modified = header(LAST_MODIFIED);
        // Content-Length is the compressed size when the body is gzipped,
        // so it only allows an early refusal; the real limit is enforced
        // on the decompressed bytes below.
        let declared = response.content_length().unwrap_or(0);
        if usize::try_from(declared).map_or(true, |len| len > self.max_bytes) {
            return Err(FetchError::TooLarge(self.max_bytes));
        }
        let mut body = Vec::with_capacity(usize::try_from(declared).unwrap_or(0));
        while let Some(chunk) = response.chunk().await? {
            if body.len() + chunk.len() > self.max_bytes {
                return Err(FetchError::TooLarge(self.max_bytes));
            }
            body.extend_from_slice(&chunk);
        }
        Ok(Fetched::Body {
            body,
            etag,
            last_modified,
        })
    }
}

/// [`Resolve`] in the shape reqwest wants.
struct DnsAdapter(Arc<dyn Resolve>);

impl reqwest::dns::Resolve for DnsAdapter {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let resolver = Arc::clone(&self.0);
        let host = name.as_str().to_owned();
        Box::pin(async move {
            let ips = resolver.resolve(&host).await?;
            if ips.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("{host} has no addresses"),
                )
                .into());
            }
            // The port is filled in by the connector.
            let addrs: reqwest::dns::Addrs =
                Box::new(ips.into_iter().map(|ip| SocketAddr::new(ip, 0)));
            Ok(addrs)
        })
    }
}
