//! DNS over HTTPS (RFC 8484).
//!
//! One HTTP client per upstream, so each keeps its own connection pool:
//! after the first query, queries share one HTTP/2 connection, multiplexed,
//! with no handshake. The URL's host is pinned to the configured `bootstrap`
//! addresses, so reaching the upstream never needs a DNS lookup, which
//! would otherwise come back to sinkhole itself.

use std::net::{IpAddr, SocketAddr};

use hickory_proto::op::Message;
use reqwest::header::{ACCEPT, CONTENT_TYPE};
use reqwest::{StatusCode, Url, redirect};

use super::tls::Roots;
use super::{ExchangeError, UpstreamError, pad};
use crate::engine::Forward;
use crate::upstream::DEFAULT_TIMEOUT;

const DNS_MESSAGE: &str = "application/dns-message";
/// A DNS message cannot be larger.
const MAX_ANSWER: usize = 65_535;

#[derive(Debug)]
pub(super) struct Doh {
    client: reqwest::Client,
    url: Url,
}

impl Doh {
    pub(super) fn new(
        url: &str,
        bootstrap: &[IpAddr],
        roots: &Roots,
    ) -> Result<Doh, UpstreamError> {
        let url = Url::parse(url).map_err(|e| UpstreamError::Url(format!("{url}: {e}")))?;
        let mut builder = reqwest::Client::builder()
            .https_only(true)
            // A proxy would put a stranger between sinkhole and its upstream,
            // and a proxy configured by name would need sinkhole to resolve it.
            .no_proxy()
            .redirect(redirect::Policy::none())
            .connect_timeout(DEFAULT_TIMEOUT);
        if let Some(host) = url.host_str()
            && !bootstrap.is_empty()
        {
            // The port is taken from the URL.
            let addrs: Vec<SocketAddr> =
                bootstrap.iter().map(|&ip| SocketAddr::new(ip, 0)).collect();
            builder = builder.resolve_to_addrs(host, &addrs);
        }
        let client = roots.apply(builder)?.build()?;
        Ok(Doh { client, url })
    }

    pub(super) fn url(&self) -> &Url {
        &self.url
    }

    pub(super) async fn exchange(&self, forward: &Forward) -> Result<Message, ExchangeError> {
        let mut query = forward.upstream_query();
        // RFC 8484 §4.1: ID 0. HTTP matches answers to questions; the ID
        // only gets in the way of caching.
        query.metadata.id = 0;
        pad(&mut query)?;
        let mut response = self
            .client
            .post(self.url.clone())
            .header(CONTENT_TYPE, DNS_MESSAGE)
            .header(ACCEPT, DNS_MESSAGE)
            .body(query.to_vec()?)
            .send()
            .await?;
        if response.status() != StatusCode::OK {
            return Err(ExchangeError::Status(response.status().as_u16()));
        }
        let content_type = response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if !content_type.starts_with(DNS_MESSAGE) {
            return Err(ExchangeError::ContentType(content_type.to_owned()));
        }
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await? {
            if body.len() + chunk.len() > MAX_ANSWER {
                return Err(ExchangeError::TooLarge);
            }
            body.extend_from_slice(&chunk);
        }
        let answer = Message::from_vec(&body)?;
        if !forward.is_answer(&query, &answer) {
            return Err(ExchangeError::Mismatch);
        }
        Ok(answer)
    }
}
