//! A local HTTPS list server for tests, with a throwaway CA.
//!
//! The server answers for `lists.test` and `other.test` (two origins, for
//! `!#include` tests) on one loopback port. [`StaticResolver`] maps both
//! names to `127.0.0.1`, and [`TestServer::fetcher`] trusts only the
//! throwaway CA, so tests exercise real TLS and certificate checks without
//! touching the network or the system trust store.
#![allow(clippy::missing_panics_doc)]

use std::collections::HashMap;
use std::io::{self, Write};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex, MutexGuard};

use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;

use crate::fetch::{BoxFuture, Fetcher, FetcherBuilder, Resolve};

/// The names the server's certificate carries.
pub const HOSTS: [&str; 2] = ["lists.test", "other.test"];

/// A throwaway certificate authority and one server certificate it signed.
pub struct TestCa {
    ca_der: Vec<u8>,
    cert_der: Vec<u8>,
    key_der: Vec<u8>,
}

impl TestCa {
    /// A CA, and a server certificate for `names` (DNS names or IP
    /// addresses).
    pub fn new(names: &[&str]) -> TestCa {
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).expect("CA params");
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "sinkd test CA");
        let ca_key = KeyPair::generate().expect("CA key");
        let ca_cert = ca_params.self_signed(&ca_key).expect("CA certificate");
        let issuer = Issuer::new(ca_params, ca_key);

        let key = KeyPair::generate().expect("server key");
        let names: Vec<String> = names.iter().map(|n| (*n).to_owned()).collect();
        let params = CertificateParams::new(names).expect("params");
        let cert = params.signed_by(&key, &issuer).expect("server certificate");
        TestCa {
            ca_der: ca_cert.der().to_vec(),
            cert_der: cert.der().to_vec(),
            key_der: key.serialize_der(),
        }
    }

    /// The CA certificate, DER-encoded: the root a client must trust.
    pub fn ca_der(&self) -> Vec<u8> {
        self.ca_der.clone()
    }

    /// A TLS server config presenting the server certificate, offering
    /// `alpn` protocols (e.g. `h2`).
    pub fn server_config(&self, alpn: &[&[u8]]) -> rustls::ServerConfig {
        let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .expect("protocol versions")
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(self.cert_der.clone())],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(self.key_der.clone())),
        )
        .expect("server config");
        config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
        config
    }
}

/// A scripted response.
#[derive(Debug, Clone)]
pub struct Response {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    etag: bool,
    gzip: bool,
    stall: bool,
}

impl Response {
    /// `200` with an ETag derived from the body; a matching
    /// `If-None-Match` gets `304`.
    pub fn list(body: impl Into<Vec<u8>>) -> Self {
        Response {
            etag: true,
            ..Self::plain(body)
        }
    }

    /// `200` without validators, like a server that sends no ETag.
    pub fn plain(body: impl Into<Vec<u8>>) -> Self {
        Response {
            status: 200,
            headers: Vec::new(),
            body: body.into(),
            etag: false,
            gzip: false,
            stall: false,
        }
    }

    pub fn status(status: u16) -> Self {
        Response {
            status,
            ..Self::plain("")
        }
    }

    pub fn redirect(location: &str) -> Self {
        Self::status(302).header("Location", location)
    }

    /// Reads the request and never answers.
    pub fn stall() -> Self {
        Response {
            stall: true,
            ..Self::status(200)
        }
    }

    pub fn header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    /// Sends the body gzip-compressed.
    pub fn gzip(mut self) -> Self {
        self.gzip = true;
        self
    }

    fn etag(&self) -> String {
        format!("\"{:016x}\"", crate::cache::fnv1a(&self.body))
    }
}

/// A request the server received.
#[derive(Debug, Clone)]
pub struct Request {
    pub path: String,
    /// Header names in lower case.
    pub headers: Vec<(String, String)>,
}

impl Request {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

#[derive(Default)]
struct State {
    routes: HashMap<String, Response>,
    requests: Vec<Request>,
}

/// The server. Stops when dropped.
pub struct TestServer {
    port: u16,
    ca_der: Vec<u8>,
    state: Arc<Mutex<State>>,
    task: JoinHandle<()>,
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl TestServer {
    pub async fn start() -> TestServer {
        let ca = TestCa::new(&HOSTS);
        let acceptor = TlsAcceptor::from(Arc::new(ca.server_config(&[])));

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind");
        let port = listener.local_addr().expect("local addr").port();
        let state = Arc::new(Mutex::new(State::default()));
        let task = tokio::spawn({
            let state = Arc::clone(&state);
            async move {
                while let Ok((stream, _)) = listener.accept().await {
                    tokio::spawn(serve(stream, acceptor.clone(), Arc::clone(&state)));
                }
            }
        });
        TestServer {
            port,
            ca_der: ca.ca_der(),
            state,
            task,
        }
    }

    /// `https://lists.test:<port><path>`.
    pub fn url(&self, path: &str) -> String {
        self.url_on("lists.test", path)
    }

    pub fn url_on(&self, host: &str, path: &str) -> String {
        format!("https://{host}:{}{path}", self.port)
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    /// Serves `response` at `path` from now on. Unknown paths get `404`.
    pub fn set(&self, path: &str, response: Response) {
        self.lock().routes.insert(path.into(), response);
    }

    /// Every request so far, oldest first.
    pub fn requests(&self) -> Vec<Request> {
        self.lock().requests.clone()
    }

    /// The throwaway CA's certificate, DER-encoded.
    pub fn ca_der(&self) -> Vec<u8> {
        self.ca_der.clone()
    }

    /// A fetcher that trusts only the throwaway CA and resolves the test
    /// names to loopback.
    pub fn fetcher_builder(&self) -> FetcherBuilder {
        Fetcher::builder()
            .roots_only(vec![self.ca_der()])
            .resolver(Arc::new(StaticResolver))
    }

    pub fn fetcher(&self) -> Fetcher {
        self.fetcher_builder().build().expect("fetcher")
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// Resolves [`HOSTS`] to `127.0.0.1` and nothing else.
pub struct StaticResolver;

impl Resolve for StaticResolver {
    fn resolve(&self, host: &str) -> BoxFuture<io::Result<Vec<IpAddr>>> {
        let known = HOSTS.contains(&host);
        Box::pin(async move {
            if known {
                Ok(vec![IpAddr::V4(Ipv4Addr::LOCALHOST)])
            } else {
                Err(io::Error::new(io::ErrorKind::NotFound, "unknown test host"))
            }
        })
    }
}

async fn serve(stream: TcpStream, acceptor: TlsAcceptor, state: Arc<Mutex<State>>) {
    let Ok(mut tls) = acceptor.accept(stream).await else {
        return;
    };
    let mut head = Vec::new();
    let mut chunk = [0; 4096];
    while !head.windows(4).any(|w| w == b"\r\n\r\n") {
        match tls.read(&mut chunk).await {
            Ok(0) | Err(_) => return,
            Ok(n) => head.extend_from_slice(&chunk[..n]),
        }
        if head.len() > 64 << 10 {
            return;
        }
    }
    let head = String::from_utf8_lossy(&head);
    let mut lines = head.split("\r\n");
    let path = lines
        .next()
        .and_then(|l| l.split(' ').nth(1))
        .unwrap_or("/")
        .to_owned();
    let headers = lines
        .take_while(|l| !l.is_empty())
        .filter_map(|l| l.split_once(':'))
        .map(|(n, v)| (n.trim().to_ascii_lowercase(), v.trim().to_owned()))
        .collect();
    let request = Request { path, headers };
    let response = {
        let mut state = state.lock().unwrap_or_else(|e| e.into_inner());
        state.requests.push(request.clone());
        state
            .routes
            .get(&request.path)
            .cloned()
            .unwrap_or_else(|| Response::status(404))
    };
    if response.stall {
        std::future::pending::<()>().await;
    }

    let mut status = response.status;
    let mut headers = response.headers.clone();
    let mut body = response.body.clone();
    if response.etag {
        let etag = response.etag();
        if request.header("if-none-match") == Some(etag.as_str()) {
            status = 304;
            body.clear();
        }
        headers.push(("ETag".into(), etag));
    }
    if response.gzip && !body.is_empty() {
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        if encoder.write_all(&body).is_err() {
            return;
        }
        let Ok(compressed) = encoder.finish() else {
            return;
        };
        body = compressed;
        headers.push(("Content-Encoding".into(), "gzip".into()));
    }
    let mut out = format!(
        "HTTP/1.1 {status} Scripted\r\nContent-Length: {}\r\nConnection: close\r\n",
        body.len()
    );
    for (name, value) in headers {
        out.push_str(&format!("{name}: {value}\r\n"));
    }
    out.push_str("\r\n");
    let mut bytes = out.into_bytes();
    bytes.extend_from_slice(&body);
    let _ = tls.write_all(&bytes).await;
    let _ = tls.shutdown().await;
}
