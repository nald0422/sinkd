//! Fake upstreams for integration tests: DoH and DoT servers behind a
//! throwaway CA, both answering from one scripted zone and logging what
//! they were asked.
#![allow(dead_code, clippy::unwrap_used)]

use std::convert::Infallible;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use hickory_proto::op::{Message, OpCode, ResponseCode};
use hickory_proto::rr::rdata::opt::EdnsCode;
use hickory_proto::rr::rdata::{A, CNAME, HTTPS, SOA, SVCB};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use sinkhole_lists::testing::TestCa;
use tokio::io::{AsyncReadExt, AsyncWriteExt, split};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

/// The names on the fake servers' certificate.
pub const DOH_HOST: &str = "doh.test";
pub const DOT_HOST: &str = "dot.test";

pub fn ca() -> TestCa {
    TestCa::new(&[DOH_HOST, DOT_HOST])
}

/// One query a fake upstream received.
#[derive(Debug, Clone)]
pub struct Seen {
    pub name: String,
    pub record_type: RecordType,
    pub id: u16,
    /// Length on the wire, and whether it carried an EDNS Padding option.
    pub len: usize,
    pub padded: bool,
}

#[derive(Debug, Default)]
pub struct Log(Mutex<Vec<Seen>>);

impl Log {
    fn record(&self, query: &Message, len: usize) {
        let Some(q) = query.queries.first() else {
            return;
        };
        self.0.lock().unwrap().push(Seen {
            name: q.name().to_lowercase().to_ascii(),
            record_type: q.query_type(),
            id: query.metadata.id,
            len,
            padded: query
                .edns
                .as_ref()
                .is_some_and(|e| e.options().get(EdnsCode::Padding).is_some()),
        });
    }

    pub fn all(&self) -> Vec<Seen> {
        self.0.lock().unwrap().clone()
    }

    /// Queries for `name` (lower case, with the trailing dot).
    pub fn count(&self, name: &str) -> usize {
        self.all().iter().filter(|s| s.name == name).count()
    }
}

fn name(s: &str) -> Name {
    Name::from_ascii(s).unwrap()
}

fn soa() -> Record {
    Record::from_rdata(
        name("test."),
        300,
        RData::SOA(SOA::new(
            name("ns.test."),
            name("host.test."),
            1,
            3600,
            600,
            86400,
            60,
        )),
    )
}

/// The scripted zone. Names are matched in lower case:
///
/// - `short.test` A 192.0.2.2, TTL 1
/// - `cloaked.test` CNAME `metrics.tracker.test` → A 192.0.2.3
/// - `svc.test` HTTPS 1 `edge.tracker.test.`; A 192.0.2.4
/// - `missing.test` NXDOMAIN, with an SOA (negative TTL 60)
/// - `fail.test` SERVFAIL
/// - `slow.test` answered after 300 ms (by the DoT server)
/// - anything else: A 192.0.2.1, TTL 300; NODATA with an SOA for other types
pub fn answer(query: &Message) -> Message {
    let mut r = Message::response(query.metadata.id, OpCode::Query);
    r.metadata.recursion_desired = query.metadata.recursion_desired;
    r.metadata.recursion_available = true;
    r.add_queries(query.queries.iter().cloned());
    if let Some(edns) = &query.edns {
        let mut ours = hickory_proto::op::Edns::new();
        ours.set_max_payload(1232);
        ours.set_dnssec_ok(edns.flags().dnssec_ok);
        r.set_edns(ours);
    }
    let Some(q) = query.queries.first() else {
        r.metadata.response_code = ResponseCode::FormErr;
        return r;
    };
    let qname = q.name().clone();
    let a = |octet: u8, ttl: u32| {
        Record::from_rdata(
            qname.clone(),
            ttl,
            RData::A(A(Ipv4Addr::new(192, 0, 2, octet))),
        )
    };
    match (q.name().to_lowercase().to_ascii().as_str(), q.query_type()) {
        ("short.test.", RecordType::A) => r.add_answer(a(2, 1)),
        ("cloaked.test.", RecordType::A) => {
            r.add_answer(Record::from_rdata(
                qname.clone(),
                300,
                RData::CNAME(CNAME(name("metrics.tracker.test."))),
            ));
            r.add_answer(Record::from_rdata(
                name("metrics.tracker.test."),
                300,
                RData::A(A(Ipv4Addr::new(192, 0, 2, 3))),
            ))
        }
        ("svc.test.", RecordType::HTTPS) => r.add_answer(Record::from_rdata(
            qname.clone(),
            300,
            RData::HTTPS(HTTPS(SVCB::new(1, name("edge.tracker.test."), Vec::new()))),
        )),
        ("svc.test.", RecordType::A) => r.add_answer(a(4, 300)),
        ("missing.test.", _) => {
            r.metadata.response_code = ResponseCode::NXDomain;
            r.add_authority(soa())
        }
        ("fail.test.", _) => {
            r.metadata.response_code = ResponseCode::ServFail;
            &mut r
        }
        (_, RecordType::A) => r.add_answer(a(1, 300)),
        _ => r.add_authority(soa()),
    };
    r
}

/// How the DoH server misbehaves, if at all.
#[derive(Debug, Clone, Default)]
pub enum DohMode {
    #[default]
    Normal,
    Status(u16),
    ContentType(&'static str),
}

pub struct DohServer {
    pub port: u16,
    pub log: Arc<Log>,
    pub mode: Arc<Mutex<DohMode>>,
    /// HTTP versions of the requests, e.g. `HTTP/2.0`.
    pub versions: Arc<Mutex<Vec<String>>>,
    /// TLS connections accepted.
    pub connections: Arc<AtomicUsize>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for DohServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl DohServer {
    pub async fn start(ca: &TestCa) -> DohServer {
        let acceptor = TlsAcceptor::from(Arc::new(ca.server_config(&[b"h2", b"http/1.1"])));
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let log = Arc::new(Log::default());
        let mode = Arc::new(Mutex::new(DohMode::Normal));
        let versions = Arc::new(Mutex::new(Vec::new()));
        let connections = Arc::new(AtomicUsize::new(0));
        let task = tokio::spawn({
            let (log, mode, versions) =
                (Arc::clone(&log), Arc::clone(&mode), Arc::clone(&versions));
            let connections = Arc::clone(&connections);
            async move {
                while let Ok((tcp, _)) = listener.accept().await {
                    connections.fetch_add(1, Ordering::SeqCst);
                    let (acceptor, log, mode, versions) = (
                        acceptor.clone(),
                        Arc::clone(&log),
                        Arc::clone(&mode),
                        Arc::clone(&versions),
                    );
                    tokio::spawn(async move {
                        let Ok(tls) = acceptor.accept(tcp).await else {
                            return;
                        };
                        let service = hyper::service::service_fn(move |req| {
                            handle(
                                req,
                                Arc::clone(&log),
                                Arc::clone(&mode),
                                Arc::clone(&versions),
                            )
                        });
                        let _ = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
                            .serve_connection(TokioIo::new(tls), service)
                            .await;
                    });
                }
            }
        });
        DohServer {
            port,
            log,
            mode,
            versions,
            connections,
            task,
        }
    }

    /// The config entry for this server, reached through its bootstrap
    /// address since `doh.test` resolves nowhere.
    pub fn upstream_toml(&self) -> String {
        format!(
            "[[upstream]]\nprotocol = \"doh\"\nurl = \"https://{DOH_HOST}:{}/dns-query\"\nbootstrap = [\"127.0.0.1\"]\n",
            self.port
        )
    }

    pub fn set_mode(&self, mode: DohMode) {
        *self.mode.lock().unwrap() = mode;
    }
}

async fn handle(
    req: Request<Incoming>,
    log: Arc<Log>,
    mode: Arc<Mutex<DohMode>>,
    versions: Arc<Mutex<Vec<String>>>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    versions
        .lock()
        .unwrap()
        .push(format!("{:?}", req.version()));
    let typed = req
        .headers()
        .get("content-type")
        .is_some_and(|v| v == "application/dns-message");
    let body = req.into_body().collect().await.map(|b| b.to_bytes());
    let reply = |status: StatusCode, content_type: &str, body: Vec<u8>| {
        Ok(Response::builder()
            .status(status)
            .header("content-type", content_type)
            .body(Full::new(Bytes::from(body)))
            .unwrap())
    };
    let (Ok(body), true) = (body, typed) else {
        return reply(
            StatusCode::BAD_REQUEST,
            "text/plain",
            b"bad request".to_vec(),
        );
    };
    let Ok(query) = Message::from_vec(&body) else {
        return reply(
            StatusCode::BAD_REQUEST,
            "text/plain",
            b"bad message".to_vec(),
        );
    };
    log.record(&query, body.len());
    let mode = mode.lock().unwrap().clone();
    match mode {
        DohMode::Status(code) => reply(
            StatusCode::from_u16(code).unwrap(),
            "text/plain",
            b"nope".to_vec(),
        ),
        DohMode::ContentType(ct) => reply(StatusCode::OK, ct, answer(&query).to_vec().unwrap()),
        DohMode::Normal => reply(
            StatusCode::OK,
            "application/dns-message",
            answer(&query).to_vec().unwrap(),
        ),
    }
}

pub struct DotServer {
    pub addr: SocketAddr,
    pub log: Arc<Log>,
    pub connections: Arc<AtomicUsize>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for DotServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl DotServer {
    /// `close_after`: hang up after answering this many queries on a
    /// connection, as servers do with idle or busy connections.
    pub async fn start(ca: &TestCa, close_after: Option<usize>) -> DotServer {
        let acceptor = TlsAcceptor::from(Arc::new(ca.server_config(&[])));
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let log = Arc::new(Log::default());
        let connections = Arc::new(AtomicUsize::new(0));
        let task = tokio::spawn({
            let (log, connections) = (Arc::clone(&log), Arc::clone(&connections));
            async move {
                while let Ok((tcp, _)) = listener.accept().await {
                    connections.fetch_add(1, Ordering::SeqCst);
                    let (acceptor, log) = (acceptor.clone(), Arc::clone(&log));
                    tokio::spawn(serve_dot(acceptor, tcp, log, close_after));
                }
            }
        });
        DotServer {
            addr,
            log,
            connections,
            task,
        }
    }

    pub fn upstream_toml(&self) -> String {
        format!(
            "[[upstream]]\nprotocol = \"dot\"\naddr = \"{}\"\nserver_name = \"{DOT_HOST}\"\n",
            self.addr
        )
    }
}

async fn serve_dot(
    acceptor: TlsAcceptor,
    tcp: tokio::net::TcpStream,
    log: Arc<Log>,
    close_after: Option<usize>,
) {
    let Ok(tls) = acceptor.accept(tcp).await else {
        return;
    };
    let (mut reader, writer) = split(tls);
    let writer = Arc::new(tokio::sync::Mutex::new(writer));
    let mut answered = 0;
    let mut replies = Vec::new();
    while let Ok(len) = reader.read_u16().await {
        let mut frame = vec![0; usize::from(len)];
        if reader.read_exact(&mut frame).await.is_err() {
            break;
        }
        let Ok(query) = Message::from_vec(&frame) else {
            break;
        };
        log.record(&query, frame.len());
        let slow = query
            .queries
            .first()
            .is_some_and(|q| q.name().to_lowercase().to_ascii() == "slow.test.");
        let writer = Arc::clone(&writer);
        // Answered concurrently, so a slow answer overtakes nothing and
        // later answers can arrive first.
        replies.push(tokio::spawn(async move {
            if slow {
                tokio::time::sleep(Duration::from_millis(300)).await;
            }
            let bytes = answer(&query).to_vec().unwrap();
            let mut frame = (bytes.len() as u16).to_be_bytes().to_vec();
            frame.extend_from_slice(&bytes);
            let _ = writer.lock().await.write_all(&frame).await;
        }));
        answered += 1;
        if close_after.is_some_and(|n| answered >= n) {
            break;
        }
    }
    for reply in replies {
        let _ = reply.await;
    }
    let _ = writer.lock().await.shutdown().await;
}
