//! DNS over TLS (RFC 7858), over one long-lived, pipelined connection.
//!
//! Every query to an upstream shares one TLS connection: each goes out with
//! an ID unique among those in flight and is matched to its answer by that
//! ID, in whatever order answers come back (RFC 7766 §6.2.1.1). A reader
//! task owns the receiving half. When the connection dies, every waiting
//! query fails at once, and the next query opens a new connection.
//!
//! Servers close idle connections, and a query can race such a close. A
//! query that loses that race on a reused connection is retried once on a
//! fresh one; a failure on a fresh connection is reported.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use hickory_proto::op::Message;
use rustls::pki_types::ServerName;
use tokio::io::{ReadHalf, WriteHalf, split};
use tokio::net::TcpStream;
use tokio::sync::{Mutex as AsyncMutex, oneshot};
use tokio::task::JoinHandle;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

use super::tls::Roots;
use super::{ExchangeError, UpstreamError, pad};
use crate::engine::Forward;
use crate::wire::{read_frame, write_frame};

/// An idle connection is closed after this long. Servers typically allow
/// 10 s or more; closing our side first keeps us from writing into a
/// connection the server has already dropped.
const IDLE: Duration = Duration::from_secs(8);

type Stream = TlsStream<TcpStream>;

pub(super) struct Dot {
    addr: SocketAddr,
    server_name: ServerName<'static>,
    connector: TlsConnector,
    conn: AsyncMutex<Option<Arc<Conn>>>,
}

impl std::fmt::Debug for Dot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Dot")
            .field("addr", &self.addr)
            .field("server_name", &self.server_name)
            .finish_non_exhaustive()
    }
}

impl Dot {
    pub(super) fn new(
        addr: SocketAddr,
        server_name: &str,
        roots: &Roots,
    ) -> Result<Dot, UpstreamError> {
        let server_name = ServerName::try_from(server_name.to_owned())
            .map_err(|e| UpstreamError::ServerName(format!("{server_name}: {e}")))?;
        let config = roots.client_config()?;
        Ok(Dot {
            addr,
            server_name,
            connector: TlsConnector::from(Arc::new(config)),
            conn: AsyncMutex::new(None),
        })
    }

    pub(super) fn addr(&self) -> SocketAddr {
        self.addr
    }

    pub(super) async fn exchange(&self, forward: &Forward) -> Result<Message, ExchangeError> {
        let (conn, fresh) = self.connection().await?;
        match conn.query(forward).await {
            Err(ExchangeError::Closed) if !fresh => {
                let (conn, _) = self.connection().await?;
                conn.query(forward).await
            }
            result => result,
        }
    }

    /// The open connection, or a new one. Concurrent callers wait for a
    /// single connect rather than each opening their own.
    async fn connection(&self) -> Result<(Arc<Conn>, bool), ExchangeError> {
        let mut slot = self.conn.lock().await;
        if let Some(conn) = slot.as_ref()
            && !conn.state.closed.load(Ordering::Acquire)
        {
            return Ok((Arc::clone(conn), false));
        }
        let tcp = TcpStream::connect(self.addr).await?;
        tcp.set_nodelay(true)?;
        let tls = self
            .connector
            .connect(self.server_name.clone(), tcp)
            .await?;
        let (reader, writer) = split(tls);
        let state = Arc::new(State::default());
        let conn = Arc::new(Conn {
            writer: AsyncMutex::new(writer),
            next_id: AtomicU16::new(0),
            reader: tokio::spawn(read_loop(reader, Arc::clone(&state))),
            state,
        });
        *slot = Some(Arc::clone(&conn));
        Ok((conn, true))
    }
}

/// What the reader task and the queries share.
#[derive(Debug, Default)]
struct State {
    pending: Mutex<HashMap<u16, oneshot::Sender<Vec<u8>>>>,
    closed: AtomicBool,
}

impl State {
    fn pending(&self) -> MutexGuard<'_, HashMap<u16, oneshot::Sender<Vec<u8>>>> {
        self.pending.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn close(&self) {
        self.closed.store(true, Ordering::Release);
        // Dropping the senders wakes every waiting query with an error.
        self.pending().clear();
    }
}

#[derive(Debug)]
struct Conn {
    writer: AsyncMutex<WriteHalf<Stream>>,
    next_id: AtomicU16,
    state: Arc<State>,
    reader: JoinHandle<()>,
}

impl Drop for Conn {
    fn drop(&mut self) {
        self.reader.abort();
    }
}

/// Removes a query's slot when the query ends, answered or not (a timeout
/// drops the future mid-wait).
struct Slot<'a> {
    state: &'a State,
    id: u16,
}

impl Drop for Slot<'_> {
    fn drop(&mut self) {
        self.state.pending().remove(&self.id);
    }
}

impl Conn {
    async fn query(&self, forward: &Forward) -> Result<Message, ExchangeError> {
        let (tx, rx) = oneshot::channel();
        let id = {
            let mut pending = self.state.pending();
            if pending.len() >= usize::from(u16::MAX) {
                return Err(ExchangeError::Closed);
            }
            // The channel is encrypted, so IDs need only be unique among
            // the queries in flight, not unpredictable.
            let id = loop {
                let id = self.next_id.fetch_add(1, Ordering::Relaxed);
                if !pending.contains_key(&id) {
                    break id;
                }
            };
            pending.insert(id, tx);
            id
        };
        let _slot = Slot {
            state: &self.state,
            id,
        };
        let mut query = forward.upstream_query();
        query.metadata.id = id;
        pad(&mut query)?;
        let bytes = query.to_vec()?;
        {
            let mut writer = self.writer.lock().await;
            if write_frame(&mut *writer, &bytes).await.is_err() {
                self.state.close();
                return Err(ExchangeError::Closed);
            }
        }
        let frame = rx.await.map_err(|_| ExchangeError::Closed)?;
        let answer = Message::from_vec(&frame)?;
        if !forward.is_answer(&query, &answer) {
            return Err(ExchangeError::Mismatch);
        }
        Ok(answer)
    }
}

async fn read_loop(mut reader: ReadHalf<Stream>, state: Arc<State>) {
    loop {
        match tokio::time::timeout(IDLE, read_frame(&mut reader)).await {
            Ok(Ok(frame)) => {
                let Some(&[hi, lo]) = frame.get(..2) else {
                    continue;
                };
                let waiting = state.pending().remove(&u16::from_be_bytes([hi, lo]));
                if let Some(tx) = waiting {
                    let _ = tx.send(frame);
                }
            }
            // Closed by the server, or broken.
            Ok(Err(_)) => break,
            Err(_idle) if state.pending().is_empty() => break,
            Err(_idle) => {}
        }
    }
    state.close();
}
