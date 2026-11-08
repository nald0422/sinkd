//! Plain DNS: UDP, and TCP when the answer is truncated. Unencrypted, so
//! only the random ID and source port stand between it and an off-path
//! spoofer; the encrypted transports are the default.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

use hickory_proto::op::Message;
use tokio::net::{TcpStream, UdpSocket};

use super::ExchangeError;
use crate::engine::Forward;
use crate::wire::{read_frame, write_frame};

/// We advertise 1232 bytes; the slack is for servers that ignore that.
const RECV_BUF: usize = 4096;

pub(super) async fn exchange(
    server: SocketAddr,
    forward: &Forward,
) -> Result<Message, ExchangeError> {
    let answer = exchange_udp(server, forward).await?;
    if answer.metadata.truncation {
        return exchange_tcp(server, forward).await;
    }
    Ok(answer)
}

/// One query over a fresh UDP socket. The socket is connected, so the kernel
/// discards datagrams from any other address, and an ICMP "port unreachable"
/// fails the attempt at once instead of after the timeout.
async fn exchange_udp(server: SocketAddr, forward: &Forward) -> Result<Message, ExchangeError> {
    let query = forward.upstream_query();
    let bytes = query.to_vec()?;
    let local: SocketAddr = match server {
        SocketAddr::V4(_) => (Ipv4Addr::UNSPECIFIED, 0).into(),
        SocketAddr::V6(_) => (Ipv6Addr::UNSPECIFIED, 0).into(),
    };
    let socket = UdpSocket::bind(local).await?;
    socket.connect(server).await?;
    socket.send(&bytes).await?;
    let mut buf = vec![0; RECV_BUF];
    loop {
        let len = socket.recv(&mut buf).await?;
        // A forged or stray datagram is skipped, not fatal: giving up on it
        // would let an attacker deny service with a single packet.
        if let Some(datagram) = buf.get(..len)
            && let Ok(answer) = Message::from_vec(datagram)
            && forward.is_answer(&query, &answer)
        {
            return Ok(answer);
        }
    }
}

async fn exchange_tcp(server: SocketAddr, forward: &Forward) -> Result<Message, ExchangeError> {
    let query = forward.upstream_query();
    let bytes = query.to_vec()?;
    let mut stream = TcpStream::connect(server).await?;
    stream.set_nodelay(true)?;
    write_frame(&mut stream, &bytes).await?;
    loop {
        let frame = read_frame(&mut stream).await?;
        if let Ok(answer) = Message::from_vec(&frame)
            && forward.is_answer(&query, &answer)
        {
            return Ok(answer);
        }
    }
}
