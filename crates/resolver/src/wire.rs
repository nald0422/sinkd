//! DNS over TCP framing: each message is preceded by its length as a
//! two-byte big-endian integer (RFC 1035 §4.2.2).

use std::io;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub(crate) async fn read_frame<R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<Vec<u8>> {
    let len = reader.read_u16().await?;
    let mut message = vec![0; usize::from(len)];
    reader.read_exact(&mut message).await?;
    Ok(message)
}

/// Writes the length and the message in one write, so they leave in one
/// segment instead of two.
pub(crate) async fn write_frame<W: AsyncWrite + Unpin>(
    writer: &mut W,
    message: &[u8],
) -> io::Result<()> {
    let len = u16::try_from(message.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "DNS message over 65535 bytes"))?;
    let mut frame = Vec::with_capacity(2 + message.len());
    frame.extend_from_slice(&len.to_be_bytes());
    frame.extend_from_slice(message);
    writer.write_all(&frame).await
}
