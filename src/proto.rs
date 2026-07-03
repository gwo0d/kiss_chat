//! Length-prefixed framing over an iroh QUIC stream.
//!
//! Every message on the wire is `u32` big-endian length + that many payload
//! bytes. This is all the structure kiss_chat needs: the handshake sends two
//! frames, then every chat message is one sealed frame.

use anyhow::{Result, ensure};
use iroh::endpoint::{RecvStream, SendStream};

/// Maximum accepted frame size. The largest legitimate frame is the responder's
/// handshake message (ML-KEM ciphertext + ML-DSA key + signature, ~8.6 KiB); chat
/// lines are tiny. 64 KiB is comfortably above both and caps how much a peer can
/// make us allocate from a single length prefix.
const MAX_FRAME: usize = 64 * 1024;

/// Write one length-prefixed frame.
///
/// # Errors
///
/// Fails if `data` is larger than a `u32` length prefix can express, or the
/// underlying stream write fails.
pub async fn write_frame(send: &mut SendStream, data: &[u8]) -> Result<()> {
    let len = u32::try_from(data.len()).map_err(|_| anyhow::anyhow!("frame too large to send"))?;
    send.write_all(&len.to_be_bytes()).await?;
    send.write_all(data).await?;
    Ok(())
}

/// Read one length-prefixed frame.
///
/// # Errors
///
/// Fails if the stream ends before a full frame arrives, or the peer's length
/// prefix exceeds [`MAX_FRAME`].
pub async fn read_frame(recv: &mut RecvStream) -> Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    recv.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    ensure!(len <= MAX_FRAME, "peer sent oversized frame: {len} bytes");
    let mut buf = vec![0u8; len];
    recv.read_exact(&mut buf).await?;
    Ok(buf)
}
