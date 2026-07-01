//! iroh transport: bind an endpoint, dial a peer by key, or accept an inbound peer.
//!
//! iroh owns the hard parts of P2P — NAT traversal (hole-punching with relay
//! fallback) and dialing by public key via DNS discovery — so this module stays
//! tiny. It hands back the raw `(Connection, SendStream, RecvStream)`; the
//! post-quantum handshake and encryption live one layer up in [`crate::crypto`].

use anyhow::{Context, Result};
use iroh::endpoint::{Connection, RecvStream, SendStream, presets};
use iroh::{Endpoint, EndpointAddr};

/// Application-layer protocol identifier negotiated during the QUIC handshake.
pub const ALPN: &[u8] = b"kiss-chat/0";

/// Bind an endpoint using the N0 preset (relay + DNS discovery enabled), which
/// lets peers be reached by [`EndpointId`] alone.
pub async fn bind() -> Result<Endpoint> {
    Endpoint::builder(presets::N0)
        .alpns(vec![ALPN.to_vec()])
        .bind()
        .await
        .context("failed to bind iroh endpoint")
}

/// Dial `peer` (an [`EndpointId`] resolved via discovery, or a full
/// [`EndpointAddr`]) and open the single chat stream. We are the initiator, so we
/// must be the first to write to the stream (the caller sends the handshake's msg1).
///
/// [`EndpointId`]: iroh::EndpointId
pub async fn dial(
    endpoint: &Endpoint,
    peer: impl Into<EndpointAddr>,
) -> Result<(Connection, SendStream, RecvStream)> {
    let conn = endpoint
        .connect(peer, ALPN)
        .await
        .context("failed to connect to peer")?;
    let (send, recv) = conn.open_bi().await.context("failed to open stream")?;
    Ok((conn, send, recv))
}

/// Wait for one inbound peer and accept its chat stream. `accept_bi` returns once
/// the initiator has sent its first bytes (msg1).
pub async fn accept(endpoint: &Endpoint) -> Result<(Connection, SendStream, RecvStream)> {
    let incoming = endpoint.accept().await.context("endpoint closed")?;
    let conn = incoming.await.context("inbound handshake failed")?;
    let (send, recv) = conn.accept_bi().await.context("failed to accept stream")?;
    Ok((conn, send, recv))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{crypto, message, proto};
    use iroh::endpoint::presets;
    use std::time::Duration;

    // Bind a discovery-free, relay-free endpoint pinned to loopback so the test
    // runs entirely through localhost without touching any external network.
    async fn bind_local() -> Endpoint {
        Endpoint::builder(presets::Minimal)
            .alpns(vec![ALPN.to_vec()])
            .bind_addr("127.0.0.1:0")
            .expect("valid bind addr")
            .bind()
            .await
            .expect("bind local endpoint")
    }

    // Poll until the endpoint has published its direct socket addresses.
    async fn dialable_addr(endpoint: &Endpoint) -> EndpointAddr {
        for _ in 0..50 {
            let addr = endpoint.addr();
            if !addr.is_empty() {
                return addr;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("endpoint never became dialable");
    }

    /// Full stack over real iroh loopback: connect, hybrid handshake, and an
    /// encrypted round-trip through the framing layer.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn encrypted_echo_over_loopback() {
        let outcome = tokio::time::timeout(Duration::from_secs(30), async {
            let server = bind_local().await;
            let client = bind_local().await;
            let server_id = server.id();
            let server_addr = dialable_addr(&server).await;

            // Server: accept, run the responder handshake, echo one message.
            let server_task = tokio::spawn(async move {
                let (conn, mut send, mut recv) = accept(&server).await.unwrap();
                let peer = conn.remote_id();
                let msg1 = proto::read_frame(&mut recv).await.unwrap();
                let (session, msg2) =
                    crypto::responder_respond(&msg1, peer.as_bytes(), server.id().as_bytes())
                        .unwrap();
                proto::write_frame(&mut send, &msg2).await.unwrap();

                let (mut sealer, mut opener) = session.split();
                let plaintext = opener
                    .open(&proto::read_frame(&mut recv).await.unwrap())
                    .unwrap();
                proto::write_frame(&mut send, &sealer.seal(&plaintext).unwrap())
                    .await
                    .unwrap();
                // Stay alive until the client has the echo and closes; dropping
                // `conn` here would tear down QUIC before the (buffered) echo is
                // actually transmitted.
                conn.closed().await;
                String::from_utf8(plaintext).unwrap()
            });

            // Client: dial, run the initiator handshake, send + verify the echo.
            let (conn, mut send, mut recv) = dial(&client, server_addr).await.unwrap();
            let initiator = crypto::initiator_start();
            proto::write_frame(&mut send, initiator.msg1()).await.unwrap();
            let msg2 = proto::read_frame(&mut recv).await.unwrap();
            let session = initiator
                .finish(&msg2, client.id().as_bytes(), server_id.as_bytes())
                .unwrap();

            let (mut sealer, mut opener) = session.split();
            proto::write_frame(&mut send, &sealer.seal(b"ping over PQ").unwrap())
                .await
                .unwrap();
            let echo = opener
                .open(&proto::read_frame(&mut recv).await.unwrap())
                .unwrap();

            assert_eq!(echo, b"ping over PQ");
            conn.close(0u32.into(), b"done"); // release the server's `closed().await`
            assert_eq!(server_task.await.unwrap(), "ping over PQ");
        })
        .await;

        outcome.expect("test timed out — iroh could not connect over loopback");
    }

    /// The `Bye` control frame is delivered and decodes cleanly on the far side.
    /// This mirrors the app's graceful shutdown: the leaver sends `Bye`, then waits
    /// for the peer to receive it and close in response.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn goodbye_frame_is_received_over_loopback() {
        let outcome = tokio::time::timeout(Duration::from_secs(30), async {
            let server = bind_local().await;
            let client = bind_local().await;
            let server_id = server.id();
            let server_addr = dialable_addr(&server).await;

            // Server: handshake, read one frame, report whether it's a Bye, and
            // acknowledge so the client can drive delivery and learn we're done.
            let server_task = tokio::spawn(async move {
                let (conn, mut send, mut recv) = accept(&server).await.unwrap();
                let peer = conn.remote_id();
                let msg1 = proto::read_frame(&mut recv).await.unwrap();
                let (session, msg2) =
                    crypto::responder_respond(&msg1, peer.as_bytes(), server.id().as_bytes())
                        .unwrap();
                proto::write_frame(&mut send, &msg2).await.unwrap();

                let (mut sealer, mut opener) = session.split();
                let frame = proto::read_frame(&mut recv).await.unwrap();
                let is_bye = matches!(message::decode(&opener.open(&frame).unwrap()), message::Incoming::Bye);
                proto::write_frame(&mut send, &sealer.seal(b"ack").unwrap())
                    .await
                    .unwrap();
                conn.closed().await;
                is_bye
            });

            // Client: handshake, send a Bye, then read the ack (which confirms the
            // Bye was delivered) before closing.
            let (conn, mut send, mut recv) = dial(&client, server_addr).await.unwrap();
            let initiator = crypto::initiator_start();
            proto::write_frame(&mut send, initiator.msg1()).await.unwrap();
            let msg2 = proto::read_frame(&mut recv).await.unwrap();
            let session = initiator
                .finish(&msg2, client.id().as_bytes(), server_id.as_bytes())
                .unwrap();

            let (mut sealer, _opener) = session.split();
            let bye = sealer.seal(&message::encode(&message::Outgoing::Bye)).unwrap();
            proto::write_frame(&mut send, &bye).await.unwrap();
            let _ack = proto::read_frame(&mut recv).await.unwrap();
            conn.close(0u32.into(), b"done");

            assert!(server_task.await.unwrap(), "server should decode a Bye frame");
        })
        .await;

        outcome.expect("test timed out — iroh could not connect over loopback");
    }
}
