//! The frontend-neutral connection driver: dial or accept a peer, run the
//! post-quantum handshake, and pump encrypted frames to and from a session.
//!
//! Nothing here knows how the session is presented: every frontend — the terminal
//! one in [`crate::app`], and any other — drives these same tasks and consumes the
//! same [`NetEvent`]s, differing only in what it does with them. The dialer is
//! always the crypto *initiator*; the accepter the *responder*.
//!
//! The shape is deliberately channel-shaped rather than callback-shaped: every
//! task reports back through an `mpsc` sender, so a frontend's event loop can
//! `select!` over connection results, decrypted messages, and its own input
//! without holding any locks.

use std::time::Duration;

use iroh::endpoint::{Connection, RecvStream, SendStream};
use iroh::{Endpoint, EndpointAddr, EndpointId};
use tokio::sync::mpsc::{Sender, UnboundedReceiver, UnboundedSender};
use tokio::task::JoinHandle;

use kiss_chat_core::crypto::{Opener, Sealer, Session};
use kiss_chat_core::message::Outgoing;
use kiss_chat_core::{crypto, message, proto, transport};

/// How long to wait for a peer to acknowledge our goodbye before closing anyway.
pub const FAREWELL_TIMEOUT: Duration = Duration::from_secs(1);

/// How long a dial or an accepted connection may spend completing the handshake
/// before we give up. This bounds two things: a dial to an unresponsive peer (so
/// a frontend can't get stuck in "connecting…" with no way back to the lobby) and
/// a peer that connects but then stalls mid-handshake (so it can't tie up the
/// listener indefinitely). It does not cover the idle wait for a peer to appear.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

/// Capacity of the decrypted-network-event queue. Bounding it applies backpressure
/// to the reader task — and, through it, to the QUIC stream's own flow control — so
/// a peer flooding messages faster than the frontend can consume them can't grow
/// this queue without limit and exhaust memory.
pub const NET_EVENT_QUEUE: usize = 256;

/// An event flowing from the network tasks into a frontend.
pub enum NetEvent {
    /// A decrypted message from the peer.
    Message(String),
    /// The peer shared (or, with `None`, cleared) their display name.
    PeerName(Option<String>),
    /// The session ended; carries a human-readable reason.
    Disconnected(String),
}

/// A freshly established, encrypted session, handed from a handshake task to a
/// frontend's event loop.
pub struct Established {
    pub conn: Connection,
    pub send: SendStream,
    pub recv: RecvStream,
    pub session: Session,
    pub peer: EndpointId,
}

/// The handles for the currently connected session, held by a frontend's loop for
/// as long as the session lasts.
pub struct LiveSession {
    pub conn: Connection,
    pub outgoing_tx: UnboundedSender<Outgoing>,
    pub reader: JoinHandle<()>,
    pub writer: JoinHandle<()>,
    /// The peer's iroh address (as text) and long-term ML-DSA identity key, kept so
    /// that accepting can pin them to the contact list for trust-on-first-use.
    pub peer_id: String,
    pub peer_identity: Vec<u8>,
    /// The peer's display name once they share it this session, cached so it can be
    /// stored against their pin (for at-a-glance identification next time).
    pub peer_name: Option<String>,
}

/// The result of a connection attempt (dial or accept), reported to the loop.
pub enum ConnResult {
    Established(Box<Established>),
    /// A dial or accept failed. `from_accept` records which, so the loop knows
    /// whether the background *listener* died (and must be re-armed) or merely an
    /// outbound dial did (leaving the listener untouched).
    Failed {
        reason: String,
        from_accept: bool,
    },
}

/// Spawn a background task that waits for an incoming peer.
pub fn arm_accept(
    endpoint: &Endpoint,
    my_id: EndpointId,
    auth_seed: [u8; 32],
    conn_tx: &UnboundedSender<ConnResult>,
) -> JoinHandle<()> {
    tokio::spawn(accept_and_handshake(
        endpoint.clone(),
        my_id,
        auth_seed,
        conn_tx.clone(),
    ))
}

/// Spawn a background task that dials a peer.
///
/// `peer` is anything addressing an endpoint: an [`EndpointId`] to be resolved by
/// discovery, or a full [`EndpointAddr`] naming direct socket addresses (which
/// dials without discovery — how the loopback tests, and a headless caller given
/// explicit addresses, reach a peer).
pub fn spawn_dial(
    endpoint: &Endpoint,
    my_id: EndpointId,
    peer: impl Into<EndpointAddr>,
    auth_seed: [u8; 32],
    conn_tx: &UnboundedSender<ConnResult>,
) {
    tokio::spawn(dial_and_handshake(
        endpoint.clone(),
        my_id,
        peer.into(),
        auth_seed,
        conn_tx.clone(),
    ));
}

/// Announce departure to the peer and close down gracefully.
///
/// Sends a `Bye` frame, then waits (bounded) for the peer to receive it and close
/// in response — which both confirms delivery and keeps the connection alive long
/// enough for the frame to actually reach the wire.
pub async fn farewell(
    conn: Connection,
    outgoing_tx: UnboundedSender<Outgoing>,
    writer: JoinHandle<()>,
) {
    let _ = outgoing_tx.send(Outgoing::Bye);
    let _ = tokio::time::timeout(FAREWELL_TIMEOUT, conn.closed()).await;
    writer.abort();
    conn.close(0u32.into(), b"bye");
}

/// Dial a peer and run the initiator side of the handshake, reporting the result.
///
/// The whole attempt (connect + handshake) is bounded by [`HANDSHAKE_TIMEOUT`] so
/// an unresponsive peer can't leave a frontend stuck in "connecting…" forever.
async fn dial_and_handshake(
    endpoint: Endpoint,
    my_id: EndpointId,
    peer: EndpointAddr,
    auth_seed: [u8; 32],
    tx: UnboundedSender<ConnResult>,
) {
    // The transcript binds both EndpointIds, so keep the id even when we were
    // handed a full address to dial.
    let peer_id = peer.id;
    let attempt = async {
        let (conn, mut send, mut recv) = transport::dial(&endpoint, peer).await?;
        let identity = crypto::SigningIdentity::from_seed(&auth_seed);
        let initiator = crypto::initiator_start(identity);
        proto::write_frame(&mut send, initiator.msg1()).await?;
        let msg2 = proto::read_frame(&mut recv).await?;
        let (session, msg3) = initiator.finish(&msg2, my_id.as_bytes(), peer_id.as_bytes())?;
        proto::write_frame(&mut send, &msg3).await?;
        anyhow::Ok(Established {
            conn,
            send,
            recv,
            session,
            peer: peer_id,
        })
    };
    let result = match tokio::time::timeout(HANDSHAKE_TIMEOUT, attempt).await {
        Ok(Ok(established)) => ConnResult::Established(Box::new(established)),
        Ok(Err(err)) => ConnResult::Failed {
            reason: format!("could not connect: {err}"),
            from_accept: false,
        },
        Err(_) => ConnResult::Failed {
            reason: "could not connect: handshake timed out".into(),
            from_accept: false,
        },
    };
    let _ = tx.send(result);
}

/// Wait for an incoming peer and run the responder side of the handshake.
///
/// Only the handshake is time-boxed (by [`HANDSHAKE_TIMEOUT`]) — not the idle wait
/// for a peer to arrive — so a peer that connects and then stalls can't tie up the
/// listener indefinitely.
async fn accept_and_handshake(
    endpoint: Endpoint,
    my_id: EndpointId,
    auth_seed: [u8; 32],
    tx: UnboundedSender<ConnResult>,
) {
    let attempt = async {
        let (conn, mut send, mut recv) = transport::accept(&endpoint).await?;
        tokio::time::timeout(HANDSHAKE_TIMEOUT, async move {
            let peer = conn.remote_id();
            let identity = crypto::SigningIdentity::from_seed(&auth_seed);
            let msg1 = proto::read_frame(&mut recv).await?;
            let (pending, msg2) =
                crypto::responder_receive(&msg1, peer.as_bytes(), my_id.as_bytes(), identity)?;
            proto::write_frame(&mut send, &msg2).await?;
            let msg3 = proto::read_frame(&mut recv).await?;
            let session = pending.finish(&msg3)?;
            anyhow::Ok(Established {
                conn,
                send,
                recv,
                session,
                peer,
            })
        })
        .await
        .map_err(|_| anyhow::anyhow!("handshake timed out"))?
    };
    let _ = tx.send(match attempt.await {
        Ok(established) => ConnResult::Established(Box::new(established)),
        Err(err) => ConnResult::Failed {
            reason: format!("incoming connection failed: {err}"),
            from_accept: true,
        },
    });
}

/// Decrypt inbound frames and forward messages (or a disconnect) to the frontend.
///
/// `net_tx` is bounded, so a slow frontend stalls this `send`, which stops us
/// reading the next frame and lets QUIC flow control throttle a flooding peer.
pub fn spawn_reader(
    mut recv: RecvStream,
    mut opener: Opener,
    net_tx: Sender<NetEvent>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            let event = match proto::read_frame(&mut recv).await {
                Ok(ciphertext) => match opener.open(&ciphertext) {
                    Ok(plaintext) => match message::decode(&plaintext) {
                        message::Incoming::Text(text) => NetEvent::Message(text),
                        message::Incoming::Name(name) => NetEvent::PeerName(name),
                        message::Incoming::Bye => {
                            NetEvent::Disconnected("peer left the chat".into())
                        }
                        message::Incoming::Malformed => {
                            NetEvent::Disconnected("received a malformed message".into())
                        }
                    },
                    Err(err) => NetEvent::Disconnected(format!("connection lost: {err}")),
                },
                Err(err) => NetEvent::Disconnected(format!("connection lost: {err}")),
            };
            let done = matches!(event, NetEvent::Disconnected(_));
            if net_tx.send(event).await.is_err() || done {
                break;
            }
        }
    })
}

/// Encrypt outgoing messages from the frontend and send them as frames.
pub fn spawn_writer(
    mut send: SendStream,
    mut sealer: Sealer,
    mut outgoing_rx: UnboundedReceiver<Outgoing>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        while let Some(message) = outgoing_rx.recv().await {
            match sealer.seal(&message::encode(&message)) {
                Ok(ciphertext) => {
                    if proto::write_frame(&mut send, &ciphertext).await.is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    })
}
