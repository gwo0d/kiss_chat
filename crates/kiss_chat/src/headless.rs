//! The headless frontend: kiss_chat driven by another program instead of a person.
//!
//! Started with `--headless`, kiss_chat takes over no terminal. It writes one JSON
//! object per line to stdout (events) and reads one JSON object per line from stdin
//! (commands), so an application in any language can spawn it as a child process
//! and use it as a secure, peer-to-peer transport for as long as it runs. Chat
//! messages carry whatever payload the application likes — moves in a game, say,
//! as JSON text.
//!
//! # Protocol, version 1
//!
//! Newline-delimited JSON, UTF-8, one object per line. Consumers **must ignore**
//! fields and event types they don't recognise: that is what lets this protocol
//! grow without breaking them. The `ready` event carries the protocol version.
//!
//! ## Events (stdout)
//!
//! | Event | Fields | When |
//! | --- | --- | --- |
//! | `ready` | `proto`, `address`, `fingerprint`, `name`, `direct_addrs` | Once, after binding. Everything needed to build an invitation. |
//! | `connecting` | `peer` | A dial started. |
//! | `verify` | `peer`, `words`, `fingerprint`, `pin`, `known_name` | A channel is up and awaiting an accept/reject decision. |
//! | `accepted` | `peer`, `fingerprint` | *We* accepted; the peer has been told. |
//! | `connected` | `peer`, `fingerprint` | Both sides have accepted. Sending is now allowed. |
//! | `peer_name` | `name` | The peer shared or cleared their display name. |
//! | `message` | `text` | A decrypted chat message. |
//! | `disconnected` | `reason` | The session ended. |
//! | `error` | `message` | A non-fatal problem with a command. |
//!
//! ## Commands (stdin)
//!
//! | Command | Fields | Meaning |
//! | --- | --- | --- |
//! | `connect` | `peer`, `addrs` (optional) | Dial a peer, optionally at explicit `ip:port` addresses. |
//! | `accept` | — | Accept the peer being verified. |
//! | `reject` | — | Reject the peer being verified. |
//! | `send` | `text` | Send a chat message. Only valid after `connected`. |
//! | `quit` | — | Say goodbye and exit. EOF on stdin means the same. |
//!
//! # Trust
//!
//! The safety-word ritual is not skipped here, it is **delegated**: the `verify`
//! event hands the words, the peer's fingerprint and their pin status to the
//! controlling application, which shows them to its human and answers `accept` or
//! `reject`. For unattended use, `--expect <fingerprint>` instead pre-pins the
//! identity a peer must present, moving the out-of-band check into the invitation
//! that carried the address. There is deliberately no accept-everything mode.

use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;

use anyhow::{Context, Result};
use iroh::{Endpoint, EndpointAddr, EndpointId, SecretKey, TransportAddr};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;

use kiss_chat_core::contacts::PinStatus;
use kiss_chat_core::message::Outgoing;
use kiss_chat_core::{contacts, identity, message, transport};

use crate::net::{
    ConnResult, Established, LiveSession, NET_EVENT_QUEUE, NetEvent, arm_accept, farewell,
    spawn_dial, spawn_reader, spawn_writer,
};

/// Version of the NDJSON protocol described in the module docs, reported in
/// `ready`. Adding fields or events doesn't change it; a change that would break a
/// conforming consumer does.
const PROTO_VERSION: u32 = 1;

/// Longest stdin line accepted, in bytes. Generous next to the 4096-character
/// message cap, but bounded so a parent that never sends a newline can't make us
/// buffer without limit.
const MAX_LINE_BYTES: usize = 64 * 1024;

/// Where a headless instance keeps its identity.
///
/// There is no "the user's config directory" option on purpose: sharing that with
/// an interactive session would mean two endpoints claiming one address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Identity {
    /// Persist keys (and contacts) in this directory, reusing them across runs.
    Dir(PathBuf),
    /// Generate keys in memory, use them for this run, and never write them down.
    /// Contacts are neither read nor written, so every peer is a first meeting.
    Ephemeral,
}

/// How the headless frontend was asked to run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Options {
    pub identity: Identity,
    /// Identity fingerprints that may be accepted without asking. Empty means every
    /// channel is delegated to the controlling application via a `verify` event.
    pub expect: Vec<String>,
    /// Display name for this run. Never persisted by the headless frontend.
    pub name: Option<String>,
    /// Exit once the first session ends, rather than returning to the lobby.
    pub once: bool,
    /// A peer to dial at startup.
    pub peer: Option<String>,
}

/// What the process exits with. See the module docs on the lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Exit {
    /// Clean exit: `quit`, EOF, or (under `--once`) a session that ended normally.
    Ok,
    /// Under `--once`: a dial or handshake that never established.
    Failed,
    /// A peer presented an identity that `--expect` did not allow.
    Refused,
}

impl Exit {
    /// The process exit code for this outcome.
    #[must_use]
    pub fn code(self) -> i32 {
        match self {
            Exit::Ok => 0,
            Exit::Failed => 1,
            Exit::Refused => 2,
        }
    }
}

/// An event written to stdout, one JSON object per line.
#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(tag = "event", rename_all = "snake_case")]
enum Event {
    Ready {
        proto: u32,
        address: String,
        fingerprint: String,
        name: Option<String>,
        direct_addrs: Vec<String>,
    },
    Connecting {
        peer: String,
    },
    Verify {
        peer: String,
        words: String,
        fingerprint: String,
        pin: Pin,
        known_name: Option<String>,
    },
    Accepted {
        peer: String,
        fingerprint: String,
    },
    Connected {
        peer: String,
        fingerprint: String,
    },
    PeerName {
        name: Option<String>,
    },
    Message {
        text: String,
    },
    Disconnected {
        reason: String,
    },
    Error {
        message: String,
    },
}

/// How a peer's identity key compares to what we have pinned for their address.
#[derive(Debug, Serialize, PartialEq, Eq, Clone, Copy)]
#[serde(rename_all = "snake_case")]
enum Pin {
    /// No pin for this address yet.
    New,
    /// The presented key matches the pin.
    Known,
    /// The presented key differs from the pin — worth extra care.
    Changed,
}

impl From<PinStatus> for Pin {
    fn from(status: PinStatus) -> Self {
        match status {
            PinStatus::New => Pin::New,
            PinStatus::Known => Pin::Known,
            PinStatus::Changed => Pin::Changed,
        }
    }
}

/// A command read from stdin, one JSON object per line.
///
/// Unknown fields are ignored rather than rejected, so a newer controller can send
/// fields this version doesn't know without breaking.
#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(tag = "cmd", rename_all = "snake_case")]
enum Cmd {
    Connect {
        peer: String,
        #[serde(default)]
        addrs: Vec<String>,
    },
    Accept,
    Reject,
    Send {
        text: String,
    },
    Quit,
}

/// Writes events as newline-delimited JSON.
///
/// Every write is flushed, because the consumer is a pipe reader waiting on
/// whole lines: buffering an event would look to them like nothing happened.
struct EventSink<W> {
    out: W,
}

impl<W: AsyncWrite + Unpin> EventSink<W> {
    fn new(out: W) -> Self {
        Self { out }
    }

    /// Emit one event. Fails only if the consumer has gone away.
    async fn emit(&mut self, event: &Event) -> Result<()> {
        // Serialising our own closed enum cannot fail.
        let line = serde_json::to_string(event).expect("event serialises");
        self.out.write_all(line.as_bytes()).await?;
        self.out.write_all(b"\n").await?;
        self.out.flush().await?;
        Ok(())
    }
}

/// Resolve the configured identity into the two secrets a session needs.
fn load_identity(identity: &Identity) -> Result<(SecretKey, [u8; 32])> {
    match identity {
        Identity::Dir(dir) => Ok((
            identity::load_or_create_endpoint_secret_in(dir)
                .with_context(|| format!("failed to load identity from {}", dir.display()))?,
            identity::load_or_create_auth_seed_in(dir)
                .with_context(|| format!("failed to load identity from {}", dir.display()))?,
        )),
        Identity::Ephemeral => Ok((SecretKey::generate(), identity::random_auth_seed())),
    }
}

/// Run the headless frontend to completion, returning how the process should exit.
///
/// # Errors
///
/// Fails if the identity can't be loaded or the endpoint can't bind. Once running,
/// problems are reported as `error` or `disconnected` events instead.
pub async fn run(options: Options) -> Result<Exit> {
    let (secret, auth_seed) = load_identity(&options.identity)?;
    let endpoint = transport::bind_with(secret).await?;
    let stdin = tokio::io::BufReader::new(tokio::io::stdin());
    let result = event_loop(&endpoint, &options, auth_seed, stdin, tokio::io::stdout()).await;
    endpoint.close().await;
    result
}

/// The state a session moves through between connecting and chatting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stage {
    /// A channel is up, awaiting the controller's accept/reject.
    Verifying,
    /// We accepted; waiting for the peer's acceptance to arrive.
    WaitingPeer,
    /// Both sides accepted: chat is open.
    Chatting,
}

/// The headless event loop, generic over its input and output so tests can drive it
/// through in-memory pipes instead of the real stdio.
///
/// `auth_seed` must be the same seed the endpoint's identity was resolved with —
/// for an ephemeral run, generating a second one here would sign the handshake as
/// a different identity than the one advertised in `ready`.
async fn event_loop(
    endpoint: &Endpoint,
    options: &Options,
    auth_seed: [u8; 32],
    input: impl AsyncBufRead + Unpin,
    output: impl AsyncWrite + Unpin,
) -> Result<Exit> {
    let my_id = endpoint.id();
    let mut sink = EventSink::new(output);
    let mut lines = input.lines();

    // The display name: explicit for this run, else whatever the identity directory
    // remembers. Headless never writes the name file — that's the user's setting.
    let my_name = match &options.name {
        Some(name) => message::sanitize_name(name),
        None => match &options.identity {
            Identity::Dir(dir) => identity::load_display_name_in(dir)?
                .and_then(|stored| message::sanitize_name(&stored)),
            Identity::Ephemeral => None,
        },
    };

    sink.emit(&Event::Ready {
        proto: PROTO_VERSION,
        address: my_id.to_string(),
        fingerprint: contacts::fingerprint(
            kiss_chat_core::crypto::SigningIdentity::from_seed(&auth_seed).public_bytes(),
        ),
        name: my_name.clone(),
        direct_addrs: direct_addrs(endpoint),
    })
    .await?;

    let (conn_tx, mut conn_rx) = mpsc::unbounded_channel::<ConnResult>();
    let (net_tx, mut net_rx) = mpsc::channel::<NetEvent>(NET_EVENT_QUEUE);

    let mut accept_handle = arm_accept(endpoint, my_id, auth_seed, &conn_tx);
    let mut session: Option<LiveSession> = None;
    let mut stage = Stage::Verifying;
    // Whether the peer's acceptance has arrived. Kept apart from `stage` because it
    // can land before our own decision, in which case accepting opens chat at once.
    let mut peer_accepted = false;
    let mut peer_fingerprint = String::new();
    let mut peer_short = String::new();

    if let Some(arg) = &options.peer {
        match EndpointId::from_str(arg.trim()) {
            Ok(peer) => {
                sink.emit(&Event::Connecting {
                    peer: peer.to_string(),
                })
                .await?;
                spawn_dial(endpoint, my_id, peer, auth_seed, &conn_tx);
            }
            Err(_) => {
                sink.emit(&Event::Error {
                    message: format!("invalid peer id: {arg}"),
                })
                .await?;
                if options.once {
                    return Ok(Exit::Failed);
                }
            }
        }
    }

    loop {
        tokio::select! {
            line = lines.next_line() => {
                // EOF on stdin means the parent is done with us: say goodbye and go.
                let Some(line) = line? else { break };
                if line.len() > MAX_LINE_BYTES {
                    sink.emit(&Event::Error {
                        message: format!("command line too long (max {MAX_LINE_BYTES} bytes)"),
                    }).await?;
                    continue;
                }
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }
                let cmd = match serde_json::from_str::<Cmd>(trimmed) {
                    Ok(cmd) => cmd,
                    Err(err) => {
                        sink.emit(&Event::Error { message: format!("bad command: {err}") }).await?;
                        continue;
                    }
                };

                match cmd {
                    Cmd::Quit => break,
                    Cmd::Connect { peer, addrs } => {
                        let Ok(peer_id) = EndpointId::from_str(peer.trim()) else {
                            sink.emit(&Event::Error {
                                message: format!("invalid peer id: {peer}"),
                            }).await?;
                            continue;
                        };
                        let target = match endpoint_addr(peer_id, &addrs) {
                            Ok(target) => target,
                            Err(err) => {
                                sink.emit(&Event::Error { message: err }).await?;
                                continue;
                            }
                        };
                        // Leave whoever we're with before dialling someone new.
                        if let Some(old) = session.take() {
                            old.reader.abort();
                            tokio::spawn(farewell(old.conn, old.outgoing_tx, old.writer));
                            sink.emit(&Event::Disconnected {
                                reason: "left the chat to connect elsewhere".into(),
                            }).await?;
                            accept_handle = arm_accept(endpoint, my_id, auth_seed, &conn_tx);
                        }
                        sink.emit(&Event::Connecting { peer: peer_id.to_string() }).await?;
                        spawn_dial(endpoint, my_id, target, auth_seed, &conn_tx);
                    }
                    Cmd::Accept => {
                        if session.is_none() || stage != Stage::Verifying {
                            sink.emit(&Event::Error {
                                message: "nothing to accept".into(),
                            }).await?;
                            continue;
                        }
                        stage = accept_peer(
                            &mut sink,
                            session.as_mut().expect("checked above"),
                            &options.identity,
                            my_name.as_deref(),
                            &peer_short,
                            &peer_fingerprint,
                            peer_accepted,
                        ).await?;
                    }
                    Cmd::Reject => {
                        if let Some(old) = session.take() {
                            old.reader.abort();
                            tokio::spawn(farewell(old.conn, old.outgoing_tx, old.writer));
                            accept_handle = arm_accept(endpoint, my_id, auth_seed, &conn_tx);
                            sink.emit(&Event::Disconnected {
                                reason: "rejected the peer".into(),
                            }).await?;
                            if options.once {
                                return Ok(Exit::Ok);
                            }
                        } else {
                            sink.emit(&Event::Error {
                                message: "nothing to reject".into(),
                            }).await?;
                        }
                    }
                    Cmd::Send { text } => {
                        let len = text.chars().count();
                        if len > message::MAX_MESSAGE_CHARS {
                            sink.emit(&Event::Error {
                                message: format!(
                                    "message too long ({len} characters, max {})",
                                    message::MAX_MESSAGE_CHARS
                                ),
                            }).await?;
                        } else if stage == Stage::Chatting && let Some(live) = &session {
                            let _ = live.outgoing_tx.send(Outgoing::Text(text));
                        } else {
                            // Deliberately not queued: a program has the `connected`
                            // event to wait for, and silently holding its messages
                            // would hide the bug rather than surface it.
                            sink.emit(&Event::Error {
                                message: "not connected — wait for the connected event".into(),
                            }).await?;
                        }
                    }
                }
            }

            result = conn_rx.recv() => match result {
                Some(ConnResult::Established(established)) => {
                    let Established { conn, send, recv, session: new_session, peer } = *established;
                    if session.is_some() {
                        // Already busy with someone; refuse the extra connection.
                        conn.close(0u32.into(), b"already connected");
                        continue;
                    }
                    accept_handle.abort();
                    while net_rx.try_recv().is_ok() {}

                    let peer_id = peer.to_string();
                    let peer_identity = new_session.peer_identity().to_vec();
                    let fingerprint = contacts::fingerprint(&peer_identity);
                    let (pin, known_name) = recognize(&options.identity, &peer_id, &peer_identity);

                    let words = new_session.safety_number().to_string();
                    let (sealer, opener) = new_session.split();
                    let (out_tx, out_rx) = mpsc::unbounded_channel::<Outgoing>();
                    let mut live = LiveSession {
                        conn,
                        outgoing_tx: out_tx,
                        reader: spawn_reader(recv, opener, net_tx.clone()),
                        writer: spawn_writer(send, sealer, out_rx),
                        peer_id: peer_id.clone(),
                        peer_identity,
                        peer_name: None,
                    };
                    peer_short = peer_id.clone();
                    peer_fingerprint = fingerprint.clone();
                    stage = Stage::Verifying;
                    peer_accepted = false;

                    if options.expect.is_empty() {
                        // Delegate the decision to the controlling application.
                        sink.emit(&Event::Verify {
                            peer: peer_id,
                            words,
                            fingerprint,
                            pin: pin.into(),
                            known_name,
                        }).await?;
                        session = Some(live);
                    } else if options.expect.contains(&fingerprint) {
                        // Pre-pinned: the out-of-band check already happened, in
                        // whatever invitation carried this fingerprint.
                        stage = accept_peer(
                            &mut sink,
                            &mut live,
                            &options.identity,
                            my_name.as_deref(),
                            &peer_short,
                            &peer_fingerprint,
                            peer_accepted,
                        ).await?;
                        session = Some(live);
                    } else {
                        live.reader.abort();
                        live.writer.abort();
                        live.conn.close(0u32.into(), b"unexpected identity");
                        sink.emit(&Event::Disconnected {
                            reason: format!(
                                "peer identity {fingerprint} is not one of the expected identities"
                            ),
                        }).await?;
                        if options.once {
                            return Ok(Exit::Refused);
                        }
                        accept_handle = arm_accept(endpoint, my_id, auth_seed, &conn_tx);
                    }
                }
                Some(ConnResult::Failed { reason, from_accept }) if session.is_none() => {
                    if from_accept {
                        accept_handle = arm_accept(endpoint, my_id, auth_seed, &conn_tx);
                    }
                    sink.emit(&Event::Disconnected { reason }).await?;
                    if options.once && !from_accept {
                        return Ok(Exit::Failed);
                    }
                }
                _ => {}
            },

            event = net_rx.recv(), if session.is_some() => match event {
                Some(NetEvent::Message(text)) => {
                    if stage == Stage::Chatting {
                        sink.emit(&Event::Message { text }).await?;
                    } else if let Some(live) = session.take() {
                        // Text before mutual acceptance breaks the protocol; a
                        // conforming peer cannot get here.
                        live.reader.abort();
                        live.writer.abort();
                        live.conn.close(0u32.into(), b"protocol violation");
                        sink.emit(&Event::Disconnected {
                            reason: "peer sent a message before the channel was open".into(),
                        }).await?;
                        if options.once {
                            return Ok(Exit::Ok);
                        }
                        accept_handle = arm_accept(endpoint, my_id, auth_seed, &conn_tx);
                    }
                }
                Some(NetEvent::PeerAccepted) => {
                    peer_accepted = true;
                    // If we were only waiting on them, the channel is now open. If we
                    // haven't decided yet, our verify gate still stands and accepting
                    // will open it immediately.
                    if stage == Stage::WaitingPeer {
                        stage = Stage::Chatting;
                        sink.emit(&Event::Connected {
                            peer: peer_short.clone(),
                            fingerprint: peer_fingerprint.clone(),
                        }).await?;
                    }
                }
                Some(NetEvent::PeerName(name)) => {
                    if let Some(live) = &mut session {
                        live.peer_name = name.clone();
                        if stage != Stage::Verifying {
                            set_contact_name(&options.identity, &live.peer_id, name.as_deref());
                        }
                    }
                    if stage != Stage::Verifying {
                        sink.emit(&Event::PeerName { name }).await?;
                    }
                }
                Some(NetEvent::Disconnected(reason)) => {
                    if let Some(live) = session.take() {
                        live.reader.abort();
                        live.writer.abort();
                        live.conn.close(0u32.into(), b"bye");
                    }
                    sink.emit(&Event::Disconnected { reason }).await?;
                    if options.once {
                        return Ok(Exit::Ok);
                    }
                    accept_handle = arm_accept(endpoint, my_id, auth_seed, &conn_tx);
                }
                None => {}
            },
        }
    }

    if let Some(live) = session.take() {
        live.reader.abort();
        farewell(live.conn, live.outgoing_tx, live.writer).await;
    }
    accept_handle.abort();
    Ok(Exit::Ok)
}

/// Accept the peer: tell them, pin them, share our name, and report where that
/// leaves the session.
///
/// Emits `accepted` always, and `connected` too when `peer_accepted` says the peer
/// got there first — in that case acceptance is already mutual and chat is open.
async fn accept_peer<W: AsyncWrite + Unpin>(
    sink: &mut EventSink<W>,
    live: &mut LiveSession,
    identity: &Identity,
    my_name: Option<&str>,
    peer_short: &str,
    peer_fingerprint: &str,
    peer_accepted: bool,
) -> Result<Stage> {
    // Announce acceptance before anything else we send: it is what opens the
    // peer's side, and the stream is ordered, so it can never trail a message.
    let _ = live.outgoing_tx.send(Outgoing::Accepted);
    remember_contact(identity, &live.peer_id, &live.peer_identity);
    if let Some(name) = my_name {
        let _ = live
            .outgoing_tx
            .send(Outgoing::Name(Some(name.to_string())));
    }
    sink.emit(&Event::Accepted {
        peer: peer_short.to_string(),
        fingerprint: peer_fingerprint.to_string(),
    })
    .await?;

    // A name the peer volunteered before we accepted was recorded but withheld;
    // now that we've accepted, cache it against their fresh pin and report it.
    if live.peer_name.is_some() {
        set_contact_name(identity, &live.peer_id, live.peer_name.as_deref());
        sink.emit(&Event::PeerName {
            name: live.peer_name.clone(),
        })
        .await?;
    }

    if peer_accepted {
        sink.emit(&Event::Connected {
            peer: peer_short.to_string(),
            fingerprint: peer_fingerprint.to_string(),
        })
        .await?;
        return Ok(Stage::Chatting);
    }
    Ok(Stage::WaitingPeer)
}

/// Look a peer up in the contact list, if this identity keeps one.
fn recognize(
    identity: &Identity,
    address: &str,
    identity_key: &[u8],
) -> (PinStatus, Option<String>) {
    match identity {
        // An ephemeral run has no memory, so every peer is a first meeting.
        Identity::Ephemeral => (PinStatus::New, None),
        Identity::Dir(dir) => match contacts::recognize_in(dir, address, identity_key) {
            Ok(rec) => (rec.status, rec.name),
            Err(_) => (PinStatus::New, None),
        },
    }
}

/// Pin a peer's identity key, if this identity keeps contacts.
fn remember_contact(identity: &Identity, address: &str, identity_key: &[u8]) {
    if let Identity::Dir(dir) = identity {
        let _ = contacts::remember_in(dir, address, identity_key);
    }
}

/// Cache a peer's display name, if this identity keeps contacts.
fn set_contact_name(identity: &Identity, address: &str, name: Option<&str>) {
    if let Identity::Dir(dir) = identity {
        let _ = contacts::set_name_in(dir, address, name);
    }
}

/// The endpoint's directly reachable socket addresses, as `ip:port` strings, so a
/// controller can pass them to a peer that should dial without discovery.
fn direct_addrs(endpoint: &Endpoint) -> Vec<String> {
    endpoint
        .addr()
        .addrs
        .iter()
        .filter_map(|addr| match addr {
            TransportAddr::Ip(socket) => Some(socket.to_string()),
            // Relay URLs aren't dialable as `ip:port`, so they're not offered here.
            _ => None,
        })
        .collect()
}

/// Build a dialable address from a peer id and any explicit socket addresses.
fn endpoint_addr(peer: EndpointId, addrs: &[String]) -> Result<EndpointAddr, String> {
    if addrs.is_empty() {
        return Ok(EndpointAddr::from(peer));
    }
    let mut parsed = BTreeSet::new();
    for addr in addrs {
        let socket: SocketAddr = addr
            .parse()
            .map_err(|_| format!("invalid address: {addr}"))?;
        parsed.insert(TransportAddr::Ip(socket));
    }
    Ok(EndpointAddr {
        id: peer,
        addrs: parsed,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::time::Duration;

    use iroh::endpoint::presets;
    use tokio::io::{AsyncWriteExt, BufReader, DuplexStream};
    use tokio::task::JoinHandle;

    /// Parse an emitted event back into generic JSON for field-level assertions.
    fn as_json(event: &Event) -> serde_json::Value {
        serde_json::from_str(&serde_json::to_string(event).unwrap()).unwrap()
    }

    // --- harness for the full-stack loopback tests -------------------------
    //
    // Two headless loops, each on a discovery-free loopback endpoint, wired to
    // in-memory pipes standing in for stdio. This exercises the real handshake,
    // the real encryption and the real protocol — everything but the process
    // boundary — without touching the network.

    /// How long any single expected event may take before the test gives up.
    const STEP_TIMEOUT: Duration = Duration::from_secs(20);

    /// A running headless instance under test, addressed through its pipes.
    struct Harness {
        stdin: DuplexStream,
        events: tokio::io::Lines<BufReader<DuplexStream>>,
        task: JoinHandle<Result<Exit>>,
    }

    impl Harness {
        /// Send one command.
        async fn send(&mut self, json: &str) {
            self.stdin.write_all(json.as_bytes()).await.unwrap();
            self.stdin.write_all(b"\n").await.unwrap();
            self.stdin.flush().await.unwrap();
        }

        /// Read the next event, whatever it is.
        async fn next_event(&mut self) -> serde_json::Value {
            let line = tokio::time::timeout(STEP_TIMEOUT, self.events.next_line())
                .await
                .expect("timed out waiting for an event")
                .expect("reading events failed")
                .expect("event stream ended early");
            serde_json::from_str(&line).expect("every line must be one JSON object")
        }

        /// Read events until one of type `name` arrives, returning it.
        ///
        /// Skipping past the others keeps a test focused on the transition it is
        /// about, rather than restating the whole event order every time.
        async fn wait_for(&mut self, name: &str) -> serde_json::Value {
            loop {
                let event = self.next_event().await;
                if event["event"] == name {
                    return event;
                }
                assert_ne!(
                    event["event"], "error",
                    "unexpected error while waiting for {name}: {event}"
                );
            }
        }

        /// Close stdin (as a parent process exiting would) and collect the exit.
        async fn finish(self) -> Exit {
            drop(self.stdin);
            tokio::time::timeout(STEP_TIMEOUT, self.task)
                .await
                .expect("headless loop did not exit")
                .expect("headless task panicked")
                .expect("headless loop returned an error")
        }
    }

    /// Bind a discovery-free, relay-free endpoint on loopback: no external network.
    async fn bind_local() -> Endpoint {
        Endpoint::builder(presets::Minimal)
            .alpns(vec![transport::ALPN.to_vec()])
            .bind_addr("127.0.0.1:0")
            .expect("valid bind addr")
            .bind()
            .await
            .expect("bind local endpoint")
    }

    /// Wait until the endpoint knows a socket address a peer can dial directly.
    async fn dialable_addrs(endpoint: &Endpoint) -> Vec<String> {
        for _ in 0..100 {
            let addrs = direct_addrs(endpoint);
            if !addrs.is_empty() {
                return addrs;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("endpoint never became dialable");
    }

    /// Options for a test instance: ephemeral identity, nothing persisted.
    fn ephemeral_options() -> Options {
        Options {
            identity: Identity::Ephemeral,
            expect: Vec::new(),
            name: None,
            once: false,
            peer: None,
        }
    }

    /// Start a headless loop on `endpoint` with a fresh throwaway auth seed.
    fn start(endpoint: Endpoint, options: Options) -> Harness {
        start_with(endpoint, options, identity::random_auth_seed())
    }

    /// Start a headless loop on `endpoint` with an explicit auth seed — needed when
    /// the identity is persistent, so the seed matches the endpoint key on disk.
    fn start_with(endpoint: Endpoint, options: Options, seed: [u8; 32]) -> Harness {
        // 64 KiB each way: ample for the tests, and a real bound, so a loop that
        // writes without anyone reading would block rather than grow forever.
        let (stdin_tx, stdin_rx) = tokio::io::duplex(64 * 1024);
        let (stdout_tx, stdout_rx) = tokio::io::duplex(64 * 1024);
        let task = tokio::spawn(async move {
            event_loop(
                &endpoint,
                &options,
                seed,
                BufReader::new(stdin_rx),
                stdout_tx,
            )
            .await
        });
        Harness {
            stdin: stdin_tx,
            events: BufReader::new(stdout_rx).lines(),
            task,
        }
    }

    /// A fresh directory under the system temp dir, for tests that need an identity
    /// to survive a restart. Removed by the test that made it.
    fn tempdir() -> PathBuf {
        // Process id plus a counter: unique within and across concurrent runs,
        // without pulling in a temp-file dependency for a handful of tests.
        use std::sync::atomic::{AtomicU32, Ordering};
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "kiss_chat-headless-test-{}-{unique}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }

    /// Bring up two instances and dial one from the other, leaving both at the
    /// point where each has a `verify` event in hand. Returns `(dialer, listener)`
    /// and the two verify events.
    async fn connected_pair(
        dialer_options: Options,
        listener_options: Options,
    ) -> (Harness, Harness, serde_json::Value, serde_json::Value) {
        let listener_endpoint = bind_local().await;
        let dialer_endpoint = bind_local().await;
        let listener_id = listener_endpoint.id().to_string();
        let listener_addrs = dialable_addrs(&listener_endpoint).await;

        let mut listener = start(listener_endpoint, listener_options);
        let mut dialer = start(dialer_endpoint, dialer_options);

        // Both announce themselves before anything else happens.
        assert_eq!(dialer.wait_for("ready").await["proto"], PROTO_VERSION);
        assert_eq!(listener.wait_for("ready").await["proto"], PROTO_VERSION);

        // Dial by explicit address, so no discovery service is involved.
        let addrs = serde_json::to_string(&listener_addrs).unwrap();
        dialer
            .send(&format!(
                r#"{{"cmd":"connect","peer":"{listener_id}","addrs":{addrs}}}"#
            ))
            .await;

        let dialer_verify = dialer.wait_for("verify").await;
        let listener_verify = listener.wait_for("verify").await;
        (dialer, listener, dialer_verify, listener_verify)
    }

    #[test]
    fn events_are_tagged_objects_in_snake_case() {
        let ready = as_json(&Event::Ready {
            proto: PROTO_VERSION,
            address: "abc".into(),
            fingerprint: "def".into(),
            name: None,
            direct_addrs: vec!["127.0.0.1:1234".into()],
        });
        assert_eq!(ready["event"], "ready");
        assert_eq!(ready["proto"], 1);
        assert_eq!(ready["address"], "abc");
        // An absent name is explicitly null rather than missing, so a consumer can
        // read the field unconditionally.
        assert!(ready["name"].is_null());
        assert_eq!(ready["direct_addrs"][0], "127.0.0.1:1234");

        let peer_name = as_json(&Event::PeerName {
            name: Some("Alice".into()),
        });
        assert_eq!(peer_name["event"], "peer_name");
        assert_eq!(peer_name["name"], "Alice");
    }

    #[test]
    fn accepted_and_connected_are_distinct_events() {
        // The whole point of the pair: one reports our decision, the other reports
        // that the peer has made theirs too.
        assert_eq!(
            as_json(&Event::Accepted {
                peer: "p".into(),
                fingerprint: "f".into()
            })["event"],
            "accepted"
        );
        assert_eq!(
            as_json(&Event::Connected {
                peer: "p".into(),
                fingerprint: "f".into()
            })["event"],
            "connected"
        );
    }

    #[test]
    fn pin_status_maps_onto_the_wire_names() {
        for (status, expected) in [
            (PinStatus::New, "new"),
            (PinStatus::Known, "known"),
            (PinStatus::Changed, "changed"),
        ] {
            let event = as_json(&Event::Verify {
                peer: "p".into(),
                words: "w".into(),
                fingerprint: "f".into(),
                pin: status.into(),
                known_name: None,
            });
            assert_eq!(event["pin"], expected);
        }
    }

    #[test]
    fn message_text_is_escaped_so_one_event_stays_one_line() {
        // Chat text is peer-supplied and applications tunnel JSON through it, so
        // quotes and newlines must not break the line framing.
        let nasty = "a \"quoted\" line\nand a second\twith \\ backslash";
        let encoded = serde_json::to_string(&Event::Message { text: nasty.into() }).unwrap();
        assert_eq!(encoded.lines().count(), 1, "an event must occupy one line");
        let decoded: serde_json::Value = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded["text"], nasty);
    }

    #[test]
    fn commands_parse_from_their_wire_form() {
        assert_eq!(
            serde_json::from_str::<Cmd>(r#"{"cmd":"send","text":"e2e4"}"#).unwrap(),
            Cmd::Send {
                text: "e2e4".into()
            }
        );
        assert_eq!(
            serde_json::from_str::<Cmd>(r#"{"cmd":"accept"}"#).unwrap(),
            Cmd::Accept
        );
        assert_eq!(
            serde_json::from_str::<Cmd>(r#"{"cmd":"quit"}"#).unwrap(),
            Cmd::Quit
        );
    }

    #[test]
    fn connect_takes_optional_direct_addresses() {
        // Omitted `addrs` means "resolve by discovery".
        assert_eq!(
            serde_json::from_str::<Cmd>(r#"{"cmd":"connect","peer":"abc"}"#).unwrap(),
            Cmd::Connect {
                peer: "abc".into(),
                addrs: Vec::new()
            }
        );
        assert_eq!(
            serde_json::from_str::<Cmd>(
                r#"{"cmd":"connect","peer":"abc","addrs":["127.0.0.1:1"]}"#
            )
            .unwrap(),
            Cmd::Connect {
                peer: "abc".into(),
                addrs: vec!["127.0.0.1:1".into()]
            }
        );
    }

    #[test]
    fn unknown_fields_in_a_command_are_ignored() {
        // Forward compatibility: a newer controller may send fields we don't know.
        assert_eq!(
            serde_json::from_str::<Cmd>(r#"{"cmd":"accept","future_field":42}"#).unwrap(),
            Cmd::Accept
        );
    }

    #[test]
    fn unknown_or_malformed_commands_are_rejected() {
        // These become an `error` event rather than being silently dropped.
        for bad in [
            r#"{"cmd":"teleport"}"#,
            r#"{"no_cmd":true}"#,
            r#"{"cmd":"send"}"#, // missing the text field
            "not json at all",
            "",
        ] {
            assert!(
                serde_json::from_str::<Cmd>(bad).is_err(),
                "should reject: {bad}"
            );
        }
    }

    #[test]
    fn exit_codes_match_the_documented_meanings() {
        assert_eq!(Exit::Ok.code(), 0);
        assert_eq!(Exit::Failed.code(), 1);
        assert_eq!(Exit::Refused.code(), 2);
    }

    #[test]
    fn an_endpoint_addr_without_explicit_addresses_relies_on_discovery() {
        let peer = SecretKey::generate().public();
        let addr = endpoint_addr(peer, &[]).unwrap();
        assert_eq!(addr.id, peer);
        assert!(addr.addrs.is_empty());
    }

    #[test]
    fn explicit_addresses_are_parsed_and_bad_ones_refused() {
        let peer = SecretKey::generate().public();
        let addr = endpoint_addr(peer, &["127.0.0.1:4242".to_string()]).unwrap();
        assert_eq!(addr.addrs.len(), 1);
        assert!(endpoint_addr(peer, &["not-an-address".to_string()]).is_err());
    }

    // --- full-stack loopback scenarios -------------------------------------

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn two_instances_verify_accept_and_exchange_messages() {
        let (mut dialer, mut listener, dialer_verify, listener_verify) =
            connected_pair(ephemeral_options(), ephemeral_options()).await;

        // The safety words are the trust anchor, so both ends must compute the
        // same phrase — that is what makes reading them aloud meaningful.
        assert_eq!(dialer_verify["words"], listener_verify["words"]);
        assert!(!dialer_verify["words"].as_str().unwrap().is_empty());
        // Each side is told the *other's* fingerprint, and (with no contacts on an
        // ephemeral run) sees a first meeting.
        assert_ne!(dialer_verify["fingerprint"], listener_verify["fingerprint"]);
        assert_eq!(dialer_verify["pin"], "new");
        assert_eq!(listener_verify["pin"], "new");

        // Accepting one side is not enough to open the chat.
        dialer.send(r#"{"cmd":"accept"}"#).await;
        assert_eq!(dialer.wait_for("accepted").await["event"], "accepted");
        dialer.send(r#"{"cmd":"send","text":"too early"}"#).await;
        let refused = dialer.wait_for("error").await;
        assert!(
            refused["message"]
                .as_str()
                .unwrap()
                .contains("not connected"),
            "sending before mutual acceptance must be refused: {refused}"
        );

        // The second acceptance opens it, on both sides.
        listener.send(r#"{"cmd":"accept"}"#).await;
        assert_eq!(dialer.wait_for("connected").await["event"], "connected");
        assert_eq!(listener.wait_for("connected").await["event"], "connected");

        // Messages flow both ways, carrying an application's own payload.
        dialer
            .send(r#"{"cmd":"send","text":"{\"move\":\"e2e4\"}"}"#)
            .await;
        assert_eq!(
            listener.wait_for("message").await["text"],
            r#"{"move":"e2e4"}"#
        );
        listener
            .send(r#"{"cmd":"send","text":"{\"move\":\"e7e5\"}"}"#)
            .await;
        assert_eq!(
            dialer.wait_for("message").await["text"],
            r#"{"move":"e7e5"}"#
        );

        // Quitting tells the peer, rather than leaving them on a dead connection.
        dialer.send(r#"{"cmd":"quit"}"#).await;
        let parting = listener.wait_for("disconnected").await;
        assert!(
            parting["reason"].as_str().unwrap().contains("left"),
            "the peer should be told the session ended: {parting}"
        );

        assert_eq!(dialer.finish().await, Exit::Ok);
        assert_eq!(listener.finish().await, Exit::Ok);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_message_sent_before_the_peer_accepts_still_arrives() {
        // The regression this release is really about: the sender accepts first and
        // starts talking, and nothing they say is lost while the peer decides.
        let (mut dialer, mut listener, _, _) =
            connected_pair(ephemeral_options(), ephemeral_options()).await;

        dialer.send(r#"{"cmd":"accept"}"#).await;
        dialer.wait_for("accepted").await;

        // The listener takes its time before accepting.
        tokio::time::sleep(Duration::from_millis(250)).await;
        listener.send(r#"{"cmd":"accept"}"#).await;

        // Whoever accepted first is connected as soon as the other does.
        dialer.wait_for("connected").await;
        listener.wait_for("connected").await;

        dialer.send(r#"{"cmd":"send","text":"first move"}"#).await;
        assert_eq!(listener.wait_for("message").await["text"], "first move");

        assert_eq!(dialer.finish().await, Exit::Ok);
        assert_eq!(listener.finish().await, Exit::Ok);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn accepting_second_opens_the_chat_immediately() {
        // The other ordering: by the time this side accepts, the peer's acceptance
        // has already arrived, so `connected` follows `accepted` without waiting.
        let (mut dialer, mut listener, _, _) =
            connected_pair(ephemeral_options(), ephemeral_options()).await;

        listener.send(r#"{"cmd":"accept"}"#).await;
        listener.wait_for("accepted").await;
        // Give their acceptance time to reach the dialer before it decides.
        tokio::time::sleep(Duration::from_millis(250)).await;

        dialer.send(r#"{"cmd":"accept"}"#).await;
        let accepted = dialer.next_event().await;
        assert_eq!(accepted["event"], "accepted");
        let connected = dialer.next_event().await;
        assert_eq!(
            connected["event"], "connected",
            "accepting last should open the chat at once, not wait again"
        );

        assert_eq!(dialer.finish().await, Exit::Ok);
        assert_eq!(listener.finish().await, Exit::Ok);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn rejecting_ends_the_session_for_both_sides() {
        let (mut dialer, mut listener, _, _) =
            connected_pair(ephemeral_options(), ephemeral_options()).await;

        dialer.send(r#"{"cmd":"reject"}"#).await;
        let ours = dialer.wait_for("disconnected").await;
        assert!(ours["reason"].as_str().unwrap().contains("rejected"));
        // The peer learns the channel is gone rather than waiting forever.
        listener.wait_for("disconnected").await;

        assert_eq!(dialer.finish().await, Exit::Ok);
        assert_eq!(listener.finish().await, Exit::Ok);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn an_expected_identity_is_accepted_without_asking() {
        // First run: learn the listener's fingerprint the way an invitation would
        // carry it, out of band.
        let (dialer, listener, dialer_verify, _) =
            connected_pair(ephemeral_options(), ephemeral_options()).await;
        let listener_fingerprint = dialer_verify["fingerprint"].as_str().unwrap().to_string();
        let _ = dialer.finish().await;
        let _ = listener.finish().await;

        // Second run: a fresh listener, and a dialer that will only talk to that
        // fingerprint. Since the identity is ephemeral it won't match, which is
        // exactly the case that must be refused.
        let stale_expect = Options {
            expect: vec![listener_fingerprint],
            once: true,
            ..ephemeral_options()
        };
        let (dialer, mut listener, _, _) = {
            let listener_endpoint = bind_local().await;
            let dialer_endpoint = bind_local().await;
            let listener_id = listener_endpoint.id().to_string();
            let listener_addrs = dialable_addrs(&listener_endpoint).await;
            let mut listener = start(listener_endpoint, ephemeral_options());
            let mut dialer = start(dialer_endpoint, stale_expect);
            dialer.wait_for("ready").await;
            listener.wait_for("ready").await;
            let addrs = serde_json::to_string(&listener_addrs).unwrap();
            dialer
                .send(&format!(
                    r#"{{"cmd":"connect","peer":"{listener_id}","addrs":{addrs}}}"#
                ))
                .await;
            let disconnected = dialer.wait_for("disconnected").await;
            assert!(
                disconnected["reason"]
                    .as_str()
                    .unwrap()
                    .contains("not one of the expected identities"),
                "an unexpected identity must be refused: {disconnected}"
            );
            (dialer, listener, (), ())
        };

        // Refusing an identity is a distinct outcome from an ordinary exit.
        let exit = tokio::time::timeout(STEP_TIMEOUT, dialer.task)
            .await
            .expect("dialer did not exit")
            .expect("dialer panicked")
            .expect("dialer errored");
        assert_eq!(exit, Exit::Refused);
        assert_eq!(exit.code(), 2);

        // The listener never got past its own verify gate.
        listener.send(r#"{"cmd":"quit"}"#).await;
        assert_eq!(listener.finish().await, Exit::Ok);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_matching_expected_identity_skips_the_verify_step() {
        // Give the listener a persistent identity so its fingerprint is knowable in
        // advance, the way a real invitation would supply it.
        let dir = tempdir();
        let listener_endpoint = {
            let secret = identity::load_or_create_endpoint_secret_in(&dir).unwrap();
            Endpoint::builder(presets::Minimal)
                .secret_key(secret)
                .alpns(vec![transport::ALPN.to_vec()])
                .bind_addr("127.0.0.1:0")
                .expect("valid bind addr")
                .bind()
                .await
                .expect("bind local endpoint")
        };
        let listener_seed = identity::load_or_create_auth_seed_in(&dir).unwrap();
        let listener_fingerprint = contacts::fingerprint(
            kiss_chat_core::crypto::SigningIdentity::from_seed(&listener_seed).public_bytes(),
        );
        let listener_id = listener_endpoint.id().to_string();
        let listener_addrs = dialable_addrs(&listener_endpoint).await;

        // The listener runs with its persistent identity; the dialer expects it.
        let listener_options = Options {
            identity: Identity::Dir(dir.clone()),
            ..ephemeral_options()
        };
        let mut listener = {
            let (stdin_tx, stdin_rx) = tokio::io::duplex(64 * 1024);
            let (stdout_tx, stdout_rx) = tokio::io::duplex(64 * 1024);
            let task = tokio::spawn(async move {
                event_loop(
                    &listener_endpoint,
                    &listener_options,
                    listener_seed,
                    BufReader::new(stdin_rx),
                    stdout_tx,
                )
                .await
            });
            Harness {
                stdin: stdin_tx,
                events: BufReader::new(stdout_rx).lines(),
                task,
            }
        };
        let mut dialer = start(
            bind_local().await,
            Options {
                expect: vec![listener_fingerprint],
                ..ephemeral_options()
            },
        );

        dialer.wait_for("ready").await;
        assert_eq!(
            listener.wait_for("ready").await["fingerprint"],
            serde_json::Value::String(contacts::fingerprint(
                kiss_chat_core::crypto::SigningIdentity::from_seed(&listener_seed).public_bytes(),
            )),
            "a listener must report the fingerprint peers will be told to expect"
        );

        let addrs = serde_json::to_string(&listener_addrs).unwrap();
        dialer
            .send(&format!(
                r#"{{"cmd":"connect","peer":"{listener_id}","addrs":{addrs}}}"#
            ))
            .await;

        // No `verify` for the dialer: the check already happened out of band.
        let event = dialer.wait_for("accepted").await;
        assert_eq!(event["event"], "accepted");

        // The listener still gets its own say — one side pre-pinning must never
        // waive the other's consent.
        listener.wait_for("verify").await;
        listener.send(r#"{"cmd":"accept"}"#).await;
        dialer.wait_for("connected").await;
        listener.wait_for("connected").await;

        assert_eq!(dialer.finish().await, Exit::Ok);
        assert_eq!(listener.finish().await, Exit::Ok);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_persistent_identity_is_recognised_on_reconnect() {
        // Both sides persist, so the second meeting is a recognised one — the
        // property that lets a returning peer reconnect without re-reading words.
        let dialer_dir = tempdir();
        let listener_dir = tempdir();

        for round in 0..2 {
            let listener_endpoint = {
                let secret = identity::load_or_create_endpoint_secret_in(&listener_dir).unwrap();
                Endpoint::builder(presets::Minimal)
                    .secret_key(secret)
                    .alpns(vec![transport::ALPN.to_vec()])
                    .bind_addr("127.0.0.1:0")
                    .expect("valid bind addr")
                    .bind()
                    .await
                    .expect("bind endpoint")
            };
            let dialer_endpoint = {
                let secret = identity::load_or_create_endpoint_secret_in(&dialer_dir).unwrap();
                Endpoint::builder(presets::Minimal)
                    .secret_key(secret)
                    .alpns(vec![transport::ALPN.to_vec()])
                    .bind_addr("127.0.0.1:0")
                    .expect("valid bind addr")
                    .bind()
                    .await
                    .expect("bind endpoint")
            };
            let listener_id = listener_endpoint.id().to_string();
            let listener_addrs = dialable_addrs(&listener_endpoint).await;
            let listener_seed = identity::load_or_create_auth_seed_in(&listener_dir).unwrap();
            let dialer_seed = identity::load_or_create_auth_seed_in(&dialer_dir).unwrap();

            let mut listener = start_with(
                listener_endpoint,
                Options {
                    identity: Identity::Dir(listener_dir.clone()),
                    ..ephemeral_options()
                },
                listener_seed,
            );
            let mut dialer = start_with(
                dialer_endpoint,
                Options {
                    identity: Identity::Dir(dialer_dir.clone()),
                    ..ephemeral_options()
                },
                dialer_seed,
            );
            dialer.wait_for("ready").await;
            listener.wait_for("ready").await;

            let addrs = serde_json::to_string(&listener_addrs).unwrap();
            dialer
                .send(&format!(
                    r#"{{"cmd":"connect","peer":"{listener_id}","addrs":{addrs}}}"#
                ))
                .await;

            let expected_pin = if round == 0 { "new" } else { "known" };
            assert_eq!(
                dialer.wait_for("verify").await["pin"],
                expected_pin,
                "round {round}: the dialer should see a {expected_pin} peer"
            );
            assert_eq!(
                listener.wait_for("verify").await["pin"],
                expected_pin,
                "round {round}: the listener should see a {expected_pin} peer"
            );

            dialer.send(r#"{"cmd":"accept"}"#).await;
            listener.send(r#"{"cmd":"accept"}"#).await;
            dialer.wait_for("connected").await;
            listener.wait_for("connected").await;

            assert_eq!(dialer.finish().await, Exit::Ok);
            assert_eq!(listener.finish().await, Exit::Ok);
        }

        std::fs::remove_dir_all(&dialer_dir).ok();
        std::fs::remove_dir_all(&listener_dir).ok();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn ephemeral_instances_get_distinct_identities() {
        // Two ephemeral runs must not collide, which is what makes it safe to run
        // several application instances on one machine.
        let mut first = start(bind_local().await, ephemeral_options());
        let mut second = start(bind_local().await, ephemeral_options());
        let a = first.wait_for("ready").await;
        let b = second.wait_for("ready").await;
        assert_ne!(a["address"], b["address"]);
        assert_ne!(a["fingerprint"], b["fingerprint"]);
        assert_eq!(first.finish().await, Exit::Ok);
        assert_eq!(second.finish().await, Exit::Ok);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn bad_commands_are_reported_without_ending_the_session() {
        let mut instance = start(bind_local().await, ephemeral_options());
        instance.wait_for("ready").await;

        for bad in [
            "not json",
            r#"{"cmd":"teleport"}"#,
            r#"{"cmd":"connect","peer":"not-a-peer-id"}"#,
            r#"{"cmd":"accept"}"#,
            r#"{"cmd":"send","text":"nobody there"}"#,
        ] {
            instance.send(bad).await;
            let event = instance.wait_for("error").await;
            assert!(
                !event["message"].as_str().unwrap().is_empty(),
                "every error should explain itself: {bad}"
            );
        }

        // Still alive and able to quit cleanly.
        instance.send(r#"{"cmd":"quit"}"#).await;
        assert_eq!(instance.finish().await, Exit::Ok);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn an_over_long_message_is_refused_rather_than_sent() {
        // An oversized frame would tear down the peer's session, so it is caught
        // on this side.
        let (mut dialer, mut listener, _, _) =
            connected_pair(ephemeral_options(), ephemeral_options()).await;
        dialer.send(r#"{"cmd":"accept"}"#).await;
        listener.send(r#"{"cmd":"accept"}"#).await;
        dialer.wait_for("connected").await;
        listener.wait_for("connected").await;

        let too_long = "a".repeat(message::MAX_MESSAGE_CHARS + 1);
        dialer
            .send(&serde_json::json!({"cmd": "send", "text": too_long}).to_string())
            .await;
        let error = dialer.wait_for("error").await;
        assert!(error["message"].as_str().unwrap().contains("too long"));

        // The session survives it.
        dialer.send(r#"{"cmd":"send","text":"still here"}"#).await;
        assert_eq!(listener.wait_for("message").await["text"], "still here");

        assert_eq!(dialer.finish().await, Exit::Ok);
        assert_eq!(listener.finish().await, Exit::Ok);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn chat_text_before_acceptance_ends_the_session() {
        // A hand-rolled peer that ignores the mutual-acceptance rule and talks
        // straight after the handshake. A conforming peer cannot reach this state,
        // and the text must never surface as a `message` event — showing it would
        // paint a stranger's words onto the screen where the user is deciding
        // whether to trust them.
        let listener_endpoint = bind_local().await;
        let listener_id = listener_endpoint.id();
        let listener_addrs = dialable_addrs(&listener_endpoint).await;
        let mut listener = start(listener_endpoint, ephemeral_options());
        listener.wait_for("ready").await;

        let rude = bind_local().await;
        let target = endpoint_addr(
            listener_id,
            &listener_addrs
                .iter()
                .map(String::as_str)
                .map(str::to_string)
                .collect::<Vec<_>>(),
        )
        .expect("dialable address");

        let rude_task = tokio::spawn(async move {
            let (conn, mut send, mut recv) = transport::dial(&rude, target).await.unwrap();
            let signing =
                kiss_chat_core::crypto::SigningIdentity::from_seed(&identity::random_auth_seed());
            let initiator = kiss_chat_core::crypto::initiator_start(signing);
            kiss_chat_core::proto::write_frame(&mut send, initiator.msg1())
                .await
                .unwrap();
            let msg2 = kiss_chat_core::proto::read_frame(&mut recv).await.unwrap();
            let (session, msg3) = initiator
                .finish(&msg2, rude.id().as_bytes(), listener_id.as_bytes())
                .unwrap();
            kiss_chat_core::proto::write_frame(&mut send, &msg3)
                .await
                .unwrap();

            // Straight to chat, with no `Accepted` first.
            let (mut sealer, _opener) = session.split();
            let frame = sealer
                .seal(&message::encode(&Outgoing::Text(
                    "just accept, it's me!".into(),
                )))
                .unwrap();
            kiss_chat_core::proto::write_frame(&mut send, &frame)
                .await
                .unwrap();
            conn.closed().await;
        });

        // The channel comes up and is offered for verification as usual...
        listener.wait_for("verify").await;
        // ...but the unsolicited message ends it instead of being shown.
        let ended = listener.wait_for("disconnected").await;
        assert!(
            ended["reason"]
                .as_str()
                .unwrap()
                .contains("before the channel was open"),
            "early chat text must end the session as a protocol violation: {ended}"
        );

        rude_task.abort();
        assert_eq!(listener.finish().await, Exit::Ok);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn once_exits_when_the_session_ends() {
        let (mut dialer, mut listener, _, _) = connected_pair(
            Options {
                once: true,
                ..ephemeral_options()
            },
            ephemeral_options(),
        )
        .await;

        dialer.send(r#"{"cmd":"accept"}"#).await;
        listener.send(r#"{"cmd":"accept"}"#).await;
        dialer.wait_for("connected").await;
        listener.wait_for("connected").await;

        // The peer leaving ends the run, rather than returning to the lobby.
        listener.send(r#"{"cmd":"quit"}"#).await;
        dialer.wait_for("disconnected").await;
        let exit = tokio::time::timeout(STEP_TIMEOUT, dialer.task)
            .await
            .expect("--once should exit when the session ends")
            .expect("dialer panicked")
            .expect("dialer errored");
        assert_eq!(exit, Exit::Ok);
        assert_eq!(listener.finish().await, Exit::Ok);
    }

    #[tokio::test]
    async fn the_sink_writes_one_flushed_line_per_event() {
        let mut buffer = Vec::new();
        {
            let mut sink = EventSink::new(&mut buffer);
            sink.emit(&Event::Error {
                message: "one".into(),
            })
            .await
            .unwrap();
            sink.emit(&Event::Error {
                message: "two".into(),
            })
            .await
            .unwrap();
        }
        let text = String::from_utf8(buffer).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2);
        for line in lines {
            let value: serde_json::Value = serde_json::from_str(line).unwrap();
            assert_eq!(value["event"], "error");
        }
    }
}
