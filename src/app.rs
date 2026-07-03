//! The application: brings up the UI in the lobby, wires terminal input,
//! connection tasks, and decrypted network events together, and drives the
//! event loop until the user quits.
//!
//! The dialer is always the crypto *initiator*; the accepter is the *responder*.

use std::str::FromStr;
use std::time::Duration;

use anyhow::Result;
use crossterm::event::{Event, KeyEvent, KeyEventKind};
use iroh::endpoint::{Connection, RecvStream, SendStream};
use iroh::{Endpoint, EndpointId};
use ratatui::DefaultTerminal;
use tokio::sync::mpsc::{self, Sender, UnboundedReceiver, UnboundedSender};
use tokio::task::JoinHandle;

use crate::contacts::PinStatus;
use crate::crypto::{Opener, Sealer, Session};
use crate::message::Outgoing;
use crate::ui::{Action, App, NetEvent};
use crate::{contacts, crypto, identity, message, proto, transport};

/// How long to wait for a peer to acknowledge our goodbye before closing anyway.
const FAREWELL_TIMEOUT: Duration = Duration::from_secs(1);

/// How long a dial or an accepted connection may spend completing the handshake
/// before we give up. This bounds two things: a dial to an unresponsive peer (so
/// the UI can't get stuck in "connecting…" with no way back to the lobby) and a
/// peer that connects but then stalls mid-handshake (so it can't tie up the
/// listener indefinitely). It does not cover the idle wait for a peer to appear.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

/// Capacity of the decrypted-network-event queue. Bounding it applies backpressure
/// to the reader task — and, through it, to the QUIC stream's own flow control — so
/// a peer flooding messages faster than the UI can render them can't grow this
/// queue without limit and exhaust memory.
const NET_EVENT_QUEUE: usize = 256;

/// A freshly established, encrypted session, handed from a handshake task to the loop.
struct Established {
    conn: Connection,
    send: SendStream,
    recv: RecvStream,
    session: Session,
    peer: EndpointId,
}

/// The result of a connection attempt (dial or accept), reported to the loop.
enum ConnResult {
    Established(Box<Established>),
    /// A dial or accept failed. `from_accept` records which, so the loop knows
    /// whether the background *listener* died (and must be re-armed) or merely an
    /// outbound dial did (leaving the listener untouched).
    Failed {
        reason: String,
        from_accept: bool,
    },
}

/// The handles for the currently connected session.
struct LiveSession {
    conn: Connection,
    outgoing_tx: UnboundedSender<Outgoing>,
    reader: JoinHandle<()>,
    writer: JoinHandle<()>,
    /// The peer's iroh address (as text) and long-term ML-DSA identity key, kept so
    /// that `/accept` can pin them to the contact list for trust-on-first-use.
    peer_id: String,
    peer_identity: Vec<u8>,
    /// The peer's display name once they share it this session, cached so it can be
    /// stored against their pin (for at-a-glance identification next time).
    peer_name: Option<String>,
}

/// Print command-line usage to stdout.
pub fn print_usage() {
    println!(
        "kiss_chat — P2P quantum-resistant chat\n\n\
         usage:\n\
         \x20 kiss_chat              listen in the lobby; share your address and wait\n\
         \x20 kiss_chat <peer-id>    dial a peer immediately\n\n\
         inside the app: /connect <peer-id>, /accept, /reject, /name, /clear, /help, /quit"
    );
}

/// List the peers we've accepted before (name, if cached, and full address so it can
/// be copied straight into `/connect`) into the message pane.
fn list_contacts(app: &mut App) {
    match contacts::known_peers() {
        Ok(peers) if peers.is_empty() => {
            app.push_system("no known peers yet — accepting a peer remembers them here");
        }
        Ok(peers) => {
            let label = if peers.len() == 1 { "peer" } else { "peers" };
            app.push_system(format!("{} known {label}:", peers.len()));
            for peer in peers {
                let name = peer.name.as_deref().unwrap_or("(unnamed)");
                app.push_system(format!("  {name}  ·  {}", peer.address));
            }
        }
        Err(err) => app.push_system(format!("could not read contacts: {err}")),
    }
}

/// Bring up the application: bind the endpoint, load our persistent identity, take
/// over the terminal, and run the event loop until the user quits. The terminal is
/// always restored before returning, even if the loop errors out.
///
/// `peer_arg` is an optional peer id (an iroh [`EndpointId`]) to dial on startup.
pub async fn run(peer_arg: Option<String>) -> Result<()> {
    let endpoint = transport::bind().await?;
    let auth_seed = identity::load_or_create_auth_seed()?;
    // An optional, previously-saved display name. Sanitised so a hand-edited file
    // can't feed control characters or an over-long name into the session.
    let display_name = identity::load_display_name()?.and_then(|n| message::sanitize_name(&n));

    let mut terminal = ratatui::init();
    let result = event_loop(&mut terminal, endpoint, peer_arg, auth_seed, display_name).await;
    ratatui::restore();
    result
}

/// The main event loop. Brings up the UI in the lobby, listens for an incoming
/// peer, and lets the user dial out — driven by three sources: key presses,
/// connection-attempt results, and decrypted network messages.
async fn event_loop(
    terminal: &mut DefaultTerminal,
    endpoint: Endpoint,
    peer_arg: Option<String>,
    auth_seed: [u8; 32],
    display_name: Option<String>,
) -> Result<()> {
    let my_id = endpoint.id();
    let mut app = App::new(my_id.to_string());

    // Our own display name (optional) and whether we've accepted the current peer.
    // We share the name only once accepted — never during the verify step.
    let mut my_name = display_name;
    let mut accepted = false;

    // Bridge blocking crossterm input into async on a dedicated thread.
    let (input_tx, mut input_rx) = mpsc::unbounded_channel::<KeyEvent>();
    std::thread::spawn(move || {
        while let Ok(event) = crossterm::event::read() {
            if let Event::Key(key) = event {
                // Ignore key-release/repeat noise (notably on Windows).
                if key.kind == KeyEventKind::Press && input_tx.send(key).is_err() {
                    break;
                }
            }
        }
    });

    let (conn_tx, mut conn_rx) = mpsc::unbounded_channel::<ConnResult>();
    let (net_tx, mut net_rx) = mpsc::channel::<NetEvent>(NET_EVENT_QUEUE);

    // Listen for an incoming peer whenever we're not in a session.
    let mut accept_handle = arm_accept(&endpoint, my_id, auth_seed, &conn_tx);

    // Optional auto-dial from the command line.
    if let Some(arg) = peer_arg {
        match EndpointId::from_str(arg.trim()) {
            Ok(peer) => {
                app.set_connecting(peer.fmt_short().to_string());
                spawn_dial(&endpoint, my_id, peer, auth_seed, &conn_tx);
            }
            Err(_) => app.push_system("ignoring invalid peer id from the command line"),
        }
    }

    let mut session: Option<LiveSession> = None;

    loop {
        terminal.draw(|frame| app.render(frame))?;
        if app.should_quit {
            break;
        }

        tokio::select! {
            key = input_rx.recv() => {
                let Some(key) = key else { break }; // input thread ended
                match app.on_key(key) {
                    Action::Quit => break,
                    Action::Connect(id) => match EndpointId::from_str(id.trim()) {
                        Ok(peer) => {
                            // If we're already connected, leave the current peer first
                            // (announcing our departure) before dialing the new one.
                            if let Some(old) = session.take() {
                                old.reader.abort();
                                tokio::spawn(farewell(old.conn, old.outgoing_tx, old.writer));
                                app.push_system("left the current chat");
                                // Accepting was paused while we were connected; resume it
                                // so we keep listening (and stay reachable) while we dial.
                                accept_handle = arm_accept(&endpoint, my_id, auth_seed, &conn_tx);
                            }
                            accepted = false;
                            app.set_connecting(peer.fmt_short().to_string());
                            spawn_dial(&endpoint, my_id, peer, auth_seed, &conn_tx);
                        }
                        Err(_) => app.push_system("invalid peer id"),
                    },
                    Action::Accept => {
                        // Now — and only now — is it safe to share our display name.
                        accepted = true;
                        if let Some(live) = &session {
                            // Pin (or re-pin) this peer's identity key so a future
                            // change is flagged. Accepting is the user asserting trust.
                            if let Err(err) = contacts::remember(&live.peer_id, &live.peer_identity)
                            {
                                app.push_system(format!("could not save contact: {err}"));
                            }
                            // If the peer already shared a name (they accepted first),
                            // cache it against the fresh pin now.
                            if live.peer_name.is_some()
                                && let Err(err) =
                                    contacts::set_name(&live.peer_id, live.peer_name.as_deref())
                            {
                                app.push_system(format!("could not save contact name: {err}"));
                            }
                            if let Some(name) = &my_name {
                                let _ = live.outgoing_tx.send(Outgoing::Name(Some(name.clone())));
                            }
                        }
                    }
                    Action::RejectPeer => {
                        // The safety number didn't match: leave and return to the lobby.
                        if let Some(old) = session.take() {
                            old.reader.abort();
                            tokio::spawn(farewell(old.conn, old.outgoing_tx, old.writer));
                        }
                        accepted = false;
                        accept_handle = arm_accept(&endpoint, my_id, auth_seed, &conn_tx);
                        app.set_lobby("rejected the peer — back in the lobby");
                    }
                    Action::SetName(raw) => {
                        my_name = message::sanitize_name(&raw);
                        if let Err(err) = identity::save_display_name(my_name.as_deref()) {
                            app.push_system(format!("could not save display name: {err}"));
                        }
                        match &my_name {
                            Some(name) => app.push_system(format!("display name set to \"{name}\"")),
                            None => app.push_system("display name cleared"),
                        }
                        // Propagate the change (including a clear) to a peer we're
                        // already chatting with; otherwise it waits for /accept.
                        if accepted && let Some(live) = &session {
                            let _ = live.outgoing_tx.send(Outgoing::Name(my_name.clone()));
                        }
                    }
                    Action::Send(line) => {
                        if let Some(live) = &session {
                            let _ = live.outgoing_tx.send(Outgoing::Text(line));
                        }
                    }
                    Action::ListContacts => list_contacts(&mut app),
                    Action::None => {}
                }
            }

            result = conn_rx.recv() => match result {
                Some(ConnResult::Established(established)) => {
                    let Established { conn, send, recv, session: new_session, peer } = *established;
                    if session.is_some() {
                        // Already talking to someone; refuse the extra connection.
                        conn.close(0u32.into(), b"already connected");
                    } else {
                        accept_handle.abort(); // stop accepting while we're busy
                        // Drop any stale events left over from a previous session.
                        while net_rx.try_recv().is_ok() {}

                        // Fresh channel: not yet accepted, so no name is shared.
                        accepted = false;

                        // Compare the peer's long-term identity key against any we
                        // pinned for this address when we last accepted it (TOFU), so
                        // the verify step can flag a first meeting, a recognised peer
                        // (by their cached name), or a changed identity key.
                        let peer_id = peer.to_string();
                        let peer_identity = new_session.peer_identity().to_vec();
                        let (pin, known_name) = match contacts::recognize(&peer_id, &peer_identity) {
                            Ok(rec) => (rec.status, rec.name),
                            Err(err) => {
                                app.push_system(format!("could not read contacts: {err}"));
                                (PinStatus::New, None)
                            }
                        };

                        let safety_number = new_session.safety_number().to_string();
                        let (sealer, opener) = new_session.split();
                        let (out_tx, out_rx) = mpsc::unbounded_channel::<Outgoing>();
                        session = Some(LiveSession {
                            conn,
                            outgoing_tx: out_tx,
                            reader: spawn_reader(recv, opener, net_tx.clone()),
                            writer: spawn_writer(send, sealer, out_rx),
                            peer_id,
                            peer_identity,
                            peer_name: None,
                        });
                        // The channel is up, but hold chat until the user has compared
                        // the safety number out-of-band and accepted.
                        app.set_verifying(peer.fmt_short().to_string(), safety_number, pin, known_name);
                    }
                }
                // Dial/accept failed: return to the lobby. Re-arm the listener only if
                // it was the listener that died; a failed *dial* leaves the still-live
                // listener alone (re-arming it here would leak the running task).
                Some(ConnResult::Failed { reason, from_accept }) if session.is_none() => {
                    if from_accept {
                        accept_handle = arm_accept(&endpoint, my_id, auth_seed, &conn_tx);
                    }
                    app.set_lobby(reason);
                }
                _ => {}
            },

            event = net_rx.recv(), if session.is_some() => match event {
                Some(NetEvent::Message(text)) => app.push_peer(text),
                Some(NetEvent::PeerName(name)) => {
                    // Remember the name for this session, and — once we've accepted
                    // the peer — cache it against their pin for next time.
                    if let Some(live) = &mut session {
                        live.peer_name = name.clone();
                        if accepted
                            && let Err(err) = contacts::set_name(&live.peer_id, name.as_deref())
                        {
                            app.push_system(format!("could not save contact name: {err}"));
                        }
                    }
                    app.set_peer_name(name);
                }
                Some(NetEvent::Disconnected(reason)) => {
                    // The peer is already gone, so just tear down and re-open the lobby.
                    if let Some(live) = session.take() {
                        live.reader.abort();
                        live.writer.abort();
                        live.conn.close(0u32.into(), b"bye");
                    }
                    accepted = false;
                    accept_handle = arm_accept(&endpoint, my_id, auth_seed, &conn_tx);
                    app.set_lobby(format!("{reason} — back in the lobby"));
                }
                None => {}
            },
        }
    }

    // On exit, say a proper goodbye to the peer if we're still connected.
    if let Some(live) = session.take() {
        live.reader.abort();
        farewell(live.conn, live.outgoing_tx, live.writer).await;
    }
    accept_handle.abort();
    Ok(())
}

/// Spawn a background task that waits for an incoming peer.
fn arm_accept(
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
fn spawn_dial(
    endpoint: &Endpoint,
    my_id: EndpointId,
    peer: EndpointId,
    auth_seed: [u8; 32],
    conn_tx: &UnboundedSender<ConnResult>,
) {
    tokio::spawn(dial_and_handshake(
        endpoint.clone(),
        my_id,
        peer,
        auth_seed,
        conn_tx.clone(),
    ));
}

/// Announce departure to the peer and close down gracefully.
///
/// Sends a `Bye` frame, then waits (bounded) for the peer to receive it and close
/// in response — which both confirms delivery and keeps the connection alive long
/// enough for the frame to actually reach the wire.
async fn farewell(
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
/// an unresponsive peer can't leave the UI stuck in "connecting…" forever.
async fn dial_and_handshake(
    endpoint: Endpoint,
    my_id: EndpointId,
    peer: EndpointId,
    auth_seed: [u8; 32],
    tx: UnboundedSender<ConnResult>,
) {
    let attempt = async {
        let (conn, mut send, mut recv) = transport::dial(&endpoint, peer).await?;
        let identity = crypto::SigningIdentity::from_seed(&auth_seed);
        let initiator = crypto::initiator_start(identity);
        proto::write_frame(&mut send, initiator.msg1()).await?;
        let msg2 = proto::read_frame(&mut recv).await?;
        let (session, msg3) = initiator.finish(&msg2, my_id.as_bytes(), peer.as_bytes())?;
        proto::write_frame(&mut send, &msg3).await?;
        anyhow::Ok(Established {
            conn,
            send,
            recv,
            session,
            peer,
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

/// Decrypt inbound frames and forward messages (or a disconnect) to the UI.
///
/// `net_tx` is bounded, so a slow UI stalls this `send`, which stops us reading
/// the next frame and lets QUIC flow control throttle a flooding peer.
fn spawn_reader(
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

/// Encrypt outgoing messages from the UI and send them as frames.
fn spawn_writer(
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
