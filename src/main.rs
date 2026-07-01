//! kiss_chat — a keep-it-simple P2P chat with quantum-resistant E2E encryption.
//!
//! Usage:
//!   kiss_chat              # come up in the lobby: share your address, wait or /connect
//!   kiss_chat <ADDRESS>    # come up and immediately dial that peer (an iroh EndpointId)
//!
//! In-app commands (the input line is a command prompt until a peer is connected):
//!   /connect <peer-id>     dial a peer (switches peers if already connected)
//!   /clear                 clear the screen
//!   /help                  list commands
//!   /quit                  exit (also Esc / Ctrl-C)
//!
//! Architecture:
//!   transport  — iroh: bind, dial-by-key, accept (handles NAT traversal)
//!   proto      — length-prefixed framing over the QUIC stream
//!   message    — the 1-byte-tagged in-band protocol (chat text vs. Bye control)
//!   crypto     — hybrid X25519 + ML-KEM-768 handshake, then ChaCha20-Poly1305
//!   ui         — ratatui terminal interface (pure state)
//!   main       — the event loop wiring input, connection tasks, and the UI together
//!
//! The dialer is always the crypto *initiator*; the accepter is the *responder*.

mod crypto;
mod message;
mod proto;
mod transport;
mod ui;

use std::str::FromStr;
use std::time::Duration;

use anyhow::Result;
use crossterm::event::{Event, KeyEvent, KeyEventKind};
use iroh::endpoint::{Connection, RecvStream, SendStream};
use iroh::{Endpoint, EndpointId};
use ratatui::DefaultTerminal;
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};
use tokio::task::JoinHandle;

use crate::crypto::{Opener, Sealer, Session};
use crate::message::Outgoing;
use crate::ui::{Action, App, NetEvent};

/// How long to wait for a peer to acknowledge our goodbye before closing anyway.
const FAREWELL_TIMEOUT: Duration = Duration::from_secs(1);

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
    Failed(String),
}

/// The handles for the currently connected session.
struct LiveSession {
    conn: Connection,
    outgoing_tx: UnboundedSender<Outgoing>,
    reader: JoinHandle<()>,
    writer: JoinHandle<()>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let peer_arg = std::env::args().nth(1);
    if matches!(peer_arg.as_deref(), Some("-h" | "--help")) {
        print_usage();
        return Ok(());
    }

    let endpoint = transport::bind().await?;

    let mut terminal = ratatui::init();
    let result = run(&mut terminal, endpoint, peer_arg).await;
    ratatui::restore();
    result
}

fn print_usage() {
    println!(
        "kiss_chat — P2P quantum-resistant chat\n\n\
         usage:\n\
         \x20 kiss_chat              listen in the lobby; share your address and wait\n\
         \x20 kiss_chat <peer-id>    dial a peer immediately\n\n\
         inside the app: /connect <peer-id>, /clear, /help, /quit"
    );
}

/// The main event loop. Brings up the UI in the lobby, listens for an incoming
/// peer, and lets the user dial out — driven by three sources: key presses,
/// connection-attempt results, and decrypted network messages.
async fn run(terminal: &mut DefaultTerminal, endpoint: Endpoint, peer_arg: Option<String>) -> Result<()> {
    let my_id = endpoint.id();
    let mut app = App::new(my_id.to_string());

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
    let (net_tx, mut net_rx) = mpsc::unbounded_channel::<NetEvent>();

    // Listen for an incoming peer whenever we're not in a session.
    let mut accept_handle = arm_accept(&endpoint, my_id, &conn_tx);

    // Optional auto-dial from the command line.
    if let Some(arg) = peer_arg {
        match EndpointId::from_str(arg.trim()) {
            Ok(peer) => {
                app.set_connecting(peer.fmt_short().to_string());
                spawn_dial(&endpoint, my_id, peer, &conn_tx);
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
                            }
                            app.set_connecting(peer.fmt_short().to_string());
                            spawn_dial(&endpoint, my_id, peer, &conn_tx);
                        }
                        Err(_) => app.push_system("invalid peer id"),
                    },
                    Action::Send(line) => {
                        if let Some(live) = &session {
                            let _ = live.outgoing_tx.send(Outgoing::Text(line));
                        }
                    }
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

                        let fingerprint = new_session.fingerprint();
                        let (sealer, opener) = new_session.split();
                        let (out_tx, out_rx) = mpsc::unbounded_channel::<Outgoing>();
                        session = Some(LiveSession {
                            conn,
                            outgoing_tx: out_tx,
                            reader: spawn_reader(recv, opener, net_tx.clone()),
                            writer: spawn_writer(send, sealer, out_rx),
                        });
                        app.set_connected(peer.fmt_short().to_string(), fingerprint);
                    }
                }
                // Dial/accept failed: return to the lobby and keep listening.
                Some(ConnResult::Failed(reason)) if session.is_none() => {
                    accept_handle = arm_accept(&endpoint, my_id, &conn_tx);
                    app.set_lobby(reason);
                }
                _ => {}
            },

            event = net_rx.recv(), if session.is_some() => match event {
                Some(NetEvent::Message(text)) => app.push_peer(text),
                Some(NetEvent::Disconnected(reason)) => {
                    // The peer is already gone, so just tear down and re-open the lobby.
                    if let Some(live) = session.take() {
                        live.reader.abort();
                        live.writer.abort();
                        live.conn.close(0u32.into(), b"bye");
                    }
                    accept_handle = arm_accept(&endpoint, my_id, &conn_tx);
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
fn arm_accept(endpoint: &Endpoint, my_id: EndpointId, conn_tx: &UnboundedSender<ConnResult>) -> JoinHandle<()> {
    tokio::spawn(accept_and_handshake(endpoint.clone(), my_id, conn_tx.clone()))
}

/// Spawn a background task that dials a peer.
fn spawn_dial(endpoint: &Endpoint, my_id: EndpointId, peer: EndpointId, conn_tx: &UnboundedSender<ConnResult>) {
    tokio::spawn(dial_and_handshake(endpoint.clone(), my_id, peer, conn_tx.clone()));
}

/// Announce departure to the peer and close down gracefully.
///
/// Sends a `Bye` frame, then waits (bounded) for the peer to receive it and close
/// in response — which both confirms delivery and keeps the connection alive long
/// enough for the frame to actually reach the wire.
async fn farewell(conn: Connection, outgoing_tx: UnboundedSender<Outgoing>, writer: JoinHandle<()>) {
    let _ = outgoing_tx.send(Outgoing::Bye);
    let _ = tokio::time::timeout(FAREWELL_TIMEOUT, conn.closed()).await;
    writer.abort();
    conn.close(0u32.into(), b"bye");
}

/// Dial a peer and run the initiator side of the handshake, reporting the result.
async fn dial_and_handshake(
    endpoint: Endpoint,
    my_id: EndpointId,
    peer: EndpointId,
    tx: UnboundedSender<ConnResult>,
) {
    let attempt = async {
        let (conn, mut send, mut recv) = transport::dial(&endpoint, peer).await?;
        let initiator = crypto::initiator_start();
        proto::write_frame(&mut send, initiator.msg1()).await?;
        let msg2 = proto::read_frame(&mut recv).await?;
        let session = initiator.finish(&msg2, my_id.as_bytes(), peer.as_bytes())?;
        anyhow::Ok(Established { conn, send, recv, session, peer })
    };
    let _ = tx.send(match attempt.await {
        Ok(established) => ConnResult::Established(Box::new(established)),
        Err(err) => ConnResult::Failed(format!("could not connect: {err}")),
    });
}

/// Wait for an incoming peer and run the responder side of the handshake.
async fn accept_and_handshake(endpoint: Endpoint, my_id: EndpointId, tx: UnboundedSender<ConnResult>) {
    let attempt = async {
        let (conn, mut send, mut recv) = transport::accept(&endpoint).await?;
        let peer = conn.remote_id();
        let msg1 = proto::read_frame(&mut recv).await?;
        let (session, msg2) = crypto::responder_respond(&msg1, peer.as_bytes(), my_id.as_bytes())?;
        proto::write_frame(&mut send, &msg2).await?;
        anyhow::Ok(Established { conn, send, recv, session, peer })
    };
    let _ = tx.send(match attempt.await {
        Ok(established) => ConnResult::Established(Box::new(established)),
        Err(err) => ConnResult::Failed(format!("incoming connection failed: {err}")),
    });
}

/// Decrypt inbound frames and forward messages (or a disconnect) to the UI.
fn spawn_reader(
    mut recv: RecvStream,
    mut opener: Opener,
    net_tx: UnboundedSender<NetEvent>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            let event = match proto::read_frame(&mut recv).await {
                Ok(ciphertext) => match opener.open(&ciphertext) {
                    Ok(plaintext) => match message::decode(&plaintext) {
                        message::Incoming::Text(text) => NetEvent::Message(text),
                        message::Incoming::Bye => NetEvent::Disconnected("peer left the chat".into()),
                        message::Incoming::Malformed => {
                            NetEvent::Disconnected("received a malformed message".into())
                        }
                    },
                    Err(err) => NetEvent::Disconnected(format!("connection lost: {err}")),
                },
                Err(err) => NetEvent::Disconnected(format!("connection lost: {err}")),
            };
            let done = matches!(event, NetEvent::Disconnected(_));
            if net_tx.send(event).is_err() || done {
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
