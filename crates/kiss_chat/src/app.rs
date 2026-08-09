//! The terminal application: brings up the UI in the lobby, wires terminal input,
//! connection tasks, and decrypted network events together, and drives the
//! event loop until the user quits.
//!
//! The connection machinery itself — dialling, accepting, the handshake, and the
//! reader/writer tasks — lives in [`crate::net`], which knows nothing about the
//! terminal. This module is what turns those events into a UI.

use std::path::{Path, PathBuf};

use anyhow::Result;
use crossterm::event::{
    DisableBracketedPaste, EnableBracketedPaste, Event, KeyEvent, KeyEventKind,
};
use iroh::Endpoint;
use ratatui::DefaultTerminal;
use tokio::sync::mpsc;

use kiss_chat_core::contacts::PinStatus;
use kiss_chat_core::message::Outgoing;
use kiss_chat_core::{address, contacts, identity, message, transport};

use crate::net::{
    ConnResult, Established, LiveSession, NET_EVENT_QUEUE, NetEvent, arm_accept, farewell,
    spawn_dial, spawn_reader, spawn_writer,
};
use crate::ui::{Action, App, OwnAddress};

/// Terminal input forwarded from the blocking reader thread into the async loop.
enum Input {
    /// A key press to interpret.
    Key(KeyEvent),
    /// A pasted string, delivered whole. Bracketed paste is what makes this one
    /// event instead of a stream of key presses — pasted newlines must insert,
    /// never act as Enter and submit half the paste.
    Paste(String),
    /// A terminal resize. Carries no data — it exists only to wake the loop so the
    /// UI redraws at the new size (the draw happens at the top of every iteration).
    Resize,
}

/// Print command-line usage to stdout.
pub fn print_usage() {
    print_usage_to(&mut std::io::stdout());
}

/// Print command-line usage to `out` (stderr, when usage follows an error).
pub fn print_usage_to(out: &mut impl std::io::Write) {
    let _ = writeln!(
        out,
        "kiss_chat {} — P2P quantum-resistant chat\n\n\
         usage:\n\
         \x20 kiss_chat                    listen in the lobby; share your address and wait\n\
         \x20 kiss_chat <address>          dial a peer immediately (hex, kiss1…, or 24 words)\n\
         \x20 kiss_chat --config-dir <dir> keep this session's identity in <dir>\n\
         \x20 kiss_chat --version          print the version and exit (also -v)\n\n\
         headless (driven by another program over stdin/stdout as JSON lines):\n\
         \x20 kiss_chat --headless --ephemeral            throwaway identity, nothing on disk\n\
         \x20 kiss_chat --headless --config-dir <dir>     identity kept in <dir>\n\
         \x20   --expect <fingerprint>   only talk to this identity; may be repeated\n\
         \x20   --name <text>            display name for this run (not saved)\n\
         \x20   --once                   exit when the first session ends\n\
         \x20   [address]                dial this peer on startup\n\n\
         inside the app: /connect <address>, /accept, /reject, /name, /safety,\n\
         \x20               /contacts, /address, /qr, /clear, /version, /help, /quit",
        env!("CARGO_PKG_VERSION")
    );
}

/// Print the version to stdout (for `--version` / `-v`).
pub fn print_version() {
    println!("kiss_chat {}", env!("CARGO_PKG_VERSION"));
}

/// List the peers we've accepted before (name, if cached, and full address so it can
/// be copied straight into `/connect`) into the message pane.
fn list_contacts(app: &mut App, config_dir: &Path) {
    match contacts::known_peers_in(config_dir) {
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
/// `config_dir` overrides where the identity, contacts, and display name live;
/// `None` uses the user's own config directory. `peer_arg` is an optional peer
/// address, in any form [`address::parse`] accepts, to dial on startup.
///
/// # Errors
///
/// Fails if the endpoint can't bind or the persistent identity can't be loaded;
/// the terminal is always restored before returning, error or not.
pub async fn run(config_dir: Option<PathBuf>, peer_arg: Option<String>) -> Result<()> {
    let config_dir = match config_dir {
        Some(dir) => dir,
        None => identity::config_dir()?,
    };
    let endpoint =
        transport::bind_with(identity::load_or_create_endpoint_secret_in(&config_dir)?).await?;
    let auth_seed = identity::load_or_create_auth_seed_in(&config_dir)?;
    // An optional, previously-saved display name. Sanitised so a hand-edited file
    // can't feed control characters or an over-long name into the session.
    let display_name =
        identity::load_display_name_in(&config_dir)?.and_then(|n| message::sanitize_name(&n));

    let mut terminal = ratatui::init();
    // Best-effort: a terminal without bracketed paste just keeps the old
    // behaviour (a paste arrives as key presses, newlines acting as Enter).
    let _ = crossterm::execute!(std::io::stdout(), EnableBracketedPaste);
    let result = event_loop(
        &mut terminal,
        endpoint,
        &config_dir,
        peer_arg,
        auth_seed,
        display_name,
    )
    .await;
    let _ = crossterm::execute!(std::io::stdout(), DisableBracketedPaste);
    ratatui::restore();
    result
}

/// The main event loop. Brings up the UI in the lobby, listens for an incoming
/// peer, and lets the user dial out — driven by three sources: key presses,
/// connection-attempt results, and decrypted network messages.
async fn event_loop(
    terminal: &mut DefaultTerminal,
    endpoint: Endpoint,
    config_dir: &Path,
    peer_arg: Option<String>,
    auth_seed: [u8; 32],
    display_name: Option<String>,
) -> Result<()> {
    let my_id = endpoint.id();
    let mut app = App::new(OwnAddress {
        hex: my_id.to_string(),
        bech32: address::to_bech32(&my_id),
        words: address::to_words(&my_id),
    });

    // Our own display name (optional) and the two halves of mutual acceptance:
    // whether we've accepted the current peer, and whether they've accepted us.
    // We share the name only once *we* have accepted — never during the verify
    // step — while chat may flow only once both are true.
    let mut my_name = display_name;
    let mut accepted = false;
    let mut peer_accepted = false;

    // Bridge blocking crossterm input into async on a dedicated thread. Both key
    // presses and resizes are forwarded; a resize just wakes the loop to redraw.
    let (input_tx, mut input_rx) = mpsc::unbounded_channel::<Input>();
    std::thread::spawn(move || {
        while let Ok(event) = crossterm::event::read() {
            let forward = match event {
                // Ignore key-release/repeat noise (notably on Windows).
                Event::Key(key) if key.kind == KeyEventKind::Press => Input::Key(key),
                Event::Paste(text) => Input::Paste(text),
                Event::Resize(..) => Input::Resize,
                _ => continue,
            };
            if input_tx.send(forward).is_err() {
                break;
            }
        }
    });

    let (conn_tx, mut conn_rx) = mpsc::unbounded_channel::<ConnResult>();
    let (net_tx, mut net_rx) = mpsc::channel::<NetEvent>(NET_EVENT_QUEUE);

    // Listen for an incoming peer whenever we're not in a session.
    let mut accept_handle = arm_accept(&endpoint, my_id, auth_seed, &conn_tx);

    // Optional auto-dial from the command line.
    if let Some(arg) = peer_arg {
        match address::parse(&arg) {
            Ok(peer) => {
                app.set_connecting(peer.fmt_short().to_string());
                spawn_dial(&endpoint, my_id, peer, auth_seed, &conn_tx);
            }
            Err(err) => {
                app.push_system(format!("ignoring the address from the command line: {err}"))
            }
        }
    }

    let mut session: Option<LiveSession> = None;

    loop {
        terminal.draw(|frame| app.render(frame))?;
        if app.should_quit {
            break;
        }

        tokio::select! {
            input = input_rx.recv() => {
                let Some(input) = input else { break }; // input thread ended
                let key = match input {
                    Input::Key(key) => key,
                    // A paste only ever edits the input line; nothing to act on.
                    Input::Paste(text) => {
                        app.on_paste(&text);
                        continue;
                    }
                    // A resize needs only a redraw, done at the top of the next loop.
                    Input::Resize => continue,
                };
                match app.on_key(key) {
                    Action::Quit => break,
                    Action::Connect(id) => match address::parse(&id) {
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
                            peer_accepted = false;
                            app.set_connecting(peer.fmt_short().to_string());
                            spawn_dial(&endpoint, my_id, peer, auth_seed, &conn_tx);
                        }
                        Err(err) => app.push_system(format!("invalid address: {err}")),
                    },
                    Action::Accept => {
                        // Now — and only now — is it safe to share our display name.
                        accepted = true;
                        // A name the peer volunteered before we accepted was recorded
                        // but held back from the verify screen; surface it now.
                        let mut peer_name_to_show = None;
                        if let Some(live) = &session {
                            // Tell the peer we've accepted, before anything else we
                            // send: it is what opens their side of the chat, and the
                            // stream is ordered, so it can never trail our first
                            // message.
                            let _ = live.outgoing_tx.send(Outgoing::Accepted);
                            // Pin (or re-pin) this peer's identity key so a future
                            // change is flagged. Accepting is the user asserting trust.
                            if let Err(err) = contacts::remember_in(config_dir, &live.peer_id, &live.peer_identity)
                            {
                                app.push_system(format!("could not save contact: {err}"));
                            }
                            // If the peer already shared a name (they accepted first),
                            // cache it against the fresh pin now.
                            if live.peer_name.is_some() {
                                if let Err(err) =
                                    contacts::set_name_in(config_dir, &live.peer_id, live.peer_name.as_deref())
                                {
                                    app.push_system(format!(
                                        "could not save contact name: {err}"
                                    ));
                                }
                                peer_name_to_show = live.peer_name.clone();
                            }
                            if let Some(name) = &my_name {
                                let _ = live.outgoing_tx.send(Outgoing::Name(Some(name.clone())));
                            }
                        }
                        if peer_name_to_show.is_some() {
                            app.set_peer_name(peer_name_to_show);
                        }
                    }
                    Action::RejectPeer => {
                        // The user declined (safety words mismatched, or an unwanted
                        // connection): leave and return to the lobby.
                        if let Some(old) = session.take() {
                            old.reader.abort();
                            tokio::spawn(farewell(old.conn, old.outgoing_tx, old.writer));
                        }
                        accepted = false;
                        peer_accepted = false;
                        accept_handle = arm_accept(&endpoint, my_id, auth_seed, &conn_tx);
                        app.set_lobby("rejected the peer — back in the lobby");
                    }
                    Action::SetName(raw) => {
                        my_name = message::sanitize_name(&raw);
                        if let Err(err) = identity::save_display_name_in(config_dir, my_name.as_deref()) {
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
                    Action::ListContacts => list_contacts(&mut app, config_dir),
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

                        // Fresh channel: neither side has accepted yet, so no name is
                        // shared and no chat may flow.
                        accepted = false;
                        peer_accepted = false;

                        // Compare the peer's long-term identity key against any we
                        // pinned for this address when we last accepted it (TOFU), so
                        // the verify step can flag a first meeting, a recognised peer
                        // (by their cached name), or a changed identity key.
                        let peer_id = peer.to_string();
                        let peer_identity = new_session.peer_identity().to_vec();
                        let (pin, known_name) = match contacts::recognize_in(config_dir, &peer_id, &peer_identity) {
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
                        // The channel is up, but hold chat until the user accepts —
                        // comparing the safety words out-of-band for a new or changed
                        // peer, or just consenting to reconnect for a recognised one.
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
                // Chat text before acceptance is mutual is a protocol violation: a
                // well-behaved peer waits for our `Accepted` before saying anything.
                // Ending the session is both the honest reading of a peer that isn't
                // following the protocol, and the strongest answer to a malicious one
                // trying to paint text — "it's me, just accept!" — onto the very
                // screen where the safety-word ritual matters most.
                Some(NetEvent::Message(text)) => {
                    if accepted && peer_accepted {
                        app.push_peer(text);
                    } else if let Some(live) = session.take() {
                        live.reader.abort();
                        live.writer.abort();
                        live.conn.close(0u32.into(), b"protocol violation");
                        accepted = false;
                        peer_accepted = false;
                        accept_handle = arm_accept(&endpoint, my_id, auth_seed, &conn_tx);
                        app.set_lobby(
                            "peer sent a message before the channel was open — disconnected",
                        );
                    }
                }
                Some(NetEvent::PeerAccepted) => {
                    peer_accepted = true;
                    // If this completes the mutual acceptance, the UI opens the chat
                    // and hands back whatever the user typed while waiting, which we
                    // send now — in the order they typed it.
                    let held = app.mark_peer_accepted();
                    if let Some(live) = &session {
                        for line in held {
                            let _ = live.outgoing_tx.send(Outgoing::Text(line));
                        }
                    }
                    if !accepted {
                        // They accepted first; our verify gate still stands.
                        app.note_peer_accepted_first();
                    }
                }
                Some(NetEvent::PeerName(name)) => {
                    // Remember the name for this session, and — once we've accepted
                    // the peer — cache it against their pin for next time and show it.
                    if let Some(live) = &mut session {
                        live.peer_name = name.clone();
                        if accepted
                            && let Err(err) = contacts::set_name_in(config_dir, &live.peer_id, name.as_deref())
                        {
                            app.push_system(format!("could not save contact name: {err}"));
                        }
                    }
                    if accepted {
                        app.set_peer_name(name);
                    }
                }
                Some(NetEvent::Disconnected(reason)) => {
                    // The peer is already gone, so just tear down and re-open the lobby.
                    if let Some(live) = session.take() {
                        live.reader.abort();
                        live.writer.abort();
                        live.conn.close(0u32.into(), b"bye");
                    }
                    accepted = false;
                    peer_accepted = false;
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
