//! Terminal UI state: a scrolling history above a single input line.
//!
//! This module is pure state + rendering + key interpretation. It never touches
//! crypto or the network — the main loop drives it, feeding in
//! [`NetEvent`](crate::net::NetEvent)s and acting on the [`Action`]s that key
//! presses produce.
//!
//! The input line is a command prompt (`/connect`, `/help`, `/quit`) until a peer
//! is connected. When a channel comes up the app holds it in a **verify** gate: a
//! first-seen (or changed-key) peer must have their safety words compared out-of-band,
//! while a peer you've verified before is simply *recognised* and asked only for a
//! quick `/accept`. Either way nothing is sent until the user `/accept`s (or `/reject`s).
//!
//! Accepting doesn't open the chat on its own, because the peer has their own gate
//! to pass: the app then **waits** for their acceptance, and only once both sides
//! have accepted does chat begin. Lines typed while waiting aren't lost — they're
//! held and sent the moment the peer accepts.
//!
//! Timestamps shown next to messages are in UTC.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use kiss_chat_core::contacts::PinStatus;
use kiss_chat_core::message;
use ratatui::{
    Frame,
    layout::{Constraint, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, List, ListItem, Paragraph},
};

/// How many wrapped lines PageUp/PageDown move the history view.
const SCROLL_STEP: usize = 5;

/// The crate version, shown in the frame title and reported by `/version`.
const VERSION: &str = env!("CARGO_PKG_VERSION");

/// What a key press asked for, interpreted by the main loop.
pub enum Action {
    /// Nothing for the main loop to do.
    None,
    /// Quit the application.
    Quit,
    /// Dial the given peer id (from `/connect`).
    Connect(String),
    /// Accept the peer being verified and begin chatting (from `/accept`).
    Accept,
    /// Reject the peer being verified and return to the lobby (from `/reject`).
    RejectPeer,
    /// Send the given line to the connected peer.
    Send(String),
    /// Set (or, with an empty string, clear) our own display name (from `/name`).
    SetName(String),
    /// List the peers we've accepted before (from `/contacts`).
    ListContacts,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Lobby,
    Connecting,
    Verifying,
    /// We have accepted; the peer hasn't yet (or their acceptance hasn't arrived).
    /// Typing is allowed here — lines are held and sent the moment chat opens — but
    /// nothing may be sent or received until acceptance is mutual.
    WaitingPeer,
    Connected,
}

enum Author {
    You,
    Peer,
    System,
    /// A security-relevant notice (e.g. a peer's identity key changed), styled to
    /// stand out from ordinary system chatter.
    Warning,
    /// The out-of-band safety words. The one thing on the verify screen the user
    /// must actually scrutinise, so it gets its own bold, numbered block instead of
    /// being buried in the dim system chatter. `text` holds the raw space-separated
    /// phrase; the grid layout is computed at render time to fit the terminal width.
    Safety,
    /// One form of our own address, laid out to be copied: no timestamp/label
    /// prefix (which would both waste width and ride along on a drag-select), a
    /// small indent, and wrapping only at the spaces already in the text.
    Address,
    /// The 24-word form of our own address, rendered as a numbered grid like the
    /// safety words — but in the address accent, under an unmistakable header,
    /// because the two must never be confused: an address is public, safety words
    /// are a verification ritual.
    AddressWords,
    /// A QR code of our own address, rendered in half-block characters. Never
    /// wrapped — a wrapped QR code is garbage — so if the terminal is too narrow
    /// a note takes its place until the user widens it and scrolls or re-runs /qr.
    Qr,
}

/// Accent colour for the safety words — high-contrast and distinct from the You /
/// Peer / System / Warning palette so the block reads as its own thing.
const SAFETY_ACCENT: Color = Color::LightYellow;

/// Accent colour for our own address blocks. Cyan is the colour of "you" in the
/// chat labels, which is exactly what an address is — and visibly not the safety
/// words' yellow, so the two word blocks can never be mistaken for one another.
const ADDRESS_ACCENT: Color = Color::Cyan;

/// The user's own address in each display form, precomputed by the frontend —
/// this module renders and recalls them but never encodes or parses.
pub struct OwnAddress {
    /// Canonical hex [`iroh::EndpointId`] — the form every kiss_chat version,
    /// however old, can dial.
    pub hex: String,
    /// The `kiss1…` bech32m form: checksummed, and the best one to copy or share.
    pub bech32: String,
    /// The 24-word form, for reading aloud or writing down.
    pub words: String,
}

struct ChatLine {
    author: Author,
    text: String,
    timestamp: String,
}

pub struct App {
    mode: Mode,
    status: String,
    history: Vec<ChatLine>,
    input: String,
    /// Cursor position within `input`, as a character index.
    cursor: usize,
    /// How many wrapped lines the history is scrolled up from the bottom.
    scroll_lines: usize,
    /// Short peer id and safety number of the session under verification / in use.
    peer_short: String,
    safety_number: String,
    /// While gating a channel ([`Mode::Verifying`]), whether the peer was already
    /// recognised — their identity key matches a pin we verified before. A recognised
    /// peer gets a light re-connect consent instead of the full safety-word ritual.
    /// Only meaningful in `Mode::Verifying`; overwritten on each gate.
    recognized: bool,
    /// The peer's chosen display name, once they share it (only after accepting).
    peer_name: Option<String>,
    /// Whether the peer has accepted the channel. Chat opens only when this and our
    /// own acceptance have both happened — in whichever order they occur.
    peer_accepted: bool,
    /// Lines typed while waiting for the peer to accept, held so they can be sent
    /// the moment chat opens instead of being silently dropped.
    pending_lines: Vec<String>,
    /// Our own address (in every display form), kept so `/address`, `/qr` and
    /// friends can recall it after `/clear`.
    my_address: OwnAddress,
    pub should_quit: bool,
}

impl App {
    /// Create the app in the lobby, showing our own address so it can be shared.
    #[must_use]
    pub fn new(my_address: OwnAddress) -> Self {
        let mut app = Self {
            mode: Mode::Lobby,
            status: "lobby".into(),
            history: Vec::new(),
            input: String::new(),
            cursor: 0,
            scroll_lines: 0,
            peer_short: String::new(),
            safety_number: String::new(),
            recognized: false,
            peer_name: None,
            peer_accepted: false,
            pending_lines: Vec::new(),
            my_address,
            should_quit: false,
        };
        app.push_system("welcome to kiss_chat");
        app.push_system("your address:");
        let bech32 = grouped_bech32(&app.my_address.bech32);
        app.push(Author::Address, bech32);
        app.push_system("share it so a peer can dial you, or connect out with:");
        app.push_system("  /connect <address>");
        app.push_system("type /help for all commands (/address shows more ways to share yours)");
        app
    }

    fn push(&mut self, author: Author, text: String) {
        self.history.push(ChatLine {
            author,
            text,
            timestamp: timestamp_now(),
        });
    }

    pub fn push_system(&mut self, text: impl Into<String>) {
        self.push(Author::System, text.into());
    }

    fn push_warning(&mut self, text: impl Into<String>) {
        self.push(Author::Warning, text.into());
    }

    pub fn push_peer(&mut self, text: String) {
        self.push(Author::Peer, text);
    }

    /// Push the safety words as their own highlighted, numbered block.
    fn push_safety(&mut self, phrase: impl Into<String>) {
        self.push(Author::Safety, phrase.into());
    }

    /// Push the 24-word form of our own address, bracketed by guidance that keeps
    /// it from ever being mistaken for the safety words.
    fn push_address_words(&mut self) {
        self.push_system("your address as 24 words — the easiest form to read aloud:");
        let words = self.my_address.words.clone();
        self.push(Author::AddressWords, words);
        self.push_system("these words are your public address: share them freely.");
        self.push_system("they are NOT safety words — never use them to verify a peer.");
    }

    /// Enter the "dialing a peer" state.
    pub fn set_connecting(&mut self, peer_short: String) {
        self.mode = Mode::Connecting;
        self.status = format!("connecting to {peer_short}…");
        self.push_system(format!("connecting to {peer_short}…"));
    }

    /// Enter the gate that holds a freshly-established channel before any chatting.
    ///
    /// `pin` says how the peer's long-term identity key compares to any we pinned for
    /// this address on a previous `/accept`, which decides how much the user is asked
    /// to do:
    ///
    ///   - [`PinStatus::New`] — a first meeting: show the safety words and ask the user
    ///     to compare them out-of-band before accepting (trust-on-first-use).
    ///   - [`PinStatus::Changed`] — the identity key differs from the pin: the same
    ///     out-of-band comparison, but preceded by a prominent warning.
    ///   - [`PinStatus::Known`] — the key matches a pin we already verified once. The
    ///     handshake signatures re-authenticate the peer every session, so re-reading
    ///     the safety words adds nothing; we ask only for a light consent to reconnect,
    ///     while still leaving the words a `/safety` away for the cautious.
    ///
    /// Either way the channel is held in the verify gate until the user `/accept`s,
    /// so a peer can never force us into a chat without our say-so. `known_name` is the
    /// name cached for a recognised peer, shown so they're identifiable at a glance.
    pub fn set_verifying(
        &mut self,
        peer_short: String,
        safety_number: String,
        pin: PinStatus,
        known_name: Option<String>,
    ) {
        self.mode = Mode::Verifying;
        self.peer_short = peer_short;
        self.safety_number = safety_number.clone();
        self.recognized = pin == PinStatus::Known;
        // A fresh channel: the peer's acceptance and anything typed at the last one
        // belong to a session that is over.
        self.peer_accepted = false;
        self.pending_lines.clear();
        // Default to no name. A name cached under a *different* (New/Changed) identity
        // must never be shown as if it belonged to this peer; the recognised branch
        // below restores it, since there the cached name *is* this same identity's.
        self.peer_name = None;

        if self.recognized {
            self.status = format!("reconnect {} · /accept or /reject", self.peer_short);
            self.peer_name = known_name.clone();
            match &known_name {
                Some(name) => self.push_system(format!(
                    "incoming connection from \"{name}\" ({}) — recognised.",
                    self.peer_short
                )),
                None => self.push_system(format!(
                    "incoming connection from {} — recognised.",
                    self.peer_short
                )),
            }
            self.push_system(
                "the identity key matches the one you verified before, so there's nothing new",
            );
            self.push_system(
                "to check — the handshake signatures already prove it's the same peer.",
            );
            self.push_system("  /accept   accept and start chatting");
            self.push_system("  /reject   decline this connection");
            self.push_system("  /safety   re-show the safety words, to compare them again");
            return;
        }

        self.status = format!("verify {} · compare the safety words", self.peer_short);
        self.push_system("channel up — now verify you're talking to the right person:");
        match pin {
            PinStatus::New => self.push_system(
                "first time you've accepted this address — check the safety words with care.",
            ),
            PinStatus::Changed => {
                self.push_warning(
                    "⚠ this address's identity key has CHANGED since you last accepted it.",
                );
                self.push_warning(
                    "that can mean the peer reset their identity — or that someone is impersonating them.",
                );
                self.push_warning(
                    "re-check every safety word especially carefully before you /accept.",
                );
            }
            // Handled by the recognised early-return above; kept for exhaustiveness.
            PinStatus::Known => {}
        }
        self.push_safety(safety_number);
        self.push_system("read these aloud with your peer over a channel you already trust");
        self.push_system("(a phone call, in person) — every word must match, in order.");
        self.push_system("the safety words are what you trust, never a display name.");
        self.push_system("  /accept   every word matches — start chatting");
        self.push_system("  /reject   any word differs — disconnect");
    }

    /// Record the user's acceptance, opening the chat if the peer has already
    /// accepted too and otherwise waiting for them.
    fn mark_accepted(&mut self) {
        if self.peer_accepted {
            self.open_chat();
        } else {
            self.mode = Mode::WaitingPeer;
            self.status = format!("waiting for {} to accept…", self.peer_short);
            self.push_system(
                "accepted — waiting for the peer to accept too. Anything you type now",
            );
            self.push_system("is held and sent as soon as they do.");
        }
    }

    /// Record that the peer accepted the channel.
    ///
    /// Returns the lines typed while we were waiting, which the caller sends now
    /// that chat is open — empty unless this completed the mutual acceptance.
    pub fn mark_peer_accepted(&mut self) -> Vec<String> {
        self.peer_accepted = true;
        if self.mode != Mode::WaitingPeer {
            // They accepted before we did; the verify gate still stands, and
            // `mark_accepted` will open the chat when the user says yes.
            return Vec::new();
        }
        self.open_chat();
        std::mem::take(&mut self.pending_lines)
    }

    /// Both sides have accepted: open the chat.
    fn open_chat(&mut self) {
        self.mode = Mode::Connected;
        self.status = self.connected_status();
        let note = if self.recognized {
            "reconnected — type a message and press Enter; /quit to leave."
        } else {
            "verified — type a message and press Enter; /quit to leave."
        };
        self.push_system(note);
        if !self.pending_lines.is_empty() {
            let held = self.pending_lines.len();
            let label = if held == 1 { "message" } else { "messages" };
            self.push_system(format!(
                "sending the {held} {label} you typed while waiting"
            ));
        }
    }

    /// The status-bar text for an active chat, folding in the peer's name if known.
    /// The safety words live in the verify history, not here — they're too long for
    /// the status bar, and re-showable with `/safety`.
    fn connected_status(&self) -> String {
        match &self.peer_name {
            Some(name) => format!("connected to {name} ({})", self.peer_short),
            None => format!("connected to {}", self.peer_short),
        }
    }

    /// Record the display name the peer just shared (or cleared), and note it.
    ///
    /// The name is cosmetic only: it changes how the peer's lines are labelled but
    /// never affects trust, which rests on the already-verified safety number.
    pub fn set_peer_name(&mut self, name: Option<String>) {
        self.peer_name = name;
        let note = match &self.peer_name {
            Some(name) => format!("peer now goes by \"{name}\""),
            None => "peer cleared their display name".to_string(),
        };
        self.push_system(note);
        if self.mode == Mode::Connected {
            self.status = self.connected_status();
        }
    }

    /// Note that the peer accepted before we did, so the verify prompt doesn't look
    /// like it is waiting on them.
    pub fn note_peer_accepted_first(&mut self) {
        self.push_system("the peer has accepted — this connection is waiting on you.");
    }

    /// Return to the lobby (fresh start, or after a peer disconnects / dial fails).
    pub fn set_lobby(&mut self, note: impl Into<String>) {
        self.mode = Mode::Lobby;
        self.status = "lobby".into();
        self.peer_short.clear();
        self.safety_number.clear();
        self.peer_name = None;
        self.peer_accepted = false;
        // Anything still held was meant for a session that never opened.
        if !self.pending_lines.is_empty() {
            let held = self.pending_lines.len();
            let label = if held == 1 { "message" } else { "messages" };
            self.pending_lines.clear();
            self.push_system(format!("{held} unsent {label} discarded"));
        }
        self.push_system(note);
    }

    /// Handle a key press, returning the action for the main loop to perform.
    pub fn on_key(&mut self, key: KeyEvent) -> Action {
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        match key.code {
            KeyCode::Char('c') if ctrl => {
                self.should_quit = true;
                Action::Quit
            }
            KeyCode::Char('u') if ctrl => {
                self.clear_input();
                Action::None
            }
            KeyCode::Char('w') if ctrl => {
                self.delete_word();
                Action::None
            }
            KeyCode::Char('a') if ctrl => {
                self.cursor = 0;
                Action::None
            }
            KeyCode::Char('e') if ctrl => {
                self.cursor = self.input_len();
                Action::None
            }
            // Ignore any other control chord rather than inserting a stray letter.
            KeyCode::Char(_) if ctrl => Action::None,
            KeyCode::Esc => {
                self.should_quit = true;
                Action::Quit
            }
            KeyCode::Enter => self.submit(),
            KeyCode::Backspace => {
                self.backspace();
                Action::None
            }
            KeyCode::Delete => {
                self.delete_forward();
                Action::None
            }
            KeyCode::Left => {
                self.cursor = self.cursor.saturating_sub(1);
                Action::None
            }
            KeyCode::Right => {
                if self.cursor < self.input_len() {
                    self.cursor += 1;
                }
                Action::None
            }
            KeyCode::Home => {
                self.cursor = 0;
                Action::None
            }
            KeyCode::End => {
                self.cursor = self.input_len();
                Action::None
            }
            KeyCode::PageUp => {
                self.scroll_lines = self.scroll_lines.saturating_add(SCROLL_STEP);
                Action::None
            }
            KeyCode::PageDown => {
                self.scroll_lines = self.scroll_lines.saturating_sub(SCROLL_STEP);
                Action::None
            }
            KeyCode::Char(ch) => {
                self.insert_char(ch);
                Action::None
            }
            _ => Action::None,
        }
    }

    /// Insert pasted text at the cursor, as typing would — except that a paste
    /// must never *submit*. Terminals wrap long strings (addresses, notably), so
    /// a paste can arrive with newlines in it; fed through the key path those
    /// become Enter presses, firing off half a message and leaving the rest in
    /// the input line. Here every newline or tab becomes a single space instead,
    /// and other control characters are dropped.
    pub fn on_paste(&mut self, text: &str) {
        // Fold CRLF first so it becomes one space, not two.
        for ch in text.replace("\r\n", "\n").chars() {
            match ch {
                '\n' | '\r' | '\t' => self.insert_char(' '),
                ch if ch.is_control() => {}
                ch => self.insert_char(ch),
            }
        }
    }

    // --- input editing -----------------------------------------------------

    fn input_len(&self) -> usize {
        self.input.chars().count()
    }

    /// Byte offset of character index `char_idx` (or end-of-string past the last).
    fn byte_index(&self, char_idx: usize) -> usize {
        self.input
            .char_indices()
            .nth(char_idx)
            .map_or(self.input.len(), |(i, _)| i)
    }

    fn insert_char(&mut self, ch: char) {
        let byte = self.byte_index(self.cursor);
        self.input.insert(byte, ch);
        self.cursor += 1;
    }

    fn backspace(&mut self) {
        if self.cursor == 0 {
            return;
        }
        let start = self.byte_index(self.cursor - 1);
        let end = self.byte_index(self.cursor);
        self.input.replace_range(start..end, "");
        self.cursor -= 1;
    }

    fn delete_forward(&mut self) {
        if self.cursor >= self.input_len() {
            return;
        }
        let start = self.byte_index(self.cursor);
        let end = self.byte_index(self.cursor + 1);
        self.input.replace_range(start..end, "");
    }

    /// Delete the whitespace-delimited word to the left of the cursor (Ctrl-W).
    fn delete_word(&mut self) {
        let chars: Vec<char> = self.input.chars().collect();
        let mut start = self.cursor;
        while start > 0 && chars[start - 1] == ' ' {
            start -= 1;
        }
        while start > 0 && chars[start - 1] != ' ' {
            start -= 1;
        }
        let start_byte = self.byte_index(start);
        let end_byte = self.byte_index(self.cursor);
        self.input.replace_range(start_byte..end_byte, "");
        self.cursor = start;
    }

    fn clear_input(&mut self) {
        self.input.clear();
        self.cursor = 0;
    }

    // --- command handling --------------------------------------------------

    fn submit(&mut self) -> Action {
        let mut line = self.input.trim().to_string();
        self.clear_input();
        if line.is_empty() {
            return Action::None;
        }
        // A single leading slash is a command. A doubled one (`//`) escapes it, so a
        // message that genuinely starts with a slash — "//shrug" — can be sent as
        // "/shrug" rather than parsed as a command.
        if let Some(rest) = line.strip_prefix('/') {
            if rest.starts_with('/') {
                line.remove(0); // drop one slash; send the rest as an ordinary message
            } else {
                return self.run_command(rest);
            }
        }
        match self.mode {
            Mode::Connected | Mode::WaitingPeer => {
                // Cap the length before echoing or sending: an over-long line would
                // otherwise be a frame the peer rejects, tearing down their session.
                let len = line.chars().count();
                if len > message::MAX_MESSAGE_CHARS {
                    self.push_system(format!(
                        "message too long ({len} characters, max {}) — not sent",
                        message::MAX_MESSAGE_CHARS
                    ));
                    return Action::None;
                }
                self.push(Author::You, line.clone());
                if self.mode == Mode::WaitingPeer {
                    // Chat isn't open yet: hold the line rather than dropping it,
                    // and send it the moment the peer accepts.
                    self.pending_lines.push(line);
                    return Action::None;
                }
                Action::Send(line)
            }
            Mode::Verifying => {
                if self.recognized {
                    self.push_system("this connection is waiting on you: /accept or /reject");
                } else {
                    self.push_system("compare the safety words first: /accept or /reject");
                }
                Action::None
            }
            _ => {
                self.push_system("not connected — use /connect <address>");
                Action::None
            }
        }
    }

    fn run_command(&mut self, command: &str) -> Action {
        let mut parts = command.split_whitespace();
        let name = parts.next().unwrap_or("");
        let arg = parts.next();
        match name {
            // Allowed from the lobby or while connected (which switches peers);
            // refused mid-dial and mid-verify, when there's nothing sensible to do.
            // The whole rest of the line is the address: the word form is 24
            // whitespace-separated words, so taking a single token would cut it off.
            "connect" | "c" => {
                let rest = command
                    .split_once(char::is_whitespace)
                    .map(|(_, rest)| rest.trim().to_string())
                    .unwrap_or_default();
                if rest.is_empty() {
                    self.push_system("usage: /connect <address>");
                    Action::None
                } else if matches!(self.mode, Mode::Lobby | Mode::Connected) {
                    Action::Connect(rest)
                } else {
                    // Mid-verify or waiting on the peer: there's a pending decision or
                    // a half-open channel, so finish (or /reject) it before dialling out.
                    self.push_system("finish the current connection first");
                    Action::None
                }
            }
            "accept" | "a" => {
                if self.mode == Mode::Verifying {
                    self.mark_accepted();
                    // The main loop announces our acceptance to the peer and shares
                    // our display name (if any) now — never before.
                    Action::Accept
                } else {
                    self.push_system("nothing to accept right now");
                    Action::None
                }
            }
            "name" | "n" => {
                // Take everything after the command word so names may contain spaces;
                // an empty argument clears the name. The main loop sanitises, persists,
                // and (if we're already chatting) shares the result.
                let raw = command
                    .split_once(char::is_whitespace)
                    .map(|(_, rest)| rest.trim().to_string())
                    .unwrap_or_default();
                Action::SetName(raw)
            }
            // Also allowed while waiting on the peer: having accepted shouldn't trap
            // the user in a half-open channel if the peer never answers.
            "reject" | "r" => {
                if matches!(self.mode, Mode::Verifying | Mode::WaitingPeer) {
                    Action::RejectPeer
                } else {
                    self.push_system("nothing to reject right now");
                    Action::None
                }
            }
            "address" | "addr" => {
                if arg == Some("words") {
                    self.push_address_words();
                } else {
                    self.push_system("your address — the kiss1… form is the one to share:");
                    let bech32 = grouped_bech32(&self.my_address.bech32);
                    self.push(Author::Address, bech32);
                    self.push_system("as plain hex, for peers on older kiss_chat versions:");
                    let hex = self.my_address.hex.clone();
                    self.push(Author::Address, hex);
                    self.push_system(
                        "also shareable as words (/address words) or as a QR code (/qr)",
                    );
                }
                Action::None
            }
            "qr" => {
                match qr_half_blocks(&self.my_address.bech32) {
                    Ok(qr) => {
                        self.push_system(
                            "your address as a QR code — scan it with another device:",
                        );
                        self.push(Author::Qr, qr);
                    }
                    Err(err) => self.push_system(format!("could not build the QR code: {err}")),
                }
                Action::None
            }
            // The contact list lives on disk, so the main loop reads it and reports
            // back; usable in any mode, since it only reads.
            "contacts" | "peers" => Action::ListContacts,
            "safety" | "s" => {
                if self.safety_number.is_empty() {
                    self.push_system("no safety words yet — connect to a peer first");
                } else {
                    let phrase = self.safety_number.clone();
                    self.push_safety(phrase);
                }
                Action::None
            }
            "clear" => {
                self.history.clear();
                self.scroll_lines = 0;
                Action::None
            }
            "version" | "v" => {
                self.push_system(format!("kiss_chat {VERSION}"));
                Action::None
            }
            "quit" | "q" => {
                self.should_quit = true;
                Action::Quit
            }
            "help" | "h" | "?" => {
                self.push_system("commands:");
                self.push_system(
                    "  /connect <address>   dial a peer (switches if already connected)",
                );
                self.push_system(
                    "  /accept              accept the peer (compare the safety words first, if prompted)",
                );
                self.push_system("  /reject              reject the peer being verified");
                self.push_system(
                    "  /name [text]         set your display name (empty clears); shared on /accept",
                );
                self.push_system("  /safety              re-show the current safety words");
                self.push_system("  /contacts            list the peers you've accepted before");
                self.push_system("  /address [words]     show your own address to share");
                self.push_system("  /qr                  show your own address as a QR code");
                self.push_system("  /clear               clear the screen");
                self.push_system("  /version             show the version (alias /v)");
                self.push_system("  /help                show this help");
                self.push_system("  /quit                exit (or Esc / Ctrl-C)");
                self.push_system("  //text               send a message that begins with a slash");
                self.push_system(
                    "keys: ←/→ Home/End move · Ctrl-A/Ctrl-E start/end · Ctrl-U/W edit · PageUp/PageDown scroll",
                );
                Action::None
            }
            other => {
                self.push_system(format!("unknown command: /{other} (try /help)"));
                Action::None
            }
        }
    }

    pub fn render(&mut self, frame: &mut Frame) {
        let [msg_area, input_area] =
            Layout::vertical([Constraint::Min(1), Constraint::Length(3)]).areas(frame.area());

        // Wrap the whole history to the inner width, then show the window that fits,
        // honouring any scrollback. Clamp the scroll offset to what actually exists.
        let inner = Block::bordered().inner(msg_area);
        let width = inner.width as usize;
        let height = inner.height as usize;

        let mut wrapped: Vec<Line<'static>> = Vec::new();
        let peer_name = self.peer_name.as_deref();
        for line in &self.history {
            wrapped.extend(wrapped_lines(line, width, peer_name));
        }
        let total = wrapped.len();
        let max_scroll = total.saturating_sub(height);
        if self.scroll_lines > max_scroll {
            self.scroll_lines = max_scroll;
        }
        let start = max_scroll - self.scroll_lines;
        let items: Vec<ListItem> = wrapped
            .into_iter()
            .skip(start)
            .take(height)
            .map(ListItem::new)
            .collect();

        let title = if self.scroll_lines > 0 {
            format!(
                " kiss_chat ({VERSION}) — {} · [↑{} more] ",
                self.status, self.scroll_lines
            )
        } else {
            format!(" kiss_chat ({VERSION}) — {} ", self.status)
        };
        frame.render_widget(
            List::new(items).block(Block::bordered().title(title)),
            msg_area,
        );

        // Input line: prompt reflects whether we're chatting, verifying, or commanding.
        let (label, color) = match self.mode {
            Mode::Connected => ("message", Color::Blue),
            Mode::WaitingPeer => ("waiting for peer to accept — type to queue", Color::Yellow),
            Mode::Verifying if self.recognized => {
                ("accept connection? /accept or /reject", Color::Yellow)
            }
            Mode::Verifying => ("verify: /accept or /reject", Color::Yellow),
            Mode::Connecting => ("connecting…", Color::Yellow),
            Mode::Lobby => ("command (/connect <address>, /help)", Color::Magenta),
        };
        // The cursor's display column (wide glyphs such as CJK/emoji take two
        // cells), and a horizontal scroll that keeps it in view once the line
        // outgrows the box — so a long peer id no longer overflows the border.
        let inner_width = input_area.width.saturating_sub(2) as usize;
        let cursor_col = Span::raw(&self.input[..self.byte_index(self.cursor)]).width();
        let scroll_x = horizontal_scroll(cursor_col, inner_width);

        let input_block = Block::bordered()
            .title(label)
            .border_style(Style::new().fg(color));
        frame.render_widget(
            Paragraph::new(self.input.as_str())
                .scroll((0, scroll_x as u16))
                .block(input_block),
            input_area,
        );

        // Place the cursor within the box, shifted left by the horizontal scroll.
        let cursor_x = input_area.x + 1 + (cursor_col - scroll_x) as u16;
        frame.set_cursor_position((cursor_x, input_area.y + 1));
    }
}

/// Horizontal scroll offset that keeps the cursor — at display column `cursor_col`
/// — visible inside an input box `inner_width` columns wide. Zero until the cursor
/// reaches the right edge, then just enough to pin it to the last visible column.
fn horizontal_scroll(cursor_col: usize, inner_width: usize) -> usize {
    cursor_col.saturating_sub(inner_width.max(1) - 1)
}

/// Current UTC time as `HH:MM`.
fn timestamp_now() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let secs_of_day = secs % 86_400;
    format!("{:02}:{:02}", secs_of_day / 3600, (secs_of_day % 3600) / 60)
}

/// Render one [`ChatLine`] into one or more display lines, wrapped to `width`.
///
/// `peer_name` is the peer's chosen display name, if known; it labels their lines
/// in place of the generic "peer".
fn wrapped_lines(line: &ChatLine, width: usize, peer_name: Option<&str>) -> Vec<Line<'static>> {
    // The word blocks, address forms, and QR code get bespoke layouts rather
    // than the label-plus-body treatment every other line shares.
    match line.author {
        Author::Safety => {
            return word_grid_lines(
                &line.text,
                width,
                &line.timestamp,
                "safety words",
                SAFETY_ACCENT,
            );
        }
        Author::AddressWords => {
            return word_grid_lines(
                &line.text,
                width,
                &line.timestamp,
                "address words",
                ADDRESS_ACCENT,
            );
        }
        Author::Address => return address_lines(&line.text, width),
        Author::Qr => return qr_lines(&line.text, width),
        _ => {}
    }
    let (label, color): (&str, Color) = match line.author {
        Author::You => ("you", Color::Cyan),
        Author::Peer => (peer_name.unwrap_or("peer"), Color::Green),
        Author::System => ("--", Color::DarkGray),
        Author::Warning => ("!!", Color::Red),
        // Handled by the early returns above; kept for exhaustiveness.
        Author::Safety | Author::Address | Author::AddressWords | Author::Qr => {
            unreachable!("bespoke layouts returned early")
        }
    };
    let time = format!("{} ", line.timestamp);
    let head = format!("{label}: ");
    let prefix_width = time.chars().count() + head.chars().count();
    let indent = " ".repeat(prefix_width);
    let avail = width.saturating_sub(prefix_width).max(1);

    let time_style = Style::new().fg(Color::DarkGray);
    let head_style = Style::new().fg(color).add_modifier(Modifier::BOLD);
    // A warning colours its whole body, not just the label, so it can't be skimmed past.
    let body_style = match line.author {
        Author::Warning => Style::new().fg(Color::Red),
        _ => Style::new(),
    };

    let chunks = wrap_text(&line.text, avail);
    if chunks.is_empty() {
        return vec![Line::from(vec![
            Span::styled(time, time_style),
            Span::styled(head, head_style),
        ])];
    }
    chunks
        .into_iter()
        .enumerate()
        .map(|(i, chunk)| {
            if i == 0 {
                Line::from(vec![
                    Span::styled(time.clone(), time_style),
                    Span::styled(head.clone(), head_style),
                    Span::styled(chunk, body_style),
                ])
            } else {
                Line::from(vec![
                    Span::raw(indent.clone()),
                    Span::styled(chunk, body_style),
                ])
            }
        })
        .collect()
}

/// Render a word phrase as a highlighted, numbered grid framed by blank lines —
/// the shared layout of the safety words and the word form of an address, kept
/// visually apart by `header` and `accent` (and the guidance pushed around them).
///
/// Numbering each word lets people compare or transcribe by position (so a
/// dropped or swapped word is obvious), and the accent colour plus bold weight
/// lift the block clear of the dim system chatter around it. The grid reflows to
/// `width`: as many columns as fit, collapsing to a single column in a narrow
/// terminal.
fn word_grid_lines(
    phrase: &str,
    width: usize,
    timestamp: &str,
    header: &'static str,
    accent: Color,
) -> Vec<Line<'static>> {
    let words: Vec<&str> = phrase.split_whitespace().collect();
    let dim = Style::new().fg(Color::DarkGray);
    let accent = Style::new().fg(accent).add_modifier(Modifier::BOLD);

    // A blank spacer above, then the header carrying the timestamp prefix.
    let mut lines = vec![
        Line::from(""),
        Line::from(vec![
            Span::styled(format!("{timestamp} "), dim),
            Span::styled(header, accent),
        ]),
    ];

    if words.is_empty() {
        return lines;
    }

    // Cell = right-aligned number, a space, then the word padded to a common
    // width with a two-space gutter. Column count is whatever fits `width`.
    let indent = 4usize;
    let longest = words.iter().map(|w| w.chars().count()).max().unwrap_or(1);
    let num_w = words.len().to_string().len().max(2);
    let cell_w = num_w + 1 + longest + 2;
    let usable = width.saturating_sub(indent).max(cell_w);
    let cols = (usable / cell_w).max(1);

    for (row, chunk) in words.chunks(cols).enumerate() {
        let mut spans = vec![Span::raw(" ".repeat(indent))];
        for (col, word) in chunk.iter().enumerate() {
            let n = row * cols + col + 1;
            spans.push(Span::styled(format!("{n:>num_w$} "), dim));
            spans.push(Span::styled(
                format!("{:<pad$}", word, pad = longest + 2),
                accent,
            ));
        }
        lines.push(Line::from(spans));
    }
    // A blank spacer below, so the block stands apart from the guidance that follows.
    lines.push(Line::from(""));
    lines
}

/// The indent, in columns, of a copyable address line — small on purpose, so the
/// line fits unbroken in terminals as narrow as the address plus two columns.
const ADDRESS_INDENT: usize = 2;

/// Render one form of our own address as a bare, copyable block: no timestamp or
/// label prefix (they'd waste width and ride along on a drag-select), a small
/// indent, wrapping only at the spaces already in the text. A wrapped copy is
/// still fine — every place an address is entered strips such damage — but the
/// narrow indent keeps most terminals from wrapping it at all.
fn address_lines(text: &str, width: usize) -> Vec<Line<'static>> {
    let avail = width.saturating_sub(ADDRESS_INDENT).max(1);
    let style = Style::new().fg(ADDRESS_ACCENT).add_modifier(Modifier::BOLD);
    wrap_text(text, avail)
        .into_iter()
        .map(|chunk| {
            Line::from(vec![
                Span::raw(" ".repeat(ADDRESS_INDENT)),
                Span::styled(chunk, style),
            ])
        })
        .collect()
}

/// Render a QR code (pre-drawn in half-block characters) without ever wrapping
/// it — a wrapped QR code scans as nothing. In a terminal too narrow to show it,
/// a note takes its place; the code reappears once the window is widened, since
/// layout is recomputed from the same history every frame.
fn qr_lines(qr: &str, width: usize) -> Vec<Line<'static>> {
    let needed = qr.lines().map(|l| l.chars().count()).max().unwrap_or(0);
    if needed > width {
        return vec![Line::from(Span::styled(
            format!("(the QR code needs {needed} columns — widen the window to show it)"),
            Style::new().fg(Color::DarkGray),
        ))];
    }
    qr.lines()
        .map(|l| Line::from(Span::raw(l.to_string())))
        .collect()
}

/// Group the `kiss1…` form for reading: the prefix, then the data in blocks of
/// four — "kiss1 q3f8 x0lm …". The spaces survive a round trip because address
/// parsing discards separators.
fn grouped_bech32(bech32: &str) -> String {
    let (prefix, data) = match bech32.split_once('1') {
        Some((hrp, data)) => (format!("{hrp}1"), data),
        None => (String::new(), bech32),
    };
    let mut grouped = prefix;
    for (i, ch) in data.chars().enumerate() {
        if i % 4 == 0 {
            grouped.push(' ');
        }
        grouped.push(ch);
    }
    grouped.trim().to_string()
}

/// Draw the address as a QR code in Unicode half-block characters, two modules
/// per character cell.
///
/// The bech32 form is uppercased first: the bech32 charset then fits QR
/// *alphanumeric* mode, which yields a visibly smaller code — and scanners
/// don't care about case, since address parsing lowercases anyway.
fn qr_half_blocks(bech32: &str) -> Result<String, qrcode::types::QrError> {
    use qrcode::render::unicode::Dense1x2;
    let code = qrcode::QrCode::new(bech32.to_uppercase().as_bytes())?;
    // Terminals are usually light-on-dark, so paint the *light* modules with the
    // foreground colour and leave the dark ones to the background: that gives
    // dark modules on a bright quiet zone, the orientation scanners like best.
    Ok(code
        .render::<Dense1x2>()
        .dark_color(Dense1x2::Light)
        .light_color(Dense1x2::Dark)
        .build())
}

/// Word-wrap `text` to at most `width` characters per line, hard-splitting any
/// single word longer than `width`.
fn wrap_text(text: &str, width: usize) -> Vec<String> {
    if text.is_empty() {
        return Vec::new();
    }
    let width = width.max(1);
    let mut lines = Vec::new();
    let mut current = String::new();
    let mut current_len = 0usize;

    for word in text.split(' ') {
        let word_len = word.chars().count();
        if word_len > width {
            if !current.is_empty() {
                lines.push(std::mem::take(&mut current));
            }
            let mut chunk = String::new();
            for ch in word.chars() {
                if chunk.chars().count() == width {
                    lines.push(std::mem::take(&mut chunk));
                }
                chunk.push(ch);
            }
            current = chunk;
            current_len = current.chars().count();
            continue;
        }
        let needed = if current.is_empty() {
            word_len
        } else {
            current_len + 1 + word_len
        };
        if needed > width {
            lines.push(std::mem::take(&mut current));
            current.push_str(word);
            current_len = word_len;
        } else {
            if !current.is_empty() {
                current.push(' ');
                current_len += 1;
            }
            current.push_str(word);
            current_len += word_len;
        }
    }
    if !current.is_empty() {
        lines.push(current);
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    // Concatenate a rendered line's spans back into plain text for assertions.
    fn line_text(line: &Line) -> String {
        line.spans.iter().map(|s| s.content.as_ref()).collect()
    }

    // A fake own-address: the tests here exercise display and recall, never
    // encoding, so the forms only have to be recognisable.
    fn test_address() -> OwnAddress {
        OwnAddress {
            hex: "my-addr".into(),
            bech32: "kiss1testform".into(),
            words: "alpha beta gamma delta".into(),
        }
    }

    // Type a whole line and press Enter, returning the resulting action.
    fn submit_line(app: &mut App, line: &str) -> Action {
        for ch in line.chars() {
            app.on_key(KeyEvent::new(KeyCode::Char(ch), KeyModifiers::empty()));
        }
        app.on_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::empty()))
    }

    // Drive the app into an open chat: both sides accept (us first).
    fn reach_connected(app: &mut App) {
        app.set_verifying("peer".into(), "ab-cd".into(), PinStatus::New, None);
        let _ = submit_line(app, "/accept");
        let _ = app.mark_peer_accepted();
    }

    #[test]
    fn connect_command_in_lobby_yields_connect_action() {
        let mut app = App::new(test_address());
        match submit_line(&mut app, "/connect abc123") {
            Action::Connect(id) => assert_eq!(id, "abc123"),
            _ => panic!("expected Connect"),
        }
    }

    #[test]
    fn connect_without_argument_is_rejected() {
        let mut app = App::new(test_address());
        assert!(matches!(submit_line(&mut app, "/connect"), Action::None));
    }

    #[test]
    fn plain_text_in_lobby_is_not_sent() {
        let mut app = App::new(test_address());
        assert!(matches!(submit_line(&mut app, "hello"), Action::None));
    }

    #[test]
    fn text_while_verifying_is_not_sent() {
        let mut app = App::new(test_address());
        app.set_verifying("peer".into(), "ab-cd".into(), PinStatus::New, None);
        assert!(matches!(submit_line(&mut app, "hi"), Action::None));
    }

    #[test]
    fn accept_then_text_is_sent() {
        let mut app = App::new(test_address());
        reach_connected(&mut app);
        match submit_line(&mut app, "hi there") {
            Action::Send(line) => assert_eq!(line, "hi there"),
            _ => panic!("expected Send after /accept"),
        }
    }

    #[test]
    fn an_over_long_message_is_refused_not_sent() {
        // A line past the cap must not be echoed or sent — otherwise it becomes a
        // frame the peer rejects, tearing their session down.
        let mut app = App::new(test_address());
        reach_connected(&mut app);
        let long = "a".repeat(message::MAX_MESSAGE_CHARS + 1);
        assert!(matches!(submit_line(&mut app, &long), Action::None));
        assert!(
            app.history.iter().any(|l| l.text.contains("too long")),
            "the user should be told the message was too long"
        );
        // A "you:" echo must not have been recorded for the refused line.
        assert!(
            !app.history.iter().any(|l| matches!(l.author, Author::You)),
            "a refused message must not be echoed locally"
        );
    }

    #[test]
    fn double_slash_escapes_a_leading_slash_in_a_message() {
        // "//shrug" must be sent verbatim as "/shrug", not parsed as a command.
        let mut app = App::new(test_address());
        reach_connected(&mut app);
        match submit_line(&mut app, "//shrug") {
            Action::Send(line) => assert_eq!(line, "/shrug"),
            _ => panic!("expected the escaped line to be sent as a message"),
        }
        // The local echo carries the de-escaped text too.
        assert!(
            app.history
                .iter()
                .any(|l| matches!(l.author, Author::You) && l.text == "/shrug")
        );
    }

    #[test]
    fn a_single_slash_still_routes_as_a_command() {
        // The escape must not disturb ordinary command parsing.
        let mut app = App::new(test_address());
        match submit_line(&mut app, "/connect abc123") {
            Action::Connect(id) => assert_eq!(id, "abc123"),
            _ => panic!("expected a single slash to route as a command"),
        }
    }

    #[test]
    fn a_message_at_the_cap_is_sent() {
        let mut app = App::new(test_address());
        reach_connected(&mut app);
        let at_cap = "a".repeat(message::MAX_MESSAGE_CHARS);
        assert!(matches!(submit_line(&mut app, &at_cap), Action::Send(_)));
    }

    #[test]
    fn accepting_waits_for_the_peer_before_opening_chat() {
        // Our /accept alone must not open the chat: the peer hasn't accepted yet,
        // so anything sent now could not be shown by them.
        let mut app = App::new(test_address());
        app.set_verifying("peer".into(), "ab-cd".into(), PinStatus::New, None);
        let _ = submit_line(&mut app, "/accept");
        assert_eq!(app.mode, Mode::WaitingPeer);
        assert!(app.status.contains("waiting"));

        // Their acceptance opens it.
        let _ = app.mark_peer_accepted();
        assert_eq!(app.mode, Mode::Connected);
    }

    #[test]
    fn a_peer_accepting_first_opens_chat_on_our_accept() {
        // The other ordering: they accept while we're still verifying, so our
        // /accept completes the mutual acceptance and opens chat immediately.
        let mut app = App::new(test_address());
        app.set_verifying("peer".into(), "ab-cd".into(), PinStatus::New, None);
        let flushed = app.mark_peer_accepted();
        assert!(
            flushed.is_empty(),
            "nothing can be queued before we've accepted"
        );
        // Their acceptance must not bypass our verify gate.
        assert_eq!(app.mode, Mode::Verifying);

        let _ = submit_line(&mut app, "/accept");
        assert_eq!(app.mode, Mode::Connected);
    }

    #[test]
    fn lines_typed_while_waiting_are_held_and_flushed_in_order() {
        // The message-loss window this release closes: text typed after our accept
        // but before the peer's must reach them, not vanish.
        let mut app = App::new(test_address());
        app.set_verifying("peer".into(), "ab-cd".into(), PinStatus::New, None);
        let _ = submit_line(&mut app, "/accept");

        assert!(matches!(submit_line(&mut app, "first"), Action::None));
        assert!(matches!(submit_line(&mut app, "second"), Action::None));
        // The user sees their own lines immediately, even though they're held.
        assert!(
            app.history
                .iter()
                .any(|l| matches!(l.author, Author::You) && l.text == "first")
        );

        assert_eq!(app.mark_peer_accepted(), vec!["first", "second"]);
        // Flushing empties the queue, so a later event can't resend them.
        assert!(app.mark_peer_accepted().is_empty());
    }

    #[test]
    fn held_lines_are_discarded_when_the_channel_never_opens() {
        let mut app = App::new(test_address());
        app.set_verifying("peer".into(), "ab-cd".into(), PinStatus::New, None);
        let _ = submit_line(&mut app, "/accept");
        let _ = submit_line(&mut app, "held");

        app.set_lobby("peer left");
        assert!(app.pending_lines.is_empty());
        // And a fresh session can't inherit the previous peer's acceptance.
        app.set_verifying("other".into(), "ef-gh".into(), PinStatus::New, None);
        assert!(!app.peer_accepted);
    }

    #[test]
    fn an_over_long_message_is_refused_while_waiting_too() {
        let mut app = App::new(test_address());
        app.set_verifying("peer".into(), "ab-cd".into(), PinStatus::New, None);
        let _ = submit_line(&mut app, "/accept");
        let long = "a".repeat(message::MAX_MESSAGE_CHARS + 1);
        assert!(matches!(submit_line(&mut app, &long), Action::None));
        assert!(
            app.pending_lines.is_empty(),
            "an over-long line must not be queued either"
        );
    }

    #[test]
    fn reject_is_allowed_while_waiting_on_the_peer() {
        // Having accepted must not trap the user in a half-open channel.
        let mut app = App::new(test_address());
        app.set_verifying("peer".into(), "ab-cd".into(), PinStatus::New, None);
        let _ = submit_line(&mut app, "/accept");
        assert!(matches!(
            submit_line(&mut app, "/reject"),
            Action::RejectPeer
        ));
    }

    #[test]
    fn reject_yields_reject_action() {
        let mut app = App::new(test_address());
        app.set_verifying("peer".into(), "ab-cd".into(), PinStatus::New, None);
        assert!(matches!(
            submit_line(&mut app, "/reject"),
            Action::RejectPeer
        ));
    }

    #[test]
    fn accept_while_verifying_yields_accept_action() {
        let mut app = App::new(test_address());
        app.set_verifying("peer".into(), "ab-cd".into(), PinStatus::New, None);
        assert!(matches!(submit_line(&mut app, "/accept"), Action::Accept));
    }

    #[test]
    fn changed_identity_key_raises_a_warning_during_verification() {
        let mut app = App::new(test_address());
        app.set_verifying("peer".into(), "ab-cd".into(), PinStatus::Changed, None);
        assert!(
            app.history
                .iter()
                .any(|l| matches!(l.author, Author::Warning) && l.text.contains("CHANGED")),
            "a changed identity key must surface a warning line"
        );
    }

    #[test]
    fn recognised_peer_is_noted_without_a_warning() {
        let mut app = App::new(test_address());
        app.set_verifying("peer".into(), "ab-cd".into(), PinStatus::Known, None);
        assert!(app.history.iter().any(|l| l.text.contains("recognised")));
        assert!(
            !app.history
                .iter()
                .any(|l| matches!(l.author, Author::Warning)),
            "a matching key must not raise a warning"
        );
    }

    #[test]
    fn recognised_peer_shows_its_cached_name() {
        let mut app = App::new(test_address());
        app.set_verifying(
            "peer".into(),
            "ab-cd".into(),
            PinStatus::Known,
            Some("Alice".into()),
        );
        assert!(
            app.history
                .iter()
                .any(|l| l.text.contains("from \"Alice\"")),
            "a recognised peer's cached name should be shown"
        );
    }

    #[test]
    fn recognised_peer_skips_the_safety_word_ritual() {
        // A known peer is asked only for consent — the safety-word block is not shown
        // up front, and the prompt reads as an incoming-connection consent.
        let mut app = App::new(test_address());
        app.set_verifying("peer".into(), "ab-cd".into(), PinStatus::Known, None);
        assert!(
            !app.history
                .iter()
                .any(|l| matches!(l.author, Author::Safety)),
            "a recognised peer should not be shown the safety words up front"
        );
        assert!(
            app.history
                .iter()
                .any(|l| l.text.contains("incoming connection")),
            "a recognised peer should get a consent-to-connect prompt"
        );
    }

    #[test]
    fn a_new_or_changed_peer_is_shown_the_safety_words() {
        for pin in [PinStatus::New, PinStatus::Changed] {
            let mut app = App::new(test_address());
            app.set_verifying("peer".into(), "ab-cd".into(), pin, None);
            assert!(
                app.history
                    .iter()
                    .any(|l| matches!(l.author, Author::Safety)),
                "an unrecognised or changed peer must show the safety words to compare"
            );
        }
    }

    #[test]
    fn recognised_peer_still_requires_explicit_accept() {
        // The consent gate stands: a recognised peer can't force us straight into chat.
        let mut app = App::new(test_address());
        app.set_verifying("peer".into(), "ab-cd".into(), PinStatus::Known, None);
        // Typing plain text does not slip past the gate.
        assert!(matches!(submit_line(&mut app, "hi"), Action::None));
        // Only /accept proceeds.
        assert!(matches!(submit_line(&mut app, "/accept"), Action::Accept));
    }

    #[test]
    fn safety_command_reshows_words_for_a_recognised_peer() {
        // Even when the ritual is skipped, the user can pull the words up on demand.
        let mut app = App::new(test_address());
        app.set_verifying("peer".into(), "ab-cd".into(), PinStatus::Known, None);
        assert!(
            !app.history
                .iter()
                .any(|l| matches!(l.author, Author::Safety))
        );
        let _ = submit_line(&mut app, "/safety");
        assert!(
            app.history
                .iter()
                .any(|l| matches!(l.author, Author::Safety)),
            "/safety must surface the words even for a recognised peer"
        );
    }

    #[test]
    fn contacts_command_yields_a_list_action() {
        let mut app = App::new(test_address());
        assert!(matches!(
            submit_line(&mut app, "/contacts"),
            Action::ListContacts
        ));
    }

    #[test]
    fn accept_outside_verifying_does_nothing() {
        let mut app = App::new(test_address());
        assert!(matches!(submit_line(&mut app, "/accept"), Action::None));
    }

    #[test]
    fn name_command_keeps_spaces_and_reports_the_whole_name() {
        let mut app = App::new(test_address());
        match submit_line(&mut app, "/name Alice Smith") {
            Action::SetName(name) => assert_eq!(name, "Alice Smith"),
            _ => panic!("expected SetName"),
        }
    }

    #[test]
    fn bare_name_command_clears_the_name() {
        let mut app = App::new(test_address());
        match submit_line(&mut app, "/name") {
            Action::SetName(name) => assert!(name.is_empty()),
            _ => panic!("expected SetName with an empty argument"),
        }
    }

    #[test]
    fn peer_lines_use_the_display_name_when_known() {
        let line = ChatLine {
            author: Author::Peer,
            text: "hi".into(),
            timestamp: "12:00".into(),
        };
        let named = wrapped_lines(&line, 40, Some("Alice"));
        assert!(line_text(&named[0]).contains("Alice:"));
        let anon = wrapped_lines(&line, 40, None);
        assert!(line_text(&anon[0]).contains("peer:"));
    }

    #[test]
    fn peer_name_shows_in_the_connected_status() {
        let mut app = App::new(test_address());
        reach_connected(&mut app);
        app.set_peer_name(Some("Alice".into()));
        assert!(app.status.contains("Alice"));
        // Clearing reverts to the plain peer id in the status line.
        app.set_peer_name(None);
        assert!(!app.status.contains("Alice"));
    }

    #[test]
    fn connect_while_connected_switches_peers() {
        let mut app = App::new(test_address());
        reach_connected(&mut app);
        match submit_line(&mut app, "/connect newpeer") {
            Action::Connect(id) => assert_eq!(id, "newpeer"),
            _ => panic!("expected Connect to switch peers"),
        }
    }

    #[test]
    fn connect_is_refused_while_dialing() {
        let mut app = App::new(test_address());
        app.set_connecting("peer".into());
        assert!(matches!(
            submit_line(&mut app, "/connect abc"),
            Action::None
        ));
    }

    #[test]
    fn connect_is_refused_while_verifying() {
        let mut app = App::new(test_address());
        app.set_verifying("peer".into(), "ab-cd".into(), PinStatus::New, None);
        assert!(matches!(
            submit_line(&mut app, "/connect abc"),
            Action::None
        ));
    }

    #[test]
    fn clear_command_empties_the_history() {
        let mut app = App::new(test_address());
        assert!(!app.history.is_empty());
        assert!(matches!(submit_line(&mut app, "/clear"), Action::None));
        assert!(app.history.is_empty());
    }

    #[test]
    fn version_command_reports_the_crate_version() {
        let mut app = App::new(test_address());
        assert!(matches!(submit_line(&mut app, "/version"), Action::None));
        assert!(
            app.history
                .iter()
                .any(|line| line.text.contains(env!("CARGO_PKG_VERSION"))),
            "/version should report the crate version"
        );
        // The /v alias behaves identically.
        let mut app = App::new(test_address());
        let _ = submit_line(&mut app, "/v");
        assert!(
            app.history
                .iter()
                .any(|line| line.text.contains(env!("CARGO_PKG_VERSION")))
        );
    }

    #[test]
    fn address_command_recalls_own_address_after_clear() {
        let mut app = App::new(test_address());
        let _ = submit_line(&mut app, "/clear");
        assert!(app.history.is_empty());
        assert!(matches!(submit_line(&mut app, "/address"), Action::None));
        assert!(app.history.iter().any(|line| line.text.contains("my-addr")));
    }

    #[test]
    fn quit_command_and_ctrl_c_both_quit() {
        let mut app = App::new(test_address());
        assert!(matches!(submit_line(&mut app, "/quit"), Action::Quit));
        assert!(app.should_quit);

        let mut app = App::new(test_address());
        let ctrl_c = KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL);
        assert!(matches!(app.on_key(ctrl_c), Action::Quit));
    }

    #[test]
    fn cursor_editing_inserts_in_the_middle() {
        let mut app = App::new(test_address());
        for ch in "helo".chars() {
            app.on_key(KeyEvent::new(KeyCode::Char(ch), KeyModifiers::empty()));
        }
        // Move left once (cursor between 'l' and 'o') and insert the missing 'l'.
        app.on_key(KeyEvent::new(KeyCode::Left, KeyModifiers::empty()));
        app.on_key(KeyEvent::new(KeyCode::Char('l'), KeyModifiers::empty()));
        assert_eq!(app.input, "hello");
        assert_eq!(app.cursor, 4);
    }

    #[test]
    fn ctrl_u_clears_the_input() {
        let mut app = App::new(test_address());
        for ch in "noise".chars() {
            app.on_key(KeyEvent::new(KeyCode::Char(ch), KeyModifiers::empty()));
        }
        app.on_key(KeyEvent::new(KeyCode::Char('u'), KeyModifiers::CONTROL));
        assert_eq!(app.input, "");
        assert_eq!(app.cursor, 0);
    }

    // Join a rendered block back into one blob for substring assertions.
    fn render_blob(line: &ChatLine, width: usize) -> String {
        wrapped_lines(line, width, None)
            .iter()
            .map(line_text)
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn safety_line(phrase: &str) -> ChatLine {
        ChatLine {
            author: Author::Safety,
            text: phrase.into(),
            timestamp: "12:00".into(),
        }
    }

    #[test]
    fn safety_words_render_as_a_numbered_block() {
        let phrase = "alpha bravo charlie delta echo foxtrot golf hotel india juliet kilo lima";
        let blob = render_blob(&safety_line(phrase), 80);
        assert!(blob.contains("safety words"));
        // Every word survives, and the first and last carry their position number.
        for word in phrase.split_whitespace() {
            assert!(blob.contains(word), "missing safety word: {word}");
        }
        assert!(blob.contains("1 alpha"), "words should be numbered");
        assert!(blob.contains("12 lima"), "final word should be numbered 12");
    }

    #[test]
    fn safety_block_keeps_every_word_in_a_narrow_terminal() {
        // At a width that forces a single column, no word may be dropped.
        let phrase = "alpha bravo charlie delta echo foxtrot golf hotel india juliet kilo lima";
        let blob = render_blob(&safety_line(phrase), 16);
        for word in phrase.split_whitespace() {
            assert!(blob.contains(word), "narrow render dropped: {word}");
        }
    }

    #[test]
    fn horizontal_scroll_keeps_the_cursor_in_view() {
        // Cursor within the box: nothing scrolls.
        assert_eq!(horizontal_scroll(0, 10), 0);
        assert_eq!(horizontal_scroll(9, 10), 0);
        // Cursor at or past the right edge: scroll to pin it to the last column.
        assert_eq!(horizontal_scroll(10, 10), 1);
        assert_eq!(horizontal_scroll(25, 10), 16);
        // Degenerate widths must never panic.
        assert_eq!(horizontal_scroll(5, 0), 5);
        assert_eq!(horizontal_scroll(0, 0), 0);
    }

    #[test]
    fn wrap_text_splits_on_width() {
        let wrapped = wrap_text("the quick brown fox", 9);
        assert!(wrapped.iter().all(|l| l.chars().count() <= 9));
        assert_eq!(wrapped.join(" "), "the quick brown fox");
    }

    #[test]
    fn wrap_text_hard_splits_long_words() {
        let wrapped = wrap_text("supercalifragilistic", 5);
        assert!(wrapped.iter().all(|l| l.chars().count() <= 5));
        assert_eq!(wrapped.concat(), "supercalifragilistic");
    }

    #[test]
    fn connect_takes_the_whole_rest_of_the_line() {
        // The word form of an address is 24 whitespace-separated words; a
        // single-token /connect would silently drop 23 of them.
        let mut app = App::new(test_address());
        match submit_line(&mut app, "/connect alpha bravo charlie delta") {
            Action::Connect(addr) => assert_eq!(addr, "alpha bravo charlie delta"),
            _ => panic!("expected Connect with the full phrase"),
        }
    }

    #[test]
    fn address_words_shows_the_words_and_disclaims_safety() {
        let mut app = App::new(test_address());
        assert!(matches!(
            submit_line(&mut app, "/address words"),
            Action::None
        ));
        assert!(
            app.history
                .iter()
                .any(|l| matches!(l.author, Author::AddressWords) && l.text.contains("alpha")),
            "the word block should carry the word form"
        );
        assert!(
            app.history
                .iter()
                .any(|l| l.text.contains("NOT safety words")),
            "the block must be explicitly distinguished from the safety words"
        );
    }

    #[test]
    fn address_words_render_under_their_own_header() {
        // The grid layout is shared with the safety words; the header is one of
        // the things keeping the two blocks unmistakable.
        let line = ChatLine {
            author: Author::AddressWords,
            text: "alpha bravo charlie".into(),
            timestamp: "12:00".into(),
        };
        let blob = render_blob(&line, 80);
        assert!(blob.contains("address words"));
        assert!(!blob.contains("safety words"));
        assert!(blob.contains("1 alpha"), "words should be numbered");
    }

    #[test]
    fn address_command_shows_both_string_forms() {
        let mut app = App::new(test_address());
        let _ = submit_line(&mut app, "/clear");
        assert!(matches!(submit_line(&mut app, "/address"), Action::None));
        let addresses: Vec<&str> = app
            .history
            .iter()
            .filter(|l| matches!(l.author, Author::Address))
            .map(|l| l.text.as_str())
            .collect();
        assert!(
            addresses.iter().any(|t| t.starts_with("kiss1")),
            "missing the kiss1… form: {addresses:?}"
        );
        assert!(
            addresses.contains(&"my-addr"),
            "missing the legacy hex form: {addresses:?}"
        );
    }

    #[test]
    fn address_lines_are_bare_and_wrap_at_group_boundaries() {
        let line = ChatLine {
            author: Author::Address,
            text: "kiss1 abcd efgh ijkl".into(),
            timestamp: "12:00".into(),
        };
        // Wide enough: one line, no timestamp or label — just the indent.
        let wide = wrapped_lines(&line, 80, None);
        assert_eq!(wide.len(), 1);
        assert_eq!(line_text(&wide[0]), "  kiss1 abcd efgh ijkl");
        assert!(!line_text(&wide[0]).contains("12:00"));

        // Too narrow: wraps only at the group boundaries, never mid-group.
        let narrow = wrapped_lines(&line, 13, None);
        for rendered in &narrow {
            let text = line_text(rendered);
            assert!(
                text.split_whitespace().all(|g| line.text.contains(g)),
                "a group was split mid-token: {text:?}"
            );
        }
        let rejoined: Vec<String> = narrow
            .iter()
            .map(|l| line_text(l).trim().to_string())
            .collect();
        assert_eq!(rejoined.join(" "), line.text);
    }

    #[test]
    fn grouped_bech32_groups_after_the_prefix() {
        assert_eq!(grouped_bech32("kiss1abcdefghij"), "kiss1 abcd efgh ij");
        // Degenerate input without a separator still comes out grouped.
        assert_eq!(grouped_bech32("abcdefgh"), "abcd efgh");
    }

    #[test]
    fn qr_command_pushes_a_scannable_block() {
        let mut app = App::new(test_address());
        assert!(matches!(submit_line(&mut app, "/qr"), Action::None));
        let qr = app
            .history
            .iter()
            .find(|l| matches!(l.author, Author::Qr))
            .expect("a QR block should have been pushed");
        assert!(qr.text.contains('\n'), "a QR code is a multi-line block");
        assert!(
            qr.text.contains('█') || qr.text.contains('▀') || qr.text.contains('▄'),
            "the QR code should be drawn in half-block characters"
        );
    }

    #[test]
    fn a_qr_block_is_never_wrapped() {
        let line = ChatLine {
            author: Author::Qr,
            text: qr_half_blocks("kiss1testform").unwrap(),
            timestamp: "12:00".into(),
        };
        let needed = line.text.lines().map(|l| l.chars().count()).max().unwrap();

        // Wide enough: rendered verbatim, one Line per row.
        let wide = wrapped_lines(&line, needed, None);
        assert_eq!(wide.len(), line.text.lines().count());

        // One column short: replaced by a note, not sheared into garbage.
        let narrow = wrapped_lines(&line, needed - 1, None);
        assert_eq!(narrow.len(), 1);
        assert!(line_text(&narrow[0]).contains("widen the window"));
    }

    #[test]
    fn pasting_newlines_never_submits() {
        // A wrapped address copied out of a terminal arrives with newlines; fed
        // through the key path those would be Enter presses, firing off half the
        // input as a message. on_paste folds them to spaces instead.
        let mut app = App::new(test_address());
        reach_connected(&mut app);
        app.on_paste("first line\r\nsecond\tline\r");
        assert!(
            !app.history.iter().any(|l| matches!(l.author, Author::You)),
            "a paste must never send anything on its own"
        );
        assert_eq!(app.input, "first line second line ");

        // Enter afterwards sends the whole thing as one message.
        match app.on_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::empty())) {
            Action::Send(line) => assert_eq!(line, "first line second line"),
            _ => panic!("expected the folded paste to send as one message"),
        }
    }

    #[test]
    fn pasting_into_the_middle_respects_the_cursor() {
        let mut app = App::new(test_address());
        for ch in "ad".chars() {
            app.on_key(KeyEvent::new(KeyCode::Char(ch), KeyModifiers::empty()));
        }
        app.on_key(KeyEvent::new(KeyCode::Left, KeyModifiers::empty()));
        app.on_paste("bc");
        assert_eq!(app.input, "abcd");
        assert_eq!(app.cursor, 3);
    }
}
