//! Terminal UI state: a scrolling history above a single input line.
//!
//! This module is pure state + rendering + key interpretation. It never touches
//! crypto or the network — the main loop drives it, feeding in [`NetEvent`]s and
//! acting on the [`Action`]s that key presses produce.
//!
//! The input line is a command prompt (`/connect`, `/help`, `/quit`) until a peer
//! is connected. When a channel comes up the app enters a **verify** step: the user
//! compares the session safety number out-of-band and `/accept`s or `/reject`s.
//! Only once accepted do typed lines get sent as chat messages.
//!
//! Timestamps shown next to messages are in UTC.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use crate::contacts::PinStatus;
use ratatui::{
    Frame,
    layout::{Constraint, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, List, ListItem, Paragraph},
};

/// How many wrapped lines PageUp/PageDown move the history view.
const SCROLL_STEP: usize = 5;

/// An event flowing from the network tasks into the UI.
pub enum NetEvent {
    /// A decrypted message from the peer.
    Message(String),
    /// The peer shared (or, with `None`, cleared) their display name.
    PeerName(Option<String>),
    /// The session ended; carries a human-readable reason.
    Disconnected(String),
}

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

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Lobby,
    Connecting,
    Verifying,
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
}

/// Accent colour for the safety words — high-contrast and distinct from the You /
/// Peer / System / Warning palette so the block reads as its own thing.
const SAFETY_ACCENT: Color = Color::LightYellow;

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
    /// The peer's chosen display name, once they share it (only after accepting).
    peer_name: Option<String>,
    /// Our own address, kept so `/address` can recall it after `/clear`.
    my_address: String,
    pub should_quit: bool,
}

impl App {
    /// Create the app in the lobby, showing our own address so it can be shared.
    pub fn new(my_address: String) -> Self {
        let mut app = Self {
            mode: Mode::Lobby,
            status: "lobby".into(),
            history: Vec::new(),
            input: String::new(),
            cursor: 0,
            scroll_lines: 0,
            peer_short: String::new(),
            safety_number: String::new(),
            peer_name: None,
            my_address: my_address.clone(),
            should_quit: false,
        };
        app.push_system("welcome to kiss_chat");
        app.push_system(format!("your address: {my_address}"));
        app.push_system("share it so a peer can dial you, or connect out with:");
        app.push_system("  /connect <peer-id>");
        app.push_system("type /help for all commands");
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

    /// Enter the "dialing a peer" state.
    pub fn set_connecting(&mut self, peer_short: String) {
        self.mode = Mode::Connecting;
        self.status = format!("connecting to {peer_short}…");
        self.push_system(format!("connecting to {peer_short}…"));
    }

    /// Enter the verify step once a channel is established: the safety words must
    /// be compared out-of-band before chatting begins.
    ///
    /// `pin` says how the peer's long-term identity key compares to any we pinned
    /// for this address on a previous `/accept`, so the user is told whether this is
    /// a first meeting, a recognised peer, or — the case that matters — one whose
    /// identity key has changed since last time. `known_name` is the display name we
    /// cached for a recognised peer, shown so they can be identified at a glance.
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
        // A display name from a previous peer must not leak into this session.
        self.peer_name = None;
        self.status = format!("verify {} · compare the safety words", self.peer_short);
        self.push_system("channel up — now verify you're talking to the right person:");
        match pin {
            PinStatus::New => self.push_system(
                "first time you've accepted this address — check the safety words with care.",
            ),
            PinStatus::Known => self.push_system(match &known_name {
                Some(name) => format!(
                    "recognised as \"{name}\" — this address's identity key matches the one you verified before."
                ),
                None => "recognised — this address's identity key matches the one you verified before."
                    .to_string(),
            }),
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
        }
        self.push_safety(safety_number);
        self.push_system("read these aloud with your peer over a channel you already trust");
        self.push_system("(a phone call, in person) — every word must match, in order.");
        self.push_system("the safety words are what you trust, never a display name.");
        self.push_system("  /accept   every word matches — start chatting");
        self.push_system("  /reject   any word differs — disconnect");
    }

    /// Transition from verifying to an active chat once the user accepts.
    fn mark_connected(&mut self) {
        self.mode = Mode::Connected;
        self.status = self.connected_status();
        self.push_system("verified — type a message and press Enter; /quit to leave.");
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

    /// Return to the lobby (fresh start, or after a peer disconnects / dial fails).
    pub fn set_lobby(&mut self, note: impl Into<String>) {
        self.mode = Mode::Lobby;
        self.status = "lobby".into();
        self.peer_short.clear();
        self.safety_number.clear();
        self.peer_name = None;
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

    // --- input editing -----------------------------------------------------

    fn input_len(&self) -> usize {
        self.input.chars().count()
    }

    /// Byte offset of character index `char_idx` (or end-of-string past the last).
    fn byte_index(&self, char_idx: usize) -> usize {
        self.input
            .char_indices()
            .nth(char_idx)
            .map(|(i, _)| i)
            .unwrap_or(self.input.len())
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
        let line = self.input.trim().to_string();
        self.clear_input();
        if line.is_empty() {
            return Action::None;
        }
        if let Some(command) = line.strip_prefix('/') {
            return self.run_command(command);
        }
        match self.mode {
            Mode::Connected => {
                self.push(Author::You, line.clone());
                Action::Send(line)
            }
            Mode::Verifying => {
                self.push_system("compare the safety words first: /accept or /reject");
                Action::None
            }
            _ => {
                self.push_system("not connected — use /connect <peer-id>");
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
            "connect" | "c" => match arg {
                Some(id) if matches!(self.mode, Mode::Lobby | Mode::Connected) => {
                    Action::Connect(id.to_string())
                }
                Some(_) => {
                    self.push_system("finish the current connection first");
                    Action::None
                }
                None => {
                    self.push_system("usage: /connect <peer-id>");
                    Action::None
                }
            },
            "accept" | "a" => {
                if self.mode == Mode::Verifying {
                    self.mark_connected();
                    // The main loop shares our display name (if any) now that we've
                    // accepted — never before.
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
            "reject" | "r" => {
                if self.mode == Mode::Verifying {
                    Action::RejectPeer
                } else {
                    self.push_system("nothing to reject right now");
                    Action::None
                }
            }
            "address" | "addr" => {
                let address = self.my_address.clone();
                self.push_system(format!("your address: {address}"));
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
            "quit" | "q" => {
                self.should_quit = true;
                Action::Quit
            }
            "help" | "h" | "?" => {
                self.push_system("commands:");
                self.push_system(
                    "  /connect <peer-id>   dial a peer (switches if already connected)",
                );
                self.push_system(
                    "  /accept              accept the peer after comparing the safety words",
                );
                self.push_system("  /reject              reject the peer being verified");
                self.push_system(
                    "  /name [text]         set your display name (empty clears); shared on /accept",
                );
                self.push_system("  /safety              re-show the current safety words");
                self.push_system("  /contacts            list the peers you've accepted before");
                self.push_system("  /address             show your own address to share");
                self.push_system("  /clear               clear the screen");
                self.push_system("  /help                show this help");
                self.push_system("  /quit                exit (or Esc / Ctrl-C)");
                self.push_system(
                    "keys: PageUp/PageDown scroll · Home/End, Ctrl-U/W edit the input",
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
                " kiss_chat — {} · [↑{} more] ",
                self.status, self.scroll_lines
            )
        } else {
            format!(" kiss_chat — {} ", self.status)
        };
        frame.render_widget(
            List::new(items).block(Block::bordered().title(title)),
            msg_area,
        );

        // Input line: prompt reflects whether we're chatting, verifying, or commanding.
        let (label, color) = match self.mode {
            Mode::Connected => ("message", Color::Blue),
            Mode::Verifying => ("verify: /accept or /reject", Color::Yellow),
            Mode::Connecting => ("connecting…", Color::Yellow),
            Mode::Lobby => ("command (/connect <peer-id>, /help)", Color::Magenta),
        };
        let input_block = Block::bordered()
            .title(label)
            .border_style(Style::new().fg(color));
        frame.render_widget(
            Paragraph::new(self.input.as_str()).block(input_block),
            input_area,
        );

        // Place the cursor at its character position, clamped inside the box.
        let max_x = input_area.x + input_area.width.saturating_sub(2);
        let cursor_x = (input_area.x + 1 + self.cursor as u16).min(max_x);
        frame.set_cursor_position((cursor_x, input_area.y + 1));
    }
}

/// Current UTC time as `HH:MM`.
fn timestamp_now() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let secs_of_day = secs % 86_400;
    format!("{:02}:{:02}", secs_of_day / 3600, (secs_of_day % 3600) / 60)
}

/// Render one [`ChatLine`] into one or more display lines, wrapped to `width`.
///
/// `peer_name` is the peer's chosen display name, if known; it labels their lines
/// in place of the generic "peer".
fn wrapped_lines(line: &ChatLine, width: usize, peer_name: Option<&str>) -> Vec<Line<'static>> {
    // The safety words get a bespoke layout (numbered grid) rather than the
    // label-plus-body treatment every other line shares.
    if matches!(line.author, Author::Safety) {
        return safety_lines(&line.text, width, &line.timestamp);
    }
    let (label, color): (&str, Color) = match line.author {
        Author::You => ("you", Color::Cyan),
        Author::Peer => (peer_name.unwrap_or("peer"), Color::Green),
        Author::System => ("--", Color::DarkGray),
        Author::Warning => ("!!", Color::Red),
        // Handled by the early return above; kept for exhaustiveness.
        Author::Safety => ("safety", SAFETY_ACCENT),
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

/// Render the safety words as a highlighted, numbered grid framed by blank lines.
///
/// Numbering each word lets peers compare by position (so a dropped or swapped
/// word is obvious), and the accent colour plus bold weight lift the block clear
/// of the dim system chatter around it. The grid reflows to `width`: as many
/// columns as fit, collapsing to a single column in a narrow terminal.
fn safety_lines(phrase: &str, width: usize, timestamp: &str) -> Vec<Line<'static>> {
    let words: Vec<&str> = phrase.split_whitespace().collect();
    let dim = Style::new().fg(Color::DarkGray);
    let accent = Style::new().fg(SAFETY_ACCENT).add_modifier(Modifier::BOLD);

    // A blank spacer above, then the header carrying the timestamp prefix.
    let mut lines = vec![
        Line::from(""),
        Line::from(vec![
            Span::styled(format!("{timestamp} "), dim),
            Span::styled("safety words", accent),
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

    // Type a whole line and press Enter, returning the resulting action.
    fn submit_line(app: &mut App, line: &str) -> Action {
        for ch in line.chars() {
            app.on_key(KeyEvent::new(KeyCode::Char(ch), KeyModifiers::empty()));
        }
        app.on_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::empty()))
    }

    // Drive the app into an accepted, connected session.
    fn reach_connected(app: &mut App) {
        app.set_verifying("peer".into(), "ab-cd".into(), PinStatus::New, None);
        let _ = submit_line(app, "/accept");
    }

    #[test]
    fn connect_command_in_lobby_yields_connect_action() {
        let mut app = App::new("my-addr".into());
        match submit_line(&mut app, "/connect abc123") {
            Action::Connect(id) => assert_eq!(id, "abc123"),
            _ => panic!("expected Connect"),
        }
    }

    #[test]
    fn connect_without_argument_is_rejected() {
        let mut app = App::new("my-addr".into());
        assert!(matches!(submit_line(&mut app, "/connect"), Action::None));
    }

    #[test]
    fn plain_text_in_lobby_is_not_sent() {
        let mut app = App::new("my-addr".into());
        assert!(matches!(submit_line(&mut app, "hello"), Action::None));
    }

    #[test]
    fn text_while_verifying_is_not_sent() {
        let mut app = App::new("my-addr".into());
        app.set_verifying("peer".into(), "ab-cd".into(), PinStatus::New, None);
        assert!(matches!(submit_line(&mut app, "hi"), Action::None));
    }

    #[test]
    fn accept_then_text_is_sent() {
        let mut app = App::new("my-addr".into());
        reach_connected(&mut app);
        match submit_line(&mut app, "hi there") {
            Action::Send(line) => assert_eq!(line, "hi there"),
            _ => panic!("expected Send after /accept"),
        }
    }

    #[test]
    fn reject_yields_reject_action() {
        let mut app = App::new("my-addr".into());
        app.set_verifying("peer".into(), "ab-cd".into(), PinStatus::New, None);
        assert!(matches!(
            submit_line(&mut app, "/reject"),
            Action::RejectPeer
        ));
    }

    #[test]
    fn accept_while_verifying_yields_accept_action() {
        let mut app = App::new("my-addr".into());
        app.set_verifying("peer".into(), "ab-cd".into(), PinStatus::New, None);
        assert!(matches!(submit_line(&mut app, "/accept"), Action::Accept));
    }

    #[test]
    fn changed_identity_key_raises_a_warning_during_verification() {
        let mut app = App::new("my-addr".into());
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
        let mut app = App::new("my-addr".into());
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
        let mut app = App::new("my-addr".into());
        app.set_verifying(
            "peer".into(),
            "ab-cd".into(),
            PinStatus::Known,
            Some("Alice".into()),
        );
        assert!(
            app.history
                .iter()
                .any(|l| l.text.contains("recognised as \"Alice\"")),
            "a recognised peer's cached name should be shown"
        );
    }

    #[test]
    fn contacts_command_yields_a_list_action() {
        let mut app = App::new("my-addr".into());
        assert!(matches!(
            submit_line(&mut app, "/contacts"),
            Action::ListContacts
        ));
    }

    #[test]
    fn accept_outside_verifying_does_nothing() {
        let mut app = App::new("my-addr".into());
        assert!(matches!(submit_line(&mut app, "/accept"), Action::None));
    }

    #[test]
    fn name_command_keeps_spaces_and_reports_the_whole_name() {
        let mut app = App::new("my-addr".into());
        match submit_line(&mut app, "/name Alice Smith") {
            Action::SetName(name) => assert_eq!(name, "Alice Smith"),
            _ => panic!("expected SetName"),
        }
    }

    #[test]
    fn bare_name_command_clears_the_name() {
        let mut app = App::new("my-addr".into());
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
        let mut app = App::new("my-addr".into());
        reach_connected(&mut app);
        app.set_peer_name(Some("Alice".into()));
        assert!(app.status.contains("Alice"));
        // Clearing reverts to the plain peer id in the status line.
        app.set_peer_name(None);
        assert!(!app.status.contains("Alice"));
    }

    #[test]
    fn connect_while_connected_switches_peers() {
        let mut app = App::new("my-addr".into());
        reach_connected(&mut app);
        match submit_line(&mut app, "/connect newpeer") {
            Action::Connect(id) => assert_eq!(id, "newpeer"),
            _ => panic!("expected Connect to switch peers"),
        }
    }

    #[test]
    fn connect_is_refused_while_dialing() {
        let mut app = App::new("my-addr".into());
        app.set_connecting("peer".into());
        assert!(matches!(
            submit_line(&mut app, "/connect abc"),
            Action::None
        ));
    }

    #[test]
    fn connect_is_refused_while_verifying() {
        let mut app = App::new("my-addr".into());
        app.set_verifying("peer".into(), "ab-cd".into(), PinStatus::New, None);
        assert!(matches!(
            submit_line(&mut app, "/connect abc"),
            Action::None
        ));
    }

    #[test]
    fn clear_command_empties_the_history() {
        let mut app = App::new("my-addr".into());
        assert!(!app.history.is_empty());
        assert!(matches!(submit_line(&mut app, "/clear"), Action::None));
        assert!(app.history.is_empty());
    }

    #[test]
    fn address_command_recalls_own_address_after_clear() {
        let mut app = App::new("my-addr".into());
        let _ = submit_line(&mut app, "/clear");
        assert!(app.history.is_empty());
        assert!(matches!(submit_line(&mut app, "/address"), Action::None));
        assert!(app.history.iter().any(|line| line.text.contains("my-addr")));
    }

    #[test]
    fn quit_command_and_ctrl_c_both_quit() {
        let mut app = App::new("my-addr".into());
        assert!(matches!(submit_line(&mut app, "/quit"), Action::Quit));
        assert!(app.should_quit);

        let mut app = App::new("my-addr".into());
        let ctrl_c = KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL);
        assert!(matches!(app.on_key(ctrl_c), Action::Quit));
    }

    #[test]
    fn cursor_editing_inserts_in_the_middle() {
        let mut app = App::new("my-addr".into());
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
        let mut app = App::new("my-addr".into());
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
}
