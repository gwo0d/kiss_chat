//! Terminal UI state: a scrolling history above a single input line.
//!
//! This module is pure state + rendering + key interpretation. It never touches
//! crypto or the network — the main loop drives it, feeding in [`NetEvent`]s and
//! acting on the [`Action`]s that key presses produce.
//!
//! Before a peer is connected the input line is a small command prompt
//! (`/connect <peer-id>`, `/help`, `/quit`); once connected, typed lines are
//! sent as chat messages.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::{
    Frame,
    layout::{Constraint, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, List, ListItem, Paragraph},
};

/// An event flowing from the network tasks into the UI.
pub enum NetEvent {
    /// A decrypted message from the peer.
    Message(String),
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
    /// Send the given line to the connected peer.
    Send(String),
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Lobby,
    Connecting,
    Connected,
}

enum Author {
    You,
    Peer,
    System,
}

struct ChatLine {
    author: Author,
    text: String,
}

impl ChatLine {
    fn to_list_item(&self) -> ListItem<'static> {
        let (label, color) = match self.author {
            Author::You => ("you", Color::Cyan),
            Author::Peer => ("peer", Color::Green),
            Author::System => ("--", Color::DarkGray),
        };
        let line = Line::from(vec![
            Span::styled(
                format!("{label}: "),
                Style::new().fg(color).add_modifier(Modifier::BOLD),
            ),
            Span::raw(self.text.clone()),
        ]);
        ListItem::new(line)
    }
}

pub struct App {
    mode: Mode,
    status: String,
    history: Vec<ChatLine>,
    input: String,
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
        self.history.push(ChatLine { author, text });
    }

    pub fn push_system(&mut self, text: impl Into<String>) {
        self.push(Author::System, text.into());
    }

    pub fn push_peer(&mut self, text: String) {
        self.push(Author::Peer, text);
    }

    /// Enter the "dialing a peer" state.
    pub fn set_connecting(&mut self, peer_short: String) {
        self.mode = Mode::Connecting;
        self.status = format!("connecting to {peer_short}…");
        self.push_system(format!("connecting to {peer_short}…"));
    }

    /// Enter the connected state once a session is established.
    pub fn set_connected(&mut self, peer_short: String, fingerprint: String) {
        self.mode = Mode::Connected;
        self.status = format!("connected to {peer_short} · fingerprint {fingerprint}");
        self.push_system(format!(
            "connected · fingerprint {fingerprint} (verify it matches your peer)"
        ));
        self.push_system("type a message and press Enter — /quit to leave");
    }

    /// Return to the lobby (fresh start, or after a peer disconnects / dial fails).
    pub fn set_lobby(&mut self, note: impl Into<String>) {
        self.mode = Mode::Lobby;
        self.status = "lobby".into();
        self.push_system(note);
    }

    /// Handle a key press, returning the action for the main loop to perform.
    pub fn on_key(&mut self, key: KeyEvent) -> Action {
        match key.code {
            KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                self.should_quit = true;
                Action::Quit
            }
            KeyCode::Esc => {
                self.should_quit = true;
                Action::Quit
            }
            KeyCode::Enter => self.submit(),
            KeyCode::Backspace => {
                self.input.pop();
                Action::None
            }
            KeyCode::Char(ch) => {
                self.input.push(ch);
                Action::None
            }
            _ => Action::None,
        }
    }

    fn submit(&mut self) -> Action {
        let line = self.input.trim().to_string();
        self.input.clear();
        if line.is_empty() {
            return Action::None;
        }
        if let Some(command) = line.strip_prefix('/') {
            return self.run_command(command);
        }
        if self.mode == Mode::Connected {
            self.push(Author::You, line.clone());
            Action::Send(line)
        } else {
            self.push_system("not connected — use /connect <peer-id>");
            Action::None
        }
    }

    fn run_command(&mut self, command: &str) -> Action {
        let mut parts = command.split_whitespace();
        let name = parts.next().unwrap_or("");
        let arg = parts.next();
        match name {
            // Allowed from the lobby or while connected (which switches peers);
            // only refused mid-dial, when there's nothing sensible to do.
            "connect" | "c" => match arg {
                Some(id) if self.mode != Mode::Connecting => Action::Connect(id.to_string()),
                Some(_) => {
                    self.push_system("already connecting — please wait");
                    Action::None
                }
                None => {
                    self.push_system("usage: /connect <peer-id>");
                    Action::None
                }
            },
            "clear" => {
                self.history.clear();
                Action::None
            }
            "quit" | "q" => {
                self.should_quit = true;
                Action::Quit
            }
            "help" | "h" | "?" => {
                self.push_system("commands:");
                self.push_system("  /connect <peer-id>   dial a peer (switches if already connected)");
                self.push_system("  /clear               clear the screen");
                self.push_system("  /help                show this help");
                self.push_system("  /quit                exit (or Esc / Ctrl-C)");
                Action::None
            }
            other => {
                self.push_system(format!("unknown command: /{other} (try /help)"));
                Action::None
            }
        }
    }

    pub fn render(&self, frame: &mut Frame) {
        let [msg_area, input_area] =
            Layout::vertical([Constraint::Min(1), Constraint::Length(3)]).areas(frame.area());

        // History: show the tail that fits so the newest lines stay visible.
        let history_block = Block::bordered().title(format!(" kiss_chat — {} ", self.status));
        let visible = history_block.inner(msg_area).height as usize;
        let start = self.history.len().saturating_sub(visible);
        let items: Vec<ListItem> = self.history[start..]
            .iter()
            .map(ChatLine::to_list_item)
            .collect();
        frame.render_widget(List::new(items).block(history_block), msg_area);

        // Input line: prompt reflects whether we're chatting or entering commands.
        let (title, color) = match self.mode {
            Mode::Connected => ("message", Color::Blue),
            Mode::Connecting => ("connecting…", Color::Yellow),
            Mode::Lobby => ("command (/connect <peer-id>, /help)", Color::Magenta),
        };
        let input_block = Block::bordered()
            .title(title)
            .border_style(Style::new().fg(color));
        frame.render_widget(
            Paragraph::new(self.input.as_str()).block(input_block),
            input_area,
        );

        let cursor_x = input_area.x + 1 + self.input.chars().count() as u16;
        frame.set_cursor_position((cursor_x, input_area.y + 1));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    // Type a whole line and press Enter, returning the resulting action.
    fn submit_line(app: &mut App, line: &str) -> Action {
        for ch in line.chars() {
            app.on_key(KeyEvent::new(KeyCode::Char(ch), KeyModifiers::empty()));
        }
        app.on_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::empty()))
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
    fn plain_text_when_connected_is_sent() {
        let mut app = App::new("my-addr".into());
        app.set_connected("peer".into(), "ab-cd-ef-01".into());
        match submit_line(&mut app, "hi there") {
            Action::Send(line) => assert_eq!(line, "hi there"),
            _ => panic!("expected Send"),
        }
    }

    #[test]
    fn connect_while_connected_switches_peers() {
        let mut app = App::new("my-addr".into());
        app.set_connected("peer".into(), "ab-cd-ef-01".into());
        match submit_line(&mut app, "/connect newpeer") {
            Action::Connect(id) => assert_eq!(id, "newpeer"),
            _ => panic!("expected Connect to switch peers"),
        }
    }

    #[test]
    fn connect_is_refused_while_dialing() {
        let mut app = App::new("my-addr".into());
        app.set_connecting("peer".into());
        assert!(matches!(submit_line(&mut app, "/connect abc"), Action::None));
    }

    #[test]
    fn clear_command_empties_the_history() {
        let mut app = App::new("my-addr".into());
        assert!(!app.history.is_empty());
        assert!(matches!(submit_line(&mut app, "/clear"), Action::None));
        assert!(app.history.is_empty());
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
}
