#![doc(
    html_logo_url = "https://raw.githubusercontent.com/gwo0d/kiss_chat/main/assets/png/icon-256.png",
    html_favicon_url = "https://raw.githubusercontent.com/gwo0d/kiss_chat/main/assets/png/icon-32.png"
)]
//! A keep-it-simple, peer-to-peer chat with quantum-resistant end-to-end encryption.
//!
//! Two people, one direct encrypted conversation, no servers to trust.
//!
//! # Usage
//!
//! ```text
//! kiss_chat              come up in the lobby: share your address, then wait or /connect
//! kiss_chat <ADDRESS>    come up and immediately dial that peer (an iroh EndpointId)
//! ```
//!
//! # In-app commands
//!
//! The input line is a command prompt until a peer is connected.
//!
//! | Command | Description |
//! | --- | --- |
//! | `/connect <peer-id>` | dial a peer (switches peers if already connected) |
//! | `/accept`, `/reject` | accept or reject a peer after comparing the safety words |
//! | `/safety` | re-show the current session's safety words |
//! | `/contacts` | list the peers you've accepted before |
//! | `/address` | show your own address to share |
//! | `/name [text]` | set your (optional) display name; only shared after `/accept` |
//! | `/clear` | clear the screen |
//! | `/help` | list commands |
//! | `/quit` | exit (also `Esc` / `Ctrl-C`) |
//!
//! # Architecture
//!
//! | Module | Responsibility |
//! | --- | --- |
//! | [`identity`] | persistent on-disk keys (iroh address + ML-DSA auth seed) |
//! | [`contacts`] | pinned contact list: remembers each peer's ML-DSA key (TOFU) |
//! | [`transport`] | iroh: bind, dial-by-key, accept (handles NAT traversal) |
//! | [`proto`] | length-prefixed framing over the QUIC stream |
//! | [`message`] | the one-byte-tagged in-band protocol (chat text vs. `Bye` control) |
//! | [`crypto`] | hybrid X25519 + ML-KEM-1024 KEX, ML-DSA-87 auth, ChaCha20-Poly1305 |
//! | [`ui`] | ratatui terminal interface (pure state) |
//! | `app` | the event loop wiring input, connection tasks, and the UI together |
//!
//! The dialer is always the crypto *initiator*; the accepter is the *responder*.
//!
//! This crate is a library (the modules above) paired with a thin binary
//! (`src/main.rs`) that parses the command line and calls [`run`].

pub mod contacts;
pub mod crypto;
pub mod identity;
pub mod message;
pub mod proto;
pub mod transport;
pub mod ui;

mod app;

pub use app::{print_usage, run};
