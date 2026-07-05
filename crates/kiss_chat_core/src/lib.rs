#![doc(
    html_logo_url = "https://raw.githubusercontent.com/gwo0d/kiss_chat/main/assets/png/icon-256.png",
    html_favicon_url = "https://raw.githubusercontent.com/gwo0d/kiss_chat/main/assets/png/icon-32.png"
)]
//! The protocol core of [kiss_chat](https://github.com/gwo0d/kiss_chat): a
//! keep-it-simple, peer-to-peer chat with quantum-resistant end-to-end encryption.
//!
//! Two people, one direct encrypted conversation, no servers to trust.
//!
//! This crate is everything a kiss_chat frontend needs that isn't a user
//! interface. The `kiss_chat` crate — the terminal (ratatui) frontend — is its
//! first consumer; other frontends are meant to build on the same modules.
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
//!
//! The dialer is always the crypto *initiator*; the accepter is the *responder*.
//!
//! # Stability
//!
//! This crate exists to serve kiss_chat's own frontends, and its API follows
//! their needs: expect breaking changes between minor versions (signalled by
//! semver) until 1.0.

pub mod contacts;
pub mod crypto;
pub mod identity;
pub mod message;
pub mod proto;
pub mod transport;
