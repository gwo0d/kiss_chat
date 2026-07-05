# kiss_chat_core

[![docs.rs](https://img.shields.io/docsrs/kiss_chat_core?logo=rust&label=docs.rs)](https://docs.rs/kiss_chat_core/latest/kiss_chat_core/)
[![crates.io](https://img.shields.io/crates/v/kiss_chat_core.svg?logo=rust)](https://crates.io/crates/kiss_chat_core)
[![License: GPL-3.0-or-later](https://img.shields.io/crates/l/kiss_chat_core.svg)](https://github.com/gwo0d/kiss_chat/blob/main/LICENSE.md)

The protocol core of [kiss_chat](https://github.com/gwo0d/kiss_chat) — a
keep-it-simple, peer-to-peer chat with quantum-resistant end-to-end encryption.
Two people, one direct encrypted conversation, no servers to trust.

This crate is everything a kiss_chat frontend needs that isn't a user
interface:

| Module | Responsibility |
| --- | --- |
| `identity` | persistent on-disk keys (iroh address + ML-DSA auth seed) |
| `contacts` | pinned contact list: remembers each peer's ML-DSA key (TOFU) |
| `transport` | iroh: bind, dial-by-key, accept (handles NAT traversal) |
| `proto` | length-prefixed framing over the QUIC stream |
| `message` | the one-byte-tagged in-band protocol (chat text vs. `Bye` control) |
| `crypto` | hybrid X25519 + ML-KEM-1024 KEX, ML-DSA-87 auth, ChaCha20-Poly1305 |

The [`kiss_chat`](https://crates.io/crates/kiss_chat) crate — the terminal
frontend — is its first consumer. See the [project
README](https://github.com/gwo0d/kiss_chat#readme) for what kiss_chat is, its
threat model, and how to use it.

## Stability

This crate exists to serve kiss_chat's own frontends, and its API follows their
needs: expect breaking changes between minor versions (signalled by semver)
until 1.0.

## License

GPL-3.0-or-later. See [LICENSE.md](LICENSE.md).
