<div align="center">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="assets/lockup-dark.svg">
  <source media="(prefers-color-scheme: light)" srcset="assets/lockup-light.svg">
  <img alt="kiss_chat" src="assets/lockup-light.svg" width="440">
</picture>

</div>

A **keep-it-simple** peer-to-peer chat with quantum-resistant end-to-end encryption.

Two people, one direct encrypted conversation, no servers to trust. The whole thing is a
handful of small Rust modules — simplicity of both architecture and code is the point.

## Highlights

- **Peer-to-peer.** No central server holds your messages. Peers connect directly over QUIC,
  with NAT traversal handled for you — dial someone by their public key.
- **Stable identity.** Your address is derived from a secret key that is generated once and
  saved to disk, so it stays the same across restarts — share it once and peers can always
  reach you.
- **Quantum-resistant E2E encryption.** A hybrid **X25519 + ML-KEM-1024** handshake derives the
  session key, so your traffic stays confidential even against a future quantum computer
  ("harvest-now, decrypt-later"). Messages are sealed with ChaCha20-Poly1305.
- **Post-quantum authentication.** Each peer holds a long-term **ML-DSA-87** (FIPS 204) identity
  and signs the handshake transcript, so authentication — not just confidentiality — resists a
  quantum adversary. You confirm the peer once by comparing a short list of **safety words**.
- **Tiny and readable.** A handful of small, focused modules. Nothing clever you have to
  reverse-engineer.
- **Terminal UI.** Scrolling history with word-wrap, timestamps, scrollback, and line editing.

## Requirements

- Rust 1.85+ (2024 edition)
- Network access for internet-wide connections (peer discovery uses iroh's public
  relay/DNS infrastructure)

## Build

```bash
cargo build --release
```

## Usage

kiss_chat is symmetric: one side shares their address, the other dials it. You can do the
dialing either from the command line or from inside the app.

**Start in the lobby** (no argument). Your address is shown in the app so you can share it,
and you can wait for a peer or dial one yourself:

```bash
cargo run
```

```
-- your address: 96aedec725a0104933cfd73a2722b3497b13307100a242ccb47efe9cb1fafa39
-- share it so a peer can dial you, or connect out with:
--   /connect <peer-id>
```

**Or dial immediately** with the address your peer shared:

```bash
cargo run -- 96aedec725a0104933cfd73a2722b3497b13307100a242ccb47efe9cb1fafa39
```

Your keys live in `$XDG_CONFIG_HOME/kiss_chat/` (falling back to `~/.config/kiss_chat/`),
owner-readable only: `secret.key` is your iroh address and `auth.key` is your ML-DSA
authentication seed. Delete them to rotate to a fresh identity; copy them to run as the same
identity on another machine. An optional `name` file (not a secret) holds your display name.

### Verifying the peer

When a channel comes up, kiss_chat pauses before chat and shows a short phrase of **safety words**
derived from the whole handshake — both peers' identities *and* the session's fresh ephemeral keys —
the same phrase on both ends. Read it aloud with your peer over a trusted channel (say it aloud, a
phone call, etc.), then `/accept` if every word matches in order or `/reject` if any differs.
Verifying once is enough: the ML-DSA signatures in the handshake bind the session to that identity,
so a man-in-the-middle would show a *different* phrase. Because the words also cover the ephemeral
keys, they can't be precomputed offline, and `/safety` re-shows them at any time.

### In-app commands

The input line doubles as a command prompt:

| Command | Action |
|---------|--------|
| `/connect <peer-id>` | dial a peer; if already connected, leaves that peer and switches (alias `/c`) |
| `/accept` | accept the peer after every safety word matches (alias `/a`) |
| `/reject` | reject the peer being verified and return to the lobby (alias `/r`) |
| `/name [text]` | set your optional display name; empty clears it (alias `/n`) |
| `/safety` | re-show the current session's safety words (alias `/s`) |
| `/address` | show your own address to share (alias `/addr`) |
| `/clear` | clear the screen |
| `/help` | list commands (alias `/h`, `/?`) |
| `/quit` | exit (alias `/q`; also <kbd>Esc</kbd> or <kbd>Ctrl-C</kbd>) |

Editing keys: <kbd>←</kbd>/<kbd>→</kbd>, <kbd>Home</kbd>/<kbd>End</kbd>, <kbd>Delete</kbd>, and
<kbd>Ctrl-U</kbd> (clear line), <kbd>Ctrl-W</kbd> (delete word), <kbd>Ctrl-A</kbd>/<kbd>Ctrl-E</kbd>
(start/end). <kbd>PageUp</kbd>/<kbd>PageDown</kbd> scroll the history.

Once accepted, both sides get the same chat view — type a line and press <kbd>Enter</kbd> to send.
The status bar shows the connected peer; recall the **safety words** any time with `/safety`.
Message timestamps are in UTC.

### Display names

You can set an optional display name with `/name <text>` (`/name` alone clears it). It's purely
cosmetic and self-asserted, so it is deliberately **never** part of verification: the safety words
stay your only trust anchor. A name is shared with a peer only *after* you `/accept` them, and it
travels inside the same end-to-end-encrypted, authenticated frames as your chat messages — never in
the clear and never during the verify step. Received names are sanitised (control characters
stripped, length capped) before display. Your name persists across runs in the `name` file.

When you leave — by quitting, or by `/connect`-ing to someone else — kiss_chat sends the peer a
goodbye so they see a clean "peer left the chat" notice rather than a stalled connection. Either
side dropping returns you to the lobby, where you can `/connect` to someone new.

## How it works

```
┌──────────────┐   your typed lines    ┌────────────────────────────┐
│   UI task    │ ────────────────────► │        Net tasks           │
│  (ratatui)   │                       │  iroh QUIC + AEAD session  │
│              │ ◄──────────────────── │                            │
└──────────────┘   decrypted messages  └────────────────────────────┘
```

| Module | Responsibility |
|--------|----------------|
| `identity` | persistent on-disk keys (iroh address + ML-DSA auth seed) |
| `transport` | iroh endpoint: bind, dial-by-key, accept (QUIC + NAT traversal) |
| `proto` | length-prefixed framing over the stream |
| `message` | 1-byte-tagged in-band protocol (chat text vs. a `Bye` control frame) |
| `crypto` | hybrid KEX, ML-DSA authentication, key derivation, ChaCha20-Poly1305 session |
| `ui` | terminal interface (pure state machine) |
| `main` | the event loop wiring input, connection tasks, and the UI together |

### The handshake, briefly

iroh already provides an authenticated, TLS-1.3-encrypted QUIC channel. On top of that,
kiss_chat runs a three-message, mutually-authenticated handshake **inside** the stream (the
dialer is the *initiator*, the accepter the *responder*):

1. **I→R:** ML-KEM-1024 encapsulation key, an X25519 public key, and the initiator's ML-DSA
   identity key.
2. **R→I:** ML-KEM ciphertext, an X25519 public key, the responder's ML-DSA identity key, and a
   signature over the whole transcript.
3. **I→R:** the initiator's signature over the transcript.

Both sides then share two secrets — one post-quantum (ML-KEM), one classical (X25519) — combined
as `ikm = ml_kem_secret || x25519_secret` and run through HKDF-SHA256, salted with the transcript
(which includes both identity keys and both iroh EndpointIds). Concatenating a post-quantum and a
classical secret is *hybrid* key exchange (the 2026 industry default): the session stays
confidential as long as **either** primitive holds. Each message is then sealed with
ChaCha20-Poly1305 using deterministic, per-direction nonce counters.

The **safety words** are a short fingerprint of the whole transcript — both identity keys, both
ephemeral keys, and both iroh EndpointIds — rendered as a 12-word phrase (BIP39 wordlist) and
identical on both ends. Comparing it out-of-band authenticates the channel: under a man-in-the-middle
the two ends would compute different phrases. Binding the ephemeral keys (not just the long-term
identities) means the phrase can't be mined offline, so a MITM can't precompute a colliding identity.

## Security notes

- **Confidentiality** against both classical and quantum adversaries via the hybrid KEM.
- **Authentication** is post-quantum: each peer signs the handshake transcript with a long-term
  ML-DSA-87 key, and the transport (QUIC/TLS) authenticates the iroh identity underneath. The
  signatures bind the ephemeral keys to the identity key, so the out-of-band **safety words**
  check is what roots trust — verify it once and a MITM cannot impersonate that identity, even
  with a quantum computer.
- kiss_chat does **not** persist a contact list, so peer identities are trusted on first use
  (verified via the safety words). It re-verifies via signatures every session but will not, on
  its own, warn you if a *previously seen* peer presents a new identity key.
- The `ml-kem` and `ml-dsa` crates are pure-Rust FIPS 203/204 implementations that have **not**
  had an independent security audit. Treat kiss_chat as a simple, educational P2P chat, not a
  hardened product.

## Testing

```bash
cargo test          # crypto/identity/ui unit tests + full-stack loopback integration tests
cargo clippy --all-targets
```

The integration tests spin up two real iroh endpoints on loopback and run a complete
connect → three-message authenticated handshake → encrypted round-trip.

## Not (yet) included

Group chat, message history on disk, file transfer, a persistent contact list (identity-key
pinning with change warnings), and local-time timestamps. The architecture leaves room for each
without a rewrite.
