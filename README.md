# kiss_chat

A **keep-it-simple** peer-to-peer chat with quantum-resistant end-to-end encryption.

Two people, one direct encrypted conversation, no servers to trust. The whole thing is a
handful of small Rust modules — simplicity of both architecture and code is the point.

## Highlights

- **Peer-to-peer.** No central server holds your messages. Peers connect directly over QUIC,
  with NAT traversal handled for you — dial someone by their public key.
- **Quantum-resistant E2E encryption.** A hybrid **X25519 + ML-KEM-768** handshake derives the
  session key, so your traffic stays confidential even against a future quantum computer
  ("harvest-now, decrypt-later"). Messages are sealed with ChaCha20-Poly1305.
- **Tiny and readable.** ~850 lines across five focused modules. Nothing clever you have to
  reverse-engineer.
- **Terminal UI.** A simple scrolling history with an input line.

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

### In-app commands

The input line doubles as a command prompt:

| Command | Action |
|---------|--------|
| `/connect <peer-id>` | dial a peer; if already connected, leaves that peer and switches (alias `/c`) |
| `/clear` | clear the screen |
| `/help` | list commands (alias `/h`, `/?`) |
| `/quit` | exit (alias `/q`; also <kbd>Esc</kbd> or <kbd>Ctrl-C</kbd>) |

Once connected, both sides get the same chat view — type a line and press <kbd>Enter</kbd> to
send. The status bar shows the peer and a short session **fingerprint**, identical on both ends
when the channel is genuine.

When you leave — by quitting, or by `/connect`-ing to someone else — kiss_chat sends the peer a
goodbye so they see a clean "peer left the chat" notice rather than a stalled connection. Either
side dropping returns you to the lobby, where you can `/connect` to someone new.

## How it works

```
┌──────────────┐   your typed lines    ┌──────────────────────────┐
│   UI task    │ ────────────────────► │        Net tasks         │
│  (ratatui)   │                       │  iroh QUIC + AEAD session │
│              │ ◄──────────────────── │                          │
└──────────────┘   decrypted messages  └──────────────────────────┘
```

| Module | Responsibility |
|--------|----------------|
| `transport` | iroh endpoint: bind, dial-by-key, accept (QUIC + NAT traversal) |
| `proto` | length-prefixed framing over the stream |
| `message` | 1-byte-tagged in-band protocol (chat text vs. a `Bye` control frame) |
| `crypto` | hybrid handshake, key derivation, ChaCha20-Poly1305 session |
| `ui` | terminal interface (pure state machine) |
| `main` | the event loop wiring input, connection tasks, and the UI together |

### The encryption, briefly

iroh already provides an authenticated, TLS-1.3-encrypted QUIC channel. On top of that,
kiss_chat runs a two-message handshake **inside** the stream:

1. The dialer (initiator) sends its ML-KEM-768 encapsulation key and an X25519 public key.
2. The listener (responder) replies with an ML-KEM ciphertext and its own X25519 public key.
3. Both sides now share two secrets — one post-quantum, one classical.

Those are combined as `ikm = ml_kem_secret || x25519_secret` and run through HKDF-SHA256,
salted with the full handshake transcript and bound to both peers' identities. Concatenating a
post-quantum and a classical secret is *hybrid* key exchange (the 2026 industry default): the
session stays secure as long as **either** primitive holds. Each message is then encrypted with
ChaCha20-Poly1305 using deterministic, per-direction nonce counters.

## Security notes

- **Confidentiality** against both classical and quantum adversaries via the hybrid KEM.
- **Authentication** is currently classical: the QUIC/TLS handshake authenticates the peer's
  iroh identity, and that identity is mixed into the key derivation. Post-quantum *signatures*
  (ML-DSA) for identity are not yet implemented — a MITM would need to break the transport
  authentication *now*, whereas the confidentiality guarantee is what defends recorded traffic
  against future decryption.
- The `ml-kem` crate is a pure-Rust FIPS 203 implementation that has **not** had an independent
  security audit. Treat kiss_chat as a simple, educational P2P chat, not a hardened product.
- Verify the session fingerprint out-of-band (e.g. read it to each other) if you want assurance
  against a man-in-the-middle beyond the transport layer.

## Testing

```bash
cargo test          # crypto unit tests + a full-stack loopback integration test
cargo clippy --all-targets
```

The integration test spins up two real iroh endpoints on loopback and runs a complete
connect → handshake → encrypted round-trip.

## Not (yet) included

Group chat, message history on disk, file transfer, post-quantum identity signatures, and an
in-UI fingerprint-verification prompt. The architecture leaves room for each without a rewrite.
