<div align="center">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/gwo0d/kiss_chat/main/assets/lockup-dark.svg">
  <source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/gwo0d/kiss_chat/main/assets/lockup-light.svg">
  <img alt="kiss_chat" src="https://raw.githubusercontent.com/gwo0d/kiss_chat/main/assets/lockup-light.svg" width="440">
</picture>

[![CI](https://img.shields.io/github/actions/workflow/status/gwo0d/kiss_chat/ci.yml?branch=main&label=CI&logo=github)](https://github.com/gwo0d/kiss_chat/actions/workflows/ci.yml)
[![docs.rs](https://img.shields.io/docsrs/kiss_chat?logo=rust&label=docs.rs)](https://docs.rs/kiss_chat/latest/kiss_chat/)
[![crates.io](https://img.shields.io/crates/v/kiss_chat.svg?logo=rust)](https://crates.io/crates/kiss_chat)
[![Downloads](https://img.shields.io/crates/d/kiss_chat.svg)](https://crates.io/crates/kiss_chat)
[![License: GPL-3.0-or-later](https://img.shields.io/crates/l/kiss_chat.svg)](https://github.com/gwo0d/kiss_chat/blob/main/LICENSE.md)

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

- Rust 1.91+ to build from source. The 2024 edition itself only needs 1.85, but the
  current dependency tree (via iroh) requires 1.91. Prefer not to build? Grab a
  prebuilt binary from the [latest release](https://github.com/gwo0d/kiss_chat/releases/latest).
- Network access for internet-wide connections (peer discovery uses iroh's public
  relay/DNS infrastructure)

## Install

Install the latest release from [crates.io](https://crates.io/crates/kiss_chat) with Cargo:

```bash
cargo install kiss_chat
```

This puts a `kiss_chat` binary on your `PATH` (in `~/.cargo/bin/`). Anywhere the docs below use
`cargo run`, you can run `kiss_chat` instead — e.g. `kiss_chat` to start in the lobby, or
`kiss_chat <peer-id>` to dial a peer directly.

### Prebuilt binaries

Every [release](https://github.com/gwo0d/kiss_chat/releases/latest) also ships prebuilt binaries
for Linux, macOS, and Windows (each with a SHA-256 checksum) — download, extract, and run, no
toolchain required.

**macOS: the binaries are not code-signed.** If you download one through a browser, Gatekeeper
will refuse to open it ("Apple could not verify … is free of malware"), because it is neither
signed with an Apple Developer ID nor notarised. Clear the quarantine flag once and it runs
normally:

```bash
xattr -d com.apple.quarantine ./kiss_chat
```

Alternatively, open **System Settings → Privacy & Security** and click **Open Anyway**, or avoid
the issue entirely with `cargo install kiss_chat` — locally compiled binaries are never
quarantined.

## Build from source

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
identity on another machine. Two non-secret files sit alongside them: an optional `name` file
holds your display name, and `contacts` records the peers you've accepted (see
[Remembering peers](#remembering-peers)).

### Verifying the peer

When a channel comes up, kiss_chat pauses before chat and shows a short phrase of **safety words**
derived from the whole handshake — both peers' identities *and* the session's fresh ephemeral keys —
the same phrase on both ends. Read it aloud with your peer over a trusted channel (say it aloud, a
phone call, etc.), then `/accept` if every word matches in order or `/reject` if any differs.
Verifying once is enough: the ML-DSA signatures in the handshake bind the session to that identity,
so a man-in-the-middle would show a *different* phrase. Because the words also cover the ephemeral
keys, they can't be precomputed offline, and `/safety` re-shows them at any time.

### Remembering peers

When you `/accept` a peer, kiss_chat pins their long-term ML-DSA identity key against their
address in a small `contacts` file (trust-on-first-use). Next time you connect to that same
address, kiss_chat tells you which of three cases you're in — and asks only for as much as each
warrants:

- **first time** — this address is new, so compare the safety words with care;
- **recognised** — the identity key matches the one you verified before, so the handshake
  signatures already prove it's the same peer you trusted last time. There's nothing new to
  compare, so kiss_chat asks only for a quick **"incoming connection from …"** consent — `/accept`
  to start chatting or `/reject` to decline. (The words are still there if you want them: `/safety`
  re-shows them at any point.)
- **⚠ changed** — the identity key is *different* from the one you accepted before. That can be an
  innocent identity reset, or it can be an impersonation attempt, so re-read every safety word
  especially carefully before you `/accept`. Accepting adopts the new key as the pinned one.

A recognised peer still needs your explicit `/accept`, so a remote peer can never pull you into a
chat without your say-so — the pin removes the *re-verification* chore, not your consent. Making the
routine reconnection quiet also keeps the ⚠ changed warning meaningful instead of lost in a prompt
you clear on every session.

Once a peer shares a display name (which only happens after you've both accepted), kiss_chat caches
it alongside their pin, so a recognised peer is identified by name at the consent step. `/contacts`
lists everyone you've accepted — by name, with their address — so you can tell known peers apart at
a glance and copy an address straight into `/connect`.

Only the public identity key is stored (as a SHA-256 fingerprint), keyed by the public address and
followed by the optional cached name, so the `contacts` file holds no secrets. Delete it to forget
every peer and start fresh.

### In-app commands

The input line doubles as a command prompt:

| Command | Action |
|---------|--------|
| `/connect <peer-id>` | dial a peer; if already connected, leaves that peer and switches (alias `/c`) |
| `/accept` | accept the peer — after every safety word matches, or just to consent to a recognised one (alias `/a`) |
| `/reject` | reject the peer being verified and return to the lobby (alias `/r`) |
| `/name [text]` | set your optional display name; empty clears it (alias `/n`) |
| `/safety` | re-show the current session's safety words (alias `/s`) |
| `/contacts` | list the peers you've accepted before (alias `/peers`) |
| `/address` | show your own address to share (alias `/addr`) |
| `/clear` | clear the screen |
| `/help` | list commands (alias `/h`, `/?`) |
| `/quit` | exit (alias `/q`; also <kbd>Esc</kbd> or <kbd>Ctrl-C</kbd>) |

Editing keys: <kbd>←</kbd>/<kbd>→</kbd>, <kbd>Home</kbd>/<kbd>End</kbd>, <kbd>Delete</kbd>, and
<kbd>Ctrl-U</kbd> (clear line), <kbd>Ctrl-W</kbd> (delete word), <kbd>Ctrl-A</kbd>/<kbd>Ctrl-E</kbd>
(start/end). <kbd>PageUp</kbd>/<kbd>PageDown</kbd> scroll the history.

Once accepted, both sides get the same chat view — type a line and press <kbd>Enter</kbd> to send.
To send a message that begins with a slash, double it: `//shrug` sends `/shrug`. The status bar
shows the connected peer; recall the **safety words** any time with `/safety`. Message timestamps
are in UTC.

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

The repository is a Cargo workspace of two published crates:
[`kiss_chat_core`](crates/kiss_chat_core) — the protocol, everything that isn't a user
interface — and [`kiss_chat`](crates/kiss_chat), the terminal frontend that consumes it
(and the binary you install).

**`kiss_chat_core`:**

| Module | Responsibility |
|--------|----------------|
| `identity` | persistent on-disk keys (iroh address + ML-DSA auth seed) |
| `contacts` | pinned contact list: remembers each accepted peer's ML-DSA key (TOFU) |
| `transport` | iroh endpoint: bind, dial-by-key, accept (QUIC + NAT traversal) |
| `proto` | length-prefixed framing over the stream |
| `message` | 1-byte-tagged in-band protocol (chat text vs. a `Bye` control frame) |
| `crypto` | hybrid KEX, ML-DSA authentication, key derivation, ChaCha20-Poly1305 session |

**`kiss_chat`:**

| Module | Responsibility |
|--------|----------------|
| `ui` | terminal interface (pure state machine) |
| `app` | the event loop wiring input, connection tasks, and the UI together |

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
- Peer identities are trusted on first use (verified via the safety words) and then **pinned**:
  when you `/accept` a peer, kiss_chat remembers their ML-DSA identity key against their address,
  and warns you on a later connection if that address ever presents a *different* identity key.
  Pinning only covers peers you've accepted, and it keys on the address, so a known peer arriving
  from a brand-new address is treated as a first meeting rather than a change. A recognised peer
  reconnects on a consent step rather than a repeated word-for-word comparison, so their trust then
  rests on the pin: the `contacts` file is not secret, and a local attacker able to rewrite it could
  plant a key you'd accept without re-verifying (though such an attacker likely already has your
  identity seed beside it).
- The `ml-kem` and `ml-dsa` crates are pure-Rust FIPS 203/204 implementations that have **not**
  had an independent security audit. Treat kiss_chat as a simple, educational P2P chat, not a
  hardened product.

## Testing

```bash
cargo test          # crypto/identity/ui unit tests + full-stack loopback integration tests
cargo clippy --workspace --all-targets
```

The integration tests spin up two real iroh endpoints on loopback and run a complete
connect → three-message authenticated handshake → encrypted round-trip.

## Not (yet) included

Group chat, message history on disk, file transfer, and local-time timestamps. The architecture
leaves room for each without a rewrite.
