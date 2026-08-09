<div align="center">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/gwo0d/kiss_chat/main/assets/lockup-dark.svg">
  <source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/gwo0d/kiss_chat/main/assets/lockup-light.svg">
  <img alt="kiss_chat" src="https://raw.githubusercontent.com/gwo0d/kiss_chat/main/assets/lockup-light.svg" width="440">
</picture>

[![CI](https://img.shields.io/github/actions/workflow/status/gwo0d/kiss_chat/ci.yml?branch=main&label=CI&logo=github)](https://github.com/gwo0d/kiss_chat/actions/workflows/ci.yml)
[![docs.rs](https://img.shields.io/docsrs/kiss_chat_core?logo=rust&label=docs.rs)](https://docs.rs/kiss_chat_core/latest/kiss_chat_core/)
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
- **Embeddable.** [`--headless`](#headless-mode) turns kiss_chat into a secure transport your own
  programs can drive: spawn it, speak newline-delimited JSON on stdio, and get the same
  end-to-end encrypted channel — in any language, with no library to link.

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
-- your address:
  kiss1 j6hd a3e9 5qgy jv70 6uaz wg4n f9a3 xvr3 qz3y 9n95 0mlf ev06 lgus yhfk 3x
-- share it so a peer can dial you, or connect out with:
--   /connect <address>
```

**Or dial immediately** with the address your peer shared, in whichever form they shared it:

```bash
cargo run -- kiss1j6hda3e95qgyjv706uazwg4nf9a3xvr3qz3y9n950mlfev06lgusyhfk3x
```

### Sharing your address

An address is a full 256-bit public key, so it can't be made shorter — but it can be made
friendlier. kiss_chat shows and accepts the same address in three interchangeable forms:

- **`kiss1…`** — the form to copy/paste. Its charset avoids look-alike characters and it ends in
  a checksum, so a mistyped character is caught when it's entered rather than dialling into the
  void. Shown grouped for readability; the grouping (and any line-wrapping a terminal adds) is
  fine to include when copying.
- **24 words** (`/address words`) — the form to read over a phone call or write on paper, drawn
  from the BIP39 wordlist with its standard checksum, so a wrong, missing, or swapped word is
  caught too. *These are your public address, not safety words — never compare them to verify a
  peer.*
- **plain hex** (shown under `/address`) — the canonical form, and the one to give a peer running
  an older kiss_chat version.

`/qr` renders the address as a QR code right in the terminal, for pointing a phone at.

Every place an address is entered — `/connect`, the command line, headless `connect` — takes any
form, and forgives what terminals do to them: line breaks, indentation, grouping spaces, and even
stray TUI border characters picked up by a copy are stripped before decoding.

Pass `--version` (or `-v`) to print the version and exit; `--help` (or `-h`) prints usage. Inside
the app, `/version` (alias `/v`) shows the same version, which also appears in the frame title.

`--config-dir <path>` keeps this session's identity, contacts, and display name somewhere other
than the default directory — handy for a second identity, or for running two instances on one
machine.

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

Your peer has the same decision to make, so accepting shows **waiting for peer to accept…** until
they do; chat opens when both of you have accepted. Anything you type while waiting is held and
sent the moment they accept, so nothing you say goes missing in the gap. (`/reject` still works
while waiting, if they never answer.)
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
| `/connect <address>` | dial a peer (any address form); if already connected, leaves that peer and switches (alias `/c`) |
| `/accept` | accept the peer — after every safety word matches, or just to consent to a recognised one (alias `/a`) |
| `/reject` | reject the peer being verified and return to the lobby (alias `/r`) |
| `/name [text]` | set your optional display name; empty clears it (alias `/n`) |
| `/safety` | re-show the current session's safety words (alias `/s`) |
| `/contacts` | list the peers you've accepted before (alias `/peers`) |
| `/address [words]` | show your own address to share — `kiss1…` and hex, or the 24-word form (alias `/addr`) |
| `/qr` | show your own address as a QR code |
| `/clear` | clear the screen |
| `/version` | show the version (alias `/v`) |
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

## Headless mode

kiss_chat can be driven by a program instead of a person. `--headless` runs the same protocol
with no terminal: it writes one JSON object per line to stdout (events) and reads one per line
from stdin (commands). Spawn it as a child process and you have a secure, peer-to-peer,
post-quantum-encrypted channel for as long as your application runs — in any language, with no
library to link against.

The motivating case: two people running a small program — a chess game, a shared whiteboard —
who want to talk directly, without you standing up a server for them.

```bash
kiss_chat --headless --ephemeral                 # throwaway identity, nothing written to disk
kiss_chat --headless --config-dir ~/.myapp/kc    # stable identity kept in that directory
```

One of the two is required. kiss_chat will **not** fall back to your own config directory: that
would bind a second endpoint claiming your address, and mix an application's trusted peers in
with yours.

Other flags: `--expect <fingerprint>` (repeatable — see [Unattended use](#unattended-use)),
`--name <text>` (a display name for this run, not saved), `--once` (exit when the first session
ends — the natural fit for "one game, one process"), and a bare peer address to dial on startup.

### Events (stdout)

| Event | Fields | When |
|-------|--------|------|
| `ready` | `proto`, `address`, `address_bech32`, `address_words`, `fingerprint`, `name`, `direct_addrs` | Once, after binding. Everything you need to build an invitation. `address` is the canonical hex; `address_bech32` (`kiss1…`) and `address_words` (24 words) are the same address for handing to humans. (`direct_addrs` is a best-effort convenience for dialling without discovery, and may be empty this early — the `address` is what peers actually need.) |
| `connecting` | `peer` | A dial started. |
| `verify` | `peer`, `words`, `fingerprint`, `pin`, `known_name` | A channel is up, awaiting your accept/reject. `pin` is `new`, `known`, or `changed`. |
| `accepted` | `peer`, `fingerprint` | *You* accepted; the peer has been told. |
| `connected` | `peer`, `fingerprint` | Both sides have accepted. You may send now. |
| `peer_name` | `name` | The peer shared or cleared their display name. |
| `message` | `text` | A decrypted chat message. |
| `disconnected` | `reason` | The session ended. |
| `error` | `message` | A command was rejected; the session carries on. |

### Commands (stdin)

| Command | Fields | Meaning |
|---------|--------|---------|
| `connect` | `peer`, `addrs` (optional) | Dial a peer — `peer` takes any address form (hex, `kiss1…`, or the 24 words). `addrs` are explicit `ip:port` addresses, to skip discovery. |
| `accept` | — | Accept the peer being verified. |
| `reject` | — | Reject the peer being verified. |
| `send` | `text` | Send a message. Only valid after `connected`. |
| `quit` | — | Say goodbye and exit. Closing stdin does the same. |

Exit codes: `0` clean, `1` startup or (with `--once`) a dial that never connected, `2` a peer
whose identity `--expect` disallowed.

**Ignore what you don't recognise.** Unknown events, and unknown fields on the ones you do know,
are how this protocol grows without breaking you. `ready` carries `proto` (currently `1`), which
changes only if a conforming consumer would break.

### A session, end to end

```jsonl
← {"event":"ready","proto":1,"address":"96aede…","address_bech32":"kiss1j6hd…","address_words":"note ivory range …","fingerprint":"3c9a…","name":null,"direct_addrs":["192.168.1.7:52400"]}
→ {"cmd":"connect","peer":"b1c2…"}
← {"event":"connecting","peer":"b1c2…"}
← {"event":"verify","peer":"b1c2…","words":"vault sketch tide …","fingerprint":"77aa…","pin":"new","known_name":null}
→ {"cmd":"accept"}
← {"event":"accepted","peer":"b1c2…","fingerprint":"77aa…"}
← {"event":"connected","peer":"b1c2…","fingerprint":"77aa…"}
→ {"cmd":"send","text":"{\"move\":\"e2e4\"}"}
← {"event":"message","text":"{\"move\":\"e7e5\"}"}
→ {"cmd":"quit"}
```

`accepted` is your decision; `connected` is *both* — the peer has accepted too, and anything you
send from then on will reach them. Wait for `connected` before sending; there's no timeout on it,
so how long to wait (and whether to offer a "give up" button) is your application's call.

### Verifying, from a program

The safety-word ritual isn't skipped here, it moves: the `verify` event hands you the words, the
peer's fingerprint, and whether you've met before, and *your* interface shows them to *your* user.
Read the words aloud together, then send `accept` or `reject`. This is what the security of the
channel rests on — a man-in-the-middle produces different words on the two ends.

### Unattended use

For two programs meeting with no human present, `--expect <fingerprint>` pre-pins the identity
the peer must present: a match is accepted automatically, anything else is refused. This is
sound because you already have to send the address out of band — put the fingerprint from `ready`
in the same invitation, and the out-of-band check simply happens *before* the connection instead
of after it.

There is deliberately no "accept anything" mode.

### From Python

[`examples/python/`](examples/python) has a ~150-line stdlib-only wrapper (`kiss_pipe.py`) and a
two-terminal demo chat (`demo_chat.py`):

```python
from kiss_pipe import KissChat

with KissChat(ephemeral=True) as chat:
    print("invite your opponent with:", chat.address, chat.fingerprint)
    chat.connect(opponent_address)

    verify = chat.wait_for("verify")
    show_to_user(verify["words"])          # compare these aloud
    chat.accept()                          # ...once they match
    chat.wait_for("connected")             # both sides are in

    chat.send_json({"move": "e2e4"})
    reply = chat.wait_for("message")
```

Treat what arrives as untrusted input: kiss_chat authenticates, decrypts, and strips control
characters, but what a message *means* is your application's business — validate it as you would
anything off a socket.

If your application is itself in Rust, you don't need any of this: depend on
[`kiss_chat_core`](crates/kiss_chat_core) directly.

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
| `message` | 1-byte-tagged in-band protocol (chat text vs. `Accepted`/`Bye`/`Name` control frames) |
| `crypto` | hybrid KEX, ML-DSA authentication, key derivation, ChaCha20-Poly1305 session |

**`kiss_chat`:**

| Module | Responsibility |
|--------|----------------|
| `net` | the connection driver both frontends share: dial/accept, handshake, reader/writer tasks |
| `ui` | terminal interface (pure state machine) |
| `app` | the terminal event loop wiring input, connection tasks, and the UI together |
| `headless` | the machine-driven frontend: NDJSON events and commands on stdio |
| `cli` | argument parsing |

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

Once the channel is up, each side sends an `Accepted` frame when its user accepts, and chat opens
only when both have — so neither end can be talking to a screen that is still asking "do you trust
this person?". Chat text arriving before that is treated as a protocol violation and ends the
session. Frames tagged with something a version doesn't recognise are ignored rather than fatal,
so later additions don't need a coordinated break.

> **Compatibility.** The wire protocol is versioned by the QUIC ALPN, `kiss-chat/1` since 0.7.0
> (it was `kiss-chat/0` up to 0.6.x). Peers on different wire versions are refused when dialling,
> with a plain connection error — so both sides need to be on 0.7 or newer to talk.

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
connect → three-message authenticated handshake → encrypted round-trip. The headless tests go
further, driving two whole instances through verification, mutual acceptance, and a message
exchange over in-memory pipes — the full stack, minus the process boundary, with no network
involved. A separate suite checks the built binary's process contract (stdio, exit codes, EOF).

## Not (yet) included

Group chat, message history on disk, file transfer, and local-time timestamps. The architecture
leaves room for each without a rewrite. Headless mode is one peer at a time, like the rest of
kiss_chat, so it suits two-player applications; anything multi-party needs group chat first.
